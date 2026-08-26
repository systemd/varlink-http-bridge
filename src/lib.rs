// SPDX-License-Identifier: LGPL-2.1-or-later

pub mod sysconf;

#[cfg(feature = "sshauth")]
/// Namespace prefix for SSH-based authentication tokens, analogous to
/// `ssh-keygen -Y sign -n <namespace>`.  Binds signatures to this application
/// so they cannot be replayed against other services.
pub const SSHAUTH_MAGIC_PREFIX: [u8; 8] = *b"vhbridge";

#[cfg(feature = "sshauth")]
/// HTTP header carrying the random nonce that is included in the signed
/// token payload to prevent replay attacks.
pub const SSHAUTH_NONCE_HEADER: &str = "x-auth-nonce";

/// Default port for the HTTP bridge when listening on or connecting via vsock.
pub const DEFAULT_PORT: u32 = 1031;

/// Parse a `CID:PORT` or bare `CID` string into `(cid, port)`.
///
/// If only a single number is given it is treated as the CID and
/// [`DEFAULT_PORT`] is used.
///
/// # Errors
///
/// Returns an error if the CID or port cannot be parsed as `u32`.
pub fn parse_vsock_cid_port(authority: &str) -> anyhow::Result<(u32, u32)> {
    use anyhow::Context;
    match authority.split_once(':') {
        Some((cid_str, port_str)) => Ok((
            cid_str
                .parse::<u32>()
                .with_context(|| format!("invalid vsock CID: {cid_str}"))?,
            port_str
                .parse::<u32>()
                .with_context(|| format!("invalid vsock port: {port_str}"))?,
        )),
        None => Ok((
            authority
                .parse::<u32>()
                .with_context(|| format!("invalid vsock CID: {authority}"))?,
            DEFAULT_PORT,
        )),
    }
}

/// Fingerprint of a certificate's public key: base64 of the SHA-256 digest
/// of the DER-encoded `SubjectPublicKeyInfo`.
///
/// httpd prints it if a self-signed cert is used, and the client pins against it.
/// The encoding matches what `curl --pinnedpubkey sha256//…` expects.
///
/// # Errors
/// Returns an error if the key cannot be extracted or DER-encoded.
pub fn public_key_pin(cert: &openssl::x509::X509Ref) -> anyhow::Result<String> {
    use anyhow::Context;

    let spki = cert
        .public_key()
        .context("reading certificate public key")?
        .public_key_to_der()
        .context("encoding SubjectPublicKeyInfo")?;
    let digest = openssl::hash::hash(openssl::hash::MessageDigest::sha256(), &spki)
        .context("hashing SubjectPublicKeyInfo")?;
    Ok(openssl::base64::encode_block(&digest))
}

/// TLS channel binding label per RFC 9266 (`tls-exporter`).
///
/// Both client and server call `export_keying_material()` with this label
/// and include the result in the sshauth token so that the signature is
/// bound to the specific TLS session, preventing credential relay attacks.
pub const TLS_CHANNEL_BINDING_LABEL: &str = "EXPORTER-Channel-Binding";

/// Output length (bytes) for TLS channel binding export.
pub const TLS_CHANNEL_BINDING_LEN: usize = 32;

/// Base64-encoded RFC 9266 channel binding of a TLS 1.3 session.
///
/// Newtype: signing or verifying over one of the look-alike strings it
/// travels next to (URLs, tokens, nonces) would silently lose its relay
/// protection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsChannelBinding(String);

impl TlsChannelBinding {
    /// Test-only: real bindings come from [`export_tls_channel_binding`].
    #[cfg(any(test, feature = "test-helpers"))]
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Export the TLS channel binding value from an established TLS 1.3 session.
///
/// Returns the base64-encoded result of `export_keying_material` per RFC 9266.
///
/// # Panics
/// Panics if `export_keying_material` fails (should never happen with
/// TLS 1.3) or if the export does not work because of an underlying
/// bug in openssl and returns only zeros (should also never happen).
pub fn export_tls_channel_binding(ssl: &openssl::ssl::SslRef) -> TlsChannelBinding {
    let mut buf = [0u8; TLS_CHANNEL_BINDING_LEN];
    ssl.export_keying_material(&mut buf, TLS_CHANNEL_BINDING_LABEL, Some(&[]))
        .expect("export_keying_material must succeed with TLS 1.3");
    assert!(
        buf.iter().any(|&b| b != 0),
        "TLS channel binding must not be all zeros"
    );
    TlsChannelBinding(openssl::base64::encode_block(&buf))
}

/// A trust store holding only the certificates in `ca_path`.
///
/// # Errors
/// Returns an error if `ca_path` cannot be read, contains no PEM certificate,
/// or the store cannot be assembled.
pub fn exclusive_ca_store(
    ca_path: &std::path::Path,
) -> anyhow::Result<openssl::x509::store::X509Store> {
    use anyhow::{Context, bail};

    let pem = std::fs::read(ca_path)
        .with_context(|| format!("reading CA certificate {}", ca_path.display()))?;
    let certs = openssl::x509::X509::stack_from_pem(&pem)
        .with_context(|| format!("parsing CA certificate {}", ca_path.display()))?;
    if certs.is_empty() {
        bail!("no PEM certificate found in {}", ca_path.display());
    }

    let mut store =
        openssl::x509::store::X509StoreBuilder::new().context("creating certificate store")?;
    for cert in certs {
        store
            .add_cert(cert)
            .with_context(|| format!("adding a certificate from {}", ca_path.display()))?;
    }
    Ok(store.build())
}

/// Enable `TCP_NODELAY` and `SO_KEEPALIVE` on a TCP socket.
///
/// Keepalive timing uses the OS defaults. Tunable via
/// `sysctl net.ipv4.tcp_keepalive_{time,intvl,probes}`
///
/// # Errors
/// Returns an error if the underlying `setsockopt` calls fail.
pub fn set_tcp_keepalive_and_nodelay(fd: &impl std::os::fd::AsFd) -> anyhow::Result<()> {
    use anyhow::Context;

    // no way to do this directly yet, hence socket2, see
    // https://github.com/rust-lang/rust/issues/69774
    let sock = socket2::SockRef::from(fd);
    sock.set_tcp_nodelay(true).context("set TCP_NODELAY")?;
    // TODO: if we need more aggressive dead-peer detection, override the
    // keepalive timing here with something like:
    //   let keepalive = socket2::TcpKeepalive::new()
    //      .with_time(std::time::Duration::from_secs(300))
    //      .with_interval(std::time::Duration::from_secs(30))
    //     .with_retries(5);
    //   sock.set_tcp_keepalive(&keepalive)
    sock.set_keepalive(true).context("set SO_KEEPALIVE")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use openssl::x509::{X509, X509StoreContext, store::X509StoreRef};

    type Identity = (X509, openssl::pkey::PKey<openssl::pkey::Private>);

    /// A throwaway CA, or a leaf signed by `issuer` when one is given.
    fn identity(cn: &str, issuer: Option<&Identity>) -> Identity {
        use openssl::{asn1::Asn1Time, ec, hash::MessageDigest, nid::Nid, pkey::PKey, x509};

        let group = ec::EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        let key = PKey::from_ec_key(ec::EcKey::generate(&group).unwrap()).unwrap();

        let mut nb = x509::X509NameBuilder::new().unwrap();
        nb.append_entry_by_nid(Nid::COMMONNAME, cn).unwrap();
        let name = nb.build();

        let mut b = x509::X509::builder().unwrap();
        b.set_version(2).unwrap();
        b.set_subject_name(&name).unwrap();
        match issuer {
            Some((cert, _)) => b.set_issuer_name(cert.subject_name()).unwrap(),
            None => b.set_issuer_name(&name).unwrap(),
        }
        b.set_pubkey(&key).unwrap();
        b.set_not_before(&Asn1Time::days_from_now(0).unwrap())
            .unwrap();
        b.set_not_after(&Asn1Time::days_from_now(1).unwrap())
            .unwrap();
        if issuer.is_none() {
            b.append_extension(
                x509::extension::BasicConstraints::new()
                    .critical()
                    .ca()
                    .build()
                    .unwrap(),
            )
            .unwrap();
        }
        b.sign(issuer.map_or(&key, |(_, k)| k), MessageDigest::sha256())
            .unwrap();
        (b.build(), key)
    }

    fn write_ca(dir: &std::path::Path, cert: &X509) -> std::path::PathBuf {
        let path = dir.join("server-ca-file");
        std::fs::write(&path, cert.to_pem().unwrap()).unwrap();
        path
    }

    /// Whether `store` will vouch for `leaf`.
    fn accepts(store: &X509StoreRef, leaf: &X509) -> bool {
        let chain = openssl::stack::Stack::new().unwrap();
        X509StoreContext::new()
            .unwrap()
            .init(store, leaf, &chain, |c| {
                Ok(c.verify_cert().unwrap_or(false))
            })
            .unwrap()
    }

    #[test]
    fn trusts_only_the_configured_authority() {
        let dir = tempfile::tempdir().unwrap();
        let ca_a = identity("ca-a", None);
        let ca_b = identity("ca-b", None);
        let leaf_a = identity("leaf-a", Some(&ca_a));
        let leaf_b = identity("leaf-b", Some(&ca_b));

        let store = exclusive_ca_store(&write_ca(dir.path(), &ca_a.0)).unwrap();

        assert!(accepts(&store, &leaf_a.0), "the configured CA must vouch");
        assert!(!accepts(&store, &leaf_b.0), "no other authority may vouch");
    }

    /// The point of the helper: `set_ca_file` would leave an already loaded
    /// authority trusted next to the configured CA. For `SslConnector`, which
    /// pre-loads the default verify paths, that authority is the whole public
    /// PKI.
    #[test]
    fn replaces_the_system_bundle_rather_than_extending_it() {
        let dir = tempfile::tempdir().unwrap();
        let configured = identity("configured-ca", None);
        let preloaded = identity("preloaded-ca", None);
        let leaf = identity("leaf", Some(&preloaded));

        let mut builder =
            openssl::ssl::SslConnector::builder(openssl::ssl::SslMethod::tls_client()).unwrap();
        // Stands in for the system bundle the builder pre-loads, so the test
        // does not depend on the host having one.
        builder.cert_store_mut().add_cert(preloaded.0).unwrap();
        builder.set_cert_store(exclusive_ca_store(&write_ca(dir.path(), &configured.0)).unwrap());

        let ctx = builder.build().into_context();
        assert_eq!(
            ctx.cert_store().all_certificates().len(),
            1,
            "only the configured CA may remain in the store"
        );
        assert!(
            !accepts(ctx.cert_store(), &leaf.0),
            "a pre-loaded authority must not survive"
        );
    }

    #[test]
    fn rejects_a_file_holding_no_certificate() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("server-ca-file");
        std::fs::write(&path, b"not a certificate\n").unwrap();

        let Err(err) = exclusive_ca_store(&path) else {
            panic!("a file holding no certificate must be refused");
        };
        assert!(
            format!("{err:#}").contains("no PEM certificate"),
            "unexpected error: {err:#}"
        );
    }
}
