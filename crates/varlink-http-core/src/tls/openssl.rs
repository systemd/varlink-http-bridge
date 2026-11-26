// SPDX-License-Identifier: LGPL-2.1-or-later

//! The OpenSSL backend of [`crate::tls`].

use anyhow::Context;
use openssl::x509::X509;

use crate::{TLS_CHANNEL_BINDING_LABEL, TLS_CHANNEL_BINDING_LEN, TlsChannelBinding};

/// An established TLS session over `S`.
pub type Stream<S> = tokio_openssl::SslStream<S>;

/// An X.509 certificate.
#[derive(Clone)]
pub struct Certificate(X509);

impl Certificate {
    /// Parses every certificate in `pem`. A PEM without any certificate is
    /// an empty vector, not an error.
    ///
    /// # Errors
    /// Returns an error if a certificate in `pem` is malformed.
    pub fn from_pem_bundle(pem: &[u8]) -> anyhow::Result<Vec<Self>> {
        Ok(X509::stack_from_pem(pem)
            .context("parsing PEM certificates")?
            .into_iter()
            .map(Self)
            .collect())
    }

    /// Returns the subject as text, like `CN=host, O=org`.
    #[must_use]
    pub fn subject(&self) -> String {
        self.0
            .subject_name()
            .entries()
            .filter_map(|e| {
                let obj = e.object().nid().short_name().ok()?;
                let val = e.data().to_string().ok()?;
                Some(format!("{obj}={val}"))
            })
            .collect::<Vec<_>>()
            .join(", ")
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

/// Exports the RFC 9266 channel binding of an established TLS 1.3 session.
///
/// # Panics
/// Panics if the export fails or yields only zeros, neither of which
/// happens with TLS 1.3.
#[must_use]
pub fn channel_binding<S>(stream: &Stream<S>) -> TlsChannelBinding {
    let mut buf = [0u8; TLS_CHANNEL_BINDING_LEN];
    stream
        .ssl()
        .export_keying_material(&mut buf, TLS_CHANNEL_BINDING_LABEL, Some(&[]))
        .expect("export_keying_material must succeed with TLS 1.3");
    assert!(
        buf.iter().any(|&b| b != 0),
        "TLS channel binding must not be all zeros"
    );
    TlsChannelBinding(super::base64(&buf))
}

/// Returns the certificate the peer presented, if any.
#[must_use]
pub fn peer_certificate<S>(stream: &Stream<S>) -> Option<Certificate> {
    stream.ssl().peer_certificate().map(Certificate)
}

/// Returns a `SslAcceptorBuilder` from the given {cert,key}_path with
/// a minimum TLS1.3 version requirement for TLS channel binding.
///
/// # Errors
/// Returns an error if the certificate or key cannot be loaded or do
/// not match.
pub fn tls_acceptor_builder(
    cert_path: &str,
    key_path: &str,
) -> anyhow::Result<openssl::ssl::SslAcceptorBuilder> {
    use openssl::ssl::{SslAcceptor, SslFiletype, SslMethod};

    let mut builder = SslAcceptor::mozilla_modern_v5(SslMethod::tls_server())?;
    // mozilla_modern_v5 allows TLS 1.2, but we need 1.3 for channel binding
    // (export_keying_material requires TLS 1.3).
    builder.set_min_proto_version(Some(openssl::ssl::SslVersion::TLS1_3))?;
    builder.set_certificate_chain_file(cert_path)?;
    builder.set_private_key_file(key_path, SslFiletype::PEM)?;
    builder.check_private_key()?;
    Ok(builder)
}

/// Perform a TLS handshake on an already-accepted
/// stream. `client_store` holds the CAs a client certificate is
/// verified against. This runs per handshake the CAs can be rotated
/// without rebuilding the acceptor.
///
/// # Errors
/// Returns an error if the handshake fails.
pub async fn tls_accept<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(
    acceptor: &openssl::ssl::SslAcceptor,
    client_store: Option<openssl::x509::store::X509Store>,
    stream: S,
) -> anyhow::Result<tokio_openssl::SslStream<S>> {
    use anyhow::Context;
    let mut ssl = openssl::ssl::Ssl::new(acceptor.context()).context("SSL context error")?;
    if let Some(store) = client_store {
        ssl.set_verify_cert_store(store)
            .context("installing client CA store")?;
    }
    let mut tls_stream =
        tokio_openssl::SslStream::new(ssl, stream).context("SSL stream creation failed")?;
    std::pin::Pin::new(&mut tls_stream)
        .accept()
        .await
        .context("TLS handshake failed")?;
    Ok(tls_stream)
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

/// Returns the SHA-256 digest of `data`.
#[must_use]
pub fn sha256(data: &[u8]) -> [u8; 32] {
    openssl::sha::sha256(data)
}

/// Returns the HMAC-SHA256 of `msg` under `key`.
///
/// # Errors
/// Returns an error if the TLS library fails.
pub fn hmac_sha256(key: &[u8], msg: &[u8]) -> anyhow::Result<[u8; 32]> {
    use openssl::{hash::MessageDigest, pkey::PKey, sign::Signer};

    let key = PKey::hmac(key).context("creating HMAC key")?;
    let mut signer = Signer::new(MessageDigest::sha256(), &key).context("creating signer")?;
    signer.update(msg).context("hashing")?;
    let mut mac = [0u8; 32];
    signer.sign(&mut mac).context("computing HMAC")?;
    Ok(mac)
}

/// Fills `buf` with cryptographically secure random bytes.
///
/// # Errors
/// Returns an error if the system has no randomness to give.
pub fn random_bytes(buf: &mut [u8]) -> anyhow::Result<()> {
    openssl::rand::rand_bytes(buf).context("reading random bytes")
}

/// Compares `a` and `b` in time that depends only on their length.
#[must_use]
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && openssl::memcmp::eq(a, b)
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
