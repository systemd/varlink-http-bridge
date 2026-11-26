// SPDX-License-Identifier: LGPL-2.1-or-later

//! The OpenSSL backend of [`crate::tls`].

use std::path::Path;
use std::pin::Pin;

use anyhow::{Context, bail};
use openssl::ssl::{SslAcceptor, SslConnector, SslFiletype, SslMethod, SslVerifyMode, SslVersion};
use openssl::x509::X509;
use tokio::io::{AsyncRead, AsyncWrite};

use super::{ClientCert, Roots, Verify};
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

    /// Returns the fingerprint of the public key: base64 of the SHA-256
    /// digest of the DER-encoded `SubjectPublicKeyInfo`, which is what
    /// `curl --pinnedpubkey sha256//…` expects.
    ///
    /// # Errors
    /// Returns an error if the key cannot be extracted or DER-encoded.
    pub fn public_key_pin(&self) -> anyhow::Result<String> {
        let spki = self
            .0
            .public_key()
            .context("reading certificate public key")?
            .public_key_to_der()
            .context("encoding SubjectPublicKeyInfo")?;
        Ok(super::base64(&sha256(&spki)))
    }

    /// Returns whether the certificate names itself as its own issuer.
    #[must_use]
    pub fn is_self_signed(&self) -> bool {
        self.0
            .issuer_name()
            .try_cmp(self.0.subject_name())
            .is_ok_and(std::cmp::Ordering::is_eq)
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

/// The server side of TLS: a certificate and key, TLS 1.3 only.
#[derive(Clone)]
pub struct Acceptor(SslAcceptor);

impl Acceptor {
    /// Loads the PEM certificate chain and key. With `require_client_cert`
    /// a handshake only succeeds for a client certificate that the CAs
    /// passed to [`Acceptor::accept`] vouch for.
    ///
    /// # Errors
    /// Returns an error if the certificate or key cannot be loaded or do
    /// not match.
    pub fn new(cert_path: &str, key_path: &str, require_client_cert: bool) -> anyhow::Result<Self> {
        let mut builder = SslAcceptor::mozilla_modern_v5(SslMethod::tls_server())
            .context("creating TLS acceptor")?;
        // mozilla_modern_v5 allows TLS 1.2, but export_keying_material
        // for the channel binding requires 1.3
        builder
            .set_min_proto_version(Some(SslVersion::TLS1_3))
            .context("requiring TLS 1.3")?;
        builder
            .set_certificate_chain_file(cert_path)
            .with_context(|| format!("loading certificate {cert_path}"))?;
        builder
            .set_private_key_file(key_path, SslFiletype::PEM)
            .with_context(|| format!("loading key {key_path}"))?;
        builder
            .check_private_key()
            .context("certificate and key do not match")?;
        if require_client_cert {
            builder.set_verify(SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT);
        }
        Ok(Self(builder.build()))
    }

    /// Performs the TLS handshake on an accepted `stream`. `client_cas` are
    /// the CAs a client certificate is verified against in this handshake.
    ///
    /// # Errors
    /// Returns an error if the handshake fails.
    pub async fn accept<S: AsyncRead + AsyncWrite + Unpin>(
        &self,
        client_cas: Option<&[Certificate]>,
        stream: S,
    ) -> anyhow::Result<Stream<S>> {
        let mut ssl = openssl::ssl::Ssl::new(self.0.context()).context("SSL context error")?;
        // per handshake so that the CAs can be rotated without a new acceptor
        if let Some(cas) = client_cas {
            // SSL_set0_verify_cert_store takes ownership, so the store
            // cannot be shared; the certificates are refcounted
            let mut store = openssl::x509::store::X509StoreBuilder::new()
                .context("creating client CA store")?;
            for ca in cas {
                store.add_cert(ca.0.clone()).context("adding a client CA")?;
            }
            ssl.set_verify_cert_store(store.build())
                .context("installing client CA store")?;
        }
        let mut tls_stream =
            tokio_openssl::SslStream::new(ssl, stream).context("SSL stream creation failed")?;
        Pin::new(&mut tls_stream)
            .accept()
            .await
            .context("TLS handshake failed")?;
        Ok(tls_stream)
    }
}

/// Returns a trust store holding only the certificates in `ca_path`.
fn exclusive_ca_store(ca_path: &Path) -> anyhow::Result<openssl::x509::store::X509Store> {
    let pem = std::fs::read(ca_path)
        .with_context(|| format!("reading CA certificate {}", ca_path.display()))?;
    let certs = X509::stack_from_pem(&pem)
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

/// The client side of TLS. Building one is expensive, so reuse it.
#[derive(Clone)]
pub struct Connector(SslConnector);

impl Connector {
    /// Returns a TLS 1.3 only connector that verifies servers against the
    /// system CA store, without a client certificate.
    ///
    /// # Errors
    /// Returns an error if the TLS library cannot be set up.
    pub fn system() -> anyhow::Result<Self> {
        Self::new(&Roots::System, None, None)
    }

    /// Returns a TLS 1.3 only connector. `client_cert` is presented to
    /// servers that ask for one. With `verify` the callback has the last
    /// word on the server certificate, otherwise it has to validate against
    /// `roots`.
    ///
    /// # Errors
    /// Returns an error if a file cannot be loaded, or the client
    /// certificate and key do not match.
    pub fn new(
        roots: &Roots,
        client_cert: Option<&ClientCert>,
        verify: Option<Verify>,
    ) -> anyhow::Result<Self> {
        let mut builder =
            SslConnector::builder(SslMethod::tls_client()).context("creating TLS connector")?;
        // the RFC 9266 channel binding is only guaranteed unique with TLS 1.3
        builder
            .set_min_proto_version(Some(SslVersion::TLS1_3))
            .context("requiring TLS 1.3")?;

        if let Some(ClientCert { cert, key }) = client_cert {
            builder
                .set_certificate_chain_file(cert)
                .with_context(|| format!("loading client certificate {}", cert.display()))?;
            builder
                .set_private_key_file(key, SslFiletype::PEM)
                .with_context(|| format!("loading client key {}", key.display()))?;
            builder
                .check_private_key()
                .context("client certificate and key do not match")?;
        }

        if let Roots::Exclusive(ca) = roots {
            // set_ca_file would extend the pre-loaded system store
            builder.set_cert_store(
                exclusive_ca_store(ca)
                    .with_context(|| format!("loading CA certificate {}", ca.display()))?,
            );
        }

        if let Some(verify) = verify {
            builder.set_verify_callback(SslVerifyMode::PEER, move |chain_ok, ctx| {
                // errors above the leaf abort on their own
                if ctx.error_depth() != 0 {
                    return chain_ok;
                }
                ctx.current_cert()
                    .is_some_and(|cert| verify(&Certificate(cert.to_owned()), chain_ok))
            });
        }
        Ok(Self(builder.build()))
    }

    /// Performs the TLS handshake on a connected `stream`. Returns the
    /// session and whether the server certificate validated against the
    /// roots, which can be false only if a [`Verify`] accepted it.
    ///
    /// `verify_hostname=false` is for transports without a hostname; the
    /// certificate chain is still verified.
    ///
    /// # Errors
    /// Returns an error if the handshake fails.
    pub async fn connect<S: AsyncRead + AsyncWrite + Unpin>(
        &self,
        domain: &str,
        verify_hostname: bool,
        stream: S,
    ) -> anyhow::Result<(Stream<S>, bool)> {
        let mut config = self.0.configure().context("TLS configure")?;
        config.set_verify_hostname(verify_hostname);
        let ssl = config.into_ssl(domain).context("TLS setup")?;
        let mut tls_stream = tokio_openssl::SslStream::new(ssl, stream).context("TLS stream")?;
        Pin::new(&mut tls_stream).connect().await?;
        let validated = tls_stream.ssl().verify_result() == openssl::x509::X509VerifyResult::OK;
        Ok((tls_stream, validated))
    }
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
    use openssl::x509::{X509StoreContext, store::X509StoreRef};

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

    /// Rejecting inside the verify callback must abort before we send our own
    /// certificate; rejecting after the handshake would already have leaked it.
    #[tokio::test]
    async fn a_refused_server_never_sees_our_client_certificate() {
        for reject in [true, false] {
            let dir = tempfile::tempdir().unwrap();
            let server = identity("srv", None);
            let client = identity("cli", None);
            let client_cert = ClientCert {
                cert: dir.path().join("cli.pem"),
                key: dir.path().join("cli.key"),
            };
            std::fs::write(&client_cert.cert, client.0.to_pem().unwrap()).unwrap();
            std::fs::write(
                &client_cert.key,
                client.1.private_key_to_pem_pkcs8().unwrap(),
            )
            .unwrap();

            let mut acceptor = SslAcceptor::mozilla_modern_v5(SslMethod::tls_server()).unwrap();
            acceptor.set_certificate(&server.0).unwrap();
            acceptor.set_private_key(&server.1).unwrap();
            // any client certificate is fine, so one that was sent is kept
            // even when the handshake fails afterwards
            acceptor.set_verify_callback(SslVerifyMode::PEER, |_ok, _ctx| true);
            let acceptor = acceptor.build();

            let (ours, theirs) = tokio::io::duplex(64 * 1024);
            let saw_client_cert = tokio::spawn(async move {
                let ssl = openssl::ssl::Ssl::new(acceptor.context()).unwrap();
                let mut tls = tokio_openssl::SslStream::new(ssl, theirs).unwrap();
                let _ = Pin::new(&mut tls).accept().await;
                tls.ssl().peer_certificate().is_some()
            });

            let verify: Verify = std::sync::Arc::new(move |_cert, _chain_ok| !reject);
            let connector = Connector::new(&Roots::System, Some(&client_cert), Some(verify));
            let handshake = connector.unwrap().connect("srv", false, ours).await;

            assert_eq!(handshake.is_err(), reject);
            assert_eq!(
                saw_client_cert.await.unwrap(),
                !reject,
                "reject={reject}: the server must only see our certificate when we accept it"
            );
        }
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
