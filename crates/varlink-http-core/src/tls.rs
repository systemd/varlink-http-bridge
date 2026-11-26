// SPDX-License-Identifier: LGPL-2.1-or-later

//! Abstracts TLS and the crypto primitives we need.

mod openssl;

pub use self::openssl::{
    Acceptor, Certificate, Connector, Stream, channel_binding, constant_time_eq, hmac_sha256,
    peer_certificate, random_bytes, sha256,
};

/// Who may vouch for a server certificate.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum Roots {
    /// The system CA store.
    #[default]
    System,
    /// Only the CAs in this PEM file.
    Exclusive(std::path::PathBuf),
}

/// A client certificate for mTLS.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientCert {
    /// The certificate chain, PEM.
    pub cert: std::path::PathBuf,
    /// The private key for it, PEM.
    pub key: std::path::PathBuf,
}

/// Decides whether a server certificate is acceptable, given the certificate
/// and whether it validated against the [`Roots`]. Runs during the handshake,
/// before any client certificate is sent.
pub type Verify = std::sync::Arc<dyn Fn(&Certificate, bool) -> bool + Send + Sync>;

/// Encodes `data` as padded standard base64.
#[must_use]
pub fn base64(data: &[u8]) -> String {
    data_encoding::BASE64.encode(data)
}
