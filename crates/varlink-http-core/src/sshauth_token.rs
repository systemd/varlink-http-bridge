// SPDX-License-Identifier: LGPL-2.1-or-later

//! The sshauth token format shared by varlink-httpd and varlinkctl-http.
//! Everything that determines whether a signature verifies lives here so
//! the signing and verifying sides cannot drift apart.

use anyhow::{Context, Result};
use http::HeaderMap;
pub use sshauth::UnverifiedToken;
use sshauth::signer::TokenSignerBuilder;
use sshauth::{PrivateKey, PublicKey, TokenSigner, VerifiedToken};

use crate::TlsChannelBinding;

/// Namespace prefix for SSH-based authentication tokens, analogous to
/// `ssh-keygen -Y sign -n <namespace>`.  Binds signatures to this application
/// so they cannot be replayed against other services.
const SSHAUTH_MAGIC_PREFIX: [u8; 8] = *b"vhbridge";

/// HTTP header carrying the random nonce that is included in the signed
/// token payload to prevent replay attacks.
pub const SSHAUTH_NONCE_HEADER: &str = "x-auth-nonce";

/// A signer for a private key held in memory.
///
/// # Errors
/// Returns an error if the key algorithm is not supported for signing.
pub fn signer_from_private_key(key: PrivateKey) -> Result<TokenSigner> {
    signer_for(TokenSigner::using_private_key(key)?)
}

/// A signer that delegates to the ssh-agent at `auth_sock` for `key`.
///
/// # Errors
/// Returns an error if the agent socket cannot be used.
pub fn signer_from_agent(auth_sock: &str, key: PublicKey) -> Result<TokenSigner> {
    let mut builder = TokenSigner::using_authsock(auth_sock)?;
    builder.key(key);
    signer_for(builder)
}

fn signer_for(mut builder: TokenSignerBuilder) -> Result<TokenSigner> {
    builder
        .include_fingerprint(true)
        .magic_prefix(SSHAUTH_MAGIC_PREFIX);
    builder.build()
}

fn accept_header_value(headers: &HeaderMap) -> String {
    headers
        .get_all(http::header::ACCEPT)
        .iter()
        .map(|v| String::from_utf8_lossy(v.as_bytes()))
        .collect::<Vec<_>>()
        .join(", ")
}

/// The parts of the request covered by the signature.
pub struct SignedParts<'a> {
    method: &'a str,
    path_and_query: &'a str,
    accept: String,
    nonce: &'a str,
    tls_channel_binding: &'a TlsChannelBinding,
}

impl<'a> SignedParts<'a> {
    #[must_use]
    pub fn new(
        method: &'a str,
        path_and_query: &'a str,
        nonce: &'a str,
        headers: &HeaderMap,
        tls_channel_binding: &'a TlsChannelBinding,
    ) -> Self {
        Self {
            method,
            path_and_query,
            accept: accept_header_value(headers),
            nonce,
            tls_channel_binding,
        }
    }

    /// Return the encoded token for the `Authorization: Bearer` header.
    ///
    /// # Errors
    /// Returns an error if the key or the agent refuses to sign.
    pub async fn sign(&self, signer: &TokenSigner) -> Result<String> {
        let mut tb = signer.sign_for();
        tb.actions(self.actions());
        Ok(tb.sign().await?.encode())
    }

    /// Check a token against `keys`.
    ///
    /// # Errors
    /// Returns an error if the token is malformed, too old, not signed
    /// over these parts, or signed by a key that is not in `keys`.
    pub fn verify(
        &self,
        token: &UnverifiedToken,
        max_skew_seconds: u64,
        keys: &[PublicKey],
    ) -> Result<VerifiedToken> {
        token
            .verify_for()
            .magic_prefix(SSHAUTH_MAGIC_PREFIX)
            .max_skew_seconds(max_skew_seconds)
            .actions(self.actions())
            .with_keys(keys)
            .context("token verification failed")
    }

    fn actions(&self) -> [(&'static str, &str); 5] {
        [
            ("method", self.method),
            ("path", self.path_and_query),
            ("accept", &self.accept),
            ("nonce", self.nonce),
            ("tls-channel-binding", self.tls_channel_binding.as_str()),
        ]
    }
}
