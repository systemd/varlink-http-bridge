// SPDX-License-Identifier: LGPL-2.1-or-later

//! The OpenSSL backend of [`crate::tls`].

use anyhow::Context;

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
