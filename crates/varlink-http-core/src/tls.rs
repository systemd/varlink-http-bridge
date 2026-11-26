// SPDX-License-Identifier: LGPL-2.1-or-later

//! Abstracts TLS and the crypto primitives we need.

mod openssl;

pub use self::openssl::{constant_time_eq, hmac_sha256, random_bytes, sha256};

/// Encodes `data` as padded standard base64.
#[must_use]
pub fn base64(data: &[u8]) -> String {
    data_encoding::BASE64.encode(data)
}
