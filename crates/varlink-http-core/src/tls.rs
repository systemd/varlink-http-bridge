// SPDX-License-Identifier: LGPL-2.1-or-later

//! Abstracts TLS and the crypto primitives we need.

mod openssl;

pub use self::openssl::{
    Certificate, Stream, channel_binding, constant_time_eq, exclusive_ca_store, hmac_sha256,
    peer_certificate, public_key_pin, random_bytes, sha256, tls_accept, tls_acceptor_builder,
};

/// Encodes `data` as padded standard base64.
#[must_use]
pub fn base64(data: &[u8]) -> String {
    data_encoding::BASE64.encode(data)
}
