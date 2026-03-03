// SPDX-License-Identifier: LGPL-2.1-or-later

#[cfg(feature = "sshauth")]
/// Namespace prefix for SSH-based authentication tokens, analogous to
/// `ssh-keygen -Y sign -n <namespace>`.  Binds signatures to this application
/// so they cannot be replayed against other services.
pub const SSHAUTH_MAGIC_PREFIX: [u8; 8] = *b"vhbridge";

#[cfg(feature = "sshauth")]
/// HTTP header carrying the random nonce that is included in the signed
/// token payload to prevent replay attacks.
pub const SSHAUTH_NONCE_HEADER: &str = "x-auth-nonce";

/// TLS channel binding label per RFC 9266 (`tls-exporter`).
///
/// Both client and server call `export_keying_material()` with this label
/// and include the result in the sshauth token so that the signature is
/// bound to the specific TLS session, preventing credential relay attacks.
pub const TLS_CHANNEL_BINDING_LABEL: &str = "EXPORTER-Channel-Binding";

/// Output length (bytes) for TLS channel binding export.
pub const TLS_CHANNEL_BINDING_LEN: usize = 32;
