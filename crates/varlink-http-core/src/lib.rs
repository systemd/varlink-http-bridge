// SPDX-License-Identifier: LGPL-2.1-or-later

//! Internal crate for what the varlink-http-bridge daemons and their
//! client share, so that `varlink-http-client` can be used without
//! the server and the server built without the client.
//!
//! To talk to a bridge, use `varlink-http-client`.

pub mod secret_file;
#[cfg(feature = "sshauth")]
pub mod sshauth_token;
pub mod tls;
pub mod ws;

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
    /// Test-only: real bindings come from [`tls::export_tls_channel_binding`].
    #[cfg(any(test, feature = "test-helpers"))]
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// One object-safe stream type for every transport combination a client
/// dials (TCP, vsock, with or without TLS), so what runs on top is
/// instantiated once.
pub trait AsyncStream: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send> AsyncStream for T {}
pub type BoxedStream = Box<dyn AsyncStream>;

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
