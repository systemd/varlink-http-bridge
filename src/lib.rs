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

/// Export the TLS channel binding value from an established TLS 1.3 session.
///
/// Returns the base64-encoded result of `export_keying_material` per RFC 9266.
///
/// # Panics
/// Panics if `export_keying_material` fails (should never happen with
/// TLS 1.3) or if the export does not work because of an underlying
/// bug in openssl and returns only zeros (should also never happen).
pub fn export_tls_channel_binding(ssl: &openssl::ssl::SslRef) -> String {
    let mut buf = [0u8; TLS_CHANNEL_BINDING_LEN];
    ssl.export_keying_material(&mut buf, TLS_CHANNEL_BINDING_LABEL, Some(&[]))
        .expect("export_keying_material must succeed with TLS 1.3");
    assert!(
        buf.iter().any(|&b| b != 0),
        "TLS channel binding must not be all zeros"
    );
    openssl::base64::encode_block(&buf)
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
