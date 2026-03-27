// SPDX-License-Identifier: LGPL-2.1-or-later

use std::io::{Read, Write};
use std::net::TcpStream;
use std::os::fd::{FromRawFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use log::warn;
use openssl::ssl::{SslConnector, SslFiletype, SslMethod, SslVersion};
use rustix::event::{PollFd, PollFlags, poll};
use tungstenite::{Message, WebSocket};

#[cfg(feature = "sshauth")]
mod sshauth_client;

#[cfg(feature = "sshauth")]
use sshauth_client::maybe_add_auth_headers;
#[cfg(not(feature = "sshauth"))]
fn maybe_add_auth_headers(
    _request: &mut tungstenite::http::Request<()>,
    _uri: &tungstenite::http::Uri,
    _tls_channel_binding: Option<&str>,
) -> Result<()> {
    Ok(())
}

enum Stream {
    Plain(TcpStream),
    Tls(openssl::ssl::SslStream<TcpStream>),
    Vsock(vsock::VsockStream),
    TlsVsock(openssl::ssl::SslStream<vsock::VsockStream>),
}

impl Read for Stream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Stream::Plain(s) => s.read(buf),
            Stream::Tls(s) => s.read(buf),
            Stream::Vsock(s) => s.read(buf),
            Stream::TlsVsock(s) => s.read(buf),
        }
    }
}

impl Write for Stream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            Stream::Plain(s) => s.write(buf),
            Stream::Tls(s) => s.write(buf),
            Stream::Vsock(s) => s.write(buf),
            Stream::TlsVsock(s) => s.write(buf),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Stream::Plain(s) => s.flush(),
            Stream::Tls(s) => s.flush(),
            Stream::Vsock(s) => s.flush(),
            Stream::TlsVsock(s) => s.flush(),
        }
    }
}

impl Stream {
    fn set_nonblocking(&self, nonblocking: bool) -> std::io::Result<()> {
        match self {
            Stream::Plain(s) => s.set_nonblocking(nonblocking),
            Stream::Tls(s) => s.get_ref().set_nonblocking(nonblocking),
            Stream::Vsock(s) => s.set_nonblocking(nonblocking),
            Stream::TlsVsock(s) => s.get_ref().set_nonblocking(nonblocking),
        }
    }

    fn set_read_timeout(&self, dur: Option<Duration>) -> std::io::Result<()> {
        match self {
            Stream::Plain(s) => s.set_read_timeout(dur),
            Stream::Tls(s) => s.get_ref().set_read_timeout(dur),
            Stream::Vsock(s) => s.set_read_timeout(dur),
            Stream::TlsVsock(s) => s.get_ref().set_read_timeout(dur),
        }
    }

    fn set_write_timeout(&self, dur: Option<Duration>) -> std::io::Result<()> {
        match self {
            Stream::Plain(s) => s.set_write_timeout(dur),
            Stream::Tls(s) => s.get_ref().set_write_timeout(dur),
            Stream::Vsock(s) => s.set_write_timeout(dur),
            Stream::TlsVsock(s) => s.get_ref().set_write_timeout(dur),
        }
    }
}

impl std::os::fd::AsFd for Stream {
    fn as_fd(&self) -> std::os::fd::BorrowedFd<'_> {
        match self {
            Stream::Plain(s) => s.as_fd(),
            Stream::Tls(s) => s.get_ref().as_fd(),
            Stream::Vsock(s) => s.as_fd(),
            Stream::TlsVsock(s) => s.get_ref().as_fd(),
        }
    }
}

type Ws = WebSocket<Stream>;

/// Build an `SslConnector` with client certs and a custom CA loaded from the
/// first existing directory:
/// 1. `$XDG_CONFIG_HOME/varlinkctl-http/`
/// 2. `~/.config/varlinkctl-http/`
/// 3. `/etc/varlinkctl-http/`
fn build_ssl_connector() -> Result<SslConnector> {
    let mut builder = SslConnector::builder(SslMethod::tls_client())?;
    // We need tls channel binding per RFC 9266 ("tls-exporter") which
    // is only guaranteed unique with TLS 1.3.
    builder.set_min_proto_version(Some(SslVersion::TLS1_3))?;

    let config_dirs = [
        std::env::var_os("XDG_CONFIG_HOME").map(|d| PathBuf::from(d).join("varlinkctl-http")),
        std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config/varlinkctl-http")),
        Some(PathBuf::from("/etc/varlinkctl-http")),
    ];

    if let Some(dir) = config_dirs.into_iter().flatten().find(|d| d.is_dir()) {
        let cert = dir.join("client-cert-file");
        let key = dir.join("client-key-file");
        let ca = dir.join("server-ca-file");

        if cert.exists() && key.exists() {
            builder
                .set_certificate_chain_file(&cert)
                .with_context(|| format!("loading client certificate {}", cert.display()))?;
            builder
                .set_private_key_file(&key, SslFiletype::PEM)
                .with_context(|| format!("loading client key {}", key.display()))?;
            builder
                .check_private_key()
                .context("client certificate and key do not match")?;
        }

        if ca.exists() {
            builder
                .set_ca_file(&ca)
                .with_context(|| format!("loading CA certificate {}", ca.display()))?;
        }
    }

    Ok(builder.build())
}

/// Parse a `vsock://CID:PORT/path` URL.
///
/// The port defaults to [`varlink_http_bridge::DEFAULT_PORT`] if omitted (`vsock://CID/path`).
fn parse_vsock_url(url: &str) -> Result<(u32, u32, String)> {
    let rest = url
        .strip_prefix("vsock://")
        .ok_or_else(|| anyhow::anyhow!("not a vsock:// URL"))?;

    // Split authority from path
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };

    let (cid, port) = varlink_http_bridge::parse_vsock_cid_port(authority)?;
    Ok((cid, port, path.to_string()))
}

fn connect_vsock(url: &str, use_tls: bool) -> Result<(Stream, String, Option<String>)> {
    let (cid, port, path) = parse_vsock_url(url)?;
    let raw_stream = vsock::VsockStream::connect_with_cid_port(cid, port)
        .with_context(|| format!("vsock connect to CID {cid}:{port} failed"))?;

    if use_tls {
        let connector = build_ssl_connector()?;
        // vsock has no hostnames - skip hostname verification but still
        // verify the peer certificate against the CA chain
        let mut config = connector.configure().context("SSL configure for vsock")?;
        config.set_verify_hostname(false);
        let tls_stream = config.connect("vsock", raw_stream).context(
            "TLS handshake over vsock failed: check client cert if server requires mTLS",
        )?;
        let tls_channel_binding = Some(varlink_http_bridge::export_tls_channel_binding(
            tls_stream.ssl(),
        ));
        let ws_url = format!("wss://vsock{path}");
        Ok((Stream::TlsVsock(tls_stream), ws_url, tls_channel_binding))
    } else {
        let ws_url = format!("ws://vsock{path}");
        Ok((Stream::Vsock(raw_stream), ws_url, None))
    }
}

fn connect_tcp(url: &str) -> Result<(Stream, String, Option<String>)> {
    let ws_url = if let Some(rest) = url.strip_prefix("https://") {
        format!("wss://{rest}")
    } else if let Some(rest) = url.strip_prefix("http://") {
        format!("ws://{rest}")
    } else {
        url.to_string()
    };
    let uri: tungstenite::http::Uri = ws_url.parse().context("invalid WebSocket URL")?;
    let use_tls = uri.scheme_str() == Some("wss");
    let host = uri.host().context("URL has no host")?;
    let port = uri.port_u16().unwrap_or(if use_tls { 443 } else { 80 });

    let tcp = TcpStream::connect((host, port))
        .with_context(|| format!("TCP connect to {host}:{port} failed"))?;
    varlink_http_bridge::set_tcp_keepalive_and_nodelay(&tcp).context("configure client socket")?;

    let stream =
        if use_tls {
            let connector = build_ssl_connector()?;
            Stream::Tls(connector.connect(host, tcp).context(
                "TLS handshake failed: check client certificate if server requires mTLS",
            )?)
        } else {
            Stream::Plain(tcp)
        };

    let tls_channel_binding = match &stream {
        Stream::Tls(ssl_stream) => Some(varlink_http_bridge::export_tls_channel_binding(
            ssl_stream.ssl(),
        )),
        _ => None,
    };

    Ok((stream, ws_url, tls_channel_binding))
}

fn connect_ws(url: &str) -> Result<Ws> {
    use tungstenite::client::IntoClientRequest;

    let (stream, ws_url, tls_channel_binding) = if let Some(rest) = url.strip_prefix("vsock+tls://")
    {
        connect_vsock(&format!("vsock://{rest}"), true)?
    } else if url.starts_with("vsock://") {
        connect_vsock(url, false)?
    } else {
        connect_tcp(url)?
    };

    // Use into_client_request() here as it auto-generates standard WS upgrade headers,
    // then we add our auth headers too
    let uri: tungstenite::http::Uri = ws_url.parse().context("invalid WebSocket URL")?;
    let mut request = ws_url
        .into_client_request()
        .context("building WS request")?;
    // this adds ssh auth headers if ssh-agent is available, once we have more auth methods
    // it may add more
    maybe_add_auth_headers(&mut request, &uri, tls_channel_binding.as_deref())?;

    let ws_context = match &stream {
        Stream::Tls(_) => "WebSocket handshake failed: check client cert if server requires mTLS",
        _ => "WebSocket handshake failed",
    };
    let (ws, _) = tungstenite::client(request, stream).context(ws_context)?;
    Ok(ws)
}

/// Forward all data from the WebSocket to fd3 until it would block or the peer closes.
/// Returns Ok(true) if a Close frame was received.
fn forward_ws_until_would_block(ws: &mut Ws, fd3: &mut UnixStream) -> Result<bool> {
    loop {
        match ws.read() {
            Ok(Message::Binary(data)) => fd3.write_all(&data).context("fd3 write")?,
            Ok(Message::Text(_)) => bail!("unexpected text WebSocket frame"),
            Ok(Message::Close(_)) => return Ok(true),
            Ok(_) => {}
            Err(tungstenite::Error::Io(ref e)) if e.kind() == std::io::ErrorKind::WouldBlock => {
                return Ok(false);
            }
            Err(e) => return Err(e).context("ws read"),
        }
    }
}

fn graceful_close(ws: &mut Ws) -> Result<()> {
    let stream = ws.get_ref();
    stream.set_nonblocking(false)?;
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    stream.set_write_timeout(Some(Duration::from_secs(2)))?;

    // close and wait up to aboves timeout
    ws.close(None)?;
    while ws.can_read() {
        match ws.read() {
            Ok(Message::Close(_)) => break,
            Err(e) => return Err(e).context("waiting for close response"),
            Ok(_) => {}
        }
    }
    Ok(())
}

fn main() -> Result<()> {
    env_logger::init();

    let listen_fds: i32 = std::env::var("LISTEN_FDS")
        .context("LISTEN_FDS is not set")?
        .parse()
        .context("LISTEN_FDS is not a valid integer")?;
    if listen_fds != 1 {
        bail!("LISTEN_FDS must be 1, got {listen_fds}");
    }

    // XXX: once https://github.com/systemd/systemd/issues/40640 is implemented
    // we can remove the env_url and this confusing match
    let env_url = std::env::var("VARLINK_BRIDGE_URL").ok();
    let arg_url = std::env::args().nth(1);
    let bridge_url = match (env_url, arg_url) {
        (Some(_), Some(_)) => bail!("cannot set both VARLINK_BRIDGE_URL and argv[1]"),
        (None, None) => bail!("bridge URL required via VARLINK_BRIDGE_URL or argv[1]"),
        (Some(url), None) | (None, Some(url)) => url,
    };

    // Safety: fd 3 is passed to us via the sd_listen_fds() protocol.
    let fd3 = unsafe { OwnedFd::from_raw_fd(3) };
    rustix::io::fcntl_getfd(&fd3).context("fd 3 is not valid (LISTEN_FDS protocol error?)")?;
    let mut fd3 = UnixStream::from(fd3);

    let mut ws = connect_ws(&bridge_url)?;

    // Set non-blocking so that we deal with incomplete websocket
    // frames in ws.read() - they return WouldBlock now and we can
    // continue when waking up from PollFd next time.
    ws.get_ref().set_nonblocking(true)?;

    let shutdown = Arc::new(AtomicBool::new(false));
    signal_hook::flag::register(signal_hook::consts::SIGINT, Arc::clone(&shutdown))?;
    signal_hook::flag::register(signal_hook::consts::SIGTERM, Arc::clone(&shutdown))?;

    let mut buf = vec![0u8; 8192];
    loop {
        if shutdown.load(Ordering::Relaxed) {
            break;
        }

        let mut pollfds = [
            PollFd::new(&fd3, PollFlags::IN),
            PollFd::new(ws.get_ref(), PollFlags::IN),
        ];
        match poll(&mut pollfds, None) {
            // signal interrupted poll: continue to re-check shutdown flag
            Err(rustix::io::Errno::INTR) => continue,
            result => {
                result?;
            }
        }
        let fd3_revents = pollfds[0].revents();
        let ws_revents = pollfds[1].revents();

        if fd3_revents.contains(PollFlags::IN) {
            let n = fd3.read(&mut buf).context("fd3 read")?;
            if n == 0 {
                break;
            }
            ws.send(Message::Binary(buf[..n].to_vec().into()))
                .context("ws send")?;
        }

        if ws_revents.contains(PollFlags::IN) && forward_ws_until_would_block(&mut ws, &mut fd3)? {
            break; // peer sent Close
        }

        if fd3_revents.contains(PollFlags::HUP) {
            break;
        }
    }

    if let Err(e) = graceful_close(&mut ws) {
        warn!("WebSocket close failed: {e:#}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_vsock_url_cid_and_port() {
        let (cid, port, path) =
            parse_vsock_url("vsock://2:1031/io.systemd.Manager/Describe").unwrap();
        assert_eq!(cid, 2);
        assert_eq!(port, 1031);
        assert_eq!(path, "/io.systemd.Manager/Describe");
    }

    #[test]
    fn test_parse_vsock_url_default_port() {
        let (cid, port, path) = parse_vsock_url("vsock://2/io.systemd.Manager/Describe").unwrap();
        assert_eq!(cid, 2);
        assert_eq!(port, varlink_http_bridge::DEFAULT_PORT);
        assert_eq!(path, "/io.systemd.Manager/Describe");
    }

    #[test]
    fn test_parse_vsock_url_no_path() {
        let (cid, port, path) = parse_vsock_url("vsock://3:5000").unwrap();
        assert_eq!(cid, 3);
        assert_eq!(port, 5000);
        assert_eq!(path, "/");
    }

    #[test]
    fn test_parse_vsock_url_errors() {
        assert!(parse_vsock_url("http://localhost").is_err());
        assert!(parse_vsock_url("vsock://notanumber:1031/path").is_err());
        assert!(parse_vsock_url("vsock://2:notaport/path").is_err());
    }
}
