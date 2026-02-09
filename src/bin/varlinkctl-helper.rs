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
use openssl::ssl::{SslConnector, SslFiletype, SslMethod};
use rustix::event::{PollFd, PollFlags, poll};
use tungstenite::{Message, WebSocket};

enum Stream {
    Plain(TcpStream),
    Tls(openssl::ssl::SslStream<TcpStream>),
}

impl Read for Stream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Stream::Plain(s) => s.read(buf),
            Stream::Tls(s) => s.read(buf),
        }
    }
}

impl Write for Stream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            Stream::Plain(s) => s.write(buf),
            Stream::Tls(s) => s.write(buf),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Stream::Plain(s) => s.flush(),
            Stream::Tls(s) => s.flush(),
        }
    }
}

type Ws = WebSocket<Stream>;

fn ws_tcp_stream(ws: &Ws) -> &TcpStream {
    match ws.get_ref() {
        Stream::Plain(s) => s,
        Stream::Tls(s) => s.get_ref(),
    }
}

/// Build an `SslConnector` with client certs and a custom CA loaded from the
/// first existing directory:
/// 1. `$XDG_CONFIG_HOME/varlink-http-bridge/`
/// 2. `~/.config/varlink-http-bridge/`
/// 3. `$CREDENTIALS_DIRECTORY` (systemd, see systemd.exec(5))
fn build_ssl_connector() -> Result<SslConnector> {
    let mut builder = SslConnector::builder(SslMethod::tls_client())?;

    let maybe_credentials_dirs = [
        std::env::var_os("XDG_CONFIG_HOME").map(|d| PathBuf::from(d).join("varlink-http-bridge")),
        std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config/varlink-http-bridge")),
        std::env::var_os("CREDENTIALS_DIRECTORY").map(PathBuf::from),
    ];
    if let Some(dir) = maybe_credentials_dirs
        .into_iter()
        .flatten()
        .find(|d| d.is_dir())
    {
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

fn connect_ws(url: &str) -> Result<Ws> {
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

    let stream =
        if use_tls {
            let connector = build_ssl_connector()?;
            Stream::Tls(connector.connect(host, tcp).context(
                "TLS handshake failed: check client certificate if server requires mTLS",
            )?)
        } else {
            Stream::Plain(tcp)
        };

    let ws_context = if use_tls {
        "WebSocket handshake failed: check client cert if server requires mTLS"
    } else {
        "WebSocket handshake failed"
    };
    let (ws, _) = tungstenite::client(ws_url, stream).context(ws_context)?;
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
    let tcp = ws_tcp_stream(ws);
    tcp.set_nonblocking(false)?;
    tcp.set_read_timeout(Some(Duration::from_secs(2)))?;
    tcp.set_write_timeout(Some(Duration::from_secs(2)))?;

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
    ws_tcp_stream(&ws).set_nonblocking(true)?;

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
            PollFd::new(ws_tcp_stream(&ws), PollFlags::IN),
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
