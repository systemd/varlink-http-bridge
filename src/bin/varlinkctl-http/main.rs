// SPDX-License-Identifier: LGPL-2.1-or-later

// Reduced-feature builds leave some shared auth plumbing unused; the
// default all-features build still gets full dead-code checking.
#![cfg_attr(not(any(feature = "sshauth", feature = "jwtauth")), allow(dead_code))]

use std::os::fd::BorrowedFd;
use std::path::PathBuf;
use std::pin::Pin;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use futures_util::{SinkExt, StreamExt};
use log::{debug, warn};
use openssl::ssl::{SslConnector, SslFiletype, SslMethod, SslVersion};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::signal::unix::{SignalKind, signal};
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::{self, Message};
use varlink_http_bridge::TlsChannelBinding;

mod client_auth;
#[cfg(feature = "jwtauth")]
mod jwt_client;
#[cfg(feature = "sshauth")]
mod sshauth_client;

/// One object-safe type for all transport combinations
/// (TCP/vsock, with/without TLS).
trait AsyncStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> AsyncStream for T {}
type BoxedStream = Box<dyn AsyncStream>;

type Ws = WebSocketStream<BoxedStream>;

// Time to wait until a close needs to be complete before giving up.
const CLOSE_TIMEOUT: Duration = Duration::from_secs(2);
// Time to wait for the whole connection setup: TCP/vsock connect, TLS
// handshake, auth token generation (a hung ssh-agent) and the
// WebSocket upgrade.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

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

/// TLS-handshake `stream`, returning it with the RFC 9266 channel binding.
///
/// `verify_hostname=false` is for vsock where there is no hostname; the
/// peer certificate is still verified against the CA chain.
async fn connect_tls<S: AsyncStream + 'static>(
    domain: &str,
    verify_hostname: bool,
    stream: S,
    error_context: &'static str,
) -> Result<(BoxedStream, Option<TlsChannelBinding>)> {
    let connector = build_ssl_connector()?;
    let mut config = connector.configure().context("SSL configure")?;
    config.set_verify_hostname(verify_hostname);
    let ssl = config.into_ssl(domain).context("SSL setup")?;
    let mut tls_stream = tokio_openssl::SslStream::new(ssl, stream)?;
    Pin::new(&mut tls_stream)
        .connect()
        .await
        .context(error_context)?;
    let tls_channel_binding = varlink_http_bridge::export_tls_channel_binding(tls_stream.ssl());
    Ok((Box::new(tls_stream), Some(tls_channel_binding)))
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

async fn connect_vsock(
    url: &str,
    use_tls: bool,
) -> Result<(BoxedStream, String, Option<TlsChannelBinding>)> {
    let (cid, port, path) = parse_vsock_url(url)?;
    debug!("connecting to vsock CID {cid}:{port} (tls: {use_tls})");
    let raw_stream = tokio_vsock::VsockStream::connect(tokio_vsock::VsockAddr::new(cid, port))
        .await
        .with_context(|| format!("vsock connect to CID {cid}:{port} failed"))?;

    if use_tls {
        let (stream, tls_channel_binding) = connect_tls(
            "vsock",
            false,
            raw_stream,
            "TLS handshake over vsock failed: check client cert if server requires mTLS",
        )
        .await?;
        Ok((stream, format!("wss://vsock{path}"), tls_channel_binding))
    } else {
        Ok((Box::new(raw_stream), format!("ws://vsock{path}"), None))
    }
}

async fn connect_tcp(url: &str) -> Result<(BoxedStream, String, Option<TlsChannelBinding>)> {
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
    // Uri::host() keeps the brackets on IPv6 literals ("[::1]") but
    // TcpStream::connect and TLS verification need the bare address
    let host = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host)
        .to_string();
    let port = uri.port_u16().unwrap_or(if use_tls { 443 } else { 80 });

    debug!("connecting to {host}:{port} (tls: {use_tls})");
    let tcp = tokio::net::TcpStream::connect((host.as_str(), port))
        .await
        .with_context(|| format!("TCP connect to {host}:{port} failed"))?;
    varlink_http_bridge::set_tcp_keepalive_and_nodelay(&tcp).context("configure client socket")?;

    if use_tls {
        let (stream, tls_channel_binding) = connect_tls(
            &host,
            true,
            tcp,
            "TLS handshake failed: check client certificate if server requires mTLS",
        )
        .await?;
        Ok((stream, ws_url, tls_channel_binding))
    } else {
        Ok((Box::new(tcp), ws_url, None))
    }
}

fn resp_body_text(resp: &tungstenite::http::Response<Option<Vec<u8>>>) -> Option<String> {
    resp.body()
        .as_deref()
        .filter(|b| !b.is_empty())
        .map(|b| String::from_utf8_lossy(b).into_owned())
}

/// The TLS channel binding is returned so auth headers can be signed
/// over it before the WebSocket upgrade.
async fn connect_transport(
    url: &str,
) -> Result<(
    BoxedStream,
    tungstenite::http::Request<()>,
    Option<TlsChannelBinding>,
)> {
    use tungstenite::client::IntoClientRequest;

    let (stream, ws_url, tls_channel_binding) = if let Some(rest) = url.strip_prefix("vsock+tls://")
    {
        connect_vsock(&format!("vsock://{rest}"), true).await?
    } else if url.starts_with("vsock://") {
        connect_vsock(url, false).await?
    } else {
        connect_tcp(url).await?
    };

    // Use into_client_request() here as it auto-generates standard WS upgrade headers,
    // then we add our auth headers too
    let request = ws_url
        .into_client_request()
        .context("building WS request")?;
    Ok((stream, request, tls_channel_binding))
}

async fn ws_upgrade(
    request: tungstenite::http::Request<()>,
    stream: BoxedStream,
    is_tls: bool,
) -> Result<Ws> {
    // anyhow keeps the tungstenite::Error downcastable through context():
    // the SSH-retry logic detects a 401 via downcast_ref.
    let (ws, _) = tokio_tungstenite::client_async(request, stream)
        .await
        .map_err(|e| {
            let http_detail = match &e {
                tungstenite::Error::Http(resp) => match resp_body_text(resp) {
                    Some(body) => format!(": HTTP {}: {body}", resp.status()),
                    None => format!(": HTTP {}", resp.status()),
                },
                _ => String::new(),
            };
            let tls_hint = if is_tls {
                " (check client cert if server requires mTLS)"
            } else {
                ""
            };
            anyhow::Error::new(e)
                .context(format!("WebSocket handshake failed{http_detail}{tls_hint}"))
        })?;
    debug!("WebSocket established");
    Ok(ws)
}

/// Our half of the close handshake, bounded so a stuck peer cannot
/// hang the exit.
async fn close_ws(sink: &mut futures_util::stream::SplitSink<Ws, Message>) {
    match tokio::time::timeout(CLOSE_TIMEOUT, sink.close()).await {
        Ok(
            Ok(()) | Err(tungstenite::Error::ConnectionClosed | tungstenite::Error::AlreadyClosed),
        ) => {}
        Ok(Err(e)) => warn!("WebSocket close failed: {e:#}"),
        Err(_) => warn!("timed out closing WebSocket"),
    }
}

/// Forward data between fd3 and the WebSocket in both directions until
/// fd3 hits EOF, the peer closes, or we get SIGINT/SIGTERM.
async fn run_proxy(ws: Ws, fd3: UnixStream) -> Result<()> {
    let mut sigint = signal(SignalKind::interrupt())?;
    let mut sigterm = signal(SignalKind::terminate())?;
    let (mut sink, mut stream) = ws.split();
    let (mut fd3_read, mut fd3_write) = fd3.into_split();

    // fd3 -> websocket. send() completes only once the data is written
    // out, so a slow peer naturally stops us from reading more of fd3.
    // Borrows `sink` (no move) so the peer-close branch below can still
    // send the close reply after this future is dropped.
    let mut up = Box::pin(async {
        let mut buf = bytes::BytesMut::new();
        let mut total: u64 = 0;
        loop {
            // split().freeze() avoids copying each chunk into the message
            buf.reserve(65536);
            let n = fd3_read.read_buf(&mut buf).await.context("fd3 read")?;
            if n == 0 {
                break;
            }
            total += n as u64;
            // when this finishes the buf part that got split is dropped
            // and the next buf.reserve can just reclaim/reuse it
            sink.send(Message::Binary(buf.split().freeze()))
                .await
                .context("ws send")?;
        }
        debug!("fd3 EOF after {total} bytes, closing WebSocket");
        sink.close().await.context("ws close")
    });

    // websocket -> fd3
    let mut down = Box::pin(async move {
        let mut total: u64 = 0;
        while let Some(msg) = stream.next().await {
            match msg.context("ws read")? {
                Message::Binary(data) => {
                    total += data.len() as u64;
                    fd3_write.write_all(&data).await.context("fd3 write")?;
                }
                Message::Text(_) => bail!("unexpected text WebSocket frame"),
                Message::Close(_) => break,
                _ => {}
            }
        }
        debug!("WebSocket -> fd3 finished after {total} bytes");
        Ok(())
    });

    // select is parallel, whatever is first wins
    tokio::select! {
        r = &mut up => {
            r?;
            // all data is delivered at this point; warn if the close
            // handshake fails though
            match tokio::time::timeout(CLOSE_TIMEOUT, &mut down).await {
                Ok(Ok(())) => {}
                Ok(Err(e)) => warn!("error waiting for close response: {e:#}"),
                Err(_) => warn!("timed out waiting for close response"),
            }
        }
        r = &mut down => {
            r?;
            // peer closed first: answer the close handshake before exiting
            drop(up);
            close_ws(&mut sink).await;
        }
        _ = sigint.recv() => {
            debug!("SIGINT, closing WebSocket");
            drop(up);
            close_ws(&mut sink).await;
        }
        _ = sigterm.recv() => {
            debug!("SIGTERM, closing WebSocket");
            drop(up);
            close_ws(&mut sink).await;
        }
    }
    Ok(())
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
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
    let fd3 = unsafe { BorrowedFd::borrow_raw(3) };
    rustix::io::fcntl_getfd(fd3).context("fd 3 is not valid (LISTEN_FDS protocol error?)")?;
    // We are called by systemds "varlinkctl" which monitors fd3 and
    // if that closes immediately kills us. The implication of this is
    // that closing it too early can lead to us getting killed before
    // we had a chance to e.g. print a "connection failed" or similar
    // messages. So we never take ownership of fd3 itself (it stays
    // open until the OS closes it at process exit) and work on a
    // duplicate instead. This guarantees varlinkctl cannot see EOF
    // (and SIGTERM us) before any error output has reached stderr or
    // any cleanup has happened.
    let fd3 = fd3.try_clone_to_owned().context("duplicating fd 3")?;
    let fd3 = std::os::unix::net::UnixStream::from(fd3);
    fd3.set_nonblocking(true)?;
    let fd3 = UnixStream::from_std(fd3)?;

    let ws = tokio::time::timeout(CONNECT_TIMEOUT, client_auth::connect_ws(&bridge_url))
        .await
        .with_context(|| format!("timed out connecting to '{bridge_url}'"))??;

    run_proxy(ws, fd3).await
}

#[cfg(test)]
mod tests {
    use super::*;

    type ServerWs = WebSocketStream<tokio::net::TcpStream>;

    /// Wire `run_proxy` up against an in-process WebSocket server.
    ///
    /// Returns the server end of the WebSocket, our end of the fd3
    /// socketpair and the running proxy task.
    async fn proxy_fixture() -> (ServerWs, UnixStream, tokio::task::JoinHandle<Result<()>>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let accept = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            tokio_tungstenite::accept_async(tcp).await.unwrap()
        });

        let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
        let (ws, _) =
            tokio_tungstenite::client_async(format!("ws://{addr}/"), Box::new(tcp) as BoxedStream)
                .await
                .unwrap();
        let (ours, theirs) = UnixStream::pair().unwrap();
        let proxy = tokio::spawn(run_proxy(ws, theirs));
        (accept.await.unwrap(), ours, proxy)
    }

    /// Bulk uploads must survive a peer that reads slower than fd3
    /// delivers (this killed the poll()-based implementation with
    /// an unhandled `WouldBlock`).
    #[tokio::test]
    async fn test_run_proxy_bulk_upload_backpressure() {
        let (mut ws, ours, proxy) = proxy_fixture().await;
        let server = tokio::spawn(async move {
            // stall so the client's kernel send buffer fills up
            tokio::time::sleep(Duration::from_millis(500)).await;
            let mut received = Vec::new();
            while let Some(msg) = ws.next().await {
                match msg.unwrap() {
                    Message::Binary(data) => received.extend_from_slice(&data),
                    Message::Close(_) => break,
                    _ => {}
                }
            }
            received
        });

        // patterned so lost/duplicated/reordered frames are detected
        let payload: Vec<u8> = (0..16 * 1024 * 1024)
            .map(|i| u8::try_from(i % 251).unwrap())
            .collect();
        let (_ours_read, mut ours_write) = ours.into_split();
        ours_write.write_all(&payload).await.unwrap();
        // EOF makes run_proxy close the WebSocket and return
        drop(ours_write);

        proxy.await.unwrap().expect("run_proxy failed");
        assert!(server.await.unwrap() == payload, "payload mismatch");
    }

    /// Bulk downloads must survive fd3 backpressure: frames the WebSocket
    /// library has already buffered internally must still be delivered
    /// once fd3 drains (this stalled a poll()-based implementation,
    /// where userspace-buffered frames are invisible to `poll()`).
    #[tokio::test]
    async fn test_run_proxy_bulk_download_backpressure() {
        const PAYLOAD_LEN: usize = 16 * 1024 * 1024;
        const CHUNK: usize = 64 * 1024;

        // patterned so lost/duplicated/reordered frames are detected
        let payload: Vec<u8> = (0..PAYLOAD_LEN)
            .map(|i| u8::try_from(i % 251).unwrap())
            .collect();
        let expected = payload.clone();

        let (mut ws, ours, proxy) = proxy_fixture().await;
        let server = tokio::spawn(async move {
            for chunk in payload.chunks(CHUNK) {
                ws.send(Message::Binary(chunk.to_vec().into()))
                    .await
                    .unwrap();
            }
            // idle until the peer closes
            while let Some(msg) = ws.next().await {
                if matches!(msg, Ok(Message::Close(_))) {
                    break;
                }
            }
        });

        // let the proxy run into fd3 backpressure while the server floods
        tokio::time::sleep(Duration::from_millis(500)).await;

        let (mut ours_read, ours_write) = ours.into_split();
        let mut received = vec![0u8; PAYLOAD_LEN];
        tokio::time::timeout(Duration::from_secs(30), ours_read.read_exact(&mut received))
            .await
            .expect("timed out reading download (frames stranded?)")
            .expect("read download");
        assert!(received == expected, "downloaded payload differs");

        // EOF makes run_proxy close the WebSocket and return
        drop(ours_write);
        proxy.await.unwrap().expect("run_proxy failed");
        server.await.unwrap();
    }

    /// When the peer closes first the proxy must answer the close
    /// handshake (instead of just dropping the connection) and exit 0.
    #[tokio::test]
    async fn test_run_proxy_peer_close_first() {
        let (mut ws, mut ours, proxy) = proxy_fixture().await;
        let server = tokio::spawn(async move {
            ws.send(Message::Binary(b"hello".to_vec().into()))
                .await
                .unwrap();
            ws.close(None).await.unwrap();
            // drain until the client's close reply (or connection loss)
            let mut got_close_reply = false;
            while let Some(msg) = ws.next().await {
                if matches!(msg, Ok(Message::Close(_))) {
                    got_close_reply = true;
                }
            }
            got_close_reply
        });

        let mut hello = [0u8; 5];
        ours.read_exact(&mut hello).await.unwrap();
        assert_eq!(&hello, b"hello");

        proxy.await.unwrap().expect("run_proxy failed");
        assert!(server.await.unwrap(), "server never got a close reply");
    }

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

    #[cfg(feature = "sshauth")]
    mod sshauth {
        use super::*;

        /// Wraps the handshake error the same way `ws_upgrade` does.
        async fn handshake_error(response: &'static str) -> anyhow::Error {
            // capacity must fit the unread client request or the handshake deadlocks
            let (client, mut server) = tokio::io::duplex(64 * 1024);
            server.write_all(response.as_bytes()).await.unwrap();
            tokio_tungstenite::client_async("ws://localhost/", client)
                .await
                .map(|_| ())
                .map_err(|e| anyhow::Error::new(e).context("WebSocket handshake failed"))
                .expect_err("handshake should fail")
        }

        /// A handshake 401 must stay downcastable to `tungstenite::Error::Http`
        /// through the anyhow context so the sshauth retry logic can detect it.
        #[tokio::test]
        async fn test_ws_handshake_401_is_detected_as_unauthorized() {
            let err =
                handshake_error("HTTP/1.1 401 Unauthorized\r\ncontent-length: 0\r\n\r\n").await;
            assert!(client_auth::is_http_unauthorized(&err), "{err:#}");
        }

        #[tokio::test]
        async fn test_ws_handshake_other_error_is_not_unauthorized() {
            let err =
                handshake_error("HTTP/1.1 500 Internal Server Error\r\ncontent-length: 0\r\n\r\n")
                    .await;
            assert!(!client_auth::is_http_unauthorized(&err), "{err:#}");
        }
    }
}
