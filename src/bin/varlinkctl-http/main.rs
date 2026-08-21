// SPDX-License-Identifier: LGPL-2.1-or-later

use std::os::fd::BorrowedFd;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use futures_util::{SinkExt, StreamExt};
use log::{debug, warn};
use openssl::ssl::{SslConnector, SslFiletype, SslMethod, SslVerifyMode, SslVersion};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::signal::unix::{SignalKind, signal};
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::{self, Message};
use varlink_http_bridge::TlsChannelBinding;

mod client_auth;
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

/// Candidate client configuration directories, most specific first:
/// 1. `$XDG_CONFIG_HOME/varlinkctl-http/`
/// 2. `~/.config/varlinkctl-http/`
/// 3. `/etc/varlinkctl-http/`
fn config_dirs() -> Vec<PathBuf> {
    [
        std::env::var_os("XDG_CONFIG_HOME").map(|d| PathBuf::from(d).join("varlinkctl-http")),
        std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config/varlinkctl-http")),
        Some(PathBuf::from("/etc/varlinkctl-http")),
    ]
    .into_iter()
    .flatten()
    .collect()
}

/// First [`config_dirs`] entry that exists.
fn config_dir() -> Option<PathBuf> {
    config_dirs().into_iter().find(|d| d.is_dir())
}

/// Recorded server public keys, one line per peer:
///
/// ```text
/// myserver:1031   sha256//SHPiyqubI9L9Nor4n+SKT5CodBou6KDBMeyJlTib/38=
/// ```
///
/// The value is what the daemon prints on startup, so an operator can paste
/// an entry in ahead of time to pin a host explicitly, otherwise it is learned
/// on first contact.
fn known_hosts_path() -> Option<PathBuf> {
    let dirs = config_dirs();
    let dir = dirs.iter().find(|d| d.is_dir()).or(dirs.first())?;
    Some(dir.join("known-hosts"))
}

/// The key recorded for `peer` in the `known-hosts` file at `path`.
fn lookup_known_host(path: &Path, peer: &str) -> Result<Option<String>> {
    if !path.exists() {
        return Ok(None);
    }
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    for line in text.lines() {
        let line = line
            .split_once('#')
            .map_or(line, |(before, _)| before)
            .trim();
        let Some((host, pin)) = line.split_once(char::is_whitespace) else {
            continue;
        };
        if host == peer {
            let pin = pin.trim();
            let pin = pin.strip_prefix("sha256//").unwrap_or(pin);
            if pin.is_empty() {
                bail!("{}: empty key recorded for {peer}", path.display());
            }
            return Ok(Some(pin.to_string()));
        }
    }
    Ok(None)
}

/// Append the key observed for `peer` to the `known-hosts` file.
fn record_known_host(path: &Path, peer: &str, pin: &str) -> Result<()> {
    use std::io::Write as _;

    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    }
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .with_context(|| format!("opening {}", path.display()))?;
    writeln!(f, "{peer}\tsha256//{pin}").with_context(|| format!("writing {}", path.display()))?;
    Ok(())
}

/// Whether the certificate names itself as its own issuer.
fn is_self_signed(cert: &openssl::x509::X509Ref) -> bool {
    cert.issuer_name()
        .try_cmp(cert.subject_name())
        .is_ok_and(std::cmp::Ordering::is_eq)
}

/// Decide whether the server's certificate is acceptable.
///
/// PKI is the real signal, so a validated certificate is always accepted.
/// `known-hosts` governs only self-signed certificates.
///
/// The refusal reason is a message, not an error, because the OpenSSL verify
/// callback can only answer yes or no and stores it for the caller.
fn verify_server_cert(
    cert: &openssl::x509::X509Ref,
    chain_ok: bool,
    recorded_pin: Option<&str>,
    ca_configured: bool,
) -> Result<(), &'static str> {
    if chain_ok {
        // A stale entry is left alone; it still catches a later downgrade.
        return Ok(());
    }
    if ca_configured {
        return Err("certificate does not validate against the configured server-ca-file");
    }
    if !is_self_signed(cert) {
        return Err("certificate does not validate against trust authority");
    }

    // No record yet: first contact, connect_tls learns the key afterwards.
    let Some(pin) = recorded_pin else {
        return Ok(());
    };
    let actual = varlink_http_bridge::public_key_pin(cert)
        .map_err(|_| "cannot fingerprint the server key")?;
    if pin != actual {
        return Err(
            "the server key does not match the one recorded in known-hosts. \
                    Either the server was reinstalled, or this is not the same server.",
        );
    }
    Ok(())
}

/// Build an `SslConnector` with client certs and the system trust store.
///
/// Any refusal reason lands in `refusal`; OpenSSL drops the peer certificate
/// when it aborts, so the caller cannot work it out afterwards.
fn build_ssl_connector(
    recorded_pin: Option<String>,
    ca_configured: bool,
    refusal: Arc<OnceLock<&'static str>>,
) -> Result<SslConnector> {
    let mut builder = SslConnector::builder(SslMethod::tls_client())?;
    // We need tls channel binding per RFC 9266 ("tls-exporter") which
    // is only guaranteed unique with TLS 1.3.
    builder.set_min_proto_version(Some(SslVersion::TLS1_3))?;

    if let Some(dir) = config_dir() {
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

    builder.set_verify_callback(SslVerifyMode::PEER, move |chain_ok, ctx| {
        // errors above the leaf abort on their own
        if ctx.error_depth() != 0 {
            return chain_ok;
        }
        let Some(cert) = ctx.current_cert() else {
            return false;
        };
        match verify_server_cert(cert, chain_ok, recorded_pin.as_deref(), ca_configured) {
            Ok(()) => true,
            Err(why) => {
                let _ = refusal.set(why);
                false
            }
        }
    });

    Ok(builder.build())
}

/// TLS-handshake `stream`, returning it with the RFC 9266 channel binding.
///
/// `peer` identifies the server in `known-hosts` and must be stable and
/// unique per endpoint (`host:port`, or `vsock:CID:PORT`).
///
/// `verify_hostname=false` is for vsock where there is no hostname; the
/// peer certificate is still verified against the CA chain.
async fn connect_tls<S: AsyncStream + 'static>(
    peer: &str,
    domain: &str,
    verify_hostname: bool,
    stream: S,
    error_context: &'static str,
) -> Result<(BoxedStream, Option<TlsChannelBinding>)> {
    let known_hosts = known_hosts_path().context("no configuration directory for known-hosts")?;
    let recorded = lookup_known_host(&known_hosts, peer)?;
    let ca_configured = config_dir().is_some_and(|d| d.join("server-ca-file").exists());

    let refusal = Arc::new(OnceLock::new());
    let connector = build_ssl_connector(recorded.clone(), ca_configured, Arc::clone(&refusal))?;
    let mut config = connector.configure().context("SSL configure")?;
    // Left on so CA-issued certificates are still name-checked; self-signed
    // ones fail here too, which verify_server_cert tolerates.
    config.set_verify_hostname(verify_hostname);
    let ssl = config.into_ssl(domain).context("SSL setup")?;
    let mut tls_stream = tokio_openssl::SslStream::new(ssl, stream)?;

    if let Err(e) = Pin::new(&mut tls_stream).connect().await {
        return Err(anyhow::Error::new(e).context(match refusal.get() {
            Some(why) => format!("{peer}: {why}"),
            None => error_context.to_string(),
        }));
    }

    // First contact with a server the PKI cannot vouch for: learn its key.
    if recorded.is_none()
        && tls_stream.ssl().verify_result() != openssl::x509::X509VerifyResult::OK
        && let Some(cert) = tls_stream.ssl().peer_certificate()
    {
        let pin = varlink_http_bridge::public_key_pin(&cert)?;
        record_known_host(&known_hosts, peer, &pin)?;
        warn!(
            "{peer}: no key recorded, trusting the one presented on first contact. \
             Recorded sha256//{pin} in {}.",
            known_hosts.display()
        );
    }

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
            &format!("vsock:{cid}:{port}"),
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
            &format!("{host}:{port}"),
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
mod pin_tests {
    use super::*;
    use openssl::ssl::SslAcceptor;

    #[test]
    fn known_hosts_lookup_is_per_peer_and_tolerates_formatting() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("known-hosts");
        assert_eq!(lookup_known_host(&path, "a:1031").unwrap(), None);

        std::fs::write(
            &path,
            "# a comment\n\
             a:1031\tsha256//AAAA=\n\
             b:1031   BBBB=\n\
             \n\
             c:1031 sha256//CCCC= # trailing comment\n",
        )
        .unwrap();

        // the daemon's own output pastes in verbatim, prefix and all
        assert_eq!(
            lookup_known_host(&path, "a:1031").unwrap().unwrap(),
            "AAAA="
        );
        // ...and a bare value works too
        assert_eq!(
            lookup_known_host(&path, "b:1031").unwrap().unwrap(),
            "BBBB="
        );
        assert_eq!(
            lookup_known_host(&path, "c:1031").unwrap().unwrap(),
            "CCCC="
        );
        // a different port is a different peer
        assert_eq!(lookup_known_host(&path, "a:1032").unwrap(), None);
    }

    #[test]
    fn recorded_entries_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested").join("known-hosts");
        record_known_host(&path, "host:1031", "AAAA=").unwrap();
        record_known_host(&path, "other:1031", "BBBB=").unwrap();
        assert_eq!(
            lookup_known_host(&path, "host:1031").unwrap().unwrap(),
            "AAAA="
        );
        assert_eq!(
            lookup_known_host(&path, "other:1031").unwrap().unwrap(),
            "BBBB="
        );
    }

    type Identity = (
        openssl::x509::X509,
        openssl::pkey::PKey<openssl::pkey::Private>,
    );

    /// A throwaway identity. Given an `issuer` the certificate is signed by
    /// it and so is not self-signed; without one it signs itself.
    fn identity(cn: &str, issuer: Option<&Identity>, is_ca: bool) -> Identity {
        use openssl::{asn1::Asn1Time, ec, hash::MessageDigest, nid::Nid, pkey::PKey, x509};

        let group = ec::EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        let key = PKey::from_ec_key(ec::EcKey::generate(&group).unwrap()).unwrap();

        let mut nb = x509::X509NameBuilder::new().unwrap();
        nb.append_entry_by_nid(Nid::COMMONNAME, cn).unwrap();
        let name = nb.build();

        let mut b = x509::X509::builder().unwrap();
        b.set_version(2).unwrap();
        b.set_subject_name(&name).unwrap();
        match issuer {
            Some((cert, _)) => b.set_issuer_name(cert.subject_name()).unwrap(),
            None => b.set_issuer_name(&name).unwrap(),
        }
        b.set_pubkey(&key).unwrap();
        b.set_not_before(&Asn1Time::days_from_now(0).unwrap())
            .unwrap();
        b.set_not_after(&Asn1Time::days_from_now(1).unwrap())
            .unwrap();
        if is_ca {
            b.append_extension(
                x509::extension::BasicConstraints::new()
                    .critical()
                    .ca()
                    .build()
                    .unwrap(),
            )
            .unwrap();
        }
        b.sign(issuer.map_or(&key, |(_, k)| k), MessageDigest::sha256())
            .unwrap();
        (b.build(), key)
    }

    /// Rejecting inside the verify callback must abort before we send our own
    /// certificate; rejecting after the handshake would already have leaked it.
    #[tokio::test]
    async fn a_refused_server_never_sees_our_client_certificate() {
        for reject in [true, false] {
            let server = identity("srv", None, false);
            let client = identity("cli", None, false);

            let mut acceptor = SslAcceptor::mozilla_modern_v5(SslMethod::tls_server()).unwrap();
            acceptor.set_certificate(&server.0).unwrap();
            acceptor.set_private_key(&server.1).unwrap();
            acceptor.set_verify_callback(SslVerifyMode::PEER, |_ok, _ctx| true);
            let acceptor = acceptor.build();

            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let (tx, rx) = tokio::sync::oneshot::channel();
            tokio::spawn(async move {
                let (stream, _) = listener.accept().await.unwrap();
                let ssl = openssl::ssl::Ssl::new(acceptor.context()).unwrap();
                let mut tls = tokio_openssl::SslStream::new(ssl, stream).unwrap();
                let _ = Pin::new(&mut tls).accept().await;
                let _ = tx.send(tls.ssl().peer_certificate().is_some());
            });

            let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
            let mut b = SslConnector::builder(SslMethod::tls_client()).unwrap();
            b.set_min_proto_version(Some(SslVersion::TLS1_3)).unwrap();
            b.set_certificate(&client.0).unwrap();
            b.set_private_key(&client.1).unwrap();
            b.set_verify_callback(SslVerifyMode::PEER, move |_ok, _ctx| !reject);
            let mut cfg = b.build().configure().unwrap();
            cfg.set_verify_hostname(false);
            let ssl = cfg.into_ssl("srv").unwrap();
            let mut tls = tokio_openssl::SslStream::new(ssl, stream).unwrap();
            let handshake = Pin::new(&mut tls).connect().await;

            let saw_client_cert = tokio::time::timeout(Duration::from_secs(5), rx)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(handshake.is_err(), reject);
            assert_eq!(
                saw_client_cert, !reject,
                "reject={reject}: the server must only see our certificate when we accept it"
            );
        }
    }

    fn self_signed_pin() -> (Identity, String) {
        let id = identity("leaf", None, false);
        let pin = varlink_http_bridge::public_key_pin(&id.0).unwrap();
        (id, pin)
    }

    #[test]
    fn a_validated_chain_wins_and_known_hosts_is_not_consulted() {
        let (id, _) = self_signed_pin();
        // a deliberately wrong recorded key must not veto the CA
        assert!(verify_server_cert(&id.0, true, Some("AAAA="), false).is_ok());
    }

    #[test]
    fn an_unprovable_issuer_is_refused_even_with_a_recorded_key() {
        let ca = identity("ca", None, true);
        let leaf = identity("leaf", Some(&ca), false);
        let pin = varlink_http_bridge::public_key_pin(&leaf.0).unwrap();
        let err = verify_server_cert(&leaf.0, false, Some(&pin), false).unwrap_err();
        assert!(err.contains("does not validate"), "{err}");
    }

    #[test]
    fn self_signed_is_governed_by_known_hosts() {
        let (id, pin) = self_signed_pin();
        // first contact, connect_tls records afterwards
        assert!(verify_server_cert(&id.0, false, None, false).is_ok());
        assert!(verify_server_cert(&id.0, false, Some(&pin), false).is_ok());
        let err = verify_server_cert(&id.0, false, Some("AAAA="), false).unwrap_err();
        assert!(err.contains("does not match"), "{err}");
    }

    #[test]
    fn a_configured_ca_disables_first_contact_trust() {
        let (id, _) = self_signed_pin();
        let err = verify_server_cert(&id.0, false, None, true).unwrap_err();
        assert!(err.contains("server-ca-file"), "{err}");
    }
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
            assert!(sshauth_client::is_http_unauthorized(&err), "{err:#}");
        }

        #[tokio::test]
        async fn test_ws_handshake_other_error_is_not_unauthorized() {
            let err =
                handshake_error("HTTP/1.1 500 Internal Server Error\r\ncontent-length: 0\r\n\r\n")
                    .await;
            assert!(!sshauth_client::is_http_unauthorized(&err), "{err:#}");
        }
    }
}
