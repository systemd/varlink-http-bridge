// SPDX-License-Identifier: LGPL-2.1-or-later

//! Dial-out to a varlink-relayd: the node opens one WebSocket to the
//! relay and is the HTTP/2 server on it, the relay is the h2 client
//! so that it can connect to the local varlink-httpd (even though the
//! node did the dialing). The tunnel is kept up for good, and every
//! stream the relay opens on it is handed to the [`StreamSink`] of
//! the [`crate::tunnel_listener::TunnelListener`].

use std::time::{Duration, Instant};

use anyhow::{Context as _, Result, anyhow, bail};
use log::{debug, info, warn};
use tokio::net::TcpStream;

use varlink_http_bridge::BoxedStream;
use varlink_http_bridge::node_id::NodeId;
use varlink_http_bridge::tunnel::{TUNNEL_PATH, TunnelStream, server_handshake};
use varlink_http_bridge::ws::WsByteStream;

use crate::tunnel_listener::StreamSink;

/// Dial `url` and keep the tunnel up from now on, handing every stream
/// the relay opens to `sink`.
pub(crate) fn start(url: &str, node_id: NodeId, sink: StreamSink) -> Result<()> {
    let target = TunnelUrl::parse(url)?;
    let relay_tls = target.tls.then(relay_tls_connector).transpose()?;
    tokio::spawn(dial_loop(target, node_id, relay_tls, sink));
    Ok(())
}

struct TunnelUrl {
    tls: bool,
    host: String,
    port: u16,
}

impl TunnelUrl {
    /// Parse `ws://host[:port]` or `wss://host[:port]`. The URL takes no
    /// path, the tunnel is always at [`TUNNEL_PATH`], and the port
    /// defaults to 2062.
    fn parse(url: &str) -> Result<Self> {
        let uri: http::Uri = url
            .parse()
            .with_context(|| format!("invalid --relay URL {url:?}"))?;
        let tls = match uri.scheme_str() {
            Some("wss") => true,
            Some("ws") => false,
            _ => bail!("--relay must be a ws:// or wss:// URL, got {url:?}"),
        };
        if uri.path() != "/" || uri.query().is_some() {
            bail!("--relay takes no path, {TUNNEL_PATH} is implied: {url:?}");
        }
        let authority = uri
            .authority()
            .with_context(|| format!("--relay needs a host: {url:?}"))?;
        if authority.as_str().contains('@') {
            bail!("--relay takes no credentials: {url:?}");
        }
        // Uri keeps the brackets on an IPv6 literal
        let host = authority
            .host()
            .trim_start_matches('[')
            .trim_end_matches(']');
        // port_u16() is None both without a port and with one out of range
        let port = if authority.as_str().len() > authority.host().len() {
            authority
                .port_u16()
                .with_context(|| format!("invalid port in {url:?}"))?
        } else {
            2062
        };
        Ok(Self {
            tls,
            host: host.to_string(),
            port,
        })
    }

    fn authority(&self) -> String {
        if self.host.contains(':') {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }

    fn ws_url(&self, node_id: NodeId) -> String {
        let scheme = if self.tls { "wss" } else { "ws" };
        format!(
            "{scheme}://{}{TUNNEL_PATH}?node_id={node_id}",
            self.authority()
        )
    }
}

const REDIAL_MIN: Duration = Duration::from_secs(1);
const REDIAL_MAX: Duration = Duration::from_secs(60);
// a tunnel that ends sooner does not reset the backoff, so that a relay
// that closes right after the handshake is not redialed every second by
// every node
const STABLE_TUNNEL: Duration = Duration::from_secs(60);

/// The timeouts of one tunnel, and how often it checks the relay is still there.
struct TunnelTimeouts {
    dial_timeout: Duration,
    heartbeat_interval: Duration,
    heartbeat_timeout: Duration,
}

impl TunnelTimeouts {
    // the heartbeat mirrors the relay's, so both ends give up on a
    // silent path at about the same time
    const DEFAULT: Self = Self {
        dial_timeout: Duration::from_secs(10),
        heartbeat_interval: Duration::from_secs(30),
        heartbeat_timeout: Duration::from_secs(10),
    };
}

type Tunnel = h2::server::Connection<WsByteStream<BoxedStream>, bytes::Bytes>;

/// Keep one tunnel to `target` up forever, redialing whenever it ends,
/// and hand every stream the relay opens to `sink`. Never returns.
async fn dial_loop(
    target: TunnelUrl,
    node_id: NodeId,
    relay_tls: Option<openssl::ssl::SslConnector>,
    sink: StreamSink,
) {
    let relay = target.authority();
    let timeouts = TunnelTimeouts::DEFAULT;
    let mut backoff = REDIAL_MIN;
    // only the first failed dial of an outage is a warning, the retries
    // would otherwise fill the log
    let mut down = false;
    loop {
        match dial(&target, relay_tls.as_ref(), node_id, &timeouts).await {
            Ok(tunnel) => {
                info!("tunnel to {relay} established as node {node_id}");
                down = false;
                let started = Instant::now();
                let result = serve_tunnel(tunnel, &sink, &timeouts).await;
                let lived = started.elapsed();
                match result {
                    Ok(()) => info!("tunnel to {relay} closed after {lived:?}, redialing"),
                    Err(e) => warn!("tunnel to {relay} failed after {lived:?}, redialing: {e:#}"),
                }
                if lived >= STABLE_TUNNEL {
                    backoff = REDIAL_MIN;
                }
            }
            Err(e) if !down => {
                warn!("tunnel to {relay} is down: {e:#}");
                down = true;
            }
            Err(e) => debug!("tunnel to {relay} still down: {e:#}"),
        }
        // a fleet of nodes must not stampede a restarted relay
        tokio::time::sleep(with_jitter(backoff)).await;
        backoff = (backoff * 2).min(REDIAL_MAX);
    }
}

/// A random delay between zero and `base` ("full jitter").
fn with_jitter(base: Duration) -> Duration {
    let mut byte = [0u8; 1];
    // a zero delay on every failure would turn the dial loop into a busy loop
    if openssl::rand::rand_bytes(&mut byte).is_err() {
        return base;
    }
    base.mul_f32(f32::from(byte[0]) / 255.0)
}

async fn dial(
    target: &TunnelUrl,
    relay_tls: Option<&openssl::ssl::SslConnector>,
    node_id: NodeId,
    timeouts: &TunnelTimeouts,
) -> Result<Tunnel> {
    // none of these steps has a timeout of its own, a relay that accepts
    // and then says nothing would park the dial loop for good
    let prelude = async {
        let tcp = TcpStream::connect((target.host.as_str(), target.port))
            .await
            .context("connecting to relay")?;
        varlink_http_bridge::set_tcp_keepalive_and_nodelay(&tcp)?;
        let stream: BoxedStream = match relay_tls {
            Some(connector) => Box::new(tls_connect(connector, &target.host, tcp).await?),
            None => Box::new(tcp),
        };
        let (ws, _response) = tokio_tungstenite::client_async(target.ws_url(node_id), stream)
            .await
            .context("tunnel WebSocket upgrade")?;
        // middleboxes reap long-lived connections without a close frame,
        // that is a routine end of a tunnel and not an error
        server_handshake(WsByteStream::new(ws).abrupt_close_as_eof())
            .await
            .context("h2 handshake with relay")
    };
    tokio::time::timeout(timeouts.dial_timeout, prelude)
        .await
        .map_err(|_| {
            anyhow!(
                "the tunnel handshake did not complete within {:?}",
                timeouts.dial_timeout
            )
        })?
}

async fn serve_tunnel(
    mut conn: Tunnel,
    sink: &StreamSink,
    timeouts: &TunnelTimeouts,
) -> Result<()> {
    let mut ping_pong = conn.ping_pong().expect("first ping_pong handle");
    // the relay pings too, but after e.g. a NAT mapping expired only the
    // node can redial, and without its own PINGs it would wait for the
    // TCP keepalive (~2h by default)
    let heartbeat = async {
        loop {
            tokio::time::sleep(timeouts.heartbeat_interval).await;
            let ping = ping_pong.ping(h2::Ping::opaque());
            match tokio::time::timeout(timeouts.heartbeat_timeout, ping).await {
                Ok(Ok(_pong)) => {}
                Ok(Err(e)) => return anyhow::Error::new(e).context("PING to the relay"),
                Err(_) => {
                    return anyhow!(
                        "no PONG from the relay within {:?}",
                        timeouts.heartbeat_timeout
                    );
                }
            }
        }
    };
    tokio::pin!(heartbeat);
    loop {
        let next = tokio::select! {
            next = TunnelStream::server(&mut conn) => next,
            why = &mut heartbeat => return Err(why),
        };
        let Some(pending) = next.context("tunnel connection failed")? else {
            return Ok(());
        };
        if sink.is_closed() {
            pending.refuse(http::StatusCode::SERVICE_UNAVAILABLE);
            bail!("the server dropped the tunnel listener");
        }
        let stream_id = pending.id();
        // a caller that is gone before its stream was answered does not
        // affect the tunnel
        match pending.accept() {
            Ok(stream) => sink.deliver(stream, stream_id),
            Err(e) => debug!("tunnel stream {stream_id}: {e}"),
        }
    }
}

/// A TLS connector that verifies the relay against the system trust
/// store. Building one is expensive, so build it once and reuse it.
fn relay_tls_connector() -> Result<openssl::ssl::SslConnector> {
    Ok(
        openssl::ssl::SslConnector::builder(openssl::ssl::SslMethod::tls_client())
            .context("TLS connector")?
            .build(),
    )
}

async fn tls_connect(
    connector: &openssl::ssl::SslConnector,
    host: &str,
    tcp: TcpStream,
) -> Result<tokio_openssl::SslStream<TcpStream>> {
    let ssl = connector
        .configure()
        .context("TLS configure")?
        .into_ssl(host)
        .context("TLS setup")?;
    let mut stream = tokio_openssl::SslStream::new(ssl, tcp).context("TLS stream")?;
    std::pin::Pin::new(&mut stream)
        .connect()
        .await
        .context("TLS connect to relay")?;
    Ok(stream)
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::{SinkExt, StreamExt};
    use tokio::net::TcpListener;
    use tokio_tungstenite::tungstenite::Message;

    const TEST_NODE: &str = "0123456789abcdef0123456789abcdef";

    async fn stub_relay() -> (TcpListener, TunnelUrl) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target = TunnelUrl {
            tls: false,
            host: "127.0.0.1".to_string(),
            port: listener.local_addr().unwrap().port(),
        };
        (listener, target)
    }

    fn plain_sink() -> StreamSink {
        let (conns, _rx) = tokio::sync::mpsc::channel(1);
        StreamSink::new(conns, "stub relay".into())
    }

    #[test]
    fn tunnel_url_parsing() {
        let url = TunnelUrl::parse("wss://relay.example:2062").unwrap();
        assert!(url.tls);
        assert_eq!((url.host.as_str(), url.port), ("relay.example", 2062));

        let url = TunnelUrl::parse("ws://relay.example").unwrap();
        assert!(!url.tls);
        assert_eq!((url.host.as_str(), url.port), ("relay.example", 2062));

        let url = TunnelUrl::parse("wss://[2001:db8::1]:2062").unwrap();
        assert_eq!((url.host.as_str(), url.port), ("2001:db8::1", 2062));
        let url = TunnelUrl::parse("ws://[::1]").unwrap();
        assert_eq!((url.host.as_str(), url.port), ("::1", 2062));

        let id: NodeId = TEST_NODE.parse().unwrap();
        assert_eq!(
            TunnelUrl::parse("ws://r:80").unwrap().ws_url(id),
            format!("ws://r:80{TUNNEL_PATH}?node_id={TEST_NODE}")
        );
        assert_eq!(
            TunnelUrl::parse("ws://[::1]:80").unwrap().ws_url(id),
            format!("ws://[::1]:80{TUNNEL_PATH}?node_id={TEST_NODE}")
        );

        for bad in [
            "https://relay.example",
            "ws://relay.example/path",
            "ws://",
            "ws://host:notaport",
            "ws://host:99999",
            // would dial host "2001:db8:" on port 1
            "ws://2001:db8::1",
            "ws://user@relay.example",
        ] {
            assert!(TunnelUrl::parse(bad).is_err(), "must reject {bad:?}");
        }
    }

    #[tokio::test]
    async fn a_relay_that_stops_answering_pings_ends_the_tunnel() {
        let (listener, target) = stub_relay().await;
        // just enough h2 for the node's handshake to succeed (the client
        // preface and an empty SETTINGS), then silence
        tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut ws = tokio_tungstenite::accept_async(tcp).await.unwrap();
            let mut preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
            preface.extend_from_slice(&[0, 0, 0, 4, 0, 0, 0, 0, 0]);
            ws.send(Message::Binary(preface.into())).await.unwrap();
            while let Some(Ok(_)) = ws.next().await {}
        });
        let timeouts = TunnelTimeouts {
            heartbeat_interval: Duration::from_millis(50),
            heartbeat_timeout: Duration::from_millis(100),
            ..TunnelTimeouts::DEFAULT
        };
        let sink = plain_sink();
        let tunnel = dial(&target, None, TEST_NODE.parse().unwrap(), &timeouts)
            .await
            .unwrap();
        let e = tokio::time::timeout(
            Duration::from_secs(5),
            serve_tunnel(tunnel, &sink, &timeouts),
        )
        .await
        .expect("the heartbeat must end a tunnel nobody answers on")
        .expect_err("a silent relay is an error, not a clean close");
        assert!(format!("{e:#}").contains("no PONG"), "{e:#}");
    }

    #[tokio::test]
    async fn a_relay_that_never_finishes_the_handshake_fails_the_dial() {
        let (listener, target) = stub_relay().await;
        tokio::spawn(async move {
            let _held = listener.accept().await.unwrap();
            std::future::pending::<()>().await;
        });
        let timeouts = TunnelTimeouts {
            dial_timeout: Duration::from_millis(200),
            ..TunnelTimeouts::DEFAULT
        };
        let dial = dial(&target, None, TEST_NODE.parse().unwrap(), &timeouts);
        let Err(e) = tokio::time::timeout(Duration::from_secs(5), dial)
            .await
            .expect("the dial must be bounded")
        else {
            panic!("a handshake that never completes is a failed dial");
        };
        assert!(format!("{e:#}").contains("200ms"), "{e:#}");
    }
}
