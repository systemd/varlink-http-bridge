// SPDX-License-Identifier: LGPL-2.1-or-later

//! The node side: accepts nodes dialing out to the relay, registers
//! them in [`Nodes`] and keeps their connection alive with PINGs.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context as _, Result, anyhow, bail};
use http::StatusCode;
use log::{debug, info, warn};
use tokio::net::TcpListener;
use tokio_tungstenite::tungstenite::handshake::server::{
    ErrorResponse, Request as WsRequest, Response as WsResponse,
};

use varlink_http_bridge::BoxedStream;
use varlink_http_bridge::node_id::NodeId;
use varlink_http_bridge::tunnel::{TUNNEL_PATH, client_handshake};
use varlink_http_bridge::ws::WsByteStream;

use crate::HANDSHAKE_TIMEOUT;
use crate::registry::{Nodes, Reservation};

const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(30);
#[cfg(not(test))]
pub(crate) const HEARTBEAT_TIMEOUT: Duration = Duration::from_secs(10);
#[cfg(test)]
pub(crate) const HEARTBEAT_TIMEOUT: Duration = Duration::from_millis(1000);

pub(crate) async fn serve(
    listener: TcpListener,
    tls: Option<openssl::ssl::SslAcceptor>,
    nodes: Arc<Nodes>,
) -> Result<()> {
    loop {
        let (stream, peer) = varlink_http_bridge::listen::accept_and_configure(&listener).await;
        let nodes = Arc::clone(&nodes);
        let tls = tls.clone();
        tokio::spawn(async move {
            let result = match tls {
                Some(tls) => match tokio::time::timeout(
                    HANDSHAKE_TIMEOUT,
                    varlink_http_bridge::listen::tls_accept(&tls, None, stream),
                )
                .await
                {
                    Ok(Ok(stream)) => handle_node(Box::new(stream), &nodes, peer).await,
                    Ok(Err(e)) => Err(e),
                    Err(_) => Err(anyhow!("TLS handshake timed out")),
                },
                None => handle_node(Box::new(stream), &nodes, peer).await,
            };
            // a public port sees scanners and half-open connections all day
            if let Err(e) = result {
                debug!("node connection from {peer}: {e:#}");
            }
        });
    }
}

/// Serve one node connection until it ends: register the node in
/// `nodes` under the id it claims and keep its tunnel alive.
async fn handle_node(stream: BoxedStream, nodes: &Nodes, peer: SocketAddr) -> Result<()> {
    let mut reservation = None;
    #[allow(clippy::result_large_err)]
    let on_ws_upgrade_request = |req: &WsRequest, resp: WsResponse| {
        // the callback is the point where we can return 404/400/409
        // instead of the 101, so the id is reserved in here
        reservation = Some(reserve_from_upgrade(req, nodes)?);
        Ok(resp)
    };
    // wait for the websocket upgrade, anything else is refused by tungstenite::accept
    let ws = tokio::time::timeout(
        HANDSHAKE_TIMEOUT,
        tokio_tungstenite::accept_hdr_async(stream, on_ws_upgrade_request),
    )
    .await
    .map_err(|_| anyhow!("node WebSocket upgrade timed out"))?
    .context("node WebSocket upgrade")?;
    let reservation = reservation.expect("the upgrade callback ran");
    let id = reservation.id;

    let (h2, mut conn) = client_handshake(WsByteStream::new(ws))
        .await
        .context("h2 handshake with node")?;
    let mut ping_pong = conn.ping_pong().expect("first ping_pong handle");

    // h2's client handshake never waits for the peer, so only the first
    // pong proves that a node is listening
    tokio::select! {
        result = &mut conn => {
            return Err(match result {
                Ok(()) => anyhow!("node {id} closed before answering the first PING"),
                Err(e) => anyhow::Error::new(e)
                    .context(format!("node {id} failed before answering the first PING")),
            });
        }
        answered = ping(&mut ping_pong) => if !answered {
            bail!("node {id} did not answer the first PING within {HEARTBEAT_TIMEOUT:?}");
        }
    }
    nodes.attach(&reservation, h2);
    let connected = Instant::now();
    info!("node {id} connected from {peer}");

    let heartbeat = async {
        loop {
            tokio::time::sleep(HEARTBEAT_INTERVAL).await;
            if !ping(&mut ping_pong).await {
                return;
            }
        }
    };
    tokio::select! {
        result = &mut conn => match result {
            Ok(()) => info!("node {id} disconnected after {:?}", connected.elapsed()),
            Err(e) => info!("node {id} connection failed after {:?}: {e}", connected.elapsed()),
        },
        () = heartbeat => {
            warn!("node {id} stopped answering PINGs after {:?}, dropping it", connected.elapsed());
        }
    }
    Ok(())
}

async fn ping(ping_pong: &mut h2::PingPong) -> bool {
    matches!(
        tokio::time::timeout(HEARTBEAT_TIMEOUT, ping_pong.ping(h2::Ping::opaque())).await,
        Ok(Ok(_pong))
    )
}

/// The HTTP response that turns a node's upgrade request down, status line only.
fn reject(status: StatusCode) -> ErrorResponse {
    let mut resp = ErrorResponse::new(None);
    *resp.status_mut() = status;
    resp
}

// the error type is fixed by tungstenite's upgrade callback
#[allow(clippy::result_large_err)]
fn reserve_from_upgrade<'a>(
    req: &WsRequest,
    nodes: &'a Nodes,
) -> Result<Reservation<'a>, ErrorResponse> {
    if req.uri().path() != TUNNEL_PATH {
        return Err(reject(StatusCode::NOT_FOUND));
    }
    // in the query string so that an L7 load balancer can hash on it
    let id = req
        .uri()
        .query()
        .and_then(|q| q.split('&').find_map(|kv| kv.strip_prefix("node_id=")))
        .ok_or_else(|| reject(StatusCode::BAD_REQUEST))?
        .parse::<NodeId>()
        .map_err(|_| reject(StatusCode::BAD_REQUEST))?;
    nodes
        .reserve(id)
        .ok_or_else(|| reject(StatusCode::CONFLICT))
}
