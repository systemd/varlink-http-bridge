// SPDX-License-Identifier: LGPL-2.1-or-later

//! The caller side: accepts `CONNECT <id>`, looks the node up in
//! [`Nodes`] and copies the caller onto one h2 stream to it.

use std::sync::Arc;
use std::time::Instant;

use anyhow::{Context as _, Result, bail};
use bytes::Bytes;
use http::StatusCode;
use log::debug;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use varlink_http_bridge::node_id::NodeId;
use varlink_http_bridge::tunnel::TunnelStream;

use crate::HANDSHAKE_TIMEOUT;
use crate::registry::Nodes;

const MAX_CONNECT_REQUEST: usize = 8 * 1024;
const MAX_CONNECT_HEADERS: usize = 16;

pub(crate) async fn serve(listener: TcpListener, nodes: Arc<Nodes>) -> Result<()> {
    loop {
        let (stream, peer) = varlink_http_bridge::listen::accept_and_configure(&listener).await;
        let nodes = Arc::clone(&nodes);
        tokio::spawn(async move {
            // a public port sees nonsense and callers for nodes that are
            // not connected all day
            if let Err(e) = handle_caller(stream, &nodes).await {
                debug!("caller {peer}: {e:#}");
            }
        });
    }
}

/// Write an HTTP reply that is only a status line, no headers and no body.
async fn deny(stream: &mut TcpStream, status: StatusCode) {
    // best-effort, the connection is torn down anyway
    let _ = stream
        .write_all(format!("HTTP/1.1 {status}\r\n\r\n").as_bytes())
        .await;
}

async fn handle_caller(mut stream: TcpStream, nodes: &Nodes) -> Result<()> {
    let (id, early_data) =
        match tokio::time::timeout(HANDSHAKE_TIMEOUT, read_connect_request(&mut stream)).await {
            Ok(Ok(target)) => target,
            Ok(Err(e)) => {
                deny(&mut stream, StatusCode::BAD_REQUEST).await;
                return Err(e);
            }
            Err(_) => {
                deny(&mut stream, StatusCode::REQUEST_TIMEOUT).await;
                bail!("sent no complete CONNECT request in time");
            }
        };
    let Some(h2) = nodes.get(id) else {
        deny(&mut stream, StatusCode::BAD_GATEWAY).await;
        bail!("no connected node {id}");
    };
    let mut tunnel = match TunnelStream::client(h2).await {
        Ok(tunnel) => tunnel,
        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
            deny(&mut stream, StatusCode::SERVICE_UNAVAILABLE).await;
            bail!("{e}, refusing caller to node {id}");
        }
        Err(e) => {
            deny(&mut stream, StatusCode::BAD_GATEWAY).await;
            return Err(anyhow::Error::new(e).context(format!("opening a stream to node {id}")));
        }
    };
    // the h2 stream id is the one name both ends see in their logs
    let who = format!("node {id} stream {}", tunnel.id());

    stream
        .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
        .await
        .context("confirming CONNECT")?;
    tunnel
        .write_all(&early_data)
        .await
        .with_context(|| format!("{who}: sending early data"))?;
    debug!("{who}: connected");

    let started = Instant::now();
    let (to_node, from_node) = tokio::io::copy_bidirectional(&mut stream, &mut tunnel)
        .await
        .with_context(|| format!("{who}: ended after {:?}", started.elapsed()))?;
    debug!(
        "{who}: done after {:?}, {to_node} bytes to the node, {from_node} back",
        started.elapsed()
    );
    Ok(())
}

/// Read a `CONNECT <id>[:port] HTTP/1.1` request from `stream`, ignoring
/// the port and headers. Returns the node id and the bytes the caller
/// pipelined behind the request.
async fn read_connect_request(stream: &mut TcpStream) -> Result<(NodeId, Bytes)> {
    let mut buf = Vec::with_capacity(256);
    loop {
        if buf.len() >= MAX_CONNECT_REQUEST {
            bail!("CONNECT request too large");
        }
        let n = stream.read_buf(&mut buf).await.context("reading CONNECT")?;
        if n == 0 {
            bail!("caller closed before completing the CONNECT request");
        }
        let mut headers = [httparse::EMPTY_HEADER; MAX_CONNECT_HEADERS];
        let mut req = httparse::Request::new(&mut headers);
        if let httparse::Status::Complete(head_end) =
            req.parse(&buf).context("parsing CONNECT request")?
        {
            if req.method != Some("CONNECT") {
                bail!("expected a CONNECT request, got {:?}", req.method);
            }
            let authority = req.path.context("CONNECT without authority")?;
            // the port is meaningless, a node serves exactly one bridge
            let node_id = authority
                .split(':')
                .next()
                .unwrap_or_default()
                .parse::<NodeId>()
                .with_context(|| format!("CONNECT authority {authority:?}"))?;
            return Ok((node_id, Bytes::copy_from_slice(&buf[head_end..])));
        }
    }
}
