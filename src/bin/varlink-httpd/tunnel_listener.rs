// SPDX-License-Identifier: LGPL-2.1-or-later

//! The `axum::serve::Listener` for the tunnel a node dials out to a
//! varlink-relayd: every stream the relay opens becomes one accepted
//! connection, so [`TunnelListener`] goes under
//! [`crate::AsyncTlsListener`] like any other listener and TLS and
//! auth apply unchanged. Dialing and keeping the tunnel up is
//! [`crate::tunnel_dialout`]'s job.

use std::sync::Arc;

use anyhow::Result;
use axum::extract::connect_info::Connected;
use axum::serve::IncomingStream;
use log::error;
use tokio::sync::mpsc;

use varlink_http_bridge::node_id::NodeId;
use varlink_http_bridge::tunnel::{MAX_TUNNEL_STREAMS, TunnelStream};

use crate::tunnel_dialout;

/// An `axum::serve::Listener` that accepts the streams a varlink-relayd
/// opens over a tunnel this node dials out to, one connection per
/// stream. Create it with [`TunnelListener::start`], it keeps the
/// tunnel up on its own.
pub(crate) struct TunnelListener {
    conns: mpsc::Receiver<(TunnelStream, TunnelPeer)>,
    describe: Arc<str>,
}

impl TunnelListener {
    pub(crate) fn start(url: &str, node_id: NodeId) -> Result<Self> {
        // h2 caps the open streams, so this never fills and deliver never waits
        let (tx, rx) = mpsc::channel(MAX_TUNNEL_STREAMS as usize);
        let describe: Arc<str> = format!("{url} as node {node_id}").into();
        tunnel_dialout::start(url, node_id, StreamSink::new(tx, Arc::clone(&describe)))?;
        Ok(Self {
            conns: rx,
            describe,
        })
    }
}

impl axum::serve::Listener for TunnelListener {
    type Io = TunnelStream;
    type Addr = TunnelPeer;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        if let Some(conn) = self.conns.recv().await {
            return conn;
        }
        // the dial loop never returns, but the other listeners must keep
        // serving if it ever does
        error!("tunnel dial loop is gone, dial-out is dead");
        std::future::pending().await
    }

    fn local_addr(&self) -> std::io::Result<Self::Addr> {
        Ok(TunnelPeer {
            describe: Arc::clone(&self.describe),
            stream: None,
        })
    }
}

impl Connected<IncomingStream<'_, crate::AsyncTlsListener<TunnelListener>>>
    for crate::VarlinkConnCache
{
    fn connect_info(target: IncomingStream<'_, crate::AsyncTlsListener<TunnelListener>>) -> Self {
        let ssl = target.io().ssl();
        crate::log_tls_connection(ssl, target.remote_addr());
        Self::new(Some(varlink_http_bridge::export_tls_channel_binding(ssl)))
    }
}

/// The peer of a tunnel connection: there is no address, only the
/// tunnel and the h2 stream on it.
#[derive(Clone, Debug)]
pub(crate) struct TunnelPeer {
    describe: Arc<str>,
    // the h2 stream id is the one name both the relay and the bridge
    // see in their logs
    stream: Option<u32>,
}

impl std::fmt::Display for TunnelPeer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.describe)?;
        match self.stream {
            Some(id) => write!(f, " stream {id}"),
            None => Ok(()),
        }
    }
}

/// The dial-out side's end of the listener: every stream the relay
/// opens goes in here and comes out of [`TunnelListener::accept`].
#[derive(Clone)]
pub(crate) struct StreamSink {
    conns: mpsc::Sender<(TunnelStream, TunnelPeer)>,
    describe: Arc<str>,
}

impl StreamSink {
    pub(crate) fn new(conns: mpsc::Sender<(TunnelStream, TunnelPeer)>, describe: Arc<str>) -> Self {
        Self { conns, describe }
    }

    /// Whether the listener is gone, so that no stream can be delivered.
    pub(crate) fn is_closed(&self) -> bool {
        self.conns.is_closed()
    }

    pub(crate) fn deliver(&self, io: TunnelStream, stream: u32) {
        let peer = TunnelPeer {
            describe: Arc::clone(&self.describe),
            stream: Some(stream),
        };
        // only fails once the listener is gone, and serve_tunnel checks that
        let _ = self.conns.try_send((io, peer));
    }
}
