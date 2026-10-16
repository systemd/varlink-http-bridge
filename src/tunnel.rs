// SPDX-License-Identifier: LGPL-2.1-or-later

//! A websocket/http2 based varlink tunnel.
//!
//! The node dials out over a WebSocket and both ends run HTTP/2 over
//! it with the roles reversed, the relay as h2 client and the node as
//! h2 server, because only an h2 client may open streams and here the
//! dialing side is the one that must accept them.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use bytes::Bytes;
use h2::{RecvStream, SendStream};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// One h2 stream of a tunnel, carrying one caller, as a byte stream.
/// The relay pipes the caller's TCP connection through it with
/// `copy_bidirectional`; the node accepts it as an incoming connection.
pub struct TunnelStream {
    recv: RecvStream,
    send: SendStream<Bytes>,
    readbuf: Bytes,
    eos_sent: bool,
}

impl TunnelStream {
    #[must_use]
    pub fn new(recv: RecvStream, send: SendStream<Bytes>) -> Self {
        Self {
            recv,
            send,
            readbuf: Bytes::new(),
            eos_sent: false,
        }
    }
}

/// Whether an error out of a copy onto a [`TunnelStream`] came from the
/// h2 side rather than the local byte stream. That decides the log
/// level when a stream ends: a caller hanging up is a debug message, a
/// failing tunnel a warning.
#[must_use]
pub fn is_peer_error(e: &io::Error) -> bool {
    matches!(e.get_ref(), Some(cause) if cause.is::<h2::Error>())
}

fn peer_error(e: h2::Error) -> io::Error {
    io::Error::other(e)
}

impl AsyncRead for TunnelStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        while this.readbuf.is_empty() {
            match ready!(this.recv.poll_data(cx)) {
                None => return Poll::Ready(Ok(())),
                Some(Ok(chunk)) => this.readbuf = chunk,
                Some(Err(e)) => return Poll::Ready(Err(peer_error(e))),
            }
        }
        let n = this.readbuf.len().min(buf.remaining());
        buf.put_slice(&this.readbuf.split_to(n));
        // the window reopens only as bytes leave for the local side, so
        // a reader that stalls stops pulling more off the tunnel
        this.recv
            .flow_control()
            .release_capacity(n)
            .map_err(peer_error)?;
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for TunnelStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        this.send.reserve_capacity(buf.len());
        let available = loop {
            match ready!(this.send.poll_capacity(cx)) {
                None => return Poll::Ready(Err(peer_error(h2::Reason::STREAM_CLOSED.into()))),
                Some(Err(e)) => return Poll::Ready(Err(peer_error(e))),
                Some(Ok(0)) => {}
                Some(Ok(n)) => break n,
            }
        };
        let n = available.min(buf.len());
        this.send
            .send_data(Bytes::copy_from_slice(&buf[..n]), false)
            .map_err(peer_error)?;
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if !this.eos_sent {
            this.send
                .send_data(Bytes::new(), true)
                .map_err(peer_error)?;
            this.eos_sent = true;
        }
        Poll::Ready(Ok(()))
    }
}

/// Per-stream h2 receive window. It caps what one caller can push
/// through a stream at roughly window/RTT. One stream, one way, 16MiB:
///
/// | window        | loopback | 50ms RTT  |
/// | ------------- | -------- | --------- |
/// | 32KiB         | 136MB/s  | 0.60MB/s  |
/// | 256KiB (this) | --       | 4.89MB/s  |
/// | 1MiB          | --       | 17.65MB/s |
///
/// Windows are counters, not allocations: only a stream whose reader
/// stopped holds this much unread. Going higher trades against
/// [`CONNECTION_WINDOW`], this times [`MAX_TUNNEL_STREAMS`], which is
/// what a tunnel end buffers if every caller wedges at once. The way
/// past that is raising the window per connection at runtime once a
/// stream turns out to move volume, as hyper's BDP estimation does.
pub const STREAM_WINDOW: u32 = 256 * 1024;

/// Callers one node serves at once; further callers wait for a slot. An
/// interactive client holds a couple of streams and opens a short one
/// per poll, so this is a dozen such sessions at peak.
///
/// The relay gates admission itself rather than leaving waiters to h2,
/// where a caller that gives up still leaves its HEADERS behind to be
/// drained through the node's slots as a phantom stream.
pub const MAX_TUNNEL_STREAMS: u32 = 64;

/// Room for every stream to hold its full [`STREAM_WINDOW`]: with h2's
/// default of one stream window per connection, a single caller whose
/// service hangs starves every other caller on the tunnel. A promise,
/// not an allocation.
pub const CONNECTION_WINDOW: u32 = STREAM_WINDOW * MAX_TUNNEL_STREAMS;

/// Set up the node's end of a tunnel on the WebSocket it dialled. The
/// returned connection yields one h2 stream per caller the relay lets
/// through, each to be spliced onto the local service. The node is the
/// h2 server, since only the accepting side can advertise the stream
/// limit.
///
/// # Errors
/// If the h2 preface exchange fails.
pub async fn node_handshake<T>(io: T) -> Result<h2::server::Connection<T, Bytes>, h2::Error>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    h2::server::Builder::new()
        .initial_window_size(STREAM_WINDOW)
        .initial_connection_window_size(CONNECTION_WINDOW)
        .max_concurrent_streams(MAX_TUNNEL_STREAMS)
        .handshake(io)
        .await
}

/// Set up the relay's end of a tunnel on the WebSocket a node dialled
/// in with. The returned handle opens one h2 stream per caller, to be
/// spliced onto the caller's connection; the connection must be driven
/// alongside. The windows are the node's, since a caller that stops
/// reading stalls its stream here the way a hung service does there.
///
/// # Errors
/// If the h2 preface exchange fails.
pub async fn relay_handshake<T>(io: T) -> Result<RelayEnd<T>, h2::Error>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    h2::client::Builder::new()
        .initial_window_size(STREAM_WINDOW)
        .initial_connection_window_size(CONNECTION_WINDOW)
        .handshake(io)
        .await
}

/// The handle that opens streams, and the connection to drive alongside.
pub type RelayEnd<T> = (
    h2::client::SendRequest<Bytes>,
    h2::client::Connection<T, Bytes>,
);

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream, duplex};
    use tokio_tungstenite::WebSocketStream;
    use tokio_tungstenite::tungstenite::protocol::Role;

    use crate::ws::WsByteStream;

    async fn ws_pair() -> (WsByteStream<DuplexStream>, WsByteStream<DuplexStream>) {
        let (a, b) = duplex(4096);
        let (client, server) = tokio::join!(
            WebSocketStream::from_raw_socket(a, Role::Client, None),
            WebSocketStream::from_raw_socket(b, Role::Server, None),
        );
        (WsByteStream::new(client), WsByteStream::new(server))
    }

    async fn h2_connect(
        ws: WsByteStream<DuplexStream>,
    ) -> (
        tokio::task::JoinHandle<Result<(), h2::Error>>,
        h2::client::SendRequest<Bytes>,
        h2::client::ResponseFuture,
        SendStream<Bytes>,
    ) {
        let (send_request, conn) = relay_handshake(ws).await.unwrap();
        let conn = tokio::spawn(conn);
        let mut send_request = send_request.ready().await.unwrap();
        let request = http::Request::builder()
            .uri("https://node.invalid/")
            .body(())
            .unwrap();
        let (response, send) = send_request.send_request(request, false).unwrap();
        (conn, send_request, response, send)
    }

    async fn splice<S>(mut stream: TunnelStream, mut io: S) -> io::Result<(u64, u64)>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        tokio::io::copy_bidirectional(&mut io, &mut stream).await
    }

    /// The node side with the stream handed to a service that echoes.
    fn echo_node(
        server_ws: WsByteStream<DuplexStream>,
    ) -> tokio::task::JoinHandle<io::Result<u64>> {
        tokio::spawn(async move {
            let mut conn = node_handshake(server_ws).await.unwrap();
            let (req, mut respond) = conn.accept().await.unwrap().unwrap();
            let body = req.into_body();
            let send = respond
                .send_response(http::Response::new(()), false)
                .unwrap();
            let echo = tokio::spawn(async move {
                let (mut rd, mut wr) = tokio::io::split(TunnelStream::new(body, send));
                let n = tokio::io::copy(&mut rd, &mut wr).await?;
                wr.shutdown().await?;
                Ok(n)
            });
            // accept() also drives the connection I/O, so it must keep
            // being polled while the stream runs; it ends on connection
            // loss, None on a clean close, Err when the transport vanished
            while let Some(Ok(next)) = conn.accept().await {
                drop(next);
            }
            echo.await.unwrap()
        })
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn h2_over_ws_splice_end_to_end() {
        let (client_ws, server_ws) = ws_pair().await;
        let node = echo_node(server_ws);

        let (client_conn, send_request, response, send) = h2_connect(client_ws).await;
        let recv = response.await.unwrap().into_body();
        let (io, mut caller) = duplex(1024);
        let relay = tokio::spawn(splice(TunnelStream::new(recv, send), io));

        let msg = b"hello through four layers";
        caller.write_all(msg).await.unwrap();
        let mut got = [0u8; 25];
        caller.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, msg);

        drop(caller); // EOF ripples through all layers and ends both splices
        let step = std::time::Duration::from_secs(3);
        tokio::time::timeout(step, relay)
            .await
            .expect("relay splice must end on caller EOF")
            .unwrap()
            .unwrap();
        // end the connection the way the real world does: abruptly;
        // the node must treat that as EOF and wind down
        client_conn.abort();
        drop(send_request);
        tokio::time::timeout(step, node)
            .await
            .expect("node side must end once the client is gone")
            .unwrap()
            .unwrap();
    }

    /// However the splice read buffer carves up its capacity, every byte
    /// must come out the other end, in order.
    #[tokio::test(flavor = "multi_thread")]
    async fn many_small_messages_arrive_intact() {
        let (client_ws, server_ws) = ws_pair().await;
        let node = echo_node(server_ws);

        let (client_conn, send_request, response, send) = h2_connect(client_ws).await;
        let recv = response.await.unwrap().into_body();
        let (io, mut caller) = duplex(1024);
        let relay = tokio::spawn(splice(TunnelStream::new(recv, send), io));

        // one round trip per message keeps each splice read to one
        // message, so the buffer is refilled many times over
        let mut total = 0;
        for i in 0..4096u32 {
            let msg: Vec<u8> = (0..=i % 200)
                .map(|j| u8::try_from((i + j) % 251).unwrap())
                .collect();
            caller.write_all(&msg).await.unwrap();
            let mut got = vec![0u8; msg.len()];
            caller.read_exact(&mut got).await.unwrap();
            assert_eq!(got, msg, "message {i} was mangled");
            total += msg.len() as u64;
        }

        drop(caller);
        let step = std::time::Duration::from_secs(3);
        let moved = tokio::time::timeout(step, relay)
            .await
            .expect("relay splice must end on caller EOF")
            .unwrap()
            .unwrap();
        assert_eq!(moved, (total, total));
        client_conn.abort();
        drop(send_request);
        tokio::time::timeout(step, node)
            .await
            .expect("node side must end once the client is gone")
            .unwrap()
            .unwrap();
    }

    /// The caller's TCP reset under the relay.
    struct ResetOnRead;

    impl AsyncRead for ResetOnRead {
        fn poll_read(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            _: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Ready(Err(io::ErrorKind::ConnectionReset.into()))
        }
    }

    impl AsyncWrite for ResetOnRead {
        fn poll_write(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Ok(buf.len()))
        }
        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    /// The local side going away is the caller's own affair and must be
    /// reported as such, so the relay can keep it at debug.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_failing_local_side_is_a_local_error() {
        let (client_ws, server_ws) = ws_pair().await;
        let node = echo_node(server_ws);

        let (client_conn, send_request, response, send) = h2_connect(client_ws).await;
        let recv = response.await.unwrap().into_body();
        let err = splice(TunnelStream::new(recv, send), ResetOnRead)
            .await
            .unwrap_err();
        assert!(!is_peer_error(&err), "expected a local error, got {err:?}");
        assert_eq!(err.kind(), io::ErrorKind::ConnectionReset);

        client_conn.abort();
        drop(send_request);
        tokio::time::timeout(std::time::Duration::from_secs(3), node)
            .await
            .expect("node side must end once the client is gone")
            .unwrap()
            .unwrap_err();
    }

    /// The h2 peer resetting the stream is the tunnel's affair, and
    /// must not be blamed on the local side.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_failing_peer_is_a_peer_error() {
        let (client_ws, server_ws) = ws_pair().await;

        // node side: takes the first bytes, then resets the stream. The
        // relay has its response by then, so the reset can only land in
        // the splice
        let node = tokio::spawn(async move {
            let mut conn = node_handshake(server_ws).await.unwrap();
            let (req, mut respond) = conn.accept().await.unwrap().unwrap();
            let mut body = req.into_body();
            let mut send = respond
                .send_response(http::Response::new(()), false)
                .unwrap();
            let first = async {
                body.data().await.unwrap().unwrap();
                send.send_reset(h2::Reason::INTERNAL_ERROR);
            };
            let drive = async {
                while let Some(Ok(next)) = conn.accept().await {
                    drop(next);
                }
            };
            tokio::join!(first, drive);
        });

        let (client_conn, send_request, response, send) = h2_connect(client_ws).await;
        let recv = response.await.unwrap().into_body();
        let (io, mut caller) = duplex(1024);
        let relay = tokio::spawn(splice(TunnelStream::new(recv, send), io));
        caller.write_all(b"hello?").await.unwrap();

        let step = std::time::Duration::from_secs(3);
        let err = tokio::time::timeout(step, relay)
            .await
            .expect("relay splice must end on the reset")
            .unwrap()
            .unwrap_err();
        assert!(is_peer_error(&err), "expected a peer error, got {err:?}");

        client_conn.abort();
        drop(send_request);
        tokio::time::timeout(step, node)
            .await
            .expect("node side must end once the client is gone")
            .unwrap();
    }

    /// A local side that stops reading for a while must only cost time,
    /// never data.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_stalled_local_side_loses_nothing() {
        const PAYLOAD: usize = 4 * STREAM_WINDOW as usize;
        let (client_ws, server_ws) = ws_pair().await;

        // the local peer stops reading with several windows' worth to go
        let (io, mut peer) = duplex(4096);
        let node = tokio::spawn(async move {
            let mut conn = node_handshake(server_ws).await.unwrap();
            let (req, mut respond) = conn.accept().await.unwrap().unwrap();
            let body = req.into_body();
            let send = respond
                .send_response(http::Response::new(()), false)
                .unwrap();
            let stream = tokio::spawn(splice(TunnelStream::new(body, send), io));
            while let Some(Ok(next)) = conn.accept().await {
                drop(next);
            }
            stream.await.unwrap()
        });

        let (conn, send_request, response, send) = h2_connect(client_ws).await;
        let recv = response.await.unwrap().into_body();
        let sender = tokio::spawn(async move {
            let data: Vec<u8> = (0..PAYLOAD)
                .map(|i| u8::try_from(i % 251).unwrap())
                .collect();
            let mut stream = TunnelStream::new(recv, send);
            stream.write_all(&data).await.unwrap();
            stream.shutdown().await.unwrap();
            (data, stream)
        });

        let mut got = Vec::new();
        let mut head = vec![0u8; 1024];
        peer.read_exact(&mut head).await.unwrap();
        got.extend_from_slice(&head);
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        peer.read_to_end(&mut got).await.unwrap();

        let (expected, stream) = sender.await.unwrap();
        assert_eq!(got.len(), expected.len(), "a stall must not lose bytes");
        assert_eq!(got, expected, "nor reorder or duplicate them");

        // wind the stream down: the local peer going away ends the
        // other direction, and the node's accept loop only returns
        // once the h2 client is gone
        drop(peer);
        drop(stream);
        drop(send_request);
        conn.abort();
        let moved = tokio::time::timeout(std::time::Duration::from_secs(5), node)
            .await
            .expect("the spliced stream must finish once both ends are gone")
            .unwrap()
            .unwrap();
        assert_eq!(moved.1, PAYLOAD as u64);
    }

    /// With a closed window the writer must stall instead of buffering,
    /// and every byte must arrive once the receiver opens the window by
    /// consuming.
    #[tokio::test(flavor = "multi_thread")]
    async fn writes_stall_until_the_window_opens() {
        const PAYLOAD: usize = 64 * 1024;
        let (client_ws, server_ws) = ws_pair().await;

        let (drain_tx, drain_rx) = tokio::sync::oneshot::channel::<()>();
        let node = tokio::spawn(async move {
            let mut conn = h2::server::Builder::new()
                .initial_window_size(1024)
                .handshake::<_, Bytes>(server_ws)
                .await
                .unwrap();
            let (req, mut respond) = conn.accept().await.unwrap().unwrap();
            let mut body = req.into_body();
            let _send = respond
                .send_response(http::Response::new(()), false)
                .unwrap();
            let drive = async {
                while let Some(next) = conn.accept().await {
                    drop(next);
                }
            };
            let read = async {
                drain_rx.await.unwrap();
                let mut total = 0;
                while let Some(chunk) = body.data().await {
                    let chunk = chunk.unwrap();
                    total += chunk.len();
                    body.flow_control().release_capacity(chunk.len()).unwrap();
                }
                total
            };
            tokio::select! {
                total = read => total,
                () = drive => panic!("connection must outlive the body"),
            }
        });

        let (_conn, _send_request, response, send) = h2_connect(client_ws).await;
        let recv = response.await.unwrap().into_body();
        let sender = tokio::spawn(async move {
            let mut stream = TunnelStream::new(recv, send);
            stream.write_all(&vec![0x42; PAYLOAD]).await.unwrap();
            stream.shutdown().await.unwrap();
            stream
        });

        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        assert!(
            !sender.is_finished(),
            "sender must stall on the closed window, not buffer"
        );

        drain_tx.send(()).unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(10), async {
            let _stream = sender.await.unwrap();
            assert_eq!(node.await.unwrap(), PAYLOAD);
        })
        .await
        .expect("draining must unblock the sender");
    }
}
