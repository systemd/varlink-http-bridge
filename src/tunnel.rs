// SPDX-License-Identifier: LGPL-2.1-or-later

//! A websocket/http2 based varlink tunnel.
//!
//! The node dials out over a WebSocket and both ends run HTTP/2 over
//! it with the roles reversed, the relay as h2 client and the node as
//! h2 server, because only an h2 client may open streams and here the
//! dialing side is the one that must accept them.
//!
//! The node calls [`server_handshake`] on its WebSocket and then
//! [`TunnelStream::server`] for every stream the relay opens, which it
//! answers with [`PendingStream::accept`] or [`PendingStream::refuse`].
//! The relay calls [`client_handshake`] and then [`TunnelStream::client`]
//! for every caller.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, ready};
use std::time::Duration;

use bytes::Bytes;
use h2::{RecvStream, SendStream};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::ws::drain;

// a macro so that the paths derived from it are built at compile time
macro_rules! tunnel_protocol {
    () => {
        "varlink-tunnel-v1"
    };
}

/// The tunnel protocol's name and version, which every stream's
/// CONNECT names. [`TunnelStream::server`] refuses any other request,
/// so a relay and a node from different protocol generations fail at
/// the first stream instead of talking past each other.
pub const TUNNEL_PROTOCOL: &str = tunnel_protocol!();

/// Per-stream h2 receive window. It caps what one caller can push
/// through a stream at roughly window/RTT. Measured copying 16MiB one
/// way through a single stream, `--` not measured:
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
pub const MAX_TUNNEL_STREAMS: u32 = 64;

/// Room for every stream to hold its full [`STREAM_WINDOW`]: with h2's
/// default of one stream window per connection, a single caller whose
/// service hangs starves every other caller on the tunnel. A promise,
/// not an allocation.
pub const CONNECTION_WINDOW: u32 = STREAM_WINDOW * MAX_TUNNEL_STREAMS;

/// How long [`TunnelStream::client`] waits for the node to answer a new
/// stream. A node whose accept loop is wedged would otherwise hold every
/// new caller forever, and each of those waits is also a stream slot
/// taken on the connection.
pub const STREAM_OPEN_TIMEOUT: Duration = Duration::from_secs(10);

/// The error for a stream the peer did not answer within
/// [`STREAM_OPEN_TIMEOUT`]: `WouldBlock` if the peer is at its stream
/// limit and the stream was never sent, `TimedOut` otherwise.
fn open_timeout_error(h2: &mut h2::client::SendRequest<Bytes>) -> io::Error {
    // h2 keeps the handle not ready while its stream is queued behind
    // the peer's limit
    let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
    if h2.poll_ready(&mut cx).is_pending() {
        return io::Error::new(
            io::ErrorKind::WouldBlock,
            format!(
                "peer at its limit of {} streams for {STREAM_OPEN_TIMEOUT:?}",
                h2.current_max_send_streams()
            ),
        );
    }
    io::Error::new(
        io::ErrorKind::TimedOut,
        format!("no answer to the stream within {STREAM_OPEN_TIMEOUT:?}"),
    )
}

/// The h2 server's end of a tunnel connection.
///
/// `io` is the WebSocket it dialled the relay with, wrapped in a
/// [`WsByteStream`](crate::ws::WsByteStream). The returned connection
/// is what [`TunnelStream::server`] takes streams from, and it is only
/// driven while that is being awaited.
///
/// # Errors
/// If the h2 preface exchange fails.
pub async fn server_handshake<T>(io: T) -> Result<h2::server::Connection<T, Bytes>, h2::Error>
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

/// The h2 client's end of a tunnel connection.
///
/// `io` is the WebSocket a node dialled in with, wrapped in a
/// [`WsByteStream`](crate::ws::WsByteStream). The returned handle is
/// what [`TunnelStream::client`] opens streams on; the returned
/// connection must be driven alongside, typically spawned, and the
/// handle is dead once it ends.
///
/// # Errors
/// If the h2 preface exchange fails.
pub async fn client_handshake<T>(io: T) -> Result<ClientEnd<T>, h2::Error>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    // the node's windows: a caller that stops reading stalls its stream
    // here the way a hung service does there
    h2::client::Builder::new()
        .initial_window_size(STREAM_WINDOW)
        .initial_connection_window_size(CONNECTION_WINDOW)
        // nothing here consumes pushed streams, so a node sending
        // PUSH_PROMISE is a protocol error rather than a reserved stream
        // parked until its parent closes
        .enable_push(false)
        .handshake(io)
        .await
}

/// The handle that opens streams, and the connection to drive alongside.
pub type ClientEnd<T> = (
    h2::client::SendRequest<Bytes>,
    h2::client::Connection<T, Bytes>,
);

/// The path on the relay a node dials to open its tunnel, named after
/// [`TUNNEL_PROTOCOL`] so that the two ends agree on one version.
pub const TUNNEL_PATH: &str = concat!("/", tunnel_protocol!());

/// One h2 stream of a tunnel, carrying one caller, as a byte stream.
/// The relay pipes the caller's TCP connection through it with
/// `copy_bidirectional`; the node accepts it as an incoming connection.
#[derive(Debug)]
pub struct TunnelStream {
    recv: RecvStream,
    send: SendStream<Bytes>,
    readbuf: Bytes,
    eos_sent: bool,
}

impl TunnelStream {
    fn new(recv: RecvStream, send: SendStream<Bytes>) -> Self {
        Self {
            recv,
            send,
            readbuf: Bytes::new(),
            eos_sent: false,
        }
    }

    /// Open a stream on the h2 client's end, which is the relay's, for
    /// one caller. `h2` is a clone of the handle `client_handshake`
    /// returned. Waits for the peer's answer, so the stream is
    /// established once this returns.
    ///
    /// # Errors
    /// If the connection is gone, the stream fails before it is
    /// answered, the peer does not answer within
    /// [`STREAM_OPEN_TIMEOUT`], or it answers with anything but 200. A
    /// peer that is at [`MAX_TUNNEL_STREAMS`] for that long is reported
    /// as [`io::ErrorKind::WouldBlock`] rather than as not answering.
    pub async fn client(h2: h2::client::SendRequest<Bytes>) -> io::Result<Self> {
        let mut h2 = h2.ready().await.map_err(io::Error::other)?;
        let request = http::Request::connect(TUNNEL_PROTOCOL)
            .body(())
            .map_err(io::Error::other)?;
        let (mut response, send) = h2.send_request(request, false).map_err(io::Error::other)?;
        let Ok(response) = tokio::time::timeout(STREAM_OPEN_TIMEOUT, &mut response).await else {
            // dropping (response, send) via return here resets the
            // stream, so the node sees the caller is gone
            return Err(open_timeout_error(&mut h2));
        };
        let response = response.map_err(io::Error::other)?;
        if response.status() != http::StatusCode::OK {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                format!("stream refused with status {}", response.status()),
            ));
        }
        Ok(Self::new(response.into_body(), send))
    }

    /// The next stream the peer opened, on the h2 server's end, which
    /// is the node's. The stream is not answered yet: the node
    /// [`accept`](PendingStream::accept)s it once it has something to
    /// connect it to, or [`refuse`](PendingStream::refuse)s it, so a
    /// node that cannot serve the stream can say so instead of hanging
    /// up on an established one. A stream that is not a `CONNECT` to
    /// [`TUNNEL_PROTOCOL`] is refused with 400 and skipped. `None` once
    /// the connection has closed.
    ///
    /// This also drives the connection, so it must be polled whenever
    /// streams are in flight. It is safe to use in a `select!`.
    ///
    /// # Errors
    /// If the connection fails.
    pub async fn server<T>(
        conn: &mut h2::server::Connection<T, Bytes>,
    ) -> io::Result<Option<PendingStream>>
    where
        T: AsyncRead + AsyncWrite + Unpin,
    {
        loop {
            let Some(next) = conn.accept().await else {
                return Ok(None);
            };
            let (request, respond) = next.map_err(io::Error::other)?;
            let authority = request.uri().authority().map(http::uri::Authority::as_str);
            if request.method() != http::Method::CONNECT || authority != Some(TUNNEL_PROTOCOL) {
                log::warn!(
                    "tunnel stream {}: refusing {} {}, not {TUNNEL_PROTOCOL}",
                    u32::from(respond.stream_id()),
                    request.method(),
                    request.uri()
                );
                PendingStream {
                    recv: request.into_body(),
                    respond,
                }
                .refuse(http::StatusCode::BAD_REQUEST);
                continue;
            }
            return Ok(Some(PendingStream {
                recv: request.into_body(),
                respond,
            }));
        }
    }

    /// The h2 stream id, the one name for this stream both ends see.
    #[must_use]
    pub fn id(&self) -> u32 {
        self.send.stream_id().into()
    }
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
                Some(Err(e)) => return Poll::Ready(Err(io::Error::other(e))),
            }
        }
        let n = this.readbuf.len().min(buf.remaining());
        // the window reopens only as bytes leave for the local side, so
        // a reader that stalls stops pulling more off the tunnel
        this.recv
            .flow_control()
            .release_capacity(n)
            .map_err(io::Error::other)?;
        drain(&mut this.readbuf, buf);
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for TunnelStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        // poll_capacity stays Pending while the computed capacity is 0
        // (since h2 0.4.15, see Cargo.toml), so an empty write would hang
        // until unrelated capacity arrived
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let this = self.get_mut();
        // reserve_capacity sets the request, it does not add to it, so
        // asking for the whole buffer every time is right
        this.send.reserve_capacity(buf.len());
        let available = match ready!(this.send.poll_capacity(cx)) {
            Some(Ok(n)) => n,
            Some(Err(e)) => return Poll::Ready(Err(io::Error::other(e))),
            None if this.eos_sent => {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "write after shutdown",
                )));
            }
            // closed under us by the peer's reset or the connection
            // going. The read side would tell which too, but a splice
            // stops at whichever side fails first, so ask h2 here
            None => {
                return Poll::Ready(Err(match this.send.poll_reset(cx) {
                    Poll::Ready(Ok(reason)) => io::Error::other(h2::Error::from(reason)),
                    Poll::Ready(Err(e)) => io::Error::other(e),
                    Poll::Pending => io::Error::other("stream closed"),
                }));
            }
        };
        let n = available.min(buf.len());
        this.send
            .send_data(Bytes::copy_from_slice(&buf[..n]), false)
            .map_err(io::Error::other)?;
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.eos_sent {
            return Poll::Ready(Ok(()));
        }
        this.send
            .send_data(Bytes::new(), true)
            .map_err(io::Error::other)?;
        this.eos_sent = true;
        Poll::Ready(Ok(()))
    }
}

/// A stream the relay opened that the node has not answered yet.
/// Dropping it unanswered resets the stream, which the relay's caller
/// sees as a reset rather than a refusal.
#[derive(Debug)]
pub struct PendingStream {
    recv: RecvStream,
    respond: h2::server::SendResponse<Bytes>,
}

impl PendingStream {
    /// The h2 stream id, the one name for this stream both ends see.
    #[must_use]
    pub fn id(&self) -> u32 {
        self.respond.stream_id().into()
    }

    /// Answer with 200, so the stream is established once this returns.
    ///
    /// # Errors
    /// If the caller was gone before it was answered, which is only
    /// that caller's business: the connection carries on.
    pub fn accept(self) -> io::Result<TunnelStream> {
        let Self { recv, mut respond } = self;
        let send = respond
            .send_response(http::Response::new(()), false)
            .map_err(io::Error::other)?;
        Ok(TunnelStream::new(recv, send))
    }

    /// Answer with `status` and end the stream, which the relay's
    /// caller sees as `ConnectionRefused` carrying that status.
    pub fn refuse(mut self, status: http::StatusCode) {
        let mut refused = http::Response::new(());
        *refused.status_mut() = status;
        // the caller is gone if this fails, which is what it wanted anyway
        let _ = self.respond.send_response(refused, true);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream, duplex};

    use crate::ws::WsByteStream;
    use crate::ws::test_helpers::ws_pair;

    async fn h2_connect(
        ws: WsByteStream<DuplexStream>,
    ) -> (
        tokio::task::JoinHandle<Result<(), h2::Error>>,
        h2::client::SendRequest<Bytes>,
    ) {
        let (send_request, conn) = client_handshake(ws).await.unwrap();
        (tokio::spawn(conn), send_request)
    }

    /// `accept()` drives the connection I/O, so it must keep being polled
    /// while streams run; it ends on connection loss, None on a clean
    /// close, Err when the transport vanished.
    async fn drive_until_closed<T>(conn: &mut h2::server::Connection<T, Bytes>)
    where
        T: AsyncRead + AsyncWrite + Unpin,
    {
        while let Some(Ok(next)) = conn.accept().await {
            drop(next);
        }
    }

    /// End the connection the way the real world does, abruptly, and
    /// wait for the node side to wind down on that.
    async fn end_connection<T>(
        client_conn: tokio::task::JoinHandle<Result<(), h2::Error>>,
        send_request: h2::client::SendRequest<Bytes>,
        node: tokio::task::JoinHandle<T>,
    ) -> T {
        client_conn.abort();
        drop(send_request);
        tokio::time::timeout(std::time::Duration::from_secs(3), node)
            .await
            .expect("node side must end once the client is gone")
            .unwrap()
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
            let mut conn = server_handshake(server_ws).await.unwrap();
            let stream = TunnelStream::server(&mut conn)
                .await
                .unwrap()
                .unwrap()
                .accept()
                .unwrap();
            let echo = tokio::spawn(async move {
                let (mut rd, mut wr) = tokio::io::split(stream);
                let n = tokio::io::copy(&mut rd, &mut wr).await?;
                wr.shutdown().await?;
                Ok(n)
            });
            drive_until_closed(&mut conn).await;
            echo.await.unwrap()
        })
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn h2_over_ws_splice_end_to_end() {
        let (client_ws, server_ws) = ws_pair().await;
        let node = echo_node(server_ws);

        let (client_conn, send_request) = h2_connect(client_ws).await;
        let (io, mut caller) = duplex(1024);
        let relay = tokio::spawn(splice(
            TunnelStream::client(send_request.clone()).await.unwrap(),
            io,
        ));

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
        end_connection(client_conn, send_request, node)
            .await
            .unwrap();
    }

    /// However the splice read buffer carves up its capacity, every byte
    /// must come out the other end, in order.
    #[tokio::test(flavor = "multi_thread")]
    async fn many_small_messages_arrive_intact() {
        let (client_ws, server_ws) = ws_pair().await;
        let node = echo_node(server_ws);

        let (client_conn, send_request) = h2_connect(client_ws).await;
        let (io, mut caller) = duplex(1024);
        let relay = tokio::spawn(splice(
            TunnelStream::client(send_request.clone()).await.unwrap(),
            io,
        ));

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
        end_connection(client_conn, send_request, node)
            .await
            .unwrap();
    }

    /// What h2 said about the stream, if the error came from it at all.
    fn h2_error(e: &io::Error) -> Option<&h2::Error> {
        e.get_ref().and_then(|e| e.downcast_ref())
    }

    fn h2_reason(e: &io::Error) -> Option<h2::Reason> {
        h2_error(e).and_then(h2::Error::reason)
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

    /// The local side's own error comes out of the splice as it went in.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_failing_local_side_is_a_local_error() {
        let (client_ws, server_ws) = ws_pair().await;
        let node = echo_node(server_ws);

        let (client_conn, send_request) = h2_connect(client_ws).await;
        let err = splice(
            TunnelStream::client(send_request.clone()).await.unwrap(),
            ResetOnRead,
        )
        .await
        .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::ConnectionReset);
        assert!(h2_error(&err).is_none(), "got {err:?}");

        end_connection(client_conn, send_request, node)
            .await
            .unwrap_err();
    }

    /// A node that answers the stream, takes the caller's first bytes
    /// and then ends the stream as `end` sees fit. The relay has its
    /// response by then, so the ending can only land in the stream.
    fn node_ending_with<F>(
        server_ws: WsByteStream<DuplexStream>,
        end: F,
    ) -> tokio::task::JoinHandle<()>
    where
        F: FnOnce(RecvStream, SendStream<Bytes>) + Send + 'static,
    {
        tokio::spawn(async move {
            let mut conn = server_handshake(server_ws).await.unwrap();
            let (req, mut respond) = conn.accept().await.unwrap().unwrap();
            let mut body = req.into_body();
            let send = respond
                .send_response(http::Response::new(()), false)
                .unwrap();
            // a handle on the stream too, which server() consumes
            drop(respond);
            let first = async {
                body.data().await.unwrap().unwrap();
                end(body, send);
            };
            tokio::join!(first, drive_until_closed(&mut conn));
        })
    }

    /// Splice a caller through [`node_ending_with`] and return what
    /// ended the splice.
    async fn splice_error_from_node_ending_with<F>(end: F) -> io::Error
    where
        F: FnOnce(RecvStream, SendStream<Bytes>) + Send + 'static,
    {
        let (client_ws, server_ws) = ws_pair().await;
        let node = node_ending_with(server_ws, end);

        let (client_conn, send_request) = h2_connect(client_ws).await;
        let (io, mut caller) = duplex(1024);
        let relay = tokio::spawn(splice(
            TunnelStream::client(send_request.clone()).await.unwrap(),
            io,
        ));
        caller.write_all(b"hello?").await.unwrap();

        let step = std::time::Duration::from_secs(3);
        let err = tokio::time::timeout(step, relay)
            .await
            .expect("relay splice must end once the node ends the stream")
            .unwrap()
            .unwrap_err();

        end_connection(client_conn, send_request, node).await;
        err
    }

    /// The peer's reset ends the splice with the reason it gave.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_peer_reset_carries_its_reason() {
        let err = splice_error_from_node_ending_with(|body, mut send| {
            send.send_reset(h2::Reason::INTERNAL_ERROR);
            drop(body);
        })
        .await;
        assert_eq!(
            h2_reason(&err),
            Some(h2::Reason::INTERNAL_ERROR),
            "got {err:?}"
        );
    }

    /// A reset that lands while the caller is writing, which is the side
    /// a splice fails on first then, still names the reason.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_peer_reset_while_writing_carries_its_reason() {
        let (client_ws, server_ws) = ws_pair().await;
        let node = node_ending_with(server_ws, |body, mut send| {
            send.send_reset(h2::Reason::INTERNAL_ERROR);
            drop(body);
        });

        let (client_conn, send_request) = h2_connect(client_ws).await;
        let mut stream = TunnelStream::client(send_request.clone()).await.unwrap();
        // more than the window, so the write is stalled when the reset
        // comes rather than done
        let step = std::time::Duration::from_secs(3);
        let err = tokio::time::timeout(
            step,
            stream.write_all(&vec![0x42; 4 * STREAM_WINDOW as usize]),
        )
        .await
        .expect("the write must end on the reset")
        .unwrap_err();
        assert_eq!(
            h2_reason(&err),
            Some(h2::Reason::INTERNAL_ERROR),
            "got {err:?}"
        );

        end_connection(client_conn, send_request, node).await;
    }

    /// The other end dropping its stream is the cancel h2 sends for it.
    #[tokio::test(flavor = "multi_thread")]
    async fn the_other_end_dropping_its_stream_is_a_cancel() {
        let err = splice_error_from_node_ending_with(|body, send| drop((body, send))).await;
        assert_eq!(h2_reason(&err), Some(h2::Reason::CANCEL), "got {err:?}");
    }

    /// A stream that does not speak the tunnel protocol is refused,
    /// and the connection serves the next one that does.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_stream_that_is_not_a_tunnel_is_refused() {
        let (client_ws, server_ws) = ws_pair().await;
        let node = echo_node(server_ws);

        let (client_conn, send_request) = h2_connect(client_ws).await;
        let mut h2 = send_request.clone().ready().await.unwrap();
        let plain = http::Request::post("https://tunnel/").body(()).unwrap();
        let (response, _send) = h2.send_request(plain, true).unwrap();
        let response = response.await.unwrap();
        assert_eq!(response.status(), http::StatusCode::BAD_REQUEST);

        let mut stream = TunnelStream::client(send_request.clone()).await.unwrap();
        stream.write_all(b"still here").await.unwrap();
        let mut got = [0u8; 10];
        stream.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"still here");

        stream.shutdown().await.unwrap();
        stream.read_to_end(&mut Vec::new()).await.unwrap();
        end_connection(client_conn, send_request, node)
            .await
            .unwrap();
    }

    /// The stream id is the same at both ends, before and after the
    /// node answers, so logs from both can be put side by side.
    #[tokio::test(flavor = "multi_thread")]
    async fn both_ends_see_the_same_stream_id() {
        let (client_ws, server_ws) = ws_pair().await;
        let node = tokio::spawn(async move {
            let mut conn = server_handshake(server_ws).await.unwrap();
            let pending = TunnelStream::server(&mut conn).await.unwrap().unwrap();
            let pending_id = pending.id();
            let stream = pending.accept().unwrap();
            drive_until_closed(&mut conn).await;
            (pending_id, stream.id())
        });

        let (client_conn, send_request) = h2_connect(client_ws).await;
        let stream = TunnelStream::client(send_request.clone()).await.unwrap();
        let id = stream.id();
        drop(stream);

        let (pending_id, accepted_id) = end_connection(client_conn, send_request, node).await;
        assert_eq!((pending_id, accepted_id), (id, id));
        assert_eq!(id, 1, "the first stream a client opens is h2's 1");
    }

    /// Writing after shutdown is the caller's mistake, told apart from
    /// the stream having been closed under it.
    #[tokio::test(flavor = "multi_thread")]
    async fn writing_after_shutdown_is_a_broken_pipe() {
        let (client_ws, server_ws) = ws_pair().await;
        let node = echo_node(server_ws);

        let (client_conn, send_request) = h2_connect(client_ws).await;
        let mut stream = TunnelStream::client(send_request.clone()).await.unwrap();
        stream.shutdown().await.unwrap();
        let err = stream.write_all(b"too late").await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::BrokenPipe, "got {err:?}");

        stream.read_to_end(&mut Vec::new()).await.unwrap();
        end_connection(client_conn, send_request, node)
            .await
            .unwrap();
    }

    /// The relay closing its connection in an orderly way ends the
    /// node's accept loop with `None`, not with an error.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_clean_close_ends_the_accept_loop() {
        let (client_ws, server_ws) = ws_pair().await;
        let node = tokio::spawn(async move {
            let mut conn = server_handshake(server_ws).await.unwrap();
            TunnelStream::server(&mut conn).await
        });

        let (client_conn, send_request) = h2_connect(client_ws).await;
        // the last handle going is what makes the h2 client say goodbye
        drop(send_request);
        let step = std::time::Duration::from_secs(3);
        tokio::time::timeout(step, client_conn)
            .await
            .expect("the h2 client must end once its handle is gone")
            .unwrap()
            .unwrap();
        let next = tokio::time::timeout(step, node)
            .await
            .expect("the accept loop must end on a clean close")
            .unwrap();
        assert!(matches!(next, Ok(None)), "got {next:?}");
    }

    /// The node's connection going away takes every stream with it,
    /// as the connection's failure and not as a reset of the stream.
    #[tokio::test(flavor = "multi_thread")]
    async fn the_connection_going_away_takes_the_stream_with_it() {
        let (client_ws, server_ws) = ws_pair().await;
        let node = tokio::spawn(async move {
            let mut conn = server_handshake(server_ws).await.unwrap();
            let stream = TunnelStream::server(&mut conn)
                .await
                .unwrap()
                .unwrap()
                .accept()
                .unwrap();
            let (mut rd, _wr) = tokio::io::split(stream);
            let first = async {
                rd.read_u8().await.unwrap();
            };
            tokio::select! {
                () = first => {}
                () = drive_until_closed(&mut conn) => panic!("connection must outlive the first byte"),
            }
            conn.abrupt_shutdown(h2::Reason::NO_ERROR);
            drive_until_closed(&mut conn).await;
        });

        let (client_conn, send_request) = h2_connect(client_ws).await;
        let (io, mut caller) = duplex(1024);
        let relay = tokio::spawn(splice(
            TunnelStream::client(send_request.clone()).await.unwrap(),
            io,
        ));
        caller.write_all(b"hello?").await.unwrap();

        let step = std::time::Duration::from_secs(3);
        let err = tokio::time::timeout(step, relay)
            .await
            .expect("relay splice must end once the node is gone")
            .unwrap()
            .unwrap_err();
        let e = h2_error(&err).unwrap_or_else(|| panic!("got {err:?}"));
        assert!(!e.is_reset(), "got {err:?}");

        end_connection(client_conn, send_request, node).await;
    }

    /// A node that never answers must not hold the caller forever.
    #[tokio::test(start_paused = true)]
    async fn an_unanswered_stream_times_out() {
        let (client_ws, server_ws) = ws_pair().await;
        let node = tokio::spawn(async move {
            let mut conn = server_handshake(server_ws).await.unwrap();
            let pending = TunnelStream::server(&mut conn).await.unwrap().unwrap();
            // the node holds the stream unanswered until the connection ends
            drive_until_closed(&mut conn).await;
            drop(pending);
        });

        let (client_conn, send_request) = h2_connect(client_ws).await;
        let err = TunnelStream::client(send_request.clone())
            .await
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);

        end_connection(client_conn, send_request, node).await;
    }

    /// A node that refuses a stream is seen as such by the relay's
    /// caller, status and all.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_refused_stream_is_an_error() {
        let (client_ws, server_ws) = ws_pair().await;
        let node = tokio::spawn(async move {
            let mut conn = server_handshake(server_ws).await.unwrap();
            let pending = TunnelStream::server(&mut conn).await.unwrap().unwrap();
            pending.refuse(http::StatusCode::SERVICE_UNAVAILABLE);
            drive_until_closed(&mut conn).await;
        });

        let (client_conn, send_request) = h2_connect(client_ws).await;
        let err = TunnelStream::client(send_request.clone())
            .await
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::ConnectionRefused);
        assert!(err.to_string().contains("503"), "got {err}");

        end_connection(client_conn, send_request, node).await;
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
            let mut conn = server_handshake(server_ws).await.unwrap();
            let stream = TunnelStream::server(&mut conn)
                .await
                .unwrap()
                .unwrap()
                .accept()
                .unwrap();
            let stream = tokio::spawn(splice(stream, io));
            drive_until_closed(&mut conn).await;
            stream.await.unwrap()
        });

        let (conn, send_request) = h2_connect(client_ws).await;
        let mut stream = TunnelStream::client(send_request.clone()).await.unwrap();
        let sender = tokio::spawn(async move {
            let data: Vec<u8> = (0..PAYLOAD)
                .map(|i| u8::try_from(i % 251).unwrap())
                .collect();
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

        let (expected, mut stream) = sender.await.unwrap();
        assert_eq!(got.len(), expected.len(), "a stall must not lose bytes");
        assert_eq!(got, expected, "nor reorder or duplicate them");

        // wind the stream down: the local peer going away ends the
        // other direction, which is done once its EOS is back here,
        // and the node's accept loop only returns once the h2 client
        // is gone
        drop(peer);
        stream.read_to_end(&mut Vec::new()).await.unwrap();
        drop(stream);
        let moved = end_connection(conn, send_request, node).await.unwrap();
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

        let (_conn, send_request) = h2_connect(client_ws).await;
        let mut stream = TunnelStream::client(send_request.clone()).await.unwrap();
        let sender = tokio::spawn(async move {
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
