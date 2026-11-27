// SPDX-License-Identifier: LGPL-2.1-or-later

//! A WebSocket as an `AsyncRead`/`AsyncWrite` byte stream, so code that
//! only moves bytes, such as `io::copy` or an h2 connection, can run over
//! a WebSocket without knowing about frames.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use bytes::{Buf, Bytes};
use futures_util::{Sink, Stream};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::error::{Error as WsError, ProtocolError};
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;

/// tungstenite's 64MiB default lets any peer make us buffer that much.
/// Each message is one h2 write, under 48KiB with h2's default 16KiB
/// frames, so this leaves headroom.
pub const MAX_MESSAGE: usize = 128 * 1024;

#[must_use]
pub fn config_for_h2() -> WebSocketConfig {
    WebSocketConfig::default()
        .max_message_size(Some(MAX_MESSAGE))
        .max_frame_size(Some(MAX_MESSAGE))
}

/// Binary payloads are the stream, a close frame is EOF and a text
/// frame is an error, since only a confused peer or middlebox sends
/// one.
///
/// Shutdown ends only our direction, as it does on a socket. A
/// WebSocket has no half-close, so the end of our data is an empty
/// message, which varlink-httpd passes on to the varlink service as
/// the end of its input. The peer then closes once it has sent all it
/// has. [`WsByteStream::close_on_shutdown`] is for a peer that does not
/// know the empty message.
pub struct WsByteStream<S> {
    ws: WebSocketStream<S>,
    readbuf: Bytes,
    abrupt_close_is_eof: bool,
    /// The peer's close frame is in, so from now on a write goes
    /// nowhere, as one after the peer's FIN does on TCP. h2 answers EOF
    /// with a GOAWAY before it shuts down, and an error there would turn
    /// a clean close into a failed one.
    peer_closed: bool,
    on_shutdown: OnShutdown,
}

/// What shutdown sends.
#[derive(PartialEq)]
enum OnShutdown {
    /// A close frame, see [`WsByteStream::close_on_shutdown`].
    Close,
    /// An empty message.
    EndOfInput,
    /// Nothing, the empty message is on its way already.
    Nothing,
}

impl<S> WsByteStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    /// A peer that vanishes without a close handshake is an error, as
    /// a reset is on any socket.
    pub fn new(ws: WebSocketStream<S>) -> Self {
        Self {
            ws,
            readbuf: Bytes::new(),
            abrupt_close_is_eof: false,
            peer_closed: false,
            on_shutdown: OnShutdown::EndOfInput,
        }
    }

    /// Treat a peer that vanishes without a close handshake as EOF, for
    /// long-lived connections through middleboxes that reap them without
    /// ever sending a close frame.
    #[must_use]
    pub fn abrupt_close_as_eof(mut self) -> Self {
        self.abrupt_close_is_eof = true;
        self
    }

    /// Let shutdown send a close frame, which ends both directions. For
    /// a peer that reads with a `WsByteStream` as well, such as the other
    /// end of the h2 tunnel: it skips an empty message and so would
    /// never see the end of our data.
    #[must_use]
    pub fn close_on_shutdown(mut self) -> Self {
        self.on_shutdown = OnShutdown::Close;
        self
    }

    /// Close the WebSocket for good, which shutdown alone does not:
    /// send our close frame, or the reply to the one the peer sent.
    ///
    /// # Errors
    ///
    /// When the close frame cannot be sent to a peer that is still there.
    pub async fn close(&mut self) -> io::Result<()> {
        std::future::poll_fn(|cx| self.poll_close(cx)).await
    }

    fn poll_close(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match ready!(Pin::new(&mut self.ws).poll_close(cx)) {
            // the peer closed first and tungstenite already answered
            Ok(()) | Err(WsError::ConnectionClosed | WsError::AlreadyClosed) => Poll::Ready(Ok(())),
            Err(_) if self.peer_closed => Poll::Ready(Ok(())),
            Err(e) => Poll::Ready(Err(io::Error::other(e))),
        }
    }
}

impl<S> AsyncRead for WsByteStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            if !this.readbuf.is_empty() {
                drain(&mut this.readbuf, buf);
                return Poll::Ready(Ok(()));
            }
            let abrupt = match ready!(Pin::new(&mut this.ws).poll_next(cx)) {
                Some(Ok(Message::Binary(data))) => {
                    this.readbuf = data;
                    continue;
                }
                Some(Ok(Message::Text(_))) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "unexpected text WebSocket frame",
                    )));
                }
                // tungstenite answers pings on its read path, with retry
                // on a blocked socket; flushing here would bypass that
                // retry and could strand the pong
                Some(Ok(Message::Ping(_) | Message::Pong(_) | Message::Frame(_))) => continue,
                Some(Ok(Message::Close(_))) | None => {
                    this.peer_closed = true;
                    return Poll::Ready(Ok(()));
                }
                Some(Err(
                    e @ (WsError::Protocol(ProtocolError::ResetWithoutClosingHandshake)
                    | WsError::ConnectionClosed),
                )) => io::Error::new(io::ErrorKind::UnexpectedEof, e),
                Some(Err(WsError::Io(e)))
                    if matches!(
                        e.kind(),
                        io::ErrorKind::ConnectionReset | io::ErrorKind::UnexpectedEof
                    ) =>
                {
                    e
                }
                Some(Err(e)) => return Poll::Ready(Err(io::Error::other(e))),
            };
            return Poll::Ready(if this.abrupt_close_is_eof {
                Ok(())
            } else {
                Err(abrupt)
            });
        }
    }
}

impl<S> AsyncWrite for WsByteStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        // an empty message is the end of our data, so an empty write
        // must not send one
        if this.peer_closed || buf.is_empty() {
            return Poll::Ready(Ok(buf.len()));
        }
        ready!(Pin::new(&mut this.ws).poll_ready(cx)).map_err(io::Error::other)?;
        Pin::new(&mut this.ws)
            .start_send(Message::Binary(Bytes::copy_from_slice(buf)))
            .map_err(io::Error::other)?;
        Poll::Ready(Ok(buf.len()))
    }

    // without this a vectored writer such as h2 turns every slice into
    // its own masked WebSocket message
    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let total = bufs.iter().map(|b| b.len()).sum();
        if total == 0 {
            return Poll::Ready(Ok(0));
        }
        let this = self.get_mut();
        if this.peer_closed {
            return Poll::Ready(Ok(total));
        }
        ready!(Pin::new(&mut this.ws).poll_ready(cx)).map_err(io::Error::other)?;
        let mut data = bytes::BytesMut::with_capacity(total);
        for buf in bufs {
            data.extend_from_slice(buf);
        }
        Pin::new(&mut this.ws)
            .start_send(Message::Binary(data.freeze()))
            .map_err(io::Error::other)?;
        Poll::Ready(Ok(total))
    }

    fn is_write_vectored(&self) -> bool {
        true
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match ready!(Pin::new(&mut this.ws).poll_flush(cx)) {
            Ok(()) => Poll::Ready(Ok(())),
            // only our close reply can be left to send, and only a peer
            // that is gone already could miss it
            Err(_) if this.peer_closed => Poll::Ready(Ok(())),
            Err(e) => Poll::Ready(Err(io::Error::other(e))),
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.on_shutdown == OnShutdown::EndOfInput && !self.peer_closed {
            ready!(Pin::new(&mut self.ws).poll_ready(cx)).map_err(io::Error::other)?;
            Pin::new(&mut self.ws)
                .start_send(Message::Binary(Bytes::new()))
                .map_err(io::Error::other)?;
            self.on_shutdown = OnShutdown::Nothing;
        }
        if self.on_shutdown != OnShutdown::Close {
            return self.poll_flush(cx);
        }
        self.get_mut().poll_close(cx)
    }
}

/// Move as much of `readbuf` as fits into `buf`. Shared with the tunnel's
/// stream, which buffers the same way.
pub fn drain(readbuf: &mut Bytes, buf: &mut ReadBuf<'_>) {
    let n = readbuf.len().min(buf.remaining());
    buf.put_slice(&readbuf[..n]);
    readbuf.advance(n);
}

/// Test-only: connected WebSocket pairs over an in-memory duplex.
#[cfg(any(test, feature = "test-helpers"))]
pub mod test_helpers {
    use super::{WsByteStream, config_for_h2};
    use tokio::io::{DuplexStream, duplex};
    use tokio_tungstenite::WebSocketStream;
    use tokio_tungstenite::tungstenite::protocol::Role;
    use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;

    pub async fn raw_pair() -> (WebSocketStream<DuplexStream>, WebSocketStream<DuplexStream>) {
        raw_pair_with_config(None).await
    }

    pub async fn raw_pair_with_config(
        config: Option<WebSocketConfig>,
    ) -> (WebSocketStream<DuplexStream>, WebSocketStream<DuplexStream>) {
        let (a, b) = duplex(4096);
        tokio::join!(
            WebSocketStream::from_raw_socket(a, Role::Client, config),
            WebSocketStream::from_raw_socket(b, Role::Server, config),
        )
    }

    /// With the production limit, so that the h2 tests over it fail if
    /// h2 ever writes more than [`super::MAX_MESSAGE`] at once.
    pub async fn ws_pair() -> (WsByteStream<DuplexStream>, WsByteStream<DuplexStream>) {
        let (client, server) = raw_pair_with_config(Some(config_for_h2())).await;
        (
            WsByteStream::new(client).close_on_shutdown(),
            WsByteStream::new(server).close_on_shutdown(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::test_helpers::{raw_pair, raw_pair_with_config, ws_pair};
    use super::*;
    use futures_util::SinkExt as _;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn text_frames_are_an_error() {
        let (mut client, server) = raw_pair().await;
        let mut server = WsByteStream::new(server);
        client.send(Message::Text("nope".into())).await.unwrap();
        let mut buf = [0u8; 4];
        let err = server.read_exact(&mut buf).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn roundtrip_and_eof() {
        // unlimited, a plain write_all is one message of any size
        let (client, server) = raw_pair().await;
        let mut client = WsByteStream::new(client).close_on_shutdown();
        let mut server = WsByteStream::new(server);

        client.write_all(b"ping").await.unwrap();
        client.flush().await.unwrap();
        let mut small = [0u8; 4];
        server.read_exact(&mut small).await.unwrap();
        assert_eq!(&small, b"ping");
        server.write_all(b"pong").await.unwrap();
        server.flush().await.unwrap();
        client.read_exact(&mut small).await.unwrap();
        assert_eq!(&small, b"pong");

        // larger than every buffer in the path
        let data: Vec<u8> = (0..256 * 1024)
            .map(|i| u8::try_from(i % 251).unwrap())
            .collect();
        let expected = data.clone();
        let writer = tokio::spawn(async move {
            client.write_all(&data).await.unwrap();
            client.shutdown().await.unwrap();
        });
        let mut got = Vec::new();
        server.read_to_end(&mut got).await.unwrap();
        writer.await.unwrap();
        assert_eq!(got, expected);
    }

    #[tokio::test]
    async fn an_oversized_message_is_refused() {
        let (mut client, server) = raw_pair_with_config(Some(config_for_h2())).await;
        let mut server = WsByteStream::new(server);
        // the client's own limit only applies to what it reads, and its
        // send never completes once the server stops reading
        tokio::spawn(async move {
            let _ = client
                .send(Message::Binary(vec![0; MAX_MESSAGE + 1].into()))
                .await;
        });
        let mut buf = [0u8; 1];
        assert!(server.read(&mut buf).await.is_err());
    }

    #[tokio::test]
    async fn shutdown_after_the_peer_closed_is_not_an_error() {
        let (mut client, mut server) = ws_pair().await;
        client.shutdown().await.unwrap();
        let mut got = Vec::new();
        server.read_to_end(&mut got).await.unwrap();
        assert_eq!(got, b"");
        server.shutdown().await.unwrap();
    }

    /// Whether the peer lingers after its close frame or is gone, what
    /// is written after it is nobody's loss.
    #[tokio::test]
    async fn a_write_after_the_peer_closed_goes_nowhere() {
        for linger in [true, false] {
            let (mut client, mut server) = ws_pair().await;
            client.shutdown().await.unwrap();
            if !linger {
                drop(client);
            }
            let mut got = Vec::new();
            server.read_to_end(&mut got).await.unwrap();
            server.write_all(b"too late").await.unwrap();
            server.flush().await.unwrap();
            server.shutdown().await.unwrap();
        }
    }

    /// An empty message means the end of the data, so a write of
    /// nothing must not turn into one.
    #[tokio::test]
    async fn an_empty_write_sends_no_message() {
        use futures_util::StreamExt as _;

        let (client, mut server) = raw_pair().await;
        let mut client = WsByteStream::new(client);
        assert_eq!(client.write(b"").await.unwrap(), 0);
        client.write_all(b"data").await.unwrap();
        client.flush().await.unwrap();

        let msg = server.next().await.unwrap().unwrap();
        assert_eq!(msg, Message::Binary(Bytes::from_static(b"data")));
    }

    /// The peer gets an empty message and no close frame, and what it
    /// sends afterwards still arrives.
    #[tokio::test]
    async fn a_half_close_keeps_the_other_direction_open() {
        use futures_util::StreamExt as _;

        let (client, mut server) = raw_pair().await;
        let mut client = WsByteStream::new(client);
        client.write_all(b"request").await.unwrap();
        client.shutdown().await.unwrap();
        // a second shutdown must not send a second end of input
        client.shutdown().await.unwrap();

        let msg = server.next().await.unwrap().unwrap();
        assert_eq!(msg, Message::Binary(Bytes::from_static(b"request")));
        let msg = server.next().await.unwrap().unwrap();
        assert_eq!(msg, Message::Binary(Bytes::new()));

        server
            .send(Message::Binary(Bytes::from_static(b"late reply")))
            .await
            .unwrap();
        server.close(None).await.unwrap();
        let mut got = Vec::new();
        client.read_to_end(&mut got).await.unwrap();
        assert_eq!(got, b"late reply");

        // and close() still does the close handshake
        client.close().await.unwrap();
        assert!(matches!(server.next().await, Some(Ok(Message::Close(_)))));
    }

    #[tokio::test]
    async fn a_vanished_peer_is_an_error_unless_asked_for() {
        let (client, server) = raw_pair().await;
        let mut server = WsByteStream::new(server);
        drop(client);
        let mut buf = [0u8; 1];
        let err = server.read(&mut buf).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);

        let (client, server) = raw_pair().await;
        let mut server = WsByteStream::new(server).abrupt_close_as_eof();
        drop(client);
        assert_eq!(server.read(&mut buf).await.unwrap(), 0);
    }
}
