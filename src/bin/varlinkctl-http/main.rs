// SPDX-License-Identifier: LGPL-2.1-or-later

//! The varlinkctl bridge helper: varlinkctl hands us one end of a
//! socketpair on fd 3 and the bridge URL, we dial the varlink-httpd
//! with varlink-http-client and copy bytes in both directions.

use std::os::fd::BorrowedFd;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use log::{debug, warn};
use tokio::io::AsyncWriteExt;
use tokio::net::UnixStream;
use tokio::signal::unix::{SignalKind, signal};
use varlink_http_client::ws::WsByteStream;
use varlink_http_client::{BoxedStream, Ws, connect_ws};

// Time to wait until a close needs to be complete before giving up.
const CLOSE_TIMEOUT: Duration = Duration::from_secs(2);
// Time to wait for the whole connection setup: TCP/vsock connect, TLS
// handshake, auth token generation (a hung ssh-agent) and the
// WebSocket upgrade.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

/// Our half of the close handshake, bounded so a stuck peer cannot
/// hang the exit.
async fn close_ws(ws: &mut WsByteStream<BoxedStream>) {
    match tokio::time::timeout(CLOSE_TIMEOUT, ws.shutdown()).await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => warn!("WebSocket close failed: {e:#}"),
        Err(_) => warn!("timed out closing WebSocket"),
    }
}

/// Forward data between fd3 and the WebSocket in both directions until
/// both sides have closed or we get SIGINT/SIGTERM.
///
/// Whichever side closes first, the other is drained until it closes
/// too. varlinkctl closes fd3 and then sends SIGTERM, so a peer that
/// never answers our close is cut short by the signal branch.
async fn run_proxy(ws: Ws, mut fd3: UnixStream) -> Result<()> {
    let mut sigint = signal(SignalKind::interrupt())?;
    let mut sigterm = signal(SignalKind::terminate())?;
    let mut ws = WsByteStream::new(ws);

    tokio::select! {
        r = tokio::io::copy_bidirectional(&mut fd3, &mut ws) => {
            let (up, down) = r.context("proxy")?;
            debug!("done after {up} bytes fd3 -> WebSocket, {down} bytes back");
        }
        _ = sigint.recv() => {
            debug!("SIGINT, closing WebSocket");
            close_ws(&mut ws).await;
        }
        _ = sigterm.recv() => {
            debug!("SIGTERM, closing WebSocket");
            close_ws(&mut ws).await;
        }
    }
    Ok(())
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("warn")).init();

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

    let ws = tokio::time::timeout(CONNECT_TIMEOUT, connect_ws(&bridge_url))
        .await
        .with_context(|| format!("timed out connecting to '{bridge_url}'"))??;

    run_proxy(ws, fd3).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::{SinkExt, StreamExt};
    use tokio::io::AsyncReadExt;
    use tokio_tungstenite::WebSocketStream;
    use tokio_tungstenite::tungstenite::Message;

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
            // reading on past the close frame is what sends the reply
            while let Some(msg) = ws.next().await {
                if let Message::Binary(data) = msg.unwrap() {
                    received.extend_from_slice(&data);
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
            // idle until the close handshake is done
            while ws.next().await.is_some() {}
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

    /// When the peer closes first the proxy must pass the EOF on to fd3,
    /// answer the close handshake (instead of just dropping the
    /// connection) once fd3 is closed as well, and exit 0.
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

        let mut hello = Vec::new();
        ours.read_to_end(&mut hello).await.unwrap();
        assert_eq!(hello, b"hello");
        // like varlinkctl, close fd3 once the peer is gone
        drop(ours);

        proxy.await.unwrap().expect("run_proxy failed");
        assert!(server.await.unwrap(), "server never got a close reply");
    }
}
