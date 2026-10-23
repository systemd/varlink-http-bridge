// SPDX-License-Identifier: LGPL-2.1-or-later

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use varlink_http_bridge::node_id::NodeId;
use varlink_http_bridge::tunnel::{
    MAX_TUNNEL_STREAMS, STREAM_OPEN_TIMEOUT, STREAM_WINDOW, TUNNEL_PATH, TunnelStream,
    server_handshake,
};
use varlink_http_bridge::ws::WsByteStream;

use crate::registry::Nodes;
use crate::{caller, node};

const TEST_ID: &str = "0123456789abcdef0123456789abcdef";
const OTHER_ID: &str = "fedcba9876543210fedcba9876543210";
const STEP: Duration = Duration::from_secs(5);

async fn start_relay() -> (SocketAddr, SocketAddr, Arc<Nodes>) {
    let node_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let caller_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let node_addr = node_listener.local_addr().unwrap();
    let caller_addr = caller_listener.local_addr().unwrap();
    let nodes = Arc::new(Nodes::default());
    tokio::spawn(node::serve(node_listener, None, Arc::clone(&nodes)));
    tokio::spawn(caller::serve(caller_listener, Arc::clone(&nodes)));
    (node_addr, caller_addr, nodes)
}

/// A minimal node like varlink-httpd's dial-out: answer every stream
/// and echo its bytes.
async fn stub_node(
    node_addr: SocketAddr,
    id: &str,
) -> Result<tokio::task::JoinHandle<()>, tokio_tungstenite::tungstenite::Error> {
    stub_node_hanging_streams(node_addr, id, 0).await
}

/// The same node, but its first `hang_first` streams are never read,
/// like a hung local service.
async fn stub_node_hanging_streams(
    node_addr: SocketAddr,
    id: &str,
    hang_first: usize,
) -> Result<tokio::task::JoinHandle<()>, tokio_tungstenite::tungstenite::Error> {
    let tcp = TcpStream::connect(node_addr).await.unwrap();
    let url = format!("ws://{node_addr}{TUNNEL_PATH}?node_id={id}");
    let (ws, _response) = tokio_tungstenite::client_async(url, tcp).await?;
    Ok(tokio::spawn(async move {
        let mut conn = server_handshake(WsByteStream::new(ws)).await.unwrap();
        let mut streams = 0;
        let mut hung = Vec::new();
        while let Ok(Some(pending)) = TunnelStream::server(&mut conn).await {
            let Ok(stream) = pending.accept() else {
                continue;
            };
            streams += 1;
            if streams <= hang_first {
                hung.push(stream);
            } else {
                tokio::spawn(async move {
                    let (mut rd, mut wr) = tokio::io::split(stream);
                    let _ = tokio::io::copy(&mut rd, &mut wr).await;
                    let _ = wr.shutdown().await;
                });
            }
        }
    }))
}

// the relay only routes to a node once it answered the first PING
async fn wait_registered(nodes: &Nodes, id: &str) {
    let id = id.parse::<NodeId>().unwrap();
    tokio::time::timeout(STEP, async {
        while nodes.get(id).is_none() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("node must register");
}

async fn wait_released(nodes: &Nodes, id: &str, within: Duration, why: &str) {
    let id = id.parse::<NodeId>().unwrap();
    tokio::time::timeout(within, async {
        while nodes.occupied(id) {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect(why);
}

async fn send_connect(
    caller_addr: SocketAddr,
    authority: &str,
    extra: &[u8],
) -> (TcpStream, String) {
    let mut stream = open_connect(caller_addr, authority, extra).await;
    let status = read_status(&mut stream, STEP)
        .await
        .expect("relay must answer the CONNECT");
    (stream, status)
}

async fn open_connect(caller_addr: SocketAddr, authority: &str, extra: &[u8]) -> TcpStream {
    let mut stream = TcpStream::connect(caller_addr).await.unwrap();
    let mut request =
        format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n").into_bytes();
    request.extend_from_slice(extra);
    stream.write_all(&request).await.unwrap();
    stream
}

async fn read_status(stream: &mut TcpStream, within: Duration) -> Option<String> {
    tokio::time::timeout(within, async {
        let mut head = Vec::new();
        let mut byte = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            stream.read_exact(&mut byte).await.unwrap();
            head.push(byte[0]);
        }
        String::from_utf8(head)
            .unwrap()
            .lines()
            .next()
            .unwrap()
            .to_string()
    })
    .await
    .ok()
}

#[tokio::test(flavor = "multi_thread")]
async fn end_to_end_echo() {
    let (node_addr, caller_addr, nodes) = start_relay().await;
    let _node = stub_node(node_addr, TEST_ID).await.unwrap();
    wait_registered(&nodes, TEST_ID).await;

    let (mut stream, status) = send_connect(caller_addr, &format!("{TEST_ID}:80"), b"").await;
    assert_eq!(status, "HTTP/1.1 200 Connection established");

    stream.write_all(b"hello relay").await.unwrap();
    let mut got = [0u8; 11];
    tokio::time::timeout(STEP, stream.read_exact(&mut got))
        .await
        .expect("echo must come back")
        .unwrap();
    assert_eq!(&got, b"hello relay");
}

#[tokio::test(flavor = "multi_thread")]
async fn early_data_behind_the_connect_is_not_lost() {
    let (node_addr, caller_addr, nodes) = start_relay().await;
    let _node = stub_node(node_addr, TEST_ID).await.unwrap();
    wait_registered(&nodes, TEST_ID).await;

    let (mut stream, status) = send_connect(caller_addr, TEST_ID, b"early").await;
    assert_eq!(status, "HTTP/1.1 200 Connection established");
    let mut got = [0u8; 5];
    tokio::time::timeout(STEP, stream.read_exact(&mut got))
        .await
        .expect("pipelined bytes must be echoed")
        .unwrap();
    assert_eq!(&got, b"early");
}

#[tokio::test(flavor = "multi_thread")]
async fn unknown_node_gets_502() {
    let (_node_addr, caller_addr, _nodes) = start_relay().await;
    let (_stream, status) = send_connect(caller_addr, OTHER_ID, b"").await;
    assert_eq!(status, "HTTP/1.1 502 Bad Gateway");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_node_at_its_stream_limit_gets_503() {
    let (node_addr, caller_addr, nodes) = start_relay().await;
    let _node = stub_node(node_addr, TEST_ID).await.unwrap();
    wait_registered(&nodes, TEST_ID).await;

    let mut held = Vec::new();
    for _ in 0..MAX_TUNNEL_STREAMS {
        let (stream, status) = send_connect(caller_addr, TEST_ID, b"").await;
        assert_eq!(status, "HTTP/1.1 200 Connection established");
        held.push(stream);
    }
    // queued behind the held streams until STREAM_OPEN_TIMEOUT expires
    let mut extra = open_connect(caller_addr, TEST_ID, b"").await;
    let status = read_status(&mut extra, STREAM_OPEN_TIMEOUT + STEP).await;
    assert_eq!(status.as_deref(), Some("HTTP/1.1 503 Service Unavailable"));
    drop(held);
}

#[tokio::test(flavor = "multi_thread")]
async fn malformed_connect_gets_400() {
    let (_node_addr, caller_addr, _nodes) = start_relay().await;
    let (_stream, status) = send_connect(caller_addr, "not-a-node-id", b"").await;
    assert_eq!(status, "HTTP/1.1 400 Bad Request");
}

#[tokio::test(flavor = "multi_thread")]
async fn duplicate_claim_is_rejected_first_wins() {
    let (node_addr, _caller_addr, nodes) = start_relay().await;
    let _node = stub_node(node_addr, TEST_ID).await.unwrap();
    wait_registered(&nodes, TEST_ID).await;

    let err = stub_node(node_addr, TEST_ID)
        .await
        .expect_err("second claim must be rejected");
    let tokio_tungstenite::tungstenite::Error::Http(resp) = err else {
        panic!("expected an HTTP rejection, got {err:?}");
    };
    assert_eq!(resp.status(), 409);
    assert!(nodes.get(TEST_ID.parse().unwrap()).is_some());
}

#[tokio::test(flavor = "multi_thread")]
async fn id_is_reclaimable_after_the_node_drops() {
    let (node_addr, caller_addr, nodes) = start_relay().await;
    let node = stub_node(node_addr, TEST_ID).await.unwrap();
    wait_registered(&nodes, TEST_ID).await;

    node.abort();
    wait_released(
        &nodes,
        TEST_ID,
        STEP,
        "id must be released when the connection dies",
    )
    .await;

    let _node = stub_node(node_addr, TEST_ID).await.unwrap();
    wait_registered(&nodes, TEST_ID).await;
    let (_stream, status) = send_connect(caller_addr, TEST_ID, b"").await;
    assert_eq!(status, "HTTP/1.1 200 Connection established");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_silent_peer_never_becomes_a_node() {
    let (node_addr, caller_addr, nodes) = start_relay().await;
    let tcp = TcpStream::connect(node_addr).await.unwrap();
    let url = format!("ws://{node_addr}{TUNNEL_PATH}?node_id={TEST_ID}");
    let (_ws, _response) = tokio_tungstenite::client_async(url, tcp).await.unwrap();
    let id = TEST_ID.parse::<NodeId>().unwrap();
    assert!(nodes.occupied(id), "the upgrade reserves the id");

    tokio::time::sleep(node::HEARTBEAT_TIMEOUT / 4).await;
    assert!(
        nodes.get(id).is_none(),
        "a peer that never answered a PING must not be routable"
    );
    let (_stream, status) = send_connect(caller_addr, TEST_ID, b"").await;
    assert_eq!(status, "HTTP/1.1 502 Bad Gateway");

    wait_released(
        &nodes,
        TEST_ID,
        node::HEARTBEAT_TIMEOUT + STEP,
        "a peer that never answers the first PING must be given up on",
    )
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn upgrade_without_id_is_rejected() {
    let (node_addr, _caller_addr, _nodes) = start_relay().await;
    let tcp = TcpStream::connect(node_addr).await.unwrap();
    let err = tokio_tungstenite::client_async(format!("ws://{node_addr}{TUNNEL_PATH}"), tcp)
        .await
        .expect_err("upgrade without id must fail");
    let tokio_tungstenite::tungstenite::Error::Http(resp) = err else {
        panic!("expected an HTTP rejection, got {err:?}");
    };
    assert_eq!(resp.status(), 400);
}

#[tokio::test(flavor = "multi_thread")]
async fn callers_are_multiplexed_onto_one_tunnel() {
    let (node_addr, caller_addr, nodes) = start_relay().await;
    let _node = stub_node(node_addr, TEST_ID).await.unwrap();
    wait_registered(&nodes, TEST_ID).await;

    let (mut a, status_a) = send_connect(caller_addr, TEST_ID, b"").await;
    let (mut b, status_b) = send_connect(caller_addr, TEST_ID, b"").await;
    assert_eq!(status_a, "HTTP/1.1 200 Connection established");
    assert_eq!(status_b, "HTTP/1.1 200 Connection established");

    for round in 0..4u8 {
        a.write_all(b"aaaa").await.unwrap();
        b.write_all(b"bbbb").await.unwrap();
        let mut got_a = [0u8; 4];
        let mut got_b = [0u8; 4];
        tokio::time::timeout(STEP, a.read_exact(&mut got_a))
            .await
            .unwrap_or_else(|_| panic!("caller a stalled in round {round}"))
            .unwrap();
        tokio::time::timeout(STEP, b.read_exact(&mut got_b))
            .await
            .unwrap_or_else(|_| panic!("caller b stalled in round {round}"))
            .unwrap();
        assert_eq!((&got_a, &got_b), (b"aaaa", b"bbbb"));
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn hung_streams_do_not_starve_other_callers() {
    // with h2's default of one stream window for the whole connection the
    // hung callers would own all of it, CONNECTION_WINDOW is sized against
    // that
    const HUNG_CALLERS: usize = 8;

    let (node_addr, caller_addr, nodes) = start_relay().await;
    let _node = stub_node_hanging_streams(node_addr, TEST_ID, HUNG_CALLERS)
        .await
        .unwrap();
    wait_registered(&nodes, TEST_ID).await;

    let mut pushers = Vec::new();
    let mut pushed = Vec::new();
    for _ in 0..HUNG_CALLERS {
        let (mut hung, status) = send_connect(caller_addr, TEST_ID, b"").await;
        assert_eq!(status, "HTTP/1.1 200 Connection established");
        let counter = Arc::new(AtomicUsize::new(0));
        pushed.push(Arc::clone(&counter));
        pushers.push(tokio::spawn(async move {
            let chunk = vec![0x41u8; STREAM_WINDOW as usize];
            while hung.write_all(&chunk).await.is_ok() {
                counter.fetch_add(chunk.len(), Ordering::Relaxed);
            }
        }));
    }

    let total = || -> usize { pushed.iter().map(|c| c.load(Ordering::Relaxed)).sum() };
    tokio::time::timeout(STEP, async {
        loop {
            let before = total();
            tokio::time::sleep(Duration::from_millis(300)).await;
            if total() == before && before > 0 {
                return;
            }
        }
    })
    .await
    .expect("the hung callers must wedge");

    // half a stream window, so that leftover window is not enough
    let ping = vec![0x2Au8; STREAM_WINDOW as usize / 2];
    let (mut healthy, status) = send_connect(caller_addr, TEST_ID, b"").await;
    assert_eq!(status, "HTTP/1.1 200 Connection established");
    let mut got = vec![0u8; ping.len()];
    let echo = tokio::time::timeout(STEP, async {
        healthy.write_all(&ping).await.unwrap();
        healthy.read_exact(&mut got).await.unwrap();
    })
    .await;
    for pusher in pushers {
        pusher.abort();
    }
    echo.expect("hung streams must not block a healthy caller");
    assert_eq!(got, ping);
}
