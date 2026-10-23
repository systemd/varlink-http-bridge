// SPDX-License-Identifier: LGPL-2.1-or-later

//! The real end-to-end path: a varlink-relayd process, a varlink-httpd
//! process dialing out to it, and a caller reaching the bridge through
//! `CONNECT <id>`.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode};
use varlink_http_bridge::node_id::MachineId;

const DEADLINE: Duration = Duration::from_secs(30);

/// Kills the child on drop so a failing test leaves no processes.
struct Daemon(Child);

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn spawn_relayd() -> (Daemon, String, String) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_varlink-relayd"))
        .args([
            "--insecure",
            "--bind-node",
            "127.0.0.1:0",
            "--bind-caller",
            "127.0.0.1:0",
        ])
        // the startup line scanned below is logged at info, a RUST_LOG
        // inherited from the test runner must not hide it
        .env("RUST_LOG", "info")
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawning varlink-relayd");
    // the startup line logs the resolved addresses:
    // "nodes dial in at 127.0.0.1:PORT/<tunnel path>, callers CONNECT to 127.0.0.1:PORT"
    let stderr = child.stderr.take().expect("piped stderr");
    let mut lines = BufReader::new(stderr).lines();
    let line = loop {
        let line = lines
            .next()
            .expect("relayd exited before logging its addresses")
            .expect("reading relayd stderr");
        if line.contains("nodes dial in at ") {
            break line;
        }
    };
    let node_addr = line
        .split("nodes dial in at ")
        .nth(1)
        .and_then(|s| s.split('/').next())
        .expect("node address in startup line")
        .to_string();
    let connect_addr = line
        .split("callers CONNECT to ")
        .nth(1)
        .expect("caller address in startup line")
        .trim()
        .to_string();
    // drain the rest so the child never blocks on a full pipe
    std::thread::spawn(move || for _ in lines {});
    (Daemon(child), node_addr, connect_addr)
}

/// Start a varlink-httpd that serves `socket_dir` only through the relay
/// at `node_addr`, with a self-signed certificate in `state_dir`.
fn spawn_httpd(
    node_addr: &str,
    socket_dir: &std::path::Path,
    state_dir: &std::path::Path,
    instance: Option<&str>,
) -> Daemon {
    // --relay refuses to serve plaintext, and api-key auth with an empty
    // key file is the cheapest way to satisfy --auth; /health is open
    // anyway
    let api_keys = state_dir.join("api-keys");
    std::fs::write(&api_keys, "").unwrap();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_varlink-httpd"));
    cmd.args(["--auth", "api-key", "--api-keys"])
        .arg(&api_keys)
        .args(["--bind", "none", "--relay"])
        .arg(format!("ws://{node_addr}"))
        .env("STATE_DIRECTORY", state_dir)
        .env("RUST_LOG", "info")
        .stderr(Stdio::null())
        .stdout(Stdio::null());
    if let Some(label) = instance {
        cmd.args(["--instance", label]);
    }
    cmd.arg(socket_dir);
    Daemon(cmd.spawn().expect("spawning varlink-httpd"))
}

/// CONNECT to `id` through the relay, retrying while the node has not
/// registered yet, then return the established stream.
fn connect_via_relay(connect_addr: &str, id: &str) -> TcpStream {
    let deadline = Instant::now() + DEADLINE;
    loop {
        let mut stream = TcpStream::connect(connect_addr).expect("connecting to relay");
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        stream
            .write_all(format!("CONNECT {id}:80 HTTP/1.1\r\nHost: {id}\r\n\r\n").as_bytes())
            .unwrap();
        let mut head = Vec::new();
        let mut byte = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            let mut r = &stream;
            r.read_exact(&mut byte).expect("reading CONNECT reply");
            head.push(byte[0]);
        }
        let status = String::from_utf8_lossy(&head);
        if status.starts_with("HTTP/1.1 200") {
            return stream;
        }
        assert!(
            Instant::now() < deadline,
            "node never registered, last relay answer: {}",
            status.lines().next().unwrap_or_default()
        );
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// GET `path` from the bridge over an established CONNECT `stream`,
/// inside an end-to-end TLS session the relay never sees.
fn get_via(stream: TcpStream, id: &str, path: &str) -> String {
    let mut builder = SslConnector::builder(SslMethod::tls()).unwrap();
    // the certificate is self-signed and nothing pins it here
    builder.set_verify(SslVerifyMode::NONE);
    let mut tls = builder
        .build()
        .configure()
        .unwrap()
        .verify_hostname(false)
        .connect(id, stream)
        .expect("TLS handshake through the tunnel");
    tls.write_all(
        format!("GET {path} HTTP/1.1\r\nHost: {id}\r\nConnection: close\r\n\r\n").as_bytes(),
    )
    .unwrap();
    let mut response = String::new();
    tls.read_to_string(&mut response)
        .expect("reading bridge response");
    response
}

#[test]
fn caller_reaches_the_bridge_through_the_relay() {
    // needs a usable machine id, same states test as machine-id(5)
    let Ok(text) = std::fs::read_to_string("/etc/machine-id") else {
        return;
    };
    let Ok(machine_id) = text.trim().parse::<MachineId>() else {
        return;
    };
    let default_id = machine_id.node_id().unwrap().to_string();
    let second_id = machine_id.instance_node_id("second").unwrap().to_string();

    let (_relayd, node_addr, connect_addr) = spawn_relayd();
    let sockets = tempfile::tempdir().unwrap();
    let state = tempfile::tempdir().unwrap();
    let second_state = tempfile::tempdir().unwrap();

    // the default instance and a second one on the same host
    let _bridge = spawn_httpd(&node_addr, sockets.path(), state.path(), None);
    let _second_bridge = spawn_httpd(
        &node_addr,
        sockets.path(),
        second_state.path(),
        Some("second"),
    );

    for id in [&default_id, &second_id] {
        let stream = connect_via_relay(&connect_addr, id);
        let response = get_via(stream, id, "/health");
        assert!(
            response.starts_with("HTTP/1.1 200"),
            "unexpected response for {id}: {}",
            response.lines().next().unwrap_or_default()
        );
    }

    assert_ne!(default_id, second_id);
}

/// Callers share one tunnel per node, so many of them must be in flight
/// at once, more than the node queues internally.
#[test]
fn concurrent_callers_share_one_tunnel() {
    // needs a usable machine id, same states test as machine-id(5)
    let Ok(text) = std::fs::read_to_string("/etc/machine-id") else {
        return;
    };
    let Ok(machine_id) = text.trim().parse::<MachineId>() else {
        return;
    };
    let id = machine_id.node_id().unwrap().to_string();

    let (_relayd, node_addr, connect_addr) = spawn_relayd();
    let sockets = tempfile::tempdir().unwrap();
    let state = tempfile::tempdir().unwrap();
    let _bridge = spawn_httpd(&node_addr, sockets.path(), state.path(), None);

    // all open at once, and more than the node's connection channel holds
    let streams: Vec<TcpStream> = (0..24)
        .map(|_| connect_via_relay(&connect_addr, &id))
        .collect();

    let responses: Vec<String> = std::thread::scope(|scope| {
        let callers: Vec<_> = streams
            .into_iter()
            .map(|stream| {
                let id = &id;
                scope.spawn(move || get_via(stream, id, "/health"))
            })
            .collect();
        callers.into_iter().map(|c| c.join().unwrap()).collect()
    });
    for (i, response) in responses.iter().enumerate() {
        assert!(
            response.starts_with("HTTP/1.1 200"),
            "caller {i}: {}",
            response.lines().next().unwrap_or_default()
        );
    }
}
