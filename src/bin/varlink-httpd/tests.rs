// SPDX-License-Identifier: LGPL-2.1-or-later

use super::*;
use futures_util::{SinkExt, StreamExt};
use gethostname::gethostname;
use reqwest::Client;
use std::os::fd::OwnedFd;
use tokio::task::JoinSet;
use tokio_tungstenite::tungstenite::Message as WsMsg;
use varlink_http_bridge::TlsChannelBinding;

/// Saves each test from assembling an `AuthRequest` and its backing `HeaderMap`.
fn check_request(
    auth: &dyn Authenticator,
    method: &str,
    path: &str,
    auth_header: Option<&str>,
    nonce: Option<&str>,
    tls_channel_binding: Option<&TlsChannelBinding>,
) -> anyhow::Result<()> {
    let mut headers = axum::http::HeaderMap::new();
    if let Some(v) = auth_header {
        headers.insert("authorization", v.parse().unwrap());
    }
    if let Some(v) = nonce {
        // literal SSHAUTH_NONCE_HEADER, which is compiled out without "sshauth"
        headers.insert("x-auth-nonce", v.parse().unwrap());
    }
    auth.check_request(&AuthRequest {
        method,
        path,
        headers: &headers,
        tls_channel_binding,
    })
}

/// Bundles a spawned test server task with its bound address.
/// Dropping aborts the task, so each test's server is cleaned up
/// at end of scope.
struct TestServer<A> {
    handle: tokio::task::JoinHandle<()>,
    addr: A,
}

impl<A> Drop for TestServer<A> {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

/// A simple log capture for tests.  Installed once (via `init_test_logger`)
/// and accumulates all `info!` and above messages so tests can assert on them.
struct TestLogger;

static TEST_LOG_MESSAGES: std::sync::Mutex<Vec<String>> = std::sync::Mutex::new(Vec::new());

impl log::Log for TestLogger {
    fn enabled(&self, _: &log::Metadata) -> bool {
        true
    }

    fn log(&self, record: &log::Record) {
        TEST_LOG_MESSAGES
            .lock()
            .unwrap()
            .push(format!("[{}] {}", record.level(), record.args()));
    }

    fn flush(&self) {}
}

fn init_test_logger() {
    static INIT: std::sync::Once = std::sync::Once::new();
    INIT.call_once(|| {
        log::set_logger(&TestLogger).unwrap();
        log::set_max_level(log::LevelFilter::Trace);
    });
}

/// Build (if needed) and return the path to the varlinkctl-helper binary.
fn helper_binary() -> std::path::PathBuf {
    static BUILD: std::sync::Once = std::sync::Once::new();

    let test_exe = std::env::current_exe().expect("failed to get test exe path");
    // test binary is in target/debug/deps/, helper is in target/debug/
    let helper = test_exe
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("varlinkctl-http");

    BUILD.call_once(|| {
        let status = std::process::Command::new(env!("CARGO"))
            .args(["build", "--bin", "varlinkctl-http"])
            .status()
            .expect("failed to run cargo build");
        assert!(status.success(), "cargo build --bin varlinkctl-http failed");
    });

    helper
}

/// Run `varlinkctl call <method> <params>` against `bridge_url`,
/// returning the process output. `extra_env` adds environment
/// variables (e.g. `XDG_CONFIG_HOME`, `VARLINK_SSH_KEY`).
async fn run_varlinkctl_call(
    bridge_url: &str,
    method: &str,
    params: &str,
    more: bool,
    extra_env: &[(&str, &std::path::Path)],
) -> std::process::Output {
    let exec = format!("exec:{}", helper_binary().display());
    let mut args = vec!["call"];
    if more {
        args.push("--more");
    }
    args.extend(["--json=short", exec.as_str(), method, params]);

    let mut cmd = tokio::process::Command::new("varlinkctl");
    cmd.args(&args)
        .env("VARLINK_BRIDGE_URL", bridge_url)
        // remove to avoid external env contamination
        .env_remove("SSH_AUTH_SOCK");
    for (key, val) in extra_env {
        cmd.env(key, val);
    }
    cmd.output().await.expect("failed to run varlinkctl")
}

/// Assert a `varlinkctl` call succeeded and returned this hosts hostname.
fn assert_hostname_reply(output: &std::process::Output) {
    let stderr = std::str::from_utf8(&output.stderr).unwrap();
    assert!(
        output.status.success(),
        "varlinkctl failed (stderr: {stderr})"
    );

    let stdout = std::str::from_utf8(&output.stdout).unwrap();
    let line = stdout.trim_start_matches('\x1e');
    let body: Value = serde_json::from_str(line).expect("varlinkctl output not valid JSON");
    let expected_hostname = gethostname().into_string().expect("failed to get hostname");
    assert_eq!(body["Hostname"], expected_hostname);
}

async fn run_test_server(varlink_sockets_path: &str) -> TestServer<std::net::SocketAddr> {
    run_test_server_with_auth(
        varlink_sockets_path,
        vec![Box::new(crate::AllowAllAuthenticator { reason: "test" })],
    )
    .await
}

async fn run_test_server_with_auth(
    varlink_sockets_path: &str,
    authenticators: Vec<Box<dyn Authenticator>>,
) -> TestServer<std::net::SocketAddr> {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind to random port failed");
    let addr = listener
        .local_addr()
        .expect("failed to extract local address");

    let varlink_sockets_path = varlink_sockets_path.to_string();
    let handle = tokio::spawn(async move {
        start_server(
            Transport::Tcp(listener),
            None,
            &varlink_sockets_path,
            authenticators,
        )
        .await
        .expect("server failed");
    });

    TestServer { handle, addr }
}

#[test_with::path(/run/systemd/io.systemd.Hostname)]
#[tokio::test]
async fn test_integration_real_systemd_hostname_post() {
    let server = run_test_server("/run/systemd").await;
    let client = Client::new();
    let res = client
        .post(format!(
            "http://{}/call/io.systemd.Hostname.Describe",
            server.addr,
        ))
        .json(&json!({}))
        .send()
        .await
        .expect("failed to post to test server");
    assert_eq!(res.status(), 200);
    let body: Value = res.json().await.expect("varlink body invalid");
    assert!(body["Hostname"].as_str().is_some_and(|h| !h.is_empty()));
}

#[test_with::path(/run/systemd/io.systemd.Hostname)]
#[tokio::test]
async fn test_integration_real_systemd_socket_get() {
    let server = run_test_server("/run/systemd").await;
    let client = Client::new();
    let res = client
        .get(format!(
            "http://{}/sockets/io.systemd.Hostname",
            server.addr,
        ))
        .send()
        .await
        .expect("failed to get from test server");
    assert_eq!(res.status(), 200);
    let body: Value = res.json().await.expect("varlink body invalid");
    assert_eq!(body["product"], "systemd (systemd-hostnamed)");
}

#[test_with::path(/run/systemd/io.systemd.Hostname)]
#[tokio::test]
async fn test_integration_real_systemd_sockets_get() {
    let server = run_test_server("/run/systemd").await;
    let client = Client::new();
    let res = client
        .get(format!("http://{}/sockets", server.addr))
        .send()
        .await
        .expect("failed to get from test server");
    assert_eq!(res.status(), 200);
    let body: Value = res.json().await.expect("varlink body invalid");
    assert!(
        body["sockets"]
            .as_array()
            .expect("sockets not an array")
            .contains(&json!("io.systemd.Hostname"))
    );
}

#[test_with::path(/run/systemd/io.systemd.Hostname)]
#[tokio::test]
async fn test_integration_real_systemd_socket_interface_get() {
    let server = run_test_server("/run/systemd").await;
    let client = Client::new();
    let res = client
        .get(format!(
            "http://{}/sockets/io.systemd.Hostname/io.systemd.Hostname",
            server.addr,
        ))
        .send()
        .await
        .expect("failed to get from test server");
    assert_eq!(res.status(), 200);
    let body: Value = res.json().await.expect("varlink body invalid");
    assert_eq!(body.get("method_names").unwrap(), &json!(["Describe"]));
}

#[test_with::path(/run/systemd/io.systemd.Hostname)]
#[tokio::test]
async fn test_integration_real_systemd_hostname_parallel() {
    const NUM_TASKS: u32 = 10;

    let server = run_test_server("/run/systemd").await;
    let url = format!("http://{}/call/io.systemd.Hostname.Describe", server.addr);

    let mut set = JoinSet::new();
    let client = Client::new();
    for _ in 0..NUM_TASKS {
        let client = client.clone();
        let target_url = url.clone();

        set.spawn(async move {
            let res = client
                .post(target_url)
                .json(&json!({}))
                .send()
                .await
                .expect("failed to post to test server");

            assert_eq!(res.status(), 200);
            let body: Value = res.json().await.expect("varlink body invalid");

            body["Hostname"].as_str().unwrap_or_default().to_string()
        });
    }
    let expected_hostname = gethostname().into_string().expect("failed to get hostname");

    let mut count = 0;
    while let Some(res) = set.join_next().await {
        let hostname = res.expect("client task to collect results panicked");
        assert_eq!(expected_hostname, hostname);
        count += 1;
    }
    assert_eq!(count, NUM_TASKS);
}

#[test_with::path(/run/systemd/io.systemd.Hostname)]
#[tokio::test]
async fn test_integration_real_systemd_socket_query_param() {
    let server = run_test_server("/run/systemd").await;
    let client = Client::new();
    let res = client
        .post(format!(
            "http://{}/call/org.varlink.service.GetInfo?socket=io.systemd.Hostname",
            server.addr,
        ))
        .json(&json!({}))
        .send()
        .await
        .expect("failed to post to test server");
    assert_eq!(res.status(), 200);
    let body: Value = res.json().await.expect("varlink body invalid");
    assert_eq!(body["product"], "systemd (systemd-hostnamed)");
}

#[test_with::path(/run/systemd)]
#[tokio::test]
async fn test_error_bad_request_on_malformed_json() {
    let server = run_test_server("/run/systemd").await;
    let client = Client::new();

    let res = client
        .post(format!(
            "http://{}/call/org.varlink.service.GetInfo",
            server.addr,
        ))
        .body("this is NOT valid json")
        .header("Content-Type", "application/json")
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
}

#[test_with::path(/run/systemd)]
#[tokio::test]
async fn test_error_unknown_varlink_address() {
    let server = run_test_server("/run/systemd").await;
    let client = Client::new();

    let res = client
        .post(format!(
            "http://{}/call/no.such.address.SomeMethod",
            server.addr,
        ))
        .body("{}")
        .header("Content-Type", "application/json")
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::BAD_GATEWAY);
    let body: Value = res.json().await.expect("error body invalid");
    let error_msg = body["error"].as_str().expect("error field missing");
    assert!(
        error_msg.starts_with("I/O error:"),
        "expected I/O error message, got: {error_msg}"
    );
}

#[test_with::path(/run/systemd/io.systemd.Hostname)]
#[tokio::test]
async fn test_error_404_for_missing_method() {
    let server = run_test_server("/run/systemd").await;
    let client = Client::new();

    let res = client
        .post(format!(
            "http://{}/call/com.missing.Call?socket=io.systemd.Hostname",
            server.addr
        ))
        .json(&json!({}))
        .send()
        .await
        .expect("failed to post to test server");

    assert_eq!(res.status(), StatusCode::NOT_FOUND);
    let body: Value = res.json().await.expect("error body invalid");
    assert_eq!(body["error"], "Method not found: com.missing.Call");
}

#[test_with::path(/run/systemd)]
#[tokio::test]
async fn test_error_bad_request_for_unclean_address() {
    let server = run_test_server("/run/systemd").await;
    let client = Client::new();

    let res = client
        .post(format!(
            // %2f is url encoding for "/" so socket param is ../io.systemd.Hostname
            "http://{}/call/com.missing.Call?socket=..%2fio.systemd.Hostname",
            server.addr
        ))
        .json(&json!({}))
        .send()
        .await
        .expect("failed to post to test server");

    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let body: Value = res.json().await.expect("error body invalid");
    assert_eq!(
        body["error"],
        "invalid socket name (must be a valid varlink interface name): ../io.systemd.Hostname"
    );
}

#[test_with::path(/run/systemd)]
#[tokio::test]
async fn test_error_bad_request_for_invalid_chars_in_address() {
    let server = run_test_server("/run/systemd").await;
    let client = Client::new();

    let res = client
        .post(format!(
            // %0A is \n
            "http://{}/call/com.missing.Call?socket=io.systemd.Hostname%0Abad-msg",
            server.addr
        ))
        .json(&json!({}))
        .send()
        .await
        .expect("failed to post to test server");

    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let body: Value = res.json().await.expect("error body invalid");
    assert_eq!(
        body["error"],
        "invalid socket name (must be a valid varlink interface name): io.systemd.Hostname\nbad-msg"
    );
}

#[test_with::path(/run/systemd)]
#[tokio::test]
async fn test_error_bad_request_for_method_without_dots() {
    let server = run_test_server("/run/systemd").await;
    let client = Client::new();

    let res = client
        .post(format!("http://{}/call/NoDots", server.addr))
        .json(&json!({}))
        .send()
        .await
        .expect("failed to post to test server");

    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let body: Value = res.json().await.expect("error body invalid");
    assert_eq!(
        body["error"],
        "cannot derive socket from method 'NoDots': no dots in name"
    );
}

#[test_with::path(/run/systemd)]
#[tokio::test]
async fn test_health_endpoint() {
    let server = run_test_server("/run/systemd").await;
    let client = Client::new();
    let res = client
        .get(format!("http://{}/health", server.addr))
        .send()
        .await
        .expect("failed to get health endpoint");

    assert_eq!(res.status(), 200);
}

#[tokio::test]
async fn test_varlink_sockets_dir_or_file_missing() {
    let varlink_sockets_dir_or_file = "/does-not-exist".to_string();

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind to random port failed");
    let res = start_server(
        Transport::Tcp(listener),
        None,
        &varlink_sockets_dir_or_file,
        Vec::new(),
    )
    .await;

    assert!(res.is_err());
    assert!(
        res.unwrap_err()
            .to_string()
            .contains("failed to stat /does-not-exist"),
    );
}

#[test_with::path(/run/systemd/io.systemd.Hostname)]
#[tokio::test]
async fn test_single_socket_post() {
    let server = run_test_server("/run/systemd/io.systemd.Hostname").await;
    let client = Client::new();
    let res = client
        .post(format!(
            "http://{}/call/io.systemd.Hostname.Describe",
            server.addr,
        ))
        .json(&json!({}))
        .send()
        .await
        .expect("failed to post to test server");
    assert_eq!(res.status(), 200);
    let body: Value = res.json().await.expect("varlink body invalid");
    assert!(body["Hostname"].as_str().is_some_and(|h| !h.is_empty()));
}

#[test_with::path(/run/systemd/io.systemd.Hostname)]
#[tokio::test]
async fn test_single_socket_rejects_wrong_name() {
    let server = run_test_server("/run/systemd/io.systemd.Hostname").await;
    let client = Client::new();
    let res = client
        .post(format!(
            "http://{}/call/io.systemd.Wrong.Describe",
            server.addr,
        ))
        .json(&json!({}))
        .send()
        .await
        .expect("failed to post to test server");
    assert_eq!(res.status(), StatusCode::BAD_GATEWAY);
    let body: Value = res.json().await.expect("error body invalid");
    assert_eq!(
        body["error"],
        "socket 'io.systemd.Wrong' not available (only 'io.systemd.Hostname' is available)"
    );
}

#[test_with::path(/run/systemd/io.systemd.Hostname)]
#[tokio::test]
async fn test_varlink_unix_sockets_in_follows_symlinks() {
    let tmpdir = tempfile::tempdir().expect("failed to create tempdir");
    let symlink_path = tmpdir.path().join("io.systemd.Hostname");

    std::os::unix::fs::symlink("/run/systemd/io.systemd.Hostname", &symlink_path)
        .expect("failed to create symlink");

    let dir_fd = OwnedFd::from(std::fs::File::open(tmpdir.path()).unwrap());
    let vs = VarlinkSockets::SocketDir { dirfd: dir_fd };
    let sockets = vs.list_sockets().await.expect("list_sockets failed");
    assert_eq!(sockets, vec!["io.systemd.Hostname"]);
}

#[test_with::path(/run/systemd/io.systemd.Hostname)]
#[tokio::test]
async fn test_varlink_unix_sockets_in_skips_dangling_symlinks() {
    let tmpdir = tempfile::tempdir().expect("failed to create tempdir");

    let good = tmpdir.path().join("io.systemd.Hostname");
    std::os::unix::fs::symlink("/run/systemd/io.systemd.Hostname", &good)
        .expect("failed to create symlink");

    let bad = tmpdir.path().join("io.example.Bad");
    std::os::unix::fs::symlink("/no/such/socket", &bad).expect("failed to create dangling symlink");

    let dir_fd = OwnedFd::from(std::fs::File::open(tmpdir.path()).unwrap());
    let vs = VarlinkSockets::SocketDir { dirfd: dir_fd };
    let sockets = vs
        .list_sockets()
        .await
        .expect("list_sockets should not fail on dangling symlinks");
    assert_eq!(sockets, vec!["io.systemd.Hostname"]);
}

#[test_with::path(/run/systemd/io.systemd.Hostname)]
#[tokio::test]
async fn test_ws_hostname_describe() {
    let server = run_test_server("/run/systemd").await;
    let url = format!("ws://{}/ws/sockets/io.systemd.Hostname", server.addr);
    let (mut ws, _) = tokio_tungstenite::connect_async(&url)
        .await
        .expect("WS connect failed");

    let mut msg = r#"{"method":"io.systemd.Hostname.Describe","parameters":{}}"#.to_string();
    msg.push('\0');
    ws.send(WsMsg::Text(msg.into()))
        .await
        .expect("WS send failed");

    // each varlink message arrives as one WS binary frame (with NUL delimiter)
    let msg = ws
        .next()
        .await
        .expect("no WS response")
        .expect("WS recv error");
    let data = msg.into_data();
    let json_bytes = data.strip_suffix(&[0]).unwrap_or(&data);
    let body: Value = serde_json::from_slice(json_bytes).expect("response not valid JSON");

    // raw varlink protocol wraps responses in "parameters"
    let expected_hostname = gethostname().into_string().expect("failed to get hostname");
    assert_eq!(body["parameters"]["Hostname"], expected_hostname);
}

#[test_with::path(/run/systemd/userdb/io.systemd.Multiplexer)]
#[tokio::test]
async fn test_ws_userdb_get_user_record_more() {
    let server = run_test_server("/run/systemd/userdb").await;
    let url = format!("ws://{}/ws/sockets/io.systemd.Multiplexer", server.addr);
    let (mut ws, _) = tokio_tungstenite::connect_async(&url)
        .await
        .expect("WS connect failed");

    // Send varlink "more" call as binary frame (NUL-delimited)
    let mut msg = r#"{
        "method": "io.systemd.UserDatabase.GetUserRecord",
        "parameters": {"service": "io.systemd.Multiplexer"},
        "more": true
    }"#
    .as_bytes()
    .to_vec();
    msg.push(0);
    ws.send(WsMsg::Binary(msg.into()))
        .await
        .expect("WS send failed");

    let mut users = Vec::new();
    loop {
        let Some(Ok(msg)) = ws.next().await else {
            break;
        };
        let data = msg.into_data();
        let json_bytes = data.strip_suffix(&[0]).unwrap_or(&data);
        if json_bytes.is_empty() {
            continue;
        }
        let body: Value = serde_json::from_slice(json_bytes).expect("response not valid JSON");

        if body.get("error").is_some() {
            break;
        }
        let name = body["parameters"]["record"]["userName"]
            .as_str()
            .expect("userName missing from user record");
        users.push(name.to_string());

        if !body
            .get("continues")
            .and_then(Value::as_bool)
            .unwrap_or(false)
        {
            break;
        }
    }

    // we expect at least root + current user
    assert!(
        users.len() >= 2,
        "expected at least 2 user records, got users {users:#?}"
    );
}

#[test_with::path(/run/systemd/io.systemd.Hostname)]
#[tokio::test]
async fn test_varlink_conn_cache_reuses_connection() {
    let sockets = Arc::new(VarlinkSockets::from_socket_dir("/run/systemd").unwrap());
    let state = AppState {
        varlink_sockets: sockets,
        authenticators: Arc::new(Vec::new()),
    };
    let cache = VarlinkConnCache::new(None);

    let conn1 = get_varlink_connection("io.systemd.Hostname", &state, &cache)
        .await
        .unwrap();
    let conn2 = get_varlink_connection("io.systemd.Hostname", &state, &cache)
        .await
        .unwrap();
    assert!(
        Arc::ptr_eq(&conn1, &conn2),
        "expected cached connection to be reused"
    );

    // different socket gets a different connection
    let conn3 = get_varlink_connection("io.systemd.Manager", &state, &cache)
        .await
        .unwrap();
    assert!(
        !Arc::ptr_eq(&conn1, &conn3),
        "different sockets should have different connections"
    );
}

/// Parse a JSON text sequence (RFC 7464) body into a Vec of JSON values.
/// Each record is RS (0x1E) + JSON + LF.
fn parse_json_seq(body: &[u8]) -> Vec<Value> {
    body.split(|&b| b == 0x1e)
        .filter(|chunk| !chunk.is_empty())
        .map(|chunk| {
            let trimmed = chunk.strip_suffix(b"\n").unwrap_or(chunk);
            serde_json::from_slice(trimmed).expect("json-seq record is not valid JSON")
        })
        .collect()
}

#[test_with::path(/run/systemd/io.systemd.Hostname)]
#[tokio::test]
async fn test_jsonseq_hostname_describe() {
    let server = run_test_server("/run/systemd").await;
    let client = Client::new();
    let res = client
        .post(format!(
            "http://{}/call/io.systemd.Hostname.Describe",
            server.addr,
        ))
        .header("Accept", "application/json-seq")
        .json(&json!({}))
        .send()
        .await
        .expect("failed to post to test server");
    assert_eq!(res.status(), 200);
    assert_eq!(
        res.headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok()),
        Some("application/json-seq")
    );

    let body = res.bytes().await.expect("failed to read body");
    let records = parse_json_seq(&body);

    // non-streaming method: exactly one record
    assert_eq!(
        records.len(),
        1,
        "expected 1 json-seq record, got {records:#?}"
    );
    let expected_hostname = gethostname().into_string().expect("failed to get hostname");
    assert_eq!(records[0]["Hostname"], expected_hostname);
}

#[test_with::path(/run/systemd/userdb/io.systemd.Multiplexer)]
#[tokio::test]
async fn test_jsonseq_userdb_get_user_record_more() {
    let server = run_test_server("/run/systemd/userdb").await;
    let client = Client::new();
    let res = client
        .post(format!(
            "http://{}/call/io.systemd.UserDatabase.GetUserRecord?socket=io.systemd.Multiplexer",
            server.addr,
        ))
        .header("Accept", "application/json-seq")
        .json(&json!({"service": "io.systemd.Multiplexer"}))
        .send()
        .await
        .expect("failed to post to test server");
    assert_eq!(res.status(), 200);
    assert_eq!(
        res.headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok()),
        Some("application/json-seq")
    );

    let body = res.bytes().await.expect("failed to read body");
    let records = parse_json_seq(&body);

    let users: Vec<&str> = records
        .iter()
        .filter_map(|r| r["record"]["userName"].as_str())
        .collect();

    // we expect at least root + current user
    assert!(
        users.len() >= 2,
        "expected at least 2 user records, got {users:#?}"
    );
    assert!(users.contains(&"root"), "root user not found in {users:#?}");
}

#[test_with::path(/usr/bin/varlinkctl)]
#[test_with::path(/run/systemd/io.systemd.Hostname)]
#[tokio::test]
async fn test_varlinkctl_helper_hostname_describe() {
    let server = run_test_server("/run/systemd").await;
    let bridge_url = format!("http://{}/ws/sockets/io.systemd.Hostname", server.addr);
    let output = run_varlinkctl_call(
        &bridge_url,
        "io.systemd.Hostname.Describe",
        "{}",
        false,
        &[],
    )
    .await;
    assert_hostname_reply(&output);
}

#[test_with::path(/usr/bin/varlinkctl)]
#[test_with::path(/run/systemd/userdb/io.systemd.Multiplexer)]
#[tokio::test]
async fn test_varlinkctl_helper_userdb_get_user_record() {
    let server = run_test_server("/run/systemd/userdb").await;
    let bridge_url = format!("http://{}/ws/sockets/io.systemd.Multiplexer", server.addr);
    let output = run_varlinkctl_call(
        &bridge_url,
        "io.systemd.UserDatabase.GetUserRecord",
        r#"{"service":"io.systemd.Multiplexer"}"#,
        true,
        &[],
    )
    .await;

    let stderr = std::str::from_utf8(&output.stderr).unwrap();
    assert!(
        output.status.success(),
        "varlinkctl failed (stderr: {stderr})"
    );

    let stdout = String::from_utf8(output.stdout).expect("invalid UTF-8 in varlinkctl output");
    let mut users = Vec::new();
    for line in stdout.lines() {
        // varlinkctl uses JSON Text Sequences (RFC 7464): each record is
        // prefixed with U+001E (Record Separator)
        let line = line.trim().trim_start_matches('\x1e');
        if line.is_empty() {
            continue;
        }
        let body: Value =
            serde_json::from_str(line).expect("varlinkctl output not valid JSON: {e}: {line:?}");
        if let Some(name) = body["record"]["userName"].as_str() {
            users.push(name.to_string());
        }
    }

    // we expect at least root + current user
    assert!(
        users.len() >= 2,
        "expected at least 2 user records, got users {users:#?}"
    );
}

struct TestPki {
    _tmpdir: tempfile::TempDir,
    ca_cert_pem: Vec<u8>,
    server_cert_path: std::path::PathBuf,
    server_key_path: std::path::PathBuf,
    ca_cert_path: std::path::PathBuf,
    client_cert_path: std::path::PathBuf,
    client_key_path: std::path::PathBuf,
    client_cert_pem: Vec<u8>,
    client_key_pem: Vec<u8>,
}

#[rustfmt::skip]
fn make_test_pki() -> TestPki {
    use std::process::Command;

    let tmpdir = tempfile::tempdir().unwrap();
    let d = tmpdir.path();

    let openssl = |args: &[&str]| {
        let out = Command::new("openssl").args(args).output().unwrap();
        assert!(
            out.status.success(),
            "openssl {args:?} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    };

    // CA key + self-signed cert
    openssl(&[
        "req", "-x509", "-newkey", "rsa:2048", "-nodes",
        "-keyout", d.join("ca-key.pem").to_str().unwrap(),
        "-out",    d.join("ca.pem").to_str().unwrap(),
        "-subj",   "/CN=Test CA",
        "-days",   "365",
    ]);

    // Server key + CSR + cert signed by CA (with SAN)
    openssl(&[
        "req", "-newkey", "rsa:2048", "-nodes",
        "-keyout", d.join("server-key.pem").to_str().unwrap(),
        "-out",    d.join("server.csr").to_str().unwrap(),
        "-subj",   "/CN=localhost",
        "-addext", "subjectAltName=DNS:localhost",
    ]);
    openssl(&[
        "x509", "-req",
        "-in",      d.join("server.csr").to_str().unwrap(),
        "-CA",      d.join("ca.pem").to_str().unwrap(),
        "-CAkey",   d.join("ca-key.pem").to_str().unwrap(),
        "-CAcreateserial",
        "-out",     d.join("server-cert.pem").to_str().unwrap(),
        "-days",    "365",
        "-copy_extensions", "copy",
    ]);

    // Client key + CSR + cert signed by CA
    openssl(&[
        "req", "-newkey", "rsa:2048", "-nodes",
        "-keyout", d.join("client-key.pem").to_str().unwrap(),
        "-out",    d.join("client.csr").to_str().unwrap(),
        "-subj",   "/CN=test-client",
    ]);
    openssl(&[
        "x509", "-req",
        "-in",      d.join("client.csr").to_str().unwrap(),
        "-CA",      d.join("ca.pem").to_str().unwrap(),
        "-CAkey",   d.join("ca-key.pem").to_str().unwrap(),
        "-CAcreateserial",
        "-out",     d.join("client-cert.pem").to_str().unwrap(),
        "-days",    "365",
    ]);

    TestPki {
        ca_cert_pem:       std::fs::read(d.join("ca.pem")).unwrap(),
        server_cert_path:  d.join("server-cert.pem"),
        server_key_path:   d.join("server-key.pem"),
        ca_cert_path:      d.join("ca.pem"),
        client_cert_path:  d.join("client-cert.pem"),
        client_key_path:   d.join("client-key.pem"),
        client_cert_pem:   std::fs::read(d.join("client-cert.pem")).unwrap(),
        client_key_pem:    std::fs::read(d.join("client-key.pem")).unwrap(),
        _tmpdir: tmpdir,
    }
}

async fn run_test_tls_server(
    varlink_sockets_path: &str,
    tls_acceptor: openssl::ssl::SslAcceptor,
) -> TestServer<std::net::SocketAddr> {
    // mirror the production mTLS-only path: the client is verified during
    // the TLS handshake, no per-request HTTP authentication
    run_test_tls_server_with_auth(
        varlink_sockets_path,
        tls_acceptor,
        vec![Box::new(crate::AllowAllAuthenticator { reason: "test" })],
    )
    .await
}

async fn run_test_tls_server_with_auth(
    varlink_sockets_path: &str,
    tls_acceptor: openssl::ssl::SslAcceptor,
    authenticators: Vec<Box<dyn Authenticator>>,
) -> TestServer<std::net::SocketAddr> {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind to random port failed");
    let addr = listener
        .local_addr()
        .expect("failed to extract local address");

    let varlink_sockets_path = varlink_sockets_path.to_string();
    let handle = tokio::spawn(async move {
        start_server(
            Transport::Tcp(listener),
            Some(tls_acceptor),
            &varlink_sockets_path,
            authenticators,
        )
        .await
        .expect("server failed");
    });

    TestServer { handle, addr }
}

#[test_with::path(/usr/bin/openssl)]
#[tokio::test]
async fn test_tls_basic_connection() {
    let pki = make_test_pki();
    let varlink_dir = tempfile::tempdir().unwrap();

    let acceptor = load_tls_acceptor(
        pki.server_cert_path.to_str().unwrap(),
        pki.server_key_path.to_str().unwrap(),
        None,
    )
    .unwrap();

    let server = run_test_tls_server(varlink_dir.path().to_str().unwrap(), acceptor).await;
    let ca_cert = reqwest::Certificate::from_pem(&pki.ca_cert_pem).unwrap();
    let client = Client::builder()
        .add_root_certificate(ca_cert)
        .resolve("localhost", server.addr)
        .build()
        .unwrap();

    let res = client
        .get(format!("https://localhost:{}/health", server.addr.port()))
        .send()
        .await
        .expect("TLS connection failed");
    assert_eq!(res.status(), 200);
}

#[test_with::path(/usr/bin/openssl)]
#[tokio::test]
async fn test_mtls_accepts_client_cert_and_rejects_without() {
    init_test_logger();

    let pki = make_test_pki();
    let varlink_dir = tempfile::tempdir().unwrap();

    let acceptor = load_tls_acceptor(
        pki.server_cert_path.to_str().unwrap(),
        pki.server_key_path.to_str().unwrap(),
        Some(pki.ca_cert_path.to_str().unwrap()),
    )
    .unwrap();

    let server = run_test_tls_server(varlink_dir.path().to_str().unwrap(), acceptor).await;
    // Without a client certificate the TLS handshake is rejected
    let ca_cert = reqwest::Certificate::from_pem(&pki.ca_cert_pem).unwrap();
    let client_no_cert = Client::builder()
        .add_root_certificate(ca_cert)
        .resolve("localhost", server.addr)
        .build()
        .unwrap();

    let result = client_no_cert
        .get(format!("https://localhost:{}/health", server.addr.port()))
        .send()
        .await;
    assert!(
        result.is_err(),
        "connection without client cert should fail with mTLS"
    );

    // With a valid client certificate the request succeeds
    let ca_cert = reqwest::Certificate::from_pem(&pki.ca_cert_pem).unwrap();
    let identity =
        reqwest::Identity::from_pkcs8_pem(&pki.client_cert_pem, &pki.client_key_pem).unwrap();
    let client_with_cert = Client::builder()
        .add_root_certificate(ca_cert)
        .identity(identity)
        .resolve("localhost", server.addr)
        .build()
        .unwrap();

    let res = client_with_cert
        .get(format!("https://localhost:{}/health", server.addr.port()))
        .send()
        .await
        .expect("mTLS connection with client cert failed");
    assert_eq!(res.status(), 200);

    // Verify that the mTLS connection was logged with the client cert subject
    let logs = TEST_LOG_MESSAGES.lock().unwrap();
    assert!(
        logs.iter()
            .any(|msg| msg.contains("[INFO] New TLS connection from")
                && msg.contains("client cert: CN=test-client")),
        "expected mTLS connection log with client cert subject, got: {logs:?}"
    );
}

#[test_with::path(/usr/bin/openssl)]
#[tokio::test]
async fn test_tls_credentials_directory_fallback() {
    let pki = make_test_pki();

    // Set up a fake credentials directory with the well-known file names
    let creds_dir = tempfile::tempdir().unwrap();
    std::fs::copy(&pki.server_cert_path, creds_dir.path().join("cert")).unwrap();
    std::fs::copy(&pki.server_key_path, creds_dir.path().join("key")).unwrap();

    // No CLI flags; resolve_tls_acceptor should pick up creds from the directory
    let acceptor = resolve_tls_acceptor(None, None, None, Some(creds_dir.path()))
        .expect("credentials directory fallback failed")
        .expect("expected Some(acceptor) from credentials directory");

    let varlink_dir = tempfile::tempdir().unwrap();
    let server = run_test_tls_server(varlink_dir.path().to_str().unwrap(), acceptor).await;
    let ca_cert = reqwest::Certificate::from_pem(&pki.ca_cert_pem).unwrap();
    let client = Client::builder()
        .add_root_certificate(ca_cert)
        .resolve("localhost", server.addr)
        .build()
        .unwrap();

    let res = client
        .get(format!("https://localhost:{}/health", server.addr.port()))
        .send()
        .await
        .expect("TLS via credentials directory failed");
    assert_eq!(res.status(), 200);
}

#[test_with::path(/usr/bin/openssl)]
#[test_with::path(/usr/bin/varlinkctl)]
#[test_with::path(/run/systemd/io.systemd.Hostname)]
#[tokio::test]
async fn test_varlinkctl_helper_mtls_hostname_describe() {
    let pki = make_test_pki();

    let acceptor = load_tls_acceptor(
        pki.server_cert_path.to_str().unwrap(),
        pki.server_key_path.to_str().unwrap(),
        Some(pki.ca_cert_path.to_str().unwrap()),
    )
    .unwrap();

    let server = run_test_tls_server("/run/systemd", acceptor).await;
    let fake_xdg_home = tempfile::tempdir().unwrap();
    let tls_dir = fake_xdg_home.path().join("varlinkctl-http");
    std::fs::create_dir_all(&tls_dir).unwrap();
    std::fs::copy(&pki.client_cert_path, tls_dir.join("client-cert-file")).unwrap();
    std::fs::copy(&pki.client_key_path, tls_dir.join("client-key-file")).unwrap();
    std::fs::copy(&pki.ca_cert_path, tls_dir.join("server-ca-file")).unwrap();

    let bridge_url = format!(
        "https://localhost:{}/ws/sockets/io.systemd.Hostname",
        server.addr.port()
    );

    let output = run_varlinkctl_call(
        &bridge_url,
        "io.systemd.Hostname.Describe",
        "{}",
        false,
        &[("XDG_CONFIG_HOME", fake_xdg_home.path())],
    )
    .await;
    assert_hostname_reply(&output);
}

#[test_with::path(/usr/bin/openssl)]
#[test_with::path(/usr/bin/varlinkctl)]
#[test_with::path(/run/systemd/io.systemd.Hostname)]
#[tokio::test]
async fn test_varlinkctl_helper_mtls_no_client_cert() {
    let pki = make_test_pki();

    let acceptor = load_tls_acceptor(
        pki.server_cert_path.to_str().unwrap(),
        pki.server_key_path.to_str().unwrap(),
        Some(pki.ca_cert_path.to_str().unwrap()),
    )
    .unwrap();

    let server = run_test_tls_server("/run/systemd", acceptor).await;
    // Provide the server CA (so the client trusts the server) but NO client cert/key
    let fake_xdg_home = tempfile::tempdir().unwrap();
    let tls_dir = fake_xdg_home.path().join("varlinkctl-http");
    std::fs::create_dir_all(&tls_dir).unwrap();
    std::fs::copy(&pki.ca_cert_path, tls_dir.join("server-ca-file")).unwrap();

    let bridge_url = format!(
        "https://localhost:{}/ws/sockets/io.systemd.Hostname",
        server.addr.port()
    );

    let output = run_varlinkctl_call(
        &bridge_url,
        "io.systemd.Hostname.Describe",
        "{}",
        false,
        &[("XDG_CONFIG_HOME", fake_xdg_home.path())],
    )
    .await;

    let stderr = std::str::from_utf8(&output.stderr).unwrap();
    assert!(
        !output.status.success(),
        "expected failure without client cert, but helper succeeded"
    );
    assert!(
        stderr.contains("check client cert if server requires mTLS"),
        "expected mTLS hint in error, got: {stderr}"
    );
}

#[test]
fn test_tls_credentials_directory_returns_none_without_creds() {
    let empty_dir = tempfile::tempdir().unwrap();
    let result = resolve_tls_acceptor(None, None, None, Some(empty_dir.path())).unwrap();
    assert!(
        result.is_none(),
        "empty credentials dir should yield no TLS"
    );
}

#[test_with::path(/usr/bin/openssl)]
#[test]
fn test_format_x509_subject() {
    let pki = make_test_pki();
    let pem = std::fs::read(&pki.client_cert_path).unwrap();
    let cert = openssl::x509::X509::from_pem(&pem).unwrap();
    let subject = format_x509_subject(&cert);
    assert_eq!(subject, "CN=test-client");
}

#[test_with::path(/usr/bin/openssl)]
#[test]
fn test_format_x509_subject_multiple_fields() {
    use std::process::Command;

    let tmpdir = tempfile::tempdir().unwrap();
    let d = tmpdir.path();
    let key_path = d.join("key.pem");
    let cert_path = d.join("cert.pem");
    #[rustfmt::skip]
    let openssl_args = [
        "req", "-x509", "-newkey", "rsa:2048", "-nodes",
        "-keyout", key_path.to_str().unwrap(),
        "-out",    cert_path.to_str().unwrap(),
        "-subj",   "/O=TestOrg/CN=multi-field",
        "-days",   "1",
    ];
    let out = Command::new("openssl").args(openssl_args).output().unwrap();
    assert!(out.status.success());

    let pem = std::fs::read(d.join("cert.pem")).unwrap();
    let cert = openssl::x509::X509::from_pem(&pem).unwrap();
    let subject = format_x509_subject(&cert);
    assert_eq!(subject, "O=TestOrg, CN=multi-field");
}

// --- bind address parsing tests ---

#[test]
fn test_bind_addr_parse_defaults() {
    // "vsock" and "vsock:" both mean CID_ANY + default port
    for input in ["vsock", "vsock:"] {
        let bind: BindAddr = input.parse().unwrap();
        match bind {
            BindAddr::Vsock { cid, port } => {
                assert_eq!(cid, vsock::VMADDR_CID_ANY, "input: {input}");
                assert_eq!(port, DEFAULT_PORT, "input: {input}");
            }
            BindAddr::Tcp(_) => panic!("expected Vsock, got {bind:?}"),
        }
    }
}

#[test]
fn test_bind_addr_parse_port_only() {
    // "vsock::2000" -> CID_ANY, port 2000
    let bind: BindAddr = "vsock::2000".parse().unwrap();
    match bind {
        BindAddr::Vsock { cid, port } => {
            assert_eq!(cid, vsock::VMADDR_CID_ANY);
            assert_eq!(port, 2000);
        }
        BindAddr::Tcp(_) => panic!("expected Vsock"),
    }
}

#[test]
fn test_bind_addr_parse_cid_and_port() {
    // "vsock:5:3333" -> CID 5, port 3333
    let bind: BindAddr = "vsock:5:3333".parse().unwrap();
    match bind {
        BindAddr::Vsock { cid, port } => {
            assert_eq!(cid, 5);
            assert_eq!(port, 3333);
        }
        BindAddr::Tcp(_) => panic!("expected Vsock"),
    }
}

#[test]
fn test_bind_addr_parse_tcp() {
    let bind: BindAddr = "0.0.0.0:1031".parse().unwrap();
    match bind {
        BindAddr::Tcp(addr) => assert_eq!(addr, "0.0.0.0:1031"),
        BindAddr::Vsock { .. } => panic!("expected Tcp"),
    }
}

#[test]
fn test_bind_addr_parse_errors() {
    assert!("vsock::notaport".parse::<BindAddr>().is_err());
    assert!("vsock:abc:1031".parse::<BindAddr>().is_err());
}

// --- vsock integration tests ---

/// Check if vsock loopback (CID 1) is functional.
/// Returns false if the `vsock_loopback` module is not loaded.
fn vsock_loopback_available() -> bool {
    use std::io::Read;

    let Ok(listener) = vsock::VsockListener::bind_with_cid_port(vsock::VMADDR_CID_ANY, 0) else {
        return false;
    };
    let port = match listener.local_addr() {
        Ok(a) => a.port(),
        Err(_) => return false,
    };

    // Spawn a thread to accept one connection so we can test connect
    let handle = std::thread::spawn(move || {
        listener
            .set_nonblocking(false)
            .expect("set_nonblocking failed");
        if let Ok((mut conn, _)) = listener.accept() {
            let mut buf = [0u8; 1];
            let _ = conn.read(&mut buf);
        }
    });

    let ok = vsock::VsockStream::connect_with_cid_port(1, port).is_ok();
    // Clean up: connect success wakes the accept, connect failure means thread is stuck
    // on accept -- drop the listener (which is moved into the thread) to unblock it
    let _ = handle.join();
    ok
}

fn run_test_vsock_server(varlink_sockets_path: &str) -> TestServer<u32> {
    // Use port 0 to get an ephemeral port
    let listener = VsockListener::bind(tokio_vsock::VsockAddr::new(vsock::VMADDR_CID_ANY, 0))
        .expect("vsock bind failed");
    let addr = listener.local_addr().expect("local_addr failed").port();

    let varlink_sockets_path = varlink_sockets_path.to_string();
    let handle = tokio::spawn(async move {
        start_server(
            Transport::Vsock(listener),
            None,
            &varlink_sockets_path,
            Vec::new(),
        )
        .await
        .expect("vsock server failed");
    });

    TestServer { handle, addr }
}

#[test_with::path(/run/systemd/io.systemd.Hostname)]
#[tokio::test]
async fn test_vsock_health_endpoint() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    if !vsock_loopback_available() {
        eprintln!("SKIP: vsock loopback not available (vsock_loopback module not loaded?)");
        return;
    }

    let server = run_test_vsock_server("/run/systemd");
    // Connect over vsock loopback (CID 1) and do a raw HTTP GET /health
    let mut stream = tokio_vsock::VsockStream::connect(tokio_vsock::VsockAddr::new(1, server.addr))
        .await
        .expect("vsock connect failed");

    stream
        .write_all(b"GET /health HTTP/1.1\r\nHost: vsock\r\n\r\n")
        .await
        .expect("write failed");
    let mut buf = vec![0u8; 1024];
    let n = stream.read(&mut buf).await.expect("read failed");
    let response = String::from_utf8_lossy(&buf[..n]);
    assert!(
        response.starts_with("HTTP/1.1 200"),
        "expected 200 OK, got: {response}"
    );
}

#[test_with::path(/usr/bin/varlinkctl)]
#[test_with::path(/run/systemd/io.systemd.Hostname)]
#[tokio::test]
async fn test_varlinkctl_helper_vsock_hostname_describe() {
    if !vsock_loopback_available() {
        eprintln!("SKIP: vsock loopback not available (vsock_loopback module not loaded?)");
        return;
    }

    let server = run_test_vsock_server("/run/systemd");
    let bridge_url = format!("vsock://1:{}/ws/sockets/io.systemd.Hostname", server.addr);
    let output = run_varlinkctl_call(
        &bridge_url,
        "io.systemd.Hostname.Describe",
        "{}",
        false,
        &[],
    )
    .await;
    assert_hostname_reply(&output);
}

// --- SSH key auth tests ---

#[cfg(feature = "sshauth")]
mod sshauth_tests {
    use super::*;
    use crate::create_ssh_authenticator;

    /// Create a fake rootdir with an `etc/varlink-httpd/authorized_keys` file.
    fn make_test_rootdir_with_keys(pubkeys: &[&str]) -> tempfile::TempDir {
        use std::io::Write;
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("etc/varlink-httpd");
        std::fs::create_dir_all(&dir).unwrap();
        let mut f = std::fs::File::create(dir.join("authorized_keys")).unwrap();
        for key in pubkeys {
            writeln!(f, "{key}").unwrap();
        }
        root
    }

    /// Generate an ed25519 key pair, returning (`pubkey_line`, `privkey_path`).
    fn generate_ed25519_keypair(dir: &std::path::Path) -> (String, std::path::PathBuf) {
        let key_path = dir.join("test_ed25519");
        let status = std::process::Command::new("ssh-keygen")
            .args(["-t", "ed25519", "-f"])
            .arg(&key_path)
            .args(["-N", "", "-q"])
            .status()
            .expect("ssh-keygen failed to run");
        assert!(status.success(), "ssh-keygen failed");
        let pubkey_line = std::fs::read_to_string(key_path.with_extension("pub")).unwrap();
        (pubkey_line, key_path)
    }

    /// Set up an SSH authenticator from a freshly generated ed25519 keypair.
    ///
    /// Returns the authenticator plus the path to the private key (for tests
    /// that also need to sign tokens).
    fn make_test_ssh_auth() -> (crate::auth_ssh::SshKeyAuthenticator, std::path::PathBuf) {
        let tmpdir = tempfile::tempdir().unwrap();
        let (pubkey_line, key_path) = generate_ed25519_keypair(tmpdir.path());
        let root = make_test_rootdir_with_keys(&[pubkey_line.trim()]);
        let auth = create_ssh_authenticator(None, None, root.path()).unwrap();
        // Leak both tempdirs so they live for the test duration.
        // (The keypair dir and the rootdir with authorized_keys.)
        std::mem::forget(tmpdir);
        std::mem::forget(root);
        (auth, key_path)
    }

    /// Build a [`sshauth::signer::TokenSigner`] from the private key at `key_path`,
    /// pre-configured with fingerprint and magic prefix matching the server.
    fn make_test_token_signer(key_path: &std::path::Path) -> sshauth::signer::TokenSigner {
        let privkey_pem = std::fs::read_to_string(key_path).unwrap();
        let privkey = ssh_key::PrivateKey::from_openssh(&privkey_pem).unwrap();
        let mut builder = sshauth::TokenSigner::using_private_key(privkey).unwrap();
        builder.include_fingerprint(true).magic_prefix(*b"vhbridge");
        builder.build().unwrap()
    }

    fn make_auth_test_router(authenticators: Vec<Box<dyn Authenticator>>) -> Router {
        let tmpdir = tempfile::tempdir().unwrap();
        // Keep tmpdir so it lives for the test duration (but gets cleaned up eventually)
        let path = tmpdir.keep();
        create_router(path.to_str().unwrap(), authenticators).unwrap()
    }

    #[test]
    fn test_ssh_auth_parse_authorized_keys_ed25519() {
        let (auth, _) = make_test_ssh_auth();
        assert_eq!(auth.key_count(), 1);
    }

    #[test]
    fn test_ssh_auth_parse_authorized_keys_rsa() {
        // Use ssh-keygen to generate an RSA key for the test
        let tmpdir = tempfile::tempdir().unwrap();
        let key_path = tmpdir.path().join("test_rsa");
        let status = std::process::Command::new("ssh-keygen")
            .args(["-t", "rsa", "-b", "2048", "-f"])
            .arg(&key_path)
            .args(["-N", "", "-q"])
            .status()
            .expect("ssh-keygen failed to run");
        assert!(status.success(), "ssh-keygen failed");

        let pub_key_content = std::fs::read_to_string(key_path.with_extension("pub")).unwrap();
        let root = make_test_rootdir_with_keys(&[pub_key_content.trim()]);
        let auth = create_ssh_authenticator(None, None, root.path()).unwrap();
        assert_eq!(
            auth.key_count(),
            0,
            "RSA-only authorized_keys should have 0 usable keys"
        );
    }

    #[test]
    fn test_ssh_auth_accepts_garbage() {
        let root = make_test_rootdir_with_keys(&["not-a-real-key line", "# comment"]);
        let auth = create_ssh_authenticator(None, None, root.path()).unwrap();
        assert_eq!(
            auth.key_count(),
            0,
            "garbage authorized_keys should have 0 usable keys"
        );
    }

    #[test]
    fn test_ssh_auth_drops_keys_when_file_removed() {
        let keydir_a = tempfile::tempdir().unwrap();
        let keydir_b = tempfile::tempdir().unwrap();
        let (pubkey_a, _) = generate_ed25519_keypair(keydir_a.path());
        let (pubkey_b, _) = generate_ed25519_keypair(keydir_b.path());

        let file_a = keydir_a.path().join("authorized_keys");
        let file_b = keydir_b.path().join("authorized_keys");
        std::fs::write(&file_a, pubkey_a.as_bytes()).unwrap();
        std::fs::write(&file_b, pubkey_b.as_bytes()).unwrap();

        let auth = crate::auth_ssh::SshKeyAuthenticator::new(vec![
            file_a.to_string_lossy().into_owned(),
            file_b.to_string_lossy().into_owned(),
        ])
        .unwrap();
        assert_eq!(auth.key_count(), 2);

        std::fs::remove_file(&file_b).unwrap();
        auth.reload_for_test();
        assert_eq!(
            auth.key_count(),
            1,
            "key from removed file should be dropped"
        );

        std::fs::remove_file(&file_a).unwrap();
        auth.reload_for_test();
        assert_eq!(
            auth.key_count(),
            0,
            "all keys should be dropped when every source is removed"
        );
    }

    #[tokio::test]
    async fn test_ssh_auth_rejects_expired_timestamp() {
        let (auth, key_path) = make_test_ssh_auth();
        let auth = auth.with_max_skew(0);
        let signer = make_test_token_signer(&key_path);

        let nonce = "test-nonce-expired12345";
        let mut tb = signer.sign_for();
        tb.action("method", "GET")
            .action("path", "/sockets")
            .action("nonce", nonce);
        let token = tb.sign().await.unwrap();

        // Wait for the token to become stale (max_skew is 0)
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;

        let header = format!("Bearer {}", token.encode());
        let result = check_request(&auth, "GET", "/sockets", Some(&header), Some(nonce), None);
        assert!(result.is_err(), "expired token should be rejected");
    }

    #[tokio::test]
    async fn test_ssh_auth_rejects_unknown_fingerprint() {
        // Key A: in authorized_keys
        let (auth, _) = make_test_ssh_auth();

        // Key B: NOT in authorized_keys; sign with this one
        let tmpdir_b = tempfile::tempdir().unwrap();
        let (_, key_path_b) = generate_ed25519_keypair(tmpdir_b.path());
        let signer = make_test_token_signer(&key_path_b);

        let nonce = "test-nonce-unknown-fp12345";
        let mut tb = signer.sign_for();
        tb.action("method", "GET")
            .action("path", "/sockets")
            .action("nonce", nonce);
        let token = tb.sign().await.unwrap();

        let header = format!("Bearer {}", token.encode());
        let result = check_request(&auth, "GET", "/sockets", Some(&header), Some(nonce), None);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("token verification failed")
        );
    }

    #[tokio::test]
    async fn test_ssh_auth_verify_ed25519() {
        let (auth, key_path) = make_test_ssh_auth();
        let signer = make_test_token_signer(&key_path);

        let nonce = "test-nonce-verify12345";
        let cb = TlsChannelBinding::new("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=");

        let mut tb = signer.sign_for();
        tb.action("method", "GET")
            .action("path", "/sockets")
            .action("nonce", nonce)
            .action("tls-channel-binding", cb.as_str());
        let token = tb.sign().await.unwrap();

        let header = format!("Bearer {}", token.encode());
        check_request(
            &auth,
            "GET",
            "/sockets",
            Some(&header),
            Some(nonce),
            Some(&cb),
        )
        .expect("valid ed25519 token should pass");
    }

    #[tokio::test]
    async fn test_ssh_auth_rejects_without_header() {
        use axum::body::Body;
        use axum::http::Request;
        use tower::ServiceExt;

        let (auth, _) = make_test_ssh_auth();
        let app = make_auth_test_router(vec![Box::new(auth)]);
        let response = app
            .oneshot(Request::get("/sockets").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_ssh_auth_rejects_invalid_token() {
        use axum::body::Body;
        use axum::http::Request;
        use tower::ServiceExt;

        let (auth, _) = make_test_ssh_auth();
        let app = make_auth_test_router(vec![Box::new(auth)]);
        let response = app
            .oneshot(
                Request::get("/sockets")
                    .header("Authorization", "Bearer bogus-token")
                    .header(
                        varlink_http_bridge::SSHAUTH_NONCE_HEADER,
                        "a-nonce-long-enough-1234",
                    )
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let error = json["error"].as_str().unwrap();
        assert!(
            error.contains("invalid token"),
            "expected 'invalid token' in error, got: {error}"
        );
    }

    struct RejectingAuthenticator(&'static str);
    impl Authenticator for RejectingAuthenticator {
        fn check_request(&self, _request: &AuthRequest) -> anyhow::Result<()> {
            anyhow::bail!("{}", self.0)
        }
    }

    #[tokio::test]
    async fn test_all_auth_rejected_errors_and_errors_are_joined() {
        use axum::body::Body;
        use axum::http::Request;
        use tower::ServiceExt;

        let app = make_auth_test_router(vec![
            Box::new(RejectingAuthenticator("error1")),
            Box::new(RejectingAuthenticator("error2")),
        ]);
        let response = app
            .oneshot(
                Request::get("/sockets")
                    .header("Authorization", "Bearer dummy")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let error = json["error"].as_str().unwrap();
        assert_eq!(error, "error1; error2");
    }

    #[tokio::test]
    async fn test_ssh_auth_health_always_open() {
        use axum::body::Body;
        use axum::http::Request;
        use tower::ServiceExt;

        let (auth, _) = make_test_ssh_auth();
        let app = make_auth_test_router(vec![Box::new(auth)]);
        let response = app
            .oneshot(Request::get("/health").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_no_authenticators_rejects_all() {
        use axum::body::Body;
        use axum::http::Request;
        use tower::ServiceExt;

        // An empty authenticator list must fail closed: open access is
        // only allowed when an explicit AllowAllAuthenticator is pushed.
        let app = make_auth_test_router(Vec::new());
        let response = app
            .oneshot(Request::get("/sockets").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_allow_all_authenticator_passes_unauthed_requests() {
        use axum::body::Body;
        use axum::http::Request;
        use tower::ServiceExt;

        let app = make_auth_test_router(vec![Box::new(crate::AllowAllAuthenticator {
            reason: "test",
        })]);
        // Request has no Authorization header at all - must still be allowed
        // through the auth middleware to the (empty) /sockets handler.
        let response = app
            .oneshot(Request::get("/sockets").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_ssh_auth_rejects_replayed_nonce() {
        let (auth, key_path) = make_test_ssh_auth();
        let signer = make_test_token_signer(&key_path);

        let nonce = "replay-me12345678";
        let cb = TlsChannelBinding::new("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=");

        let mut tb = signer.sign_for();
        tb.action("method", "GET")
            .action("path", "/sockets")
            .action("nonce", nonce)
            .action("tls-channel-binding", cb.as_str());
        let token = tb.sign().await.unwrap();
        let header = format!("Bearer {}", token.encode());

        // First use should succeed
        check_request(
            &auth,
            "GET",
            "/sockets",
            Some(&header),
            Some(nonce),
            Some(&cb),
        )
        .expect("first use of nonce should pass");

        // Replay with the same nonce should fail
        let result = check_request(
            &auth,
            "GET",
            "/sockets",
            Some(&header),
            Some(nonce),
            Some(&cb),
        );
        assert!(result.is_err(), "replayed nonce should be rejected");
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("nonce already used"),
            "error should mention nonce replay"
        );
    }

    #[tokio::test]
    async fn test_ssh_auth_rejects_missing_nonce() {
        let (auth, key_path) = make_test_ssh_auth();
        let signer = make_test_token_signer(&key_path);

        let mut tb = signer.sign_for();
        tb.action("method", "GET").action("path", "/sockets");
        let token = tb.sign().await.unwrap();
        let header = format!("Bearer {}", token.encode());

        // Without a nonce, the request should be rejected
        let result = check_request(&auth, "GET", "/sockets", Some(&header), None, None);
        assert!(result.is_err(), "request without nonce should be rejected");
        assert!(result.unwrap_err().to_string().contains("missing nonce"));
    }

    #[tokio::test]
    async fn test_ssh_auth_channel_binding_mismatch_rejected() {
        let (auth, key_path) = make_test_ssh_auth();
        let signer = make_test_token_signer(&key_path);

        let nonce = "cb-mismatch-test12345";
        let cb_signer = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
        let cb_verifier = TlsChannelBinding::new("BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=");

        let mut tb = signer.sign_for();
        tb.action("method", "GET")
            .action("path", "/sockets")
            .action("nonce", nonce)
            .action("tls-channel-binding", cb_signer);
        let token = tb.sign().await.unwrap();

        let header = format!("Bearer {}", token.encode());
        let result = check_request(
            &auth,
            "GET",
            "/sockets",
            Some(&header),
            Some(nonce),
            Some(&cb_verifier),
        );
        assert!(
            result.is_err(),
            "mismatched channel binding should be rejected (relay attack)"
        );
    }

    #[tokio::test]
    async fn test_ssh_auth_channel_binding_match_accepted() {
        let (auth, key_path) = make_test_ssh_auth();
        let signer = make_test_token_signer(&key_path);

        let nonce = "cb-match-test-123456";
        let cb = TlsChannelBinding::new("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=");

        let mut tb = signer.sign_for();
        tb.action("method", "GET")
            .action("path", "/sockets")
            .action("nonce", nonce)
            .action("tls-channel-binding", cb.as_str());
        let token = tb.sign().await.unwrap();

        let header = format!("Bearer {}", token.encode());
        check_request(
            &auth,
            "GET",
            "/sockets",
            Some(&header),
            Some(nonce),
            Some(&cb),
        )
        .expect("matching channel binding should pass");
    }

    #[test]
    fn test_ssh_auth_credential_discovery() {
        use std::io::Write;

        // Generate two ed25519 key pairs (A with 1 key, B with 2 keys)
        let keygen_dir = tempfile::tempdir().unwrap();
        let (pubkey_a, _) = generate_ed25519_keypair(keygen_dir.path());

        let keygen_dir_b1 = tempfile::tempdir().unwrap();
        let (pubkey_b1, _) = generate_ed25519_keypair(keygen_dir_b1.path());
        let keygen_dir_b2 = tempfile::tempdir().unwrap();
        let (pubkey_b2, _) = generate_ed25519_keypair(keygen_dir_b2.path());

        // 1. Empty rootdir + no creds_dir → authenticator with 0 keys (waiting for files)
        let empty_root = tempfile::tempdir().unwrap();
        let auth = create_ssh_authenticator(None, None, empty_root.path()).unwrap();
        assert_eq!(auth.key_count(), 0, "empty rootdir should yield 0 keys");

        // 2. rootdir/etc/varlink-httpd/authorized_keys exists → found
        let root = make_test_rootdir_with_keys(&[pubkey_a.trim()]);
        let auth = create_ssh_authenticator(None, None, root.path()).unwrap();
        assert_eq!(auth.key_count(), 1, "should find key from /etc path");

        // 3. $CREDENTIALS_DIRECTORY/ssh.authorized_keys.root exists → found
        let creds_dir = tempfile::tempdir().unwrap();
        std::fs::write(
            creds_dir.path().join("ssh.authorized_keys.root"),
            pubkey_a.as_bytes(),
        )
        .unwrap();
        let auth =
            create_ssh_authenticator(None, Some(creds_dir.path()), empty_root.path()).unwrap();
        assert_eq!(auth.key_count(), 1, "should find key from creds_dir");

        // 4. Both /etc and $CREDENTIALS_DIRECTORY exist → keys are merged
        let root_both = tempfile::tempdir().unwrap();
        let etc_dir = root_both.path().join("etc/varlink-httpd");
        std::fs::create_dir_all(&etc_dir).unwrap();
        std::fs::write(etc_dir.join("authorized_keys"), pubkey_a.as_bytes()).unwrap();
        let creds_dir_b = tempfile::tempdir().unwrap();
        let mut creds_file =
            std::fs::File::create(creds_dir_b.path().join("ssh.authorized_keys.root")).unwrap();
        writeln!(creds_file, "{}", pubkey_b1.trim()).unwrap();
        writeln!(creds_file, "{}", pubkey_b2.trim()).unwrap();
        drop(creds_file);
        let auth =
            create_ssh_authenticator(None, Some(creds_dir_b.path()), root_both.path()).unwrap();
        assert_eq!(
            auth.key_count(),
            3,
            "/etc (1 key) + creds_dir (2 keys) should be merged"
        );

        // 5b. ssh.ephemeral-authorized_keys-all is used when .root is absent (creds_dir)
        let creds_dir_all = tempfile::tempdir().unwrap();
        std::fs::write(
            creds_dir_all
                .path()
                .join("ssh.ephemeral-authorized_keys-all"),
            pubkey_a.as_bytes(),
        )
        .unwrap();
        let auth =
            create_ssh_authenticator(None, Some(creds_dir_all.path()), empty_root.path()).unwrap();
        assert_eq!(auth.key_count(), 1, "should find key from .all credential");

        // 5c. Both .root and .all credentials exist → keys are merged
        let creds_dir_both = tempfile::tempdir().unwrap();
        std::fs::write(
            creds_dir_both.path().join("ssh.authorized_keys.root"),
            pubkey_a.as_bytes(),
        )
        .unwrap();
        let mut all_file = std::fs::File::create(
            creds_dir_both
                .path()
                .join("ssh.ephemeral-authorized_keys-all"),
        )
        .unwrap();
        writeln!(all_file, "{}", pubkey_b1.trim()).unwrap();
        writeln!(all_file, "{}", pubkey_b2.trim()).unwrap();
        drop(all_file);
        let auth =
            create_ssh_authenticator(None, Some(creds_dir_both.path()), empty_root.path()).unwrap();
        assert_eq!(
            auth.key_count(),
            3,
            ".root (1 key) + .all (2 keys) should be merged"
        );

        // 6. CLI path overrides everything (only CLI path is used)
        let cli_root = make_test_rootdir_with_keys(&[pubkey_a.trim()]);
        let cli_file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(cli_file.path(), format!("{}\n", pubkey_b1.trim())).unwrap();
        let auth = create_ssh_authenticator(
            Some(cli_file.path().to_str().unwrap().to_string()),
            Some(creds_dir.path()),
            cli_root.path(),
        )
        .unwrap();
        assert_eq!(
            auth.key_count(),
            1,
            "CLI path should be used exclusively, not /etc or credential"
        );
    }

    #[test_with::path(/usr/bin/varlinkctl)]
    #[test_with::path(/run/systemd/io.systemd.Hostname)]
    #[tokio::test]
    async fn test_tls_ssh_e2e() {
        let pki = make_test_pki();
        let (auth, key_path) = make_test_ssh_auth();

        let acceptor = load_tls_acceptor(
            pki.server_cert_path.to_str().unwrap(),
            pki.server_key_path.to_str().unwrap(),
            None,
        )
        .unwrap();

        let server =
            run_test_tls_server_with_auth("/run/systemd", acceptor, vec![Box::new(auth)]).await;
        let fake_xdg_home = tempfile::tempdir().unwrap();
        let tls_dir = fake_xdg_home.path().join("varlinkctl-http");
        std::fs::create_dir_all(&tls_dir).unwrap();
        std::fs::copy(&pki.ca_cert_path, tls_dir.join("server-ca-file")).unwrap();

        let bridge_url = format!(
            "https://localhost:{}/ws/sockets/io.systemd.Hostname",
            server.addr.port()
        );

        let output = run_varlinkctl_call(
            &bridge_url,
            "io.systemd.Hostname.Describe",
            "{}",
            false,
            &[
                ("XDG_CONFIG_HOME", fake_xdg_home.path()),
                ("VARLINK_SSH_KEY", key_path.as_path()),
            ],
        )
        .await;
        assert_hostname_reply(&output);
    }
} // mod sshauth_tests

// --- JWT bearer auth tests ---

#[cfg(feature = "jwtauth")]
mod jwtauth_tests {
    use super::*;
    use crate::auth_jwt::{JwtAuthenticator, create_jwt_authenticator};
    use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
    use openssl::pkey::PKey;
    use std::time::{SystemTime, UNIX_EPOCH};

    const TEST_ISSUER: &str = "https://issuer.example";
    const TEST_AUDIENCE: &str = "node-1";

    fn now_secs() -> i64 {
        i64::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        )
        .unwrap()
    }

    /// base64url without padding, per RFC 7515/7518 (JWK members).
    fn b64url(bytes: &[u8]) -> String {
        openssl::base64::encode_block(bytes)
            .trim_end_matches('=')
            .replace('+', "-")
            .replace('/', "_")
    }

    /// Left-pad a big-endian integer to `len` bytes (JWK coordinates are
    /// fixed-width; `BigNum::to_vec` drops leading zero bytes).
    fn pad_be(bytes: &[u8], len: usize) -> Vec<u8> {
        let mut out = vec![0u8; len.saturating_sub(bytes.len())];
        out.extend_from_slice(bytes);
        out
    }

    /// A test JWT issuer: a freshly generated keypair plus the matching JWKS.
    struct TestIssuer {
        priv_pem: Vec<u8>,
        alg: Algorithm,
        kid: String,
    }

    impl TestIssuer {
        fn es256() -> Self {
            let pkey = crate::auth_jwt::generate_p256_keypair();
            Self {
                priv_pem: pkey.private_key_to_pem_pkcs8().unwrap(),
                alg: Algorithm::ES256,
                kid: "test-ec".to_string(),
            }
        }

        fn rs256() -> Self {
            let rsa = openssl::rsa::Rsa::generate(2048).unwrap();
            let pkey = PKey::from_rsa(rsa).unwrap();
            Self {
                priv_pem: pkey.private_key_to_pem_pkcs8().unwrap(),
                alg: Algorithm::RS256,
                kid: "test-rsa".to_string(),
            }
        }

        /// The public half of this issuer's key as a single JWK.
        fn jwk(&self) -> Value {
            let pkey = PKey::private_key_from_pem(&self.priv_pem).unwrap();
            match self.alg {
                Algorithm::ES256 => {
                    use openssl::bn::{BigNum, BigNumContext};
                    let ec = pkey.ec_key().unwrap();
                    let mut ctx = BigNumContext::new().unwrap();
                    let (mut x, mut y) = (BigNum::new().unwrap(), BigNum::new().unwrap());
                    ec.public_key()
                        .affine_coordinates(ec.group(), &mut x, &mut y, &mut ctx)
                        .unwrap();
                    json!({
                        "kty": "EC", "crv": "P-256", "alg": "ES256", "use": "sig",
                        "kid": self.kid,
                        "x": b64url(&pad_be(&x.to_vec(), 32)),
                        "y": b64url(&pad_be(&y.to_vec(), 32)),
                    })
                }
                Algorithm::RS256 => {
                    let rsa = pkey.rsa().unwrap();
                    json!({
                        "kty": "RSA", "alg": "RS256", "use": "sig",
                        "kid": self.kid,
                        "n": b64url(&rsa.n().to_vec()),
                        "e": b64url(&rsa.e().to_vec()),
                    })
                }
                other => panic!("unsupported test alg {other:?}"),
            }
        }

        /// Write this issuer's JWKS to a fresh temp file and return both the
        /// tempdir (keep it alive) and the path.
        fn write_jwks(&self) -> (tempfile::TempDir, std::path::PathBuf) {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("jwks.json");
            let jwks = json!({ "keys": [self.jwk()] });
            std::fs::write(&path, serde_json::to_vec(&jwks).unwrap()).unwrap();
            (dir, path)
        }

        fn encoding_key(&self) -> EncodingKey {
            match self.alg {
                Algorithm::ES256 => EncodingKey::from_ec_pem(&self.priv_pem).unwrap(),
                Algorithm::RS256 => EncodingKey::from_rsa_pem(&self.priv_pem).unwrap(),
                other => panic!("unsupported test alg {other:?}"),
            }
        }

        fn mint(&self, claims: &Value) -> String {
            let mut header = Header::new(self.alg);
            header.kid = Some(self.kid.clone());
            encode(&header, claims, &self.encoding_key()).unwrap()
        }
    }

    /// Standard, valid set of claims (iss/aud match the server, not expired).
    fn valid_claims(sub: &str) -> Value {
        json!({
            "iss": TEST_ISSUER,
            "aud": TEST_AUDIENCE,
            "sub": sub,
            "exp": now_secs() + 300,
            "iat": now_secs(),
        })
    }

    /// `JwtAuthenticator` backed by `issuer`'s JWKS, with the given
    /// `--require-claim` rules (e.g. `["sub=alice"]`).
    fn auth_with_claims(
        issuer: &TestIssuer,
        rules: &[&str],
    ) -> (tempfile::TempDir, JwtAuthenticator) {
        let (dir, jwks_path) = issuer.write_jwks();
        let auth = JwtAuthenticator::new_for_test(
            TEST_ISSUER.to_string(),
            TEST_AUDIENCE.to_string(),
            jwks_path,
            rules.iter().map(|s| (*s).to_string()).collect(),
        )
        .unwrap();
        (dir, auth)
    }

    /// `JwtAuthenticator` requiring `sub == "alice"`, backed by `issuer`'s JWKS.
    fn auth_with_allowlist(issuer: &TestIssuer) -> (tempfile::TempDir, JwtAuthenticator) {
        auth_with_claims(issuer, &["sub=alice"])
    }

    fn bearer(token: &str) -> String {
        format!("Bearer {token}")
    }

    #[test]
    fn test_jwt_accepts_valid_es256_allowlisted_sub() {
        let issuer = TestIssuer::es256();
        let (_dir, auth) = auth_with_allowlist(&issuer);
        let token = issuer.mint(&valid_claims("alice"));
        check_request(&auth, "GET", "/sockets", Some(&bearer(&token)), None, None)
            .expect("valid token for allowlisted sub should pass");
    }

    #[test]
    fn test_jwt_rejects_sub_not_in_allowlist() {
        let issuer = TestIssuer::es256();
        let (_dir, auth) = auth_with_allowlist(&issuer);
        let token = issuer.mint(&valid_claims("mallory"));
        let err =
            check_request(&auth, "GET", "/sockets", Some(&bearer(&token)), None, None).unwrap_err();
        assert!(
            err.to_string().contains("not in the allowed set"),
            "expected allowlist rejection, got: {err}"
        );
    }

    #[test]
    fn test_jwt_accepts_rs256() {
        let issuer = TestIssuer::rs256();
        // sub=anyone is satisfied by the token, so this exercises RS256 verification.
        let (_dir, auth) = auth_with_claims(&issuer, &["sub=anyone"]);
        let token = issuer.mint(&valid_claims("anyone"));
        check_request(&auth, "GET", "/sockets", Some(&bearer(&token)), None, None)
            .expect("valid RS256 token should pass");
    }

    #[test]
    fn test_jwt_accepts_matching_custom_claim() {
        let issuer = TestIssuer::es256();
        let (_dir, auth) = auth_with_claims(&issuer, &["hd=example.com"]);
        let mut claims = valid_claims("anyone");
        claims["hd"] = json!("example.com");
        let token = issuer.mint(&claims);
        check_request(&auth, "GET", "/sockets", Some(&bearer(&token)), None, None)
            .expect("token with the required claim value should pass");
    }

    #[test]
    fn test_jwt_glob_claim_match() {
        let issuer = TestIssuer::es256();
        let (_dir, auth) = auth_with_claims(&issuer, &["sub=repo:myorg/myrepo:*"]);

        let mut ok = valid_claims("x");
        ok["sub"] = json!("repo:myorg/myrepo:ref:refs/heads/main");
        let token = issuer.mint(&ok);
        check_request(&auth, "GET", "/sockets", Some(&bearer(&token)), None, None)
            .expect("glob should match any ref under the repo");

        let mut bad = valid_claims("x");
        bad["sub"] = json!("repo:otherorg/repo:ref:refs/heads/main");
        let token = issuer.mint(&bad);
        assert!(
            check_request(&auth, "GET", "/sockets", Some(&bearer(&token)), None, None).is_err(),
            "glob is anchored: a different repo must not match"
        );
    }

    #[test]
    fn test_jwt_distinct_claims_are_anded() {
        let issuer = TestIssuer::es256();
        let (_dir, auth) =
            auth_with_claims(&issuer, &["repository=myorg/myrepo", "environment=prod"]);

        let mut claims = valid_claims("x");
        claims["repository"] = json!("myorg/myrepo");
        claims["environment"] = json!("prod");
        let token = issuer.mint(&claims);
        check_request(&auth, "GET", "/sockets", Some(&bearer(&token)), None, None)
            .expect("both required claims present and matching");

        let mut claims = valid_claims("x");
        claims["repository"] = json!("myorg/myrepo");
        claims["environment"] = json!("staging");
        let token = issuer.mint(&claims);
        assert!(
            check_request(&auth, "GET", "/sockets", Some(&bearer(&token)), None, None).is_err(),
            "all distinct claims must match (AND)"
        );

        let mut claims = valid_claims("x");
        claims["repository"] = json!("myorg/myrepo");
        let token = issuer.mint(&claims);
        let err =
            check_request(&auth, "GET", "/sockets", Some(&bearer(&token)), None, None).unwrap_err();
        assert!(err.to_string().contains("missing"), "got: {err}");
    }

    #[test]
    fn test_jwt_repeated_claim_is_ored() {
        let issuer = TestIssuer::es256();
        let (_dir, auth) = auth_with_claims(&issuer, &["repository=myorg/a", "repository=myorg/b"]);
        for repo in ["myorg/a", "myorg/b"] {
            let mut claims = valid_claims("x");
            claims["repository"] = json!(repo);
            let token = issuer.mint(&claims);
            check_request(&auth, "GET", "/sockets", Some(&bearer(&token)), None, None)
                .unwrap_or_else(|e| panic!("repository {repo} should be allowed: {e}"));
        }
        let mut claims = valid_claims("x");
        claims["repository"] = json!("myorg/c");
        let token = issuer.mint(&claims);
        assert!(
            check_request(&auth, "GET", "/sockets", Some(&bearer(&token)), None, None).is_err(),
            "a value not listed must be rejected"
        );
    }

    #[test]
    fn test_jwt_array_claim_matches_any_element() {
        let issuer = TestIssuer::es256();
        let (_dir, auth) = auth_with_claims(&issuer, &["groups=admins"]);
        let mut claims = valid_claims("x");
        claims["groups"] = json!(["users", "admins"]);
        let token = issuer.mint(&claims);
        check_request(&auth, "GET", "/sockets", Some(&bearer(&token)), None, None)
            .expect("array claim should match if any element matches");
    }

    #[test]
    fn test_jwt_configured_entirely_from_credentials() {
        let issuer = TestIssuer::es256();
        let creds = tempfile::tempdir().unwrap();
        let jwks = json!({ "keys": [issuer.jwk()] });
        std::fs::write(
            creds.path().join("varlink-httpd.jwt.jwks"),
            serde_json::to_vec(&jwks).unwrap(),
        )
        .unwrap();
        std::fs::write(creds.path().join("varlink-httpd.jwt.issuer"), TEST_ISSUER).unwrap();
        std::fs::write(
            creds.path().join("varlink-httpd.jwt.audience"),
            TEST_AUDIENCE,
        )
        .unwrap();
        std::fs::write(
            creds.path().join("varlink-httpd.jwt.require-claims"),
            "sub=alice\n# a comment line\n",
        )
        .unwrap();

        // Empty root so the /etc path is absent; everything resolves from creds.
        let root = tempfile::tempdir().unwrap();
        let auth =
            create_jwt_authenticator(JwtCliOptions::default(), Some(creds.path()), root.path())
                .unwrap()
                .expect("issuer credential should enable JWT auth");

        let token = issuer.mint(&valid_claims("alice"));
        check_request(&auth, "GET", "/sockets", Some(&bearer(&token)), None, None)
            .expect("credential-configured node should accept a valid token");

        let token = issuer.mint(&valid_claims("mallory"));
        assert!(
            check_request(&auth, "GET", "/sockets", Some(&bearer(&token)), None, None).is_err(),
            "require-claims credential should still be enforced"
        );
    }

    #[test]
    fn test_jwt_cli_require_claims_override_credential() {
        let issuer = TestIssuer::es256();
        let creds = tempfile::tempdir().unwrap();
        std::fs::write(
            creds.path().join("varlink-httpd.jwt.jwks"),
            serde_json::to_vec(&json!({ "keys": [issuer.jwk()] })).unwrap(),
        )
        .unwrap();
        // Credential requires sub=alice; the CLI flag must replace it, not merge.
        std::fs::write(
            creds.path().join("varlink-httpd.jwt.require-claims"),
            "sub=alice",
        )
        .unwrap();

        let root = tempfile::tempdir().unwrap();
        let auth = create_jwt_authenticator(
            JwtCliOptions {
                issuer: Some(TEST_ISSUER.to_string()),
                audience: Some(TEST_AUDIENCE.to_string()),
                require_claims: vec!["sub=bob".to_string()],
                ..Default::default()
            },
            Some(creds.path()),
            root.path(),
        )
        .unwrap()
        .expect("issuer enables JWT auth");

        let token = issuer.mint(&valid_claims("bob"));
        check_request(&auth, "GET", "/sockets", Some(&bearer(&token)), None, None)
            .expect("the CLI require-claim should apply");

        let token = issuer.mint(&valid_claims("alice"));
        assert!(
            check_request(&auth, "GET", "/sockets", Some(&bearer(&token)), None, None).is_err(),
            "CLI --require-claim must replace the credential's rules, not merge"
        );
    }

    #[test]
    fn test_jwt_disabled_without_issuer() {
        let creds = tempfile::tempdir().unwrap();
        let root = tempfile::tempdir().unwrap();
        let result =
            create_jwt_authenticator(JwtCliOptions::default(), Some(creds.path()), root.path())
                .unwrap();
        assert!(
            result.is_none(),
            "no issuer anywhere -> JWT auth not enabled"
        );
    }

    #[test]
    fn test_jwt_etc_jwks_file_wins_over_discovery() {
        let issuer = TestIssuer::es256();
        let root = tempfile::tempdir().unwrap();
        let etc = root.path().join("etc/varlink-httpd");
        std::fs::create_dir_all(&etc).unwrap();
        let jwks = json!({ "keys": [issuer.jwk()] });
        std::fs::write(
            etc.join("issuer-jwks.json"),
            serde_json::to_vec(&jwks).unwrap(),
        )
        .unwrap();

        // TEST_ISSUER is an https URL, but the pinned file must win (with a
        // warning) and no discovery fetch must happen.
        let auth = create_jwt_authenticator(
            JwtCliOptions {
                issuer: Some(TEST_ISSUER.to_string()),
                audience: Some(TEST_AUDIENCE.to_string()),
                require_claims: vec!["sub=alice".to_string()],
                ..Default::default()
            },
            None,
            root.path(),
        )
        .unwrap()
        .expect("issuer enables JWT auth");

        let token = issuer.mint(&valid_claims("alice"));
        check_request(&auth, "GET", "/sockets", Some(&bearer(&token)), None, None)
            .expect("pinned /etc JWKS should verify the token without discovery");
    }

    #[test]
    fn test_jwt_other_flags_without_issuer_disabled() {
        // audience/jwks/require-claim given but no issuer: still disabled (the
        // flags are ignored, with a warning), not enabled wide open.
        let creds = tempfile::tempdir().unwrap();
        let root = tempfile::tempdir().unwrap();
        let result = create_jwt_authenticator(
            JwtCliOptions {
                audience: Some(TEST_AUDIENCE.to_string()),
                require_claims: vec!["sub=alice".to_string()],
                ..Default::default()
            },
            Some(creds.path()),
            root.path(),
        )
        .unwrap();
        assert!(
            result.is_none(),
            "JWT flags without an issuer must not enable JWT auth"
        );
    }

    #[test]
    fn test_jwt_not_enabled_without_rules() {
        let issuer = TestIssuer::es256();
        let (_dir, jwks_path) = issuer.write_jwks();
        let root = tempfile::tempdir().unwrap();
        // Issuer + audience but no --require-claim: JWT is left off (not wide-open),
        // without failing the whole bridge.
        let result = create_jwt_authenticator(
            JwtCliOptions {
                issuer: Some(TEST_ISSUER.to_string()),
                audience: Some(TEST_AUDIENCE.to_string()),
                issuer_jwks: Some(jwks_path),
                ..Default::default()
            },
            None,
            root.path(),
        )
        .unwrap();
        assert!(result.is_none(), "no rules -> JWT auth not enabled");
    }

    #[test]
    fn test_jwt_rejects_expired() {
        let issuer = TestIssuer::es256();
        let (_dir, auth) = auth_with_allowlist(&issuer);
        let mut claims = valid_claims("alice");
        claims["exp"] = json!(now_secs() - 120); // beyond the 60s leeway
        claims["iat"] = json!(now_secs() - 300);
        let token = issuer.mint(&claims);
        let err =
            check_request(&auth, "GET", "/sockets", Some(&bearer(&token)), None, None).unwrap_err();
        assert!(
            err.to_string().contains("verification failed"),
            "expected verification failure for expired token, got: {err}"
        );
    }

    #[test]
    fn test_jwt_rejects_future_nbf() {
        let issuer = TestIssuer::es256();
        let (_dir, auth) = auth_with_allowlist(&issuer);
        let mut claims = valid_claims("alice");
        claims["nbf"] = json!(now_secs() + 120); // not valid yet, beyond the 60s leeway
        let token = issuer.mint(&claims);
        let err =
            check_request(&auth, "GET", "/sockets", Some(&bearer(&token)), None, None).unwrap_err();
        assert!(
            err.to_string().contains("verification failed"),
            "expected verification failure for not-yet-valid (nbf) token, got: {err}"
        );
    }

    #[test]
    fn test_jwt_rejects_wrong_issuer() {
        let issuer = TestIssuer::es256();
        let (_dir, auth) = auth_with_allowlist(&issuer);
        let mut claims = valid_claims("alice");
        claims["iss"] = json!("https://evil.example");
        let token = issuer.mint(&claims);
        assert!(
            check_request(&auth, "GET", "/sockets", Some(&bearer(&token)), None, None).is_err(),
            "token with wrong issuer should be rejected"
        );
    }

    #[test]
    fn test_jwt_rejects_wrong_audience() {
        let issuer = TestIssuer::es256();
        let (_dir, auth) = auth_with_allowlist(&issuer);
        let mut claims = valid_claims("alice");
        claims["aud"] = json!("node-2");
        let token = issuer.mint(&claims);
        assert!(
            check_request(&auth, "GET", "/sockets", Some(&bearer(&token)), None, None).is_err(),
            "token minted for another node's audience should be rejected"
        );
    }

    #[test]
    fn test_jwt_rejects_missing_audience() {
        let issuer = TestIssuer::es256();
        let (_dir, auth) = auth_with_allowlist(&issuer);
        let mut claims = valid_claims("alice");
        claims.as_object_mut().unwrap().remove("aud");
        let token = issuer.mint(&claims);
        assert!(
            check_request(&auth, "GET", "/sockets", Some(&bearer(&token)), None, None).is_err(),
            "a token omitting aud must not bypass the per-node audience check"
        );
    }

    #[test]
    fn test_jwt_rejects_missing_issuer() {
        let issuer = TestIssuer::es256();
        let (_dir, auth) = auth_with_allowlist(&issuer);
        let mut claims = valid_claims("alice");
        claims.as_object_mut().unwrap().remove("iss");
        let token = issuer.mint(&claims);
        assert!(
            check_request(&auth, "GET", "/sockets", Some(&bearer(&token)), None, None).is_err(),
            "a token omitting iss must be rejected"
        );
    }

    #[test]
    fn test_jwt_rejects_token_signed_by_untrusted_key() {
        // JWKS belongs to `trusted`; the token is signed by `attacker`.
        let trusted = TestIssuer::es256();
        let (_dir, auth) = auth_with_allowlist(&trusted);

        let mut attacker = TestIssuer::es256();
        attacker.kid = trusted.kid.clone(); // even claiming the same kid must not help
        let token = attacker.mint(&valid_claims("alice"));
        assert!(
            check_request(&auth, "GET", "/sockets", Some(&bearer(&token)), None, None).is_err(),
            "token signed by an untrusted key must be rejected"
        );
    }

    #[test]
    fn test_jwt_rejects_non_bearer_scheme() {
        let issuer = TestIssuer::es256();
        let (_dir, auth) = auth_with_allowlist(&issuer);
        let token = issuer.mint(&valid_claims("alice"));
        let dpop = format!("DPoP {token}");
        let err = check_request(&auth, "GET", "/sockets", Some(&dpop), None, None).unwrap_err();
        assert!(
            err.to_string().contains("scheme must be 'Bearer'"),
            "non-Bearer scheme should be rejected in stage-1, got: {err}"
        );
    }

    #[test]
    fn test_jwt_accepts_case_insensitive_bearer_scheme() {
        let issuer = TestIssuer::es256();
        let (_dir, auth) = auth_with_allowlist(&issuer);
        let token = issuer.mint(&valid_claims("alice"));
        check_request(
            &auth,
            "GET",
            "/sockets",
            Some(&format!("bearer {token}")),
            None,
            None,
        )
        .expect("lowercase scheme should be accepted");
        check_request(
            &auth,
            "GET",
            "/sockets",
            Some(&format!("BEARER {token}")),
            None,
            None,
        )
        .expect("uppercase scheme should be accepted");
    }

    #[test]
    fn test_jwt_picks_up_rotated_key_on_reload() {
        // Start trusting issuer A, then rotate the JWKS file to issuer B's key.
        let issuer_a = TestIssuer::es256();
        let (dir, jwks_path) = issuer_a.write_jwks();
        let auth = JwtAuthenticator::new_for_test(
            TEST_ISSUER.to_string(),
            TEST_AUDIENCE.to_string(),
            jwks_path.clone(),
            vec!["sub=anyone".to_string()],
        )
        .unwrap();

        let token_a = issuer_a.mint(&valid_claims("anyone"));
        check_request(
            &auth,
            "GET",
            "/sockets",
            Some(&bearer(&token_a)),
            None,
            None,
        )
        .expect("token from the initially-trusted key should pass");

        // Rotate: overwrite the JWKS with a different issuer key (same kid).
        let mut issuer_b = TestIssuer::es256();
        issuer_b.kid = issuer_a.kid.clone();
        let jwks = json!({ "keys": [issuer_b.jwk()] });
        // Ensure a new mtime even on coarse-grained filesystems.
        std::thread::sleep(std::time::Duration::from_millis(10));
        std::fs::write(&jwks_path, serde_json::to_vec(&jwks).unwrap()).unwrap();

        let token_b = issuer_b.mint(&valid_claims("anyone"));
        check_request(
            &auth,
            "GET",
            "/sockets",
            Some(&bearer(&token_b)),
            None,
            None,
        )
        .expect("after reload, token from the rotated key should pass");
        // The old key is gone, so its token must now be rejected.
        assert!(
            check_request(
                &auth,
                "GET",
                "/sockets",
                Some(&bearer(&token_a)),
                None,
                None
            )
            .is_err(),
            "after rotation the old key's token should be rejected"
        );
        drop(dir);
    }

    #[test]
    fn test_jwt_keeps_keys_when_jwks_becomes_invalid_then_recovers() {
        let issuer = TestIssuer::es256();
        let (dir, jwks_path) = issuer.write_jwks();
        let auth = JwtAuthenticator::new_for_test(
            TEST_ISSUER.to_string(),
            TEST_AUDIENCE.to_string(),
            jwks_path.clone(),
            vec!["sub=anyone".to_string()],
        )
        .unwrap();
        let token = issuer.mint(&valid_claims("anyone"));
        check_request(&auth, "GET", "/sockets", Some(&bearer(&token)), None, None)
            .expect("initial key should pass");

        // Overwrite with garbage: the previous keys must be retained, and (with
        // the mtime now recorded) repeated requests must keep validating.
        std::thread::sleep(std::time::Duration::from_millis(10));
        std::fs::write(&jwks_path, b"not json").unwrap();
        for _ in 0..3 {
            check_request(&auth, "GET", "/sockets", Some(&bearer(&token)), None, None)
                .expect("a broken JWKS file must not drop the working keys");
        }

        // A later valid rewrite is still picked up.
        std::thread::sleep(std::time::Duration::from_millis(10));
        std::fs::write(
            &jwks_path,
            serde_json::to_vec(&json!({ "keys": [issuer.jwk()] })).unwrap(),
        )
        .unwrap();
        check_request(&auth, "GET", "/sockets", Some(&bearer(&token)), None, None)
            .expect("after a valid rewrite the keys should reload");
        drop(dir);
    }

    #[test]
    fn test_jwt_authenticator_debug() {
        let issuer = TestIssuer::es256();
        let (_dir, auth) = auth_with_allowlist(&issuer);
        let s = format!("{auth:?}");
        assert!(s.contains("JwtAuthenticator"), "got: {s}");
        // one key loaded, lock healthy -> rendered as the count, not <poisoned>
        assert!(s.contains("key_count: 1"), "got: {s}");
    }

    // --- end-to-end through the HTTP auth middleware ---

    fn make_router(authenticators: Vec<Box<dyn Authenticator>>) -> Router {
        let tmpdir = tempfile::tempdir().unwrap();
        // /sockets over an empty dir returns an empty list with 200, which is
        // all we need to prove the request made it past the auth middleware.
        let path = tmpdir.keep();
        create_router(path.to_str().unwrap(), authenticators).unwrap()
    }

    #[tokio::test]
    async fn test_jwt_http_accepts_valid_and_rejects_invalid() {
        use axum::body::Body;
        use axum::http::Request;
        use tower::ServiceExt;

        let issuer = TestIssuer::es256();
        let (_dir, auth) = auth_with_allowlist(&issuer);
        let app = make_router(vec![Box::new(auth)]);

        // Valid token for an allowlisted sub -> request reaches the handler.
        let token = issuer.mint(&valid_claims("alice"));
        let ok = app
            .clone()
            .oneshot(
                Request::get("/sockets")
                    .header("Authorization", bearer(&token))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(ok.status(), StatusCode::OK);

        // Garbage token -> 401.
        let bad = app
            .clone()
            .oneshot(
                Request::get("/sockets")
                    .header("Authorization", "Bearer not-a-jwt")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(bad.status(), StatusCode::UNAUTHORIZED);

        // No Authorization header at all -> 401.
        let missing = app
            .oneshot(Request::get("/sockets").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(missing.status(), StatusCode::UNAUTHORIZED);
    }

    /// Build a JWT-only TLS server (issuer JWKS + `sub` allowlist) and return it
    /// together with the issuer, the temp dirs to keep alive, and a fake
    /// `XDG_CONFIG_HOME` holding the server CA so the client trusts the server.
    /// Mirrors the setup of `sshauth_tests::test_tls_ssh_e2e`.
    async fn jwt_tls_server() -> (
        TestIssuer,
        TestServer<std::net::SocketAddr>,
        tempfile::TempDir,
        tempfile::TempDir,
        TestPki,
    ) {
        let pki = make_test_pki();
        let issuer = TestIssuer::es256();
        let (jwks_dir, jwks_path) = issuer.write_jwks();
        let auth = JwtAuthenticator::new_for_test(
            TEST_ISSUER.to_string(),
            TEST_AUDIENCE.to_string(),
            jwks_path,
            vec!["sub=alice".to_string()],
        )
        .unwrap();

        let acceptor = load_tls_acceptor(
            pki.server_cert_path.to_str().unwrap(),
            pki.server_key_path.to_str().unwrap(),
            None,
        )
        .unwrap();
        let server =
            run_test_tls_server_with_auth("/run/systemd", acceptor, vec![Box::new(auth)]).await;

        let fake_xdg_home = tempfile::tempdir().unwrap();
        let tls_dir = fake_xdg_home.path().join("varlinkctl-http");
        std::fs::create_dir_all(&tls_dir).unwrap();
        std::fs::copy(&pki.ca_cert_path, tls_dir.join("server-ca-file")).unwrap();

        (issuer, server, jwks_dir, fake_xdg_home, pki)
    }

    /// Full TLS client→server flow, the JWT analogue of `test_tls_ssh_e2e`:
    /// varlinkctl drives `varlinkctl-http`, which reads `VARLINK_JWT` and sends
    /// `Authorization: Bearer <token>` on the websocket upgrade; the server
    /// verifies it against the issuer JWKS over a real TLS connection.
    #[test_with::path(/usr/bin/openssl)]
    #[test_with::path(/usr/bin/varlinkctl)]
    #[test_with::path(/run/systemd/io.systemd.Hostname)]
    #[tokio::test]
    async fn test_tls_jwt_bearer_e2e() {
        let (issuer, server, _jwks_dir, fake_xdg_home, _pki) = jwt_tls_server().await;
        let bridge_url = format!(
            "https://localhost:{}/ws/sockets/io.systemd.Hostname",
            server.addr.port()
        );
        let token = issuer.mint(&valid_claims("alice"));

        let output = tokio::process::Command::new("varlinkctl")
            .args([
                "call",
                "--json=short",
                &format!("exec:{}", helper_binary().display()),
                "io.systemd.Hostname.Describe",
                "{}",
            ])
            .env("VARLINK_BRIDGE_URL", &bridge_url)
            .env("XDG_CONFIG_HOME", fake_xdg_home.path())
            .env("VARLINK_JWT", &token)
            // make sure no ambient ssh-agent interferes with the JWT path
            .env_remove("SSH_AUTH_SOCK")
            .env_remove("VARLINK_SSH_KEY")
            .output()
            .await
            .expect("failed to run varlinkctl");

        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            output.status.success(),
            "varlinkctl with TLS + JWT bearer failed (stderr: {stderr})"
        );

        let stdout = String::from_utf8(output.stdout).expect("invalid UTF-8");
        let line = stdout.trim().trim_start_matches('\x1e');
        let body: Value = serde_json::from_str(line).expect("invalid JSON");
        let expected_hostname = gethostname().into_string().expect("failed to get hostname");
        assert_eq!(body["Hostname"], expected_hostname);
    }

    /// Same TLS setup, but without `VARLINK_JWT` the client sends no bearer
    /// token, so the JWT-only server rejects the upgrade and varlinkctl fails.
    #[test_with::path(/usr/bin/openssl)]
    #[test_with::path(/usr/bin/varlinkctl)]
    #[test_with::path(/run/systemd/io.systemd.Hostname)]
    #[tokio::test]
    async fn test_tls_jwt_bearer_e2e_no_token_rejected() {
        let (_issuer, server, _jwks_dir, fake_xdg_home, _pki) = jwt_tls_server().await;
        let bridge_url = format!(
            "https://localhost:{}/ws/sockets/io.systemd.Hostname",
            server.addr.port()
        );

        let output = tokio::process::Command::new("varlinkctl")
            .args([
                "call",
                "--json=short",
                &format!("exec:{}", helper_binary().display()),
                "io.systemd.Hostname.Describe",
                "{}",
            ])
            .env("VARLINK_BRIDGE_URL", &bridge_url)
            .env("XDG_CONFIG_HOME", fake_xdg_home.path())
            .env_remove("VARLINK_JWT")
            .env_remove("SSH_AUTH_SOCK")
            .env_remove("VARLINK_SSH_KEY")
            .output()
            .await
            .expect("failed to run varlinkctl");

        assert!(
            !output.status.success(),
            "varlinkctl without a JWT should be rejected by the JWT-only server"
        );
    }

    /// End-to-end URL mode: a local OIDC issuer serves the discovery document
    /// and JWKS over HTTP; the authenticator fetches the keys by URL (no file)
    /// and verifies a token signed by that issuer.
    #[tokio::test]
    async fn test_jwt_url_discovery_e2e() {
        use axum::Router;
        use axum::routing::get;

        let issuer = TestIssuer::es256();
        let jwks_json = json!({ "keys": [issuer.jwk()] }).to_string();

        // Bind first so we know the port to advertise in the discovery doc.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let discovery = json!({ "issuer": base, "jwks_uri": format!("{base}/jwks") }).to_string();

        let app = Router::new()
            .route(
                "/.well-known/openid-configuration",
                get(move || {
                    let d = discovery.clone();
                    async move { ([("content-type", "application/json")], d) }
                }),
            )
            .route(
                "/jwks",
                get(move || {
                    let j = jwks_json.clone();
                    async move { ([("content-type", "application/json")], j) }
                }),
            );
        let server = tokio::spawn(async move {
            axum::serve(listener, app.into_make_service())
                .await
                .unwrap();
        });

        // Build the authenticator in URL mode (no jwks file): it fetches the
        // discovery doc + JWKS at startup. Run it off the async worker since the
        // fetch is blocking.
        let root = tempfile::tempdir().unwrap();
        let root_path = root.path().to_path_buf();
        let issuer_url = base.clone();
        let auth = tokio::task::spawn_blocking(move || {
            create_jwt_authenticator(
                JwtCliOptions {
                    issuer: Some(issuer_url),
                    audience: Some(TEST_AUDIENCE.to_string()),
                    // no issuer_jwks: forces URL/discovery mode
                    require_claims: vec!["sub=alice".to_string()],
                    ..Default::default()
                },
                None,
                &root_path,
            )
        })
        .await
        .unwrap()
        .unwrap()
        .expect("issuer URL should enable JWT auth");

        // Token's iss must match the configured issuer (the server URL).
        let claims = json!({
            "iss": base,
            "aud": TEST_AUDIENCE,
            "sub": "alice",
            "exp": now_secs() + 300,
            "iat": now_secs(),
        });
        let token = issuer.mint(&claims);
        check_request(&auth, "GET", "/sockets", Some(&bearer(&token)), None, None)
            .expect("token should verify against the discovered JWKS");

        server.abort();
    }
} // mod jwtauth_tests
