// SPDX-License-Identifier: LGPL-2.1-or-later

use anyhow::{Context, bail};
use axum::{
    Router,
    extract::ws::{Message, WebSocket, WebSocketUpgrade},
    extract::{ConnectInfo, DefaultBodyLimit, Path, Query, State},
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
    routing::{get, post},
};
use listenfd::ListenFd;
use log::{debug, error, warn};
use regex_lite::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::fs::FileTypeExt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, LazyLock};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UnixStream};
use tokio::signal;
use zlink::{Reply, varlink_service::Proxy};

#[cfg(feature = "sshauth")]
mod auth_ssh;
#[cfg(feature = "sshauth")]
mod import_ssh;

#[cfg(feature = "sshauth")]
use auth_ssh::{extract_nonce, maybe_create_ssh_authenticator};
#[cfg(not(feature = "sshauth"))]
fn extract_nonce(_headers: &axum::http::HeaderMap) -> Option<String> {
    None
}
#[derive(Debug)]
struct AppError {
    status: StatusCode,
    message: String,
}

impl AppError {
    fn bad_request(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message: message.into(),
        }
    }

    fn bad_gateway(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_GATEWAY,
            message: message.into(),
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        error!("{}", self.message);
        let body = axum::Json(json!({ "error": self.message }));
        (self.status, body).into_response()
    }
}

impl From<zlink::Error> for AppError {
    fn from(e: zlink::Error) -> Self {
        use zlink::varlink_service;
        let status = match &e {
            zlink::Error::SocketRead
            | zlink::Error::SocketWrite
            | zlink::Error::UnexpectedEof
            | zlink::Error::Io(..) => StatusCode::BAD_GATEWAY,
            zlink::Error::VarlinkService(owned) => match owned.inner() {
                varlink_service::Error::InvalidParameter { .. }
                | varlink_service::Error::ExpectedMore => StatusCode::BAD_REQUEST,
                varlink_service::Error::MethodNotFound { .. }
                | varlink_service::Error::InterfaceNotFound { .. } => StatusCode::NOT_FOUND,
                varlink_service::Error::MethodNotImplemented { .. } => StatusCode::NOT_IMPLEMENTED,
                varlink_service::Error::PermissionDenied => StatusCode::FORBIDDEN,
            },
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        };
        Self {
            status,
            message: e.to_string(),
        }
    }
}

impl From<std::io::Error> for AppError {
    fn from(e: std::io::Error) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: e.to_string(),
        }
    }
}

impl From<serde_json::Error> for AppError {
    fn from(e: serde_json::Error) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: e.to_string(),
        }
    }
}

/// Method call with dynamic method name and parameters for the POST `/call/{method}` route.
#[derive(Debug, Serialize)]
struct DynMethod<'m> {
    method: &'m str,
    parameters: Option<&'m HashMap<String, Value>>,
}

/// Successful reply parameters from a dynamic varlink call.
#[derive(Debug, Default, Deserialize)]
struct DynReply<'r>(#[serde(borrow)] Option<HashMap<&'r str, Value>>);

impl IntoResponse for DynReply<'_> {
    fn into_response(self) -> Response {
        axum::Json(self.0).into_response()
    }
}

/// Error reply from a dynamic varlink call (non-standard errors only; standard
/// `org.varlink.service.*` errors are caught earlier by zlink).
#[derive(Debug, Deserialize)]
struct DynReplyError<'e> {
    error: &'e str,
    #[serde(default)]
    parameters: Option<HashMap<&'e str, Value>>,
}

impl From<DynReplyError<'_>> for AppError {
    fn from(e: DynReplyError<'_>) -> Self {
        let message = match e.parameters {
            Some(params) => format!("{}: {params:?}", e.error),
            None => e.error.to_string(),
        };
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message,
        }
    }
}

// see https://varlink.org/Interface-Definition (interface_name there)
fn varlink_interface_name_is_valid(name: &str) -> bool {
    static RE: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"^[A-Za-z]([-]*[A-Za-z0-9])*(\.[A-Za-z0-9]([-]*[A-Za-z0-9])*)+$").unwrap()
    });
    RE.is_match(name)
}

enum VarlinkSockets {
    SocketDir { dirfd: OwnedFd },
    SingleSocket { dirfd: OwnedFd, name: String },
}

impl VarlinkSockets {
    fn from_socket_dir(dir_path: &str) -> anyhow::Result<Self> {
        let dir_file =
            std::fs::File::open(dir_path).with_context(|| format!("failed to open {dir_path}"))?;
        Ok(VarlinkSockets::SocketDir {
            dirfd: OwnedFd::from(dir_file),
        })
    }

    fn from_socket(socket_path: &str) -> anyhow::Result<Self> {
        let path = std::path::Path::new(socket_path);
        let socket_name = path
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| anyhow::anyhow!("cannot extract socket name from {socket_path}"))?;
        let dir_path = path
            .parent()
            .ok_or_else(|| anyhow::anyhow!("cannot extract parent directory from {socket_path}"))?;
        let dir_file = std::fs::File::open(dir_path)
            .with_context(|| format!("failed to open parent directory {}", dir_path.display()))?;

        Ok(VarlinkSockets::SingleSocket {
            dirfd: OwnedFd::from(dir_file),
            name: socket_name.to_string(),
        })
    }

    fn resolve_socket_with_validate(&self, name: &str) -> Result<String, AppError> {
        if !varlink_interface_name_is_valid(name) {
            return Err(AppError::bad_request(format!(
                "invalid socket name (must be a valid varlink interface name): {name}"
            )));
        }

        match self {
            VarlinkSockets::SocketDir { dirfd } => {
                Ok(format!("/proc/self/fd/{}/{name}", dirfd.as_raw_fd()))
            }
            VarlinkSockets::SingleSocket {
                dirfd,
                name: expected,
            } => {
                if name == expected {
                    Ok(format!("/proc/self/fd/{}/{name}", dirfd.as_raw_fd()))
                } else {
                    Err(AppError::bad_gateway(format!(
                        "socket '{name}' not available (only '{expected}' is available)"
                    )))
                }
            }
        }
    }

    async fn list_sockets(&self) -> Result<Vec<String>, AppError> {
        match self {
            VarlinkSockets::SocketDir { dirfd } => {
                let mut socket_names = Vec::new();
                let mut entries =
                    tokio::fs::read_dir(format!("/proc/self/fd/{}", dirfd.as_raw_fd())).await?;

                while let Some(entry) = entries.next_entry().await? {
                    let path = entry.path();
                    // we cannot reuse entry() here, we need fs::metadata() so
                    // that it follows symlinks. Skip entries where metadata fails to avoid
                    // a single bad entry bringing down the entire service.
                    let Ok(metadata) = tokio::fs::metadata(&path).await else {
                        continue;
                    };
                    if metadata.file_type().is_socket()
                        && let Some(name) = path.file_name().and_then(|fname| fname.to_str())
                        && varlink_interface_name_is_valid(name)
                    {
                        socket_names.push(name.to_string());
                    }
                }
                socket_names.sort();
                Ok(socket_names)
            }
            VarlinkSockets::SingleSocket { name, .. } => Ok(vec![name.clone()]),
        }
    }
}

async fn get_varlink_connection_with_validate_socket(
    socket: &str,
    state: &AppState,
) -> Result<zlink::unix::Connection, AppError> {
    let varlink_socket_path = state.varlink_sockets.resolve_socket_with_validate(socket)?;
    debug!("Creating varlink connection for: {varlink_socket_path}");

    let connection = zlink::unix::connect(&varlink_socket_path).await?;
    Ok(connection)
}

struct TlsListener {
    inner: TcpListener,
    acceptor: openssl::ssl::SslAcceptor,
}

impl axum::serve::Listener for TlsListener {
    type Io = tokio_openssl::SslStream<tokio::net::TcpStream>;
    type Addr = std::net::SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            let res: Result<_, Box<dyn std::error::Error>> = async {
                let (stream, addr) = self
                    .inner
                    .accept()
                    .await
                    .map_err(|e| format!("TCP accept failed: {e}"))?;
                let ssl = openssl::ssl::Ssl::new(self.acceptor.context())
                    .map_err(|e| format!("SSL context error: {e}"))?;
                let mut tls_stream = tokio_openssl::SslStream::new(ssl, stream)
                    .map_err(|e| format!("SSL stream creation failed: {e}"))?;
                std::pin::Pin::new(&mut tls_stream)
                    .accept()
                    .await
                    .map_err(|e| format!("TLS handshake failed: {e}"))?;
                Ok((tls_stream, addr))
            }
            .await;

            match res {
                Ok(conn) => return conn,
                Err(e) => warn!("{e}"),
            }
        }
    }

    fn local_addr(&self) -> std::io::Result<Self::Addr> {
        self.inner.local_addr()
    }
}

#[derive(Clone)]
struct TlsConnectionInfo {
    tls_channel_binding: String,
}

use axum::extract::connect_info::Connected;
use axum::serve::IncomingStream;

impl Connected<IncomingStream<'_, TlsListener>> for TlsConnectionInfo {
    fn connect_info(target: IncomingStream<'_, TlsListener>) -> Self {
        use varlink_httpd::{TLS_CHANNEL_BINDING_LABEL, TLS_CHANNEL_BINDING_LEN};

        let mut buf = [0u8; TLS_CHANNEL_BINDING_LEN];
        target
            .io()
            .ssl()
            .export_keying_material(&mut buf, TLS_CHANNEL_BINDING_LABEL, Some(&[]))
            // Cannot fail: load_tls_acceptor enforces TLS 1.3 minimum.
            .expect("export_keying_material must succeed with TLS 1.3");
        // extra paranoia to ensure we always have a valid channel binding
        assert!(
            buf.iter().any(|&b| b != 0),
            "TLS channel binding must not be all zeros"
        );
        let tls_channel_binding = openssl::base64::encode_block(&buf);
        TlsConnectionInfo {
            tls_channel_binding,
        }
    }
}

fn load_tls_acceptor(
    cert_path: &str,
    key_path: &str,
    client_ca_path: Option<&str>,
) -> anyhow::Result<openssl::ssl::SslAcceptor> {
    use openssl::ssl::{SslAcceptor, SslFiletype, SslMethod, SslVerifyMode};

    let mut builder = SslAcceptor::mozilla_modern_v5(SslMethod::tls_server())?;
    // mozilla_modern_v5 allows TLS 1.2, but we need 1.3 for channel binding
    // (export_keying_material requires TLS 1.3).
    builder.set_min_proto_version(Some(openssl::ssl::SslVersion::TLS1_3))?;
    builder.set_certificate_chain_file(cert_path)?;
    builder.set_private_key_file(key_path, SslFiletype::PEM)?;
    builder.check_private_key()?;

    if let Some(ca_path) = client_ca_path {
        builder.set_ca_file(ca_path)?;
        builder.set_verify(SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT);
    }

    Ok(builder.build())
}

/// Resolve TLS configuration: explicit paths take priority, then fall back to
/// systemd's $`CREDENTIALS_DIRECTORY` (see systemd.exec(5)), then no TLS.
/// Credential file names match the CLI flag names: cert, key, trust.
fn resolve_tls_acceptor(
    cli_cert: Option<String>,
    cli_key: Option<String>,
    cli_ca: Option<String>,
    creds_dir: Option<&std::path::Path>,
) -> anyhow::Result<Option<openssl::ssl::SslAcceptor>> {
    let cred = |name: &str| -> Option<String> {
        creds_dir
            .map(|d| d.join(name))
            .filter(|p| p.exists())
            .and_then(|p| p.to_str().map(String::from))
    };

    let tls_cert = cli_cert.or_else(|| cred("cert"));
    let tls_key = cli_key.or_else(|| cred("key"));
    let client_ca = cli_ca.or_else(|| cred("trust"));

    match (tls_cert.as_deref(), tls_key.as_deref()) {
        (Some(cert), Some(key)) => Ok(Some(load_tls_acceptor(cert, key, client_ca.as_deref())?)),
        (None, None) => {
            if client_ca.is_some() {
                bail!("--trust requires --cert and --key");
            }
            Ok(None)
        }
        _ => bail!("--cert and --key must be specified together"),
    }
}

trait Authenticator: Send + Sync {
    fn check_request(
        &self,
        method: &str,
        path: &str,
        auth_header: &str,
        nonce: Option<&str>,
        channel_binding: Option<&str>,
    ) -> anyhow::Result<()>;
}

async fn auth_middleware(
    State(state): State<AppState>,
    request: axum::http::Request<axum::body::Body>,
    next: Next,
) -> Response {
    if state.authenticators.is_empty() {
        return next.run(request).await;
    }

    let auth_header = match request.headers().get("authorization") {
        Some(val) => match val.to_str() {
            Ok(s) => s.to_string(),
            Err(_) => {
                return (
                    StatusCode::BAD_REQUEST,
                    axum::Json(json!({"error": "invalid Authorization header encoding"})),
                )
                    .into_response();
            }
        },
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                axum::Json(json!({"error": "missing Authorization header"})),
            )
                .into_response();
        }
    };

    let nonce = extract_nonce(request.headers());

    let tls_channel_binding: Option<String> = request
        .extensions()
        .get::<ConnectInfo<TlsConnectionInfo>>()
        .map(|ci| ci.0.tls_channel_binding.clone());

    let method = request.method().as_str().to_string();
    let path = request
        .uri()
        .path_and_query()
        .map_or(request.uri().path(), axum::http::uri::PathAndQuery::as_str)
        .to_string();

    let mut errors = Vec::new();
    for authenticator in state.authenticators.iter() {
        match authenticator.check_request(
            &method,
            &path,
            &auth_header,
            nonce.as_deref(),
            tls_channel_binding.as_deref(),
        ) {
            Ok(()) => return next.run(request).await,
            Err(e) => errors.push(e.to_string()),
        }
    }

    (
        StatusCode::UNAUTHORIZED,
        axum::Json(json!({"error": errors.join("; ")})),
    )
        .into_response()
}

#[derive(Clone)]
struct AppState {
    varlink_sockets: Arc<VarlinkSockets>,
    authenticators: Arc<Vec<Box<dyn Authenticator>>>,
}

async fn route_sockets_get(State(state): State<AppState>) -> Result<axum::Json<Value>, AppError> {
    debug!("GET sockets");
    let all_sockets = state.varlink_sockets.list_sockets().await?;
    Ok(axum::Json(json!({"sockets": all_sockets})))
}

async fn route_socket_get(
    Path(socket): Path<String>,
    State(state): State<AppState>,
) -> Result<axum::Json<Value>, AppError> {
    debug!("GET socket: {socket}");
    let mut connection = get_varlink_connection_with_validate_socket(&socket, &state).await?;

    let info = connection
        .get_info()
        .await?
        .map_err(|e| AppError::bad_gateway(format!("service error: {e}")))?;
    Ok(axum::Json(serde_json::to_value(info)?))
}

async fn route_socket_interface_get(
    Path((socket, interface)): Path<(String, String)>,
    State(state): State<AppState>,
) -> Result<axum::Json<Value>, AppError> {
    debug!("GET socket: {socket}, interface: {interface}");
    let mut connection = get_varlink_connection_with_validate_socket(&socket, &state).await?;

    let description = connection
        .get_interface_description(&interface)
        .await?
        .map_err(|e| AppError::bad_gateway(format!("service error: {e}")))?;

    let iface = description
        .parse()
        .map_err(|e| AppError::bad_gateway(format!("upstream IDL parse error: {e}")))?;

    let method_names: Vec<&str> = iface.methods().map(zlink::idl::Method::name).collect();
    Ok(axum::Json(json!({"method_names": method_names})))
}

async fn route_call_post(
    Path(method): Path<String>,
    Query(params): Query<HashMap<String, String>>,
    State(state): State<AppState>,
    axum::Json(call_args): axum::Json<HashMap<String, Value>>,
) -> Result<Response, AppError> {
    debug!("POST call for method: {method}, params: {params:#?}");

    let socket = if let Some(socket) = params.get("socket") {
        socket.clone()
    } else {
        method
            .rsplit_once('.')
            .map(|x| x.0)
            .ok_or_else(|| {
                AppError::bad_request(format!(
                    "cannot derive socket from method '{method}': no dots in name"
                ))
            })?
            .to_string()
    };

    let mut connection = get_varlink_connection_with_validate_socket(&socket, &state).await?;

    let method_call = DynMethod {
        method: &method,
        parameters: Some(&call_args),
    };
    connection
        .call_method(&method_call.into(), vec![])
        .await?
        .0
        .map(|r: Reply<DynReply>| r.into_parameters().unwrap_or_default().into_response())
        .map_err(|e: DynReplyError| e.into())
}

async fn route_ws(
    Path(varlink_socket): Path<String>,
    State(state): State<AppState>,
    ws: WebSocketUpgrade,
) -> Result<Response, AppError> {
    let unix_path = state
        .varlink_sockets
        .resolve_socket_with_validate(&varlink_socket)?;

    // Connect eagerly so connection failures return proper HTTP errors.
    let varlink_stream = UnixStream::connect(&unix_path)
        .await
        .map_err(|e| AppError::bad_gateway(format!("cannot connect to {unix_path}: {e}")))?;

    Ok(ws.on_upgrade(move |ws_socket| handle_ws(ws_socket, varlink_stream)))
}

// Forwards raw bytes between the websocket and the varlink unix
// socket in both directions. Each NUL-delimited varlink message is
// sent as one WS binary frame. Once a protocol upgrade happens this is
// dropped and its just a raw byte stream.
async fn handle_ws(mut ws: WebSocket, unix: UnixStream) {
    let (unix_read, mut unix_write) = tokio::io::split(unix);
    let mut unix_reader = tokio::io::BufReader::new(unix_read);
    let (varlink_msg_tx, mut varlink_msg_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(32);
    // the complexity here is a bit ugly but without it the websocket is very hard
    // to use from tools like "websocat" which will add a \n or \0 after each "message"
    let varlink_connection_upgraded = Arc::new(AtomicBool::new(false));

    // read_until is not cancel-safe, so run it in a separate task and we need read_until
    // to ensure we keep the \0 boundaries and send these via a varlink_msg channel.
    //
    // After a varlink protocol upgrade the connection carries raw bytes without \0
    // delimiters, so the reader switches to plain read() once "upgraded" is set.
    let reader_task = tokio::spawn({
        let varlink_connection_upgraded = varlink_connection_upgraded.clone();
        async move {
            loop {
                let mut buf = Vec::new();
                let res = if varlink_connection_upgraded.load(Ordering::Relaxed) {
                    buf.reserve(8192);
                    unix_reader.read_buf(&mut buf).await
                } else {
                    unix_reader.read_until(0, &mut buf).await
                };
                match res {
                    Err(e) => {
                        warn!("varlink read error: {e}");
                        break;
                    }
                    Ok(0) => {
                        debug!("varlink socket closed (read returned 0)");
                        break;
                    }
                    Ok(_) => {
                        if varlink_msg_tx.send(buf).await.is_err() {
                            warn!("varlink_msg channel closed, ws gone?");
                            break;
                        }
                    }
                }
            }
        }
    });

    loop {
        tokio::select! {
            ws_msg = ws.recv() => {
                let Some(Ok(msg)) = ws_msg else {
                    debug!("ws.recv() returned None or error, client disconnected");
                    break;
                };
                let data = match msg {
                    Message::Binary(bin) => {
                        debug!("ws recv binary: {} bytes", bin.len());
                        bin.to_vec()
                    }
                    Message::Text(text) => {
                        debug!("ws recv text: {} bytes", text.len());
                        text.as_bytes().to_vec()
                    }
                    Message::Close(frame) => {
                        debug!("ws recv close frame: {frame:?}");
                        break;
                    }
                    other => {
                        debug!("ws recv other: {other:?}");
                        continue;
                    }
                };
                // Detect varlink protocol upgrade request
                if !varlink_connection_upgraded.load(Ordering::Relaxed) {
                    let json_bytes = data.strip_suffix(&[0]).unwrap_or(&data);
                    match serde_json::from_slice::<Value>(json_bytes) {
                        Ok(v) => {
                            if v.get("upgrade").and_then(Value::as_bool).unwrap_or(false) {
                                debug!("varlink protocol upgrade detected");
                                varlink_connection_upgraded.store(true, Ordering::Relaxed);
                            }
                        }
                        Err(e) => {
                            warn!("failed to parse ws message as JSON for upgrade detection: {e}");
                        }
                    }
                }
                if let Err(e) = unix_write.write_all(&data).await {
                    warn!("varlink write error: {e}");
                    break;
                }
            }
            Some(data) = varlink_msg_rx.recv() => {
                if let Err(e) = ws.send(Message::Binary(data.into())).await {
                    warn!("ws send error: {e}");
                    break;
                }
            }
            else => {
                debug!("select: all branches closed");
                break;
            }
        }
    }
    debug!("handle_ws loop exited");

    reader_task.abort();
}

fn create_router(
    varlink_sockets_path: &str,
    authenticators: Vec<Box<dyn Authenticator>>,
) -> anyhow::Result<Router> {
    let metadata = std::fs::metadata(varlink_sockets_path)
        .with_context(|| format!("failed to stat {varlink_sockets_path}"))?;

    let shared_state = AppState {
        varlink_sockets: Arc::new(if metadata.is_dir() {
            VarlinkSockets::from_socket_dir(varlink_sockets_path)?
        } else if metadata.file_type().is_socket() {
            VarlinkSockets::from_socket(varlink_sockets_path)?
        } else {
            bail!("path {varlink_sockets_path} is neither a directory nor a socket");
        }),
        authenticators: Arc::new(authenticators),
    };

    // API routes behind auth middleware
    let api = Router::new()
        .route("/sockets", get(route_sockets_get))
        .route("/sockets/{socket}", get(route_socket_get))
        .route(
            "/sockets/{socket}/{interface}",
            get(route_socket_interface_get),
        )
        .route("/call/{method}", post(route_call_post))
        .route("/ws/sockets/{socket}", get(route_ws))
        .layer(axum::middleware::from_fn_with_state(
            shared_state.clone(),
            auth_middleware,
        ))
        .with_state(shared_state.clone());

    // Health endpoint is always open (no auth)
    let app = Router::new()
        .route("/health", get(|| async { StatusCode::OK }))
        .merge(api)
        .layer(DefaultBodyLimit::max(4 * 1024 * 1024));

    Ok(app)
}

async fn shutdown_signal() {
    let ctrl_c = signal::ctrl_c();
    let mut sigterm = signal::unix::signal(signal::unix::SignalKind::terminate())
        .expect("failed to install SIGTERM handler");
    tokio::select! {
        _ = ctrl_c => {},
        _ = sigterm.recv() => {},
    }
    println!("Shutdown signal received, stopping server...");
}

async fn run_server(
    varlink_sockets_path: &str,
    listener: TcpListener,
    tls_acceptor: Option<openssl::ssl::SslAcceptor>,
    authenticators: Vec<Box<dyn Authenticator>>,
) -> anyhow::Result<()> {
    let app = create_router(varlink_sockets_path, authenticators)?;

    if let Some(acceptor) = tls_acceptor {
        let tls_listener = TlsListener {
            inner: listener,
            acceptor,
        };
        axum::serve(
            tls_listener,
            app.into_make_service_with_connect_info::<TlsConnectionInfo>(),
        )
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    } else {
        axum::serve(listener, app)
            .with_graceful_shutdown(shutdown_signal())
            .await?;
    }

    Ok(())
}

#[derive(Debug)]
enum Command {
    Bridge(BridgeCli),
    #[cfg(feature = "sshauth")]
    ImportSsh(import_ssh::ImportSsh),
}

#[derive(Debug)]
struct BridgeCli {
    bind: String,
    varlink_sockets_path: String,
    cert: Option<String>,
    key: Option<String>,
    trust: Option<String>,
    authorized_keys: Option<String>,
    insecure: bool,
}

fn print_help() {
    eprint!(indoc::indoc! {"
        Usage: varlink-httpd [bridge] [OPTIONS] [VARLINK_SOCKETS_PATH]
               varlink-httpd import-ssh SOURCE [OUTPUT]

        A HTTP/WebSocket daemon for varlink sockets.

        Subcommands:
          bridge (default)                  start the HTTP/WebSocket server
          import-ssh SOURCE [OUTPUT]        download SSH authorized keys from a URL

        Bridge options:
          VARLINK_SOCKETS_PATH              directory of sockets or a single socket
                                            (default: /run/varlink/registry)
          --bind=ADDR                       address to bind to (default: 0.0.0.0:1031)
          --cert=PATH                       TLS certificate PEM file
          --key=PATH                        TLS private key PEM file
          --trust=PATH                      CA certificate PEM for client verification (mTLS)
          --authorized-keys=PATH            authorized SSH public keys file
          --insecure                        run without any authentication (DANGEROUS)
          --help                            display this help and exit
    "});
}

#[cfg(feature = "sshauth")]
fn print_import_ssh_help() {
    eprint!(indoc::indoc! {"
        Usage: varlink-httpd import-ssh SOURCE [OUTPUT]

        Download SSH authorized keys from a URL and save to a local file.

        Positional arguments:
          SOURCE  key source: `gh:<user>` or `https://` URL
          OUTPUT  output file path (default: auto-detected)

        Options:
          --help  display this help and exit
    "});
}

fn parse_cli() -> anyhow::Result<Command> {
    use lexopt::prelude::*;

    let mut bind = String::from("0.0.0.0:1031");
    let mut varlink_sockets_path = String::from("/run/varlink/registry");
    let mut cert = None;
    let mut key = None;
    let mut trust = None;
    let mut authorized_keys = None;
    let mut insecure = false;
    let mut got_positional = false;

    let mut parser = lexopt::Parser::from_env();
    while let Some(arg) = parser.next()? {
        match arg {
            Long("bind") => bind = parser.value()?.parse()?,
            Long("cert") => cert = Some(parser.value()?.parse()?),
            Long("key") => key = Some(parser.value()?.parse()?),
            Long("trust") => trust = Some(parser.value()?.parse()?),
            Long("authorized-keys") => authorized_keys = Some(parser.value()?.parse()?),
            Long("insecure") => insecure = true,
            Long("help") => {
                print_help();
                std::process::exit(0);
            }
            #[cfg(feature = "sshauth")]
            Value(val) if !got_positional && val == "import-ssh" => {
                return parse_import_ssh_args(&mut parser);
            }
            Value(val) if !got_positional && val == "bridge" => {
                // explicit "bridge" subcommand — just consume the keyword
                got_positional = false;
            }
            Value(val) if !got_positional => {
                varlink_sockets_path = val.parse()?;
                got_positional = true;
            }
            _ => return Err(arg.unexpected().into()),
        }
    }

    Ok(Command::Bridge(BridgeCli {
        bind,
        varlink_sockets_path,
        cert,
        key,
        trust,
        authorized_keys,
        insecure,
    }))
}

#[cfg(feature = "sshauth")]
fn parse_import_ssh_args(parser: &mut lexopt::Parser) -> anyhow::Result<Command> {
    use lexopt::prelude::*;

    let mut source = None;
    let mut output = None;

    while let Some(arg) = parser.next()? {
        match arg {
            Long("help") => {
                print_import_ssh_help();
                std::process::exit(0);
            }
            Value(val) if source.is_none() => source = Some(val.parse()?),
            Value(val) if output.is_none() => output = Some(val.parse()?),
            _ => return Err(arg.unexpected().into()),
        }
    }

    let source =
        source.ok_or_else(|| anyhow::anyhow!("import-ssh: SOURCE argument is required"))?;
    Ok(Command::ImportSsh(import_ssh::ImportSsh { source, output }))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // not using "tracing" crate here because its quite big (>1.2mb to the production build)
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("warn")).init();

    let command = parse_cli()?;

    let cli = match command {
        #[cfg(feature = "sshauth")]
        Command::ImportSsh(cmd) => return import_ssh::run(cmd),
        Command::Bridge(cli) => cli,
    };

    // run with e.g. "systemd-socket-activate -l 127.0.0.1:1031 -- varlink-httpd"
    let mut listenfd = ListenFd::from_env();
    let listener = if let Some(std_listener) = listenfd.take_tcp_listener(0)? {
        // needed or tokio panics, see https://github.com/mitsuhiko/listenfd/pull/23
        std_listener.set_nonblocking(true)?;
        TcpListener::from_std(std_listener)?
    } else {
        TcpListener::bind(&cli.bind).await?
    };

    let creds_dir = std::env::var_os("CREDENTIALS_DIRECTORY").map(std::path::PathBuf::from);

    // Resolve mTLS: remember if trust was provided before consuming the options
    let has_mtls =
        cli.trust.is_some() || creds_dir.as_ref().is_some_and(|d| d.join("trust").exists());

    let tls_acceptor = resolve_tls_acceptor(cli.cert, cli.key, cli.trust, creds_dir.as_deref())?;

    #[cfg(not(feature = "sshauth"))]
    if cli.authorized_keys.is_some() {
        bail!("--authorized-keys= requires building with the 'sshauth' feature");
    }

    let mut authenticators: Vec<Box<dyn Authenticator>> = Vec::new();

    #[cfg(feature = "sshauth")]
    if let Some(ssh_auth) = maybe_create_ssh_authenticator(
        cli.authorized_keys,
        creds_dir.as_deref(),
        std::path::Path::new("/"),
    )? {
        authenticators.push(Box::new(ssh_auth));
    }

    if authenticators.is_empty() && !has_mtls && !cli.insecure {
        bail!("no authentication configured: use --authorized-keys=, --trust=, or --insecure");
    }
    if cli.insecure && authenticators.is_empty() && !has_mtls {
        eprintln!("WARNING: running without authentication - all routes are open");
    }

    let local_addr = listener.local_addr()?;
    let scheme = if tls_acceptor.is_some() {
        "HTTPS"
    } else {
        "HTTP"
    };

    eprintln!("Varlink proxy started");
    eprintln!(
        "Forwarding {scheme} {local_addr} -> Varlink: {varlink_sockets_path}",
        varlink_sockets_path = &cli.varlink_sockets_path
    );
    run_server(
        &cli.varlink_sockets_path,
        listener,
        tls_acceptor,
        authenticators,
    )
    .await
}

#[cfg(test)]
mod tests;
