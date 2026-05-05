// SPDX-License-Identifier: LGPL-2.1-or-later

use anyhow::{Context, bail};
use async_stream::stream;
use axum::{
    Router,
    body::Body,
    extract::connect_info::Connected,
    extract::ws::{Message, WebSocket, WebSocketUpgrade},
    extract::{ConnectInfo, DefaultBodyLimit, Path, Query, State},
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
    routing::{get, post},
    serve::IncomingStream,
};
use listenfd::ListenFd;
use log::{debug, error, info, warn};
use regex_lite::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::FileTypeExt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, LazyLock};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UnixStream};
use tokio::signal;
use tokio_vsock::VsockListener;
use zlink::varlink_service::Proxy;

#[cfg(feature = "sshauth")]
mod auth_ssh;
#[cfg(feature = "sshauth")]
mod import_ssh;

#[cfg(feature = "sshauth")]
use auth_ssh::{create_ssh_authenticator, extract_nonce};
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
        let mut message = None;
        let status = match &e {
            zlink::Error::SocketRead
            | zlink::Error::SocketWrite
            | zlink::Error::UnexpectedEof
            | zlink::Error::Io(..) => StatusCode::BAD_GATEWAY,
            zlink::Error::VarlinkService(owned) => match owned.inner() {
                varlink_service::Error::InvalidParameter { .. } => StatusCode::BAD_REQUEST,
                varlink_service::Error::ExpectedMore => {
                    message = Some(
                        "This method requires the varlink 'more' flag. \
                         Use Accept: application/json-seq to enable streaming."
                            .to_string(),
                    );
                    StatusCode::BAD_REQUEST
                }
                varlink_service::Error::MethodNotFound { .. }
                | varlink_service::Error::InterfaceNotFound { .. } => StatusCode::NOT_FOUND,
                varlink_service::Error::MethodNotImplemented { .. } => StatusCode::NOT_IMPLEMENTED,
                varlink_service::Error::PermissionDenied => StatusCode::FORBIDDEN,
            },
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        };
        Self {
            status,
            message: message.unwrap_or(e.to_string()),
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

type VarlinkConns = HashMap<String, Arc<tokio::sync::Mutex<zlink::unix::Connection>>>;

/// Per-HTTP-connection cache of varlink unix socket connections.
///
/// Created once when an HTTP connection is accepted (via [`Connected`])
/// and shared across all requests on that connection.  When the HTTP
/// connection closes the cache is dropped, closing the varlink sockets.
///
/// Also carries the optional TLS channel binding for SSH-based auth.
#[derive(Clone)]
struct VarlinkConnCache {
    conns: Arc<tokio::sync::Mutex<VarlinkConns>>,
    tls_channel_binding: Option<String>,
}

impl VarlinkConnCache {
    fn new(tls_channel_binding: Option<String>) -> Self {
        Self {
            conns: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            tls_channel_binding,
        }
    }
}

impl Connected<IncomingStream<'_, PlainListener>> for VarlinkConnCache {
    fn connect_info(target: IncomingStream<'_, PlainListener>) -> Self {
        info!("New connection from {}", target.remote_addr());
        Self::new(None)
    }
}

async fn get_varlink_connection(
    socket: &str,
    state: &AppState,
    conn_cache: &VarlinkConnCache,
) -> Result<Arc<tokio::sync::Mutex<zlink::unix::Connection>>, AppError> {
    let varlink_socket_path = state.varlink_sockets.resolve_socket_with_validate(socket)?;

    let mut cache = conn_cache.conns.lock().await;
    if let Some(conn) = cache.get(socket) {
        debug!("Reusing varlink connection for: {varlink_socket_path}");
        return Ok(conn.clone());
    }

    debug!("Creating varlink connection for: {varlink_socket_path}");
    let connection = Arc::new(tokio::sync::Mutex::new(
        zlink::unix::connect(&varlink_socket_path).await?,
    ));
    cache.insert(socket.to_string(), connection.clone());
    Ok(connection)
}

/// Accept a TCP connection, configure socket options, and retry on transient errors.
async fn accept_and_configure(
    listener: &TcpListener,
) -> (tokio::net::TcpStream, std::net::SocketAddr) {
    loop {
        match listener.accept().await {
            Ok((stream, addr)) => {
                if let Err(e) = varlink_http_bridge::set_tcp_keepalive_and_nodelay(&stream) {
                    warn!("on accept from {addr}: {e:#}");
                }
                return (stream, addr);
            }
            Err(e) => warn!("TCP accept failed: {e}"),
        }
    }
}

fn format_x509_subject(cert: &openssl::x509::X509Ref) -> String {
    cert.subject_name()
        .entries()
        .filter_map(|e| {
            let obj = e.object().nid().short_name().ok()?;
            let val = e.data().as_utf8().ok()?;
            Some(format!("{obj}={val}"))
        })
        .collect::<Vec<_>>()
        .join(", ")
}

fn log_tls_connection(ssl: &openssl::ssl::SslRef, addr: &std::net::SocketAddr) {
    match ssl.peer_certificate() {
        Some(cert) => {
            let subject = format_x509_subject(&cert);
            info!("New TLS connection from {addr}, client cert: {subject}");
        }
        None => info!("New TLS connection from {addr}, no client cert"),
    }
}

/// Perform a TLS handshake on an already-accepted stream.
async fn tls_accept<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(
    acceptor: &openssl::ssl::SslAcceptor,
    stream: S,
) -> anyhow::Result<tokio_openssl::SslStream<S>> {
    let ssl = openssl::ssl::Ssl::new(acceptor.context()).context("SSL context error")?;
    let mut tls_stream =
        tokio_openssl::SslStream::new(ssl, stream).context("SSL stream creation failed")?;
    std::pin::Pin::new(&mut tls_stream)
        .accept()
        .await
        .context("TLS handshake failed")?;
    Ok(tls_stream)
}

/// TLS wrapper for any `axum::serve::Listener`. Performs handshakes concurrently
/// so a slow or stalled client cannot block other connections. A background task
/// accepts raw connections and spawns a task per handshake; completed TLS streams
/// are delivered through an mpsc channel.
struct AsyncTlsListener<L: axum::serve::Listener> {
    local_addr: L::Addr,
    receiver: tokio::sync::mpsc::Receiver<(tokio_openssl::SslStream<L::Io>, L::Addr)>,
}

impl<L> AsyncTlsListener<L>
where
    L: axum::serve::Listener + Send + 'static,
    L::Io: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    L::Addr: Clone + Send + std::fmt::Display + 'static,
{
    fn new(mut inner: L, acceptor: openssl::ssl::SslAcceptor) -> std::io::Result<Self> {
        let local_addr = inner.local_addr()?;
        let (tx, rx) = tokio::sync::mpsc::channel(256);

        tokio::spawn(async move {
            loop {
                let (stream, addr) = inner.accept().await;
                let tx = tx.clone();
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    match tls_accept(&acceptor, stream).await {
                        Ok(tls_stream) => {
                            if tx.send((tls_stream, addr)).await.is_err() {
                                warn!("TLS listener receiver dropped");
                            }
                        }
                        Err(e) => warn!("TLS handshake from {addr}: {e:#}"),
                    }
                });
            }
        });

        Ok(Self {
            local_addr,
            receiver: rx,
        })
    }
}

impl<L> axum::serve::Listener for AsyncTlsListener<L>
where
    L: axum::serve::Listener + Send + 'static,
    L::Io: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    L::Addr: Clone + Send + 'static,
{
    type Io = tokio_openssl::SslStream<L::Io>;
    type Addr = L::Addr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        self.receiver
            .recv()
            .await
            .expect("TLS accept loop terminated unexpectedly")
    }

    fn local_addr(&self) -> std::io::Result<Self::Addr> {
        Ok(self.local_addr.clone())
    }
}

struct PlainListener {
    inner: TcpListener,
}

impl axum::serve::Listener for PlainListener {
    type Io = tokio::net::TcpStream;
    type Addr = std::net::SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        accept_and_configure(&self.inner).await
    }

    fn local_addr(&self) -> std::io::Result<Self::Addr> {
        self.inner.local_addr()
    }
}

impl Connected<IncomingStream<'_, AsyncTlsListener<PlainListener>>> for VarlinkConnCache {
    fn connect_info(target: IncomingStream<'_, AsyncTlsListener<PlainListener>>) -> Self {
        let ssl = target.io().ssl();
        log_tls_connection(ssl, target.remote_addr());
        let tls_channel_binding = varlink_http_bridge::export_tls_channel_binding(ssl);
        Self::new(Some(tls_channel_binding))
    }
}

impl Connected<IncomingStream<'_, VsockListener>> for VarlinkConnCache {
    fn connect_info(target: IncomingStream<'_, VsockListener>) -> Self {
        let peer = target.remote_addr();
        info!("New vsock connection from CID {}", peer.cid());
        Self::new(None)
    }
}

impl Connected<IncomingStream<'_, AsyncTlsListener<VsockListener>>> for VarlinkConnCache {
    fn connect_info(target: IncomingStream<'_, AsyncTlsListener<VsockListener>>) -> Self {
        let ssl = target.io().ssl();
        let peer = target.remote_addr();
        info!("New TLS vsock connection from CID {}", peer.cid());
        let tls_channel_binding = varlink_http_bridge::export_tls_channel_binding(ssl);
        Self::new(Some(tls_channel_binding))
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
        auth_header: Option<&str>,
        nonce: Option<&str>,
        channel_binding: Option<&str>,
    ) -> anyhow::Result<()>;
}

/// Authenticator that accepts every request.
///
/// Pushed explicitly when authentication is delegated to a lower layer
/// (mTLS verified during the TLS handshake) or deliberately disabled
/// (`--insecure`). Making this an explicit authenticator keeps the
/// middleware fail-closed: an empty `authenticators` list always rejects,
/// so no future code path can accidentally turn into open access by
/// failing to push a real authenticator.
struct AllowAllAuthenticator {
    reason: &'static str,
}

impl Authenticator for AllowAllAuthenticator {
    fn check_request(
        &self,
        method: &str,
        path: &str,
        _auth_header: Option<&str>,
        _nonce: Option<&str>,
        _channel_binding: Option<&str>,
    ) -> anyhow::Result<()> {
        debug!("auth: allowing {method} {path} ({})", self.reason);
        Ok(())
    }
}

/// Extract the Authorization header value, if present and valid UTF-8.
fn extract_auth_header(request: &axum::http::Request<Body>) -> Option<String> {
    request
        .headers()
        .get("authorization")?
        .to_str()
        .ok()
        .map(String::from)
}

async fn auth_middleware(
    State(state): State<AppState>,
    request: axum::http::Request<axum::body::Body>,
    next: Next,
) -> Response {
    let auth_header = extract_auth_header(&request);
    let nonce = extract_nonce(request.headers());

    let tls_channel_binding: Option<String> = request
        .extensions()
        .get::<ConnectInfo<VarlinkConnCache>>()
        .and_then(|ci| ci.0.tls_channel_binding.clone());

    let method = request.method().as_str().to_string();
    let path = request
        .uri()
        .path_and_query()
        .map_or(request.uri().path(), axum::http::uri::PathAndQuery::as_str)
        .to_string();

    debug!("auth: checking {method} {path} (nonce={nonce:?}, tls_cb={tls_channel_binding:?})");

    let mut errors = Vec::new();
    for authenticator in state.authenticators.iter() {
        match authenticator.check_request(
            &method,
            &path,
            auth_header.as_deref(),
            nonce.as_deref(),
            tls_channel_binding.as_deref(),
        ) {
            Ok(()) => {
                debug!("auth: accepted {method} {path}");
                return next.run(request).await;
            }
            Err(e) => errors.push(e.to_string()),
        }
    }

    let joined = if errors.is_empty() {
        "no authenticators configured".to_string()
    } else {
        errors.join("; ")
    };
    debug!("auth: rejected {method} {path}: {joined}");
    (
        StatusCode::UNAUTHORIZED,
        axum::Json(json!({"error": joined})),
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
    ConnectInfo(conn_cache): ConnectInfo<VarlinkConnCache>,
    Path(socket): Path<String>,
    State(state): State<AppState>,
) -> Result<axum::Json<Value>, AppError> {
    debug!("GET socket: {socket}");
    let conn_arc = get_varlink_connection(&socket, &state, &conn_cache).await?;
    let mut connection = conn_arc.lock().await;

    let info = connection
        .get_info()
        .await?
        .map_err(|e| AppError::bad_gateway(format!("service error: {e}")))?;
    Ok(axum::Json(serde_json::to_value(info)?))
}

async fn route_socket_interface_get(
    ConnectInfo(conn_cache): ConnectInfo<VarlinkConnCache>,
    Path((socket, interface)): Path<(String, String)>,
    State(state): State<AppState>,
) -> Result<axum::Json<Value>, AppError> {
    debug!("GET socket: {socket}, interface: {interface}");
    let conn_arc = get_varlink_connection(&socket, &state, &conn_cache).await?;
    let mut connection = conn_arc.lock().await;

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

/// Stream varlink `more` replies as a JSON text sequence (RFC 7464).
///
/// Each record is RS (0x1E) + JSON + LF.  The content-type is
/// `application/json-seq`.
fn varlink_call_to_jsonseq(
    mut conn: tokio::sync::OwnedMutexGuard<zlink::unix::Connection>,
) -> Response {
    let stream = stream! {
        loop {
            match conn.receive_reply::<Value, DynReplyError>().await {
                Ok((reply, _fds)) => {
                    let continues = reply.as_ref().is_ok_and(|r| r.continues().unwrap_or(false));
                    let json_str = match reply {
                        Ok(r) => serde_json::to_string(&r.into_parameters()).unwrap_or_default(),
                        Err(e) => json!({"error": e.error, "parameters": e.parameters}).to_string(),
                    };
                    yield Ok::<_, std::convert::Infallible>(
                        format!("\x1e{json_str}\n"),
                    );
                    if !continues {
                        break;
                    }
                }
                Err(e) => {
                    let error_json = json!({"error": e.to_string()});
                    yield Ok(format!("\x1e{error_json}\n"));
                    break;
                }
            }
        }
    };
    Response::builder()
        .header("Content-Type", "application/json-seq")
        .body(Body::from_stream(stream))
        .unwrap()
}

/// Call a varlink method.
///
/// - Default: single JSON response via varlink `call`
/// - `Accept: application/json-seq`: stream replies via varlink `more`
///   as a JSON text sequence (RFC 7464)
async fn route_call_post(
    ConnectInfo(conn_cache): ConnectInfo<VarlinkConnCache>,
    Path(method): Path<String>,
    Query(params): Query<HashMap<String, String>>,
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
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

    let accept = headers
        .get(axum::http::header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();

    let method_call = DynMethod {
        method: &method,
        parameters: Some(&call_args),
    };

    let conn_arc = get_varlink_connection(&socket, &state, &conn_cache).await?;
    let mut connection = conn_arc.lock_owned().await;
    if accept.contains("application/json-seq") {
        connection
            .send_call(&zlink::Call::new(&method_call).set_more(true), vec![])
            .await?;
        Ok(varlink_call_to_jsonseq(connection))
    } else {
        connection
            .call_method::<_, DynReply, DynReplyError>(&method_call.into(), vec![])
            .await?
            .0
            .map(|r| r.into_parameters().unwrap_or_default().into_response())
            .map_err(AppError::from)
    }
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

enum Transport {
    Tcp(TcpListener),
    Vsock(VsockListener),
}

impl std::fmt::Display for Transport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Transport::Tcp(l) => {
                let addr = l.local_addr().map_err(|_| std::fmt::Error)?;
                write!(f, "{addr}")
            }
            Transport::Vsock(l) => {
                let addr = l.local_addr().map_err(|_| std::fmt::Error)?;
                write!(f, "vsock:{}:{}", addr.cid(), addr.port())
            }
        }
    }
}

/// Create a [`Transport`] from a socket-activated file descriptor.
fn listener_from_activated_fd(
    fd: OwnedFd,
    tls_acceptor: Option<openssl::ssl::SslAcceptor>,
) -> anyhow::Result<(Transport, Option<openssl::ssl::SslAcceptor>)> {
    let addr = rustix::net::getsockname(fd.as_fd())?;
    match addr.address_family() {
        rustix::net::AddressFamily::VSOCK => {
            let listener = VsockListener::from(fd);
            Ok((Transport::Vsock(listener), tls_acceptor))
        }
        rustix::net::AddressFamily::INET | rustix::net::AddressFamily::INET6 => {
            let std_listener = std::net::TcpListener::from(fd);
            // needed or tokio panics, see https://github.com/mitsuhiko/listenfd/pull/23
            std_listener.set_nonblocking(true)?;
            Ok((
                Transport::Tcp(TcpListener::from_std(std_listener)?),
                tls_acceptor,
            ))
        }
        family => bail!("unsupported socket family from socket activation: {family:?}"),
    }
}

/// Create a [`Transport`] from an explicit `--bind` address.
async fn listener_from_bind_addr(bind: BindAddr) -> anyhow::Result<Transport> {
    match bind {
        BindAddr::Vsock { cid, port } => {
            let listener = VsockListener::bind(tokio_vsock::VsockAddr::new(cid, port))
                .with_context(|| format!("vsock bind to CID {cid}, port {port}"))?;
            Ok(Transport::Vsock(listener))
        }
        BindAddr::Tcp(ref addr) => {
            let listener = TcpListener::bind(addr).await?;
            Ok(Transport::Tcp(listener))
        }
    }
}

async fn serve_listener(
    listener: Transport,
    tls_acceptor: Option<openssl::ssl::SslAcceptor>,
    app: Router,
) -> anyhow::Result<()> {
    let make_svc = app.into_make_service_with_connect_info::<VarlinkConnCache>();

    match (listener, tls_acceptor) {
        (Transport::Vsock(l), Some(acceptor)) => {
            axum::serve(AsyncTlsListener::new(l, acceptor)?, make_svc)
                .with_graceful_shutdown(shutdown_signal())
                .await?;
        }
        (Transport::Vsock(l), None) => {
            axum::serve(l, make_svc)
                .with_graceful_shutdown(shutdown_signal())
                .await?;
        }
        (Transport::Tcp(l), Some(acceptor)) => {
            let plain = PlainListener { inner: l };
            axum::serve(AsyncTlsListener::new(plain, acceptor)?, make_svc)
                .with_graceful_shutdown(shutdown_signal())
                .await?;
        }
        (Transport::Tcp(l), None) => {
            axum::serve(PlainListener { inner: l }, make_svc)
                .with_graceful_shutdown(shutdown_signal())
                .await?;
        }
    }

    Ok(())
}

#[cfg(test)]
async fn start_server(
    listener: Transport,
    tls_acceptor: Option<openssl::ssl::SslAcceptor>,
    varlink_sockets_path: &str,
    authenticators: Vec<Box<dyn Authenticator>>,
) -> anyhow::Result<()> {
    let app = create_router(varlink_sockets_path, authenticators)?;
    serve_listener(listener, tls_acceptor, app).await
}

#[derive(Debug)]
enum Command {
    Bridge(BridgeCli),
    #[cfg(feature = "sshauth")]
    ImportSsh(import_ssh::ImportSsh),
}

use varlink_http_bridge::DEFAULT_PORT;

#[derive(Debug)]
enum BindAddr {
    Tcp(String),
    Vsock { cid: u32, port: u32 },
}

/// Parse a bind address string.
///
/// Strings starting with `vsock` are parsed as vsock addresses
/// (matching systemd's `ListenStream=` syntax):
/// - `vsock`          -> `CID_ANY`, default port
/// - `vsock:`         -> `CID_ANY`, default port
/// - `vsock::PORT`    -> `CID_ANY`, explicit port
/// - `vsock:CID:PORT` -> explicit CID and port
///
/// Everything else is treated as a TCP address.
impl std::str::FromStr for BindAddr {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> anyhow::Result<Self> {
        let Some(rest) = s.strip_prefix("vsock") else {
            return Ok(BindAddr::Tcp(s.to_string()));
        };
        // "vsock" or "vsock:" with nothing after
        if rest.is_empty() || rest == ":" {
            return Ok(BindAddr::Vsock {
                cid: vsock::VMADDR_CID_ANY,
                port: DEFAULT_PORT,
            });
        }
        // must start with ':'
        let rest = rest
            .strip_prefix(':')
            .ok_or_else(|| anyhow::anyhow!("invalid vsock bind address: {s}"))?;
        let parts: Vec<&str> = rest.splitn(2, ':').collect();
        match parts.as_slice() {
            // "vsock::PORT"
            ["", port] => Ok(BindAddr::Vsock {
                cid: vsock::VMADDR_CID_ANY,
                port: port
                    .parse()
                    .with_context(|| format!("invalid vsock port: {port}"))?,
            }),
            // "vsock:CID:PORT"
            [cid, port] => Ok(BindAddr::Vsock {
                cid: cid
                    .parse()
                    .with_context(|| format!("invalid vsock CID: {cid}"))?,
                port: port
                    .parse()
                    .with_context(|| format!("invalid vsock port: {port}"))?,
            }),
            // "vsock:PORT" (single number = port, CID_ANY)
            [port_or_empty] => {
                if port_or_empty.is_empty() {
                    Ok(BindAddr::Vsock {
                        cid: vsock::VMADDR_CID_ANY,
                        port: DEFAULT_PORT,
                    })
                } else {
                    Ok(BindAddr::Vsock {
                        cid: vsock::VMADDR_CID_ANY,
                        port: port_or_empty
                            .parse()
                            .with_context(|| format!("invalid vsock port: {port_or_empty}"))?,
                    })
                }
            }
            _ => bail!("invalid vsock bind address: {s}"),
        }
    }
}

#[derive(Debug)]
struct BridgeCli {
    binds: Vec<BindAddr>,
    varlink_sockets_path: String,
    cert: Option<String>,
    key: Option<String>,
    trust: Option<String>,
    authorized_keys: Option<String>,
    insecure: bool,
}

fn print_help() {
    eprint!(
        "{}",
        indoc::formatdoc! {"
        Usage: varlink-httpd [bridge] [OPTIONS] [VARLINK_SOCKETS_PATH]
               varlink-httpd import-ssh SOURCE [OUTPUT]

        A HTTP/WebSocket daemon for varlink sockets.

        Subcommands:
          bridge (default)                  start the HTTP/WebSocket server
          import-ssh SOURCE [OUTPUT]        download SSH authorized keys from a URL

        Bridge options:
          VARLINK_SOCKETS_PATH              directory of sockets or a single socket
                                            (default: /run/varlink/registry)
          --bind=ADDR                       address to bind to (repeatable;
                                            default: 0.0.0.0:{DEFAULT_PORT})
                                            use vsock::PORT for vsock (e.g. vsock::{DEFAULT_PORT})
          --cert=PATH                       TLS certificate PEM file
          --key=PATH                        TLS private key PEM file
          --trust=PATH                      CA certificate PEM for client verification (mTLS)
          --authorized-keys=PATH            authorized SSH public keys file
          --insecure                        run without any authentication (DANGEROUS)
          --help                            display this help and exit
    "}
    );
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

    let mut bind_strs: Vec<String> = Vec::new();
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
            Long("bind") => bind_strs.push(parser.value()?.parse()?),
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
                // explicit "bridge" subcommand, just consume the keyword
                got_positional = false;
            }
            Value(val) if !got_positional => {
                varlink_sockets_path = val.parse()?;
                got_positional = true;
            }
            _ => return Err(arg.unexpected().into()),
        }
    }

    if bind_strs.is_empty() {
        bind_strs.push(format!("0.0.0.0:{DEFAULT_PORT}"));
    }
    let binds: Vec<BindAddr> = bind_strs
        .iter()
        .map(|s| s.parse())
        .collect::<Result<_, _>>()?;

    Ok(Command::Bridge(BridgeCli {
        binds,
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
    {
        let ssh_auth = create_ssh_authenticator(
            cli.authorized_keys,
            creds_dir.as_deref(),
            std::path::Path::new("/"),
        )?;
        authenticators.push(Box::new(ssh_auth));
    }

    if cli.insecure {
        authenticators.clear();
        authenticators.push(Box::new(AllowAllAuthenticator {
            reason: "--insecure",
        }));
        eprintln!("WARNING: running without authentication - all routes are open");
    } else if authenticators.is_empty() {
        if has_mtls {
            // mTLS verifies the client during the TLS handshake; no
            // additional per-request HTTP authentication is needed.
            authenticators.push(Box::new(AllowAllAuthenticator {
                reason: "mTLS verified at TLS layer",
            }));
        } else {
            #[cfg(not(feature = "sshauth"))]
            bail!(
                "no authentication configured: build with 'sshauth' feature, use --trust=, or --insecure"
            );
        }
    }

    let app = create_router(&cli.varlink_sockets_path, authenticators)?;

    let scheme = if tls_acceptor.is_some() {
        "HTTPS"
    } else {
        "HTTP"
    };

    // Socket activation: consume all activated fds, or fall back to explicit --bind
    // run with e.g. "systemd-socket-activate -l 127.0.0.1:1031 -- varlink-httpd"
    let mut listeners: Vec<(Transport, Option<openssl::ssl::SslAcceptor>)> = Vec::new();
    let mut listenfd = ListenFd::from_env();
    for idx in 0..listenfd.len() {
        if let Some(raw_fd) = listenfd.take_raw_fd(idx)? {
            // SAFETY: listenfd.take_raw_fd() returns a valid, owned fd from socket activation
            let fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };
            listeners.push(listener_from_activated_fd(fd, tls_acceptor.clone())?);
        }
    }

    if listeners.is_empty() {
        // No socket activation: bind explicitly based on --bind (or default)
        for bind in cli.binds {
            let listener = listener_from_bind_addr(bind).await?;
            listeners.push((listener, tls_acceptor.clone()));
        }
    } else {
        eprintln!("Varlink proxy started (socket-activated)");
    }

    let mut join_set = tokio::task::JoinSet::new();
    for (listener, tls) in listeners {
        eprintln!(
            "Forwarding {scheme} {listener} -> Varlink: {}",
            cli.varlink_sockets_path
        );
        let app_clone = app.clone();
        join_set.spawn(async move { serve_listener(listener, tls, app_clone).await });
    }

    // Wait for all listeners; propagate the first error
    while let Some(result) = join_set.join_next().await {
        result??;
    }

    Ok(())
}
#[cfg(test)]
mod tests;
