// SPDX-License-Identifier: LGPL-2.1-or-later

// Reduced-feature builds leave some shared auth plumbing unused; the
// default build still gets full dead-code checking.
#![cfg_attr(not(feature = "sshauth"), allow(dead_code))]

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
use std::sync::{Arc, LazyLock};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UnixStream};
use tokio::signal;
use tokio_vsock::VsockListener;
use varlink_http_bridge::TlsChannelBinding;
use zlink::varlink_service::Proxy;

#[cfg(feature = "sshauth")]
mod auth_ssh;
#[cfg(feature = "sshauth")]
mod import_ssh;
mod openapi;
mod tls_cert;
mod ws_framing;

use ws_framing::VarlinkFramer;

#[cfg(feature = "sshauth")]
use auth_ssh::create_ssh_authenticator;
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

type VarlinkConns = HashMap<String, Arc<tokio::sync::Mutex<zlink::tokio::unix::Connection>>>;

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
    tls_channel_binding: Option<TlsChannelBinding>,
}

impl VarlinkConnCache {
    fn new(tls_channel_binding: Option<TlsChannelBinding>) -> Self {
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
) -> Result<Arc<tokio::sync::Mutex<zlink::tokio::unix::Connection>>, AppError> {
    let varlink_socket_path = state.varlink_sockets.resolve_socket_with_validate(socket)?;

    let mut cache = conn_cache.conns.lock().await;
    if let Some(conn) = cache.get(socket) {
        debug!("Reusing varlink connection for: {varlink_socket_path}");
        return Ok(conn.clone());
    }

    debug!("Creating varlink connection for: {varlink_socket_path}");
    let connection = Arc::new(tokio::sync::Mutex::new(
        zlink::tokio::unix::connect(&varlink_socket_path).await?,
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
            let val = e.data().to_string().ok()?;
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
    config: &TlsConfig,
    stream: S,
) -> anyhow::Result<tokio_openssl::SslStream<S>> {
    let mut ssl = openssl::ssl::Ssl::new(config.acceptor.context()).context("SSL context error")?;
    if let Some(trust) = &config.client_trust {
        // Per handshake so a CA that changed on disk applies to new connections
        // without restarting the listener.
        ssl.set_verify_cert_store(trust.store()?)
            .context("installing client CA store")?;
    }
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
    fn new(mut inner: L, config: TlsConfig) -> std::io::Result<Self> {
        let local_addr = inner.local_addr()?;
        let (tx, rx) = tokio::sync::mpsc::channel(256);

        tokio::spawn(async move {
            loop {
                let (stream, addr) = inner.accept().await;
                let tx = tx.clone();
                let config = config.clone();
                tokio::spawn(async move {
                    match tls_accept(&config, stream).await {
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

/// The CAs that client certificates are verified against, re-read when the
/// file changes so a `trust` credential that appears or rotates after start
/// takes effect without a restart.
///
/// Holding no CAs is a valid state: it rejects every client, which is what
/// mTLS that is enabled but not yet configured has to do.
struct ClientTrust {
    path: Option<std::path::PathBuf>,
    cache: std::sync::Mutex<TrustCache>,
}

struct TrustCache {
    /// `None` when the file does not (yet) exist.
    mtime: Option<std::time::SystemTime>,
    cas: Vec<openssl::x509::X509>,
}

impl ClientTrust {
    fn new(path: Option<&str>) -> Self {
        let trust = Self {
            path: path.map(std::path::PathBuf::from),
            cache: std::sync::Mutex::new(TrustCache {
                mtime: None,
                cas: Vec::new(),
            }),
        };
        trust.maybe_reload();
        if trust.cache.lock().unwrap().cas.is_empty() {
            // Otherwise the only symptom is a per-connection "certificate
            // verify failed", which reads as a bad client certificate.
            match &trust.path {
                Some(p) => warn!(
                    "mTLS is enabled but {} holds no CA, every client is rejected until one appears",
                    p.display()
                ),
                None => warn!(
                    "mTLS is enabled but no CA is configured, so every client will be rejected. \
                     Pass --trust= or supply a 'trust' credential."
                ),
            }
        }
        trust
    }

    /// Re-read the CA file when its mtime changed. A file that cannot be read
    /// or parsed keeps the previous CAs and leaves the mtime alone, so the
    /// next connection retries; a file that is gone drops them.
    fn maybe_reload(&self) {
        let Some(path) = self.path.as_deref() else {
            return;
        };
        let mut cache = self.cache.lock().unwrap();
        let on_disk = match path.metadata().and_then(|m| m.modified()) {
            Ok(mtime) => Some(mtime),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => {
                warn!(
                    "cannot stat {}: {e}, keeping cached client CAs",
                    path.display()
                );
                return;
            }
        };
        if on_disk == cache.mtime {
            return;
        }

        let Some(mtime) = on_disk else {
            warn!(
                "{} is gone, mTLS will reject every client until it returns",
                path.display()
            );
            *cache = TrustCache {
                mtime: None,
                cas: Vec::new(),
            };
            return;
        };

        match std::fs::read(path)
            .map_err(anyhow::Error::from)
            .and_then(|pem| Ok(openssl::x509::X509::stack_from_pem(&pem)?))
        {
            Ok(cas) if cas.is_empty() => {
                warn!(
                    "no certificates in {}, mTLS will reject every client",
                    path.display()
                );
                *cache = TrustCache {
                    mtime: Some(mtime),
                    cas,
                };
            }
            Ok(cas) => {
                info!("loaded {} client CA(s) from {}", cas.len(), path.display());
                *cache = TrustCache {
                    mtime: Some(mtime),
                    cas,
                };
            }
            // Leave mtime untouched so the next connection tries again.
            Err(e) => warn!(
                "cannot load {}: {e:#}, keeping cached client CAs",
                path.display()
            ),
        }
    }

    /// A store for one handshake. `SSL_set0_verify_cert_store` takes ownership,
    /// so this cannot be shared; the certificates themselves are refcounted and
    /// only the store wrapper is rebuilt.
    fn store(&self) -> anyhow::Result<openssl::x509::store::X509Store> {
        self.maybe_reload();
        let cache = self.cache.lock().unwrap();
        let mut builder = openssl::x509::store::X509StoreBuilder::new()?;
        for ca in &cache.cas {
            builder.add_cert(ca.clone())?;
        }
        Ok(builder.build())
    }
}

/// A TLS listener's configuration: the handshake parameters, plus the client
/// CAs when mTLS is enabled.
#[derive(Clone)]
struct TlsConfig {
    acceptor: openssl::ssl::SslAcceptor,
    /// `None` when mTLS is off, so no client certificate is requested.
    client_trust: Option<Arc<ClientTrust>>,
}

fn load_tls_config(
    cert_path: &str,
    key_path: &str,
    client_ca_path: Option<&str>,
    require_client_cert: bool,
) -> anyhow::Result<TlsConfig> {
    use openssl::ssl::{SslAcceptor, SslFiletype, SslMethod, SslVerifyMode};

    let mut builder = SslAcceptor::mozilla_modern_v5(SslMethod::tls_server())?;
    // mozilla_modern_v5 allows TLS 1.2, but we need 1.3 for channel binding
    // (export_keying_material requires TLS 1.3).
    builder.set_min_proto_version(Some(openssl::ssl::SslVersion::TLS1_3))?;
    builder.set_certificate_chain_file(cert_path)?;
    builder.set_private_key_file(key_path, SslFiletype::PEM)?;
    builder.check_private_key()?;

    // The CAs store is configured per-handshake.
    let client_trust = require_client_cert.then(|| {
        builder.set_verify(SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT);
        Arc::new(ClientTrust::new(client_ca_path))
    });

    Ok(TlsConfig {
        acceptor: builder.build(),
        client_trust,
    })
}

/// Resolve TLS configuration: explicit paths take priority, then systemd's
/// $`CREDENTIALS_DIRECTORY` (see systemd.exec(5)), then a self-signed
/// certificate generated and persisted under the state directory.
///
/// Credential file names match the CLI flag names: cert, key, trust.
fn resolve_tls_config(
    cli_cert: Option<String>,
    cli_key: Option<String>,
    cli_ca: Option<String>,
    creds_dir: Option<&std::path::Path>,
    require_mtls: bool,
) -> anyhow::Result<TlsConfig> {
    let creds = creds_dir.map(varlink_http_bridge::sysconf::CredentialsLoader::from_dir);
    let cred = |name: &str| -> Option<String> {
        creds
            .as_ref()
            .and_then(|c| c.path(name))
            .and_then(|p| p.to_str().map(String::from))
    };

    let tls_cert = cli_cert.or_else(|| cred("cert"));
    let tls_key = cli_key.or_else(|| cred("key"));
    // Fall back to where the credential will appear, not just where one
    // already is: with --require-mtls the CA may only show up on a later
    // `systemctl reload`, and a path we never learned cannot be watched.
    let client_ca = cli_ca
        .or_else(|| cred("trust"))
        .or_else(|| creds_dir.map(|d| d.join("trust").to_string_lossy().into_owned()));

    match (tls_cert.as_deref(), tls_key.as_deref()) {
        (Some(cert), Some(key)) => load_tls_config(cert, key, client_ca.as_deref(), require_mtls),
        (None, None) => {
            // TLS is not optional, generate a self-signed cert.
            let dir = tls_cert::state_dir()?;
            let (cert_path, key_path) = tls_cert::load_or_generate(&dir)?;
            tls_cert::print_pin(&cert_path)?;
            if require_mtls {
                warn!(
                    "The server certificate is self-signed while mTLS is enabled. \
                     Clients verifying it against your CA will refuse to connect. \
                     Pass --cert=/--key= issued by that CA, or have clients pin the key above."
                );
            }
            load_tls_config(
                cert_path
                    .to_str()
                    .expect("failed to convert cert path to str"),
                key_path
                    .to_str()
                    .expect("failed to convert key path to str"),
                client_ca.as_deref(),
                require_mtls,
            )
        }
        _ => bail!("--cert and --key must be specified together"),
    }
}

/// Carries the raw headers so each auth method extracts what it needs
/// without the trait growing a parameter per method.
struct AuthRequest<'a> {
    method: &'a str,
    path: &'a str,
    headers: &'a axum::http::HeaderMap,
    /// From the TLS layer (RFC 9266 exporter), not a header.
    tls_channel_binding: Option<&'a TlsChannelBinding>,
}

impl AuthRequest<'_> {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).and_then(|v| v.to_str().ok())
    }

    fn authorization(&self) -> Option<&str> {
        self.header("authorization")
    }

    /// Token from `Authorization: Bearer <token>`; the scheme is
    /// case-insensitive per RFC 7235.
    fn bearer_token(&self) -> anyhow::Result<&str> {
        let header = self
            .authorization()
            .context("missing Authorization header")?;
        let (scheme, token) = header
            .split_once(' ')
            .context("Authorization header must be 'Bearer <token>'")?;
        if !scheme.eq_ignore_ascii_case("bearer") {
            bail!("Authorization scheme must be 'Bearer'");
        }
        Ok(token.trim_start_matches(' '))
    }
}

/// A per-request authentication mechanism selected with `--auth=`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AuthMechanism {
    /// Bearer token signed by an authorized SSH key.
    #[cfg(feature = "sshauth")]
    Ssh,
    /// No per-request authentication.
    None,
}

impl AuthMechanism {
    const ALL: &'static [Self] = &[
        #[cfg(feature = "sshauth")]
        Self::Ssh,
        Self::None,
    ];

    fn as_str(self) -> &'static str {
        match self {
            #[cfg(feature = "sshauth")]
            Self::Ssh => "ssh",
            Self::None => "none",
        }
    }

    /// The mechanisms this build accepts, for help and error messages.
    fn names() -> String {
        Self::ALL
            .iter()
            .map(|m| m.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    }

    fn parse(name: &str) -> anyhow::Result<Self> {
        if let Some(mechanism) = Self::ALL.iter().copied().find(|m| m.as_str() == name) {
            return Ok(mechanism);
        }
        #[cfg(not(feature = "sshauth"))]
        if name == "ssh" {
            bail!("--auth=ssh requires building with the 'sshauth' feature");
        }
        bail!(
            "unknown --auth mechanism '{name}' (valid: {})",
            Self::names()
        );
    }
}

fn parse_auth(value: &str) -> anyhow::Result<Vec<AuthMechanism>> {
    let mut auth = Vec::new();
    for name in value.split(',').map(str::trim).filter(|n| !n.is_empty()) {
        let mechanism = AuthMechanism::parse(name)?;
        if !auth.contains(&mechanism) {
            auth.push(mechanism);
        }
    }
    if auth.is_empty() {
        bail!(
            "--auth= needs at least one mechanism ({})",
            AuthMechanism::names()
        );
    }
    if auth.contains(&AuthMechanism::None) && auth.len() > 1 {
        bail!("--auth=none cannot be combined with other mechanisms");
    }
    Ok(auth)
}

trait Authenticator: Send + Sync {
    fn check_request(&self, request: &AuthRequest) -> anyhow::Result<()>;
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
    fn check_request(&self, request: &AuthRequest) -> anyhow::Result<()> {
        debug!(
            "auth: allowing {} {} ({})",
            request.method, request.path, self.reason
        );
        Ok(())
    }
}

async fn auth_middleware(
    State(state): State<AppState>,
    request: axum::http::Request<axum::body::Body>,
    next: Next,
) -> Response {
    let tls_channel_binding: Option<TlsChannelBinding> = request
        .extensions()
        .get::<ConnectInfo<VarlinkConnCache>>()
        .and_then(|ci| ci.0.tls_channel_binding.clone());

    let auth_request = AuthRequest {
        method: request.method().as_str(),
        path: request
            .uri()
            .path_and_query()
            .map_or(request.uri().path(), axum::http::uri::PathAndQuery::as_str),
        headers: request.headers(),
        tls_channel_binding: tls_channel_binding.as_ref(),
    };

    debug!(
        "auth: checking {} {} (tls_cb={:?})",
        auth_request.method, auth_request.path, auth_request.tls_channel_binding
    );

    let mut errors = Vec::new();
    // flag instead of early return: `auth_request` borrows `request`, and
    // next.run() needs `request` back by value
    let mut accepted = false;
    for authenticator in state.authenticators.iter() {
        match authenticator.check_request(&auth_request) {
            Ok(()) => {
                debug!(
                    "auth: accepted {} {}",
                    auth_request.method, auth_request.path
                );
                accepted = true;
                break;
            }
            Err(e) => errors.push(e.to_string()),
        }
    }
    if accepted {
        return next.run(request).await;
    }

    let joined = if errors.is_empty() {
        "no authenticators configured".to_string()
    } else {
        errors.join("; ")
    };
    debug!(
        "auth: rejected {} {}: {joined}",
        auth_request.method, auth_request.path
    );
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

/// The IDL of one interface, as fetched from a varlink socket.
///
/// A parsed [`zlink::idl::Interface`] borrows from the IDL text, so fetching
/// and parsing cannot collapse into a single call. Holding the unparsed text
/// in its own type keeps the two halves and their error mapping together.
struct InterfaceIdl(zlink::varlink_service::InterfaceDescription<'static>);

impl InterfaceIdl {
    /// Fetch the IDL of `interface` from `socket`.
    ///
    /// The connection guard is dropped before returning: the IDL is owned, so
    /// parsing it needs no connection and must not keep other callers of the
    /// same socket waiting.
    async fn fetch(
        socket: &str,
        interface: &str,
        state: &AppState,
        conn_cache: &VarlinkConnCache,
    ) -> Result<Self, AppError> {
        let conn_arc = get_varlink_connection(socket, state, conn_cache).await?;
        let mut connection = conn_arc.lock().await;

        let description = connection
            .get_interface_description(interface)
            .await?
            .map_err(|e| AppError::bad_gateway(format!("service error: {e}")))?;
        Ok(Self(description))
    }

    fn parse(&self) -> Result<zlink::idl::Interface<'_>, AppError> {
        self.0
            .parse()
            .map_err(|e| AppError::bad_gateway(format!("upstream IDL parse error: {e}")))
    }
}

async fn route_openapi_get(
    ConnectInfo(conn_cache): ConnectInfo<VarlinkConnCache>,
    Path((socket, interface)): Path<(String, String)>,
    State(state): State<AppState>,
) -> Result<axum::Json<Value>, AppError> {
    debug!("GET openapi for socket: {socket}, interface: {interface}");
    let idl = InterfaceIdl::fetch(&socket, &interface, &state, &conn_cache).await?;
    let iface = idl.parse()?;

    // the title and every generated path come from the returned description,
    // so a service that ignores the requested name would hand out a document
    // for a different API with nothing to indicate it
    if iface.name() != interface {
        return Err(AppError::bad_gateway(format!(
            "upstream described interface '{}' but '{interface}' was requested",
            iface.name()
        )));
    }

    Ok(axum::Json(openapi::idl_to_openapi(&socket, &iface)))
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
    let idl = InterfaceIdl::fetch(&socket, &interface, &state, &conn_cache).await?;
    let iface = idl.parse()?;

    let method_names: Vec<&str> = iface.methods().map(zlink::idl::Method::name).collect();
    Ok(axum::Json(json!({"method_names": method_names})))
}

/// Stream varlink `more` replies as a JSON text sequence (RFC 7464).
///
/// Each record is RS (0x1E) + JSON + LF.  The content-type is
/// `application/json-seq`.
fn varlink_call_to_jsonseq(
    mut conn: tokio::sync::OwnedMutexGuard<zlink::tokio::unix::Connection>,
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

/// Call a varlink method on the given socket.
///
/// - Default: single JSON response via varlink `call`
/// - `Accept: application/json-seq`: stream replies via varlink `more`
///   as a JSON text sequence (RFC 7464)
async fn call_varlink_method(
    socket: &str,
    method: &str,
    state: &AppState,
    conn_cache: &VarlinkConnCache,
    headers: &axum::http::HeaderMap,
    call_args: &HashMap<String, Value>,
) -> Result<Response, AppError> {
    let accept = headers
        .get(axum::http::header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();

    let method_call = DynMethod {
        method,
        parameters: Some(call_args),
    };

    let conn_arc = get_varlink_connection(socket, state, conn_cache).await?;
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

/// Call a varlink method, deriving the socket from the method's
/// interface prefix unless overridden via `?socket=`.
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

    call_varlink_method(&socket, &method, &state, &conn_cache, &headers, &call_args).await
}

/// Call a varlink method with the socket given explicitly in the path.
/// This is the form the generated `OpenAPI` documents use.
async fn route_call_socket_post(
    ConnectInfo(conn_cache): ConnectInfo<VarlinkConnCache>,
    Path((socket, method)): Path<(String, String)>,
    Query(params): Query<HashMap<String, String>>,
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    axum::Json(call_args): axum::Json<HashMap<String, Value>>,
) -> Result<Response, AppError> {
    debug!("POST call for socket: {socket}, method: {method}");

    // `?socket=` is the override for the other /call route and has no meaning
    // here; accepting it would suggest it does something
    if params.contains_key("socket") {
        return Err(AppError::bad_request(
            "?socket= is not supported here, the socket is already given in the path",
        ));
    }

    call_varlink_method(&socket, &method, &state, &conn_cache, &headers, &call_args).await
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

/// Send each frame as one WS binary message.
async fn send_ws_frames(
    ws: &mut WebSocket,
    frames: impl IntoIterator<Item = Vec<u8>>,
) -> Result<(), axum::Error> {
    for frame in frames {
        ws.send(Message::Binary(frame.into())).await?;
    }
    Ok(())
}

// Time to wait for the close handshake to finish before giving up.
const WS_CLOSE_TIMEOUT: Duration = Duration::from_secs(2);

/// Finish the close handshake. Bounded so that a stuck peer cannot
/// hold this task forever.
async fn close_ws(ws: &mut WebSocket) {
    let closing_handshake = async {
        // tungstenite only queues the reply to a received close frame,
        // it gets written on the next flush; close() does that flush and
        // sends our own close frame when we are closing first
        if let Err(e) = futures_util::SinkExt::close(ws).await {
            debug!("ws close failed: {e}");
            return;
        }
        // ends when the peers close frame arrived or the connection died
        while let Some(Ok(msg)) = ws.recv().await {
            debug!("ws recv while closing: {msg:?}");
        }
    };
    if tokio::time::timeout(WS_CLOSE_TIMEOUT, closing_handshake)
        .await
        .is_err()
    {
        debug!("timed out closing WebSocket");
    }
}

// Forwards bytes between the websocket and the varlink unix socket in
// both directions; framing decisions live in [`VarlinkFramer`].
async fn handle_ws(mut ws: WebSocket, unix: UnixStream) {
    let (mut unix_read, mut unix_write) = tokio::io::split(unix);
    let mut varlink_framer = VarlinkFramer::new();
    let mut buf: Vec<u8> = Vec::with_capacity(8192);

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
                        close_ws(&mut ws).await;
                        break;
                    }
                    msg @ (Message::Ping(_) | Message::Pong(_)) => {
                        // keepalives; axum answers pings automatically
                        debug!("ws recv keepalive: {msg:?}");
                        continue;
                    }
                };
                varlink_framer.detect_protocol_upgrade_request(&data);
                if let Err(e) = unix_write.write_all(&data).await {
                    warn!("varlink write error: {e}");
                    close_ws(&mut ws).await;
                    break;
                }
            }
            res = unix_read.read_buf(&mut buf) => {  // this is cancel-safe
                match res {
                    Err(e) => {
                        warn!("varlink read error: {e}");
                        close_ws(&mut ws).await;
                        break;
                    }
                    Ok(0) => {
                        debug!("varlink socket closed (read returned 0)");
                        if let Err(e) = send_ws_frames(&mut ws, varlink_framer.finish()).await {
                            warn!("ws send error: {e}");
                        }
                        close_ws(&mut ws).await;
                        break;
                    }
                    Ok(_) => {
                        let ws_frames = varlink_framer.push_varlink_bytes(&buf);
                        buf.clear();  // clear() keeps the capacity of buf
                        if let Err(e) = send_ws_frames(&mut ws, ws_frames).await {
                            warn!("ws send error: {e}");
                            break;
                        }
                    }
                }
            }
        }
    }
    debug!("handle_ws loop exited");
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
        .route("/openapi/{socket}/{interface}", get(route_openapi_get))
        .route("/call/{method}", post(route_call_post))
        .route("/call/{socket}/{method}", post(route_call_socket_post))
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
    tls_config: Option<TlsConfig>,
) -> anyhow::Result<(Transport, Option<TlsConfig>)> {
    let addr = rustix::net::getsockname(fd.as_fd())?;
    match addr.address_family() {
        rustix::net::AddressFamily::VSOCK => {
            let listener = VsockListener::from(fd);
            Ok((Transport::Vsock(listener), tls_config))
        }
        rustix::net::AddressFamily::INET | rustix::net::AddressFamily::INET6 => {
            let std_listener = std::net::TcpListener::from(fd);
            // needed or tokio panics, see https://github.com/mitsuhiko/listenfd/pull/23
            std_listener.set_nonblocking(true)?;
            Ok((
                Transport::Tcp(TcpListener::from_std(std_listener)?),
                tls_config,
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
    tls_config: Option<TlsConfig>,
    app: Router,
) -> anyhow::Result<()> {
    let make_svc = app.into_make_service_with_connect_info::<VarlinkConnCache>();

    match (listener, tls_config) {
        (Transport::Vsock(l), Some(config)) => {
            axum::serve(AsyncTlsListener::new(l, config)?, make_svc)
                .with_graceful_shutdown(shutdown_signal())
                .await?;
        }
        (Transport::Vsock(l), None) => {
            axum::serve(l, make_svc)
                .with_graceful_shutdown(shutdown_signal())
                .await?;
        }
        (Transport::Tcp(l), Some(config)) => {
            let plain = PlainListener { inner: l };
            axum::serve(AsyncTlsListener::new(plain, config)?, make_svc)
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
    tls_config: Option<TlsConfig>,
    varlink_sockets_path: &str,
    authenticators: Vec<Box<dyn Authenticator>>,
) -> anyhow::Result<()> {
    let app = create_router(varlink_sockets_path, authenticators)?;
    serve_listener(listener, tls_config, app).await
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
    require_mtls: bool,
    authorized_keys: Option<String>,
    auth: Vec<AuthMechanism>,
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
          --auth=MECHANISMS                 comma-separated per-request authentication
                                            ({auth}); required unless --insecure.
                                            mTLS is enabled separately and applies
                                            on top of whatever is selected here
          --cert=PATH                       TLS certificate PEM file
                                            (default: self-signed, generated
                                            and persisted on first start)
          --key=PATH                        TLS private key PEM file
          --trust=PATH                      CA certificate PEM for client verification
                                            (mTLS); implies --require-mtls
          --require-mtls                    require a verified client certificate. The CA
                                            may be supplied later via a 'trust' credential.
                                            Until then every client is rejected
          --authorized-keys=PATH            authorized SSH public keys file
          --insecure                        run over plain HTTP without any
                                            authentication (DANGEROUS)
          --help                            display this help and exit
    ",
            auth = AuthMechanism::names(),
        }
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
    let mut require_mtls = false;
    let mut authorized_keys = None;
    let mut auth = None;
    let mut insecure = false;
    let mut got_positional = false;

    let mut parser = lexopt::Parser::from_env();
    while let Some(arg) = parser.next()? {
        match arg {
            Long("bind") => bind_strs.push(parser.value()?.parse()?),
            Long("cert") => cert = Some(parser.value()?.parse()?),
            Long("key") => key = Some(parser.value()?.parse()?),
            Long("trust") => trust = Some(parser.value()?.parse()?),
            Long("require-mtls") => require_mtls = true,
            Long("authorized-keys") => authorized_keys = Some(parser.value()?.parse()?),
            Long("auth") => auth = Some(parse_auth(&parser.value()?.string()?)?),
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

    let require_mtls = require_mtls || trust.is_some();

    // Under --insecure the TLS options are never read. Silently dropping
    // --trust would turn a setup that asked for mTLS into an open one.
    if insecure {
        for (name, set) in [
            ("--cert=", cert.is_some()),
            ("--key=", key.is_some()),
            ("--trust=", trust.is_some()),
            ("--require-mtls", require_mtls),
        ] {
            if set {
                bail!("--insecure serves plain HTTP and can't be combined with {name}");
            }
        }
    }

    let auth = match auth {
        Some(auth) if insecure && auth != [AuthMechanism::None] => bail!(
            "--insecure runs without authentication and can't be combined with --auth={}",
            auth.iter()
                .map(|m| m.as_str())
                .collect::<Vec<_>>()
                .join(","),
        ),
        Some(auth) => auth,
        // --insecure already states that no authentication is wanted.
        None if insecure => vec![AuthMechanism::None],
        None => bail!(
            "--auth= is required, pick the mechanisms to enable ({})",
            AuthMechanism::names()
        ),
    };

    #[cfg(feature = "sshauth")]
    if authorized_keys.is_some() && !auth.contains(&AuthMechanism::Ssh) {
        bail!("--authorized-keys= is only used with --auth=ssh");
    }
    #[cfg(not(feature = "sshauth"))]
    if authorized_keys.is_some() {
        bail!("--authorized-keys= requires building with the 'sshauth' feature");
    }

    Ok(Command::Bridge(BridgeCli {
        binds,
        varlink_sockets_path,
        cert,
        key,
        trust,
        require_mtls,
        authorized_keys,
        auth,
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

/// Credentials present in `creds_dir` that this configuration never reads,
/// paired with what would make them count.
///
/// Enabling a mechanism from the mere presence of a credential would mean one
/// that fails to show up silently drops it, so the flags decide and provisioned
/// material can go unread. That is easy to mistake for having taken effect.
#[cfg_attr(not(feature = "sshauth"), allow(unused_variables))]
fn unread_credentials(
    creds_dir: &std::path::Path,
    insecure: bool,
    require_mtls: bool,
    auth: &[AuthMechanism],
    authorized_keys: Option<&str>,
) -> Vec<(String, &'static str)> {
    let mut unread = Vec::new();

    for (name, read, why) in [
        ("cert", !insecure, "--insecure serves plain HTTP"),
        ("key", !insecure, "--insecure serves plain HTTP"),
        ("trust", require_mtls, "pass --require-mtls to enable mTLS"),
    ] {
        if !read && creds_dir.join(name).exists() {
            unread.push((name.to_string(), why));
        }
    }

    #[cfg(feature = "sshauth")]
    {
        // An explicit --authorized-keys= replaces discovery rather than adding
        // to it, so it hides credentials even when ssh auth is selected.
        let why = if authorized_keys.is_some() {
            Some("--authorized-keys= replaces credential discovery")
        } else if !auth.contains(&AuthMechanism::Ssh) {
            Some("pass --auth=ssh to use them")
        } else {
            None
        };
        if let Some(why) = why {
            unread.extend(
                auth_ssh::authorized_keys_credentials(creds_dir)
                    .into_iter()
                    .map(|name| (name, why)),
            );
        }
    }

    unread
}

/// The middleware accepts a request as soon as one of these accepts it, so an
/// empty list rejects everything.
///
/// `etc_root` is the filesystem root for the well-known `/etc/varlink-httpd`
/// key discovery; only tests override it.
#[cfg_attr(not(feature = "sshauth"), allow(unused_variables))]
fn build_authenticators(
    auth: &[AuthMechanism],
    insecure: bool,
    require_mtls: bool,
    authorized_keys: Option<&str>,
    creds_dir: Option<&std::path::Path>,
    etc_root: &std::path::Path,
) -> anyhow::Result<Vec<Box<dyn Authenticator>>> {
    let mut authenticators: Vec<Box<dyn Authenticator>> = Vec::new();
    for mechanism in auth {
        match mechanism {
            #[cfg(feature = "sshauth")]
            AuthMechanism::Ssh => authenticators.push(Box::new(create_ssh_authenticator(
                authorized_keys.map(String::from),
                creds_dir,
                etc_root,
            )?)),
            AuthMechanism::None if insecure => {
                warn!("running without authentication");
                authenticators.push(Box::new(AllowAllAuthenticator {
                    reason: "--insecure",
                }));
            }
            // Every other way of having no per-request mechanism needs mTLS to
            // carry the authentication, so refuse to serve without it.
            AuthMechanism::None if require_mtls => {
                authenticators.push(Box::new(AllowAllAuthenticator {
                    reason: "--auth=none, client verified at TLS layer",
                }));
            }
            AuthMechanism::None => {
                bail!(
                    "--auth=none needs mTLS (--require-mtls) to authenticate clients, or --insecure"
                );
            }
        }
    }

    Ok(authenticators)
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

    let creds_dir = varlink_http_bridge::sysconf::CredentialsLoader::path_from_env();

    if let Some(dir) = creds_dir.as_deref() {
        let unread: Vec<String> = unread_credentials(
            dir,
            cli.insecure,
            cli.require_mtls,
            &cli.auth,
            cli.authorized_keys.as_deref(),
        )
        .iter()
        .map(|(name, why)| format!("{name} ({why})"))
        .collect();
        if !unread.is_empty() {
            warn!(
                "credential(s) present but unused by this configuration: {}",
                unread.join("; ")
            );
        }
    }

    let authenticators = build_authenticators(
        &cli.auth,
        cli.insecure,
        cli.require_mtls,
        cli.authorized_keys.as_deref(),
        creds_dir.as_deref(),
        std::path::Path::new("/"),
    )?;

    let tls_config = if cli.insecure {
        None
    } else {
        Some(resolve_tls_config(
            cli.cert,
            cli.key,
            cli.trust,
            creds_dir.as_deref(),
            cli.require_mtls,
        )?)
    };
    let scheme = if tls_config.is_some() {
        "HTTPS"
    } else {
        "HTTP"
    };

    let app = create_router(&cli.varlink_sockets_path, authenticators)?;

    // Socket activation: consume all activated fds, or fall back to explicit --bind
    // run with e.g. "systemd-socket-activate -l 127.0.0.1:1031 -- varlink-httpd"
    let mut listeners: Vec<(Transport, Option<TlsConfig>)> = Vec::new();
    let mut listenfd = ListenFd::from_env();
    for idx in 0..listenfd.len() {
        if let Some(raw_fd) = listenfd.take_raw_fd(idx)? {
            // SAFETY: listenfd.take_raw_fd() returns a valid, owned fd from socket activation
            let fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };
            listeners.push(listener_from_activated_fd(fd, tls_config.clone())?);
        }
    }

    if listeners.is_empty() {
        // No socket activation: bind explicitly based on --bind (or default)
        for bind in cli.binds {
            let listener = listener_from_bind_addr(bind).await?;
            listeners.push((listener, tls_config.clone()));
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
