// SPDX-License-Identifier: LGPL-2.1-or-later

//! Client side of the varlink-http-bridge: dial a varlink-httpd
//! bridge server and get a WebSocket that carries raw varlink.
//!
//! [`connect_ws`] takes the URL of one of a bridge's endpoints, e.g.
//! `https://host:1031/ws/services/<name>`, and returns the WebSocket. Every
//! binary frame on it is one varlink message, NUL-terminated JSON as on the
//! unix socket, and [`ws::WsByteStream`] reads it as an
//! `AsyncRead + AsyncWrite` byte stream. That is the form a varlink
//! implementation such as zlink or varlink-rs wants a transport in, so the
//! usual way to use this crate is to hand the stream to one of them rather
//! than to speak the protocol yourself:
//!
//! ```no_run
//! # async fn example() -> anyhow::Result<()> {
//! let url = "https://host:1031/ws/services/io.systemd.Hostname";
//! let ws = varlink_http_client::connect_ws(url).await?;
//! let varlink = varlink_http_client::ws::WsByteStream::new(ws);
//! // `varlink` is the byte stream to give to the varlink client of your choice
//! # Ok(())
//! # }
//! ```
//!
//! Trust and credentials, the CA or pinned key for the server and the API
//! key or SSH key for the client, come from the same environment variables
//! and config dir as `varlinkctl-http` uses; see the bridge README. An API
//! to set them from the program is planned.
//!
//! # Features
//!
//! * `sshauth` (default): the SSH signature auth method.

mod api_key_client;
mod client_auth;
#[cfg(feature = "sshauth")]
mod sshauth_client;
mod transport;

pub use client_auth::connect_ws;
#[cfg(feature = "sshauth")]
pub(crate) use transport::url_is_tls;
pub(crate) use transport::{config_dir, connect_transport, ws_upgrade};
// What a caller needs to use the WebSocket this crate dials, so that one
// dependency is enough.
pub use varlink_http_core::{AsyncStream, BoxedStream, ws};

/// A dialed bridge: raw varlink in binary frames, see [`ws::WsByteStream`]
/// to read it as a byte stream.
pub type Ws = tokio_tungstenite::WebSocketStream<BoxedStream>;
