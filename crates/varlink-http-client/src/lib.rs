// SPDX-License-Identifier: LGPL-2.1-or-later

//! Client side of the varlink-http-bridge: dial a varlink-httpd
//! bridge server and get a WebSocket that carries raw varlink.
//!
//! A [`Client`] holds the trust and credentials, the CA or pinned key for
//! the server and the API key or SSH key for the client. [`Client::from_env`]
//! takes them from the same environment variables and config dir as
//! `varlinkctl-http` uses, see the bridge README. [`Client::connect`] then
//! dials the URL of one of a bridge's endpoints, e.g.
//! `https://host:1031/ws/services/<name>`, and returns the varlink as an
//! `AsyncRead + AsyncWrite` byte stream, the same NUL-terminated JSON as on
//! the unix socket. That is the form a varlink implementation such as zlink
//! or varlink-rs wants a transport in, so the usual way to use this crate is
//! to hand the stream to one of them rather than to speak the protocol
//! yourself:
//!
//! ```no_run
//! # async fn example() -> anyhow::Result<()> {
//! use varlink_http_client::Client;
//!
//! let url = "https://host:1031/ws/services/io.systemd.Hostname";
//! let varlink = Client::from_env()?.connect(url).await?;
//! // `varlink` is the byte stream to give to the varlink client of your choice
//! # Ok(())
//! # }
//! ```
//!
//! # Features
//!
//! * `sshauth` (default): the SSH signature auth method.

mod api_key_client;
mod client;
mod client_auth;
mod sshauth_client;
mod transport;

pub use client::Client;
#[cfg(feature = "sshauth")]
pub(crate) use transport::url_is_tls;
pub(crate) use transport::{config_dir, ws_upgrade};
// What a caller needs to use the stream this crate dials, so that one
// dependency is enough.
pub use varlink_http_core::{AsyncStream, BoxedStream, ws};

/// A dialed bridge: raw varlink as a byte stream. Underneath, each message
/// travels in one binary WebSocket frame, see [`ws::WsByteStream`].
pub type VarlinkStream = ws::WsByteStream<BoxedStream>;

/// The WebSocket before it is wrapped, as the auth methods hand it around.
pub(crate) type WebSocket = tokio_tungstenite::WebSocketStream<BoxedStream>;
