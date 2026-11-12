// SPDX-License-Identifier: LGPL-2.1-or-later

//! Auth method selection for the WebSocket upgrade request: the first
//! applicable method in `methods()` wins. Selection, conflict warnings,
//! reduced-build diagnostics and the unauthenticated fallback are generic,
//! so a new method (JWT, `DPoP`, RFC 9421) only adds a `ClientAuth` impl
//! and an entry.

use anyhow::Result;
use futures_util::future::LocalBoxFuture;
use log::{debug, warn};
use tokio_tungstenite::tungstenite;

pub(crate) trait ClientAuth {
    /// Short name for logs and error hints.
    fn name(&self) -> &'static str;

    /// Explicit user intent (its env var is set), never ambient state like
    /// `SSH_AUTH_SOCK`: this only drives conflict warnings, which must not
    /// fire on every desktop that happens to run an ssh-agent.
    fn configured(&self) -> bool;

    /// `Ok(None)` when the method is not applicable (e.g. its env var is
    /// unset). The method drives the whole connect flow so it can retry
    /// with several candidate credentials (one attempt per SSH key).
    /// Boxed for object safety; non-`Send` because the binary runs a
    /// `current_thread` runtime and rustc cannot prove the SSH retry
    /// future `Send` anyway.
    fn connect<'a>(&'a self, url: &'a str) -> LocalBoxFuture<'a, Result<Option<crate::Ws>>>;

    /// Added to the connect error when the server rejected this method.
    fn rejected_hint(&self) -> String {
        format!(
            "{} was rejected by the server; other auth methods were skipped",
            self.name()
        )
    }
}

/// Always compiled, so a credential whose method is compiled out warns
/// instead of being silently ignored.
const METHOD_FEATURES: &[(&str, &str, bool)] =
    &[("VARLINK_SSH_KEY", "sshauth", cfg!(feature = "sshauth"))];

/// In precedence order.
fn methods() -> Vec<&'static dyn ClientAuth> {
    vec![
        &crate::api_key_client::ApiKeyBearer,
        #[cfg(feature = "sshauth")]
        &crate::sshauth_client::SshSignature,
    ]
}

/// 403 counts too: the credential was understood and refused.
fn is_http_rejection(err: &anyhow::Error) -> bool {
    err.downcast_ref::<tungstenite::Error>().is_some_and(
        |e| matches!(e, tungstenite::Error::Http(r) if matches!(r.status().as_u16(), 401 | 403)),
    )
}

/// Dial a varlink-httpd and return the WebSocket that carries raw varlink.
///
/// `url` is the full endpoint, `https://host:1031/ws/services/io.systemd.Hostname`
/// (`/ws/sockets/` is the older spelling); `http` and `vsock://cid:port` work
/// the same way. How the server is trusted and which credential is sent
/// follow `varlinkctl-http`'s environment variables and config dir, see the
/// bridge README; the ssh-agent path may wait for a hardware key to be
/// touched. The future is not `Send`.
///
/// Binary frames carry the varlink messages; [`ws::WsByteStream`](crate::ws::WsByteStream)
/// reads them as a byte stream.
///
/// # Errors
/// Returns an error if the transport cannot be set up, the server rejects the
/// credential, or the WebSocket handshake fails.
pub async fn connect_ws(url: &str) -> Result<crate::Ws> {
    for (env, feature, enabled) in METHOD_FEATURES {
        if !enabled && std::env::var_os(env).is_some() {
            warn!("{env} is set but this build lacks the '{feature}' feature; ignoring it");
        }
    }

    connect_with(&methods(), url).await
}

/// `connect_ws` with the methods given, so that a test does not pick up
/// the credentials of whoever runs it.
async fn connect_with(methods: &[&dyn ClientAuth], url: &str) -> Result<crate::Ws> {
    for (i, method) in methods.iter().enumerate() {
        let ws = match method.connect(url).await {
            Ok(Some(ws)) => ws,
            Ok(None) => continue,
            // No other method gets a turn after a rejection, so name this one
            Err(e) if is_http_rejection(&e) => {
                let hint = method.rejected_hint();
                return Err(e.context(hint));
            }
            Err(e) => return Err(e),
        };
        debug!("auth: using {}", method.name());
        for other in &methods[i + 1..] {
            if other.configured() {
                warn!(
                    "{} takes precedence; ignoring {}",
                    method.name(),
                    other.name()
                );
            }
        }
        return Ok(ws);
    }

    // No method applicable: connect unauthenticated, the server decides.
    let (stream, request, tcb) = crate::connect_transport(url).await?;
    crate::ws_upgrade(request, stream, tcb.is_some())
        .await
        .map_err(|e| {
            if !is_http_rejection(&e) {
                return e;
            }
            // the methods are always listed, so ask which ones the user set
            e.context(if methods.iter().any(|m| m.configured()) {
                "none of the configured credentials applied, so none was sent"
            } else {
                "no credential configured"
            })
        })
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;

    /// A method that does not apply, like an agent without a usable key.
    struct NotApplicable {
        configured: bool,
    }

    impl ClientAuth for NotApplicable {
        fn name(&self) -> &'static str {
            "test auth"
        }

        fn configured(&self) -> bool {
            self.configured
        }

        fn connect<'a>(&'a self, _url: &'a str) -> LocalBoxFuture<'a, Result<Option<crate::Ws>>> {
            Box::pin(async { Ok(None) })
        }
    }

    /// A server that answers the upgrade with `status` and hangs up.
    async fn rejecting_server(status: &'static str) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut tcp, _) = listener.accept().await.unwrap();
            // consume the request so the reply is not lost to a reset
            let mut buf = [0u8; 4096];
            let _ = tcp.read(&mut buf).await;
            let response = format!("HTTP/1.1 {status}\r\ncontent-length: 0\r\n\r\n");
            tcp.write_all(response.as_bytes()).await.unwrap();
        });
        format!("http://{addr}/ws/services/x")
    }

    /// The error of connecting to a server that answers `status`.
    async fn rejection(status: &'static str, configured: bool) -> String {
        let url = rejecting_server(status).await;
        let method = NotApplicable { configured };
        let Err(err) = connect_with(&[&method], &url).await else {
            panic!("the server rejected the upgrade");
        };
        format!("{err:#}")
    }

    #[tokio::test]
    async fn a_rejection_without_any_credential_says_so() {
        let shown = rejection("401 Unauthorized", false).await;
        assert!(shown.starts_with("no credential configured"), "{shown}");
        assert!(shown.contains("401"), "{shown}");
    }

    #[tokio::test]
    async fn a_rejection_after_no_credential_applied_says_so() {
        let shown = rejection("403 Forbidden", true).await;
        assert!(
            shown.starts_with("none of the configured credentials applied"),
            "{shown}"
        );
        assert!(shown.contains("403"), "{shown}");
    }

    #[tokio::test]
    async fn other_failures_keep_their_own_message() {
        let shown = rejection("500 Internal Server Error", true).await;
        assert!(!shown.contains("credential"), "{shown}");
        assert!(shown.contains("500"), "{shown}");
    }
}
