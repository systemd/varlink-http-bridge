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

pub(crate) async fn connect_ws(url: &str) -> Result<crate::Ws> {
    for (env, feature, enabled) in METHOD_FEATURES {
        if !enabled && std::env::var_os(env).is_some() {
            warn!("{env} is set but this build lacks the '{feature}' feature; ignoring it");
        }
    }

    let methods = methods();
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
    crate::ws_upgrade(request, stream, tcb.is_some()).await
}
