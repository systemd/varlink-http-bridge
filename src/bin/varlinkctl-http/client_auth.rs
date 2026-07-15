// SPDX-License-Identifier: LGPL-2.1-or-later

//! Auth method selection for the WebSocket upgrade request: the first method
//! in `methods()` that adds its credentials wins. Selection, conflict
//! warnings, reduced-build diagnostics and rejection hints are generic, so a
//! new method (JWT, `DPoP`, RFC 9421) only adds a `ClientAuth` impl and an
//! entry.

use anyhow::Result;
use futures_util::future::BoxFuture;
use log::{debug, warn};
use tokio_tungstenite::tungstenite;

pub(crate) trait ClientAuth {
    /// Short name for logs and error hints.
    fn name(&self) -> &'static str;

    /// Explicit user intent (its env var is set), never ambient state like
    /// `SSH_AUTH_SOCK`: this only drives conflict warnings, which must not
    /// fire on every desktop that happens to run an ssh-agent.
    fn configured(&self) -> bool;

    /// Add this method's credentials to the request; `Ok(false)` when not
    /// applicable (e.g. its env var is unset). Boxed so the trait stays
    /// object-safe.
    fn add_credentials<'a>(
        &'a self,
        request: &'a mut tungstenite::http::Request<()>,
        tls_channel_binding: Option<&'a str>,
    ) -> BoxFuture<'a, Result<bool>>;

    /// Appended to the connect error when the server rejected the request.
    fn rejected_hint(&self) -> String {
        format!(
            " ({} was rejected by the server; other auth methods were skipped)",
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

/// Returns the chosen method so the connect error can carry its rejection hint.
pub(crate) async fn select_auth_method(
    request: &mut tungstenite::http::Request<()>,
    tls_channel_binding: Option<&str>,
) -> Result<Option<&'static dyn ClientAuth>> {
    for (env, feature, enabled) in METHOD_FEATURES {
        if !enabled && std::env::var_os(env).is_some() {
            warn!("{env} is set but this build lacks the '{feature}' feature; ignoring it");
        }
    }

    let methods = methods();
    for (i, method) in methods.iter().enumerate() {
        if !method.add_credentials(request, tls_channel_binding).await? {
            continue;
        }
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
        return Ok(Some(*method));
    }
    Ok(None)
}
