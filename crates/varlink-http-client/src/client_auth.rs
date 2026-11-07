// SPDX-License-Identifier: LGPL-2.1-or-later

//! The contract an auth method implements for the WebSocket upgrade
//! request. Selection, conflict warnings and the unauthenticated fallback
//! live in `Client::connect` and are generic, so a new method (JWT, `DPoP`,
//! RFC 9421) only adds a `ClientAuth` impl and an entry in
//! `Client::from_env`.

use anyhow::Result;
use futures_util::future::LocalBoxFuture;

use crate::WebSocket;

pub(crate) trait ClientAuth {
    /// Short name for logs and error hints.
    fn name(&self) -> &'static str;

    /// Explicit user intent (its credential is set), never ambient state
    /// like `SSH_AUTH_SOCK`: this only drives conflict warnings, which must
    /// not fire on every desktop that happens to run an ssh-agent.
    fn configured(&self) -> bool;

    /// `Ok(None)` when the method turns out not to apply, e.g. the agent
    /// holds no usable key. The method drives the whole connect flow so it
    /// can retry with several candidate credentials (one attempt per SSH
    /// key). Boxed for object safety; non-`Send` because the binary runs a
    /// `current_thread` runtime and rustc cannot prove the SSH retry
    /// future `Send` anyway.
    fn connect<'a>(&'a self, url: &'a str) -> LocalBoxFuture<'a, Result<Option<WebSocket>>>;

    /// Added to the connect error when the server rejected this method.
    fn rejected_hint(&self) -> String {
        format!(
            "{} was rejected by the server; other auth methods were skipped",
            self.name()
        )
    }
}
