// SPDX-License-Identifier: LGPL-2.1-or-later

//! SSH signature auth, behind the `sshauth` feature. Without it the method
//! cannot be built, and asking for it through `VARLINK_SSH_KEY` is warned
//! about rather than silently ignored.

use crate::client::Auth;

/// Path of the key to sign with, private or public (`.pub`, then the agent
/// signs).
const VARLINK_SSH_KEY_ENV: &str = "VARLINK_SSH_KEY";

/// The method the environment asks for: the key at `VARLINK_SSH_KEY`, else
/// every key in the agent at `SSH_AUTH_SOCK`, else none.
#[cfg(feature = "sshauth")]
pub(crate) fn auth_from_env() -> Option<Auth> {
    use std::path::PathBuf;

    let agent = std::env::var(enabled::SSH_AUTH_SOCK_ENV)
        .ok()
        .map(PathBuf::from);
    match std::env::var(VARLINK_SSH_KEY_ENV).ok().map(PathBuf::from) {
        Some(path) => Some(Auth::SshKey { path, agent }),
        None => agent.map(Auth::SshAgent),
    }
}

/// Without the feature: a set `VARLINK_SSH_KEY` is warned about, an agent
/// socket, ambient on every desktop, is ignored.
#[cfg(not(feature = "sshauth"))]
pub(crate) fn auth_from_env() -> Option<Auth> {
    if std::env::var_os(VARLINK_SSH_KEY_ENV).is_some() {
        log::warn!(
            "{VARLINK_SSH_KEY_ENV} is set but this build lacks the 'sshauth' feature; ignoring it"
        );
    }
    None
}

#[cfg(feature = "sshauth")]
mod enabled;
#[cfg(feature = "sshauth")]
pub(crate) use enabled::SshSignature;
// the transport tests check the 401 detection the retry loop relies on
#[cfg(all(feature = "sshauth", test))]
pub(crate) use enabled::is_http_unauthorized;

#[cfg(not(feature = "sshauth"))]
mod disabled {
    use std::path::PathBuf;

    use anyhow::{Result, bail};
    use futures_util::future::LocalBoxFuture;

    use crate::WebSocket;
    use crate::client_auth::ClientAuth;
    use crate::transport::Transport;

    /// Never constructed: `new` always fails.
    pub(crate) enum SshSignature {}

    impl SshSignature {
        pub(crate) fn new(
            _key_path: Option<PathBuf>,
            _auth_sock: Option<PathBuf>,
            _transport: Transport,
        ) -> Result<Self> {
            bail!("SSH auth was configured but this build lacks the 'sshauth' feature")
        }
    }

    impl ClientAuth for SshSignature {
        fn name(&self) -> &'static str {
            match *self {}
        }

        fn configured(&self) -> bool {
            match *self {}
        }

        fn connect<'a>(&'a self, _url: &'a str) -> LocalBoxFuture<'a, Result<Option<WebSocket>>> {
            match *self {}
        }
    }
}
#[cfg(not(feature = "sshauth"))]
pub(crate) use disabled::SshSignature;
