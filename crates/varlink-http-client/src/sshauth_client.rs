// SPDX-License-Identifier: LGPL-2.1-or-later

//! SSH signature auth, behind the `sshauth` feature. Without it the method
//! does not exist, and asking for it through `VARLINK_SSH_KEY` is warned
//! about rather than silently ignored.

/// Path of the key to sign with, private or public (`.pub`, then the agent
/// signs). Checked by both halves, so it lives here.
const VARLINK_SSH_KEY_ENV: &str = "VARLINK_SSH_KEY";

#[cfg(feature = "sshauth")]
mod enabled;
#[cfg(feature = "sshauth")]
pub(crate) use enabled::SshSignature;
// the transport tests check the 401 detection the retry loop relies on
#[cfg(all(feature = "sshauth", test))]
pub(crate) use enabled::is_http_unauthorized;

#[cfg(not(feature = "sshauth"))]
mod disabled {
    use anyhow::Result;
    use futures_util::future::LocalBoxFuture;
    use log::warn;

    use super::VARLINK_SSH_KEY_ENV;
    use crate::WebSocket;
    use crate::client_auth::ClientAuth;
    use crate::transport::Transport;

    /// Never constructed: `from_env` only warns if something asks for it.
    pub(crate) enum SshSignature {}

    impl SshSignature {
        pub(crate) fn from_env(_transport: Transport) -> Option<Self> {
            if std::env::var_os(VARLINK_SSH_KEY_ENV).is_some() {
                warn!(
                    "{VARLINK_SSH_KEY_ENV} is set but this build lacks the 'sshauth' feature; ignoring it"
                );
            }
            None
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
