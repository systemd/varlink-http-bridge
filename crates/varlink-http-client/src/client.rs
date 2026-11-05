// SPDX-License-Identifier: LGPL-2.1-or-later

//! The client configuration: the transport settings and the auth methods
//! with their credentials. [`Client::from_env`] assembles it the way
//! `varlinkctl-http` always has, each part reading its own variables, and
//! [`Client::connect`] dials with it, the first applicable method winning.

use std::fmt;

use anyhow::Result;
use log::{debug, warn};
use tokio_tungstenite::tungstenite;

use crate::client_auth::ClientAuth;
use crate::transport::Transport;
use crate::ws::WsByteStream;

/// A configured client, see [`Client::from_env`].
///
/// Read-only once built so that a connection cannot find its configuration
/// changed under it halfway through a retry loop.
pub struct Client {
    pub(crate) transport: Transport,
    /// In precedence order; the first one that applies is used.
    pub(crate) methods: Vec<Box<dyn ClientAuth>>,
}

impl Client {
    /// The configuration `varlinkctl-http` uses: the trust files from the
    /// first existing of `$XDG_CONFIG_HOME/varlinkctl-http`,
    /// `~/.config/varlinkctl-http` and `/etc/varlinkctl-http`, the API key
    /// from `VARLINK_API_KEY` or the `api-key` file there, and the SSH key
    /// from `VARLINK_SSH_KEY` or the agent at `SSH_AUTH_SOCK`. See the
    /// bridge README.
    ///
    /// # Errors
    /// Returns an error if the `api-key` file exists but cannot be used,
    /// e.g. because it is readable by others.
    pub fn from_env() -> Result<Self> {
        let transport = Transport::from_env();
        let mut methods: Vec<Box<dyn ClientAuth>> = Vec::new();
        if let Some(api_key) = crate::api_key_client::ApiKeyBearer::from_env(transport.clone())? {
            methods.push(Box::new(api_key));
        }
        if let Some(ssh) = crate::sshauth_client::SshSignature::from_env(transport.clone()) {
            methods.push(Box::new(ssh));
        }

        Ok(Self { transport, methods })
    }

    /// Dial a varlink-httpd and return the raw varlink as a byte stream.
    ///
    /// `url` is the full endpoint, `https://host:1031/ws/services/io.systemd.Hostname`
    /// (`/ws/sockets/` is the older spelling); `http` and `vsock://cid:port`
    /// work the same way. The first applicable auth method wins: the API key
    /// if set, else the SSH key or every key in the agent, else no credential
    /// and the server decides. The ssh-agent path may wait for a hardware key
    /// to be touched. The future is not `Send`.
    ///
    /// # Errors
    /// Returns an error if the transport cannot be set up, the server
    /// rejects the credential, or the WebSocket handshake fails.
    pub async fn connect(&self, url: &str) -> Result<crate::VarlinkStream> {
        for (i, method) in self.methods.iter().enumerate() {
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
            for other in &self.methods[i + 1..] {
                if other.configured() {
                    warn!(
                        "{} takes precedence; ignoring {}",
                        method.name(),
                        other.name()
                    );
                }
            }
            return Ok(WsByteStream::new(ws));
        }

        // No method applicable: connect unauthenticated, the server decides.
        let (stream, request, tcb) = self.transport.connect(url).await?;
        let ws = crate::ws_upgrade(request, stream, tcb.is_some()).await?;
        Ok(WsByteStream::new(ws))
    }
}

impl fmt::Debug for Client {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // the methods hold secrets, so only their names are shown
        let methods: Vec<&str> = self.methods.iter().map(|m| m.name()).collect();
        f.debug_struct("Client")
            .field("transport", &self.transport)
            .field("methods", &methods)
            .finish()
    }
}

/// 403 counts too: the credential was understood and refused.
fn is_http_rejection(err: &anyhow::Error) -> bool {
    err.downcast_ref::<tungstenite::Error>().is_some_and(
        |e| matches!(e, tungstenite::Error::Http(r) if matches!(r.status().as_u16(), 401 | 403)),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::ServerTrust;

    #[test]
    fn debug_output_names_the_methods_and_keeps_the_secrets() {
        let transport = Transport {
            server_trust: ServerTrust::SystemCas,
            known_hosts: None,
            client_cert: None,
        };
        let client = Client {
            methods: vec![Box::new(crate::api_key_client::ApiKeyBearer {
                key: "vhb_secret".to_string(),
                transport: transport.clone(),
            })],
            transport,
        };
        let shown = format!("{client:?}");
        assert!(!shown.contains("vhb_secret"), "{shown}");
        assert!(shown.contains("API key auth"), "{shown}");
    }
}
