// SPDX-License-Identifier: LGPL-2.1-or-later

//! The client configuration: the transport settings and the auth methods
//! with their credentials. [`ClientBuilder`] takes them from the program,
//! [`Client::from_env`] the way `varlinkctl-http` always has, each part
//! reading its own variables. [`Client::connect`] dials with it, the first
//! applicable method winning.

use std::fmt;
use std::path::PathBuf;

use anyhow::Result;
use log::{debug, warn};
use tokio_tungstenite::tungstenite;

use crate::client_auth::ClientAuth;
use crate::transport::{ClientCert, ServerTrust, Transport};
use crate::ws::WsByteStream;

/// A credential and the method that presents it.
#[non_exhaustive]
pub enum Auth {
    /// `Authorization: Bearer <key>`, the key as `varlink-httpd gen-api-key`
    /// printed it.
    ApiKey(String),
    /// A signature with the key file at `path`: a private key directly, or
    /// a `.pub` or hardware key through the agent at `agent`.
    SshKey {
        /// The private key, or its `.pub` when only the agent can sign.
        path: PathBuf,
        /// The ssh-agent socket, needed for a `.pub` or hardware key.
        agent: Option<PathBuf>,
    },
    /// A signature with any key the agent at `path` holds, tried in turn.
    SshAgent(PathBuf),
}

impl fmt::Debug for Auth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // manual so that the key stays out of logs
        match self {
            Self::ApiKey(_) => f.write_str("ApiKey(<redacted>)"),
            Self::SshKey { path, agent } => f
                .debug_struct("SshKey")
                .field("path", path)
                .field("agent", agent)
                .finish(),
            Self::SshAgent(path) => f.debug_tuple("SshAgent").field(path).finish(),
        }
    }
}

/// A configured client, see [`Client::builder`] and [`Client::from_env`].
///
/// Read-only once built so that a connection cannot find its configuration
/// changed under it halfway through a retry loop.
pub struct Client {
    pub(crate) transport: Transport,
    /// In precedence order; the first one that applies is used.
    pub(crate) methods: Vec<Box<dyn ClientAuth>>,
}

impl Client {
    /// Returns a builder with nothing set.
    #[must_use]
    pub fn builder() -> ClientBuilder {
        ClientBuilder::default()
    }

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
        let mut auths = Vec::new();
        auths.extend(crate::api_key_client::auth_from_env()?);
        auths.extend(crate::sshauth_client::auth_from_env());
        ClientBuilder {
            transport: Transport::from_env(),
            auths,
        }
        .build()
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

/// Builds a [`Client`] from values the program holds, see [`Client::builder`].
#[derive(Debug, Default)]
pub struct ClientBuilder {
    /// The trust and client certificate settings.
    transport: Transport,
    /// In the order given, which is the precedence.
    auths: Vec<Auth>,
}

impl ClientBuilder {
    /// How the server is trusted; the default is the system CAs.
    #[must_use]
    pub fn trust(mut self, trust: ServerTrust) -> Self {
        self.transport.server_trust = trust;
        self
    }

    /// Trust a self-signed server on first contact and remember its key in
    /// this file; without it, only [`trust`](Self::trust) decides.
    #[must_use]
    pub fn known_hosts(mut self, path: impl Into<PathBuf>) -> Self {
        self.transport.known_hosts = Some(path.into());
        self
    }

    /// The certificate and key to present, for servers that require mTLS.
    #[must_use]
    pub fn client_cert(mut self, cert: impl Into<PathBuf>, key: impl Into<PathBuf>) -> Self {
        self.transport.client_cert = Some(ClientCert {
            cert: cert.into(),
            key: key.into(),
        });
        self
    }

    /// A credential to offer; the first one given that applies is used.
    #[must_use]
    pub fn auth(mut self, auth: Auth) -> Self {
        self.auths.push(auth);
        self
    }

    /// The client with these settings, ready to connect.
    ///
    /// # Errors
    /// Returns an error if a credential asks for an auth method this build
    /// lacks, or cannot be used as given.
    pub fn build(self) -> Result<Client> {
        let mut methods: Vec<Box<dyn ClientAuth>> = Vec::with_capacity(self.auths.len());
        for auth in self.auths {
            let transport = self.transport.clone();
            methods.push(match auth {
                Auth::ApiKey(key) => {
                    Box::new(crate::api_key_client::ApiKeyBearer::new(key, transport))
                }
                Auth::SshKey { path, agent } => Box::new(crate::sshauth_client::SshSignature::new(
                    Some(path),
                    agent,
                    transport,
                )?),
                Auth::SshAgent(path) => Box::new(crate::sshauth_client::SshSignature::new(
                    None,
                    Some(path),
                    transport,
                )?),
            });
        }
        Ok(Client {
            transport: self.transport,
            methods,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builder_keeps_the_settings_and_the_auth_order() {
        let client = Client::builder()
            .trust(ServerTrust::Pin("sha256//AAAA=".to_string()))
            .known_hosts("/tmp/kh")
            .client_cert("/tmp/cert.pem", "/tmp/key.pem")
            .auth(Auth::ApiKey("vhb_x".to_string()))
            .build()
            .unwrap();
        assert_eq!(
            client.transport.server_trust,
            ServerTrust::Pin("sha256//AAAA=".to_string())
        );
        assert_eq!(
            client.transport.known_hosts.as_deref(),
            Some("/tmp/kh".as_ref())
        );
        assert_eq!(
            client.transport.client_cert.as_ref().map(|c| &c.key),
            Some(&PathBuf::from("/tmp/key.pem"))
        );
        let names: Vec<&str> = client.methods.iter().map(|m| m.name()).collect();
        assert_eq!(names.len(), 1);
        assert!(names[0].starts_with("API key auth"), "{names:?}");
    }

    #[test]
    fn an_empty_builder_is_strict_pki_without_credentials() {
        let client = Client::builder().build().unwrap();
        assert_eq!(client.transport.server_trust, ServerTrust::SystemCas);
        assert_eq!(client.transport.known_hosts, None);
        assert!(client.transport.client_cert.is_none());
        assert!(client.methods.is_empty());
    }

    #[cfg(feature = "sshauth")]
    #[test]
    fn ssh_credentials_come_after_the_api_key_when_given_so() {
        let client = Client::builder()
            .auth(Auth::ApiKey("vhb_x".to_string()))
            .auth(Auth::SshAgent("/tmp/agent.sock".into()))
            .build()
            .unwrap();
        let names: Vec<&str> = client.methods.iter().map(|m| m.name()).collect();
        assert_eq!(names.len(), 2);
        assert!(names[1].starts_with("SSH signature auth"), "{names:?}");
    }

    #[cfg(not(feature = "sshauth"))]
    #[test]
    fn ssh_credentials_are_an_error_without_the_feature() {
        let err = Client::builder()
            .auth(Auth::SshAgent("/tmp/agent.sock".into()))
            .build()
            .unwrap_err();
        assert!(format!("{err:#}").contains("sshauth"), "{err:#}");
    }

    #[test]
    fn debug_output_keeps_the_secrets() {
        let auth = Auth::ApiKey("vhb_secret".to_string());
        assert_eq!(format!("{auth:?}"), "ApiKey(<redacted>)");

        let client = Client::builder().auth(auth).build().unwrap();
        let shown = format!("{client:?}");
        assert!(!shown.contains("vhb_secret"), "{shown}");
        assert!(shown.contains("API key auth"), "{shown}");
    }
}
