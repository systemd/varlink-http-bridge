// SPDX-License-Identifier: LGPL-2.1-or-later

use std::fmt;
use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use futures_util::future::LocalBoxFuture;
use log::{debug, warn};
use tokio_tungstenite::tungstenite;
use varlink_http_core::TlsChannelBinding;
use varlink_http_core::sshauth_token::{
    SSHAUTH_NONCE_HEADER, SignedParts, signer_from_agent, signer_from_private_key,
};
use zeroize::Zeroizing;

use super::VARLINK_SSH_KEY_ENV;
use crate::WebSocket;
use crate::client_auth::ClientAuth;
use crate::transport::Transport;

/// The ssh-agent socket, the same variable ssh itself uses.
pub(super) const SSH_AUTH_SOCK_ENV: &str = "SSH_AUTH_SOCK";

/// An SSH key that can be used for authentication.
enum SshKey {
    /// A private key read from a file (`VARLINK_SSH_KEY`).
    PrivateKey {
        path: String,
        key: Box<ssh_key::PrivateKey>,
    },
    /// A public key signed through the ssh-agent.  Used both when only
    /// `SSH_AUTH_SOCK` is set and when `VARLINK_SSH_KEY` points to a
    /// hardware token key (sk-*), an encrypted private key or a
    /// public-key-only file.
    AgentKey {
        auth_sock: String,
        key: ssh_key::PublicKey,
    },
}

impl fmt::Display for SshKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SshKey::PrivateKey { path, key } => {
                write!(
                    f,
                    "{} {} ({}) from {}",
                    key.algorithm(),
                    key.fingerprint(ssh_key::HashAlg::Sha256),
                    key.comment(),
                    path,
                )
            }
            SshKey::AgentKey { auth_sock, key } => {
                write!(
                    f,
                    "{} {} ({}) from agent {}",
                    key.algorithm(),
                    key.fingerprint(ssh_key::HashAlg::Sha256),
                    key.comment(),
                    auth_sock,
                )
            }
        }
    }
}

/// Add SSH auth headers to the request, signing with the given key.
///
/// A signing failure is returned as a [`SigningFailed`] error so the retry
/// loop can skip the key and move on to the next one.
async fn add_auth_headers(
    request: &mut tungstenite::http::Request<()>,
    key: &SshKey,
    tls_channel_binding: &TlsChannelBinding,
) -> Result<()> {
    // to_string: ends the borrow of `request` before headers_mut() below
    let path_and_query = request
        .uri()
        .path_and_query()
        .map_or(request.uri().path(), |pq| pq.as_str())
        .to_string();
    let nonce = generate_nonce();

    let signer = signer_for_key(key).context(SigningFailed)?;
    let signed_parts = SignedParts::new(
        "GET",
        &path_and_query,
        &nonce,
        request.headers(),
        tls_channel_binding,
    );
    let token = signed_parts.sign(&signer).await.context(SigningFailed)?;

    request.headers_mut().insert(
        "Authorization",
        format!("Bearer {token}")
            .parse()
            .context("invalid auth header value")?,
    );
    request.headers_mut().insert(
        SSHAUTH_NONCE_HEADER,
        nonce.parse().context("invalid nonce header value")?,
    );
    Ok(())
}

/// Signs with the key file at `key_path`, or with any key the agent at
/// `auth_sock` holds. Only the path is explicit user intent; an agent socket
/// is ambient state that every desktop has.
pub(crate) struct SshSignature {
    key_path: Option<String>,
    auth_sock: Option<String>,
    transport: Transport,
}

impl SshSignature {
    /// Signs with the key file at `key_path`, or with every key the agent at
    /// `auth_sock` holds.
    ///
    /// # Errors
    /// Returns an error if a path is not valid UTF-8.
    pub(crate) fn new(
        key_path: Option<PathBuf>,
        auth_sock: Option<PathBuf>,
        transport: Transport,
    ) -> Result<Self> {
        // the key readers and the agent protocol take strings
        let utf8 = |path: PathBuf| {
            path.into_os_string()
                .into_string()
                .map_err(|p| anyhow::anyhow!("{} is not valid UTF-8", p.to_string_lossy()))
        };
        Ok(Self {
            key_path: key_path.map(utf8).transpose()?,
            auth_sock: auth_sock.map(utf8).transpose()?,
            transport,
        })
    }

    /// Try connecting with each available SSH key, retrying on 401;
    /// `Ok(None)` when no key is available.
    ///
    /// When keys exist but none was ever presented to the server (all
    /// failed to sign), one unauthenticated attempt is made and the
    /// server decides whether to allow that.
    async fn connect_with_retry(&self, url: &str) -> Result<Option<WebSocket>> {
        if !crate::url_is_tls(url) {
            if self.configured() {
                bail!("{VARLINK_SSH_KEY_ENV} is set but {url} is not TLS, SSH auth needs TLS");
            }
            debug!("plain transport, not offering SSH auth");
            return Ok(None);
        }

        let keys = list_ssh_keys(self.key_path.as_deref(), self.auth_sock.as_deref()).await?;
        if keys.is_empty() {
            return Ok(None);
        }
        let ws = try_each_key(&keys, async |key| {
            let (stream, mut request, tcb) = self.transport.connect(url).await?;
            if let Some(key) = key {
                let tcb = tcb
                    .as_ref()
                    .context("TLS connection without channel binding")?;
                add_auth_headers(&mut request, key, tcb).await?;
            }
            crate::ws_upgrade(request, stream, true).await
        })
        .await?;
        Ok(Some(ws))
    }
}

impl ClientAuth for SshSignature {
    fn name(&self) -> &'static str {
        "SSH signature auth (VARLINK_SSH_KEY or ssh-agent)"
    }

    fn configured(&self) -> bool {
        self.key_path.is_some()
    }

    fn connect<'a>(&'a self, url: &'a str) -> LocalBoxFuture<'a, Result<Option<WebSocket>>> {
        Box::pin(self.connect_with_retry(url))
    }
}

/// Generic retry loop: try `connect` for each key.
async fn try_each_key<K: fmt::Display, T>(
    keys: &[K],
    mut connect: impl AsyncFnMut(Option<&K>) -> Result<T>,
) -> Result<T> {
    let mut last_rejection = None;
    let mut rejected = 0;
    for key in keys {
        match connect(Some(key)).await {
            Ok(val) => return Ok(val),
            Err(e) if is_http_unauthorized(&e) => {
                debug!("SSH key {key} rejected by server (HTTP 401), trying next key");
                last_rejection = Some(e);
                rejected += 1;
            }
            Err(e) if is_signing_failure(&e) => {
                warn!("skipping SSH key {key}: {e:#}");
            }
            Err(e) => return Err(e),
        }
    }
    match last_rejection {
        // Rejected keys are logged only at debug level, so state the count to
        // keep a multi-key failure from reading as a single-key one.
        Some(e) if rejected > 1 => Err(e.context(format!(
            "{rejected} SSH keys were rejected by the server (HTTP 401)"
        ))),
        // At least one key was presented and rejected: the server requires
        // auth, so an unauthenticated attempt is pointless.
        Some(e) => Err(e),
        // No key was ever presented (none found, or all failed to sign):
        // try unauthenticated and let the server decide.
        None => connect(None).await,
    }
}

/// Signing can fail for reasons that are not the key's fault (e.g. a
/// hardware token that requires user presence and times out).
#[derive(Debug, Clone, Copy)]
struct SigningFailed;

impl fmt::Display for SigningFailed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SSH token signing failed")
    }
}

fn is_signing_failure(err: &anyhow::Error) -> bool {
    err.is::<SigningFailed>()
}

pub(crate) fn is_http_unauthorized(err: &anyhow::Error) -> bool {
    err.downcast_ref::<tungstenite::Error>()
        .is_some_and(|e| matches!(e, tungstenite::Error::Http(r) if r.status() == 401))
}

/// Return all available SSH keys for authentication.
///
/// - `key_path` with a normal private key: a single `PrivateKey`.
/// - `key_path` with a hardware token key, an encrypted private key or only
///   a public key: a single `AgentKey` (signed through the agent at
///   `auth_sock`).
/// - `auth_sock` only: every non-RSA key from the agent.
/// - Neither: an empty vec (no auth).
async fn list_ssh_keys(key_path: Option<&str>, auth_sock: Option<&str>) -> Result<Vec<SshKey>> {
    if let Some(key_path) = key_path {
        let pubkey = match read_private_key(key_path)? {
            // An unencrypted, non-hardware-token private key signs directly.
            Some(privkey) if !privkey.is_encrypted() && !requires_agent(&privkey.algorithm()) => {
                return Ok(vec![SshKey::PrivateKey {
                    path: key_path.to_owned(),
                    key: Box::new(privkey),
                }]);
            }
            // A hardware token key (sk-*) and an encrypted key can only sign
            // through the SSH agent. Their files store the public key
            // unencrypted, so no .pub file is needed to find the key there.
            Some(privkey) => privkey.public_key().clone(),
            // Only the .pub file exists on disk.
            None => read_public_key(key_path)?,
        };
        let auth_sock = auth_sock.with_context(|| {
            format!(
                "{VARLINK_SSH_KEY_ENV} requires agent-based signing (hardware token key, \
                 encrypted private key or public key only); set {SSH_AUTH_SOCK_ENV}"
            )
        })?;
        let fp = pubkey.fingerprint(ssh_key::HashAlg::Sha256);
        let agent_keys = sshauth::agent::list_keys(auth_sock)
            .await
            .context("listing ssh-agent keys")?;
        if !agent_keys
            .iter()
            .any(|k| k.fingerprint(ssh_key::HashAlg::Sha256) == fp)
        {
            bail!(
                "{VARLINK_SSH_KEY_ENV} key {fp} not found in ssh-agent; \
                 add it with ssh-add or provide the private key"
            );
        }
        return Ok(vec![SshKey::AgentKey {
            auth_sock: auth_sock.to_owned(),
            key: pubkey,
        }]);
    }

    if let Some(auth_sock) = auth_sock {
        let all_keys = sshauth::agent::list_keys(auth_sock)
            .await
            .context("listing ssh-agent keys")?;

        let mut keys = Vec::new();
        for k in all_keys {
            if matches!(k.algorithm(), ssh_key::Algorithm::Rsa { .. }) {
                warn!(
                    "skipping RSA key {} ({}): RSA signing is not supported, use Ed25519 or ECDSA",
                    k.fingerprint(ssh_key::HashAlg::Sha256),
                    k.comment(),
                );
            } else {
                keys.push(SshKey::AgentKey {
                    auth_sock: auth_sock.to_owned(),
                    key: k,
                });
            }
        }
        return Ok(keys);
    }

    Ok(vec![])
}

/// A token signer for `key`, either from the private key on disk or via
/// the ssh-agent.
fn signer_for_key(key: &SshKey) -> Result<sshauth::TokenSigner> {
    debug!("SSH auth: using {key}");
    match key {
        SshKey::PrivateKey { key, .. } => signer_from_private_key(key.as_ref().clone()),
        SshKey::AgentKey { auth_sock, key } => signer_from_agent(auth_sock, key.clone()),
    }
}

fn generate_nonce() -> String {
    let mut buf = [0u8; 16];
    openssl::rand::rand_bytes(&mut buf).expect("openssl PRNG failed");
    openssl::base64::encode_block(&buf)
}

/// Read a private key from `key_path`.
///
/// If the path ends in `.pub`, the corresponding private key path (without the
/// extension) is tried instead.  Returns `Ok(None)` when the private key file
/// does not exist.
#[allow(clippy::case_sensitive_file_extension_comparisons)]
fn read_private_key(key_path: &str) -> Result<Option<ssh_key::PrivateKey>> {
    let privkey_path = key_path.strip_suffix(".pub").unwrap_or(key_path);
    let data = match std::fs::read_to_string(privkey_path) {
        Ok(data) => Zeroizing::new(data),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => {
            return Err(
                anyhow::Error::new(e).context(format!("reading private key from {privkey_path}"))
            );
        }
    };
    let privkey = ssh_key_import::parse_private_key(&data)
        .with_context(|| format!("loading private key from {privkey_path}"))?;
    ensure_supported_algorithm(&privkey.algorithm(), key_path)?;
    Ok(Some(privkey))
}

/// Read a public key from `key_path`.
///
/// If the path does not end in `.pub`, the `.pub` extension is appended.
#[allow(clippy::case_sensitive_file_extension_comparisons)]
fn read_public_key(key_path: &str) -> Result<ssh_key::PublicKey> {
    let pubkey_path = if key_path.ends_with(".pub") {
        key_path.to_string()
    } else {
        format!("{key_path}.pub")
    };
    let data = std::fs::read_to_string(&pubkey_path)
        .with_context(|| format!("reading public key from {pubkey_path}"))?;
    let pubkey = ssh_key::PublicKey::from_openssh(data.trim())
        .with_context(|| format!("parsing public key from {pubkey_path}"))?;
    ensure_supported_algorithm(&pubkey.algorithm(), key_path)?;
    Ok(pubkey)
}

fn ensure_supported_algorithm(algo: &ssh_key::Algorithm, source: &str) -> Result<()> {
    if matches!(algo, ssh_key::Algorithm::Rsa { .. }) {
        bail!("{source} is an RSA key, which is not supported; use Ed25519 or ECDSA");
    }
    Ok(())
}

/// Hardware-token key algorithms (FIDO2 sk-*) that cannot sign directly
/// and must be delegated to the SSH agent.
fn requires_agent(algo: &ssh_key::Algorithm) -> bool {
    matches!(
        algo,
        ssh_key::Algorithm::SkEcdsaSha2NistP256 | ssh_key::Algorithm::SkEd25519
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_http_error(status: u16) -> anyhow::Error {
        let response = tungstenite::http::Response::builder()
            .status(status)
            .body(None)
            .unwrap();
        tungstenite::Error::Http(Box::new(response)).into()
    }

    fn make_signing_error() -> anyhow::Error {
        anyhow::anyhow!("agent refused operation").context(SigningFailed)
    }

    const ENCRYPTED_OPENSSH_PRIVATE_KEY: &str = "-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABAs4U5OTx
pJQz9n5CC9hueiAAAAGAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAAIJzpIVYSYi1HTRJk
M5XaGJkYC6+fw2SICxlSJQC5WK+3AAAAkNe45MiHjROFtso/EbHFZ2jhoBMGe3kpqZDfNC
3d8bK5jIRIHS9pDSTJOUN//0B9cWxSy+OHUX7r7bCfWUtDQkYMRZ/1ziXhHN4N/FP1GItL
77ncfjF/caYGSnvbJerUH2HtUOHaImhtKleaqkEBo6/eZCBxiaOuhYCwWb1sNUgGlw9KlJ
2GrS0ySFwa+i6eQA==
-----END OPENSSH PRIVATE KEY-----
";

    #[tokio::test]
    async fn test_encrypted_key_uses_agent() {
        // An encrypted private key can only sign through the SSH agent, and
        // its public key comes from the private key file, so no .pub file is
        // needed. Without SSH_AUTH_SOCK, list_ssh_keys() must fail with an
        // error that names SSH_AUTH_SOCK. With a socket that doesn't exist,
        // it must fail listing the agent keys, which shows that it got the
        // public key without a .pub file.
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("key");
        std::fs::write(&key_path, ENCRYPTED_OPENSSH_PRIVATE_KEY).unwrap();
        let key_path = key_path.to_str().unwrap();
        let sock = dir.path().join("agent.sock");

        for (auth_sock, expected) in [
            (None, SSH_AUTH_SOCK_ENV),
            (sock.to_str(), "listing ssh-agent keys"),
        ] {
            let err = list_ssh_keys(Some(key_path), auth_sock)
                .await
                .err()
                .expect("list_ssh_keys() returned keys for an encrypted key without an agent");
            let err = format!("{err:#}");
            assert!(err.contains(expected), "{err}");
        }
    }

    #[tokio::test]
    async fn test_pkcs8_key_signs_without_agent() {
        // vmspawn writes its private keys as PKCS#8. Such a key must load
        // from VARLINK_SSH_KEY and sign directly, without an agent and
        // without a .pub file.
        const PKCS8_PRIVATE_KEY: &str = "-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIJp/ivWBrtAi7u6Z72WTMWrpu1zVlz4Ls6+mJkD8mu2c
-----END PRIVATE KEY-----
";
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("key");
        std::fs::write(&key_path, PKCS8_PRIVATE_KEY).unwrap();

        let keys = list_ssh_keys(key_path.to_str(), None).await.unwrap();
        assert!(
            matches!(keys.as_slice(), [SshKey::PrivateKey { .. }]),
            "the PKCS#8 key did not load as a private key"
        );
    }

    #[test]
    fn test_is_http_unauthorized_detects_401() {
        assert!(is_http_unauthorized(&make_http_error(401)));
    }

    #[test]
    fn test_is_http_unauthorized_ignores_other_status() {
        assert!(!is_http_unauthorized(&make_http_error(403)));
        assert!(!is_http_unauthorized(&make_http_error(500)));
    }

    #[test]
    fn test_is_http_unauthorized_ignores_non_http_errors() {
        assert!(!is_http_unauthorized(&anyhow::anyhow!(
            "connection refused"
        )));
    }

    #[tokio::test]
    async fn test_retry_no_keys_connects_without_auth() {
        let keys: Vec<String> = vec![];
        let result = try_each_key(&keys, async |key| {
            assert!(key.is_none());
            Ok("connected")
        })
        .await;
        assert_eq!(result.unwrap(), "connected");
    }

    #[tokio::test]
    async fn test_retry_first_key_succeeds() {
        let keys = vec!["key-a".to_string(), "key-b".to_string()];
        let attempts = std::cell::Cell::new(0);
        let result = try_each_key(&keys, async |_key| {
            attempts.set(attempts.get() + 1);
            Ok("connected")
        })
        .await;
        assert_eq!(result.unwrap(), "connected");
        assert_eq!(attempts.get(), 1);
    }

    #[tokio::test]
    async fn test_retry_skips_401_tries_next_key() {
        let keys = vec![
            "key-a".to_string(),
            "key-b".to_string(),
            "key-c".to_string(),
        ];
        let attempts = std::cell::Cell::new(0);
        let result = try_each_key(&keys, async |key| {
            let n = attempts.get();
            attempts.set(n + 1);
            if n < 2 {
                Err(make_http_error(401))
            } else {
                assert_eq!(key.unwrap(), "key-c");
                Ok("connected")
            }
        })
        .await;
        assert_eq!(result.unwrap(), "connected");
        assert_eq!(attempts.get(), 3);
    }

    #[tokio::test]
    async fn test_retry_all_keys_rejected() {
        let keys = vec!["key-a".to_string(), "key-b".to_string()];
        let result: Result<()> = try_each_key(&keys, async |_key| Err(make_http_error(401))).await;
        let err = result.unwrap_err();
        // Still downcasts to the underlying 401 after context is added.
        assert!(is_http_unauthorized(&err));
        // With multiple keys rejected the message must not imply a single key.
        assert!(
            format!("{err:#}").contains("2 SSH keys were rejected"),
            "{err:#}"
        );
    }

    #[tokio::test]
    async fn test_retry_reject_count_excludes_signing_failures() {
        // key-a fails to sign (skipped), key-b and key-c are rejected: the
        // count must be 2 (rejections only), not 3 (total keys).
        let keys = vec![
            "key-a".to_string(),
            "key-b".to_string(),
            "key-c".to_string(),
        ];
        let attempts = std::cell::Cell::new(0);
        let result: Result<()> = try_each_key(&keys, async |_key| {
            let n = attempts.get();
            attempts.set(n + 1);
            if n == 0 {
                Err(make_signing_error())
            } else {
                Err(make_http_error(401))
            }
        })
        .await;
        let err = result.unwrap_err();
        assert!(is_http_unauthorized(&err));
        assert!(
            format!("{err:#}").contains("2 SSH keys were rejected"),
            "{err:#}"
        );
    }

    #[tokio::test]
    async fn test_retry_single_key_rejected_keeps_bare_error() {
        let keys = vec!["key-a".to_string()];
        let result: Result<()> = try_each_key(&keys, async |_key| Err(make_http_error(401))).await;
        let err = result.unwrap_err();
        assert!(is_http_unauthorized(&err));
        // Only one key: no misleading "all N keys" context added.
        assert!(
            !format!("{err:#}").contains("SSH keys were rejected"),
            "{err:#}"
        );
    }

    #[tokio::test]
    async fn test_retry_signing_failure_skips_key() {
        let keys = vec!["key-a".to_string(), "key-b".to_string()];
        let attempts = std::cell::Cell::new(0);
        let result = try_each_key(&keys, async |key| {
            let n = attempts.get();
            attempts.set(n + 1);
            if n == 0 {
                Err(make_signing_error())
            } else {
                assert_eq!(key.unwrap(), "key-b");
                Ok("connected")
            }
        })
        .await;
        assert_eq!(result.unwrap(), "connected");
        assert_eq!(attempts.get(), 2);
    }

    #[tokio::test]
    async fn test_retry_all_signing_failures_falls_back_unauthenticated() {
        let keys = vec!["key-a".to_string(), "key-b".to_string()];
        let result = try_each_key(&keys, async |key| match key {
            Some(_) => Err(make_signing_error()),
            None => Ok("anonymous"),
        })
        .await;
        assert_eq!(result.unwrap(), "anonymous");
    }

    #[tokio::test]
    async fn test_retry_no_unauthenticated_fallback_after_rejection() {
        // key-a fails to sign, key-b is rejected by the server: the server
        // requires auth, so connect must not be called with None.
        let keys = vec!["key-a".to_string(), "key-b".to_string()];
        let attempts = std::cell::Cell::new(0);
        let result: Result<()> = try_each_key(&keys, async |key| {
            assert!(key.is_some());
            let n = attempts.get();
            attempts.set(n + 1);
            if n == 0 {
                Err(make_signing_error())
            } else {
                Err(make_http_error(401))
            }
        })
        .await;
        assert!(is_http_unauthorized(&result.unwrap_err()));
        assert_eq!(attempts.get(), 2);
    }

    #[tokio::test]
    async fn test_retry_non_auth_error_stops_immediately() {
        let keys = vec!["key-a".to_string(), "key-b".to_string()];
        let attempts = std::cell::Cell::new(0);
        let result: Result<()> = try_each_key(&keys, async |_key| {
            attempts.set(attempts.get() + 1);
            Err(anyhow::anyhow!("connection refused"))
        })
        .await;
        assert!(result.is_err());
        assert_eq!(attempts.get(), 1);
    }
}
