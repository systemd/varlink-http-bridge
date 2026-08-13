// SPDX-License-Identifier: LGPL-2.1-or-later

use std::fmt;

use anyhow::{Context, Result, bail};
use futures_util::future::LocalBoxFuture;
use log::{debug, warn};
use tokio_tungstenite::tungstenite;
use varlink_http_bridge::{SSHAUTH_MAGIC_PREFIX, TlsChannelBinding};

use crate::client_auth::{ClientAuth, is_http_unauthorized};

/// An SSH key that can be used for authentication.
enum SshKey {
    /// A private key read from a file (`VARLINK_SSH_KEY`).
    PrivateKey {
        path: String,
        key: Box<ssh_key::PrivateKey>,
    },
    /// A public key signed through the ssh-agent.  Used both when only
    /// `SSH_AUTH_SOCK` is set and when `VARLINK_SSH_KEY` points to a
    /// hardware token (sk-*) or a public-key-only file.
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
    tls_channel_binding: Option<&TlsChannelBinding>,
) -> Result<()> {
    // to_string: ends the borrow of `request` before headers_mut() below
    let path_and_query = request
        .uri()
        .path_and_query()
        .map_or(request.uri().path(), |pq| pq.as_str())
        .to_string();

    let (auth_header, nonce) = sign_with_key(key, "GET", &path_and_query, tls_channel_binding)
        .await
        .context(SigningFailed)?;

    request.headers_mut().insert(
        "Authorization",
        auth_header.parse().context("invalid auth header value")?,
    );
    request.headers_mut().insert(
        varlink_http_bridge::SSHAUTH_NONCE_HEADER,
        nonce.parse().context("invalid nonce header value")?,
    );
    Ok(())
}

pub(crate) struct SshSignature;

impl ClientAuth for SshSignature {
    fn name(&self) -> &'static str {
        "SSH signature auth (VARLINK_SSH_KEY or ssh-agent)"
    }

    fn configured(&self) -> bool {
        std::env::var_os("VARLINK_SSH_KEY").is_some()
    }

    fn connect<'a>(&'a self, url: &'a str) -> LocalBoxFuture<'a, Result<Option<crate::Ws>>> {
        Box::pin(connect_with_ssh_retry(url))
    }
}

/// Try connecting with each available SSH key, retrying on 401;
/// `Ok(None)` when no key is available.
///
/// When keys exist but none was ever presented to the server (all
/// failed to sign), one unauthenticated attempt is made and the
/// server decides whether to allow that.
async fn connect_with_ssh_retry(url: &str) -> Result<Option<crate::Ws>> {
    let keys = list_ssh_keys().await?;
    if keys.is_empty() {
        return Ok(None);
    }
    let ws = try_each_key(&keys, async |key| {
        let (stream, mut request, tcb) = crate::connect_transport(url).await?;
        if let Some(key) = key {
            add_auth_headers(&mut request, key, tcb.as_ref()).await?;
        }
        crate::ws_upgrade(request, stream, tcb.is_some()).await
    })
    .await?;
    Ok(Some(ws))
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

/// Return all available SSH keys for authentication.
///
/// - `VARLINK_SSH_KEY` with a normal private key: a single `PrivateKey`.
/// - `VARLINK_SSH_KEY` with a hardware token or public-key-only file: a
///   single `AgentKey` (signed through `SSH_AUTH_SOCK`).
/// - `SSH_AUTH_SOCK` only: every non-RSA key from the agent.
/// - Neither: an empty vec (no auth).
async fn list_ssh_keys() -> Result<Vec<SshKey>> {
    let key_path = std::env::var("VARLINK_SSH_KEY").ok();
    let auth_sock = std::env::var("SSH_AUTH_SOCK").ok();

    if let Some(key_path) = key_path {
        // If a normal (non-hardware-token) private key exists, sign directly.
        if let Some(privkey) = read_private_key(&key_path)?
            && !requires_agent(&privkey.algorithm())
        {
            return Ok(vec![SshKey::PrivateKey {
                path: key_path,
                key: Box::new(privkey),
            }]);
        }

        // Otherwise delegate to the SSH agent: either the key is a
        // hardware token (sk-*) or only the .pub file exists on disk.
        let pubkey = read_public_key(&key_path)?;
        let auth_sock = auth_sock.context(
            "VARLINK_SSH_KEY requires agent-based signing (hardware token \
             or public key only); set SSH_AUTH_SOCK",
        )?;
        let fp = pubkey.fingerprint(ssh_key::HashAlg::Sha256);
        let agent_keys = sshauth::agent::list_keys(&auth_sock)
            .await
            .context("listing ssh-agent keys")?;
        if !agent_keys
            .iter()
            .any(|k| k.fingerprint(ssh_key::HashAlg::Sha256) == fp)
        {
            bail!(
                "VARLINK_SSH_KEY key {fp} not found in ssh-agent; \
                 add it with ssh-add or provide the private key"
            );
        }
        return Ok(vec![SshKey::AgentKey {
            auth_sock,
            key: pubkey,
        }]);
    }

    if let Some(auth_sock) = auth_sock {
        let all_keys = sshauth::agent::list_keys(&auth_sock)
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
                    auth_sock: auth_sock.clone(),
                    key: k,
                });
            }
        }
        return Ok(keys);
    }

    Ok(vec![])
}

/// Sign the request parameters (method, path, nonce, TLS channel binding)
/// with the given key.  Returns the `Authorization` header value carrying
/// the signed sshauth token, and the nonce.
async fn sign_with_key(
    key: &SshKey,
    method: &str,
    path_and_query: &str,
    tls_channel_binding: Option<&TlsChannelBinding>,
) -> Result<(String, String)> {
    let nonce = generate_nonce();

    let mut signer_builder = match key {
        SshKey::PrivateKey { key, .. } => {
            sshauth::TokenSigner::using_private_key(key.as_ref().clone())?
        }
        SshKey::AgentKey { auth_sock, key } => {
            let mut sb = sshauth::TokenSigner::using_authsock(auth_sock)?;
            sb.key(key.clone());
            sb
        }
    };
    debug!("SSH auth: using {key}");

    signer_builder
        .include_fingerprint(true)
        .magic_prefix(SSHAUTH_MAGIC_PREFIX);
    let signer = signer_builder.build()?;

    let mut tb = signer.sign_for();
    tb.action("method", method)
        .action("path", path_and_query)
        .action("nonce", &nonce)
        .action(
            "tls-channel-binding",
            tls_channel_binding.map_or("", TlsChannelBinding::as_str),
        );
    let token: sshauth::token::Token = tb.sign().await?;

    Ok((format!("Bearer {}", token.encode()), nonce))
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
    let pem = match std::fs::read_to_string(privkey_path) {
        Ok(pem) => pem,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => {
            return Err(
                anyhow::Error::new(e).context(format!("reading private key from {privkey_path}"))
            );
        }
    };
    let privkey = ssh_key::PrivateKey::from_openssh(pem.trim())
        .with_context(|| format!("parsing private key from {privkey_path}"))?;
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
