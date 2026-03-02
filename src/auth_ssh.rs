// SPDX-License-Identifier: LGPL-2.1-or-later

use anyhow::{Context, bail};
use log::{info, warn};
use ssh_key::{HashAlg, PublicKey};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Instant, SystemTime};

use crate::Authenticator;
use varlink_httpd::{SSHAUTH_MAGIC_PREFIX, SSHAUTH_NONCE_HEADER};

struct KeyCache {
    keys: HashMap<String, PublicKey>,
    mtime: SystemTime,
}

/// Tracks recently seen nonces to prevent replay attacks.
///
/// By using sshauth we already get a signed timestamp that is checked
/// by the underlying sshauth checks. It can only diverge by
/// `max_skew` seconds or will be rejected. On top of this we add a
/// nonce to make each request resilient against replay attacks. This
/// means we need to keep track of the used nonces. But because there
/// is already a time limit we only need to remember them for
/// `max_skew` seconds: after that the timestamp check in sshauth will
/// reject the token anyway. To be on the safe side we remember for
/// `2*max_skew` seconds. And because this all fuzzy anyway we don't
/// need to extract the timestamp from the http request, just using
/// "now" is good enough.
struct NonceStore {
    seen: HashMap<String, Instant>,
    max_age: std::time::Duration,
}

impl NonceStore {
    fn new(max_skew_secs: u64) -> Self {
        Self {
            seen: HashMap::new(),
            max_age: std::time::Duration::from_secs(max_skew_secs * 2),
        }
    }

    /// Insert a nonce, returning `Err` if it was already used (replay attack).
    fn check_and_insert_and_prune_old(&mut self, nonce: &str) -> anyhow::Result<()> {
        if nonce.len() < 16 {
            anyhow::bail!("nonce too short ({} bytes, minimum 16)", nonce.len());
        }

        let now = Instant::now();

        // prune here (lazy) to avoid having an extra thread/timer doing it
        // (its fast)
        self.seen
            .retain(|_, inserted_at| now.duration_since(*inserted_at) < self.max_age);

        // insert() returns the old value (if it existed before) so we
        // need to error if it's not None
        if self.seen.insert(nonce.to_string(), now).is_some() {
            anyhow::bail!("nonce already used (possible replay attack)");
        }

        Ok(())
    }
}

pub(crate) struct SshKeyAuthenticator {
    path: String,
    max_skew: u64,
    authorized_keys: Mutex<KeyCache>,
    nonces: Mutex<NonceStore>,
}

impl SshKeyAuthenticator {
    pub(crate) fn new(path: &str) -> anyhow::Result<Self> {
        let keys = Self::load_keys(path)?;
        // XXX: should we make it a warning only? the file can dynamically
        // get updated so it could be okay to start empty. OTOH ppl might
        // be surprised by it.
        if keys.is_empty() {
            bail!(
                "no supported SSH public keys in {path} (note: RSA is not supported, use Ed25519 or ECDSA)"
            );
        }
        let mtime = std::fs::metadata(path)
            .and_then(|m| m.modified())
            .with_context(|| format!("failed to stat {path}"))?;

        let max_skew = 60;
        Ok(Self {
            path: path.to_string(),
            max_skew,
            authorized_keys: Mutex::new(KeyCache { keys, mtime }),
            nonces: Mutex::new(NonceStore::new(max_skew)),
        })
    }

    pub(crate) fn key_count(&self) -> usize {
        self.authorized_keys.lock().unwrap().keys.len()
    }

    #[cfg(test)]
    pub(crate) fn with_max_skew(mut self, max_skew: u64) -> Self {
        self.max_skew = max_skew;
        self.nonces = Mutex::new(NonceStore::new(max_skew));
        self
    }

    /// Parse an `authorized_keys` file, returning only supported (non-RSA) keys.
    fn load_keys(path: &str) -> anyhow::Result<HashMap<String, PublicKey>> {
        let keys_vec = sshauth::keyfile::parse_authorized_keys(path, true)
            .with_context(|| format!("failed to read authorized keys from {path}"))?;

        let mut keys = HashMap::new();
        for key in keys_vec {
            if matches!(key.algorithm(), ssh_key::Algorithm::Rsa { .. }) {
                warn!(
                    "ignoring RSA key {} ({}): RSA signing is not supported, use Ed25519 or ECDSA",
                    key.fingerprint(HashAlg::Sha256),
                    key.comment(),
                );
                continue;
            }
            let fp = key.fingerprint(HashAlg::Sha256).to_string();
            keys.insert(fp, key);
        }

        Ok(keys)
    }

    /// Reload the `authorized_keys` file if its mtime has changed.
    fn maybe_reload(&self) {
        let current_mtime = match std::fs::metadata(&self.path).and_then(|m| m.modified()) {
            Ok(m) => m,
            Err(e) => {
                warn!(
                    "cannot stat {path}: {e}, keeping cached keys",
                    path = self.path
                );
                return;
            }
        };

        // note that we could use an RWLock here but its probably not worth it
        let mut ak = self.authorized_keys.lock().unwrap();
        if ak.mtime == current_mtime {
            return;
        }

        match Self::load_keys(&self.path) {
            Ok(keys) => {
                info!(
                    "reloaded {count} SSH key(s) from {path} (file changed)",
                    count = keys.len(),
                    path = self.path,
                );
                if keys.is_empty() {
                    warn!(
                        "authorized keys file {path} is empty, SSH auth will reject all requests",
                        path = self.path,
                    );
                }
                ak.keys = keys;
                ak.mtime = current_mtime;
            }
            Err(e) => {
                warn!(
                    "failed to reload {path}: {e:#}, clearing keys (fail closed)",
                    path = self.path,
                );
                ak.keys.clear();
                ak.mtime = current_mtime;
            }
        }
    }
}

impl std::fmt::Debug for SshKeyAuthenticator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let ak = self.authorized_keys.lock().unwrap();
        let fingerprints: Vec<&str> = ak.keys.keys().map(String::as_str).collect();
        f.debug_struct("SshKeyAuthenticator")
            .field("path", &self.path)
            .field("max_skew", &self.max_skew)
            .field("fingerprints", &fingerprints)
            .finish_non_exhaustive()
    }
}

/// Extract the replay-protection nonce from the request headers.
pub(crate) fn extract_nonce(headers: &axum::http::HeaderMap) -> Option<String> {
    headers
        .get(SSHAUTH_NONCE_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(String::from)
}

/// Well-known credential name for SSH authorized keys, see
/// systemd.system-credentials(7).
const SSH_AUTHORIZED_KEYS_CREDENTIAL: &str = "ssh.authorized_keys.root";

pub(crate) fn maybe_create_ssh_authenticator(
    cli_authorized_keys: Option<String>,
    creds_dir: Option<&std::path::Path>,
    root: &std::path::Path,
) -> anyhow::Result<Option<SshKeyAuthenticator>> {
    fn exists(p: &std::path::Path) -> Option<String> {
        p.exists().then(|| p.to_string_lossy().to_string())
    }

    // Priority: explicit CLI > /etc config > $CREDENTIALS_DIRECTORY >
    // system-wide /run/credentials/@system/ (see systemd.system-credentials(7))
    let authorized_keys_path = cli_authorized_keys
        .or_else(|| exists(&root.join("etc/varlink-httpd/authorized_keys")))
        .or_else(|| creds_dir.and_then(|d| exists(&d.join(SSH_AUTHORIZED_KEYS_CREDENTIAL))))
        .or_else(|| {
            exists(
                &root
                    .join("run/credentials/@system")
                    .join(SSH_AUTHORIZED_KEYS_CREDENTIAL),
            )
        });

    let Some(ak_path) = authorized_keys_path else {
        return Ok(None);
    };
    let ssh_auth = SshKeyAuthenticator::new(&ak_path)?;
    info!(
        "Authenticator: adding SSH authorized keys ({count} keys from {ak_path})",
        count = ssh_auth.key_count()
    );
    Ok(Some(ssh_auth))
}

impl Authenticator for SshKeyAuthenticator {
    fn check_request(
        &self,
        method: &str,
        path: &str,
        auth_header: &str,
        nonce: Option<&str>,
        tls_channel_binding: Option<&str>,
    ) -> anyhow::Result<()> {
        self.maybe_reload();

        let nonce = nonce.context("missing nonce header (x-auth-nonce)")?;

        let token_str = auth_header
            .strip_prefix("Bearer ")
            .context("Authorization header must start with 'Bearer '")?;

        let unverified_token =
            sshauth::UnverifiedToken::try_from(token_str).context("invalid token")?;

        // clone the keys to drop the authorized_keys.lock() ASAP and avoid it being
        // held during the (slow) verify_for()
        let authorized_keys: Vec<ssh_key::PublicKey> = {
            let ak = self.authorized_keys.lock().unwrap();
            ak.keys.values().cloned().collect()
        };

        let verified = unverified_token
            .verify_for()
            .magic_prefix(SSHAUTH_MAGIC_PREFIX)
            .max_skew_seconds(self.max_skew)
            .action("method", method)
            .action("path", path)
            .action("nonce", nonce)
            .action(
                "tls-channel-binding",
                // Safe: when TLS is active the server always provides a real binding
                // (TLS 1.3 enforced in load_tls_acceptor), so a token signed with ""
                // will fail verification. The "" default only applies to non-TLS
                // connections where channel binding is not relevant.
                tls_channel_binding.unwrap_or_default(),
            )
            .with_keys(&authorized_keys)
            .context("token verification failed")?;

        // good signature, check that nonce is unique
        self.nonces
            .lock()
            .unwrap()
            .check_and_insert_and_prune_old(nonce)?;

        log::info!(
            "SSH auth OK: {method} {path} key={fp}",
            fp = verified.fingerprint()
        );
        Ok(())
    }
}
