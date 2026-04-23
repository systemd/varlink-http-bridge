// SPDX-License-Identifier: LGPL-2.1-or-later

use anyhow::Context;
use log::{debug, info, warn};
use ssh_key::{HashAlg, PublicKey};
use std::collections::{HashMap, HashSet};
use std::sync::Mutex;
use std::time::{Instant, SystemTime};

use crate::Authenticator;
use varlink_http_bridge::{SSHAUTH_MAGIC_PREFIX, SSHAUTH_NONCE_HEADER};

/// One tracked `authorized_keys` file: its mtime when last read and the
/// (fingerprint -> key) map of supported keys it contained. Bundling
/// these avoids having to keep the per-path mtime in a second map in
/// lockstep with the keys.
struct AuthKeysFile {
    mtime: SystemTime,
    keys: HashMap<String, PublicKey>,
}

impl AuthKeysFile {
    /// Stat `path`, folding `NotFound` into `Ok(None)` so missing files are
    /// treated as "tracked absence" rather than a hard error.
    fn stat_mtime(path: &str) -> std::io::Result<Option<SystemTime>> {
        match std::fs::metadata(path).and_then(|m| m.modified()) {
            Ok(m) => Ok(Some(m)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Parse an `authorized_keys` file, returning only supported (non-RSA) keys.
    fn parse_keys(path: &str) -> anyhow::Result<HashMap<String, PublicKey>> {
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
            debug!(
                "  authorized key: {fp} ({comment})",
                comment = key.comment()
            );
            keys.insert(fp, key);
        }
        Ok(keys)
    }

    /// Stat and parse `path`. Returns `Ok(None)` if the file does not
    /// exist yet (it will be picked up by `maybe_reload` once it appears).
    fn load(path: &str) -> anyhow::Result<Option<Self>> {
        let mtime = match Self::stat_mtime(path) {
            Ok(Some(m)) => m,
            Ok(None) => return Ok(None),
            Err(e) => {
                return Err(anyhow::Error::new(e).context(format!("failed to stat {path}")));
            }
        };
        let keys = Self::parse_keys(path)?;
        Ok(Some(Self { mtime, keys }))
    }
}

struct KeyCache {
    files: HashMap<String, AuthKeysFile>,
}

impl KeyCache {
    /// Initial load of all tracked paths. Files that do not (yet) exist
    /// are silently skipped; they will be picked up by `reload` once
    /// they appear. Parse errors propagate (startup should fail loud).
    fn load_all(paths: &[String]) -> anyhow::Result<Self> {
        let mut files = HashMap::new();
        for path in paths {
            match AuthKeysFile::load(path)? {
                Some(f) => {
                    files.insert(path.clone(), f);
                }
                None => info!("authorized keys file {path} does not exist yet, skipping"),
            }
        }
        Ok(Self { files })
    }

    /// Number of distinct key fingerprints across all tracked files.
    fn unique_key_count(&self) -> usize {
        let mut fps: HashSet<&str> = HashSet::new();
        for f in self.files.values() {
            fps.extend(f.keys.keys().map(String::as_str));
        }
        fps.len()
    }

    /// All keys across all tracked files, deduplicated by fingerprint
    /// (a key listed in more than one file is returned once).
    fn all_keys(&self) -> Vec<PublicKey> {
        let mut by_fp: HashMap<&str, PublicKey> = HashMap::new();
        for f in self.files.values() {
            for (fp, key) in &f.keys {
                by_fp.entry(fp.as_str()).or_insert_with(|| key.clone());
            }
        }
        by_fp.into_values().collect()
    }

    /// All unique fingerprints currently cached, across all tracked files.
    fn fingerprints(&self) -> Vec<&str> {
        let fps: HashSet<&str> = self
            .files
            .values()
            .flat_map(|f| f.keys.keys().map(String::as_str))
            .collect();
        fps.into_iter().collect()
    }

    /// Ok(true) if any `path` in `paths` has an mtime that differs from
    /// what this cache has recorded (including "file now exists" and
    /// "file now gone"). Err carries the path that failed a transient
    /// stat so the caller can log it.
    fn any_mtime_changed(&self, paths: &[String]) -> Result<bool, (String, std::io::Error)> {
        for path in paths {
            let now = AuthKeysFile::stat_mtime(path).map_err(|e| (path.clone(), e))?;
            let cached = self.files.get(path).map(|f| f.mtime);
            if now != cached {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// If any tracked path has changed on disk, re-read it; transient
    /// stat errors are logged and the cache is left untouched (retried
    /// on the next call).
    fn maybe_reload(&mut self, paths: &[String]) {
        match self.any_mtime_changed(paths) {
            Ok(false) => {}
            Ok(true) => self.reload(paths),
            Err((path, e)) => {
                // Transient error (permissions, IO): skip this reload cycle
                // rather than risk dropping valid keys. Retry next request.
                warn!("cannot stat {path}: {e}, skipping reload (keeping cached keys)");
            }
        }
    }

    /// Re-read all `paths` into this cache, replacing previously tracked
    /// entries. On parse errors the file's mtime is still recorded (with
    /// empty keys) so we don't log-spam the same warning on every request
    /// until the file changes again.
    fn reload(&mut self, paths: &[String]) {
        let mut new_files = HashMap::new();
        for path in paths {
            let Ok(Some(mtime)) = AuthKeysFile::stat_mtime(path) else {
                continue; // file is gone or unreadable; drop its cached keys
            };
            let keys = match AuthKeysFile::parse_keys(path) {
                Ok(keys) => {
                    info!(
                        "reloaded {count} SSH key(s) from {path} (file changed)",
                        count = keys.len(),
                    );
                    keys
                }
                Err(e) => {
                    warn!("failed to reload {path}: {e:#}, skipping this source");
                    HashMap::new()
                }
            };
            new_files.insert(path.clone(), AuthKeysFile { mtime, keys });
        }

        self.files = new_files;
        if self.unique_key_count() == 0 {
            warn!("all authorized key sources are empty, SSH auth will reject all requests");
        }
    }
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
    paths: Vec<String>,
    max_skew: u64,
    authorized_keys: Mutex<KeyCache>,
    nonces: Mutex<NonceStore>,
}

impl SshKeyAuthenticator {
    pub(crate) fn new(paths: Vec<String>) -> anyhow::Result<Self> {
        let cache = KeyCache::load_all(&paths)?;
        if cache.unique_key_count() == 0 {
            warn!(
                "no supported SSH public keys in {} (note: RSA is not supported, use Ed25519 or ECDSA); SSH auth will reject all requests until keys appear",
                paths.join(", "),
            );
        }

        let max_skew = 60;
        Ok(Self {
            paths,
            max_skew,
            authorized_keys: Mutex::new(cache),
            nonces: Mutex::new(NonceStore::new(max_skew)),
        })
    }

    pub(crate) fn key_count(&self) -> usize {
        self.authorized_keys.lock().unwrap().unique_key_count()
    }

    #[cfg(test)]
    pub(crate) fn with_max_skew(mut self, max_skew: u64) -> Self {
        self.max_skew = max_skew;
        self.nonces = Mutex::new(NonceStore::new(max_skew));
        self
    }

    #[cfg(test)]
    pub(crate) fn reload_for_test(&self) {
        self.authorized_keys
            .lock()
            .unwrap()
            .maybe_reload(&self.paths);
    }
}

impl std::fmt::Debug for SshKeyAuthenticator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let ak = self.authorized_keys.lock().unwrap();
        let fingerprints = ak.fingerprints();
        f.debug_struct("SshKeyAuthenticator")
            .field("paths", &self.paths)
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

/// Well-known credential names for SSH authorized keys, see
/// systemd.system-credentials(7).  The dedicated credential is checked
/// first so it takes priority over the broader ephemeral one.
const SSH_AUTHORIZED_KEYS_CREDENTIALS: &[&str] = &[
    "ssh.authorized_keys.root",
    "ssh.ephemeral-authorized_keys-all",
];

pub(crate) fn create_ssh_authenticator(
    cli_authorized_keys: Option<String>,
    creds_dir: Option<&std::path::Path>,
    root: &std::path::Path,
) -> anyhow::Result<SshKeyAuthenticator> {
    let paths: Vec<String> = if let Some(cli_path) = cli_authorized_keys {
        // Explicit CLI path overrides all auto-discovery
        vec![cli_path]
    } else {
        // Register all well-known sources; files that don't exist yet
        // will be picked up by maybe_reload() once they appear.
        let mut paths = Vec::new();
        paths.push(
            root.join("etc/varlink-httpd/authorized_keys")
                .to_string_lossy()
                .to_string(),
        );
        if let Some(d) = creds_dir {
            for name in SSH_AUTHORIZED_KEYS_CREDENTIALS {
                paths.push(d.join(name).to_string_lossy().to_string());
            }
        }
        paths
    };

    let ssh_auth = SshKeyAuthenticator::new(paths.clone())?;
    info!(
        "Authenticator: adding SSH authorized keys ({count} keys from {sources})",
        count = ssh_auth.key_count(),
        sources = paths.join(", "),
    );
    Ok(ssh_auth)
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
        self.authorized_keys
            .lock()
            .unwrap()
            .maybe_reload(&self.paths);

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
            ak.all_keys()
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
