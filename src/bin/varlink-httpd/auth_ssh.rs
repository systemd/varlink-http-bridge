// SPDX-License-Identifier: LGPL-2.1-or-later

use anyhow::Context;
use log::{debug, info, warn};
use ssh_key::{HashAlg, PublicKey};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Instant, SystemTime};

use crate::{AuthRequest, Authenticator};
use varlink_http_bridge::sshauth_token::{SSHAUTH_NONCE_HEADER, SignedParts, UnverifiedToken};
use varlink_http_bridge::sysconf::{CredentialsLoader, current_key_sources};

/// One tracked `authorized_keys` file: its mtime when last read and the
/// (fingerprint -> key) map of supported keys it contained. Bundling
/// these avoids having to keep the per-path mtime in a second map in
/// lockstep with the keys.
// TODO: AuthKeysFile/KeyCache are duplicated as ApiKeysFile/ApiKeyCache
// in auth_api_key; extract a generic WatchedFiles<T> so behavior fixes
// cannot diverge.
struct AuthKeysFile {
    mtime: SystemTime,
    keys: HashMap<String, PublicKey>,
}

impl AuthKeysFile {
    /// Stat `path`, folding `NotFound` into `Ok(None)` so missing files are
    /// treated as "tracked absence" rather than a hard error.
    fn stat_mtime(path: &Path) -> std::io::Result<Option<SystemTime>> {
        match std::fs::metadata(path).and_then(|m| m.modified()) {
            Ok(m) => Ok(Some(m)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Parse an `authorized_keys` file, returning only supported (non-RSA) keys.
    fn parse_keys(path: &Path) -> anyhow::Result<HashMap<String, PublicKey>> {
        let keys_vec = sshauth::keyfile::parse_authorized_keys(path, true)
            .with_context(|| format!("failed to read authorized keys from {}", path.display()))?;

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
    fn load(path: &Path) -> anyhow::Result<Option<Self>> {
        let mtime = match Self::stat_mtime(path) {
            Ok(Some(m)) => m,
            Ok(None) => return Ok(None),
            Err(e) => {
                return Err(
                    anyhow::Error::new(e).context(format!("failed to stat {}", path.display()))
                );
            }
        };
        let keys = Self::parse_keys(path)?;
        Ok(Some(Self { mtime, keys }))
    }
}

/// Keep track of the mtime of the tracked paths. This means when comparing two
/// `MtimeSnapshot`s for "eq" we cover changed, appeared or vanished files.
#[derive(PartialEq)]
struct MtimeSnapshot(HashMap<PathBuf, SystemTime>);

impl MtimeSnapshot {
    /// Takes a snapshot of the given paths. Any error that is not
    /// ENOENT fails the snapshot and returns an error that contains
    /// the failing path.
    fn take(paths: &[PathBuf]) -> Result<Self, (PathBuf, std::io::Error)> {
        let mut on_disk = HashMap::new();
        for path in paths {
            if let Some(t) = AuthKeysFile::stat_mtime(path).map_err(|e| (path.clone(), e))? {
                on_disk.insert(path.clone(), t);
            }
        }
        Ok(Self(on_disk))
    }
}

struct KeyCache {
    files: HashMap<PathBuf, AuthKeysFile>,
}

impl KeyCache {
    /// Initial load of all tracked paths. Files that do not (yet) exist
    /// are silently skipped; they will be picked up by `reload` once
    /// they appear. Parse errors propagate (startup should fail loud).
    fn load_all(paths: &[PathBuf]) -> anyhow::Result<Self> {
        let mut files = HashMap::new();
        for path in paths {
            match AuthKeysFile::load(path)? {
                Some(f) => {
                    files.insert(path.clone(), f);
                }
                None => info!(
                    "authorized keys file {} does not exist yet, skipping",
                    path.display()
                ),
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

    /// The snapshot this cache currently reflects.
    fn snapshot(&self) -> MtimeSnapshot {
        MtimeSnapshot(
            self.files
                .iter()
                .map(|(p, f)| (p.clone(), f.mtime))
                .collect(),
        )
    }

    /// If any tracked path has changed on disk, re-read it; transient
    /// stat errors are logged and the cache is left untouched (retried
    /// on the next call).
    fn maybe_reload(&mut self, paths: &[PathBuf]) {
        match MtimeSnapshot::take(paths) {
            Ok(on_disk) => {
                if on_disk != self.snapshot() {
                    self.reload(on_disk);
                }
            }
            Err((path, e)) => {
                // Transient error (permissions, IO): skip this reload cycle
                // rather than risk dropping valid keys. Retry next request.
                warn!(
                    "cannot stat {}: {e}, skipping reload (keeping cached keys)",
                    path.display()
                );
            }
        }
    }

    /// Re-read the changed files in the snapshot into this cache,
    /// replacing previously tracked entries; entries whose mtime is
    /// unchanged are kept as-is. On parse errors the file's mtime is
    /// still recorded (with empty keys) so we don't log-spam the same
    /// warning on every request until the file changes again.
    fn reload(&mut self, on_disk: MtimeSnapshot) {
        let mut new_files = HashMap::new();
        for (path, mtime) in on_disk.0 {
            if let Some(cached) = self.files.remove(&path)
                && cached.mtime == mtime
            {
                new_files.insert(path, cached);
                continue;
            }
            let keys = match AuthKeysFile::parse_keys(&path) {
                Ok(keys) => {
                    info!(
                        "reloaded {count} SSH key(s) from {path} (file changed)",
                        count = keys.len(),
                        path = path.display(),
                    );
                    keys
                }
                Err(e) => {
                    warn!(
                        "failed to reload {}: {e:#}, skipping this source",
                        path.display()
                    );
                    HashMap::new()
                }
            };
            new_files.insert(path, AuthKeysFile { mtime, keys });
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
    /// Fixed paths only; the credentials in `creds` are re-enumerated on
    /// every reload check.
    paths: Vec<PathBuf>,
    creds: Option<CredentialsLoader>,
    max_skew: u64,
    authorized_keys: Mutex<KeyCache>,
    nonces: Mutex<NonceStore>,
}

impl SshKeyAuthenticator {
    pub(crate) fn new(
        paths: Vec<PathBuf>,
        creds: Option<CredentialsLoader>,
    ) -> anyhow::Result<Self> {
        let all_paths =
            current_key_sources(&paths, creds.as_ref(), SSH_AUTHORIZED_KEYS_CREDENTIALS)
                .context("failed to enumerate credentials")?;
        let cache = KeyCache::load_all(&all_paths)?;
        let sources = all_paths
            .iter()
            .map(|p| p.display().to_string())
            .collect::<Vec<_>>()
            .join(", ");
        if cache.unique_key_count() == 0 {
            warn!(
                "no supported SSH public keys in {sources} (note: RSA is not supported, use Ed25519 or ECDSA); SSH auth will reject all requests until keys appear"
            );
        }
        info!(
            "Authenticator: adding SSH authorized keys ({count} keys from {sources})",
            count = cache.unique_key_count(),
        );

        let max_skew = 60;
        Ok(Self {
            paths,
            creds,
            max_skew,
            authorized_keys: Mutex::new(cache),
            nonces: Mutex::new(NonceStore::new(max_skew)),
        })
    }

    #[cfg(test)]
    pub(crate) fn key_count(&self) -> usize {
        self.authorized_keys.lock().unwrap().unique_key_count()
    }

    fn maybe_reload(&self) {
        let Ok(paths) = current_key_sources(
            &self.paths,
            self.creds.as_ref(),
            SSH_AUTHORIZED_KEYS_CREDENTIALS,
        )
        .inspect_err(|e| {
            warn!("cannot enumerate credentials: {e}, skipping reload (keeping cached keys)");
        }) else {
            return;
        };
        self.authorized_keys.lock().unwrap().maybe_reload(&paths);
    }

    #[cfg(test)]
    pub(crate) fn with_max_skew(mut self, max_skew: u64) -> Self {
        self.max_skew = max_skew;
        self.nonces = Mutex::new(NonceStore::new(max_skew));
        self
    }

    #[cfg(test)]
    pub(crate) fn reload_for_test(&self) {
        self.maybe_reload();
    }
}

impl std::fmt::Debug for SshKeyAuthenticator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let ak = self.authorized_keys.lock().unwrap();
        let fingerprints = ak.fingerprints();
        f.debug_struct("SshKeyAuthenticator")
            .field("paths", &self.paths)
            .field("creds", &self.creds)
            .field("max_skew", &self.max_skew)
            .field("fingerprints", &fingerprints)
            .finish_non_exhaustive()
    }
}

/// Extract the replay-protection nonce from the request headers.
fn extract_nonce(headers: &axum::http::HeaderMap) -> Option<String> {
    headers
        .get(SSHAUTH_NONCE_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(String::from)
}

/// Everything ssh auth reads from the credentials directory, in
/// `ImportCredential=` syntax (see [`CredentialsLoader::find`]). The first
/// two are the well-known names from systemd.system-credentials(7).
pub(crate) const SSH_AUTHORIZED_KEYS_CREDENTIALS: &[&str] = &[
    "ssh.authorized_keys.root",
    "ssh.ephemeral-authorized_keys-all",
    "varlink-httpd.ssh.authorized-keys.*",
];

/// Report if any API key credentials are present but not read because
/// the ssh auth is not selected or an explicit path is used instead.
pub(crate) fn unread_credentials(
    creds: &CredentialsLoader,
    auth_is_selected: bool,
    explicit_path_set: bool,
) -> Vec<String> {
    // An explicit --authorized-keys= replaces discovery rather than adding
    // to it, so it hides credentials even when ssh auth is selected.
    let why = if explicit_path_set {
        "--authorized-keys= replaces credential discovery"
    } else if !auth_is_selected {
        "pass --auth=ssh to use them"
    } else {
        return Vec::new();
    };
    // diagnostics only, so an unreadable directory lists nothing
    creds
        .find_with(SSH_AUTHORIZED_KEYS_CREDENTIALS, |id| {
            format!("{id} ({why})")
        })
        .unwrap_or_default()
}

// TODO: this is our own config file, so it should follow the
// /etc > /run > /usr/lib hierarchy like auth_api_key's api-keys file, via
// find_config(). Not a plain swap though: auth_api_key resolves the
// hierarchy once at startup, and both need it resolved at reload time so
// a file appearing later (or shadowing /usr/lib) is picked up.
pub(crate) fn create_ssh_authenticator(
    cli_authorized_keys: Option<PathBuf>,
    creds: Option<CredentialsLoader>,
    root: &Path,
) -> anyhow::Result<SshKeyAuthenticator> {
    // An explicit path replaces discovery, which is both the /etc file and
    // the credentials directory, so the latter is dropped as well.
    let (paths, creds) = if let Some(cli_path) = cli_authorized_keys {
        (vec![cli_path], None)
    } else {
        // Registered even if absent, so it is picked up by maybe_reload()
        // once it appears. Credentials need no registration: current_key_sources()
        // enumerates them on every reload check.
        (vec![root.join("etc/varlink-httpd/authorized_keys")], creds)
    };

    SshKeyAuthenticator::new(paths, creds)
}

impl Authenticator for SshKeyAuthenticator {
    fn check_request(&self, request: &AuthRequest) -> anyhow::Result<()> {
        self.maybe_reload();

        let (method, path) = (request.method, request.path);
        let token_str = request.bearer_token()?;
        let nonce =
            extract_nonce(request.headers).context("missing nonce header (x-auth-nonce)")?;
        let nonce = nonce.as_str();
        let unverified_token = UnverifiedToken::try_from(token_str).context("invalid token")?;

        // sshauth over non-TLS is not secure so refuse it
        let tls_channel_binding = request
            .tls_channel_binding
            .context("SSH auth requires TLS (no channel binding)")?;
        let signed_parts =
            SignedParts::new(method, path, nonce, request.headers, tls_channel_binding);

        // clone the keys to drop the authorized_keys.lock() ASAP and avoid it being
        // held during the (slow) verify()
        let authorized_keys: Vec<ssh_key::PublicKey> = {
            let ak = self.authorized_keys.lock().unwrap();
            ak.all_keys()
        };

        let verified = signed_parts.verify(&unverified_token, self.max_skew, &authorized_keys)?;

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
