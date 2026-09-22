// SPDX-License-Identifier: LGPL-2.1-or-later

use anyhow::{Context, bail};
use data_encoding::{HEXLOWER, HEXLOWER_PERMISSIVE};
use log::{info, warn};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::SystemTime;

use varlink_http_bridge::sysconf::{CredentialsLoader, current_key_sources, find_config};

use crate::{AuthRequest, Authenticator};

/// Prefix for generated API keys so a leaked key is recognizable
/// (e.g. by secret scanners) as belonging to this service.
const API_KEY_PREFIX: &str = "vhb_";

const API_KEYS_CONFIG: &str = "varlink-httpd/api-keys";

// The credential names that can provide api-keys
pub(crate) const API_KEY_CREDENTIALS: &[&str] =
    &["varlink-httpd.api-keys", "varlink-httpd.api-keys.*"];

const SHA256_LEN: usize = 32;

fn validate_api_key(key: &str) -> anyhow::Result<()> {
    const API_KEY_MIN_LEN: usize = 32;

    if key.is_empty() {
        bail!("empty API key");
    }
    let len = key.chars().count();
    if len < API_KEY_MIN_LEN {
        bail!("API key too short: {len} characters, at least {API_KEY_MIN_LEN} required");
    }
    Ok(())
}

fn hex_decode_sha256(hex: &str) -> anyhow::Result<[u8; SHA256_LEN]> {
    // the value is left out of the error to avoid leaking real keys
    // that got pasted accidentially without hasing
    HEXLOWER_PERMISSIVE
        .decode(hex.as_bytes())
        .context("digest is not valid hex")?
        .try_into()
        .map_err(|v: Vec<u8>| anyhow::anyhow!("expected {SHA256_LEN} bytes, got {}", v.len()))
}

/// One accepted API key, stored as its SHA-256 digest so the keys file
/// never contains the secret itself. The name identifies the key in
/// logs and makes revocation (deleting its line) practical.
struct ApiKeyEntry {
    digest: [u8; SHA256_LEN],
    name: String,
}

impl ApiKeyEntry {
    /// Parse a `sha256:<hex> [name]` line; empty lines and `#` comments
    /// yield `None`.
    fn parse_line(line: &str) -> anyhow::Result<Option<Self>> {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            return Ok(None);
        }
        let mut fields = line.split_whitespace();
        let hex = fields
            .next()
            .expect("non-empty line has a first field")
            .strip_prefix("sha256:")
            .context("API key line must start with 'sha256:'")?;
        let digest = hex_decode_sha256(hex)?;
        let name = fields.next().unwrap_or(&hex[..8]).to_string();
        Ok(Some(Self { digest, name }))
    }
}

/// One tracked API keys file: its mtime when last read and the entries it
/// contained (mirrors `AuthKeysFile` in `auth_ssh`).
// TODO: the mtime-tracking/hot-reload machinery here (ApiKeysFile,
// ApiKeyCache) duplicates AuthKeysFile/KeyCache in auth_ssh; extract a
// generic WatchedFiles<T> so behavior fixes cannot diverge.
struct ApiKeysFile {
    mtime: SystemTime,
    entries: Vec<ApiKeyEntry>,
}

impl ApiKeysFile {
    /// Stat `path`, folding `NotFound` into `Ok(None)` so missing files are
    /// treated as "tracked absence" rather than a hard error.
    fn stat_mtime(path: &Path) -> std::io::Result<Option<SystemTime>> {
        match std::fs::metadata(path).and_then(|m| m.modified()) {
            Ok(m) => Ok(Some(m)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Parse an API keys file. Malformed lines are skipped with a warning:
    /// a bad line can only reduce access, and dropping the whole file on
    /// one typo would lock out every other key.
    fn parse_keys(path: &Path) -> anyhow::Result<Vec<ApiKeyEntry>> {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read API keys from {}", path.display()))?;
        let mut entries = Vec::new();
        for (nr, line) in content.lines().enumerate() {
            match ApiKeyEntry::parse_line(line) {
                Ok(Some(entry)) => entries.push(entry),
                Ok(None) => {}
                Err(e) => warn!(
                    "{}:{}: skipping API key line: {e:#}",
                    path.display(),
                    nr + 1
                ),
            }
        }
        Ok(entries)
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
        let entries = Self::parse_keys(path)?;
        Ok(Some(Self { mtime, entries }))
    }
}

struct ApiKeyCache {
    files: HashMap<PathBuf, ApiKeysFile>,
}

impl ApiKeyCache {
    /// Initial load of all tracked paths. Files that do not (yet) exist
    /// are silently skipped; they will be picked up by `reload` once
    /// they appear. Read errors propagate (startup should fail loud).
    fn load_all(paths: &[PathBuf]) -> anyhow::Result<Self> {
        let mut files = HashMap::new();
        for path in paths {
            match ApiKeysFile::load(path)? {
                Some(f) => {
                    files.insert(path.clone(), f);
                }
                None => info!(
                    "API keys file {} does not exist yet, skipping",
                    path.display()
                ),
            }
        }
        Ok(Self { files })
    }

    fn key_count(&self) -> usize {
        self.files.values().map(|f| f.entries.len()).sum()
    }

    /// Find the name of the API key matching `digest`. Comparing digests in
    /// constant time is cheap insurance even though a timing side channel
    /// on a digest does not reveal the key itself.
    fn lookup(&self, digest: &[u8; SHA256_LEN]) -> Option<String> {
        self.files
            .values()
            .flat_map(|f| &f.entries)
            .find(|e| openssl::memcmp::eq(&e.digest, digest))
            .map(|e| e.name.clone())
    }

    /// True if any `path` in `paths` has an mtime that differs from what
    /// this cache has recorded (including "file now exists" and "file now
    /// gone"). A path that cannot be stat()ed counts as unchanged so it
    /// cannot block refreshing the others.
    fn any_mtime_changed(&self, paths: &[PathBuf]) -> bool {
        // a vanished credential is no longer in `paths`, so the loop below
        // cannot notice it and its keys would stay valid
        if self.files.keys().any(|path| !paths.contains(path)) {
            return true;
        }
        for path in paths {
            let now = match ApiKeysFile::stat_mtime(path) {
                Ok(now) => now,
                Err(e) => {
                    warn!(
                        "cannot stat {}: {e}, keeping cached API keys",
                        path.display()
                    );
                    continue;
                }
            };
            let cached = self.files.get(path).map(|f| f.mtime);
            if now != cached {
                return true;
            }
        }
        false
    }

    /// If any tracked path has changed on disk, re-read it; a path with a
    /// transient stat error keeps its cached keys (retried on the next call).
    fn maybe_reload(&mut self, paths: &[PathBuf]) {
        if self.any_mtime_changed(paths) {
            self.reload(paths);
        }
    }

    fn reload(&mut self, paths: &[PathBuf]) {
        let mut new_files = HashMap::new();
        for path in paths {
            let mtime = match ApiKeysFile::stat_mtime(path) {
                Ok(Some(mtime)) => mtime,
                Ok(None) => continue, // gone: drop its cached keys
                Err(_) => {
                    // unreadable: keep what we had, already warned about
                    if let Some(cached) = self.files.remove(path) {
                        new_files.insert(path.clone(), cached);
                    }
                    continue;
                }
            };
            let entries = match ApiKeysFile::parse_keys(path) {
                Ok(entries) => {
                    info!(
                        "reloaded {count} API key(s) from {path} (file changed)",
                        count = entries.len(),
                        path = path.display(),
                    );
                    entries
                }
                Err(e) => {
                    warn!(
                        "failed to reload {}: {e:#}, skipping this source",
                        path.display()
                    );
                    Vec::new()
                }
            };
            new_files.insert(path.clone(), ApiKeysFile { mtime, entries });
        }

        self.files = new_files;
        if self.key_count() == 0 {
            warn!("all API key sources are empty, API key auth will reject all requests");
        }
    }
}

/// Report if any API key credentials are present but not read because
/// the `api_key_auth` is not selected or an explicit path is used instead.
pub(crate) fn unread_credentials(
    creds: &CredentialsLoader,
    auth_is_selected: bool,
    explicit_path_set: bool,
) -> Vec<String> {
    // An explicit --api-keys= replaces discovery rather than adding to it,
    // so it hides credentials even when API key auth is selected.
    let why = if !auth_is_selected {
        "pass --auth=api-key to use it"
    } else if explicit_path_set {
        "an explicit path takes priority"
    } else {
        // if the auth is selected and no path is set we can return
        return Vec::new();
    };
    // diagnostics only, so an unreadable directory lists nothing
    creds
        .find_with(API_KEY_CREDENTIALS, |id| format!("{id} ({why})"))
        .unwrap_or_default()
}

pub(crate) struct ApiKeyAuthenticator {
    paths: Vec<PathBuf>,
    creds: Option<CredentialsLoader>,
    keys: Mutex<ApiKeyCache>,
}

impl ApiKeyAuthenticator {
    pub(crate) fn new(
        paths: Vec<PathBuf>,
        creds: Option<CredentialsLoader>,
    ) -> anyhow::Result<Self> {
        let all = current_key_sources(&paths, creds.as_ref(), API_KEY_CREDENTIALS)
            .context("failed to enumerate credentials")?;
        let cache = ApiKeyCache::load_all(&all)?;
        Ok(Self {
            paths,
            creds,
            keys: Mutex::new(cache),
        })
    }

    pub(crate) fn current_key_sources(&self) -> std::io::Result<Vec<PathBuf>> {
        current_key_sources(&self.paths, self.creds.as_ref(), API_KEY_CREDENTIALS)
    }

    pub(crate) fn key_count(&self) -> usize {
        self.keys.lock().unwrap().key_count()
    }
}

impl std::fmt::Debug for ApiKeyAuthenticator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApiKeyAuthenticator")
            .field("paths", &self.paths)
            .field("creds", &self.creds)
            .field("key_count", &self.key_count())
            .finish_non_exhaustive()
    }
}

impl Authenticator for ApiKeyAuthenticator {
    fn check_request(&self, request: &AuthRequest) -> anyhow::Result<()> {
        // enumerate before taking the lock, it touches the filesystem
        let paths = self.current_key_sources().inspect_err(|e| {
            warn!("cannot enumerate credentials: {e}, skipping reload (keeping cached API keys)");
        });
        let mut keys = self.keys.lock().unwrap();
        if let Ok(paths) = paths {
            keys.maybe_reload(&paths);
        }

        let token_str = request.bearer_token()?;
        validate_api_key(token_str)?;
        let digest = openssl::sha::sha256(token_str.as_bytes());
        let name = keys.lookup(&digest).context("unknown API key")?;

        info!(
            "api-key auth OK: {method} {path} key={name}",
            method = request.method,
            path = request.path
        );
        Ok(())
    }
}

/// Create an API key authenticator, or `None` when API key auth is not
/// configured. An explicit `--api-keys` flag always enables it (even for a
/// not-yet-existing file, which is picked up on reload); the well-known
/// locations enable it only when present, so a bridge without any API key
/// configuration does not grow an authenticator that rejects everything.
///
/// The hierarchy contributes only its highest-precedence file; every
/// [`API_KEY_CREDENTIALS`] credential is merged on top.
// TODO: discover -> build -> warn-if-empty -> log is the same shape as
// create_ssh_authenticator; fold into the WatchedFiles<T> extraction.
pub(crate) fn create_api_key_authenticator(
    cli_api_keys: Option<PathBuf>,
    creds: Option<CredentialsLoader>,
    root: &Path,
) -> anyhow::Result<Option<ApiKeyAuthenticator>> {
    let (paths, creds) = if let Some(cli_path) = cli_api_keys {
        // an explicit path replaces discovery rather than adding to it
        (vec![cli_path], None)
    } else {
        let paths: Vec<PathBuf> = find_config(API_KEYS_CONFIG, root).into_iter().collect();
        if current_key_sources(&paths, creds.as_ref(), API_KEY_CREDENTIALS)?.is_empty() {
            return Ok(None);
        }
        (paths, creds)
    };

    let api_key_auth = ApiKeyAuthenticator::new(paths, creds)?;
    let sources = api_key_auth
        .current_key_sources()?
        .iter()
        .map(|p| p.display().to_string())
        .collect::<Vec<_>>()
        .join(", ");
    if api_key_auth.key_count() == 0 {
        warn!("no API keys in {sources}; API key auth will reject all requests until keys appear");
    }
    info!(
        "Authenticator: adding API keys ({count} key(s) from {sources})",
        count = api_key_auth.key_count(),
    );
    Ok(Some(api_key_auth))
}

#[derive(Debug)]
pub(crate) struct GenApiKey {
    pub name: Option<String>,
    pub output: Option<PathBuf>,
}

fn default_api_keys_path() -> PathBuf {
    // not find_config(): a write target must be named even when absent
    if rustix::process::getuid().is_root() {
        return Path::new("/etc").join(API_KEYS_CONFIG);
    }
    let config_dir = std::env::var_os("XDG_CONFIG_HOME").map_or_else(
        || {
            let home = std::env::var_os("HOME").unwrap_or_else(|| "/root".into());
            Path::new(&home).join(".config")
        },
        PathBuf::from,
    );
    config_dir.join(API_KEYS_CONFIG)
}

pub(crate) fn generate_api_key() -> String {
    let mut buf = [0u8; 32];
    openssl::rand::rand_bytes(&mut buf).expect("openssl PRNG failed");
    format!("{API_KEY_PREFIX}{}", HEXLOWER.encode(&buf))
}

/// Append the hash line for `key` to the API keys file at `path`,
/// returning the name it was stored under.
pub(crate) fn append_api_key(path: &Path, key: &str, name: Option<&str>) -> anyhow::Result<String> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    validate_api_key(key)?;

    let hex = HEXLOWER.encode(&openssl::sha::sha256(key.as_bytes()));
    let name = name.unwrap_or(&hex[..8]);
    // The name is a whitespace-separated field on the key line.
    if name.chars().any(char::is_whitespace) {
        bail!("API key name must not contain whitespace: {name:?}");
    }

    let parent = path
        .parent()
        .with_context(|| format!("cannot determine parent directory of {}", path.display()))?;
    std::fs::create_dir_all(parent)
        .with_context(|| format!("failed to create directory {}", parent.display()))?;
    // 0600: the file only holds hashes, but there is no reason to share it.
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("failed to open {}", path.display()))?;
    writeln!(f, "sha256:{hex} {name}")
        .with_context(|| format!("failed to write {}", path.display()))?;
    Ok(name.to_string())
}

pub(crate) fn run_gen_api_key(cmd: GenApiKey) -> anyhow::Result<()> {
    let output_path = cmd.output.unwrap_or_else(default_api_keys_path);
    let key = generate_api_key();
    let name = append_api_key(&output_path, &key, cmd.name.as_deref())?;

    // The key itself goes to stdout (and nowhere else) so that
    // `API_KEY=$(varlink-httpd gen-api-key)` works; only its hash is stored.
    println!("{key}");
    let output_path = output_path.display();
    eprintln!("Appended hash of API key '{name}' to {output_path}, run with:");
    if output_path.to_string() == "/etc/varlink-httpd/api-keys" {
        eprintln!("  varlink-httpd --auth=api-key");
    } else {
        eprintln!("  varlink-httpd --auth=api-key --api-keys={output_path}");
    }
    Ok(())
}
