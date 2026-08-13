// SPDX-License-Identifier: LGPL-2.1-or-later

use anyhow::{Context, bail};
use data_encoding::{HEXLOWER, HEXLOWER_PERMISSIVE};
use log::{info, warn};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::SystemTime;

use varlink_http_bridge::sysconf::{CredentialsLoader, find_config};

use crate::{AuthRequest, Authenticator};

/// Prefix for generated API keys so a leaked key is recognizable
/// (e.g. by secret scanners) as belonging to this service.
const API_KEY_PREFIX: &str = "vhb_";

const API_KEYS_CONFIG: &str = "varlink-httpd/api-keys";

/// The shipped unit renames `varlink-httpd.api-keys` to this, so the
/// credential id matches the `--api-keys` flag.
const API_KEYS_CREDENTIAL: &str = "api-keys";

const SHA256_LEN: usize = 32;

fn hex_decode_sha256(hex: &str) -> anyhow::Result<[u8; SHA256_LEN]> {
    HEXLOWER_PERMISSIVE
        .decode(hex.as_bytes())
        .with_context(|| format!("invalid hex in {hex:?}"))?
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
    fn stat_mtime(path: &str) -> std::io::Result<Option<SystemTime>> {
        match std::fs::metadata(path).and_then(|m| m.modified()) {
            Ok(m) => Ok(Some(m)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Parse an API keys file. Malformed lines are skipped with a warning:
    /// a bad line can only reduce access, and dropping the whole file on
    /// one typo would lock out every other key.
    fn parse_keys(path: &str) -> anyhow::Result<Vec<ApiKeyEntry>> {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read API keys from {path}"))?;
        let mut entries = Vec::new();
        for (nr, line) in content.lines().enumerate() {
            match ApiKeyEntry::parse_line(line) {
                Ok(Some(entry)) => entries.push(entry),
                Ok(None) => {}
                Err(e) => warn!("{path}:{}: skipping API key line: {e:#}", nr + 1),
            }
        }
        Ok(entries)
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
        let entries = Self::parse_keys(path)?;
        Ok(Some(Self { mtime, entries }))
    }
}

struct ApiKeyCache {
    files: HashMap<String, ApiKeysFile>,
}

impl ApiKeyCache {
    /// Initial load of all tracked paths. Files that do not (yet) exist
    /// are silently skipped; they will be picked up by `reload` once
    /// they appear. Read errors propagate (startup should fail loud).
    fn load_all(paths: &[String]) -> anyhow::Result<Self> {
        let mut files = HashMap::new();
        for path in paths {
            match ApiKeysFile::load(path)? {
                Some(f) => {
                    files.insert(path.clone(), f);
                }
                None => info!("API keys file {path} does not exist yet, skipping"),
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

    /// Ok(true) if any `path` in `paths` has an mtime that differs from
    /// what this cache has recorded (including "file now exists" and
    /// "file now gone").
    fn any_mtime_changed(&self, paths: &[String]) -> Result<bool, (String, std::io::Error)> {
        for path in paths {
            let now = ApiKeysFile::stat_mtime(path).map_err(|e| (path.clone(), e))?;
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
                warn!("cannot stat {path}: {e}, skipping reload (keeping cached API keys)");
            }
        }
    }

    fn reload(&mut self, paths: &[String]) {
        let mut new_files = HashMap::new();
        for path in paths {
            let Ok(Some(mtime)) = ApiKeysFile::stat_mtime(path) else {
                continue; // file is gone or unreadable; drop its cached keys
            };
            let entries = match ApiKeysFile::parse_keys(path) {
                Ok(entries) => {
                    info!(
                        "reloaded {count} API key(s) from {path} (file changed)",
                        count = entries.len(),
                    );
                    entries
                }
                Err(e) => {
                    warn!("failed to reload {path}: {e:#}, skipping this source");
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

pub(crate) struct ApiKeyAuthenticator {
    paths: Vec<String>,
    keys: Mutex<ApiKeyCache>,
}

impl ApiKeyAuthenticator {
    pub(crate) fn new(paths: Vec<String>) -> anyhow::Result<Self> {
        let cache = ApiKeyCache::load_all(&paths)?;
        Ok(Self {
            paths,
            keys: Mutex::new(cache),
        })
    }

    pub(crate) fn key_count(&self) -> usize {
        self.keys.lock().unwrap().key_count()
    }
}

impl std::fmt::Debug for ApiKeyAuthenticator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApiKeyAuthenticator")
            .field("paths", &self.paths)
            .field("key_count", &self.key_count())
            .finish_non_exhaustive()
    }
}

impl Authenticator for ApiKeyAuthenticator {
    fn check_request(&self, request: &AuthRequest) -> anyhow::Result<()> {
        let mut keys = self.keys.lock().unwrap();
        keys.maybe_reload(&self.paths);

        let key = request.bearer_token()?;
        let digest = openssl::sha::sha256(key.as_bytes());
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
/// The hierarchy contributes only its highest-precedence file; a
/// credential of the same name is merged on top.
// TODO: discover -> build -> warn-if-empty -> log is the same shape as
// create_ssh_authenticator; fold into the WatchedFiles<T> extraction.
pub(crate) fn create_api_key_authenticator(
    cli_api_keys: Option<String>,
    creds_dir: Option<&std::path::Path>,
    root: &std::path::Path,
) -> anyhow::Result<Option<ApiKeyAuthenticator>> {
    let paths: Vec<String> = if let Some(cli_path) = cli_api_keys {
        vec![cli_path]
    } else {
        let paths: Vec<String> = find_config(API_KEYS_CONFIG, root)
            .into_iter()
            .chain(
                creds_dir
                    .map(CredentialsLoader::from_dir)
                    .and_then(|creds| creds.path(API_KEYS_CREDENTIAL)),
            )
            .map(|p| p.to_string_lossy().into_owned())
            .collect();
        if paths.is_empty() {
            return Ok(None);
        }
        paths
    };

    let api_key_auth = ApiKeyAuthenticator::new(paths.clone())?;
    if api_key_auth.key_count() == 0 {
        warn!(
            "no API keys in {}; API key auth will reject all requests until keys appear",
            paths.join(", "),
        );
    }
    info!(
        "Authenticator: adding API keys ({count} key(s) from {sources})",
        count = api_key_auth.key_count(),
        sources = paths.join(", "),
    );
    Ok(Some(api_key_auth))
}

#[derive(Debug)]
pub(crate) struct GenApiKey {
    pub name: Option<String>,
    pub output: Option<String>,
}

fn default_api_keys_path() -> String {
    // not find_config(): a write target must be named even when absent
    if rustix::process::getuid().is_root() {
        return std::path::Path::new("/etc")
            .join(API_KEYS_CONFIG)
            .to_string_lossy()
            .into_owned();
    }
    let config_dir = std::env::var_os("XDG_CONFIG_HOME").map_or_else(
        || {
            let home = std::env::var_os("HOME").unwrap_or_else(|| "/root".into());
            std::path::Path::new(&home).join(".config")
        },
        std::path::PathBuf::from,
    );
    config_dir
        .join(API_KEYS_CONFIG)
        .to_string_lossy()
        .into_owned()
}

pub(crate) fn generate_api_key() -> String {
    let mut buf = [0u8; 32];
    openssl::rand::rand_bytes(&mut buf).expect("openssl PRNG failed");
    format!("{API_KEY_PREFIX}{}", HEXLOWER.encode(&buf))
}

/// Append the hash line for `key` to the API keys file at `path`,
/// returning the name it was stored under.
pub(crate) fn append_api_key(
    path: &std::path::Path,
    key: &str,
    name: Option<&str>,
) -> anyhow::Result<String> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

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
    let name = append_api_key(
        std::path::Path::new(&output_path),
        &key,
        cmd.name.as_deref(),
    )?;

    // The key itself goes to stdout (and nowhere else) so that
    // `API_KEY=$(varlink-httpd gen-api-key)` works; only its hash is stored.
    println!("{key}");
    eprintln!("Appended hash of API key '{name}' to {output_path}, run with:");
    if output_path == "/etc/varlink-httpd/api-keys" {
        eprintln!("  varlink-httpd");
    } else {
        eprintln!("  varlink-httpd --api-keys={output_path}");
    }
    Ok(())
}
