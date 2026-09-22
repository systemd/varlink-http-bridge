// SPDX-License-Identifier: LGPL-2.1-or-later

//! Locating service configuration the systemd way: credentials passed via
//! `$CREDENTIALS_DIRECTORY` (see systemd.exec(5) / systemd.system-credentials(7)),
//! and config files in the `/etc` > `/run` > `/usr/lib` precedence hierarchy.

use std::path::{Path, PathBuf};

/// Mirrors (and extends) libsystemd's `CredentialsLoader`: one file per
/// credential, the filename is the credential id. On top of the lookup by
/// id, [`Self::find`] selects credentials by `ImportCredential=` patterns.
#[derive(Clone, Debug)]
pub struct CredentialsLoader {
    dir: PathBuf,
}

impl CredentialsLoader {
    /// The credentials systemd passed to this service, `None` when it
    /// passed none (no `$CREDENTIALS_DIRECTORY`).
    #[must_use]
    pub fn from_env() -> Option<Self> {
        std::env::var_os("CREDENTIALS_DIRECTORY").map(|dir| Self { dir: dir.into() })
    }

    /// Test-only: production code gets its loader from [`Self::from_env`].
    #[cfg(any(test, feature = "test-helpers"))]
    pub fn from_dir(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    /// Path of credential `id`, if the file exists.
    #[must_use]
    pub fn path(&self, id: &str) -> Option<PathBuf> {
        let path = self.expected_path(id);
        path.exists().then_some(path)
    }

    /// Where credential `id` would be, whether or not it exists yet: for a
    /// source that has to be watched before it appears.
    #[must_use]
    pub fn expected_path(&self, id: &str) -> PathBuf {
        self.dir.join(id)
    }

    /// Paths of the credentials matching `patterns`, sorted so the merge
    /// order is stable.
    ///
    /// Patterns use the `ImportCredential=` syntax of systemd.exec(5): an
    /// exact id, or a prefix with a trailing `*`. The latter is for
    /// per-provider credentials (`<id>.<provider>`).
    ///
    /// # Errors
    /// A missing directory means no credentials; other errors propagate so the
    /// caller can keep what it already loaded rather than lose sources silently.
    pub fn find(&self, patterns: &[&str]) -> std::io::Result<Vec<PathBuf>> {
        self.find_with(patterns, |id| self.dir.join(id))
    }

    /// [`Self::find`], with each matching id handed to `f` in sorted order.
    ///
    /// # Errors
    /// As for [`Self::find`].
    pub fn find_with<T>(
        &self,
        patterns: &[&str],
        f: impl Fn(&str) -> T,
    ) -> std::io::Result<Vec<T>> {
        let entries = match std::fs::read_dir(&self.dir) {
            Ok(entries) => entries,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(e),
        };
        let mut ids = Vec::new();
        for entry in entries {
            let Some(id) = entry?.file_name().to_str().map(String::from) else {
                continue;
            };
            if patterns.iter().any(|p| pattern_matches(p, &id)) {
                ids.push(id);
            }
        }
        ids.sort();
        Ok(ids.iter().map(|id| f(id)).collect())
    }
}

/// The authentication key sources of one auth mechanism right now:
/// its fixed `paths` plus the credentials matching `patterns`,
/// re-enumerated on every call because `RefreshOnReload=credentials`
/// swaps in a fresh tree on `systemctl reload`, so credentials come
/// and go while the service runs.
///
/// # Errors
/// As for [`CredentialsLoader::find`]; the caller keeps its cached keys.
pub fn current_key_sources(
    paths: &[PathBuf],
    creds: Option<&CredentialsLoader>,
    credential_patterns: &[&str],
) -> std::io::Result<Vec<PathBuf>> {
    let mut all = paths.to_vec();
    if let Some(creds) = creds {
        all.extend(creds.find(credential_patterns)?);
    }
    Ok(all)
}

/// `ImportCredential=` matching: only a trailing `*` is a glob.
fn pattern_matches(pattern: &str, name: &str) -> bool {
    match pattern.strip_suffix('*') {
        Some(prefix) => {
            debug_assert!(
                !prefix.contains('*'),
                "only a trailing * is a glob: {pattern}"
            );
            name.starts_with(prefix)
        }
        None => name == pattern,
    }
}

/// Highest-precedence existing config file for `rel`, following the systemd
/// hierarchy (`/etc` over `/run` over `/usr/lib`). `root` is `/` in
/// production, a tempdir in tests.
#[must_use]
pub fn find_config(rel: &str, root: &Path) -> Option<PathBuf> {
    ["etc", "run", "usr/lib"]
        .into_iter()
        .map(|base| root.join(base).join(rel))
        .find(|path| path.exists())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_credentials_loader_path() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("cert"), "dummy").unwrap();

        let loader = CredentialsLoader::from_dir(dir.path());
        assert_eq!(loader.path("cert"), Some(dir.path().join("cert")));
        assert_eq!(loader.path("missing"), None);
        assert_eq!(
            loader.expected_path("missing"),
            dir.path().join("missing"),
            "a not-yet-existing credential still has a known location"
        );
    }

    #[test]
    fn test_credentials_loader_find_import_credential_patterns() {
        const PATTERNS: &[&str] = &[
            "varlink-httpd.api-keys",
            "ssh.authorized_keys.root",
            "varlink-httpd.api-keys.*",
        ];
        let dir = tempfile::tempdir().unwrap();
        for name in [
            "varlink-httpd.api-keys.b",
            "varlink-httpd.api-keys.a",
            "varlink-httpd.api-keys",
            "varlink-httpd.api-keys-backup",
            "ssh.authorized_keys.root",
            "api-keys",
            "unrelated",
        ] {
            std::fs::write(dir.path().join(name), "dummy").unwrap();
        }

        let loader = CredentialsLoader::from_dir(dir.path());
        assert_eq!(
            loader.find(PATTERNS).unwrap(),
            vec![
                dir.path().join("ssh.authorized_keys.root"),
                dir.path().join("varlink-httpd.api-keys"),
                dir.path().join("varlink-httpd.api-keys.a"),
                dir.path().join("varlink-httpd.api-keys.b"),
            ],
            "exact ids and trailing-* globs, sorted; no look-alikes"
        );
        assert_eq!(
            loader
                .find_with(PATTERNS, |id| format!("{id} (unused)"))
                .unwrap(),
            vec![
                "ssh.authorized_keys.root (unused)",
                "varlink-httpd.api-keys (unused)",
                "varlink-httpd.api-keys.a (unused)",
                "varlink-httpd.api-keys.b (unused)",
            ],
            "the closure sees the ids, in the same order as find()"
        );
        assert!(
            loader.find(&["nomatch.*"]).unwrap().is_empty(),
            "no match is not an error"
        );

        let missing = CredentialsLoader::from_dir(dir.path().join("nonexistent"));
        assert!(
            missing.find(PATTERNS).unwrap().is_empty(),
            "a missing credentials directory means no credentials"
        );
        assert!(
            missing
                .find_with(PATTERNS, str::to_string)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn test_current_key_sources_is_fixed_paths_plus_credentials() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("svc.keys.a"), "dummy").unwrap();
        std::fs::write(dir.path().join("other"), "dummy").unwrap();
        let fixed = vec![PathBuf::from("/etc/svc/keys")];
        let loader = CredentialsLoader::from_dir(dir.path());

        assert_eq!(
            current_key_sources(&fixed, Some(&loader), &["svc.keys.*"]).unwrap(),
            vec![
                PathBuf::from("/etc/svc/keys"),
                dir.path().join("svc.keys.a")
            ],
            "fixed paths first, then the matching credentials"
        );
        assert_eq!(
            current_key_sources(&fixed, None, &["svc.keys.*"]).unwrap(),
            fixed,
            "no credentials directory adds nothing"
        );
    }

    #[test]
    fn test_find_config_precedence() {
        let root = tempfile::tempdir().unwrap();
        let rel = "varlink-httpd/api-keys";
        let write = |base: &str| {
            let p = root.path().join(base).join(rel);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(&p, base).unwrap();
            p
        };

        assert_eq!(find_config(rel, root.path()), None);

        let usr = write("usr/lib");
        assert_eq!(find_config(rel, root.path()), Some(usr));
        let run = write("run");
        assert_eq!(find_config(rel, root.path()), Some(run));
        let etc = write("etc");
        assert_eq!(find_config(rel, root.path()), Some(etc));
    }
}
