// SPDX-License-Identifier: LGPL-2.1-or-later

//! Locating service configuration the systemd way: credentials passed via
//! `$CREDENTIALS_DIRECTORY` (see systemd.exec(5) / systemd.system-credentials(7)),
//! and config files in the `/etc` > `/run` > `/usr/lib` precedence hierarchy.

use std::path::{Path, PathBuf};

/// Mirrors libsystemd's `CredentialsLoader`: one file per credential,
/// filename = credential id.
pub struct CredentialsLoader {
    dir: PathBuf,
}

impl CredentialsLoader {
    #[must_use]
    pub fn path_from_env() -> Option<PathBuf> {
        std::env::var_os("CREDENTIALS_DIRECTORY").map(PathBuf::from)
    }

    /// Loader rooted at an explicit directory (mainly for tests).
    pub fn from_dir(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    /// Path of credential `id`, if the file exists.
    #[must_use]
    pub fn path(&self, id: &str) -> Option<PathBuf> {
        let path = self.dir.join(id);
        path.exists().then_some(path)
    }

    /// Sorted, so the merge order is stable.
    ///
    /// # Errors
    /// A missing directory means no credentials; other errors propagate so the
    /// caller can keep what it already loaded rather than lose sources silently.
    pub fn paths_with_prefix(&self, prefix: &str) -> std::io::Result<Vec<PathBuf>> {
        let entries = match std::fs::read_dir(&self.dir) {
            Ok(entries) => entries,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(e),
        };
        let mut paths = Vec::new();
        for entry in entries {
            let entry = entry?;
            if entry
                .file_name()
                .to_str()
                .is_some_and(|name| name.starts_with(prefix))
            {
                paths.push(entry.path());
            }
        }
        paths.sort();
        Ok(paths)
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
    }

    #[test]
    fn test_credentials_loader_paths_with_prefix() {
        let dir = tempfile::tempdir().unwrap();
        for name in [
            "varlink-httpd.api-keys.b",
            "varlink-httpd.api-keys.a",
            "api-keys",
            "unrelated",
        ] {
            std::fs::write(dir.path().join(name), "dummy").unwrap();
        }

        let loader = CredentialsLoader::from_dir(dir.path());
        assert_eq!(
            loader.paths_with_prefix("varlink-httpd.api-keys.").unwrap(),
            vec![
                dir.path().join("varlink-httpd.api-keys.a"),
                dir.path().join("varlink-httpd.api-keys.b"),
            ],
            "only prefixed credentials, sorted"
        );
        assert!(
            loader.paths_with_prefix("nomatch.").unwrap().is_empty(),
            "no match is not an error"
        );

        let missing = CredentialsLoader::from_dir(dir.path().join("nonexistent"));
        assert!(
            missing
                .paths_with_prefix("varlink-httpd.")
                .unwrap()
                .is_empty(),
            "a missing credentials directory means no credentials"
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
