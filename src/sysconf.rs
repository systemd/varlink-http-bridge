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

    /// Trimmed content of a scalar credential, if present and non-empty.
    #[must_use]
    pub fn get_string(&self, id: &str) -> Option<String> {
        let path = self.path(id)?;
        std::fs::read_to_string(path)
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
    }

    /// Non-empty, non-`#` lines of a list credential.
    #[must_use]
    pub fn get_lines(&self, id: &str) -> Vec<String> {
        self.path(id)
            .and_then(|path| std::fs::read_to_string(path).ok())
            .map(|s| {
                s.lines()
                    .map(str::trim)
                    .filter(|l| !l.is_empty() && !l.starts_with('#'))
                    .map(String::from)
                    .collect()
            })
            .unwrap_or_default()
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
    fn test_credentials_loader_content() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("scalar"), "  value\n").unwrap();
        std::fs::write(dir.path().join("list"), "a\n# comment\n\n b \n").unwrap();

        let loader = CredentialsLoader::from_dir(dir.path());
        assert_eq!(loader.get_string("scalar").as_deref(), Some("value"));
        assert_eq!(loader.get_string("missing"), None);
        assert_eq!(
            loader.get_lines("list"),
            vec!["a".to_string(), "b".to_string()]
        );
        assert_eq!(loader.get_lines("missing"), Vec::<String>::new());
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
