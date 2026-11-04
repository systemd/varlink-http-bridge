// SPDX-License-Identifier: LGPL-2.1-or-later

//! Permission checks for secret files, shared by the daemon and the client.

use std::fs::{File, Metadata};
use std::io::Read;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;

use anyhow::{Context, bail};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretAccess {
    OwnerOnly,
    /// Lets a root-owned file under /etc be shared with a dedicated group.
    OwnerAndGroup,
}

impl SecretAccess {
    fn forbidden_bits(self) -> u32 {
        match self {
            Self::OwnerOnly => 0o077,
            Self::OwnerAndGroup => 0o007,
        }
    }

    fn requirement(self) -> &'static str {
        match self {
            Self::OwnerOnly => "group- or world-accessible",
            Self::OwnerAndGroup => "world-accessible",
        }
    }
}

/// Only forbidden bits are checked, so 0400 passes wherever 0600 does. The
/// owner must be us or root: mode bits say who may read the file, not who
/// wrote it.
fn check_secret_metadata(
    path: &Path,
    metadata: &Metadata,
    access: SecretAccess,
) -> anyhow::Result<()> {
    if !metadata.is_file() {
        bail!("refusing to use {}: not a regular file", path.display());
    }
    let uid = metadata.uid();
    if uid != 0 && uid != rustix::process::geteuid().as_raw() {
        bail!(
            "refusing to use {}: owned by uid {uid}, must be owned by us or root",
            path.display()
        );
    }
    let mode = metadata.permissions().mode() & 0o777;
    if mode & access.forbidden_bits() != 0 {
        bail!(
            "refusing to use {}: permissions are 0{mode:o}, must not be {}",
            path.display(),
            access.requirement()
        );
    }
    Ok(())
}

/// For files a library such as openssl opens by path afterwards. Inherently
/// racy: the file can be swapped between this check and that open, so prefer
/// [`read_secret_file`] whenever possible.
///
/// # Errors
/// If `path` cannot be stat'ed, is not a regular file owned by us or root,
/// or is too open.
pub fn check_secret_file(path: &Path, access: SecretAccess) -> anyhow::Result<()> {
    let metadata = std::fs::metadata(path).with_context(|| format!("stat {}", path.display()))?;
    check_secret_metadata(path, &metadata, access)
}

/// Checks the opened handle rather than the path, so the file that was
/// checked is the file that is read.
///
/// # Errors
/// If `path` cannot be read, is not a regular file owned by us or root, or
/// is too open.
pub fn read_secret_file(path: &Path, access: SecretAccess) -> anyhow::Result<String> {
    let mut file = File::open(path).with_context(|| format!("reading {}", path.display()))?;
    let metadata = file
        .metadata()
        .with_context(|| format!("stat {}", path.display()))?;
    check_secret_metadata(path, &metadata, access)?;
    let mut content = String::new();
    file.read_to_string(&mut content)
        .with_context(|| format!("reading {}", path.display()))?;
    Ok(content)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secret_with_mode(dir: &Path, mode: u32) -> std::path::PathBuf {
        let path = dir.join(format!("secret-{mode:o}"));
        std::fs::write(&path, "s3cret\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
        path
    }

    #[test]
    fn owner_only_refuses_group_and_world() {
        let dir = tempfile::tempdir().unwrap();
        for mode in [0o600, 0o400] {
            let path = secret_with_mode(dir.path(), mode);
            read_secret_file(&path, SecretAccess::OwnerOnly)
                .unwrap_or_else(|e| panic!("0{mode:o} must be accepted: {e:#}"));
        }
        for mode in [0o640, 0o604, 0o644, 0o660] {
            let path = secret_with_mode(dir.path(), mode);
            let err = format!(
                "{:#}",
                read_secret_file(&path, SecretAccess::OwnerOnly).unwrap_err()
            );
            assert!(
                err.contains(&format!("0{mode:o}")) && err.contains("group- or world-accessible"),
                "0{mode:o} must be refused naming the mode, got: {err}"
            );
        }
    }

    #[test]
    fn owner_and_group_refuses_only_world() {
        let dir = tempfile::tempdir().unwrap();
        for mode in [0o600, 0o640, 0o660] {
            let path = secret_with_mode(dir.path(), mode);
            check_secret_file(&path, SecretAccess::OwnerAndGroup)
                .unwrap_or_else(|e| panic!("0{mode:o} must be accepted: {e:#}"));
        }
        for mode in [0o604, 0o644, 0o601] {
            let path = secret_with_mode(dir.path(), mode);
            let err = format!(
                "{:#}",
                check_secret_file(&path, SecretAccess::OwnerAndGroup).unwrap_err()
            );
            assert!(
                err.contains(&format!("0{mode:o}")) && err.contains("must not be world-accessible"),
                "0{mode:o} must be refused naming the mode, got: {err}"
            );
        }
    }

    #[test]
    fn refuses_anything_but_a_regular_file() {
        let dir = tempfile::tempdir().unwrap();
        let err = format!(
            "{:#}",
            check_secret_file(dir.path(), SecretAccess::OwnerOnly).unwrap_err()
        );
        assert!(err.contains("not a regular file"), "{err}");
        let err = format!(
            "{:#}",
            read_secret_file(dir.path(), SecretAccess::OwnerOnly).unwrap_err()
        );
        assert!(err.contains("not a regular file"), "{err}");
    }

    // only root can hand a file to another user, so this runs in CI (mkosi)
    // and is a no-op for a developer's cargo test
    #[test]
    fn refuses_a_file_owned_by_someone_else() {
        if !rustix::process::geteuid().is_root() {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let path = secret_with_mode(dir.path(), 0o600);
        let nobody = 65534;
        std::os::unix::fs::chown(&path, Some(nobody), None).unwrap();
        let err = format!(
            "{:#}",
            check_secret_file(&path, SecretAccess::OwnerOnly).unwrap_err()
        );
        assert!(err.contains("owned by uid 65534"), "{err}");
    }

    #[test]
    fn read_returns_the_content_and_names_a_missing_path() {
        let dir = tempfile::tempdir().unwrap();
        let path = secret_with_mode(dir.path(), 0o600);
        assert_eq!(
            read_secret_file(&path, SecretAccess::OwnerOnly).unwrap(),
            "s3cret\n"
        );

        let missing = dir.path().join("missing");
        let err = format!(
            "{:#}",
            read_secret_file(&missing, SecretAccess::OwnerOnly).unwrap_err()
        );
        assert!(err.contains(&missing.display().to_string()), "{err}");
    }
}
