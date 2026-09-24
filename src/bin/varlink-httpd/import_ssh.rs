// SPDX-License-Identifier: LGPL-2.1-or-later

use anyhow::Context;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;

#[derive(Debug)]
pub(crate) struct ImportSsh {
    pub source: String,
    pub output: Option<String>,
}

fn default_authorized_keys_path() -> String {
    if let Some(creds_dir) = varlink_http_bridge::sysconf::CredentialsLoader::path_from_env() {
        return creds_dir
            .join("authorized_keys")
            .to_string_lossy()
            .into_owned();
    }
    if rustix::process::getuid().is_root() {
        return "/etc/varlink-httpd/authorized_keys".to_string();
    }
    let config_dir = std::env::var_os("XDG_CONFIG_HOME").map_or_else(
        || {
            let home = std::env::var_os("HOME").unwrap_or_else(|| "/root".into());
            std::path::Path::new(&home).join(".config")
        },
        std::path::PathBuf::from,
    );
    config_dir
        .join("varlink-httpd/authorized_keys")
        .to_string_lossy()
        .into_owned()
}

/// Write `text` as the authorized_keys at `out`. Mode 0644 because the
/// bridge can run as non-root.
fn write_authorized_keys(out: &std::path::Path, text: &str) -> anyhow::Result<()> {
    let parent = out
        .parent()
        .ok_or_else(|| anyhow::anyhow!("cannot determine parent directory of {}", out.display()))?;
    std::fs::create_dir_all(parent)
        .with_context(|| format!("failed to create directory {}", parent.display()))?;

    // Write to a tempfile in the target directory, then rename, so a
    // reader never observes a partially-written authorized_keys.
    let mut tmp_authorized_keys = tempfile::Builder::new()
        .permissions(std::fs::Permissions::from_mode(0o644))
        .tempfile_in(parent)
        .with_context(|| format!("failed to create tempfile in {}", parent.display()))?;
    tmp_authorized_keys
        .write_all(text.as_bytes())
        .with_context(|| format!("failed to write tempfile in {}", parent.display()))?;
    tmp_authorized_keys
        .persist(out)
        .with_context(|| format!("failed to rename tempfile to {}", out.display()))?;
    Ok(())
}

pub(crate) fn run(cmd: ImportSsh) -> anyhow::Result<()> {
    let output_path = cmd.output.unwrap_or_else(default_authorized_keys_path);

    // Fetch and validate up front. A typo in the URL returning an HTML
    // page instead of keys must not overwrite a good authorized_keys file
    // and lock out all users.
    let imported = ssh_key_import::fetch(&cmd.source)?;

    write_authorized_keys(std::path::Path::new(&output_path), &imported.text)?;

    eprintln!(
        "Wrote {keys_count} key(s) to {output_path}, run with:",
        keys_count = imported.keys.len()
    );
    if varlink_http_bridge::sysconf::CredentialsLoader::path_from_env().is_some() {
        eprintln!("  varlink-httpd --auth=ssh");
    } else {
        eprintln!("  varlink-httpd --auth=ssh --authorized-keys={output_path}");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authorized_keys_are_readable_by_a_non_root_bridge() {
        let tmp = tempfile::tempdir().unwrap();
        let out = tmp.path().join("authorized_keys");
        let keys = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExample user@host\n";

        write_authorized_keys(&out, keys).unwrap();

        assert_eq!(std::fs::read_to_string(&out).unwrap(), keys);
        let mode = std::fs::metadata(&out).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o644);
    }
}
