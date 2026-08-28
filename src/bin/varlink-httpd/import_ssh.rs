// SPDX-License-Identifier: LGPL-2.1-or-later

use anyhow::Context;
use std::io::Write;

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

pub(crate) fn run(cmd: ImportSsh) -> anyhow::Result<()> {
    let output_path = cmd.output.unwrap_or_else(default_authorized_keys_path);

    // Fetch and validate up front. A typo in the URL returning an HTML
    // page instead of keys must not overwrite a good authorized_keys file
    // and lock out all users.
    let imported = ssh_key_import::fetch(&cmd.source)?;

    let out = std::path::Path::new(&output_path);
    let parent = out
        .parent()
        .ok_or_else(|| anyhow::anyhow!("cannot determine parent directory of {output_path}"))?;
    std::fs::create_dir_all(parent)
        .with_context(|| format!("failed to create directory {}", parent.display()))?;

    // Write to a tempfile in the target directory, then rename, so a
    // reader never observes a partially-written authorized_keys.
    let mut tmp_authorized_keys = tempfile::NamedTempFile::new_in(parent)
        .with_context(|| format!("failed to create tempfile in {}", parent.display()))?;
    tmp_authorized_keys
        .write_all(imported.text.as_bytes())
        .with_context(|| format!("failed to write tempfile in {}", parent.display()))?;
    tmp_authorized_keys
        .persist(out)
        .with_context(|| format!("failed to rename tempfile to {output_path}"))?;

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
