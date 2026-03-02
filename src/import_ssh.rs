// SPDX-License-Identifier: LGPL-2.1-or-later

use anyhow::{Context, bail};
use std::io::Write;

#[derive(Debug)]
pub(crate) struct ImportSsh {
    pub source: String,
    pub output: Option<String>,
}

fn resolve_key_url(source: &str) -> anyhow::Result<String> {
    if let Some(user) = source.strip_prefix("gh:") {
        Ok(format!("https://github.com/{user}.keys"))
    } else if source.starts_with("https://") {
        Ok(source.to_string())
    } else {
        bail!("unsupported source: {source} (use `gh:<user>` or an `https://` URL)")
    }
}

fn default_authorized_keys_path() -> String {
    if let Some(creds_dir) = std::env::var_os("CREDENTIALS_DIRECTORY") {
        return std::path::Path::new(&creds_dir)
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
    let url = resolve_key_url(&cmd.source)?;

    let output_path = cmd.output.unwrap_or_else(default_authorized_keys_path);

    let tls = ureq::tls::TlsConfig::builder()
        .provider(ureq::tls::TlsProvider::NativeTls)
        .build();
    let agent = ureq::config::Config::builder()
        .tls_config(tls)
        .build()
        .new_agent();
    let body = agent
        .get(&url)
        .call()
        .with_context(|| format!("failed to fetch keys from {url}"))?
        .body_mut()
        .with_config()
        .limit(640 * 1024) // 640KB ought to be enough for anybody (default of 10mb is a bit much)
        .read_to_string()
        .with_context(|| format!("failed to read response body from {url}"))?;

    let out = std::path::Path::new(&output_path);
    let parent = out
        .parent()
        .ok_or_else(|| anyhow::anyhow!("cannot determine parent directory of {output_path}"))?;
    std::fs::create_dir_all(parent)
        .with_context(|| format!("failed to create directory {}", parent.display()))?;

    // Write to tempfile first...
    let mut tmp_authorized_keys = tempfile::NamedTempFile::new_in(parent)
        .with_context(|| format!("failed to create tempfile in {}", parent.display()))?;
    tmp_authorized_keys
        .write_all(body.as_bytes())
        .with_context(|| format!("failed to write tempfile in {}", parent.display()))?;

    // Then validate before committing. A typo in the URL returning an
    // HTML page instead of the keys would otherwise overwrite a good
    // authorized_keys file and lock out all users.
    let keys = sshauth::keyfile::parse_authorized_keys(tmp_authorized_keys.path(), true)
        .with_context(|| format!("response from {url} contains invalid SSH public keys"))?;
    if keys.is_empty() {
        bail!("no valid SSH public keys found in response from {url}");
    }

    tmp_authorized_keys
        .persist(out)
        .with_context(|| format!("failed to rename tempfile to {output_path}"))?;

    eprintln!(
        "Wrote {keys_count} key(s) to {output_path}, run with:",
        keys_count = keys.len()
    );
    if std::env::var_os("CREDENTIALS_DIRECTORY").is_some() {
        eprintln!("  varlink-httpd");
    } else {
        eprintln!("  varlink-httpd --authorized-keys={output_path}");
    }

    Ok(())
}
