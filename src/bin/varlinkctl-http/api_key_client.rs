// SPDX-License-Identifier: LGPL-2.1-or-later

//! Client-side API key support: the key is obtained out of band (see
//! `varlink-httpd gen-api-key`) and simply attached as
//! `Authorization: Bearer <key>`.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use futures_util::future::LocalBoxFuture;
use log::debug;

use varlink_http_bridge::secret_file::{SecretAccess, read_secret_file};

use crate::client_auth::ClientAuth;

/// Environment variable carrying the API key itself (not a path, unlike
/// `VARLINK_SSH_KEY`); surrounding whitespace is trimmed so a key piped in
/// with a trailing newline still works.
const VARLINK_API_KEY_ENV: &str = "VARLINK_API_KEY";

const API_KEY_FILE: &str = "api-key";

fn api_key_path() -> Option<PathBuf> {
    crate::config_dir()
        .map(|dir| dir.join(API_KEY_FILE))
        .filter(|path| path.exists())
}

/// Trimmed so a trailing newline works; an empty file is unset, not an empty
/// key.
fn key_from_file(path: &Path) -> Result<Option<String>> {
    let key = read_secret_file(path, SecretAccess::OwnerAndGroup)?;
    let key = key.trim();
    Ok((!key.is_empty()).then(|| key.to_string()))
}

/// The environment wins over the file, so a one-off key can override the
/// configured one without editing it away.
fn api_key() -> Result<Option<String>> {
    if let Ok(key) = std::env::var(VARLINK_API_KEY_ENV) {
        let key = key.trim();
        if !key.is_empty() {
            debug!("API key auth: using the key from {VARLINK_API_KEY_ENV}");
            return Ok(Some(key.to_string()));
        }
    }
    let Some(path) = api_key_path() else {
        return Ok(None);
    };
    let key = key_from_file(&path)?;
    if key.is_some() {
        debug!("API key auth: using the key from {}", path.display());
    }
    Ok(key)
}

pub(crate) struct ApiKeyBearer;

impl ClientAuth for ApiKeyBearer {
    fn name(&self) -> &'static str {
        "API key auth (VARLINK_API_KEY or the api-key config file)"
    }

    fn configured(&self) -> bool {
        std::env::var_os(VARLINK_API_KEY_ENV).is_some() || api_key_path().is_some()
    }

    fn connect<'a>(&'a self, url: &'a str) -> LocalBoxFuture<'a, Result<Option<crate::Ws>>> {
        Box::pin(connect_with_api_key(url))
    }
}

/// `Ok(None)` when no API key is set. One credential only, so unlike the
/// SSH method there is nothing to retry.
async fn connect_with_api_key(url: &str) -> Result<Option<crate::Ws>> {
    let Some(api_key) = api_key()? else {
        return Ok(None);
    };

    let (stream, mut request, tcb) = crate::connect_transport(url).await?;
    request.headers_mut().insert(
        "Authorization",
        format!("Bearer {api_key}")
            .parse()
            .context("the API key is not a valid HTTP header value")?,
    );
    let ws = crate::ws_upgrade(request, stream, tcb.is_some()).await?;
    Ok(Some(ws))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn write_fake_key(path: &Path, content: &str, mode: u32) {
        std::fs::write(path, content).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    #[test]
    fn test_key_from_file_trims_and_treats_empty_as_unset() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(API_KEY_FILE);

        write_fake_key(&path, "vhb_abc\n", 0o600);
        assert_eq!(key_from_file(&path).unwrap().as_deref(), Some("vhb_abc"));

        write_fake_key(&path, "  \n\t ", 0o600);
        assert_eq!(
            key_from_file(&path).unwrap(),
            None,
            "a whitespace-only file must not become an empty bearer key"
        );
    }

    #[test]
    fn test_key_from_file_refuses_world_readable_but_allows_group() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(API_KEY_FILE);

        write_fake_key(&path, "vhb_abc\n", 0o644);
        let err = format!("{:#}", key_from_file(&path).unwrap_err());
        assert!(err.contains("0644"), "{err}");

        // a root-owned /etc copy shared with a group is a supported setup
        write_fake_key(&path, "vhb_abc\n", 0o640);
        assert_eq!(key_from_file(&path).unwrap().as_deref(), Some("vhb_abc"));
    }

    #[test]
    fn test_key_from_file_reports_the_path_on_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("missing");
        let err = format!("{:#}", key_from_file(&path).unwrap_err());
        assert!(err.contains(&path.display().to_string()), "{err}");
    }
}
