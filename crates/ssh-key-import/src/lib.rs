// SPDX-License-Identifier: LGPL-2.1-or-later

//! Fetch and validate SSH `authorized_keys` from a remote source.
//!
//! Shared by `varlink-httpd import-ssh` and `amutablectl` so the
//! `gh:<user>` / `https://` resolution and key validation live in one
//! place instead of being duplicated per consumer.

use anyhow::{Context, bail};
use std::io::Write as _;
use std::time::Duration;

pub use ssh_key;

/// A validated set of authorized keys.
pub struct AuthorizedKeys {
    /// The raw response text, exactly as fetched, suitable to persist verbatim.
    pub text: String,
    /// The parsed public keys (guaranteed non-empty when returned from [`fetch`]).
    pub keys: Vec<ssh_key::PublicKey>,
}

/// Resolve a key `source` to an `https://` URL.
///
/// Accepts `gh:<user>` (that user's published GitHub keys) or a literal
/// `https://` URL. Other schemes (including plain `http://`) are rejected:
/// the fetched keys are trusted verbatim, so the transport must be
/// authenticated.
///
/// # Errors
/// Fails if `source` is neither `gh:<user>` nor an `https://` URL.
pub fn resolve_key_url(source: &str) -> anyhow::Result<String> {
    if let Some(user) = source.strip_prefix("gh:") {
        Ok(format!("https://github.com/{user}.keys"))
    } else if source.starts_with("https://") {
        Ok(source.to_string())
    } else {
        bail!("unsupported source: {source} (use `gh:<user>` or an `https://` URL)")
    }
}

/// 640KB ought to be enough for anybody (ureq's default of 10MB is a bit much).
const BODY_LIMIT: u64 = 640 * 1024;

/// Bounds the whole exchange so a stalled endpoint cannot hang the import.
const FETCH_TIMEOUT: Duration = Duration::from_secs(30);

/// Fetch authorized keys from `source`, validate them, and return the raw
/// text together with the parsed keys.
///
/// # Errors
/// Fails if the source is unsupported, the HTTP request fails, or the
/// response contains no valid SSH public keys (e.g. an HTML error page
/// from a mistyped URL).
pub fn fetch(source: &str) -> anyhow::Result<AuthorizedKeys> {
    let url = resolve_key_url(source)?;

    // resolve_key_url has already guaranteed https; https_only keeps a
    // redirect from downgrading away from it, which matters because the keys
    // below are trusted verbatim.
    let text =
        http_fetch::Fetcher::new(true, FETCH_TIMEOUT, BODY_LIMIT).get(&url, "authorized keys")?;

    let keys = validate(&text)
        .with_context(|| format!("response from {url} contains invalid SSH public keys"))?;
    if keys.is_empty() {
        bail!("no valid SSH public keys found in response from {url}");
    }

    Ok(AuthorizedKeys { text, keys })
}

/// Parse `text` as an `authorized_keys` file and return the public keys.
///
/// # Errors
/// Fails if `text` is not valid `authorized_keys` syntax.
pub fn validate(text: &str) -> anyhow::Result<Vec<ssh_key::PublicKey>> {
    // sshauth parses from a path, so stage the bytes in a tempfile.
    let mut tmp = tempfile::NamedTempFile::new().context("failed to create tempfile")?;
    tmp.write_all(text.as_bytes())
        .context("failed to write tempfile")?;
    sshauth::keyfile::parse_authorized_keys(tmp.path(), true)
        .context("failed to parse authorized keys")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_gh_shorthand() {
        assert_eq!(
            resolve_key_url("gh:octocat").unwrap(),
            "https://github.com/octocat.keys"
        );
    }

    #[test]
    fn resolve_https_passthrough() {
        let url = "https://example.com/keys";
        assert_eq!(resolve_key_url(url).unwrap(), url);
    }

    #[test]
    fn resolve_rejects_other_schemes() {
        assert!(resolve_key_url("http://example.com/keys").is_err());
        assert!(resolve_key_url("octocat").is_err());
        assert!(resolve_key_url("ftp://example.com").is_err());
    }

    #[test]
    fn validate_rejects_garbage() {
        assert!(validate("<!DOCTYPE html><html>not a key</html>").is_err());
    }
}
