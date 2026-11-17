// SPDX-License-Identifier: LGPL-2.1-or-later

//! Fetch and validate SSH `authorized_keys` from a remote source.
//!
//! Shared by `varlink-httpd import-ssh` and `amutablectl` so the
//! `gh:<user>` / `https://` resolution and key validation live in one
//! place instead of being duplicated per consumer.

use anyhow::{Context, bail};
use std::io::Write as _;

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

/// Fetch authorized keys from `source`, validate them, and return the raw
/// text together with the parsed keys.
///
/// # Errors
/// Fails if the source is unsupported, the HTTP request fails, or the
/// response contains no valid SSH public keys (e.g. an HTML error page
/// from a mistyped URL).
pub fn fetch(source: &str) -> anyhow::Result<AuthorizedKeys> {
    fetch_url(&resolve_key_url(source)?)
}

/// Fetch and validate the authorized keys at `url`, without the checks
/// of [`resolve_key_url`].
fn fetch_url(url: &str) -> anyhow::Result<AuthorizedKeys> {
    let tls = ureq::tls::TlsConfig::builder()
        .provider(ureq::tls::TlsProvider::NativeTls)
        .build();
    let agent = ureq::config::Config::builder()
        .tls_config(tls)
        .build()
        .new_agent();
    let text = agent
        .get(url)
        .call()
        .with_context(|| format!("failed to fetch keys from {url}"))?
        .body_mut()
        .with_config()
        // 640KB ought to be enough for anybody (default of 10mb is a bit much)
        .limit(640 * 1024)
        .read_to_string()
        .with_context(|| format!("failed to read response body from {url}"))?;

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
    sshauth::keyfile::parse_authorized_keys(tmp.path(), false)
        .context("failed to parse authorized keys")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead as _, BufReader};
    use std::net::TcpListener;

    const ED25519_KEY: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDZYUGiotDpNU07XsWdzpzhocaq8GrWroAYBBjHkagdm alice@laptop";

    /// Serve one HTTP reply with `status` and `body` and return its URL.
    fn serve_once(status: &'static str, body: &str) -> String {
        let body = body.to_owned();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/keys", listener.local_addr().unwrap());
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = BufReader::new(stream.try_clone().unwrap());
            let mut line = String::new();
            while request.read_line(&mut line).unwrap() > 2 {
                line.clear();
            }
            write!(
                stream,
                "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
            .unwrap();
        });
        url
    }

    #[test]
    fn fetch_url_returns_the_served_keys() {
        let body = format!("{ED25519_KEY}\n");
        let imported = fetch_url(&serve_once("200 OK", &body)).unwrap();
        assert_eq!(imported.text, body);
        assert_eq!(imported.keys.len(), 1);
        assert_eq!(imported.keys[0].to_openssh().unwrap(), ED25519_KEY);
    }

    #[test]
    fn fetch_url_rejects_a_reply_without_keys() {
        for (status, body, expected) in [
            (
                "200 OK",
                "<!DOCTYPE html><html>not a key</html>",
                "SSH public keys",
            ),
            ("200 OK", "", "no valid SSH public keys"),
            ("404 Not Found", "Not Found", "failed to fetch keys"),
        ] {
            let Err(err) = fetch_url(&serve_once(status, body)) else {
                panic!("{status} {body:?} was accepted");
            };
            assert!(format!("{err:#}").contains(expected), "{err:#}");
        }
    }

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
