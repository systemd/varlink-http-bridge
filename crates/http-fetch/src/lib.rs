// SPDX-License-Identifier: LGPL-2.1-or-later

//! A small HTTP GET helper for fetching material we go on to trust.
//!
//! Both the SSH `authorized_keys` import and the JWT JWKS fetch need the same
//! three properties -- a bounded body, a bounded wait, and redirects that
//! cannot leave https -- and getting any of them wrong is a security problem
//! rather than a bug. Keeping the policy in one place means it is decided
//! once instead of per caller.

use anyhow::Context;
use std::time::Duration;

/// A GET client with a fixed body cap, timeout and redirect policy.
pub struct Fetcher {
    agent: ureq::Agent,
    body_limit: u64,
}

impl Fetcher {
    /// `body_limit` caps the response against a hostile or broken endpoint and
    /// `timeout` bounds the whole exchange, so a stalled endpoint cannot hang
    /// the caller.
    ///
    /// Redirect targets are not seen by whatever validated the original URL,
    /// so they are constrained here: with `https_only` a redirect may not
    /// leave https, and without it -- the loopback development case, where
    /// plain http is accepted -- redirects are refused outright, since
    /// following one could silently leave the local machine. ureq with
    /// `max_redirects(0)` hands the 3xx response back as a success rather
    /// than erroring, so `get` rejects it explicitly.
    #[must_use]
    pub fn new(https_only: bool, timeout: Duration, body_limit: u64) -> Self {
        let tls = ureq::tls::TlsConfig::builder()
            .provider(ureq::tls::TlsProvider::NativeTls)
            .build();
        let mut config = ureq::config::Config::builder()
            .tls_config(tls)
            .timeout_global(Some(timeout))
            .https_only(https_only);
        if !https_only {
            config = config.max_redirects(0);
        }
        Self {
            agent: config.build().new_agent(),
            body_limit,
        }
    }

    /// GET `url` and return the body as text.
    ///
    /// `what` names the thing being fetched and appears in the error context,
    /// so a failure says which of several fetches went wrong.
    ///
    /// # Errors
    /// Fails if the request fails, the policy above rejects it, or the body is
    /// over the limit or not UTF-8.
    pub fn get(&self, url: &str, what: &str) -> anyhow::Result<String> {
        self.fetch(url, what, None)
    }

    /// Like [`get`](Self::get), but bounded by `timeout` instead of the one
    /// given to [`new`](Self::new), for a caller spending a single budget
    /// across several requests.
    ///
    /// # Errors
    /// As for [`get`](Self::get).
    pub fn get_with_timeout(
        &self,
        url: &str,
        what: &str,
        timeout: Duration,
    ) -> anyhow::Result<String> {
        self.fetch(url, what, Some(timeout))
    }

    fn fetch(&self, url: &str, what: &str, timeout: Option<Duration>) -> anyhow::Result<String> {
        let mut request = self.agent.get(url);
        if let Some(timeout) = timeout {
            request = request.config().timeout_global(Some(timeout)).build();
        }
        let mut response = request
            .call()
            .with_context(|| format!("{what} request to {url} failed"))?;
        if response.status().is_redirection() {
            anyhow::bail!(
                "{what} request to {url} failed: got a redirect ({}) and redirects are not \
                 followed from a plain-http endpoint",
                response.status()
            );
        }
        response
            .body_mut()
            .with_config()
            .limit(self.body_limit)
            .read_to_string()
            .with_context(|| format!("reading {what} from {url}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The https-only policy is enforced before any connection is attempted,
    /// so this needs no server.
    #[test]
    fn https_only_refuses_a_plain_http_url() {
        let fetcher = Fetcher::new(true, Duration::from_secs(1), 1024);
        let err = fetcher.get("http://example.com/keys", "test").unwrap_err();
        assert!(
            format!("{err:#}").contains("test request to http://example.com/keys failed"),
            "unexpected error: {err:#}"
        );
    }

    #[test]
    fn a_malformed_url_is_rejected() {
        let fetcher = Fetcher::new(true, Duration::from_secs(1), 1024);
        assert!(fetcher.get("not a url", "test").is_err());
    }

    /// Serve one connection with a fixed response and return the base URL.
    fn serve_once(response: &'static str) -> String {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            use std::io::{Read, Write};
            let (mut stream, _) = listener.accept().unwrap();
            // Drain the request headers before answering.
            let mut buf = [0u8; 4096];
            let _ = stream.read(&mut buf);
            stream.write_all(response.as_bytes()).unwrap();
        });
        format!("http://{addr}")
    }

    #[test]
    fn a_redirect_from_a_plain_http_endpoint_is_an_error() {
        let base = serve_once(
            "HTTP/1.1 302 Found\r\nLocation: http://example.com/elsewhere\r\n\
             Content-Length: 11\r\nConnection: close\r\n\r\nredirected!",
        );
        let fetcher = Fetcher::new(false, Duration::from_secs(5), 1024);
        let err = fetcher.get(&format!("{base}/keys"), "test").unwrap_err();
        assert!(
            format!("{err:#}").contains("got a redirect (302 Found)"),
            "unexpected error: {err:#}"
        );
    }

    #[test]
    fn a_per_request_timeout_overrides_the_fetcher_timeout() {
        // Accept the connection but never answer.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let (done_tx, done_rx) = std::sync::mpsc::channel::<()>();
        std::thread::spawn(move || {
            let _conn = listener.accept().unwrap();
            let _ = done_rx.recv(); // hold the connection until the test ends
        });
        let fetcher = Fetcher::new(false, Duration::from_secs(60), 1024);
        let start = std::time::Instant::now();
        let err = fetcher
            .get_with_timeout(
                &format!("http://{addr}/keys"),
                "test",
                Duration::from_millis(100),
            )
            .unwrap_err();
        drop(done_tx);
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "per-request timeout not applied: took {:?}",
            start.elapsed()
        );
        assert!(
            format!("{err:#}").contains("test request to http://"),
            "unexpected error: {err:#}"
        );
    }

    #[test]
    fn a_plain_http_success_is_returned() {
        let base =
            serve_once("HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello");
        let fetcher = Fetcher::new(false, Duration::from_secs(5), 1024);
        assert_eq!(
            fetcher.get(&format!("{base}/keys"), "test").unwrap(),
            "hello"
        );
    }
}
