// SPDX-License-Identifier: LGPL-2.1-or-later

//! Client-side API key support: the key is obtained out of band (see
//! `varlink-httpd gen-api-key`) and simply attached as
//! `Authorization: Bearer <key>`.

use anyhow::{Context, Result};
use futures_util::future::BoxFuture;
use log::debug;
use tokio_tungstenite::tungstenite;

use crate::client_auth::ClientAuth;

/// Environment variable carrying the API key itself (not a path, unlike
/// `VARLINK_SSH_KEY`); surrounding whitespace is trimmed so a key piped in
/// with a trailing newline still works.
const VARLINK_API_KEY_ENV: &str = "VARLINK_API_KEY";

pub(crate) struct ApiKeyBearer;

impl ClientAuth for ApiKeyBearer {
    fn name(&self) -> &'static str {
        "API key auth (VARLINK_API_KEY)"
    }

    fn configured(&self) -> bool {
        std::env::var_os(VARLINK_API_KEY_ENV).is_some()
    }

    fn add_credentials<'a>(
        &'a self,
        request: &'a mut tungstenite::http::Request<()>,
        _tls_channel_binding: Option<&'a str>,
    ) -> BoxFuture<'a, Result<bool>> {
        Box::pin(async move {
            let Ok(api_key) = std::env::var(VARLINK_API_KEY_ENV) else {
                return Ok(false);
            };
            let api_key = api_key.trim();
            if api_key.is_empty() {
                return Ok(false);
            }

            request.headers_mut().insert(
                "Authorization",
                format!("Bearer {api_key}")
                    .parse()
                    .context("VARLINK_API_KEY is not a valid HTTP header value")?,
            );
            debug!("API key auth: attached bearer key from {VARLINK_API_KEY_ENV}");
            Ok(true)
        })
    }
}
