// SPDX-License-Identifier: LGPL-2.1-or-later

//! Client-side API key support: the key is obtained out of band (see
//! `varlink-httpd gen-api-key`) and simply attached as
//! `Authorization: Bearer <key>`.

use anyhow::{Context, Result};
use futures_util::future::LocalBoxFuture;
use log::debug;

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

    fn connect<'a>(&'a self, url: &'a str) -> LocalBoxFuture<'a, Result<Option<crate::Ws>>> {
        Box::pin(connect_with_api_key(url))
    }
}

/// `Ok(None)` when no API key is set. One credential only, so unlike the
/// SSH method there is nothing to retry.
async fn connect_with_api_key(url: &str) -> Result<Option<crate::Ws>> {
    let Ok(api_key) = std::env::var(VARLINK_API_KEY_ENV) else {
        return Ok(None);
    };
    let api_key = api_key.trim();
    if api_key.is_empty() {
        return Ok(None);
    }

    let (stream, mut request, tcb) = crate::connect_transport(url).await?;
    request.headers_mut().insert(
        "Authorization",
        format!("Bearer {api_key}")
            .parse()
            .context("VARLINK_API_KEY is not a valid HTTP header value")?,
    );
    debug!("API key auth: attached bearer key from {VARLINK_API_KEY_ENV}");
    let ws = crate::ws_upgrade(request, stream, tcb.is_some()).await?;
    Ok(Some(ws))
}
