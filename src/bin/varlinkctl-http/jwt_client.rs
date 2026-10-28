// SPDX-License-Identifier: LGPL-2.1-or-later

//! Client-side JWT bearer support
//!
//! The Bearer mode needs no client-side crypto: the token is obtained out of
//! band (pasted, piped from a CI OIDC endpoint, or minted by an issuer helper)
//! and simply attached as `Authorization: Bearer <JWT>`. The proof-of-possession
//! modes (RFC 9421 and `DPoP`) will add request signing here later.

use anyhow::{Context, Result};
use futures_util::future::LocalBoxFuture;
use log::debug;

use crate::client_auth::{ClientAuth, is_http_unauthorized};

/// Environment variable carrying the bearer token itself (not a path, unlike
/// `VARLINK_SSH_KEY`); surrounding whitespace is trimmed so a token piped in
/// with a trailing newline still works.
const VARLINK_JWT_ENV: &str = "VARLINK_JWT";

/// The trimmed token from the environment, or `None` when it is unset or
/// blank. Shared by `configured` and `connect` so the two cannot disagree on
/// what counts as "set" (and warn about ignoring a token that was never used).
fn token_from_env() -> Option<String> {
    let token = std::env::var(VARLINK_JWT_ENV).ok()?;
    let token = token.trim();
    (!token.is_empty()).then(|| token.to_string())
}

pub(crate) struct JwtBearer;

impl ClientAuth for JwtBearer {
    fn name(&self) -> &'static str {
        "JWT bearer auth (VARLINK_JWT)"
    }

    fn configured(&self) -> bool {
        token_from_env().is_some()
    }

    fn connect<'a>(&'a self, url: &'a str) -> LocalBoxFuture<'a, Result<Option<crate::Ws>>> {
        Box::pin(async move {
            let Some(token) = token_from_env() else {
                return Ok(None);
            };

            let (stream, mut request, tcb) = crate::connect_transport(url).await?;
            request.headers_mut().insert(
                "Authorization",
                format!("Bearer {token}")
                    .parse()
                    .context("VARLINK_JWT is not a valid HTTP header value")?,
            );
            debug!("JWT auth: attached bearer token from {VARLINK_JWT_ENV}");
            match crate::ws_upgrade(request, stream, tcb.is_some()).await {
                Ok(ws) => Ok(Some(ws)),
                Err(e) if is_http_unauthorized(&e) => {
                    Err(e.context("the VARLINK_JWT bearer token was rejected; is it expired?"))
                }
                Err(e) => Err(e),
            }
        })
    }
}
