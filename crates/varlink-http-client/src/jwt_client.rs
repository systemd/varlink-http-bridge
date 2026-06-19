// SPDX-License-Identifier: LGPL-2.1-or-later

//! Client-side JWT bearer support, behind the `jwtauth` feature. Without it
//! the method cannot be built, and asking for it through `VARLINK_JWT` is
//! warned about rather than silently ignored.
//!
//! The Bearer mode needs no client-side crypto: the token is obtained out of
//! band (pasted, piped from a CI OIDC endpoint, or minted by an issuer helper)
//! and simply attached as `Authorization: Bearer <JWT>`. The proof-of-possession
//! modes (RFC 9421 and `DPoP`) will add request signing here later.

use crate::client::Auth;

/// Environment variable carrying the bearer token itself (not a path, unlike
/// `VARLINK_SSH_KEY`); surrounding whitespace is trimmed so a token piped in
/// with a trailing newline still works.
const VARLINK_JWT_ENV: &str = "VARLINK_JWT";

/// The token from `VARLINK_JWT`, if it is set and not blank.
#[cfg(feature = "jwtauth")]
pub(crate) fn auth_from_env() -> Option<Auth> {
    let token = std::env::var(VARLINK_JWT_ENV).ok()?;
    let token = token.trim();
    (!token.is_empty()).then(|| Auth::Jwt(token.to_string()))
}

/// Without the feature a set `VARLINK_JWT` is warned about.
#[cfg(not(feature = "jwtauth"))]
pub(crate) fn auth_from_env() -> Option<Auth> {
    if std::env::var_os(VARLINK_JWT_ENV).is_some() {
        log::warn!(
            "{VARLINK_JWT_ENV} is set but this build lacks the 'jwtauth' feature; ignoring it"
        );
    }
    None
}

#[cfg(feature = "jwtauth")]
mod enabled {
    use anyhow::{Context, Result};
    use futures_util::future::LocalBoxFuture;
    use log::debug;

    use crate::WebSocket;
    use crate::client_auth::{ClientAuth, is_http_unauthorized};
    use crate::transport::Transport;

    pub(crate) struct JwtBearer {
        token: String,
        transport: Transport,
    }

    impl JwtBearer {
        pub(crate) fn new(token: String, transport: Transport) -> Self {
            Self { token, transport }
        }

        async fn connect_with_token(&self, url: &str) -> Result<Option<WebSocket>> {
            let (stream, mut request, tcb) = self.transport.connect(url).await?;
            let mut value: http::HeaderValue = format!("Bearer {}", self.token)
                .parse()
                .context("the JWT is not a valid HTTP header value")?;
            value.set_sensitive(true);
            request.headers_mut().insert("Authorization", value);
            debug!("JWT auth: attached the bearer token");
            match crate::ws_upgrade(request, stream, tcb.is_some()).await {
                Ok(ws) => Ok(Some(ws)),
                Err(e) if is_http_unauthorized(&e) => {
                    Err(e.context("the JWT bearer token was rejected; is it expired?"))
                }
                Err(e) => Err(e),
            }
        }
    }

    impl ClientAuth for JwtBearer {
        fn name(&self) -> &'static str {
            "JWT bearer auth (VARLINK_JWT)"
        }

        fn configured(&self) -> bool {
            true
        }

        fn connect<'a>(&'a self, url: &'a str) -> LocalBoxFuture<'a, Result<Option<WebSocket>>> {
            Box::pin(self.connect_with_token(url))
        }
    }
}
#[cfg(feature = "jwtauth")]
pub(crate) use enabled::JwtBearer;
