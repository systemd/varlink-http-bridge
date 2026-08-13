// SPDX-License-Identifier: LGPL-2.1-or-later

//! JWT bearer-token authentication
//!
//! This is the JWT verify *core* plus the simplest auth mode, **Bearer**:
//! the client presents only `Authorization: Bearer <JWT>`, the node verifies
//! the JWS against a trusted JWKS and checks `iss` / `aud` / `exp`, then
//! requires the configured claim rules (`--require-claim`) to match. There is
//! no proof-of-possession; security rests on TLS, a short token lifetime and
//! the claim rules.
//!
//! The proof-of-possession modes (RFC 9421 and `DPoP`) will be built
//! later on this core.

use anyhow::{Context, bail};
use jsonwebtoken::jwk::{AlgorithmParameters, EllipticCurve, JwkSet};
use jsonwebtoken::{Algorithm, DecodingKey};
use log::{debug, info, warn};
use serde_json::{Map, Value};
use std::collections::HashMap;
use std::sync::{Mutex, RwLock};
use std::time::{Duration, Instant, SystemTime};
use varlink_http_bridge::sysconf::{CredentialsLoader, find_config};

use crate::{AuthRequest, Authenticator};

/// Clock skew (seconds) tolerated when checking `exp` and `nbf`.
const JWT_LEEWAY_SECS: u64 = 60;

// To allow access via a JWT the user needs to set one or more rules of the
// form `--require-claim=NAME=VALUE`. To validate those, our data structure
// has three levels:
//
//   ClaimRules       all rules: every distinct NAME must match        (AND)
//     AllowedValues    all VALUEs given for one NAME: any may match   (OR)
//       ValueMatcher     a single VALUE: an exact string or a `*`-glob
//
// The `*`-glob engine is hand-rolled as it is very simple right now and it
// avoids a dependency on a glob or fnmatch crate.

/// All `--require-claim` rules: every distinct name must match (AND);
/// a repeated name adds an alternative value (OR). E.g.
/// `--require-claim=repository=myorg/foo --require-claim=env=staging --require-claim=env=test`
/// translates to
/// `repository=myorg/foo` AND (`env=staging` OR `env=test`)
#[derive(Debug)]
struct ClaimRules {
    by_name: HashMap<String, AllowedValues>,
}

impl ClaimRules {
    fn parse(rules: Vec<String>) -> anyhow::Result<Self> {
        let mut by_name: HashMap<String, AllowedValues> = HashMap::new();
        for rule in rules {
            let (name, value) = rule.split_once('=').with_context(|| {
                format!("invalid --require-claim '{rule}', expected NAME=VALUE")
            })?;
            by_name
                .entry(name.to_string())
                .or_default()
                .push(ValueMatcher::new(value));
        }
        Ok(Self { by_name })
    }

    /// Verify every required claim is present and matches one of its allowed
    /// values. On success returns the sorted names of the matched claims.
    fn check(&self, claims: &Map<String, Value>) -> anyhow::Result<String> {
        // Fail closed: with no rules a token would pass on signature alone.
        if self.by_name.is_empty() {
            bail!("JWT auth not configured: no claim rules to authorize against");
        }
        let mut matched = Vec::new();
        for (name, allowed) in &self.by_name {
            let Some(value) = claims.get(name) else {
                bail!("required claim '{name}' is missing");
            };
            if !allowed.matches(value) {
                debug!("JWT claim '{name}'={value} is not in the allowed set");
                bail!("claim '{name}' is not in the allowed set");
            }
            debug!("JWT claim matched: {name}={value}");
            matched.push(name.clone());
        }
        matched.sort_unstable();
        Ok(matched.join(" "))
    }

    /// Sorted required-claim names (not their values), for logging.
    fn names(&self) -> String {
        let mut names: Vec<&str> = self.by_name.keys().map(String::as_str).collect();
        names.sort_unstable();
        names.join(" ")
    }
}

/// One claim name allowed values (OR). Non-string claim values
/// (e.g. number) are converted to strings before matching. This
/// matches if any value for the claim name matches. E.g.
/// `environment=staging` OR `environment=prod`
#[derive(Debug, Default)]
struct AllowedValues(Vec<ValueMatcher>);

impl AllowedValues {
    fn push(&mut self, matcher: ValueMatcher) {
        self.0.push(matcher);
    }

    fn matches(&self, value: &Value) -> bool {
        match value {
            Value::String(s) => self.0.iter().any(|m| m.matches(s)),
            Value::Bool(b) => self.0.iter().any(|m| m.matches(&b.to_string())),
            Value::Number(n) => self.0.iter().any(|m| m.matches(&n.to_string())),
            Value::Array(items) => items.iter().any(|v| self.matches(v)),
            Value::Null | Value::Object(_) => false,
        }
    }
}

/// One allowed value: an exact string, or a `*`-wildcard pattern. E.g.
/// `sub=repo:octo-org/octo-repo:*"`
#[derive(Debug)]
enum ValueMatcher {
    Exact(String),
    Glob(String),
}

impl ValueMatcher {
    fn new(pattern: &str) -> Self {
        if pattern.contains('*') {
            Self::Glob(pattern.to_string())
        } else {
            Self::Exact(pattern.to_string())
        }
    }

    fn matches(&self, value: &str) -> bool {
        match self {
            Self::Exact(s) => s == value,
            Self::Glob(p) => glob_match_wildcard(p, value),
        }
    }
}

/// Match `value` against `pattern` with shell/fnmatch-style `*`, where `*`
/// matches any run of characters (including none, and including separators).
/// The whole string must match. Only `*` is special: `?` and `[...]` are
/// literal, and matching is case-sensitive.
// hand-rolled to avoid another dependency while we only need `*`.
// TODO: pull in e.g. rust-lang/glob if we ever need full fnmatch.
fn glob_match_wildcard(pattern: &str, value: &str) -> bool {
    // The literal pieces between the '*'s. No '*' means an exact match.
    let parts: Vec<&str> = pattern.split('*').collect();
    if parts.len() == 1 {
        return pattern == value;
    }

    // The piece before the first '*' must be a prefix of the value, the piece
    // after the last '*' a suffix. Strip both; what's left in the middle must
    // contain the remaining pieces in order.
    let Some(after_prefix) = value.strip_prefix(parts[0]) else {
        return false;
    };
    let Some(mut middle) = after_prefix.strip_suffix(parts[parts.len() - 1]) else {
        return false;
    };

    for part in &parts[1..parts.len() - 1] {
        match middle.find(part) {
            Some(i) => middle = &middle[i + part.len()..],
            None => return false,
        }
    }
    true
}

// The JWKS fetching/handling is done via an abstract JwksSource that can either
// be a file or URL source. Both will refresh automatically (the file on mtime
// change and the URL periodically or if a keyId (kid) is missing).
//
// They have a keyring of all the JWKS keys used for verifying. Each key is
// actually a key and the algorithm used so that an attacker cannot trick us
// into using a key meant for RSA as a HMAC key. The hierarchy:
//
//   JwksSource      File(JwksFromFile) | Url(JwksFromUrl)
//     JwksFromFile    mtime hot-reload      -> JwksKeyring
//     JwksFromUrl     OIDC fetch + throttle -> JwksKeyring
//       JwksKeyring     RwLock<KeyMap>: concurrent lookup + hot swap
//         KeyMap          kid -> VerifyingKey
//           VerifyingKey    one key + its pinned algorithm

/// Where the trusted JWKS comes from: a local file (hot-reloaded) or a
/// HTTP endpoint via OIDC discovery.
enum JwksSource {
    File(JwksFromFile),
    Url(JwksFromUrl),
}

impl JwksSource {
    fn lookup(&self, key_id: &str) -> anyhow::Result<VerifyingKey> {
        match self {
            JwksSource::File(file) => file.lookup(key_id),
            JwksSource::Url(url) => url.lookup(key_id),
        }
    }

    fn key_count(&self) -> usize {
        let keyring = match self {
            JwksSource::File(file) => &file.keys,
            JwksSource::Url(url) => &url.keys,
        };
        keyring.len()
    }
}

/// The trusted keyring. Reloads happen on demand inside a request, but
/// requests run concurrently, so a lookup can race the reloading request's
/// swap; the `RwLock` keeps concurrent lookups cheap and serializes only
/// the swap.
#[derive(Default)]
struct JwksKeyring {
    keys: RwLock<KeyMap>,
}

impl JwksKeyring {
    /// Verifying key for `kid`, if currently present.
    fn get(&self, key_id: &str) -> Option<VerifyingKey> {
        self.keys.read().ok().and_then(|k| k.get(key_id))
    }

    /// Count of cached keys.
    fn len(&self) -> usize {
        self.keys.read().map_or(0, |k| k.len())
    }

    /// Log and install freshly-loaded keys.
    fn swap(&self, keys: KeyMap, source: impl std::fmt::Display) {
        info!(
            "loaded {} JWKS {} from {source}",
            keys.len(),
            if keys.len() == 1 { "key" } else { "keys" }
        );
        if let Ok(mut guard) = self.keys.write() {
            *guard = keys;
        }
    }
}

/// Retry gap for failed loads, so a persistently broken file is not
/// re-parsed on every request.
const JWKS_FILE_RETRY: Duration = Duration::from_secs(5);

#[derive(Default)]
struct ReloadState {
    /// Only successful loads count (`None`: nothing loaded or file absent);
    /// failures must stay retryable even when the mtime does not change.
    loaded_mtime: Option<SystemTime>,
    failed_at: Option<Instant>,
}

/// Trusted JWKS read from a local file, reloaded when the file's
/// mtime changes. A read/parse error keeps the previous keys, a
/// missing file drops them.
struct JwksFromFile {
    path: std::path::PathBuf,
    keys: JwksKeyring,
    state: Mutex<ReloadState>,
}

impl JwksFromFile {
    fn new(path: std::path::PathBuf) -> Self {
        let file = Self {
            path,
            keys: JwksKeyring::default(),
            state: Mutex::new(ReloadState::default()),
        };
        file.maybe_reload(); // best-effort initial load; picked up later if absent
        file
    }

    fn lookup(&self, key_id: &str) -> anyhow::Result<VerifyingKey> {
        self.maybe_reload();
        self.keys
            .get(key_id)
            .with_context(|| format!("no JWKS key for kid={key_id}"))
    }

    fn stat_mtime(path: &std::path::Path) -> std::io::Result<SystemTime> {
        std::fs::metadata(path)?.modified()
    }

    /// Reload when the file's mtime changed. The lock is held across the
    /// read so the swap is single-flight (cf. `JwksFromUrl::maybe_refresh`).
    /// A failed load is retried (throttled) rather than parked until the
    /// next mtime change: a non-atomic writer can finish inside the same
    /// mtime tick, which would otherwise pin the previous keys forever.
    fn maybe_reload(&self) {
        let mtime = match Self::stat_mtime(&self.path) {
            Ok(m) => Some(m),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            // Transient stat error: keep the cached keys rather than risk
            // dropping them; retried on the next request.
            Err(e) => {
                warn!(
                    "cannot stat {}: {e}, skipping JWKS reload",
                    self.path.display()
                );
                return;
            }
        };
        // poison-tolerant: a panic mid-reload must not panic every later request
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if mtime == state.loaded_mtime {
            return;
        }
        if let Some(failed_at) = state.failed_at
            && failed_at.elapsed() < JWKS_FILE_RETRY
        {
            return;
        }
        let parsed = match mtime {
            None => Ok(KeyMap::default()), // missing file drops the keys
            Some(_) => std::fs::read_to_string(&self.path)
                .with_context(|| format!("failed to read JWKS from {}", self.path.display()))
                .and_then(|data| KeyMap::parse(&data, self.path.display())),
        };
        match parsed {
            Ok(keys) => {
                state.loaded_mtime = mtime;
                state.failed_at = None;
                self.keys.swap(keys, self.path.display());
            }
            Err(e) => {
                state.failed_at = Some(Instant::now());
                warn!(
                    "JWKS reload from {} failed: {e:#}; keeping previous keys",
                    self.path.display()
                );
            }
        }
    }
}

/// A JWKS fetched from the issuer over HTTP (typically via OIDC
/// discovery), refreshed when older than `max_age` (so a key removal
/// is eventually dropped) and on an unknown-`kid` miss (so a rotation
/// is picked up at once). Both are throttled to `min_refetch`. A
/// fetch failure keeps the previous keys. The triggering request
/// blocks for the fetch (if this becomes a problem we can make it a
/// background refresh).
struct JwksFromUrl {
    issuer: String,
    keys: JwksKeyring,
    /// Time of the last fetch *attempt* (success or failure); the lock is held
    /// across the fetch (see `maybe_refresh`). Drives the `min_refetch` throttle.
    last_attempt: Mutex<Option<Instant>>,
    /// Time of the last *successful* fetch; drives the `max_age` staleness check.
    /// Separate from `last_attempt` so a failed attempt doesn't look fresh.
    last_success: Mutex<Option<Instant>>,
    fetcher: JwksFetcher,
    min_refetch: Duration,
    max_age: Duration,
}

impl JwksFromUrl {
    fn new(issuer: String, fetcher: JwksFetcher, min_refetch: Duration, max_age: Duration) -> Self {
        let url = Self {
            issuer,
            keys: JwksKeyring::default(),
            last_attempt: Mutex::new(None),
            last_success: Mutex::new(None),
            fetcher,
            min_refetch,
            max_age,
        };
        // Best-effort eager fetch: an unreachable/misconfigured issuer shows
        // up in the startup logs instead of on the first request; a failure
        // does not fail startup and is retried on the first miss.
        url.maybe_refresh();
        url
    }

    fn lookup(&self, key_id: &str) -> anyhow::Result<VerifyingKey> {
        // Periodic refresh drops issuer-removed keys without needing a miss.
        if self.is_stale() {
            self.maybe_refresh();
        }
        if let Some(key) = self.keys.get(key_id) {
            return Ok(key);
        }
        // Unknown kid: the issuer may have rotated. Refetch (throttled) and retry.
        self.maybe_refresh();
        self.keys
            .get(key_id)
            .with_context(|| format!("no JWKS key for kid={key_id}"))
    }

    // TODO: instead of this add a background fetcher that refreshes
    // on JWKS_MAX_AGE. The current design has the big downside that
    // if the bridge is used once per day each request will first
    // refresh the JWKS which will result in a slow call.
    /// Keys older than `max_age` (or never fetched) are due a refresh.
    fn is_stale(&self) -> bool {
        self.last_success
            .lock()
            .map_or(true, |t| t.is_none_or(|t| t.elapsed() >= self.max_age))
    }

    /// Refetch the JWKS, throttled to `min_refetch`; swap in the new keys on
    /// success, keep the previous ones on failure.
    ///
    /// The `last_attempt` lock is held across the (network) fetch, so both
    /// the fetch and any waiters block for up to the full fetch timeout;
    /// `run_blocking_without_stalling_runtime` keeps that from starving the async runtime.
    fn maybe_refresh(&self) {
        run_blocking_without_stalling_runtime(|| self.refresh());
    }

    fn refresh(&self) {
        // poison-tolerant: a panic mid-fetch must not panic every later request
        let mut last_attempt = self
            .last_attempt
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if last_attempt.is_some_and(|t| t.elapsed() < self.min_refetch) {
            return; // throttled
        }
        let now = Instant::now();
        *last_attempt = Some(now);
        match (self.fetcher)() {
            Ok(keys) => {
                if let Ok(mut t) = self.last_success.lock() {
                    *t = Some(now);
                }
                self.keys.swap(keys, &self.issuer);
            }
            Err(e) => warn!(
                "JWKS fetch from {} failed: {e:#}; keeping previous keys",
                self.issuer
            ),
        }
    }
}

/// On a multi-thread runtime, `block_in_place` has tokio spin up a
/// replacement worker, so a slow JWKS fetch stalls only its own request
/// instead of the whole bridge; elsewhere (plain tests, current-thread
/// runtimes, where it is unsupported) run directly.
fn run_blocking_without_stalling_runtime<T>(f: impl FnOnce() -> T) -> T {
    use tokio::runtime::{Handle, RuntimeFlavor};
    match Handle::try_current() {
        Ok(h) if h.runtime_flavor() == RuntimeFlavor::MultiThread => tokio::task::block_in_place(f),
        _ => f(),
    }
}

/// Minimum gap between on-demand JWKS refetches to avoid that we can
/// get hammered by something that keeps requesting unknown keyIds.
const JWKS_MIN_REFETCH: Duration = Duration::from_mins(1);

/// How long before JWKS keys are re-fetched, so an issuer-side key
/// removal (revocation) is eventually dropped.
const JWKS_MAX_AGE: Duration = Duration::from_hours(8);

/// Fetches a JWKS, returning the parsed keys. Boxed so the cache is agnostic
/// to HTTP (and so tests can inject a fake without a server).
type JwksFetcher = Box<dyn Fn() -> anyhow::Result<KeyMap> + Send + Sync>;

#[derive(serde::Deserialize)]
struct OidcDiscovery {
    jwks_uri: String,
}

/// The bounded timeout keeps a stalled endpoint from hanging us. Redirect
/// targets bypass our URL checks, so they must be constrained here:
/// `https_only` makes ureq reject non-https redirects, and loopback dev mode
/// (`https_only: false`) disables redirects entirely instead.
fn build_jwks_agent(https_only: bool) -> ureq::Agent {
    let tls = ureq::tls::TlsConfig::builder()
        .provider(ureq::tls::TlsProvider::NativeTls)
        .build();
    let mut config = ureq::config::Config::builder()
        .tls_config(tls)
        .timeout_global(Some(std::time::Duration::from_secs(10)))
        .https_only(https_only);
    if !https_only {
        config = config.max_redirects(0);
    }
    config.build().new_agent()
}

/// GET `url` with the body size-capped against a hostile or broken endpoint.
fn get_capped(agent: &ureq::Agent, url: &str, what: &str) -> anyhow::Result<String> {
    const BODY_LIMIT: u64 = 1024 * 1024;
    agent
        .get(url)
        .call()
        .with_context(|| format!("{what} request to {url} failed"))?
        .body_mut()
        .with_config()
        .limit(BODY_LIMIT)
        .read_to_string()
        .with_context(|| format!("reading {what} from {url}"))
}

/// OIDC discovery: GET `<issuer>/.well-known/openid-configuration`, then GET its
/// `jwks_uri`, and parse the result.
fn fetch_jwks_via_discovery(issuer: &str, agent: &ureq::Agent) -> anyhow::Result<KeyMap> {
    let discovery_url = format!(
        "{}/.well-known/openid-configuration",
        issuer.trim_end_matches('/')
    );
    let body = get_capped(agent, &discovery_url, "OIDC discovery")?;
    let discovery: OidcDiscovery = serde_json::from_str(&body)
        .with_context(|| format!("parsing OIDC discovery from {discovery_url}"))?;
    require_secure_jwks_url(&discovery.jwks_uri)?;

    let jwks = get_capped(agent, &discovery.jwks_uri, "JWKS")?;
    KeyMap::parse(&jwks, &discovery.jwks_uri)
}

/// A parsed JWKS as a `kid -> VerifyingKey` map: the immutable batch produced by
/// `parse` (or the fetcher) and swapped into a `JwksKeyring`.
#[derive(Default)]
struct KeyMap(HashMap<String, VerifyingKey>);

impl KeyMap {
    /// Parse a JWKS document (RFC 7517). `source` is used only for log/error
    /// context. Unsupported (non RSA / EC P-256), malformed, or kid-less keys
    /// are skipped rather than failing the whole set.
    fn parse(data: &str, source: impl std::fmt::Display) -> anyhow::Result<Self> {
        let set: JwkSet =
            serde_json::from_str(data).with_context(|| format!("invalid JWKS from {source}"))?;

        let mut keys = HashMap::new();
        for jwk in &set.keys {
            let alg = match &jwk.algorithm {
                AlgorithmParameters::EllipticCurve(ec) if ec.curve == EllipticCurve::P256 => {
                    Algorithm::ES256
                }
                AlgorithmParameters::RSA(_) => Algorithm::RS256,
                other => {
                    warn!(
                        "ignoring unsupported JWK from {source} (only RSA/RS256 and EC P-256/ES256 \
                         are supported): {other:?}"
                    );
                    continue;
                }
            };
            let key = match DecodingKey::from_jwk(jwk) {
                Ok(k) => k,
                Err(e) => {
                    warn!("ignoring malformed JWK from {source}: {e}");
                    continue;
                }
            };

            // kid is optional in rfc7517 but provided in practice by all
            // relevant issuers. TODO: relax if a use-case appears.
            let Some(key_id) = jwk.common.key_id.clone() else {
                warn!("ignoring JWK without a key id (kid) from {source}");
                continue;
            };
            debug!("JWKS key kid={key_id} alg={alg:?}");
            keys.insert(key_id, VerifyingKey { key, alg });
        }
        Ok(Self(keys))
    }

    fn get(&self, key_id: &str) -> Option<VerifyingKey> {
        self.0.get(key_id).cloned()
    }

    fn len(&self) -> usize {
        self.0.len()
    }
}

/// A verifying key from the JWKS plus the single algorithm it may be used with.
/// Pinning the algorithm to the key type (never the attacker-chosen JWT header)
/// prevents algorithm-confusion attacks.
#[derive(Clone)]
struct VerifyingKey {
    key: DecodingKey,
    alg: Algorithm,
}

pub(crate) struct JwtAuthenticator {
    issuer: String,
    audience: String,
    jwks: JwksSource,
    required_claims: ClaimRules,
}

impl std::fmt::Debug for JwtAuthenticator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JwtAuthenticator")
            .field("issuer", &self.issuer)
            .field("audience", &self.audience)
            // key_count is poison-tolerant, so Debug never panics.
            .field("key_count", &self.jwks.key_count())
            .field("required_claims", &self.required_claims)
            .finish()
    }
}

impl JwtAuthenticator {
    fn with_source(
        issuer: String,
        audience: String,
        jwks: JwksSource,
        require_claims: Vec<String>,
    ) -> anyhow::Result<Self> {
        if jwks.key_count() == 0 {
            warn!(
                "no usable JWKS keys loaded yet; JWT auth will reject requests until keys appear"
            );
        }
        Ok(Self {
            issuer,
            audience,
            jwks,
            required_claims: ClaimRules::parse(require_claims)?,
        })
    }

    pub(crate) fn key_count(&self) -> usize {
        self.jwks.key_count()
    }

    pub(crate) fn required_claim_names(&self) -> String {
        self.required_claims.names()
    }

    #[cfg(test)]
    pub(crate) fn new_for_test(
        issuer: String,
        audience: String,
        jwks_path: std::path::PathBuf,
        require_claims: Vec<String>,
    ) -> anyhow::Result<Self> {
        let source = JwksSource::File(JwksFromFile::new(jwks_path));
        Self::with_source(issuer, audience, source, require_claims)
    }
}

impl Authenticator for JwtAuthenticator {
    fn check_request(&self, request: &AuthRequest) -> anyhow::Result<()> {
        let (method, path) = (request.method, request.path);
        // Bearer mode only for now. TODO: add DPoP
        let token = request.bearer_token()?;

        let header = jsonwebtoken::decode_header(token).context("invalid JWT header")?;
        // Note that "kid" is optional, but in practise it should be
        // there for all relevant issuers.
        let key_id = header.kid.context("token has no 'kid' header")?;
        debug!(
            "JWT auth: {method} {path} kid={key_id} header-alg={:?}",
            header.alg
        );

        let verifying_key = self.jwks.lookup(&key_id).inspect_err(|e| {
            debug!("JWT auth: no verifying key for {method} {path}: {e:#}");
        })?;

        let mut validation = jsonwebtoken::Validation::new(verifying_key.alg);
        validation.set_issuer(&[&self.issuer]);
        validation.set_audience(&[&self.audience]);
        // jsonwebtoken only checks iss/aud when the claim is present, so require
        // them: a token from the trusted key that omits aud must not skip the
        // per-node audience check.
        validation.set_required_spec_claims(&["exp", "iss", "aud"]);
        // jsonwebtoken validates exp by default but not nbf; reject not-yet-valid tokens.
        validation.validate_nbf = true;
        validation.leeway = JWT_LEEWAY_SECS;

        // Verify the JWS signature (against the pinned key + alg) and iss/aud/exp/nbf.
        let data =
            jsonwebtoken::decode::<Map<String, Value>>(token, &verifying_key.key, &validation)
                // log the full chain at debug; the caller only surfaces the top message
                .inspect_err(|e| {
                    debug!("JWT verification failed for {method} {path} (kid={key_id}): {e:#}");
                })
                .context("JWT verification failed")?;
        // Authenticated now; apply our authorization rules to the trusted claims.
        let matched = self.required_claims.check(&data.claims)?;
        info!("JWT auth OK: {method} {path} (matched claims: {matched})");
        Ok(())
    }
}

/// Well-known systemd credential names (see systemd.system-credentials(7)), so
/// a node can be configured entirely from the credstore for auto-deployment.
const JWKS_CREDENTIAL: &str = "varlink-httpd.jwt.jwks";
const ISSUER_CREDENTIAL: &str = "varlink-httpd.jwt.issuer";
const AUDIENCE_CREDENTIAL: &str = "varlink-httpd.jwt.audience";
const REQUIRE_CLAIMS_CREDENTIAL: &str = "varlink-httpd.jwt.require-claims";

/// Path under `/etc`, `/run` or `/usr/lib` for the shipped/admin JWKS file.
const JWKS_CONFIG_REL: &str = "varlink-httpd/issuer-jwks.json";

/// The scheme is parsed, not prefix-matched, so it is case-insensitive.
fn is_http_url(s: &str) -> bool {
    url_scheme(s).is_some_and(|scheme| {
        scheme.eq_ignore_ascii_case("http") || scheme.eq_ignore_ascii_case("https")
    })
}

fn url_scheme(url: &str) -> Option<String> {
    url.parse::<ureq::http::Uri>()
        .ok()?
        .scheme_str()
        .map(str::to_string)
}

/// True if `url`'s host is a loopback address (`localhost`, `127.0.0.0/8`, `::1`).
fn is_loopback_url(url: &str) -> bool {
    let Ok(uri) = url.parse::<ureq::http::Uri>() else {
        return false;
    };
    let Some(host) = uri.host() else {
        return false;
    };
    // Uri::host() returns IPv6 hosts bracketed ("[::1]"); IpAddr won't parse those.
    let host = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    host == "localhost"
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())
}

/// Allow `https://` anywhere and plaintext `http://` only from loopback
/// (local testing). An allowlist over parsed schemes: a denylist over string
/// prefixes is case-trickable ("HTTP://") into a cleartext fetch.
fn require_secure_jwks_url(url: &str) -> anyhow::Result<()> {
    let scheme = url_scheme(url).unwrap_or_default();
    if scheme.eq_ignore_ascii_case("https")
        || (scheme.eq_ignore_ascii_case("http") && is_loopback_url(url))
    {
        return Ok(());
    }
    bail!(
        "refusing to fetch JWKS from {url}: only https:// (or http:// from loopback) is supported"
    );
}

/// Choose the JWKS source: an explicit/present file wins (the `jwks`
/// argument, then an existing file in the `/etc` > `/run` >
/// `/usr/lib` hierarchy); otherwise, if the issuer is an HTTP(S) URL,
/// fetch it via OIDC discovery; otherwise watch the `/etc` config
/// path so a later-installed file is still picked up.
fn build_jwks_source(
    jwks: Option<std::path::PathBuf>,
    issuer: &str,
    root: &std::path::Path,
) -> anyhow::Result<JwksSource> {
    if let Some(path) = jwks {
        info!("JWT: using JWKS file {}", path.display());
        return Ok(JwksSource::File(JwksFromFile::new(path)));
    }
    if let Some(path) = find_config(JWKS_CONFIG_REL, root) {
        // An implicitly-found file is a local key pin and wins over discovery,
        // but must not do so silently: it blocks issuer key rotation.
        if is_http_url(issuer) {
            warn!(
                "JWT: found JWKS file {}; OIDC discovery from {issuer} is disabled and \
                 issuer key rotation will not be picked up (remove the file, or pass \
                 --issuer-jwks to make the pin explicit)",
                path.display()
            );
        } else {
            info!("JWT: using JWKS file {}", path.display());
        }
        return Ok(JwksSource::File(JwksFromFile::new(path)));
    }
    if is_http_url(issuer) {
        require_secure_jwks_url(issuer)?;
        info!("JWT: fetching JWKS via OIDC discovery from {issuer}");
        let agent = build_jwks_agent(!is_loopback_url(issuer));
        let issuer_owned = issuer.to_string();
        let fetcher: JwksFetcher =
            Box::new(move || fetch_jwks_via_discovery(&issuer_owned, &agent));
        return Ok(JwksSource::Url(JwksFromUrl::new(
            issuer.to_string(),
            fetcher,
            JWKS_MIN_REFETCH,
            JWKS_MAX_AGE,
        )));
    }
    // No file and the issuer isn't a URL: watch the /etc path for one to appear.
    let path = root.join("etc").join(JWKS_CONFIG_REL);
    Ok(JwksSource::File(JwksFromFile::new(path)))
}

/// Fresh P-256 keypair, shared by this module's and tests.rs's JWT tests.
#[cfg(test)]
pub(crate) fn generate_p256_keypair() -> openssl::pkey::PKey<openssl::pkey::Private> {
    let group = openssl::ec::EcGroup::from_curve_name(openssl::nid::Nid::X9_62_PRIME256V1).unwrap();
    openssl::pkey::PKey::from_ec_key(openssl::ec::EcKey::generate(&group).unwrap()).unwrap()
}

/// Default audience when `--audience` is unset: this node's hostname. The only
/// risk is a hostname collision across nodes, which silently widens scope.
fn default_audience() -> anyhow::Result<String> {
    let uname = rustix::system::uname();
    Ok(uname
        .nodename()
        .to_str()
        .context("hostname is not valid UTF-8")?
        .to_string())
}

/// Build the JWT authenticator from CLI flags and/or systemd credentials.
/// Returns `Ok(None)` when no issuer is configured (JWT auth not enabled).
pub(crate) fn create_jwt_authenticator(
    cli_options: crate::JwtCliOptions,
    creds_dir: Option<&std::path::Path>,
    root: &std::path::Path,
) -> anyhow::Result<Option<JwtAuthenticator>> {
    let creds = creds_dir.map(CredentialsLoader::from_dir);
    let creds = creds.as_ref();

    // A CLI option overrides (not extends) the matching credential.
    let resolved = crate::JwtCliOptions {
        issuer: cli_options
            .issuer
            .or_else(|| creds.and_then(|c| c.get_string(ISSUER_CREDENTIAL))),
        audience: cli_options
            .audience
            .or_else(|| creds.and_then(|c| c.get_string(AUDIENCE_CREDENTIAL))),
        issuer_jwks: cli_options
            .issuer_jwks
            .or_else(|| creds.and_then(|c| c.path(JWKS_CREDENTIAL))),
        require_claims: if cli_options.require_claims.is_empty() {
            creds
                .map(|c| c.get_lines(REQUIRE_CLAIMS_CREDENTIAL))
                .unwrap_or_default()
        } else {
            cli_options.require_claims
        },
    };

    // exhaustive destructure, so a new option cannot be silently ignored
    let (issuer, audience, issuer_jwks, require_claims) = match resolved {
        crate::JwtCliOptions {
            issuer: Some(issuer),
            audience,
            issuer_jwks,
            require_claims,
        } => (issuer, audience, issuer_jwks, require_claims),
        // The above Some(issuer) ensures this match arm is taken if issuer
        // is None.
        cli_options_with_unset_issuer => {
            if cli_options_with_unset_issuer.any_option_set() {
                warn!(
                    "JWT auth not enabled: no --issuer (nor the {ISSUER_CREDENTIAL} credential); \
                     the other JWT settings (audience/jwks/require-claim) are ignored"
                );
            }
            return Ok(None);
        }
    };
    let audience = match audience {
        Some(a) => a,
        None => default_audience().context("--audience not set and hostname unavailable")?,
    };
    // With no rules from required claims any token that has signature
    // + iss + aud + exp alone (aud is matched against --audience)
    // would pass. Many third-party IdP are weak to identify the
    // caller: `aud` is an app/org-wide value (Google: the OAuth
    // client id; GitHub: an org URL the caller can even choose
    // itself), so it proves almost nothing. So instead require a
    // claim that the issuer sets and the caller cannot forge
    // (repository/sub, verified email, ...). Unless we have
    // require_claims turn off the jwt authenticator (at least for now
    // until we have a better use-case)
    if require_claims.is_empty() {
        warn!(
            "JWT auth not enabled: please add at least one --require-claim (or a \
	     {REQUIRE_CLAIMS_CREDENTIAL} credential). Without this any token from {issuer} \
	     with aud={audience} would be accepted which is unsafe."
        );
        return Ok(None);
    }

    let jwks = build_jwks_source(issuer_jwks, &issuer, root)?;
    let auth =
        JwtAuthenticator::with_source(issuer.clone(), audience.clone(), jwks, require_claims)?;
    info!(
        "Authenticator: adding JWT bearer (issuer={issuer}, audience={audience}, \
         {count} {keys_word}, required-claims: {claims})",
        count = auth.key_count(),
        keys_word = if auth.key_count() == 1 { "key" } else { "keys" },
        claims = auth.required_claim_names(),
    );
    Ok(Some(auth))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_glob_match_wildcard() {
        assert!(glob_match_wildcard(
            "repo:myorg/myrepo:*",
            "repo:myorg/myrepo:ref:refs/heads/main"
        ));
        assert!(!glob_match_wildcard("repo:myorg/*", "repo:other/x"));
        assert!(glob_match_wildcard("*", "anything"));
        assert!(glob_match_wildcard("a*b*c", "a-b-c"));
        assert!(glob_match_wildcard("a*c", "ac"));
        assert!(!glob_match_wildcard("a*c", "ab"));
        assert!(glob_match_wildcard("prefix*", "prefix"));
        assert!(glob_match_wildcard("*suffix", "xxsuffix"));
        assert!(!glob_match_wildcard("*suffix", "suffixx"));
        assert!(glob_match_wildcard("noglob", "noglob"));
        assert!(!glob_match_wildcard("noglob", "noglob2"));

        // adjacent stars collapse to a single '*' (empty middle piece is a no-op)
        assert!(glob_match_wildcard("a**b", "axxb"));
        assert!(glob_match_wildcard("a**b", "ab"));

        // only `*` is special: `?` and `[...]` are literal, matching is case-sensitive
        assert!(glob_match_wildcard("a?c*", "a?cx"));
        assert!(!glob_match_wildcard("a?c*", "abcx"));
        assert!(glob_match_wildcard("a[x]*", "a[x]y"));
        assert!(!glob_match_wildcard("ABC*", "abcx"));
    }

    #[test]
    fn test_value_matcher_new() {
        assert!(matches!(ValueMatcher::new("exact"), ValueMatcher::Exact(_)));
        assert!(matches!(
            ValueMatcher::new("has*star"),
            ValueMatcher::Glob(_)
        ));
    }

    #[test]
    fn test_allowed_values_matches() {
        let mut allowed = AllowedValues::default();
        allowed.push(ValueMatcher::new("myorg"));
        allowed.push(ValueMatcher::new("repo:*"));

        assert!(allowed.matches(&json!("myorg")));
        assert!(allowed.matches(&json!("repo:anything")));
        assert!(!allowed.matches(&json!("other")));
        // an array matches if any element does
        assert!(allowed.matches(&json!(["x", "myorg"])));
        assert!(!allowed.matches(&json!(["x", "y"])));
        // null and objects never match
        assert!(!allowed.matches(&json!(null)));
        assert!(!allowed.matches(&json!({ "a": 1 })));

        // bools and numbers are compared by their string form
        let mut truthy = AllowedValues::default();
        truthy.push(ValueMatcher::new("true"));
        assert!(truthy.matches(&json!(true)));
        assert!(!truthy.matches(&json!(false)));

        let mut num = AllowedValues::default();
        num.push(ValueMatcher::new("42"));
        assert!(num.matches(&json!(42)));
        assert!(!num.matches(&json!(43)));
    }

    #[test]
    fn test_claim_rules_parse_rejects_malformed() {
        let err = ClaimRules::parse(vec!["no-equals-sign".to_string()]).unwrap_err();
        assert!(err.to_string().contains("NAME=VALUE"), "got: {err}");
    }

    #[test]
    fn test_claim_rules_check_and_or_and_summary() {
        // distinct names AND; the repeated name ORs its values.
        let rules = ClaimRules::parse(vec![
            "repository=org/a".to_string(),
            "repository=org/b".to_string(),
            "environment=prod".to_string(),
        ])
        .unwrap();

        let claims = |v: serde_json::Value| v.as_object().unwrap().clone();

        // both names satisfied (repository via the second OR value); summary is
        // the matched claim names, sorted, without the (possibly sensitive) values.
        let summary = rules
            .check(&claims(
                json!({"repository": "org/b", "environment": "prod"}),
            ))
            .unwrap();
        assert_eq!(summary, "environment repository");

        // repository present but not an allowed value
        assert!(
            rules
                .check(&claims(
                    json!({"repository": "org/c", "environment": "prod"})
                ))
                .is_err()
        );
        // environment missing -> AND not satisfied
        assert!(
            rules
                .check(&claims(json!({"repository": "org/a"})))
                .is_err()
        );
    }

    // A throwaway verifying key; URL-cache tests only check presence by kid, not
    // the key material, so a fresh random EC key per call is fine.
    fn fake_verifying_key() -> VerifyingKey {
        let pem = generate_p256_keypair().public_key_to_pem().unwrap();
        VerifyingKey {
            key: DecodingKey::from_ec_pem(&pem).unwrap(),
            alg: Algorithm::ES256,
        }
    }

    fn keys_with(ids: &[&str]) -> KeyMap {
        KeyMap(
            ids.iter()
                .map(|id| ((*id).to_string(), fake_verifying_key()))
                .collect(),
        )
    }

    #[test]
    fn test_url_jwks_initial_fetch_and_lookup() {
        let url = JwksFromUrl::new(
            "https://issuer.example".to_string(),
            Box::new(|| Ok(keys_with(&["k1"]))),
            Duration::from_hours(1),
            Duration::from_hours(1), // max_age (not exercised here)
        );
        assert!(url.lookup("k1").is_ok());
        assert!(url.lookup("k2").is_err());
    }

    #[test]
    fn test_url_jwks_refetches_on_unknown_kid() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};
        let rotated = Arc::new(AtomicBool::new(false));
        let r = rotated.clone();
        let url = JwksFromUrl::new(
            "https://issuer.example".to_string(),
            Box::new(move || {
                if r.load(Ordering::SeqCst) {
                    Ok(keys_with(&["k1", "k2"]))
                } else {
                    Ok(keys_with(&["k1"]))
                }
            }),
            Duration::ZERO,          // no throttle: every miss refetches
            Duration::from_hours(1), // max_age (not exercised here)
        );
        assert!(url.lookup("k1").is_ok());
        assert!(url.lookup("k2").is_err()); // not rotated yet
        rotated.store(true, Ordering::SeqCst);
        assert!(url.lookup("k2").is_ok()); // unknown kid triggers a refetch
    }

    #[test]
    fn test_url_jwks_throttles_refetch() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};
        let calls = Arc::new(AtomicUsize::new(0));
        let c = calls.clone();
        let url = JwksFromUrl::new(
            "https://issuer.example".to_string(),
            Box::new(move || {
                c.fetch_add(1, Ordering::SeqCst);
                Ok(keys_with(&["k1"]))
            }),
            Duration::from_hours(1), // long throttle
            Duration::from_hours(1), // max_age (not exercised here)
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1, "one initial fetch");
        let _ = url.lookup("unknown");
        let _ = url.lookup("unknown");
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "refetch on unknown kid must be throttled"
        );
    }

    #[test]
    fn test_url_jwks_keeps_last_good_on_fetch_error() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};
        let fail = Arc::new(AtomicBool::new(false));
        let f = fail.clone();
        let url = JwksFromUrl::new(
            "https://issuer.example".to_string(),
            Box::new(move || {
                if f.load(Ordering::SeqCst) {
                    anyhow::bail!("issuer unreachable")
                }
                Ok(keys_with(&["k1"]))
            }),
            Duration::ZERO,
            Duration::from_hours(1), // max_age (not exercised here)
        );
        assert!(url.lookup("k1").is_ok()); // good initial fetch
        fail.store(true, Ordering::SeqCst);
        assert!(url.lookup("k2").is_err()); // a miss now refetches and fails
        assert!(
            url.lookup("k1").is_ok(),
            "previous keys must be retained on fetch failure"
        );
    }

    #[test]
    fn test_url_jwks_concurrent_unknown_kid_during_rotation() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};
        let rotated = Arc::new(AtomicBool::new(false));
        let r = rotated.clone();
        let url = JwksFromUrl::new(
            "https://issuer.example".to_string(),
            Box::new(move || {
                // sleep so the two lookups below genuinely overlap on the fetch
                std::thread::sleep(Duration::from_millis(50));
                if r.load(Ordering::SeqCst) {
                    Ok(keys_with(&["k1", "k2"]))
                } else {
                    Ok(keys_with(&["k1"]))
                }
            }),
            Duration::ZERO,
            Duration::from_hours(1), // max_age (not exercised here)
        );
        assert!(url.lookup("k1").is_ok());
        rotated.store(true, Ordering::SeqCst);

        // Two threads hit the new kid at once. Neither may get a false 401: the
        // second must block on the in-flight fetch and then see the fresh keys.
        let barrier = std::sync::Barrier::new(2);
        let (a, b) = std::thread::scope(|s| {
            let h = s.spawn(|| {
                barrier.wait();
                url.lookup("k2").is_ok()
            });
            barrier.wait();
            (url.lookup("k2").is_ok(), h.join().unwrap())
        });
        assert!(a && b, "both concurrent lookups must see the rotated key");
    }

    #[test]
    fn test_url_jwks_periodic_refresh_drops_removed_key() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};
        // max_age=0: every lookup is stale, so a periodic refresh runs.
        let removed = Arc::new(AtomicBool::new(false));
        let r = removed.clone();
        let url = JwksFromUrl::new(
            "https://issuer.example".to_string(),
            Box::new(move || {
                if r.load(Ordering::SeqCst) {
                    Ok(keys_with(&["k2"]))
                } else {
                    Ok(keys_with(&["k1"]))
                }
            }),
            Duration::ZERO, // no throttle
            Duration::ZERO, // always stale
        );
        assert!(url.lookup("k1").is_ok());
        removed.store(true, Ordering::SeqCst);
        // k1 is still a known kid: without periodic refresh it would stay cached.
        assert!(url.lookup("k1").is_err());
        assert!(url.lookup("k2").is_ok());
    }

    #[test]
    fn test_url_jwks_no_refresh_within_max_age() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};
        // min_refetch=0 isolates max_age: an extra fetch could only be staleness.
        let calls = Arc::new(AtomicUsize::new(0));
        let c = calls.clone();
        let url = JwksFromUrl::new(
            "https://issuer.example".to_string(),
            Box::new(move || {
                c.fetch_add(1, Ordering::SeqCst);
                Ok(keys_with(&["k1"]))
            }),
            Duration::ZERO,
            Duration::from_hours(1), // fresh for the whole test
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1, "one initial fetch");
        let _ = url.lookup("k1");
        let _ = url.lookup("k1");
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "fresh keys must not trigger a refresh"
        );
    }

    #[test]
    fn test_empty_claim_rules_reject() {
        // no rules must reject, not vacuously accept (fail closed)
        let rules = ClaimRules::parse(vec![]).unwrap();
        let err = rules
            .check(&json!({"sub": "anyone"}).as_object().unwrap().clone())
            .unwrap_err();
        assert!(err.to_string().contains("no claim rules"), "got: {err}");
    }

    #[test]
    fn test_require_secure_jwks_url() {
        // https and loopback http are allowed
        assert!(require_secure_jwks_url("https://issuer.example/jwks").is_ok());
        assert!(require_secure_jwks_url("http://localhost:8080/jwks").is_ok());
        assert!(require_secure_jwks_url("http://127.0.0.1/jwks").is_ok());
        assert!(require_secure_jwks_url("http://[::1]:9000/jwks").is_ok());
        // plaintext http to a routable host is rejected
        assert!(require_secure_jwks_url("http://issuer.example/jwks").is_err());
        assert!(require_secure_jwks_url("http://10.0.0.5/jwks").is_err());
        // scheme matching must be case-insensitive: HTTP:// is still plaintext
        assert!(require_secure_jwks_url("HTTP://issuer.example/jwks").is_err());
        assert!(require_secure_jwks_url("HTTPS://issuer.example/jwks").is_ok());
        // unknown schemes and non-URLs are rejected (allowlist, not denylist)
        assert!(require_secure_jwks_url("ftp://issuer.example/jwks").is_err());
        assert!(require_secure_jwks_url("issuer.example/jwks").is_err());
        assert!(require_secure_jwks_url("").is_err());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_run_blocking_without_stalling_runtime_on_multithread_runtime() {
        // the block_in_place branch, from a worker
        assert_eq!(run_blocking_without_stalling_runtime(|| 7), 7);
        // and from the blocking pool, where a raw block_in_place could panic
        let r = tokio::task::spawn_blocking(|| run_blocking_without_stalling_runtime(|| 7))
            .await
            .unwrap();
        assert_eq!(r, 7);
    }

    #[tokio::test]
    async fn test_run_blocking_without_stalling_runtime_on_current_thread_runtime() {
        // block_in_place is unsupported here; must fall back to direct call
        assert_eq!(run_blocking_without_stalling_runtime(|| 7), 7);
    }

    #[test]
    fn test_run_blocking_without_stalling_runtime_outside_runtime() {
        assert_eq!(run_blocking_without_stalling_runtime(|| 7), 7);
    }

    #[test]
    fn test_jwks_file_fixed_within_same_mtime_tick_is_retried() {
        // RFC 7517 A.1 example EC key; only needs to parse, not verify.
        const VALID_JWKS: &str = r#"{"keys":[{"kty":"EC","crv":"P-256",
            "x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
            "y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM","kid":"1"}]}"#;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("jwks.json");
        std::fs::write(&path, "{ mid-write garbage").unwrap();
        let broken_mtime = std::fs::metadata(&path).unwrap().modified().unwrap();

        let jwks = JwksFromFile::new(path.clone()); // initial load fails
        assert_eq!(jwks.keys.len(), 0);

        // The writer finishes within the same mtime tick.
        std::fs::write(&path, VALID_JWKS).unwrap();
        std::fs::File::options()
            .write(true)
            .open(&path)
            .unwrap()
            .set_times(std::fs::FileTimes::new().set_modified(broken_mtime))
            .unwrap();

        jwks.maybe_reload();
        assert_eq!(jwks.keys.len(), 0, "retry must be throttled");

        // fast-forward past the throttle
        jwks.state.lock().unwrap().failed_at = None;
        jwks.maybe_reload();
        assert_eq!(
            jwks.keys.len(),
            1,
            "an unchanged mtime must not pin the broken state"
        );
    }
}
