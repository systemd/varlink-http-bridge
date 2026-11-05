// SPDX-License-Identifier: LGPL-2.1-or-later

//! Dialing a varlink-httpd: TCP or vsock, TLS with the client's trust
//! configuration, then the WebSocket upgrade that an auth method (see
//! `client_auth`) adds its headers to.

use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::{Arc, OnceLock};

use anyhow::{Context, Result};
use log::{debug, warn};
use openssl::ssl::{SslConnector, SslFiletype, SslMethod, SslVerifyMode, SslVersion};
use tokio_tungstenite::tungstenite;

use varlink_http_core::{AsyncStream, BoxedStream, TlsChannelBinding};

use crate::WebSocket;

/// Candidate client configuration directories, most specific first:
/// 1. `$XDG_CONFIG_HOME/varlinkctl-http/`
/// 2. `~/.config/varlinkctl-http/`
/// 3. `/etc/varlinkctl-http/`
fn config_dirs() -> Vec<PathBuf> {
    [
        std::env::var_os("XDG_CONFIG_HOME").map(|d| PathBuf::from(d).join("varlinkctl-http")),
        std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config/varlinkctl-http")),
        Some(PathBuf::from("/etc/varlinkctl-http")),
    ]
    .into_iter()
    .flatten()
    .collect()
}

/// First [`config_dirs`] entry that exists.
pub(crate) fn config_dir() -> Option<PathBuf> {
    config_dirs().into_iter().find(|d| d.is_dir())
}

/// What `known-hosts` records about a peer.
#[derive(Debug, PartialEq, Eq)]
enum KnownHost {
    /// Pinned public key of a self-signed server. Trust on first use, pin to
    /// ensure we are talking to the same system on second contact.
    /// Written as the `sha256//…` the daemon prints on startup, so an operator
    /// can paste an entry in ahead of time.
    Pin(String),
    /// A trust authority vouched for this peer. No key is pinned, so the
    /// server stays free to rotate its key. Recorded so we don't fall back
    /// to trust a self-sigend cert for the server in a later contact.
    TrustAuthority,
}

impl KnownHost {
    /// Parse a recorded value; `None` if the line carries none.
    fn parse(value: &str) -> Option<Self> {
        if value == "ca" {
            return Some(Self::TrustAuthority);
        }
        let pin = value.strip_prefix("sha256//").unwrap_or(value);
        (!pin.is_empty()).then(|| Self::Pin(pin.to_string()))
    }
}

/// The value as written to `known-hosts`; the inverse of [`KnownHost::parse`].
impl std::fmt::Display for KnownHost {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pin(pin) => write!(f, "sha256//{pin}"),
            Self::TrustAuthority => f.write_str("ca"),
        }
    }
}

/// What is known about each server, one [`KnownHost`] per line:
///
/// ```text
/// myserver:1031   sha256//SHPiyqubI9L9Nor4n+SKT5CodBou6KDBMeyJlTib/38=
/// otherhost:1031  ca
/// ```
fn known_hosts_path() -> Option<PathBuf> {
    let dirs = config_dirs();
    let dir = dirs.iter().find(|d| d.is_dir()).or(dirs.first())?;
    Some(dir.join("known-hosts"))
}

/// What is recorded for `peer` in the `known-hosts` file at `path`.
fn lookup_known_host(path: &Path, peer: &str) -> Result<Option<KnownHost>> {
    if !path.exists() {
        return Ok(None);
    }
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    for line in text.lines() {
        let line = line
            .split_once('#')
            .map_or(line, |(before, _)| before)
            .trim();
        let Some((host, value)) = line.split_once(char::is_whitespace) else {
            continue;
        };
        if host == peer {
            let known = KnownHost::parse(value.trim())
                .with_context(|| format!("{}: empty value recorded for {peer}", path.display()))?;
            return Ok(Some(known));
        }
    }
    Ok(None)
}

/// Append what `peer` proved on first contact to the `known-hosts` file.
fn record_known_host(path: &Path, peer: &str, host: &KnownHost) -> Result<()> {
    use std::io::Write as _;

    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    }
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .with_context(|| format!("opening {}", path.display()))?;
    writeln!(f, "{peer}\t{host}").with_context(|| format!("writing {}", path.display()))?;

    match host {
        KnownHost::Pin(_) => warn!(
            "{peer}: no key recorded, trusting the one presented on first contact. \
             Recorded {host} in {}.",
            path.display()
        ),
        KnownHost::TrustAuthority => debug!(
            "{peer}: recorded as vouched for by a trust authority in {}.",
            path.display()
        ),
    }
    Ok(())
}

/// Whether the certificate names itself as its own issuer.
fn is_self_signed(cert: &openssl::x509::X509Ref) -> bool {
    cert.issuer_name()
        .try_cmp(cert.subject_name())
        .is_ok_and(std::cmp::Ordering::is_eq)
}

/// Decide whether the server's certificate is acceptable.
///
/// PKI is the real signal, so a validated certificate is always accepted, and
/// `known-hosts` only governs the certificates nothing vouches for. Accepting
/// early is also what lets a [`KnownHost::TrustAuthority`] peer rotate its
/// key: the new certificate validates and never reaches the rules below.
///
/// The refusal reason is a message, not an error, because the OpenSSL verify
/// callback can only answer yes or no and stores it for the caller.
fn verify_server_cert(
    cert: &openssl::x509::X509Ref,
    chain_ok: bool,
    recorded: Option<&KnownHost>,
    ca_configured: bool,
) -> Result<(), &'static str> {
    if chain_ok {
        // A stale pin is left alone; it still catches a later downgrade.
        return Ok(());
    }
    if ca_configured {
        return Err("certificate does not validate against the configured server-ca-file");
    }
    if !is_self_signed(cert) {
        return Err("certificate does not validate against trust authority");
    }

    match recorded {
        // No record yet: first contact, Transport::handshake learns the key afterwards.
        None => Ok(()),
        Some(KnownHost::TrustAuthority) => Err(
            "this peer was reached before with a certificate signed by a trust authority \
             and now presents a self-signed one. Refusing the downgrade. If the server \
             really stopped using a CA cert, delete its known-hosts line.",
        ),
        Some(KnownHost::Pin(pin)) => {
            let actual = varlink_http_core::public_key_pin(cert)
                .map_err(|_| "cannot fingerprint the server key")?;
            if *pin != actual {
                return Err(
                    "the server key does not match the one recorded in known-hosts. \
                     Either the server was reinstalled, or this is not the same server.",
                );
            }
            Ok(())
        }
    }
}

/// Build an `SslConnector` with the client certs and CA from `config_dir`
/// and the system trust store.
///
/// Any refusal reason lands in `refusal`; OpenSSL drops the peer certificate
/// when it aborts, so the caller cannot work it out afterwards.
fn build_ssl_connector(
    config_dir: Option<&Path>,
    recorded: Option<KnownHost>,
    ca_configured: bool,
    refusal: Arc<OnceLock<&'static str>>,
) -> Result<SslConnector> {
    let mut builder = SslConnector::builder(SslMethod::tls_client())?;
    // We need tls channel binding per RFC 9266 ("tls-exporter") which
    // is only guaranteed unique with TLS 1.3.
    builder.set_min_proto_version(Some(SslVersion::TLS1_3))?;

    if let Some(dir) = config_dir {
        let cert = dir.join("client-cert-file");
        let key = dir.join("client-key-file");
        let ca = dir.join("server-ca-file");

        if cert.exists() && key.exists() {
            builder
                .set_certificate_chain_file(&cert)
                .with_context(|| format!("loading client certificate {}", cert.display()))?;
            builder
                .set_private_key_file(&key, SslFiletype::PEM)
                .with_context(|| format!("loading client key {}", key.display()))?;
            builder
                .check_private_key()
                .context("client certificate and key do not match")?;
        }

        if ca.exists() {
            builder.set_cert_store(
                varlink_http_core::exclusive_ca_store(&ca)
                    .with_context(|| format!("loading CA certificate {}", ca.display()))?,
            );
        }
    }

    builder.set_verify_callback(SslVerifyMode::PEER, move |chain_ok, ctx| {
        // errors above the leaf abort on their own
        if ctx.error_depth() != 0 {
            return chain_ok;
        }
        let Some(cert) = ctx.current_cert() else {
            return false;
        };
        match verify_server_cert(cert, chain_ok, recorded.as_ref(), ca_configured) {
            Ok(()) => true,
            Err(why) => {
                let _ = refusal.set(why);
                false
            }
        }
    });

    Ok(builder.build())
}

/// How a bridge is reached: TCP or vsock, and for TLS the trust files and
/// `known-hosts` to use.
#[derive(Debug, Clone)]
pub(crate) struct Transport {
    /// Holds `client-cert-file`, `client-key-file` and `server-ca-file`,
    /// each used if present.
    pub(crate) config_dir: Option<PathBuf>,
    /// Where the server keys seen on first contact are looked up and
    /// recorded. TLS cannot be used without one.
    pub(crate) known_hosts: Option<PathBuf>,
}

impl Transport {
    pub(crate) fn from_env() -> Self {
        Self {
            config_dir: config_dir(),
            known_hosts: known_hosts_path(),
        }
    }

    /// TLS-handshake `stream`, returning it with the RFC 9266 channel binding.
    ///
    /// `peer` identifies the server in `known-hosts` and must be stable and
    /// unique per endpoint (`host:port`, or `vsock:CID:PORT`).
    ///
    /// `verify_hostname=false` is for vsock where there is no hostname; the
    /// peer certificate is still verified against the CA chain.
    async fn handshake<S: AsyncStream + 'static>(
        &self,
        peer: &str,
        domain: &str,
        verify_hostname: bool,
        stream: S,
        error_context: &'static str,
    ) -> Result<(BoxedStream, Option<TlsChannelBinding>)> {
        let known_hosts = self
            .known_hosts
            .as_deref()
            .context("no configuration directory for known-hosts")?;
        let recorded = lookup_known_host(known_hosts, peer)?;
        let first_contact = recorded.is_none();
        let config_dir = self.config_dir.as_deref();
        let ca_configured = config_dir.is_some_and(|d| d.join("server-ca-file").exists());

        let refusal = Arc::new(OnceLock::new());
        let connector =
            build_ssl_connector(config_dir, recorded, ca_configured, Arc::clone(&refusal))?;
        let mut config = connector.configure().context("SSL configure")?;
        // Left on so CA-issued certificates are still name-checked; self-signed
        // ones fail here too, which verify_server_cert tolerates.
        config.set_verify_hostname(verify_hostname);
        let ssl = config.into_ssl(domain).context("SSL setup")?;
        let mut tls_stream = tokio_openssl::SslStream::new(ssl, stream)?;

        if let Err(e) = Pin::new(&mut tls_stream).connect().await {
            return Err(anyhow::Error::new(e).context(match refusal.get() {
                Some(why) => format!("{peer}: {why}"),
                None => error_context.to_string(),
            }));
        }

        if first_contact && let Some(cert) = tls_stream.ssl().peer_certificate() {
            let observed =
                if tls_stream.ssl().verify_result() == openssl::x509::X509VerifyResult::OK {
                    KnownHost::TrustAuthority
                } else {
                    KnownHost::Pin(varlink_http_core::public_key_pin(&cert)?)
                };
            record_known_host(known_hosts, peer, &observed)
                .with_context(|| format!("recording what {peer} presented"))?;
        }

        let tls_channel_binding = varlink_http_core::export_tls_channel_binding(tls_stream.ssl());
        Ok((Box::new(tls_stream), Some(tls_channel_binding)))
    }

    async fn connect_vsock(
        &self,
        url: &str,
    ) -> Result<(BoxedStream, String, Option<TlsChannelBinding>)> {
        let (cid, port, path, use_tls) = parse_vsock_url(url)?;
        debug!("connecting to vsock CID {cid}:{port} (tls: {use_tls})");
        let raw_stream = tokio_vsock::VsockStream::connect(tokio_vsock::VsockAddr::new(cid, port))
            .await
            .with_context(|| format!("vsock connect to CID {cid}:{port} failed"))?;

        if use_tls {
            let (stream, tls_channel_binding) = self
                .handshake(
                    &format!("vsock:{cid}:{port}"),
                    "vsock",
                    false,
                    raw_stream,
                    "TLS handshake over vsock failed: check client cert if server requires mTLS",
                )
                .await?;
            Ok((stream, format!("wss://vsock{path}"), tls_channel_binding))
        } else {
            Ok((Box::new(raw_stream), format!("ws://vsock{path}"), None))
        }
    }

    async fn connect_tcp(
        &self,
        url: &str,
    ) -> Result<(BoxedStream, String, Option<TlsChannelBinding>)> {
        let ws_url = if let Some(rest) = url.strip_prefix("https://") {
            format!("wss://{rest}")
        } else if let Some(rest) = url.strip_prefix("http://") {
            format!("ws://{rest}")
        } else {
            url.to_string()
        };
        let uri: tungstenite::http::Uri = ws_url.parse().context("invalid WebSocket URL")?;
        let use_tls = uri.scheme_str() == Some("wss");
        let host = uri.host().context("URL has no host")?;
        // Uri::host() keeps the brackets on IPv6 literals ("[::1]") but
        // TcpStream::connect and TLS verification need the bare address
        let host = host
            .strip_prefix('[')
            .and_then(|h| h.strip_suffix(']'))
            .unwrap_or(host)
            .to_string();
        let port = uri.port_u16().unwrap_or(if use_tls { 443 } else { 80 });

        debug!("connecting to {host}:{port} (tls: {use_tls})");
        let tcp = tokio::net::TcpStream::connect((host.as_str(), port))
            .await
            .with_context(|| format!("TCP connect to {host}:{port} failed"))?;
        varlink_http_core::set_tcp_keepalive_and_nodelay(&tcp)
            .context("configure client socket")?;

        if use_tls {
            let (stream, tls_channel_binding) = self
                .handshake(
                    &format!("{host}:{port}"),
                    &host,
                    true,
                    tcp,
                    "TLS handshake failed: check client certificate if server requires mTLS",
                )
                .await?;
            Ok((stream, ws_url, tls_channel_binding))
        } else {
            Ok((Box::new(tcp), ws_url, None))
        }
    }

    /// The TLS channel binding is returned so auth headers can be signed
    /// over it before the WebSocket upgrade.
    pub(crate) async fn connect(
        &self,
        url: &str,
    ) -> Result<(
        BoxedStream,
        tungstenite::http::Request<()>,
        Option<TlsChannelBinding>,
    )> {
        use tungstenite::client::IntoClientRequest;

        let (stream, ws_url, tls_channel_binding) =
            if url.starts_with("vsock://") || url.starts_with("vsock+tls://") {
                self.connect_vsock(url).await?
            } else {
                self.connect_tcp(url).await?
            };

        // Use into_client_request() here as it auto-generates standard WS upgrade headers,
        // then we add our auth headers too
        let request = ws_url
            .into_client_request()
            .context("building WS request")?;
        Ok((stream, request, tls_channel_binding))
    }
}

/// Parse a `vsock://CID:PORT/path` or `vsock+tls://CID:PORT/path` URL into
/// CID, port, path and whether the scheme asks for TLS.
///
/// The port defaults to [`varlink_http_core::DEFAULT_PORT`] if omitted (`vsock://CID/path`).
fn parse_vsock_url(url: &str) -> Result<(u32, u32, String, bool)> {
    let (rest, use_tls) = if let Some(rest) = url.strip_prefix("vsock+tls://") {
        (rest, true)
    } else if let Some(rest) = url.strip_prefix("vsock://") {
        (rest, false)
    } else {
        anyhow::bail!("not a vsock:// URL");
    };

    // Split authority from path
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };

    let (cid, port) = varlink_http_core::parse_vsock_cid_port(authority)?;
    Ok((cid, port, path.to_string(), use_tls))
}

fn resp_body_text(resp: &tungstenite::http::Response<Option<Vec<u8>>>) -> Option<String> {
    resp.body()
        .as_deref()
        .filter(|b| !b.is_empty())
        .map(|b| String::from_utf8_lossy(b).into_owned())
}

/// Whether `url` selects a TLS transport, mirroring the scheme handling
/// in [`Transport::connect`] and [`Transport::connect_tcp`].
///
/// Schemes are case-insensitive (RFC 3986 section 3.1), so `HTTPS://` has
/// to count as TLS here too.
/// <https://www.rfc-editor.org/rfc/rfc3986#section-3.1>
#[cfg(feature = "sshauth")]
pub(crate) fn url_is_tls(url: &str) -> bool {
    let scheme = url.split_once("://").map_or("", |(scheme, _)| scheme);
    ["https", "wss", "vsock+tls"]
        .iter()
        .any(|tls_scheme| scheme.eq_ignore_ascii_case(tls_scheme))
}

pub(crate) async fn ws_upgrade(
    request: tungstenite::http::Request<()>,
    stream: BoxedStream,
    is_tls: bool,
) -> Result<WebSocket> {
    // anyhow keeps the tungstenite::Error downcastable through context():
    // the SSH-retry logic detects a 401 via downcast_ref.
    let (ws, _) = tokio_tungstenite::client_async(request, stream)
        .await
        .map_err(|e| {
            let http_detail = match &e {
                tungstenite::Error::Http(resp) => match resp_body_text(resp) {
                    Some(body) => format!(": HTTP {}: {body}", resp.status()),
                    None => format!(": HTTP {}", resp.status()),
                },
                _ => String::new(),
            };
            let tls_hint = if is_tls {
                " (check client cert if server requires mTLS)"
            } else {
                ""
            };
            anyhow::Error::new(e)
                .context(format!("WebSocket handshake failed{http_detail}{tls_hint}"))
        })?;
    debug!("WebSocket established");
    Ok(ws)
}

#[cfg(test)]
mod pin_tests {
    use super::*;
    use openssl::ssl::SslAcceptor;
    use std::time::Duration;

    #[test]
    fn known_hosts_lookup_is_per_peer_and_tolerates_formatting() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("known-hosts");
        assert_eq!(lookup_known_host(&path, "a:1031").unwrap(), None);

        std::fs::write(
            &path,
            "# a comment\n\
             a:1031\tsha256//AAAA=\n\
             b:1031   BBBB=\n\
             \n\
             c:1031 sha256//CCCC= # trailing comment\n\
             d:1031\tca\n",
        )
        .unwrap();

        let pin = |s: &str| KnownHost::Pin(s.to_string());
        // the daemon's own output pastes in verbatim, prefix and all
        assert_eq!(
            lookup_known_host(&path, "a:1031").unwrap(),
            Some(pin("AAAA="))
        );
        // ...and a bare value works too
        assert_eq!(
            lookup_known_host(&path, "b:1031").unwrap(),
            Some(pin("BBBB="))
        );
        assert_eq!(
            lookup_known_host(&path, "c:1031").unwrap(),
            Some(pin("CCCC="))
        );
        // the marker for a peer a trust authority vouched for
        assert_eq!(
            lookup_known_host(&path, "d:1031").unwrap(),
            Some(KnownHost::TrustAuthority)
        );
        // a different port is a different peer
        assert_eq!(lookup_known_host(&path, "a:1032").unwrap(), None);
    }

    #[test]
    fn recorded_entries_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested").join("known-hosts");
        let entries = [
            ("host:1031", KnownHost::Pin("AAAA=".to_string())),
            ("other:1031", KnownHost::Pin("BBBB=".to_string())),
            ("ca-backed:1031", KnownHost::TrustAuthority),
        ];
        for (peer, host) in &entries {
            record_known_host(&path, peer, host).unwrap();
        }
        for (peer, host) in &entries {
            assert_eq!(lookup_known_host(&path, peer).unwrap().as_ref(), Some(host));
        }
    }

    type Identity = (
        openssl::x509::X509,
        openssl::pkey::PKey<openssl::pkey::Private>,
    );

    /// A throwaway identity. Given an `issuer` the certificate is signed by
    /// it and so is not self-signed; without one it signs itself.
    fn identity(cn: &str, issuer: Option<&Identity>, is_ca: bool) -> Identity {
        use openssl::{asn1::Asn1Time, ec, hash::MessageDigest, nid::Nid, pkey::PKey, x509};

        let group = ec::EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        let key = PKey::from_ec_key(ec::EcKey::generate(&group).unwrap()).unwrap();

        let mut nb = x509::X509NameBuilder::new().unwrap();
        nb.append_entry_by_nid(Nid::COMMONNAME, cn).unwrap();
        let name = nb.build();

        let mut b = x509::X509::builder().unwrap();
        b.set_version(2).unwrap();
        b.set_subject_name(&name).unwrap();
        match issuer {
            Some((cert, _)) => b.set_issuer_name(cert.subject_name()).unwrap(),
            None => b.set_issuer_name(&name).unwrap(),
        }
        b.set_pubkey(&key).unwrap();
        b.set_not_before(&Asn1Time::days_from_now(0).unwrap())
            .unwrap();
        b.set_not_after(&Asn1Time::days_from_now(1).unwrap())
            .unwrap();
        if is_ca {
            b.append_extension(
                x509::extension::BasicConstraints::new()
                    .critical()
                    .ca()
                    .build()
                    .unwrap(),
            )
            .unwrap();
        }
        b.sign(issuer.map_or(&key, |(_, k)| k), MessageDigest::sha256())
            .unwrap();
        (b.build(), key)
    }

    /// Rejecting inside the verify callback must abort before we send our own
    /// certificate; rejecting after the handshake would already have leaked it.
    #[tokio::test]
    async fn a_refused_server_never_sees_our_client_certificate() {
        for reject in [true, false] {
            let server = identity("srv", None, false);
            let client = identity("cli", None, false);

            let mut acceptor = SslAcceptor::mozilla_modern_v5(SslMethod::tls_server()).unwrap();
            acceptor.set_certificate(&server.0).unwrap();
            acceptor.set_private_key(&server.1).unwrap();
            acceptor.set_verify_callback(SslVerifyMode::PEER, |_ok, _ctx| true);
            let acceptor = acceptor.build();

            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let (tx, rx) = tokio::sync::oneshot::channel();
            tokio::spawn(async move {
                let (stream, _) = listener.accept().await.unwrap();
                let ssl = openssl::ssl::Ssl::new(acceptor.context()).unwrap();
                let mut tls = tokio_openssl::SslStream::new(ssl, stream).unwrap();
                let _ = Pin::new(&mut tls).accept().await;
                let _ = tx.send(tls.ssl().peer_certificate().is_some());
            });

            let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
            let mut b = SslConnector::builder(SslMethod::tls_client()).unwrap();
            b.set_min_proto_version(Some(SslVersion::TLS1_3)).unwrap();
            b.set_certificate(&client.0).unwrap();
            b.set_private_key(&client.1).unwrap();
            b.set_verify_callback(SslVerifyMode::PEER, move |_ok, _ctx| !reject);
            let mut cfg = b.build().configure().unwrap();
            cfg.set_verify_hostname(false);
            let ssl = cfg.into_ssl("srv").unwrap();
            let mut tls = tokio_openssl::SslStream::new(ssl, stream).unwrap();
            let handshake = Pin::new(&mut tls).connect().await;

            let saw_client_cert = tokio::time::timeout(Duration::from_secs(5), rx)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(handshake.is_err(), reject);
            assert_eq!(
                saw_client_cert, !reject,
                "reject={reject}: the server must only see our certificate when we accept it"
            );
        }
    }

    fn self_signed_pin() -> (Identity, String) {
        let id = identity("leaf", None, false);
        let pin = varlink_http_core::public_key_pin(&id.0).unwrap();
        (id, pin)
    }

    #[test]
    fn a_validated_chain_wins_and_known_hosts_is_not_consulted() {
        let (id, _) = self_signed_pin();
        // a deliberately wrong recorded key must not veto the CA
        let wrong = KnownHost::Pin("AAAA=".to_string());
        assert!(verify_server_cert(&id.0, true, Some(&wrong), false).is_ok());
    }

    #[test]
    fn an_unprovable_issuer_is_refused_even_with_a_recorded_key() {
        let ca = identity("ca", None, true);
        let leaf = identity("leaf", Some(&ca), false);
        let pin = KnownHost::Pin(varlink_http_core::public_key_pin(&leaf.0).unwrap());
        let err = verify_server_cert(&leaf.0, false, Some(&pin), false).unwrap_err();
        assert!(err.contains("does not validate"), "{err}");
    }

    #[test]
    fn self_signed_is_governed_by_known_hosts() {
        let (id, pin) = self_signed_pin();
        // first contact, Transport::handshake records afterwards
        assert!(verify_server_cert(&id.0, false, None, false).is_ok());
        let recorded = KnownHost::Pin(pin);
        assert!(verify_server_cert(&id.0, false, Some(&recorded), false).is_ok());
        let wrong = KnownHost::Pin("AAAA=".to_string());
        let err = verify_server_cert(&id.0, false, Some(&wrong), false).unwrap_err();
        assert!(err.contains("does not match"), "{err}");
    }

    /// The downgrade the `ca` record exists to catch: a peer only ever reached
    /// with a certificate a trust authority vouched for must not be allowed to
    /// turn up self-signed, even though no key was ever pinned for it.
    #[test]
    fn a_ca_backed_peer_refuses_a_later_self_signed_certificate() {
        let (id, _) = self_signed_pin();
        let err =
            verify_server_cert(&id.0, false, Some(&KnownHost::TrustAuthority), false).unwrap_err();
        assert!(err.contains("Refusing the downgrade"), "{err}");
    }

    /// ...while pinning no key, so the server stays free to rotate as long as
    /// what it presents still validates.
    #[test]
    fn a_ca_backed_peer_may_rotate_its_key() {
        let ca = identity("ca", None, true);
        for cn in ["leaf", "leaf-after-rotation"] {
            // a fresh keypair each time round, so this is a real rotation
            let leaf = identity(cn, Some(&ca), false);
            assert!(
                verify_server_cert(&leaf.0, true, Some(&KnownHost::TrustAuthority), false).is_ok(),
                "{cn} must be accepted"
            );
        }
    }

    #[test]
    fn a_configured_ca_disables_first_contact_trust() {
        let (id, _) = self_signed_pin();
        let err = verify_server_cert(&id.0, false, None, true).unwrap_err();
        assert!(err.contains("server-ca-file"), "{err}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_vsock_url_cid_and_port() {
        let (cid, port, path, use_tls) =
            parse_vsock_url("vsock://2:1031/io.systemd.Manager/Describe").unwrap();
        assert!(!use_tls);
        assert_eq!(cid, 2);
        assert_eq!(port, 1031);
        assert_eq!(path, "/io.systemd.Manager/Describe");
    }

    #[test]
    fn test_parse_vsock_url_default_port() {
        let (cid, port, path, _) =
            parse_vsock_url("vsock://2/io.systemd.Manager/Describe").unwrap();
        assert_eq!(cid, 2);
        assert_eq!(port, varlink_http_core::DEFAULT_PORT);
        assert_eq!(path, "/io.systemd.Manager/Describe");
    }

    #[test]
    fn test_parse_vsock_url_no_path() {
        let (cid, port, path, _) = parse_vsock_url("vsock://3:5000").unwrap();
        assert_eq!(cid, 3);
        assert_eq!(port, 5000);
        assert_eq!(path, "/");
    }

    #[test]
    fn test_parse_vsock_url_tls_scheme() {
        let (cid, port, path, use_tls) = parse_vsock_url("vsock+tls://2:1031/path").unwrap();
        assert_eq!(
            (cid, port, path.as_str(), use_tls),
            (2, 1031, "/path", true)
        );
    }

    #[test]
    fn test_parse_vsock_url_errors() {
        assert!(parse_vsock_url("http://localhost").is_err());
        assert!(parse_vsock_url("vsock://notanumber:1031/path").is_err());
        assert!(parse_vsock_url("vsock://2:notaport/path").is_err());
    }

    #[cfg(feature = "sshauth")]
    mod sshauth {
        use super::*;
        use tokio::io::AsyncWriteExt;

        #[test]
        fn test_url_is_tls_ignores_scheme_case() {
            for url in [
                "https://h/",
                "HTTPS://h/",
                "WsS://h/",
                "VSOCK+TLS://2:1031/",
            ] {
                assert!(url_is_tls(url), "{url}");
            }
            for url in [
                "http://h/",
                "HTTP://h/",
                "ws://h/",
                "vsock://2:1031/",
                "h:1031",
            ] {
                assert!(!url_is_tls(url), "{url}");
            }
        }

        /// Wraps the handshake error the same way `ws_upgrade` does.
        async fn handshake_error(response: &'static str) -> anyhow::Error {
            // capacity must fit the unread client request or the handshake deadlocks
            let (client, mut server) = tokio::io::duplex(64 * 1024);
            server.write_all(response.as_bytes()).await.unwrap();
            tokio_tungstenite::client_async("ws://localhost/", client)
                .await
                .map(|_| ())
                .map_err(|e| anyhow::Error::new(e).context("WebSocket handshake failed"))
                .expect_err("handshake should fail")
        }

        /// A handshake 401 must stay downcastable to `tungstenite::Error::Http`
        /// through the anyhow context so the sshauth retry logic can detect it.
        #[tokio::test]
        async fn test_ws_handshake_401_is_detected_as_unauthorized() {
            let err =
                handshake_error("HTTP/1.1 401 Unauthorized\r\ncontent-length: 0\r\n\r\n").await;
            assert!(crate::sshauth_client::is_http_unauthorized(&err), "{err:#}");
        }

        #[tokio::test]
        async fn test_ws_handshake_other_error_is_not_unauthorized() {
            let err =
                handshake_error("HTTP/1.1 500 Internal Server Error\r\ncontent-length: 0\r\n\r\n")
                    .await;
            assert!(
                !crate::sshauth_client::is_http_unauthorized(&err),
                "{err:#}"
            );
        }
    }
}
