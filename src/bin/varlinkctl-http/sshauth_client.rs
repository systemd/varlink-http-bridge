// SPDX-License-Identifier: LGPL-2.1-or-later

use anyhow::{Context, Result, bail};
use log::{debug, warn};
use varlink_httpd::SSHAUTH_MAGIC_PREFIX;

struct Signer {
    builder: sshauth::signer::TokenSignerBuilder,
    algo: ssh_key::Algorithm,
    fingerprint: ssh_key::Fingerprint,
    comment: String,
    source: String,
}

// Slightly ugly to build it here dynamically, but when this code is
// built without the sshauth feature this file is not built at all so
// making everything async seems overkill (only this helper needs
// async so far)
static TOKIO_RT: std::sync::LazyLock<tokio::runtime::Runtime> = std::sync::LazyLock::new(|| {
    tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .build()
        .expect("creating tokio runtime")
});

pub(crate) fn maybe_add_auth_headers(
    request: &mut tungstenite::http::Request<()>,
    uri: &tungstenite::http::Uri,
    tls_channel_binding: Option<&str>,
) -> Result<()> {
    let path_and_query = uri
        .path_and_query()
        .map_or(uri.path(), tungstenite::http::uri::PathAndQuery::as_str);

    let (bearer, nonce) = match build_auth_token("GET", path_and_query, tls_channel_binding) {
        Ok(Some((bearer, nonce))) => (bearer, nonce),
        Ok(None) => return Ok(()),
        Err(e) => {
            warn!("SSH auth token generation failed, proceeding without: {e:#}");
            return Ok(());
        }
    };
    request.headers_mut().insert(
        "Authorization",
        bearer.parse().context("invalid auth header value")?,
    );
    request.headers_mut().insert(
        varlink_httpd::SSHAUTH_NONCE_HEADER,
        nonce.parse().context("invalid nonce header value")?,
    );
    Ok(())
}

/// Build an SSH auth token for the given HTTP method and path.
///
/// Returns `Ok(None)` when no SSH credentials are available.
fn build_auth_token(
    method: &str,
    path_and_query: &str,
    tls_channel_binding: Option<&str>,
) -> Result<Option<(String, String)>> {
    // The sshauth crate is async so we need to run this inside an async context
    TOKIO_RT.block_on(async {
        let Some(mut signer) = build_signer().await? else {
            return Ok(None);
        };
        debug!(
            "SSH auth: using {} key {} ({}) from {}",
            signer.algo, signer.fingerprint, signer.comment, signer.source,
        );

        let nonce = generate_nonce();

        signer
            .builder
            .include_fingerprint(true)
            .magic_prefix(SSHAUTH_MAGIC_PREFIX);
        let token_signer = signer.builder.build()?;

        let mut tb = token_signer.sign_for();
        tb.action("method", method)
            .action("path", path_and_query)
            .action("nonce", &nonce)
            .action(
                "tls-channel-binding",
                tls_channel_binding.unwrap_or_default(),
            );

        let token: sshauth::token::Token = tb.sign().await?;
        Ok(Some((format!("Bearer {}", token.encode()), nonce)))
    })
}

/// Build a [`Signer`] from the available SSH credentials.
///
/// Reads `VARLINK_SSH_KEY` and `SSH_AUTH_SOCK` from the environment and
/// tries, in order:
/// 1. `VARLINK_SSH_KEY` with a private key on disk → sign directly.
/// 2. `VARLINK_SSH_KEY` with only a public key → delegate to the ssh-agent.
/// 3. `SSH_AUTH_SOCK` only → pick the first supported key from the agent.
///
/// Returns `Ok(None)` when neither variable is set.
async fn build_signer() -> Result<Option<Signer>> {
    let key_path = std::env::var("VARLINK_SSH_KEY").ok();
    let auth_sock = std::env::var("SSH_AUTH_SOCK").ok();

    if let Some(key_path) = key_path {
        // If a normal (non-hardware-token) private key exists, sign directly.
        if let Some(privkey) = read_private_key(&key_path)?
            && !requires_agent(&privkey.algorithm())
        {
            let algo = privkey.algorithm();
            let fingerprint = privkey.fingerprint(ssh_key::HashAlg::Sha256);
            let comment = privkey.comment().to_string();
            let builder = sshauth::TokenSigner::using_private_key(privkey)?;
            return Ok(Some(Signer {
                builder,
                algo,
                fingerprint,
                comment,
                source: key_path,
            }));
        }

        // Otherwise delegate to the SSH agent: either the key is a
        // hardware token (sk-*) or only the .pub file exists on disk.
        let pubkey = read_public_key(&key_path)?;

        // Delegate to the SSH agent for signing.
        let auth_sock = auth_sock.as_deref().context(
            "VARLINK_SSH_KEY requires agent-based signing (hardware token \
             or public key only); set SSH_AUTH_SOCK",
        )?;
        let fp = pubkey.fingerprint(ssh_key::HashAlg::Sha256);
        let agent_keys = sshauth::agent::list_keys(auth_sock)
            .await
            .context("listing ssh-agent keys")?;
        if !agent_keys
            .iter()
            .any(|k| k.fingerprint(ssh_key::HashAlg::Sha256) == fp)
        {
            bail!(
                "VARLINK_SSH_KEY key {fp} not found in ssh-agent; \
                 add it with ssh-add or provide the private key"
            );
        }
        let algo = pubkey.algorithm();
        let comment = pubkey.comment().to_string();
        let mut builder = sshauth::TokenSigner::using_authsock(auth_sock)?;
        builder.key(pubkey);
        return Ok(Some(Signer {
            builder,
            algo,
            fingerprint: fp,
            comment,
            source: key_path,
        }));
    }

    // SSH_AUTH_SOCK is set
    if let Some(auth_sock) = auth_sock {
        let keys = sshauth::agent::list_keys(&auth_sock)
            .await
            .context("listing ssh-agent keys")?;
        let key = read_agent_key(keys)?;
        let algo = key.algorithm();
        let fingerprint = key.fingerprint(ssh_key::HashAlg::Sha256);
        let comment = key.comment().to_string();
        let mut builder = sshauth::TokenSigner::using_authsock(&auth_sock)?;
        builder.key(key);
        return Ok(Some(Signer {
            builder,
            algo,
            fingerprint,
            comment,
            source: auth_sock,
        }));
    }

    // No VARLINK_SSH_KEY or SSH_AUTH_SOCK
    Ok(None)
}

fn generate_nonce() -> String {
    let mut buf = [0u8; 16];
    openssl::rand::rand_bytes(&mut buf).expect("openssl PRNG failed");
    openssl::base64::encode_block(&buf)
}

/// Read the signing key from the agent.
///
/// Picks the first supported (non-RSA) key, warning about any RSA keys found.
fn read_agent_key(keys: Vec<ssh_key::PublicKey>) -> Result<ssh_key::PublicKey> {
    for k in &keys {
        if ensure_supported_algorithm(&k.algorithm(), "ssh-agent key").is_err() {
            warn!(
                "skipping RSA key {} ({}): RSA signing is not supported, use Ed25519 or ECDSA",
                k.fingerprint(ssh_key::HashAlg::Sha256),
                k.comment(),
            );
        }
    }
    keys.into_iter()
        .find(|k| ensure_supported_algorithm(&k.algorithm(), "ssh-agent key").is_ok())
        .context("no supported key in ssh-agent")
}

/// Read a private key from `key_path`.
///
/// If the path ends in `.pub`, the corresponding private key path (without the
/// extension) is tried instead.  Returns `Ok(None)` when the private key file
/// does not exist.
#[allow(clippy::case_sensitive_file_extension_comparisons)]
fn read_private_key(key_path: &str) -> Result<Option<ssh_key::PrivateKey>> {
    let privkey_path = key_path.strip_suffix(".pub").unwrap_or(key_path);
    let pem = match std::fs::read_to_string(privkey_path) {
        Ok(pem) => pem,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => {
            return Err(
                anyhow::Error::new(e).context(format!("reading private key from {privkey_path}"))
            );
        }
    };
    let privkey = ssh_key::PrivateKey::from_openssh(pem.trim())
        .with_context(|| format!("parsing private key from {privkey_path}"))?;
    ensure_supported_algorithm(&privkey.algorithm(), key_path)?;
    Ok(Some(privkey))
}

/// Read a public key from `key_path`.
///
/// If the path does not end in `.pub`, the `.pub` extension is appended.
#[allow(clippy::case_sensitive_file_extension_comparisons)]
fn read_public_key(key_path: &str) -> Result<ssh_key::PublicKey> {
    let pubkey_path = if key_path.ends_with(".pub") {
        key_path.to_string()
    } else {
        format!("{key_path}.pub")
    };
    let data = std::fs::read_to_string(&pubkey_path)
        .with_context(|| format!("reading public key from {pubkey_path}"))?;
    let pubkey = ssh_key::PublicKey::from_openssh(data.trim())
        .with_context(|| format!("parsing public key from {pubkey_path}"))?;
    ensure_supported_algorithm(&pubkey.algorithm(), key_path)?;
    Ok(pubkey)
}

fn ensure_supported_algorithm(algo: &ssh_key::Algorithm, source: &str) -> Result<()> {
    if matches!(algo, ssh_key::Algorithm::Rsa { .. }) {
        bail!("{source} is an RSA key, which is not supported; use Ed25519 or ECDSA");
    }
    Ok(())
}

/// Hardware-token key algorithms (FIDO2 sk-*) that cannot sign directly
/// and must be delegated to the SSH agent.
fn requires_agent(algo: &ssh_key::Algorithm) -> bool {
    matches!(
        algo,
        ssh_key::Algorithm::SkEcdsaSha2NistP256 | ssh_key::Algorithm::SkEd25519
    )
}
