// SPDX-License-Identifier: LGPL-2.1-or-later

//! Self-signed server certificate management.
//!
//! TLS is mandatory for TCP listeners, so an operator who provides no
//! `--cert`/`--key` (or no `cert`/`key` credential) still needs
//! one. Rather than refusing to start, the bridge generates a
//! long-lived self-signed certificate on first run and persists it
//! alongside its key, mirroring how `sshd` treats host keys.
//!
//! It chains to nothing, so clients must pin it. The pin covers the public
//! key, not the certificate, so regenerating the certificate from the same
//! key keeps every existing pin valid.

use anyhow::{Context, bail};
use openssl::asn1::Asn1Time;
use openssl::bn::{BigNum, MsbOption};
use openssl::ec::{EcGroup, EcKey};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{PKey, Private};
use openssl::x509::extension::{
    BasicConstraints, ExtendedKeyUsage, KeyUsage, SubjectAlternativeName,
};
use openssl::x509::{X509, X509NameBuilder};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

/// Ten years. A self-signed certificate has no revocation story.
const VALIDITY_DAYS: u32 = 3650;

/// P-256 rather than Ed25519: the certificate has to be accepted by whatever
/// HTTP client a user reaches for, and ECDSA support is universal where
/// Ed25519 certificate support still is not.
fn generate_keypair() -> anyhow::Result<PKey<Private>> {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).context("selecting P-256 curve")?;
    let ec = EcKey::generate(&group).context("generating P-256 key")?;
    PKey::from_ec_key(ec).context("wrapping EC key")
}

/// Names this host is likely to be reached by.
///
/// Deliberately a short static list rather than anything clever.
/// Users should rather pin the pub key (curl's `--pinnedpubkey`)
/// for server verification in the auto-generated cert flow.
fn default_sans() -> Vec<String> {
    let mut sans = vec![
        "localhost".to_string(),
        "127.0.0.1".to_string(),
        "::1".to_string(),
    ];
    let uname = rustix::system::uname();
    if let Ok(host) = uname.nodename().to_str()
        && !host.is_empty()
        && host != "localhost"
    {
        sans.push(host.to_string());
        if !host.contains('.') {
            sans.push(format!("{host}.local"));
        }
    }
    sans
}

fn build_self_signed(key: &PKey<Private>, sans: &[String]) -> anyhow::Result<X509> {
    let mut name = X509NameBuilder::new()?;
    name.append_entry_by_nid(Nid::COMMONNAME, "varlink-httpd")?;
    let name = name.build();

    let mut builder = X509::builder()?;
    builder.set_version(2)?; // X.509 v3
    builder.set_subject_name(&name)?;
    builder.set_issuer_name(&name)?;
    builder.set_pubkey(key)?;
    let not_before = Asn1Time::days_from_now(0)?;
    let not_after = Asn1Time::days_from_now(VALIDITY_DAYS)?;
    builder.set_not_before(&not_before)?;
    builder.set_not_after(&not_after)?;

    let mut serial = BigNum::new()?;
    serial.rand(159, MsbOption::MAYBE_ZERO, false)?;
    let serial = serial.to_asn1_integer()?;
    builder.set_serial_number(&serial)?;

    builder.append_extension(BasicConstraints::new().critical().build()?)?;
    builder.append_extension(
        KeyUsage::new()
            .critical()
            .digital_signature()
            .key_encipherment()
            .build()?,
    )?;
    builder.append_extension(ExtendedKeyUsage::new().server_auth().build()?)?;

    let mut san = SubjectAlternativeName::new();
    for entry in sans {
        if entry.parse::<std::net::IpAddr>().is_ok() {
            san.ip(entry);
        } else {
            san.dns(entry);
        }
    }
    let ctx = builder.x509v3_context(None, None);
    builder.append_extension(san.build(&ctx)?)?;

    builder.sign(key, MessageDigest::sha256())?;
    Ok(builder.build())
}

pub(crate) fn state_dir() -> anyhow::Result<PathBuf> {
    if let Some(d) = std::env::var_os("STATE_DIRECTORY") {
        return Ok(PathBuf::from(d));
    }
    if let Some(d) = std::env::var_os("XDG_STATE_HOME") {
        return Ok(PathBuf::from(d).join("varlink-httpd"));
    }
    let home = std::env::var_os("HOME")
        .context("none of STATE_DIRECTORY, XDG_STATE_HOME or HOME is set")?;
    Ok(PathBuf::from(home).join(".local/state/varlink-httpd"))
}

/// Write `contents` to `path` atomically with `mode`.
fn write_private(path: &Path, contents: &[u8], mode: u32) -> anyhow::Result<()> {
    use std::io::Write as _;

    let dir = path.parent().context("path has no parent directory")?;
    std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    let mut tmp = tempfile::NamedTempFile::new_in(dir)
        .with_context(|| format!("creating tempfile in {}", dir.display()))?;
    std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(mode))
        .with_context(|| format!("setting mode {mode:o} on tempfile for {}", path.display()))?;
    tmp.write_all(contents)
        .with_context(|| format!("writing {}", path.display()))?;
    tmp.as_file()
        .sync_all()
        .with_context(|| format!("syncing {}", path.display()))?;
    tmp.persist(path)
        .with_context(|| format!("renaming tempfile to {}", path.display()))?;
    Ok(())
}

/// Load the persisted self-signed certificate, or create one if absent.
pub(crate) fn load_or_generate(dir: &Path) -> anyhow::Result<(PathBuf, PathBuf)> {
    let (cert_path, key_path) = (dir.join("server-cert.pem"), dir.join("server-key.pem"));

    match (cert_path.exists(), key_path.exists()) {
        (true, true) => {
            let mode = std::fs::metadata(&key_path)
                .with_context(|| format!("stat {}", key_path.display()))?
                .permissions()
                .mode()
                & 0o777;
            // reject group/other access only, so 0400 is as fine as 0600
            if mode & 0o077 != 0 {
                bail!(
                    "refusing to use generated TLS key {}: permissions are 0{mode:o}, must not be group- or world-accessible",
                    key_path.display()
                );
            }
            return Ok((cert_path, key_path));
        }
        (false, false) => {}
        // Regenerating would silently invalidate every client pin, so leave
        // a half-written pair to the operator.
        _ => bail!(
            "incomplete generated TLS material in {}: expected both {} and {}",
            dir.display(),
            cert_path.display(),
            key_path.display()
        ),
    }

    let sans = default_sans();
    let key = generate_keypair()?;
    let cert = build_self_signed(&key, &sans)?;

    write_private(
        &key_path,
        &key.private_key_to_pem_pkcs8()
            .context("encoding private key")?,
        0o600,
    )?;
    write_private(
        &cert_path,
        &cert.to_pem().context("encoding certificate")?,
        0o644,
    )?;

    eprintln!(
        "TLS: generated self-signed certificate {} (SAN: {})",
        cert_path.display(),
        sans.join(", ")
    );
    Ok((cert_path, key_path))
}

/// Announce the pin clients must verify the server against: what
/// `varlinkctl-http` records in `known-hosts`, and what curl takes via
/// `--pinnedpubkey`.
pub(crate) fn print_pin(cert_path: &Path) -> anyhow::Result<()> {
    let pem =
        std::fs::read(cert_path).with_context(|| format!("reading {}", cert_path.display()))?;
    let cert = X509::from_pem(&pem).with_context(|| format!("parsing {}", cert_path.display()))?;
    let pin = varlink_http_bridge::public_key_pin(&cert)?;
    eprintln!("TLS: using self-signed certificate, pin clients to sha256//{pin}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir() -> tempfile::TempDir {
        tempfile::tempdir().unwrap()
    }

    #[test]
    fn generates_a_usable_pair_on_first_run() {
        let dir = tmpdir();
        let (cert_path, key_path) = load_or_generate(dir.path()).unwrap();
        assert!(cert_path.exists() && key_path.exists());

        // the pair must actually load as a TLS server identity
        crate::load_tls_config(
            cert_path.to_str().unwrap(),
            key_path.to_str().unwrap(),
            None,
            false,
        )
        .expect("generated material must build an acceptor");
    }

    #[test]
    fn key_is_written_0600_and_cert_world_readable() {
        let dir = tmpdir();
        let (cert_path, key_path) = load_or_generate(dir.path()).unwrap();
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&key_path), 0o600);
        assert_eq!(mode(&cert_path), 0o644);
    }

    #[test]
    fn second_run_reuses_the_same_key_so_pins_survive() {
        let dir = tmpdir();
        let (cert_a, _) = load_or_generate(dir.path()).unwrap();
        let pin_a = varlink_http_bridge::public_key_pin(
            &X509::from_pem(&std::fs::read(&cert_a).unwrap()).unwrap(),
        )
        .unwrap();

        let (cert_b, _) = load_or_generate(dir.path()).unwrap();
        let pin_b = varlink_http_bridge::public_key_pin(
            &X509::from_pem(&std::fs::read(&cert_b).unwrap()).unwrap(),
        )
        .unwrap();

        assert_eq!(pin_a, pin_b, "regeneration must not invalidate client pins");
    }

    #[test]
    fn refuses_a_half_written_pair() {
        let dir = tmpdir();
        let (cert_path, key_path) = load_or_generate(dir.path()).unwrap();
        std::fs::remove_file(&key_path).unwrap();

        let err = load_or_generate(dir.path()).unwrap_err();
        assert!(
            format!("{err:#}").contains("incomplete"),
            "expected an incomplete-material error, got: {err:#}"
        );
        assert!(cert_path.exists(), "the surviving half must be left alone");
    }

    #[test]
    fn refuses_a_world_readable_key() {
        let dir = tmpdir();
        let (_, key_path) = load_or_generate(dir.path()).unwrap();
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o644)).unwrap();

        let err = load_or_generate(dir.path()).unwrap_err();
        assert!(
            format!("{err:#}").contains("0644"),
            "expected a permissions error naming the mode, got: {err:#}"
        );
    }

    #[test]
    fn cert_carries_the_loopback_sans() {
        let dir = tmpdir();
        let (cert_path, _) = load_or_generate(dir.path()).unwrap();
        let cert = X509::from_pem(&std::fs::read(cert_path).unwrap()).unwrap();
        let san = cert.subject_alt_names().expect("cert must carry SANs");
        let dns: Vec<String> = san
            .iter()
            .filter_map(|n| n.dnsname().map(String::from))
            .collect();
        assert!(
            dns.contains(&"localhost".to_string()),
            "got DNS SANs {dns:?}"
        );
        assert!(
            san.iter().any(|n| n.ipaddress().is_some()),
            "loopback IP SANs must be present"
        );
    }
}
