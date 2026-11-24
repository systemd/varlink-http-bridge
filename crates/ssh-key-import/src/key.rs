// SPDX-License-Identifier: LGPL-2.1-or-later

//! Parses SSH private keys in the OpenSSH format or as PKCS#8.

use anyhow::{Context, bail};
use p256::elliptic_curve::sec1::ToEncodedPoint as _;
use p256::pkcs8::{AssociatedOid as _, PrivateKeyInfo, SecretDocument};
use ssh_key::private::{EcdsaKeypair, Ed25519Keypair, KeypairData};

/// The first line of an unencrypted PEM-encoded PKCS#8 private key.
const PKCS8_PEM_BEGIN: &str = "-----BEGIN PRIVATE KEY-----";

/// The first line of an encrypted PEM-encoded PKCS#8 private key.
const ENCRYPTED_PKCS8_PEM_BEGIN: &str = "-----BEGIN ENCRYPTED PRIVATE KEY-----";

/// Parses a private key in the OpenSSH format or an unencrypted PEM-encoded
/// PKCS#8 private key. A PKCS#8 key must be an Ed25519 or ECDSA P-256 key,
/// and the returned key has no comment.
///
/// # Errors
/// Fails if `s` is in neither format, if a PKCS#8 key is encrypted, or if a
/// PKCS#8 key uses another algorithm.
pub fn parse_private_key(s: &str) -> anyhow::Result<ssh_key::PrivateKey> {
    let pem = s.trim();
    if pem.starts_with(ENCRYPTED_PKCS8_PEM_BEGIN) {
        bail!("encrypted PKCS#8 private keys are not supported");
    }
    if pem.starts_with(PKCS8_PEM_BEGIN) {
        return private_key_from_pkcs8(pem);
    }
    ssh_key::PrivateKey::from_openssh(s).context("parsing the OpenSSH private key")
}

fn private_key_from_pkcs8(pem: &str) -> anyhow::Result<ssh_key::PrivateKey> {
    // PKCS#8 is specified in https://www.rfc-editor.org/rfc/rfc5958
    let (_, der) = SecretDocument::from_pem(pem).context("decoding the PEM private key")?;
    let info =
        PrivateKeyInfo::try_from(der.as_bytes()).context("parsing the PKCS#8 private key")?;
    let algorithm = info.algorithm;
    let key_data = if algorithm.oid == ed25519_dalek::pkcs8::ALGORITHM_OID {
        let key =
            ed25519_dalek::SigningKey::try_from(info).context("parsing the Ed25519 private key")?;
        KeypairData::Ed25519(Ed25519Keypair::from(key))
    } else if algorithm.oid == p256::elliptic_curve::ALGORITHM_OID
        && algorithm.parameters_oid().ok() == Some(p256::NistP256::OID)
    {
        let key = p256::SecretKey::try_from(info).context("parsing the ECDSA P-256 private key")?;
        KeypairData::Ecdsa(EcdsaKeypair::NistP256 {
            public: key.public_key().to_encoded_point(false),
            private: key.into(),
        })
    } else {
        bail!("unsupported PKCS#8 private key; use an Ed25519 or ECDSA P-256 key");
    };
    ssh_key::PrivateKey::new(key_data, "").context("creating the SSH private key")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An Ed25519 private key as `ssh-keygen -m PKCS8` writes it.
    const ED25519_PKCS8: &str = "-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIJp/ivWBrtAi7u6Z72WTMWrpu1zVlz4Ls6+mJkD8mu2c
-----END PRIVATE KEY-----
";
    const ED25519_PUBLIC: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBzYVZA+gLrPAWNlOTZB8GwPqe4347ra42rkwGRCr0E2";

    const P256_PKCS8: &str = "-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQglnZKzmSnljj4Tn+u
XtFo1GZnBm8xvf1Ec0X/LowXSk6hRANCAASerdqRuOBGj6gEz+t3XM2vX51KR0HC
ss7/7rrV3JCqYJFBhENj/wPPXyLXPylZcR1I6fjbWlFQMvRu0exMzoyN
-----END PRIVATE KEY-----
";
    const P256_PUBLIC: &str = "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBJ6t2pG44EaPqATP63dcza9fnUpHQcKyzv/uutXckKpgkUGEQ2P/A89fItc/KVlxHUjp+NtaUVAy9G7R7EzOjI0=";

    const P384_PKCS8: &str = "-----BEGIN PRIVATE KEY-----
MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDDlSNGi7PVp7teqdNn8
10pHXSg1X/jOjYN+X/kQ6w715Hr+4iDn6Ob5AV3pPMcEWtuhZANiAATElsqcxl1W
F4WzlwxvD/c7rDujA47uk4485L1PCAvjdILRWrait2f1Xlu5a/eGKeqZSgJDEH4o
ngulUvY8brUEosq8PiUWZJKmC/3fNFc23JhaNHy8sAjBbtL/eKkExVI=
-----END PRIVATE KEY-----
";

    /// parse_private_key() rejects an encrypted PKCS#8 key by its first
    /// line, so the key needs no content.
    const ENCRYPTED_PKCS8: &str = "-----BEGIN ENCRYPTED PRIVATE KEY-----
-----END ENCRYPTED PRIVATE KEY-----
";

    #[test]
    fn test_parse_pkcs8_private_key() {
        // Ed25519 and ECDSA P-256 keys in PKCS#8 must parse to the key pairs
        // whose public keys `ssh-keygen -y` prints for them.
        for (pkcs8, public) in [(ED25519_PKCS8, ED25519_PUBLIC), (P256_PKCS8, P256_PUBLIC)] {
            let key = parse_private_key(pkcs8).unwrap();
            let expected = ssh_key::PublicKey::from_openssh(public).unwrap();
            assert_eq!(key.public_key().key_data(), expected.key_data());
        }
    }

    #[test]
    fn test_parse_openssh_private_key_roundtrip() {
        // A key parsed from PKCS#8 and written in the OpenSSH format must
        // parse back to the same key.
        let key = parse_private_key(ED25519_PKCS8).unwrap();
        let openssh = key.to_openssh(ssh_key::LineEnding::LF).unwrap();
        assert_eq!(parse_private_key(&openssh).unwrap(), key);
    }

    #[test]
    fn test_parse_unsupported_pkcs8_private_key() {
        // A P-384 key and an encrypted key in PKCS#8 must fail with an error
        // that names the problem.
        for (pkcs8, expected) in [
            (P384_PKCS8, "Ed25519 or ECDSA P-256"),
            (ENCRYPTED_PKCS8, "encrypted"),
        ] {
            let err = format!("{:#}", parse_private_key(pkcs8).unwrap_err());
            assert!(err.contains(expected), "{err}");
        }
    }

    #[test]
    fn test_parse_malformed_private_key() {
        // Empty input, text that isn't a key and a truncated PKCS#8 key must
        // fail to parse.
        let truncated = &ED25519_PKCS8[..ED25519_PKCS8.len() / 2];
        for input in ["", "not a key", truncated] {
            assert!(parse_private_key(input).is_err(), "parsed {input:?}");
        }
    }

    #[test]
    fn test_parse_corrupt_ed25519_private_key() {
        // A PKCS#8 Ed25519 key with a private key of the wrong length must
        // fail with an error about the Ed25519 key, not about the algorithm.
        // The key below stores 31 instead of 32 bytes.
        let corrupt = "-----BEGIN PRIVATE KEY-----
MC0CAQAwBQYDK2VwBCEEH5p/ivWBrtAi7u6Z72WTMWrpu1zVlz4Ls6+mJkD8mu0=
-----END PRIVATE KEY-----
";
        let err = format!("{:#}", parse_private_key(corrupt).unwrap_err());
        assert!(err.contains("parsing the Ed25519 private key"), "{err}");
    }
}
