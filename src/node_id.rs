// SPDX-License-Identifier: LGPL-2.1-or-later

//! Handle the node-id for the varlink relayd tunnel. Uses the
//! /etc/machine-id and `sd_id128_get_machine_app_specific()` to get
//! a per-machine stable node identifier (see `man machine-id`).

use anyhow::{Context, bail};

/// Fixed forever: changing it renames every node in every deployment.
const TUNNEL_APP_ID: u128 = 0x7a16_4c93_87b5_48ae_aaa0_8cbf_80d2_7865;

/// The id this machine is addressed by. A host may run more than one
/// bridge, each addressed separately: `instance` is that bridge's
/// label, `None` is the host itself.
///
/// # Errors
/// Returns an error if `/etc/machine-id` cannot be read or parsed;
/// empty and "uninitialized" are valid states per `machine-id(5)`.
pub fn local_node_id(instance: Option<&str>) -> anyhow::Result<NodeId> {
    let text = std::fs::read_to_string("/etc/machine-id").context("reading /etc/machine-id")?;
    let machine_id: MachineId = text.trim().parse()?;
    match instance {
        Some(label) => machine_id.instance_node_id(label),
        None => machine_id.node_id(),
    }
}

/// The machine id from `/etc/machine-id`. Confidential, so no
/// `Display`, a redacting `Debug`, and the only way out is the
/// derivation in [`MachineId::node_id`].
pub struct MachineId(u128);

impl std::fmt::Debug for MachineId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("MachineId(<redacted>)")
    }
}

impl std::str::FromStr for MachineId {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(
            parse_id128(s).context("invalid machine id (value redacted)")?,
        ))
    }
}

impl MachineId {
    /// What `systemd-id128 machine-id -a <app-id>` prints for the
    /// fixed app id.
    ///
    /// # Errors
    /// Returns an error if the HMAC computation fails.
    pub fn node_id(&self) -> anyhow::Result<NodeId> {
        Ok(NodeId(hmac_id128(
            &self.0.to_be_bytes(),
            &TUNNEL_APP_ID.to_be_bytes(),
        )?))
    }

    /// The id of the bridge labelled `label` on this host. The label is
    /// folded into the app id by the same step, so `systemd-id128
    /// machine-id -a` still prints it given that derived app id.
    ///
    /// # Errors
    /// Returns an error if the HMAC computation fails.
    pub fn instance_node_id(&self, label: &str) -> anyhow::Result<NodeId> {
        let instance_app_id = hmac_id128(&TUNNEL_APP_ID.to_be_bytes(), label.as_bytes())?;
        Ok(NodeId(hmac_id128(
            &self.0.to_be_bytes(),
            &instance_app_id.to_be_bytes(),
        )?))
    }
}

/// One `sd_id128_get_app_specific(3)` step.
fn hmac_id128(key: &[u8], msg: &[u8]) -> anyhow::Result<u128> {
    // the libsystemd crate has this too, but would add nom plus a
    // duplicate nix dependency for one function. Reconsider if we
    // need more from rusts libsystemd
    let mac = crate::tls::hmac_sha256(key, msg)?;

    let mut id = [0u8; 16];
    id.copy_from_slice(&mac[..16]);
    // v4 UUID fixup, as sd_id128 does
    id[6] = (id[6] & 0x0F) | 0x40;
    id[8] = (id[8] & 0x3F) | 0x80;
    Ok(u128::from_be_bytes(id))
}

/// The derived node-id, public. Prints in the `machine-id(5)` format.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct NodeId(u128);

impl std::str::FromStr for NodeId {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(parse_id128(s).with_context(|| {
            format!("not a 128-bit id in hex format: {s:?}")
        })?))
    }
}

impl std::fmt::Display for NodeId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:032x}", self.0)
    }
}

impl std::fmt::Debug for NodeId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "NodeId({self})")
    }
}

/// The error never contains the input, which may be a confidential
/// machine id; callers add their own context.
fn parse_id128(s: &str) -> anyhow::Result<u128> {
    // from_str_radix alone would tolerate a leading '+'
    if s.len() != 32 || s.starts_with('+') {
        bail!("not 32 hex chars");
    }
    u128::from_str_radix(s, 16).context("not 32 hex chars")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn node_id_matches_fixed_vector() {
        // computed independently with python's hmac
        let machine_id: MachineId = "0123456789abcdef0123456789abcdef".parse().unwrap();
        assert_eq!(
            machine_id.node_id().unwrap().to_string(),
            "f2315cbd916742ecaab3178006407118"
        );
    }

    #[test]
    fn instance_node_id_matches_fixed_vector() {
        // computed independently with python's hmac; the instance app
        // id for "update" is 4608112769664e2db94e37a233b9572b
        let machine_id: MachineId = "0123456789abcdef0123456789abcdef".parse().unwrap();
        assert_eq!(
            machine_id.instance_node_id("update").unwrap().to_string(),
            "0e4178539a8045b492c42674e271b422"
        );
        assert_ne!(
            machine_id.instance_node_id("update").unwrap(),
            machine_id.node_id().unwrap()
        );
        assert_ne!(
            machine_id.instance_node_id("update").unwrap(),
            machine_id.instance_node_id("metrics").unwrap()
        );
    }

    #[test]
    fn machine_id_never_prints_its_value() {
        let machine_id: MachineId = "0123456789abcdef0123456789abcdef".parse().unwrap();
        assert_eq!(format!("{machine_id:?}"), "MachineId(<redacted>)");

        // an untrimmed read of /etc/machine-id is the common near-miss
        let err = "0123456789abcdef0123456789abcdef\n"
            .parse::<MachineId>()
            .unwrap_err();
        assert!(!format!("{err:#}").contains("0123456789"));
    }

    #[test_with::path(/etc/machine-id)]
    #[test_with::executable(systemd-id128)]
    #[test]
    fn node_id_matches_systemd_id128() {
        // empty or "uninitialized" are valid, nothing to compare then
        let Ok(machine_id) = std::fs::read_to_string("/etc/machine-id") else {
            return;
        };
        let Ok(machine_id) = machine_id.trim().parse::<MachineId>() else {
            return;
        };
        let app_id = format!("{TUNNEL_APP_ID:032x}");
        let out = std::process::Command::new("systemd-id128")
            .args(["machine-id", "-a", &app_id])
            .output()
            .unwrap();
        if !out.status.success() {
            return;
        }
        let theirs = String::from_utf8(out.stdout).unwrap();
        assert_eq!(machine_id.node_id().unwrap().to_string(), theirs.trim());
    }

    #[test]
    fn parse_id128_rejects_garbage() {
        let id = "0123456789abcdef0123456789abcdef";
        assert_eq!(id.parse::<NodeId>().unwrap().to_string(), id);
        for bad in [
            "",
            "0123",
            "g123456789abcdef0123456789abcdef",
            "+123456789abcdef0123456789abcdef",
        ] {
            assert!(bad.parse::<NodeId>().is_err(), "must reject {bad:?}");
        }
    }
}
