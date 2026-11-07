// SPDX-License-Identifier: LGPL-2.1-or-later

//! SSH signature auth, behind the `sshauth` feature.

mod enabled;
pub(crate) use enabled::SshSignature;
// the transport tests check the 401 detection the retry loop relies on
#[cfg(test)]
pub(crate) use enabled::is_http_unauthorized;
