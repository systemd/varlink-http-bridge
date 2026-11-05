// SPDX-License-Identifier: LGPL-2.1-or-later

pub mod listen;
pub mod node_id;
pub mod sysconf;
pub mod tunnel;

// The client side lives in its own crate so that a client does not
// drag the server dependencies in; everything the bridge shares with
// it is re-exported here.
#[cfg(feature = "sshauth")]
pub use varlink_http_core::sshauth_token;
pub use varlink_http_core::{
    AsyncStream, BoxedStream, DEFAULT_PORT, TLS_CHANNEL_BINDING_LABEL, TLS_CHANNEL_BINDING_LEN,
    TlsChannelBinding, exclusive_ca_store, export_tls_channel_binding, parse_vsock_cid_port,
    public_key_pin, secret_file, set_tcp_keepalive_and_nodelay, ws,
};
