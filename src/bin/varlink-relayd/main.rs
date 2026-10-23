// SPDX-License-Identifier: LGPL-2.1-or-later

//! varlink-relayd: makes a `varlink-httpd` reachable when it runs
//! behind NAT or a firewall that only lets HTTPS out.
//!
//! Nodes dial out to `--bind-node` with a WebSocket and stay connected, the
//! relay runs HTTP/2 over it as the h2 client. A caller sends `CONNECT
//! <id>` to `--bind-caller` and the relay copies its bytes onto one h2
//! stream to that node, without terminating the caller's TLS.

mod caller;
mod node;
mod registry;

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context as _, Result, bail};
use log::{info, warn};
use tokio::net::TcpListener;

use varlink_http_bridge::tunnel::TUNNEL_PATH;

use crate::registry::Nodes;

const DEFAULT_BIND_NODE: &str = "127.0.0.1:2062";
const DEFAULT_BIND_CALLER: &str = "127.0.0.1:2063";
// so that a silent peer cannot pin a task and fd forever
pub(crate) const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const USAGE: &str = "\
usage: varlink-relayd --insecure [options]

options:
  --bind-node ADDR    where nodes dial in (default 127.0.0.1:2062)
  --bind-caller ADDR  where callers CONNECT (default 127.0.0.1:2063)
  --cert PEM          TLS certificate for the --bind-node listener
  --key PEM           TLS key for the --bind-node listener
  --insecure          nodes just assert their id, with no signature

This command is EXPERIMENTAL.
";

struct Args {
    bind_node: String,
    bind_caller: String,
    tls: Option<openssl::ssl::SslAcceptor>,
}

fn parse_args() -> Result<Args> {
    use lexopt::prelude::*;

    let mut bind_node = DEFAULT_BIND_NODE.to_string();
    let mut bind_caller = DEFAULT_BIND_CALLER.to_string();
    let mut cert = None;
    let mut key = None;
    let mut insecure = false;

    let mut parser = lexopt::Parser::from_env();
    while let Some(arg) = parser.next()? {
        match arg {
            Long("bind-node") => bind_node = parser.value()?.string()?,
            Long("bind-caller") => bind_caller = parser.value()?.string()?,
            Long("cert") => cert = Some(parser.value()?.string()?),
            Long("key") => key = Some(parser.value()?.string()?),
            Long("insecure") => insecure = true,
            Short('h') | Long("help") => {
                print!("{USAGE}");
                std::process::exit(0);
            }
            _ => return Err(arg.unexpected().into()),
        }
    }

    if !insecure {
        bail!(
            "device-key node authentication is not implemented yet; \
             --insecure (nodes just assert their id) is required for now"
        );
    }
    warn!("running with --insecure: anyone reaching {bind_node} can claim any node id");

    let tls = match (cert, key) {
        (Some(cert), Some(key)) => {
            Some(varlink_http_bridge::listen::tls_acceptor_builder(&cert, &key)?.build())
        }
        (None, None) if insecure => {
            warn!("no --cert/--key: nodes connect over plain ws://");
            None
        }
        (None, None) => bail!("--cert and --key are required, or --insecure for plain ws://"),
        _ => bail!("--cert and --key must be given together"),
    };
    Ok(Args {
        bind_node,
        bind_caller,
        tls,
    })
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let args = parse_args()?;
    warn!("varlink-relayd is EXPERIMENTAL and subject to change without advance notice");

    let node_listener = TcpListener::bind(&args.bind_node)
        .await
        .with_context(|| format!("binding node listener {}", args.bind_node))?;
    let caller_listener = TcpListener::bind(&args.bind_caller)
        .await
        .with_context(|| format!("binding caller listener {}", args.bind_caller))?;
    info!(
        "nodes dial in at {}{TUNNEL_PATH}, callers CONNECT to {}",
        node_listener
            .local_addr()
            .context("node listener address")?,
        caller_listener
            .local_addr()
            .context("caller listener address")?,
    );

    let nodes = Arc::new(Nodes::default());
    tokio::try_join!(
        node::serve(node_listener, args.tls, Arc::clone(&nodes)),
        caller::serve(caller_listener, nodes),
    )?;
    Ok(())
}

#[cfg(test)]
mod tests;
