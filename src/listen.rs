// SPDX-License-Identifier: LGPL-2.1-or-later

//! Listening helpers for the server code.

/// Accept a TCP connection and configure socket options. A failed
/// accept (a client gone between SYN and accept, no file descriptors
/// left) or setsockopt must never take the whole listener down.
pub async fn accept_and_configure(
    listener: &tokio::net::TcpListener,
) -> (tokio::net::TcpStream, std::net::SocketAddr) {
    use log::warn;
    use rustix::io::Errno;

    const RETRY_DELAY: std::time::Duration = std::time::Duration::from_millis(100);

    loop {
        match listener.accept().await {
            Ok((stream, addr)) => {
                if let Err(e) = crate::set_tcp_keepalive_and_nodelay(&stream) {
                    warn!("on accept from {addr}: {e:#}");
                }
                return (stream, addr);
            }
            Err(e) => {
                // out of file descriptors: tell the admin what to do
                let hint = match Errno::from_io_error(&e) {
                    Some(Errno::MFILE) => ", increase LimitNOFILE= in the systemd unit file",
                    Some(Errno::NFILE) => {
                        ", the system-wide fs.file-max is exhausted (check fs.file-max)"
                    }
                    _ => "",
                };
                warn!(
                    "TCP accept failed: {e}; retrying in {}ms{hint}",
                    RETRY_DELAY.as_millis()
                );
                // nothing we can do here but wait and hope resource exhaustion gets better
                tokio::time::sleep(RETRY_DELAY).await;
            }
        }
    }
}
