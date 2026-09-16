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

/// Returns a SslAcceptorBuilder from the given {cert,key}_path with
/// a minimium TLS1.3 version requirement for TLS channel binding.
///
/// # Errors
/// Returns an error if the certificate or key cannot be loaded or do
/// not match.
pub fn tls_acceptor_builder(
    cert_path: &str,
    key_path: &str,
) -> anyhow::Result<openssl::ssl::SslAcceptorBuilder> {
    use openssl::ssl::{SslAcceptor, SslFiletype, SslMethod};

    let mut builder = SslAcceptor::mozilla_modern_v5(SslMethod::tls_server())?;
    // mozilla_modern_v5 allows TLS 1.2, but we need 1.3 for channel binding
    // (export_keying_material requires TLS 1.3).
    builder.set_min_proto_version(Some(openssl::ssl::SslVersion::TLS1_3))?;
    builder.set_certificate_chain_file(cert_path)?;
    builder.set_private_key_file(key_path, SslFiletype::PEM)?;
    builder.check_private_key()?;
    Ok(builder)
}

/// Perform a TLS handshake on an already-accepted
/// stream. `client_store` holds the CAs a client certificate is
/// verified against. This runs per handshake the CAs can be rotated
/// without rebuilding the acceptor.
///
/// # Errors
/// Returns an error if the handshake fails.
pub async fn tls_accept<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(
    acceptor: &openssl::ssl::SslAcceptor,
    client_store: Option<openssl::x509::store::X509Store>,
    stream: S,
) -> anyhow::Result<tokio_openssl::SslStream<S>> {
    use anyhow::Context;
    let mut ssl = openssl::ssl::Ssl::new(acceptor.context()).context("SSL context error")?;
    if let Some(store) = client_store {
        ssl.set_verify_cert_store(store)
            .context("installing client CA store")?;
    }
    let mut tls_stream =
        tokio_openssl::SslStream::new(ssl, stream).context("SSL stream creation failed")?;
    std::pin::Pin::new(&mut tls_stream)
        .accept()
        .await
        .context("TLS handshake failed")?;
    Ok(tls_stream)
}
