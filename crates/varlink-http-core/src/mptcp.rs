// SPDX-License-Identifier: LGPL-2.1-or-later

//! Multipath TCP (MPTCP) sockets, so the long-lived connection from a
//! node survives the node's addresses changing, as on a vehicle moving
//! between cellular networks. The kernel falls back to plain TCP on the
//! wire when the peer or a middlebox does not speak MPTCP, see
//! <https://www.kernel.org/doc/html/latest/networking/mptcp.html>

use std::io;
use std::net::SocketAddr;
use std::os::fd::OwnedFd;

use rustix::net::{AddressFamily, SocketFlags, SocketType, ipproto};
use tokio::net::{TcpListener, TcpSocket, TcpStream, ToSocketAddrs, lookup_host};

/// The accept backlog of [`bind`].
const BACKLOG: u32 = 1024;

/// Opens a non-blocking stream socket for `addr`'s family, MPTCP where
/// the kernel offers it and `usable` accepts the socket, TCP otherwise.
fn socket(
    addr: SocketAddr,
    usable: impl Fn(&OwnedFd) -> anyhow::Result<()>,
) -> io::Result<TcpSocket> {
    let family = if addr.is_ipv4() {
        AddressFamily::INET
    } else {
        AddressFamily::INET6
    };
    let open = |proto| {
        rustix::net::socket_with(
            family,
            SocketType::STREAM,
            SocketFlags::CLOEXEC | SocketFlags::NONBLOCK,
            Some(proto),
        )
    };
    let fd = open(ipproto::MPTCP)
        .map_err(anyhow::Error::from)
        // older kernels create the socket but reject our options on it,
        // and once it is connected or listening it is too late for TCP
        .and_then(|fd| usable(&fd).map(|()| fd))
        // on any error, not only EPROTONOSUPPORT: net.mptcp.enabled=0
        // gives ENOPROTOOPT, seccomp or an LSM gives EPERM/EACCES
        .or_else(|e| {
            log::debug!("MPTCP is not usable ({e:#}), using TCP");
            open(ipproto::TCP)
        })?;
    Ok(TcpSocket::from_std_stream(fd.into()))
}

/// Returns the result of `f` for the first address `addr` resolves to
/// that `f` succeeds on, otherwise the last error.
async fn each_addr<T>(
    addr: impl ToSocketAddrs,
    f: impl AsyncFn(SocketAddr) -> io::Result<T>,
) -> io::Result<T> {
    let mut last = io::Error::new(
        io::ErrorKind::InvalidInput,
        "could not resolve to any addresses",
    );
    for addr in lookup_host(addr).await? {
        match f(addr).await {
            Ok(v) => return Ok(v),
            // keep going like std does, so an AAAA record on a host with
            // IPv6 disabled does not hide a working A record
            Err(e) => last = e,
        }
    }
    Err(last)
}

/// Connects like [`TcpStream::connect`] but over MPTCP, or over TCP
/// where the kernel has no usable MPTCP.
///
/// # Errors
/// If `addr` resolves to nothing or no address can be connected to.
pub async fn connect(addr: impl ToSocketAddrs) -> io::Result<TcpStream> {
    each_addr(addr, async |addr| {
        socket(addr, crate::set_tcp_keepalive_and_nodelay)?
            .connect(addr)
            .await
    })
    .await
}

/// Binds like [`TcpListener::bind`] but over MPTCP, or over TCP where
/// the kernel has no usable MPTCP.
///
/// # Errors
/// If `addr` resolves to nothing or no address can be bound.
pub async fn bind(addr: impl ToSocketAddrs) -> io::Result<TcpListener> {
    each_addr(addr, async |addr| {
        let socket = socket(addr, crate::set_tcp_keepalive_and_nodelay)?;
        // so a restart does not wait out TIME_WAIT
        socket.set_reuseaddr(true)?;
        socket.bind(addr)?;
        // same as tokio's TcpListener::bind
        socket.listen(BACKLOG)
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustix::net::sockopt;
    use std::time::{Duration, Instant};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn kernel_has_mptcp() -> bool {
        std::fs::read_to_string("/proc/sys/net/mptcp/enabled").is_ok_and(|s| s.trim() == "1")
    }

    fn protocol_of(fd: &impl rustix::fd::AsFd) -> rustix::net::Protocol {
        sockopt::socket_protocol(fd).unwrap().unwrap()
    }

    async fn roundtrip(listener: &TcpListener, client: &mut TcpStream) -> TcpStream {
        let (mut server, _) = listener.accept().await.unwrap();
        client.write_all(b"hi").await.unwrap();
        let mut got = [0u8; 2];
        server.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"hi");
        server
    }

    async fn closed_port() -> SocketAddr {
        bind("127.0.0.1:0").await.unwrap().local_addr().unwrap()
    }

    #[tokio::test]
    async fn connects_over_mptcp_or_falls_back_to_tcp() {
        let listener = bind("127.0.0.1:0").await.unwrap();
        let mut client = connect(listener.local_addr().unwrap()).await.unwrap();
        let server = roundtrip(&listener, &mut client).await;

        let expected = if kernel_has_mptcp() {
            ipproto::MPTCP
        } else {
            ipproto::TCP
        };
        assert_eq!(protocol_of(&listener), expected);
        assert_eq!(protocol_of(&client), expected);
        assert_eq!(protocol_of(&server), expected);
    }

    #[test]
    fn falls_back_to_tcp_when_mptcp_rejects_our_options() {
        let addr = "127.0.0.1:0".parse().unwrap();
        let socket = socket(addr, |fd| {
            anyhow::ensure!(protocol_of(fd) != ipproto::MPTCP, "no options on MPTCP");
            Ok(())
        })
        .unwrap();
        assert_eq!(protocol_of(&socket), ipproto::TCP);
    }

    #[test]
    fn our_options_are_set_on_the_socket() {
        let socket = socket(
            "127.0.0.1:0".parse().unwrap(),
            crate::set_tcp_keepalive_and_nodelay,
        )
        .unwrap();
        assert!(sockopt::tcp_nodelay(&socket).unwrap());
        assert!(sockopt::socket_keepalive(&socket).unwrap());
    }

    #[test]
    fn timed_out_connect_does_not_hold_up_runtime_shutdown() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let start = Instant::now();
        // TEST-NET-1 is never routed, so the connect hangs or, on a host
        // without a default route, fails at once, see
        // https://www.rfc-editor.org/rfc/rfc5737
        let _ = rt.block_on(async {
            tokio::time::timeout(Duration::from_millis(100), connect("192.0.2.1:9")).await
        });
        drop(rt);
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "runtime shutdown waited for the connect"
        );
    }

    #[tokio::test]
    async fn nothing_to_resolve_is_an_error() {
        let none: &[SocketAddr] = &[];
        let err = connect(none).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        let err = bind(none).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[tokio::test]
    async fn connect_reports_the_last_failure() {
        let err = connect(closed_port().await).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::ConnectionRefused);
    }

    #[tokio::test]
    async fn connect_moves_on_to_the_next_address() {
        let listener = bind("127.0.0.1:0").await.unwrap();
        let addrs = [closed_port().await, listener.local_addr().unwrap()];
        let mut client = connect(&addrs[..]).await.unwrap();
        roundtrip(&listener, &mut client).await;
    }

    #[tokio::test]
    async fn bind_reports_the_last_failure() {
        let taken = bind("127.0.0.1:0").await.unwrap();
        let err = bind(taken.local_addr().unwrap()).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::AddrInUse);
    }

    #[tokio::test]
    async fn bind_moves_on_to_the_next_address() {
        let taken = bind("127.0.0.1:0").await.unwrap();
        let free: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let listener = bind(&[taken.local_addr().unwrap(), free][..])
            .await
            .unwrap();
        assert_ne!(listener.local_addr().unwrap(), taken.local_addr().unwrap());
    }
}
