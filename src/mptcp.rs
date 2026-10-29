// SPDX-License-Identifier: LGPL-2.1-or-later

//! Multipath TCP (MPTCP) sockets, so the long-lived connection from a
//! node survives the node's addresses changing, as on a vehicle moving
//! between cellular networks. The kernel falls back to plain TCP on the
//! wire when the peer or a middlebox does not speak MPTCP, see
//! <https://www.kernel.org/doc/html/latest/networking/mptcp.html>

use std::io;
use std::net::{SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::os::fd::OwnedFd;

use rustix::net::{AddressFamily, SocketFlags, SocketType, ipproto, sockopt};

// same as tokio's TcpListener::bind, which bind() replaced
const BACKLOG: i32 = 1024;

/// A stream socket for `addr`'s family, MPTCP where the kernel offers it
/// and TCP otherwise.
fn socket(addr: SocketAddr) -> io::Result<OwnedFd> {
    let family = if addr.is_ipv4() {
        AddressFamily::INET
    } else {
        AddressFamily::INET6
    };
    let open = |proto| {
        rustix::net::socket_with(
            family,
            SocketType::STREAM,
            SocketFlags::CLOEXEC,
            Some(proto),
        )
    };
    open(ipproto::MPTCP)
        // on any error, not only EPROTONOSUPPORT: net.mptcp.enabled=0
        // gives ENOPROTOOPT, seccomp or an LSM gives EPERM/EACCES
        .or_else(|e| {
            log::debug!("MPTCP is not available ({e}), using TCP");
            open(ipproto::TCP)
        })
        .map_err(io::Error::from)
}

/// The result of `f` for the first address `addr` resolves to that `f`
/// succeeds on, otherwise the last error.
fn each_addr(
    addr: impl ToSocketAddrs,
    f: impl Fn(SocketAddr) -> io::Result<OwnedFd>,
) -> io::Result<OwnedFd> {
    let mut last = io::Error::new(
        io::ErrorKind::InvalidInput,
        "could not resolve to any addresses",
    );
    for addr in addr.to_socket_addrs()? {
        match f(addr) {
            Ok(fd) => return Ok(fd),
            // keep going like std does, so an AAAA record on a host with
            // IPv6 disabled does not hide a working A record
            Err(e) => last = e,
        }
    }
    Err(last)
}

/// [`TcpStream::connect`] over MPTCP, or TCP where the kernel has no MPTCP.
///
/// # Errors
/// If `addr` resolves to nothing or no address can be connected to.
pub fn connect(addr: impl ToSocketAddrs) -> io::Result<TcpStream> {
    each_addr(addr, |addr| {
        let fd = socket(addr)?;
        rustix::net::connect(&fd, &addr)?;
        Ok(fd)
    })
    .map(TcpStream::from)
}

/// [`TcpListener::bind`] over MPTCP, or TCP where the kernel has no MPTCP.
///
/// # Errors
/// If `addr` resolves to nothing or no address can be bound.
pub fn bind(addr: impl ToSocketAddrs) -> io::Result<TcpListener> {
    each_addr(addr, |addr| {
        let fd = socket(addr)?;
        // so a restart does not wait out TIME_WAIT
        sockopt::set_socket_reuseaddr(&fd, true)?;
        rustix::net::bind(&fd, &addr)?;
        rustix::net::listen(&fd, BACKLOG)?;
        Ok(fd)
    })
    .map(TcpListener::from)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};

    fn kernel_has_mptcp() -> bool {
        std::fs::read_to_string("/proc/sys/net/mptcp/enabled").is_ok_and(|s| s.trim() == "1")
    }

    fn protocol_of(fd: &impl rustix::fd::AsFd) -> rustix::net::Protocol {
        sockopt::socket_protocol(fd).unwrap().unwrap()
    }

    fn roundtrip(listener: &TcpListener, client: &mut TcpStream) -> TcpStream {
        let (mut server, _) = listener.accept().unwrap();
        client.write_all(b"hi").unwrap();
        let mut got = [0u8; 2];
        server.read_exact(&mut got).unwrap();
        assert_eq!(&got, b"hi");
        server
    }

    fn closed_port() -> SocketAddr {
        bind("127.0.0.1:0").unwrap().local_addr().unwrap()
    }

    #[test]
    fn connects_over_mptcp_or_falls_back_to_tcp() {
        let listener = bind("127.0.0.1:0").unwrap();
        let mut client = connect(listener.local_addr().unwrap()).unwrap();
        let server = roundtrip(&listener, &mut client);

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
    fn nothing_to_resolve_is_an_error() {
        let none: &[SocketAddr] = &[];
        let err = connect(none).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        let err = bind(none).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn connect_reports_the_last_failure() {
        let err = connect(closed_port()).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::ConnectionRefused);
    }

    #[test]
    fn connect_moves_on_to_the_next_address() {
        let listener = bind("127.0.0.1:0").unwrap();
        let addrs = [closed_port(), listener.local_addr().unwrap()];
        let mut client = connect(&addrs[..]).unwrap();
        roundtrip(&listener, &mut client);
    }

    #[test]
    fn bind_reports_the_last_failure() {
        let taken = bind("127.0.0.1:0").unwrap();
        let err = bind(taken.local_addr().unwrap()).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::AddrInUse);
    }

    #[test]
    fn bind_moves_on_to_the_next_address() {
        let taken = bind("127.0.0.1:0").unwrap();
        let free: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let listener = bind(&[taken.local_addr().unwrap(), free][..]).unwrap();
        assert_ne!(listener.local_addr().unwrap(), taken.local_addr().unwrap());
    }
}
