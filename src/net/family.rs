//! Native address families: an IPv6 socket never carries IPv4-mapped packets.
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub enum AddressFamily {
    Ipv6,
    Ipv4,
}

impl AddressFamily {
    pub fn of(addr: SocketAddr) -> Self {
        if addr.is_ipv4() {
            Self::Ipv4
        } else {
            Self::Ipv6
        }
    }
    pub fn wildcard(self, port: u16) -> SocketAddr {
        SocketAddr::new(
            match self {
                Self::Ipv4 => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                Self::Ipv6 => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            },
            port,
        )
    }
    pub fn loopback(self, port: u16) -> SocketAddr {
        SocketAddr::new(
            match self {
                Self::Ipv4 => IpAddr::V4(Ipv4Addr::LOCALHOST),
                Self::Ipv6 => IpAddr::V6(Ipv6Addr::LOCALHOST),
            },
            port,
        )
    }
    pub fn accepts(self, addr: SocketAddr) -> bool {
        Self::of(addr) == self && usable_address(addr)
    }
}
impl std::fmt::Display for AddressFamily {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Ipv4 => "IPv4",
            Self::Ipv6 => "IPv6",
        })
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, clap::ValueEnum)]
pub enum NetworkFamilies {
    #[default]
    DualStack,
    Ipv4Only,
    Ipv6Only,
}
impl NetworkFamilies {
    pub fn enabled(self, family: AddressFamily) -> bool {
        self == Self::DualStack
            || matches!(
                (self, family),
                (Self::Ipv4Only, AddressFamily::Ipv4) | (Self::Ipv6Only, AddressFamily::Ipv6)
            )
    }
}

/// No scoped link-local, mapped, unspecified, multicast or zero-port candidates.
/// ULA and global IPv6 remain ordinary Host candidates, independently of STUN.
pub fn usable_address(addr: SocketAddr) -> bool {
    if addr.port() == 0 || addr.ip().is_unspecified() || addr.ip().is_multicast() {
        return false;
    }
    match addr {
        SocketAddr::V4(a) => !a.ip().is_broadcast(),
        SocketAddr::V6(a) => {
            a.scope_id() == 0
                && a.flowinfo() == 0
                && !a.ip().is_unicast_link_local()
                && a.ip().to_ipv4_mapped().is_none()
        }
    }
}

/// Set IPV6_V6ONLY before bind on every platform; do not release/rebind the port.
pub fn bind_udp(bind: SocketAddr) -> std::io::Result<std::net::UdpSocket> {
    let domain = if bind.is_ipv4() {
        socket2::Domain::IPV4
    } else {
        socket2::Domain::IPV6
    };
    let socket = socket2::Socket::new(domain, socket2::Type::DGRAM, Some(socket2::Protocol::UDP))?;
    if bind.is_ipv6() {
        socket.set_only_v6(true)?;
    }
    socket.set_nonblocking(true)?;
    socket.bind(&bind.into())?;
    Ok(socket.into())
}

#[cfg(test)]
pub(crate) fn ipv6_test_available() -> bool {
    match bind_udp(AddressFamily::Ipv6.loopback(0)) {
        Ok(_) => true,
        Err(error)
            if matches!(
                error.raw_os_error(),
                Some(97 | 99 | 49 | 47 | 10047 | 10049)
            ) || error.kind() == std::io::ErrorKind::Unsupported =>
        {
            eprintln!("SKIP IPv6 loopback: runner has no IPv6 capability: {error}");
            false
        }
        Err(error) => panic!("IPv6 capability probe failed unexpectedly: {error}"),
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn global_ula_and_loopback_are_native_but_scoped_mapped_and_multicast_are_not() {
        for address in [
            "[2001:db8::1]:9000",
            "[fd00::7]:9000",
            "[::1]:9000",
            "192.168.1.2:9000",
        ] {
            assert!(usable_address(address.parse().unwrap()), "{address}");
        }
        for address in [
            "[fe80::1]:9000",
            "[ff02::1]:9000",
            "[::ffff:192.168.1.2]:9000",
            "[::]:9000",
            "0.0.0.0:9000",
            "[::1]:0",
        ] {
            assert!(!usable_address(address.parse().unwrap()), "{address}");
        }
        let scoped = SocketAddr::V6(std::net::SocketAddrV6::new(Ipv6Addr::LOCALHOST, 9000, 0, 2));
        assert!(!usable_address(scoped));
        assert!(!AddressFamily::Ipv4.accepts("[::1]:9000".parse().unwrap()));
        assert!(!AddressFamily::Ipv6.accepts("127.0.0.1:9000".parse().unwrap()));
    }
    #[test]
    fn native_v6only_and_v4_can_hold_the_same_fixed_port() {
        if !ipv6_test_available() {
            return;
        }
        let v6 = bind_udp(AddressFamily::Ipv6.wildcard(0)).unwrap();
        let port = v6.local_addr().unwrap().port();
        let reference = socket2::SockRef::from(&v6);
        assert!(reference.only_v6().unwrap());
        let v4 = bind_udp(AddressFamily::Ipv4.wildcard(port)).unwrap();
        assert_eq!(v4.local_addr().unwrap().port(), port);
        assert!(bind_udp(AddressFamily::Ipv6.wildcard(port)).is_err());
        assert!(bind_udp(AddressFamily::Ipv4.wildcard(port)).is_err());
    }
}
