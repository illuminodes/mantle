use std::net::{Ipv4Addr, SocketAddrV4};

/// Whether a peer address can be reached on the public internet, and which
/// /16 group it belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Routable(SocketAddrV4);

impl Routable {
    pub(crate) fn new(address: SocketAddrV4) -> Option<Self> {
        let ip = *address.ip();
        let refused = address.port() == 0
            || ip.is_unspecified()
            || ip.is_loopback()
            || ip.is_private()
            || ip.is_link_local()
            || ip.is_multicast()
            || ip.is_broadcast()
            || ip.is_documentation()
            || Self::is_shared(ip)
            || Self::is_reserved(ip)
            || ip.octets()[0] == 0;
        (!refused).then_some(Self(address))
    }

    pub(crate) const fn address(self) -> SocketAddrV4 {
        self.0
    }

    pub(crate) fn group(self) -> [u8; 2] {
        let [a, b, _, _] = self.0.ip().octets();
        [a, b]
    }

    fn is_shared(ip: Ipv4Addr) -> bool {
        let [a, b, _, _] = ip.octets();
        a == 100 && (b & 0xc0) == 64
    }

    fn is_reserved(ip: Ipv4Addr) -> bool {
        ip.octets()[0] >= 240
    }
}

#[cfg(test)]
mod tests {
    use super::Routable;

    #[test]
    fn public_addresses_are_routable() {
        let address = "8.8.4.4:8333".parse().unwrap();
        assert_eq!(Routable::new(address).map(Routable::address), Some(address));
    }

    #[test]
    fn local_and_reserved_addresses_are_refused() {
        for text in [
            "0.0.0.0:8333",
            "0.1.2.3:8333",
            "127.0.0.1:8333",
            "10.0.0.1:8333",
            "172.16.0.1:8333",
            "192.168.1.1:8333",
            "169.254.0.1:8333",
            "100.64.0.1:8333",
            "224.0.0.1:8333",
            "240.0.0.1:8333",
            "255.255.255.255:8333",
            "192.0.2.1:8333",
            "8.8.8.8:0",
        ] {
            assert!(Routable::new(text.parse().unwrap()).is_none(), "{text}");
        }
    }

    #[test]
    fn the_group_is_the_first_two_octets() {
        let routable = Routable::new("81.2.3.4:8333".parse().unwrap()).unwrap();
        assert_eq!(routable.group(), [81, 2]);
    }
}
