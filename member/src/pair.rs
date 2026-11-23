// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! What joining a group at home needs of the network: which addresses the
//! QR code names, which reach the member port, how a pairing window counts
//! connections by their source, and how long an admin may take to confirm
//! a device.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

/// How long a remote invitation's admin may take to confirm the device, as
/// Go's confirmWait.
pub const CONFIRM_WAIT: Duration = Duration::from_secs(300);

/// The source a connection from ip counts against, for the limits of a
/// pairing window, a listening joiner and the member port: the address
/// itself, or the /64 of a global IPv6 address, within which a device may
/// change its address at will. Every device of a home network shares its
/// unique-local and link-local /64s, so those count address by address.
pub fn source(ip: IpAddr) -> IpAddr {
    match ip.to_canonical() {
        IpAddr::V4(a) => IpAddr::V4(a),
        IpAddr::V6(a) => {
            let s = a.segments();
            let shared = (s[0] & 0xfe00) == 0xfc00 || (s[0] & 0xffc0) == 0xfe80;
            if shared { IpAddr::V6(a) } else { IpAddr::V6(std::net::Ipv6Addr::new(s[0], s[1], s[2], s[3], 0, 0, 0, 0)) }
        }
    }
}

/// Reports whether an address may reach the member port: what mDNS would
/// publish (private IPv4, unique-local and link-local IPv6) or loopback.
pub fn home_address(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(a) => a.is_private() || a.is_loopback() || a.is_link_local(),
        IpAddr::V6(a) => {
            if let Some(v4) = a.to_ipv4_mapped() {
                return home_address(IpAddr::V4(v4));
            }
            a.is_loopback() || (a.segments()[0] & 0xfe00) == 0xfc00 || (a.segments()[0] & 0xffc0) == 0xfe80
        }
    }
}

/// The addresses for the QR code: those mDNS would publish, IPv4 first,
/// without link-local ones, at most four.
pub fn qr_addresses(port: u16) -> Vec<String> {
    let mut v4 = Vec::new();
    let mut v6 = Vec::new();
    for iface in if_addrs::get_if_addrs().unwrap_or_default() {
        if iface.is_loopback() || !crate::interfaces::allowed(&iface.name) {
            continue;
        }
        match iface.ip() {
            IpAddr::V4(a) if a.is_private() => v4.push(SocketAddr::new(IpAddr::V4(a), port).to_string()),
            IpAddr::V6(a) if (a.segments()[0] & 0xfe00) == 0xfc00 => {
                v6.push(SocketAddr::new(IpAddr::V6(a), port).to_string())
            }
            _ => {}
        }
    }
    v4.extend(v6);
    v4.dedup();
    v4.truncate(4);
    v4
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sources() {
        let a: IpAddr = "192.168.1.5".parse().unwrap();
        assert_eq!(source(a), a);
        assert_eq!(source("::ffff:192.168.1.5".parse().unwrap()), a);
        // A global address counts by its /64.
        let b: IpAddr = "2001:db8:2:3:aaaa:bbbb:cccc:dddd".parse().unwrap();
        assert_eq!(source(b), "2001:db8:2:3::".parse::<IpAddr>().unwrap());
        assert_eq!(source("2001:db8:2:3::9".parse().unwrap()), source(b));
        assert_ne!(source("2001:db8:2:4::9".parse().unwrap()), source(b));
        // Every device of the network shares the unique-local and
        // link-local /64s: each address counts on its own.
        for (one, other) in [("fd00:1:2:3::1", "fd00:1:2:3::2"), ("fe80::1", "fe80::2")] {
            let (one, other): (IpAddr, IpAddr) = (one.parse().unwrap(), other.parse().unwrap());
            assert_eq!(source(one), one);
            assert_ne!(source(one), source(other));
        }
    }
}
