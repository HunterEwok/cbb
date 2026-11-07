// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The interface list, CBB_INTERFACES, as the full member has it
//! (docs/design.md): on a router the lite member publishes and browses
//! mDNS, listens for members and joins only on the network devices it
//! names, never on the one that faces the internet. A connection counts
//! only when it arrives at an address of a listed device from an address
//! on that device's own networks. Without the list, every device counts.

use std::net::{IpAddr, SocketAddr, TcpStream};
use std::sync::OnceLock;

/// The names in CBB_INTERFACES, separated by commas or spaces; empty when
/// it is not set. On OpenWrt, a cbb pair started by hand reads the list
/// that the init script gave the service.
pub fn only() -> &'static [String] {
    static ONLY: OnceLock<Vec<String>> = OnceLock::new();
    ONLY.get_or_init(|| {
        let v = std::env::var("CBB_INTERFACES").unwrap_or_default();
        if v.is_empty() && crate::openwrt() {
            return parse(&std::fs::read_to_string(OPENWRT_LIST).unwrap_or_default());
        }
        parse(&v)
    })
}

/// Where OpenWrt's init script writes the list.
const OPENWRT_LIST: &str = "/var/run/cbb/interfaces";

fn parse(v: &str) -> Vec<String> {
    let mut names: Vec<String> = Vec::new();
    for n in v.split([',', ' ', '\t', '\n']).filter(|n| !n.is_empty()) {
        if !names.iter().any(|m| m == n) {
            names.push(n.to_string());
        }
    }
    names
}

/// Reports whether the device named name may be used.
pub fn allowed(name: &str) -> bool {
    let only = only();
    only.is_empty() || only.iter().any(|n| n == name)
}

/// One address of a network device.
pub struct Iface {
    pub name: String,
    pub ip: IpAddr,
    pub prefix: u8,
    pub index: Option<u32>,
}

fn system() -> Vec<Iface> {
    if_addrs::get_if_addrs()
        .unwrap_or_default()
        .into_iter()
        .map(|i| {
            let (ip, prefix) = match &i.addr {
                if_addrs::IfAddr::V4(a) => (IpAddr::V4(a.ip), a.prefixlen),
                if_addrs::IfAddr::V6(a) => (IpAddr::V6(a.ip), a.prefixlen),
            };
            Iface { name: i.name, ip, prefix, index: i.index }
        })
        .collect()
}

/// Reports whether the connection arrived on a listed device from that
/// device's networks.
pub fn arrived(sock: &TcpStream) -> bool {
    if only().is_empty() {
        return true;
    }
    match (sock.local_addr(), sock.peer_addr()) {
        (Ok(local), Ok(remote)) => on_link(&system(), only(), local, remote),
        _ => false,
    }
}

/// Reports whether a connection from remote to local is on one of the
/// devices only names: local is an address of that device, and remote is
/// on one of its networks, or link-local on that device.
pub fn on_link(ifs: &[Iface], only: &[String], local: SocketAddr, remote: SocketAddr) -> bool {
    let (l, r) = (plain(local.ip()), plain(remote.ip()));
    if r.is_loopback() {
        return true;
    }
    let scope = match remote {
        SocketAddr::V6(a) => a.scope_id(),
        SocketAddr::V4(_) => 0,
    };
    ifs.iter().filter(|i| only.contains(&i.name) && i.ip == l).any(|dev| {
        if let IpAddr::V6(v6) = r
            && v6.is_unicast_link_local()
        {
            return dev.index == Some(scope);
        }
        ifs.iter().filter(|i| i.name == dev.name).any(|i| within(r, i.ip, i.prefix))
    })
}

/// An IPv4 address that arrives as IPv6 (::ffff:a.b.c.d), as IPv4.
fn plain(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(a) => a.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
        v4 => v4,
    }
}

fn within(ip: IpAddr, net: IpAddr, prefix: u8) -> bool {
    match (ip, net) {
        (IpAddr::V4(a), IpAddr::V4(n)) => {
            let mask = if prefix == 0 { 0 } else { u32::MAX << (32 - u32::from(prefix.min(32))) };
            u32::from(a) & mask == u32::from(n) & mask
        }
        (IpAddr::V6(a), IpAddr::V6(n)) => {
            let mask = if prefix == 0 { 0 } else { u128::MAX << (128 - u32::from(prefix.min(128))) };
            u128::from(a) & mask == u128::from(n) & mask
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn iface(name: &str, ip: &str, prefix: u8, index: u32) -> Iface {
        Iface { name: name.into(), ip: ip.parse().unwrap(), prefix, index: Some(index) }
    }

    #[test]
    fn parses_the_list() {
        assert_eq!(parse("br-lan, br-iot br-lan\twg0"), vec!["br-lan", "br-iot", "wg0"]);
        assert!(parse("").is_empty());
    }

    #[test]
    fn only_the_listed_devices() {
        let ifs = [
            iface("br-lan", "192.168.1.1", 24, 3),
            iface("br-lan", "fe80::1", 64, 3),
            iface("br-lan", "fd00::1", 64, 3),
            iface("wan", "192.168.0.2", 24, 4),
            iface("wan", "fe80::2", 64, 4),
        ];
        let only = vec!["br-lan".to_string()];
        let sa = |s: &str| s.parse::<SocketAddr>().unwrap();
        // From the lan to the lan's address, also as IPv4 in IPv6.
        assert!(on_link(&ifs, &only, sa("192.168.1.1:8764"), sa("192.168.1.20:5000")));
        assert!(on_link(&ifs, &only, sa("[::ffff:192.168.1.1]:8764"), sa("[::ffff:192.168.1.20]:5000")));
        assert!(on_link(&ifs, &only, sa("[fd00::1]:8764"), sa("[fd00::20]:5000")));
        assert!(on_link(&ifs, &only, sa("[fe80::1%3]:8764"), sa("[fe80::20%3]:5000")));
        // From the wan's network, to either address.
        assert!(!on_link(&ifs, &only, sa("192.168.0.2:8764"), sa("192.168.0.10:5000")));
        assert!(!on_link(&ifs, &only, sa("192.168.1.1:8764"), sa("192.168.0.10:5000")));
        assert!(!on_link(&ifs, &only, sa("[fe80::1%3]:8764"), sa("[fe80::20%4]:5000")));
        // Loopback always.
        assert!(on_link(&ifs, &only, sa("127.0.0.1:8764"), sa("127.0.0.1:5000")));
    }
}
