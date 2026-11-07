// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! Finding the members and dialing them, and taking the connections of
//! those that dial this one (docs/protocol.md, sections 3 and 4). A lite
//! member publishes itself with `r=lite` and listens on the member port, so
//! that phones reach it without a computer; it dials the full members, and
//! the lite members whose device ID is greater than its own.
//! Members can also be given by address, for a network where multicast
//! does not reach.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr, SocketAddrV6, TcpListener};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::certs::DeviceId;
use crate::interfaces;
use crate::node::Node;
use crate::pair::home_address;
use crate::uptime;

const SERVICE: &str = "_cbb._tcp.local.";
const MAX_WAIT: Duration = Duration::from_secs(30);
const STEADY: Duration = Duration::from_secs(30);
/// At most this many connections may be in their TLS handshake at once.
const MAX_HANDSHAKES: usize = 16;
/// The members found by browsing that are dialed at once, as Go's mDNS
/// cache reports at most.
const MAX_FOUND: usize = 64;

/// The addresses of a found member; None once it is gone.
type Addrs = Arc<Mutex<Option<Vec<SocketAddr>>>>;

/// Dials the member at addrs again and again, waiting 1 s after a round of
/// failures, doubling to 30 s; a connection that lasted more than 30 s
/// resets the wait.
fn dial_loop(node: Arc<Node>, addrs: Addrs, peer: Option<DeviceId>) {
    let mut wait = Duration::from_secs(1);
    loop {
        if node.is_closed() {
            return;
        }
        let Some(list) = addrs.lock().unwrap().clone() else { return };
        if peer.as_ref().is_some_and(|p| node.connected(p)) {
            std::thread::sleep(Duration::from_secs(1));
            continue;
        }
        let mut steady = false;
        for a in list {
            let start = uptime::now();
            let res = node.dial(a, peer.clone());
            if uptime::now().saturating_sub(start) > STEADY {
                steady = true;
            }
            if res.is_ok() || steady {
                break;
            }
        }
        if steady {
            wait = Duration::from_secs(1);
        }
        std::thread::sleep(wait);
        wait = (wait * 2).min(MAX_WAIT);
    }
}

/// Listens on the member port, on all addresses, for the members that dial
/// this one; only home network addresses may connect. It returns the port,
/// or None when it cannot listen: the lite member then only dials.
pub fn listen(node: Arc<Node>, port: u16, log: Arc<dyn Fn(&str) + Send + Sync>) -> Option<u16> {
    let ln = match TcpListener::bind(("::", port)).or_else(|_| TcpListener::bind(("0.0.0.0", port))) {
        Ok(ln) => ln,
        Err(e) => {
            log(&format!(
                "cbb: cannot listen on port {port}: {e}; phones reach this device only through a computer \
                 until the port is free (-port to change it)"
            ));
            return None;
        }
    };
    let port = ln.local_addr().map(|a| a.port()).unwrap_or(port);
    let busy = Arc::new(AtomicUsize::new(0));
    std::thread::spawn(move || {
        for conn in ln.incoming() {
            if node.is_closed() {
                return;
            }
            let Ok(sock) = conn else { continue };
            let Ok(addr) = sock.peer_addr() else { continue };
            if !home_address(addr.ip()) || !interfaces::arrived(&sock) || busy.load(Ordering::SeqCst) >= MAX_HANDSHAKES
            {
                continue; // dropping the socket closes it
            }
            busy.fetch_add(1, Ordering::SeqCst);
            let (node, busy, log) = (node.clone(), busy.clone(), log.clone());
            std::thread::spawn(move || {
                let mut slot = Some(busy);
                let mut release = || {
                    if let Some(b) = slot.take() {
                        b.fetch_sub(1, Ordering::SeqCst);
                    }
                };
                let res = node.accept(sock, addr, &mut release);
                release();
                if let Err(e) = res {
                    log(&format!("cbb: connection from {addr}: {}", e.for_log()));
                }
            });
        }
    });
    Some(port)
}

/// Starts dialing: the members at the given addresses, and, with mdns, the
/// members of the group tag that browsing finds. With a port, it also
/// publishes this member there.
pub fn start(
    node: Arc<Node>,
    tag: String,
    statics: Vec<SocketAddr>,
    mdns: bool,
    port: Option<u16>,
    log: Arc<dyn Fn(&str) + Send + Sync>,
) {
    for a in statics {
        let node = node.clone();
        std::thread::spawn(move || dial_loop(node, Arc::new(Mutex::new(Some(vec![a]))), None));
    }
    if !mdns {
        return;
    }
    std::thread::spawn(move || {
        if let Err(e) = browse(node, &tag, port, false, &*log) {
            log(&format!("cbb: finding the members failed: {e}; give them with -peer"));
        }
    });
}

/// Starts dialing as a phone does: it publishes nothing and listens on no
/// port, so it dials every member that browsing finds, lite members too,
/// whatever their device IDs.
pub fn start_as_phone(node: Arc<Node>, tag: String, log: Arc<dyn Fn(&str) + Send + Sync>) {
    std::thread::spawn(move || {
        if let Err(e) = browse(node, &tag, None, true, &*log) {
            log(&format!("cbb: finding the members failed: {e}"));
        }
    });
}

fn browse(
    node: Arc<Node>,
    tag: &str,
    port: Option<u16>,
    as_phone: bool,
    log: &(dyn Fn(&str) + Send + Sync),
) -> Result<(), mdns_sd::Error> {
    let daemon = mdns_sd::ServiceDaemon::new()?;
    // As Go's responder: no loopback interfaces.
    let _ = daemon.disable_interface(vec![mdns_sd::IfKind::LoopbackV4, mdns_sd::IfKind::LoopbackV6]);
    // On a router, only the devices of the interface list.
    let only = interfaces::only();
    if !only.is_empty() {
        let _ = daemon.disable_interface(mdns_sd::IfKind::All);
        let _ = daemon.enable_interface(only.iter().map(|n| mdns_sd::IfKind::Name(n.clone())).collect::<Vec<_>>());
    }
    let me = node.identity().id.clone();
    if let Some(port) = port {
        // The protocol version, the group tag and the role.
        let txt = [("v", "1"), ("g", tag), ("r", "lite")];
        let info =
            mdns_sd::ServiceInfo::new(SERVICE, me.as_str(), &format!("{}.", me.host_name()), "", port, &txt[..])?
                .enable_addr_auto();
        daemon.register(info)?;
    }
    let events = daemon.browse(SERVICE)?;
    let mut found: HashMap<DeviceId, Addrs> = HashMap::new();
    while let Ok(ev) = events.recv() {
        if node.is_closed() {
            break;
        }
        match ev {
            mdns_sd::ServiceEvent::ServiceResolved(info) => {
                let Some(id) = instance_id(&info.fullname) else { continue };
                // Members of another group, or of a replaced CA, are ignored;
                // of two lite members the one with the lower ID dials; a
                // phone dials them all.
                let r = info.get_property_val_str("r");
                if id == me || info.get_property_val_str("g") != Some(tag) || (lite(r) && id < me && !as_phone) {
                    continue;
                }
                // A phone that is the hub publishes itself while its app is
                // open; it dials this member, as every phone does.
                if phone(r) {
                    if !as_phone {
                        node.found(&id, true);
                    }
                    continue;
                }
                let addrs = order(info.get_addresses().iter().map(|ip| match ip {
                    mdns_sd::ScopedIp::V6(v6) if v6.addr().is_unicast_link_local() => {
                        SocketAddr::V6(SocketAddrV6::new(*v6.addr(), info.port, 0, v6.scope_id().index))
                    }
                    other => SocketAddr::new(other.to_ip_addr(), info.port),
                }));
                if addrs.is_empty() {
                    continue;
                }
                match found.get(&id) {
                    Some(cur) => {
                        node.found(&id, true);
                        *cur.lock().unwrap() = Some(addrs)
                    }
                    // Anyone on the network can announce the group's tag, so
                    // the members dialed are bounded, as in Go.
                    None if found.len() >= MAX_FOUND => continue,
                    None => {
                        node.found(&id, true);
                        log(&format!("cbb: found {id} at {}", addrs[0]));
                        let cur: Addrs = Arc::new(Mutex::new(Some(addrs)));
                        found.insert(id.clone(), cur.clone());
                        let node = node.clone();
                        std::thread::spawn(move || dial_loop(node, cur, Some(id)));
                    }
                }
            }
            mdns_sd::ServiceEvent::ServiceRemoved(_, fullname) => {
                if let Some(id) = instance_id(&fullname) {
                    node.found(&id, false);
                    if let Some(cur) = found.remove(&id) {
                        *cur.lock().unwrap() = None;
                    }
                }
            }
            _ => {}
        }
    }
    let _ = daemon.shutdown();
    Ok(())
}

/// Reports whether a TXT `r` value names a lite member; keys and values
/// are compared without regard to case.
fn lite(r: Option<&str>) -> bool {
    r.is_some_and(|v| v.eq_ignore_ascii_case("lite"))
}

/// Reports whether a TXT `r` value names a phone, the group's hub while its
/// app is open.
fn phone(r: Option<&str>) -> bool {
    r.is_some_and(|v| v.eq_ignore_ascii_case("phone"))
}

/// The device ID in an instance name, <device ID>._cbb._tcp.local.
fn instance_id(fullname: &str) -> Option<DeviceId> {
    let label = fullname.strip_suffix(SERVICE)?.strip_suffix('.')?;
    DeviceId::parse(label).ok()
}

/// The addresses that would be published, IPv4 first, then routable IPv6,
/// then link-local IPv6.
fn order(addrs: impl Iterator<Item = SocketAddr>) -> Vec<SocketAddr> {
    let mut out: Vec<SocketAddr> = addrs.filter(|a| home_address(a.ip()) && !a.ip().is_loopback()).collect();
    out.sort_by_key(|a| match a.ip() {
        IpAddr::V4(_) => 0,
        IpAddr::V6(v6) if !v6.is_unicast_link_local() => 1,
        IpAddr::V6(_) => 2,
    });
    out.dedup();
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn instance_names() {
        let id = "0123456789abcdef0123456789abcdef";
        assert_eq!(instance_id(&format!("{id}._cbb._tcp.local.")).unwrap().as_str(), id);
        assert!(instance_id("printer._cbb._tcp.local.").is_none());
        assert!(instance_id(&format!("{id}._http._tcp.local.")).is_none());
    }

    #[test]
    fn lite_role() {
        assert!(lite(Some("lite")) && lite(Some("LITE")));
        assert!(phone(Some("phone")) && phone(Some("Phone")) && !phone(Some("lite")) && !phone(None));
        assert!(!lite(None) && !lite(Some("linux")) && !lite(Some("")));
    }

    #[test]
    fn address_order() {
        let got = order(
            ["[fe80::1]:8764", "[fd00::2]:8764", "192.168.1.5:8764", "8.8.8.8:8764"].iter().map(|s| s.parse().unwrap()),
        );
        let want: Vec<SocketAddr> =
            ["192.168.1.5:8764", "[fd00::2]:8764", "[fe80::1]:8764"].iter().map(|s| s.parse().unwrap()).collect();
        assert_eq!(got, want);
    }
}
