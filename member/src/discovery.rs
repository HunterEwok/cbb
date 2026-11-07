// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! Finding the members and dialing them, and taking the connections of
//! those that dial this one (docs/protocol.md, sections 3 and 4). A lite
//! member publishes itself with `r=lite`, a computer with the service as a
//! full member without it, and either listens on the member port, so
//! that phones reach it without a computer; it dials the full members, and
//! the lite members whose device ID is greater than its own.
//! Members can also be given by address, for a network where multicast
//! does not reach.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr, SocketAddrV6, TcpListener};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::certs::DeviceId;
use crate::interfaces;
use crate::node::Node;
use crate::pair::home_address;

const SERVICE: &str = "_cbb._tcp.local.";
const MAX_WAIT: Duration = Duration::from_secs(30);
/// At most this many connections may be in their TLS handshake at once.
const MAX_HANDSHAKES: usize = 16;
/// The members found by browsing that are dialed at once, as Go's mDNS
/// cache reports at most.
const MAX_FOUND: usize = 64;

/// The addresses of a found member; None once it is gone.
type Addrs = Arc<Mutex<Option<Vec<SocketAddr>>>>;

/// Dials the member at addrs again and again: at once after this member
/// ended the connection to connect again (a new hello), a second after a
/// connection that came up ended, and after a round of failures 1 s,
/// doubling to 30 s.
fn dial_loop(node: Arc<Node>, addrs: Addrs, peer: Option<DeviceId>) {
    let mut wait = FIRST_WAIT;
    loop {
        if node.is_closed() {
            return;
        }
        let Some(list) = addrs.lock().unwrap().clone() else { return };
        // A connection up to the peer is left alone; a loopback address
        // (the tunnel's, a relay's) replaces one at home (Node::connected_for).
        if node.is_paused() || peer.as_ref().is_some_and(|p| list.first().is_some_and(|a| node.connected_for(p, a))) {
            node.nap(Duration::from_secs(1));
            continue;
        }
        let mut up = false;
        let mut again = false;
        for a in list {
            if let Ok(d) = node.dial_ended(a, peer.clone()) {
                (up, again) = (d.up, d.again);
                break;
            }
        }
        wait = next_wait(wait, up, again);
        if wait.is_zero() {
            wait = FIRST_WAIT;
            continue;
        }
        // A kick (the app resumed, or handed in new addresses) tries again
        // at once.
        if node.nap(wait) {
            wait = FIRST_WAIT;
        }
    }
}

/// The first wait before dialing again, after a connection ended.
const FIRST_WAIT: Duration = Duration::from_secs(1);

/// The wait before the next dial, after one whose connection came up (up)
/// and that this member ended to connect again (again), from the wait
/// before it: none, the first wait, or the last doubled for a failure.
fn next_wait(last: Duration, up: bool, again: bool) -> Duration {
    match (up, again) {
        (true, true) => Duration::ZERO,
        (true, false) => FIRST_WAIT,
        (false, _) => (last * 2).min(MAX_WAIT),
    }
}

/// Listens on the member port, on all addresses, for the members that dial
/// this one; only home network addresses may connect. It returns the port,
/// or None when it cannot listen: the lite member then only dials.
pub fn listen(node: Arc<Node>, port: u16, log: Arc<dyn Fn(&str) + Send + Sync>) -> Option<u16> {
    listen_until(node, port, false, None, Arc::new(AtomicBool::new(false)), log)
}

/// As listen, until stop is set and a connection wakes the listener
/// (Listener::stop).
/// With loopback it listens on 127.0.0.1 only, for the connections a
/// phone's tunnel or relay link makes there; admit checks each connection
/// before it is served.
pub fn listen_until(
    node: Arc<Node>,
    port: u16,
    loopback: bool,
    admit: Option<crate::node::Admit>,
    stop: Arc<AtomicBool>,
    log: Arc<dyn Fn(&str) + Send + Sync>,
) -> Option<u16> {
    let bound = if loopback {
        TcpListener::bind(("127.0.0.1", port))
    } else {
        TcpListener::bind(("::", port)).or_else(|_| TcpListener::bind(("0.0.0.0", port)))
    };
    let ln = match bound {
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
            if node.is_closed() || stop.load(Ordering::SeqCst) {
                return;
            }
            let Ok(sock) = conn else { continue };
            let Ok(addr) = sock.peer_addr() else { continue };
            if !home_address(addr.ip()) || !interfaces::arrived(&sock) || busy.load(Ordering::SeqCst) >= MAX_HANDSHAKES
            {
                continue; // dropping the socket closes it
            }
            busy.fetch_add(1, Ordering::SeqCst);
            let (node, busy, log, admit) = (node.clone(), busy.clone(), log.clone(), admit.clone());
            std::thread::spawn(move || {
                let mut slot = Some(busy);
                let mut release = || {
                    if let Some(b) = slot.take() {
                        b.fetch_sub(1, Ordering::SeqCst);
                    }
                };
                let res = node.accept_checked(sock, addr, &mut release, admit.as_ref());
                release();
                if let Err(e) = res {
                    log(&format!("cbb: connection from {addr}: {}", e.for_log()));
                }
            });
        }
    });
    Some(port)
}

/// A member port a phone's app opened while it is in the front, so that
/// members reach it as the group's hub at home or through its tunnel; it
/// closes on stop or drop.
pub struct Listener {
    pub port: u16,
    stop: Arc<AtomicBool>,
}

impl Listener {
    /// Listens on port (0: any free one), or None when it cannot.
    pub fn open(node: Arc<Node>, port: u16, log: Arc<dyn Fn(&str) + Send + Sync>) -> Option<Listener> {
        Self::open_with(node, port, false, None, log)
    }

    /// As open, on the loopback address only with loopback, each connection
    /// checked by admit before it is served.
    pub fn open_with(
        node: Arc<Node>,
        port: u16,
        loopback: bool,
        admit: Option<crate::node::Admit>,
        log: Arc<dyn Fn(&str) + Send + Sync>,
    ) -> Option<Listener> {
        let stop = Arc::new(AtomicBool::new(false));
        listen_until(node, port, loopback, admit, stop.clone(), log).map(|port| Listener { port, stop })
    }

    /// Closes the port: the listener's thread sees the flag at the
    /// connection this makes to it.
    pub fn stop(&self) {
        if self.stop.swap(true, Ordering::SeqCst) {
            return;
        }
        for host in [IpAddr::from([127, 0, 0, 1]), IpAddr::from(std::net::Ipv6Addr::LOCALHOST)] {
            if std::net::TcpStream::connect_timeout(&SocketAddr::new(host, self.port), Duration::from_secs(1)).is_ok() {
                return;
            }
        }
    }
}

impl Drop for Listener {
    fn drop(&mut self) {
        self.stop();
    }
}

/// The members a phone's app finds itself (Bonjour, NSD, its tunnel's
/// loopback port) and hands in by address, each dialed again and again
/// until it is lost.
#[derive(Default)]
pub struct Dialers {
    found: Mutex<HashMap<String, Addrs>>,
}

impl Dialers {
    /// Dials the member the app knows as key at addrs; peer is its device
    /// ID when the app knows it. A key found again takes the new addresses.
    pub fn found(&self, node: &Arc<Node>, key: &str, addrs: Vec<SocketAddr>, peer: Option<DeviceId>) {
        // The loopback address too: the tunnel's port to the hub is there.
        let mut addrs: Vec<SocketAddr> = addrs.into_iter().filter(|a| home_address(a.ip())).collect();
        addrs.sort_by_key(|a| (a.ip().is_ipv6(), a.ip().is_loopback()));
        addrs.dedup();
        let mut found = self.found.lock().unwrap();
        if let Some(a) = found.get(key) {
            *a.lock().unwrap() = Some(addrs);
        } else if found.len() < MAX_FOUND {
            let a: Addrs = Arc::new(Mutex::new(Some(addrs)));
            found.insert(key.to_string(), a.clone());
            let node = node.clone();
            std::thread::spawn(move || dial_loop(node, a, peer));
        }
        drop(found);
        node.kick();
    }

    /// Stops dialing the member the app lost.
    pub fn lost(&self, node: &Node, key: &str) {
        if let Some(a) = self.found.lock().unwrap().remove(key) {
            *a.lock().unwrap() = None;
            node.kick();
        }
    }
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
    // A computer with the service publishes itself as a full member does,
    // without a role.
    let full = node.role() == "full";
    // The protocol version, the group tag, the role, and p=1 while a
    // pairing window is open, which a joiner looks for.
    let publish = |window: bool| -> Result<(), mdns_sd::Error> {
        let Some(port) = port else { return Ok(()) };
        let mut txt = vec![("v", "1"), ("g", tag)];
        if !full {
            txt.push(("r", "lite"));
        }
        if window {
            txt.push(("p", "1"));
        }
        let info =
            mdns_sd::ServiceInfo::new(SERVICE, me.as_str(), &format!("{}.", me.host_name()), "", port, &txt[..])?
                .enable_addr_auto();
        daemon.register(info)
    };
    let mut window = node.window_open();
    publish(window)?;
    let events = daemon.browse(SERVICE)?;
    let mut found: HashMap<DeviceId, Addrs> = HashMap::new();
    loop {
        let ev = events.recv_timeout(Duration::from_secs(1));
        if node.is_closed() {
            break;
        }
        if node.window_open() != window {
            window = !window;
            if let Err(e) = publish(window) {
                log(&format!("cbb: announcing the pairing window failed: {e}"));
            }
        }
        let Ok(ev) = ev else {
            if events.is_disconnected() {
                break;
            }
            continue;
        };
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
                // As Go's full members: the lite members dial this one, and
                // of two full members the one with the lower ID dials.
                if full && (lite(r) || id < me) {
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

    /// A connection this member ended to send a new hello (a mode, a tunnel
    /// key) is dialed again at once, one that came up and ended after a
    /// second, and failures back off from 1 s to 30 s: a phone whose mode
    /// changed often waited up to 30 s for its computer (the Android
    /// emulator's GroupTest).
    #[test]
    fn redials_at_once_after_a_reconnect() {
        use super::{FIRST_WAIT, MAX_WAIT, next_wait};
        let s = Duration::from_secs;
        assert_eq!(next_wait(s(16), true, true), Duration::ZERO);
        assert_eq!(next_wait(s(16), true, false), FIRST_WAIT);
        assert_eq!(next_wait(FIRST_WAIT, false, false), s(2));
        assert_eq!(next_wait(s(16), false, false), MAX_WAIT);
        assert_eq!(next_wait(MAX_WAIT, false, false), MAX_WAIT);
        // Many reconnects in a row never grow the wait.
        let mut w = FIRST_WAIT;
        for _ in 0..10 {
            w = next_wait(w, true, false);
        }
        assert_eq!(w, FIRST_WAIT);
    }

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
