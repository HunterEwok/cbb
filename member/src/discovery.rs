// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! Finding the members and dialing them, and taking the connections of
//! those that dial this one (docs/protocol.md, sections 3 and 4). A member
//! that does not dial publishes itself with `r=listen`, one that dials
//! without it, and either listens on the member port, so that phones reach
//! it without a computer; a member that dials dials those with `r=listen`
//! and, of the others, those whose device ID is greater than its own.
//! Members can also be given by address, for a network where multicast
//! does not reach.

use std::collections::HashMap;
use std::io::Write as _;
use std::net::{IpAddr, SocketAddr, SocketAddrV6, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::certs::DeviceId;
use crate::interfaces;
use crate::node::Node;
use crate::pair::home_address;

const SERVICE: &str = "_cbb._tcp.local.";

/// The file CBB_MDNS_TRACE names, for the tests: every event browsing
/// sees and mdns-sd's own debug log (the packets it sends and takes, its
/// cache), with the time, so that a member that does not find another on
/// CI can be told from what mDNS did.
fn trace_file() -> Option<&'static Mutex<std::fs::File>> {
    static FILE: std::sync::OnceLock<Option<Mutex<std::fs::File>>> = std::sync::OnceLock::new();
    FILE.get_or_init(|| {
        let path = std::env::var_os("CBB_MDNS_TRACE")?;
        let f = std::fs::OpenOptions::new().create(true).append(true).open(path).ok()?;
        Some(Mutex::new(f))
    })
    .as_ref()
}

/// Writes a line to the trace, after the time of day in UTC.
fn trace(line: &str) {
    let Some(f) = trace_file() else { return };
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
    let (s, ms) = (now.as_secs() % 86400, now.subsec_millis());
    let mut f = f.lock().unwrap_or_else(|e| e.into_inner());
    let _ = writeln!(f, "{:02}:{:02}:{:02}.{ms:03} {line}", s / 3600, s / 60 % 60, s % 60);
}

/// Hands mdns-sd's debug log to the trace.
struct TraceLog;

impl log::Log for TraceLog {
    fn enabled(&self, m: &log::Metadata) -> bool {
        m.level() <= log::Level::Debug && m.target().starts_with("mdns_sd")
    }

    fn log(&self, r: &log::Record) {
        if self.enabled(r.metadata()) {
            trace(&format!("mdns-sd {}: {}", r.level(), r.args()));
        }
    }

    fn flush(&self) {}
}

/// Starts the trace when CBB_MDNS_TRACE names a file.
fn start_trace() {
    if trace_file().is_some() && log::set_logger(&TraceLog).is_ok() {
        log::set_max_level(log::LevelFilter::Debug);
    }
}

/// Announces a device that listens to join (docs/protocol.md section 3,
/// TXT `j=1` and `f`, its certificate's fingerprint), so that a computer of
/// the group finds it by the code it shows. The announcement ends when the
/// returned value is dropped; None when mDNS is not at hand.
pub fn announce_joiner(id: &DeviceId, port: u16, fingerprint: &str) -> Option<Announcement> {
    let daemon = mdns_sd::ServiceDaemon::new().ok()?;
    let _ = daemon.disable_interface(vec![mdns_sd::IfKind::LoopbackV4, mdns_sd::IfKind::LoopbackV6]);
    let only = interfaces::only();
    if !only.is_empty() {
        let _ = daemon.disable_interface(mdns_sd::IfKind::All);
        let _ = daemon.enable_interface(only.iter().map(|n| mdns_sd::IfKind::Name(n.clone())).collect::<Vec<_>>());
    }
    let txt = [("v", "1"), ("j", "1"), ("f", fingerprint)];
    let info = mdns_sd::ServiceInfo::new(SERVICE, id.as_str(), &format!("{}.", id.host_name()), "", port, &txt[..])
        .ok()?
        .enable_addr_auto();
    daemon.register(info).ok()?;
    // A joiner waits for minutes: a daemon whose cache another device
    // floods stops announcing it, and the QR code still works.
    let watched = daemon.clone();
    std::thread::spawn(move || {
        let mut flood = Flood::default();
        loop {
            std::thread::sleep(CACHE_CHECK);
            // A daemon shut down takes no more commands.
            let Ok(rx) = watched.get_metrics() else { return };
            if flood.check(rx.recv_timeout(CACHE_CHECK).ok().map(|m| sum_cached(&m))) {
                let _ = watched.shutdown();
                return;
            }
        }
    });
    Some(Announcement(daemon))
}

/// An announcement of announce_joiner: dropping it shuts the mDNS daemon
/// down, which sends the goodbyes.
pub struct Announcement(mdns_sd::ServiceDaemon);

impl Drop for Announcement {
    fn drop(&mut self) {
        let _ = self.0.shutdown();
    }
}

/// How long a joiner browses for a member with an open pairing window, as
/// Go's service does, and how long it waits after the first for others.
pub const PAIRING_BROWSE: Duration = Duration::from_secs(5);
const PAIRING_SETTLE: Duration = Duration::from_secs(2);

/// The addresses of the members that announce an open pairing window (TXT
/// `p=1`), for a device that joins with a code alone: browsed for up to
/// wait, then a moment more for the others; an error when none is found.
/// More than one window is refused, as in Go: the code fits only one.
pub fn find_pairing(wait: Duration) -> crate::error::Result<Vec<SocketAddr>> {
    use crate::error::Error;
    let open = browse_txt(wait, |info| (info.get_property_val_str("p") == Some("1")).then_some(()))?;
    match open.len() {
        0 => Err(Error::msg(
            "no member with an open pairing window found; run cbb pair on the group's root or an admin, or give its address",
        )),
        1 => Ok(open.into_values().next().map(|(a, ())| a).unwrap_or_default()),
        n => Err(Error::msg(format!(
            "{n} devices announce a pairing window ({}); give the address that cbb pair showed",
            open.keys().cloned().collect::<Vec<_>>().join(", ")
        ))),
    }
}

/// The device that announces that it waits to join (TXT `j=1` with its
/// certificate's fingerprint `f`, docs/protocol.md section 3), with its
/// addresses, for cbb pair with a code alone, as Go's findJoiners. More
/// than one is refused, as find_pairing refuses more than one window: the
/// code serves one device, and each other one would be one more guess.
pub fn find_joiner(wait: Duration) -> crate::error::Result<(Vec<SocketAddr>, String)> {
    let waiting = browse_txt(wait, |info| {
        let fp = info.get_property_val_str("f").filter(|f| !f.is_empty())?;
        (info.get_property_val_str("j") == Some("1")).then(|| fp.to_string())
    })?;
    the_one_joiner(waiting.into_values().collect())
}

/// The one device of those that wait to join, its addresses cut to a QR
/// code's.
fn the_one_joiner(mut waiting: Vec<(Vec<SocketAddr>, String)>) -> crate::error::Result<(Vec<SocketAddr>, String)> {
    match waiting.len() {
        0 => Err(crate::error::Error::msg(
            "no device that waits to join was found; on the new device, choose to join a group (cbb pair there) and type the code it shows",
        )),
        1 => {
            let (mut addrs, fp) = waiting.remove(0);
            addrs.truncate(cbb_core::pair::MAX_ADDRS);
            Ok((addrs, fp))
        }
        n => Err(crate::error::Error::msg(format!(
            "{n} devices wait to join on the network; scan the QR code that the new device shows, or give its address"
        ))),
    }
}

/// The addresses of the members of the group tag that browsing finds, one
/// list for each member, for a new phone that restores the group with its
/// recovery key: browsed for up to wait, then a moment more for the others.
pub fn find_group(tag: &str, wait: Duration) -> crate::error::Result<Vec<Vec<SocketAddr>>> {
    let found = browse_txt(wait, |info| (info.get_property_val_str("g") == Some(tag)).then_some(()))?;
    Ok(found.into_values().map(|(a, ())| a).collect())
}

/// The members of any group that browsing finds for up to wait, by
/// device, for a restore with a card's recovery key, which names no group.
pub fn find_any_group(wait: Duration) -> crate::error::Result<Vec<Vec<SocketAddr>>> {
    let found = browse_txt(wait, |info| info.get_property_val_str("g").filter(|g| !g.is_empty()).map(|_| ()))?;
    Ok(found.into_values().map(|(a, ())| a).collect())
}

/// Browses for up to wait for the members whose TXT pick takes, then a
/// moment more for the others; by instance name, their addresses and what
/// pick made of them.
fn browse_txt<T>(
    wait: Duration,
    pick: impl Fn(&mdns_sd::ResolvedService) -> Option<T>,
) -> crate::error::Result<std::collections::BTreeMap<String, (Vec<SocketAddr>, T)>> {
    use crate::error::Error;
    let daemon = mdns_sd::ServiceDaemon::new().map_err(|e| Error::with("cannot browse with mDNS", e))?;
    set_interfaces(&daemon);
    start_trace();
    let rx = daemon.browse(SERVICE).map_err(|e| Error::with("cannot browse with mDNS", e))?;
    let mut found = std::collections::BTreeMap::new();
    let mut deadline = std::time::Instant::now() + wait;
    let mut settled = false;
    let mut checked = std::time::Instant::now();
    let mut flood = Flood::default();
    while let Some(left) = deadline.checked_duration_since(std::time::Instant::now()) {
        if checked.elapsed() >= CACHE_CHECK {
            checked = std::time::Instant::now();
            if flood.check(cached(&daemon)) {
                break;
            }
        }
        let Ok(ev) = rx.recv_timeout(left.min(CACHE_CHECK)) else { continue };
        trace(&format!("pairing browse: {ev:?}"));
        let mdns_sd::ServiceEvent::ServiceResolved(info) = ev else { continue };
        let Some(v) = pick(&info) else { continue };
        let addrs = order(dial_addrs(&info).into_iter());
        if addrs.is_empty() {
            continue;
        }
        let name = instance(&info.fullname);
        if found.len() >= MAX_FOUND && !found.contains_key(&name) {
            continue;
        }
        found.insert(name, (addrs, v));
        if !settled {
            settled = true;
            deadline = std::time::Instant::now() + PAIRING_SETTLE;
        }
    }
    let _ = daemon.shutdown();
    Ok(found)
}

/// The device a found service is: its instance name without the " (n)"
/// that mDNS adds when a name conflicts, as when one daemon announces the
/// same device again.
fn instance(fullname: &str) -> String {
    let name = fullname.split('.').next().unwrap_or(fullname);
    match name.rsplit_once(" (") {
        Some((base, n))
            if n.strip_suffix(')').is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit())) =>
        {
            base.to_string()
        }
        _ => name.to_string(),
    }
}

/// Whether the tests put this device on another network: the folder
/// CBB_TEST_ELSEWHERE names holds a file named by its device ID. It then
/// neither publishes itself nor dials what browsing finds, as the Go
/// service's tests' hidden members.
fn elsewhere(me: &DeviceId) -> bool {
    crate::testbuild::env_os("CBB_TEST_ELSEWHERE").is_some_and(|d| std::path::Path::new(&d).join(me.as_str()).exists())
}

const MAX_WAIT: Duration = Duration::from_secs(30);
/// How long a member that dials waits for one with a lower device ID to
/// dial it before it dials that one itself, as Go's fallbackDial.
const FALLBACK: Duration = Duration::from_secs(30);

/// The fallback test's wait, in milliseconds from CBB_TEST_FALLBACK, as
/// Go's fallbackAfter: with it set, this member also dials the members with
/// a greater device ID at port 1, as if a firewall there dropped the member
/// port, so that only their fallback dials connect.
fn test_fallback() -> Option<Duration> {
    static AFTER: std::sync::OnceLock<Option<Duration>> = std::sync::OnceLock::new();
    *AFTER.get_or_init(|| crate::testbuild::env("CBB_TEST_FALLBACK")?.parse().ok().map(Duration::from_millis))
}
/// At most this many connections may be in their TLS handshake at once.
const MAX_HANDSHAKES: usize = 16;
/// At most this many of them from one source (crate::pair::source), other
/// than the loopback address, which the tunnels' and relays' ports share.
const MAX_HANDSHAKES_PER_SOURCE: usize = 4;
/// How long a connection from another device has to start its TLS
/// handshake: a member sends its client hello as soon as it connects.
const HELLO_TIMEOUT: Duration = Duration::from_secs(3);

/// The connections in their handshake, in all and by source.
#[derive(Default)]
struct Handshakes {
    all: usize,
    by_source: HashMap<IpAddr, usize>,
}

impl Handshakes {
    /// Takes a slot for a connection from ip, if one is free.
    fn take(&mut self, ip: IpAddr) -> bool {
        if self.all >= MAX_HANDSHAKES {
            return false;
        }
        if !ip.to_canonical().is_loopback() {
            let n = self.by_source.entry(crate::pair::source(ip)).or_default();
            if *n >= MAX_HANDSHAKES_PER_SOURCE {
                return false;
            }
            *n += 1;
        }
        self.all += 1;
        true
    }

    /// Gives back the slot of a connection from ip.
    fn give(&mut self, ip: IpAddr) {
        self.all = self.all.saturating_sub(1);
        if !ip.to_canonical().is_loopback() {
            let k = crate::pair::source(ip);
            if let Some(n) = self.by_source.get_mut(&k) {
                *n -= 1;
                if *n == 0 {
                    self.by_source.remove(&k);
                }
            }
        }
    }
}

/// Whether a connection from another device starts its TLS handshake
/// within HELLO_TIMEOUT; a loopback one has the handshake's whole time,
/// since it may come from far through a tunnel or a relay.
fn hello_comes(sock: &TcpStream, from: IpAddr) -> bool {
    if from.to_canonical().is_loopback() {
        return true;
    }
    if sock.set_read_timeout(Some(HELLO_TIMEOUT)).is_err() {
        return false;
    }
    matches!(sock.peek(&mut [0u8; 1]), Ok(n) if n > 0)
}
/// The members found by browsing that are dialed at once, as Go's mDNS
/// cache reports at most.
const MAX_FOUND: usize = 64;
/// How often the networks where this device publishes itself are checked
/// again: an interface may have come up or moved to another network.
const RECHECK: Duration = Duration::from_secs(5);
/// The least time between two changes of this device's registration. A
/// change of its TXT record is probed for about a second before mdns-sd
/// announces it; a second change in that time, as a pairing window that
/// closes and opens again for the next device, had mdns-sd hear its own
/// announcement as another device's, rename this one ("ID (2)", "ID (3)",
/// ...) and answer for none of the names until the renames stopped.
const REPUBLISH_GAP: Duration = Duration::from_millis(1500);

/// The addresses of a found member; None once it is gone.
type Addrs = Arc<Mutex<Option<Vec<SocketAddr>>>>;

/// Keeps the addresses of a member the app found: a member found again
/// takes the new ones, and a new one is kept while fewer than MAX_FOUND
/// are, and returned to be dialed. A member past MAX_FOUND is not dialed.
fn remember(found: &mut HashMap<String, Addrs>, key: String, addrs: Vec<SocketAddr>) -> Option<Addrs> {
    if let Some(a) = found.get(&key) {
        *a.lock().unwrap() = Some(addrs);
        return None;
    }
    if found.len() >= MAX_FOUND {
        return None;
    }
    let a: Addrs = Arc::new(Mutex::new(Some(addrs)));
    found.insert(key, a.clone());
    Some(a)
}

/// Dials the member at addrs again and again: at once after this member
/// ended the connection to connect again (a new hello), a second after a
/// connection that came up ended, and after a round of failures 1 s,
/// doubling to 30 s.
fn dial_loop(node: Arc<Node>, addrs: Addrs, peer: Option<DeviceId>) {
    dial_loop_as(node, addrs, peer, false)
}

/// As dial_loop; later, for a member that dials with a lower device ID,
/// which dials this one (docs/protocol.md, section 4, "Who dials whom"):
/// it dials only once no connection to it has been up for
/// FALLBACK, a firewall may stop that member's dials, or at once on
/// Node::redial, as Go's later dialer.
fn dial_loop_as(node: Arc<Node>, addrs: Addrs, peer: Option<DeviceId>, later: bool) {
    let mut wait = FIRST_WAIT;
    let mut redials = node.redials();
    let mut since = std::time::Instant::now();
    let mut last_failure = String::new();
    loop {
        if node.is_closed() {
            return;
        }
        let Some(list) = addrs.lock().unwrap().clone() else { return };
        if let (true, Some(p)) = (later, &peer) {
            let r = node.redials();
            if node.connected(p) {
                // It dialed this one: this loop dials only below.
                node.set_unreached(p, false);
                (since, redials) = (std::time::Instant::now(), r);
                node.nap(Duration::from_secs(1));
                continue;
            }
            if r == redials && since.elapsed() < test_fallback().unwrap_or(FALLBACK) {
                node.nap(Duration::from_secs(1));
                continue;
            }
            // A redial (a new network, the app resumed) is no sign that it
            // could not dial this one.
            if r == redials {
                node.set_unreached(p, true);
            }
            redials = r;
        }
        // A connection up to the peer is left alone; a loopback address
        // (the tunnel's, a relay's) replaces one at home (Node::connected_for).
        if node.is_paused() || peer.as_ref().is_some_and(|p| list.first().is_some_and(|a| node.connected_for(p, a))) {
            node.nap(Duration::from_secs(1));
            continue;
        }
        let mut up = false;
        let mut again = false;
        let mut failed = Vec::new();
        for a in list {
            match node.dial_ended(a, peer.clone()) {
                Ok(d) => {
                    (up, again) = (d.up, d.again);
                    failed.clear();
                    break;
                }
                Err(e) => failed.push(format!("{a}: {e:#}")),
            }
        }
        // Why a member cannot be reached is logged once, until it changes.
        let why = failed.join("; ");
        if why != last_failure {
            if !why.is_empty() && !node.is_closed() {
                let who = peer.as_ref().map_or_else(|| "the member".to_string(), ToString::to_string);
                node.logf(&format!("cbb: cannot reach {who}: {why}"));
            }
            last_failure = why;
        }
        wait = next_wait(wait, up, again);
        if wait.is_zero() {
            wait = FIRST_WAIT;
            continue;
        }
        if later {
            // The next try waits for FALLBACK again, or a redial.
            since = std::time::Instant::now();
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
/// or None when it cannot listen: the member then only dials.
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
    let busy = Arc::new(Mutex::new(Handshakes::default()));
    std::thread::spawn(move || {
        for conn in ln.incoming() {
            if node.is_closed() || stop.load(Ordering::SeqCst) {
                return;
            }
            let Ok(sock) = conn else { continue };
            let Ok(addr) = sock.peer_addr() else { continue };
            if !home_address(addr.ip()) || !interfaces::arrived(&sock) {
                continue; // dropping the socket closes it
            }
            if let Ok(local) = sock.local_addr()
                && !node.takes_on(local, addr)
            {
                log(&format!(
                    "cbb: a connection from {} to {local}, on a network this device has not met its group on; closed",
                    addr.ip()
                ));
                continue;
            }
            if !busy.lock().unwrap().take(addr.ip()) {
                continue;
            }
            let (node, busy, log, admit) = (node.clone(), busy.clone(), log.clone(), admit.clone());
            std::thread::spawn(move || {
                let mut slot = Some(busy);
                let mut release = || {
                    if let Some(b) = slot.take() {
                        b.lock().unwrap().give(addr.ip());
                    }
                };
                if !hello_comes(&sock, addr.ip()) {
                    release();
                    return;
                }
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
        let a = remember(&mut self.found.lock().unwrap(), key.to_string(), addrs);
        if let Some(a) = a {
            let node = node.clone();
            std::thread::spawn(move || dial_loop(node, a, peer));
        }
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

/// The mDNS sockets opened before the service gave up root (cbb service
/// -user), which browsing takes when it starts.
static PREOPENED: Mutex<Option<mdns_sd::ServiceDaemon>> = Mutex::new(None);

/// Opens the mDNS sockets now, as Go's mdns.Preopen: on FreeBSD a socket on
/// port 5353 shares it with avahi or another user's responder only when
/// root opened it, and cbb service -user gives up root right after.
pub fn preopen() -> Result<(), mdns_sd::Error> {
    *PREOPENED.lock().unwrap_or_else(|e| e.into_inner()) = Some(mdns_sd::ServiceDaemon::new()?);
    Ok(())
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
/// port, so it dials every member that browsing finds, those with `r=listen` too,
/// whatever their device IDs.
pub fn start_as_phone(node: Arc<Node>, tag: String, log: Arc<dyn Fn(&str) + Send + Sync>) {
    std::thread::spawn(move || {
        if let Err(e) = browse(node, &tag, None, true, &*log) {
            log(&format!("cbb: finding the members failed: {e}"));
        }
    });
}

/// The most records an mDNS daemon of the service may cache. mdns-sd
/// bounds its cache by nothing but the senders' TTLs, so any device on the
/// network could grow it without end; past this many, the daemon is
/// replaced by a new one, whose cache is empty, as Go's responder kept at
/// most 1024 entries.
const MAX_CACHED: i64 = 1024;
/// How often the cache's size is checked, and how long the daemon has to
/// answer.
const CACHE_CHECK: Duration = Duration::from_millis(100);
/// How many checks in a row the daemon may leave unanswered: one too busy
/// to answer for that long is flooded.
const MAX_MISSES: u32 = 10;
/// After a flood, how long browsing pauses before a new daemon: nothing
/// after the first, then twice as long after each one that comes within
/// CALM of the last, up to MAX_PAUSE, so that a lasting flood does not have
/// the daemon replaced, and this device announced again, every moment.
const FIRST_PAUSE: Duration = Duration::from_secs(5);
const MAX_PAUSE: Duration = Duration::from_secs(60);
const CALM: Duration = Duration::from_secs(120);

/// How many records the daemon caches, and the timers it keeps for them;
/// None when it does not answer within CACHE_CHECK.
fn cached(daemon: &mdns_sd::ServiceDaemon) -> Option<i64> {
    let m = daemon.get_metrics().ok()?.recv_timeout(CACHE_CHECK).ok()?;
    Some(sum_cached(&m))
}

/// The checks of the daemon's cache and the floods so far.
#[derive(Default)]
struct Flood {
    misses: u32,
    pause: Duration,
    last: Option<Instant>,
}

impl Flood {
    /// Whether a check that found cached records (None: no answer) shows
    /// the daemon flooded.
    fn check(&mut self, cached: Option<i64>) -> bool {
        match cached {
            Some(n) => {
                self.misses = 0;
                n > MAX_CACHED
            }
            None => {
                self.misses += 1;
                self.misses >= MAX_MISSES
            }
        }
    }

    /// How long browsing pauses after a flood at now.
    fn pause(&mut self, now: Instant) -> Duration {
        self.misses = 0;
        let again = self.last.is_some_and(|t| now.duration_since(t) < CALM + self.pause);
        self.pause = match (again, self.pause.is_zero()) {
            (false, _) => Duration::ZERO,
            (true, true) => FIRST_PAUSE,
            (true, false) => (self.pause * 2).min(MAX_PAUSE),
        };
        self.last = Some(now);
        self.pause
    }
}

/// The records and timers among an mDNS daemon's metrics.
fn sum_cached(m: &mdns_sd::Metrics) -> i64 {
    m.iter().filter(|(k, _)| k.starts_with("cached-") || k.as_str() == "timer").map(|(_, v)| *v).sum()
}

/// Sets the interfaces a daemon uses: as Go's responder, no loopback
/// interfaces, and on a router only the devices of the interface list.
fn set_interfaces(daemon: &mdns_sd::ServiceDaemon) {
    let _ = daemon.disable_interface(vec![mdns_sd::IfKind::LoopbackV4, mdns_sd::IfKind::LoopbackV6]);
    let only = interfaces::only();
    if !only.is_empty() {
        let _ = daemon.disable_interface(mdns_sd::IfKind::All);
        let _ = daemon.enable_interface(only.iter().map(|n| mdns_sd::IfKind::Name(n.clone())).collect::<Vec<_>>());
    }
}

/// How long after the first member found without its TXT record browsing
/// asks for it, past the second in which mdns-sd's responder sends a record
/// it has just multicast no more.
const ASK_FIRST: Duration = Duration::from_millis(1500);

/// The wait between later asks, doubled each time up to ASK_MAX; longer
/// than ASK_FOR, so that one asker runs at a time.
const ASK_GAP: Duration = Duration::from_secs(5);
const ASK_MAX: Duration = Duration::from_secs(60);

/// How long an asker browses.
const ASK_FOR: Duration = Duration::from_secs(3);

/// The members browsing found without their TXT record, and when to ask
/// for it again.
///
/// mdns-sd resolves a member from its SRV and address records alone. A
/// responder that multicast its TXT record within the last second leaves it
/// out of its answer (mdns-sd's rate limit), so a daemon that started
/// browsing just then resolves the member with no TXT, no group tag and no
/// role. It never asks for the TXT again: it asks only for what has no SRV,
/// and its own browse queries carry the PTR as a known answer, which the
/// responders do not answer again; the TXT lives 75 minutes, and a member
/// that dials never found the other.
#[derive(Default)]
struct Untold {
    names: std::collections::HashSet<String>,
    next: Option<Instant>,
    gap: Duration,
}

impl Untold {
    /// Notes a member resolved with no TXT record; true when it is new.
    /// Anyone on the network can announce names, so they are bounded as
    /// the members dialed are.
    fn add(&mut self, fullname: &str, now: Instant) -> bool {
        if self.names.len() >= MAX_FOUND && !self.names.contains(fullname) {
            return false;
        }
        if self.names.is_empty() {
            self.next = Some(now + ASK_FIRST);
            self.gap = ASK_GAP;
        }
        self.names.insert(fullname.to_string())
    }

    /// Notes a member resolved with its TXT record, or gone.
    fn remove(&mut self, fullname: &str) {
        self.names.remove(fullname);
        if self.names.is_empty() {
            self.next = None;
        }
    }

    /// Reports whether to ask now, and if so when to ask next.
    fn due(&mut self, now: Instant) -> bool {
        match self.next {
            Some(t) if now >= t => {
                self.next = Some(now + self.gap);
                self.gap = (self.gap * 2).min(ASK_MAX);
                true
            }
            _ => false,
        }
    }
}

/// Asks the members for their records again, from a daemon of its own:
/// its first browse query carries no known answers, so every member answers
/// it with its PTR, SRV, TXT and address records, multicast, which the
/// browsing daemon takes too and resolves the members again with their TXT.
fn ask_again() {
    std::thread::spawn(|| {
        let daemon = match mdns_sd::ServiceDaemon::new() {
            Ok(d) => d,
            Err(e) => return trace(&format!("asking for the TXT records: {e}")),
        };
        set_interfaces(&daemon);
        match daemon.browse(SERVICE) {
            Ok(rx) => {
                let end = Instant::now() + ASK_FOR;
                while let Some(left) = end.checked_duration_since(Instant::now()) {
                    let Ok(ev) = rx.recv_timeout(left) else { break };
                    trace(&format!("asking for the TXT records: {ev:?}"));
                }
            }
            Err(e) => trace(&format!("asking for the TXT records: {e}")),
        }
        let _ = daemon.shutdown();
    });
}

fn browse(
    node: Arc<Node>,
    tag: &str,
    port: Option<u16>,
    as_phone: bool,
    log: &(dyn Fn(&str) + Send + Sync),
) -> Result<(), mdns_sd::Error> {
    let preopened = PREOPENED.lock().unwrap_or_else(|e| e.into_inner()).take();
    let mut daemon = match preopened {
        Some(d) => d,
        None => mdns_sd::ServiceDaemon::new()?,
    };
    // The members found, whose dial loops outlive a daemon that is replaced.
    let mut found: HashMap<DeviceId, Addrs> = HashMap::new();
    let mut said = false;
    let mut flood = Flood::default();
    loop {
        if !browse_with(&node, tag, port, as_phone, log, &daemon, &mut found, &mut flood)? {
            let _ = daemon.shutdown();
            return Ok(());
        }
        if !said {
            log(&format!(
                "cbb: the mDNS cache holds more than {MAX_CACHED} records, or mDNS is too busy to answer, which \
                 another device on the network causes; it starts again empty, and pauses while that lasts (said once)"
            ));
            said = true;
        }
        let _ = daemon.shutdown();
        // The members found are still dialed meanwhile.
        let pause = flood.pause(Instant::now());
        if !pause.is_zero() {
            node.nap(pause);
        }
        loop {
            if node.is_closed() {
                return Ok(());
            }
            match mdns_sd::ServiceDaemon::new() {
                Ok(d) => {
                    daemon = d;
                    break;
                }
                Err(e) => {
                    log(&format!("cbb: cannot start mDNS again: {e}; trying again in 10 s"));
                    node.nap(Duration::from_secs(10));
                }
            }
        }
    }
}

/// Publishes and browses with daemon until the node closes (false) or the
/// daemon's cache is flooded (true), which the caller answers with a new
/// daemon.
#[allow(clippy::too_many_arguments)]
fn browse_with(
    node: &Arc<Node>,
    tag: &str,
    port: Option<u16>,
    as_phone: bool,
    log: &(dyn Fn(&str) + Send + Sync),
    daemon: &mdns_sd::ServiceDaemon,
    found: &mut HashMap<DeviceId, Addrs>,
    flood: &mut Flood,
) -> Result<bool, mdns_sd::Error> {
    set_interfaces(daemon);
    start_trace();
    let me = node.identity().id.clone();
    if let Ok(events) = daemon.monitor() {
        let n = node.clone();
        std::thread::spawn(move || {
            while let Ok(ev) = events.recv() {
                trace(&format!("daemon: {ev:?}"));
                if let mdns_sd::DaemonEvent::NameChange(c) = ev {
                    n.logf(&format!(
                        "cbb: mDNS renamed {} to {}: another device answers for the name",
                        c.original, c.new_name
                    ));
                }
            }
        });
    }
    // A member that dials publishes itself without a role; one that does
    // not says so, and every other member dials it.
    let dials = node.can(cbb_core::authority::CAP_DIALS);
    // The protocol version, the group tag, r=listen on a member that does
    // not dial, and p=1 while a pairing window is open, which a joiner
    // looks for.
    // With known networks (a computer's service), only the addresses of
    // the interfaces on them are published, or every address while a
    // pairing window is open, as Go's responder with Publish; None for all.
    let where_ = || -> Option<Vec<IpAddr>> {
        if elsewhere(&me) {
            return Some(Vec::new());
        }
        let mut out: Vec<IpAddr> = match node.networks() {
            Some(n) if !node.window_open() => {
                n.published().into_iter().flat_map(|f| f.prefixes.into_iter().map(|(a, _)| a)).collect()
            }
            // Every address, listed here rather than by mdns-sd's
            // enable_addr_auto: a registration updated in place from a
            // list of addresses to automatic ones answered with none.
            _ => if_addrs::get_if_addrs()
                .unwrap_or_default()
                .into_iter()
                .filter(|f| !f.is_loopback() && interfaces::allowed(&f.name))
                .map(|f| f.ip())
                .collect(),
        };
        out.sort();
        out.dedup();
        Some(out)
    };
    let mut registered: Option<String> = None;
    let mut publish = |window: bool, at: &Option<Vec<IpAddr>>| -> Result<(), mdns_sd::Error> {
        let Some(port) = port else { return Ok(()) };
        if at.as_ref().is_some_and(Vec::is_empty) {
            // On no known network: browse only.
            if let Some(name) = registered.take() {
                log(
                    "cbb: on no known network now: this device stops publishing itself by mDNS and only looks for the members",
                );
                let _ = daemon.unregister(&name);
            }
            return Ok(());
        }
        // A registration of the same name is updated in place below: taking
        // it back first would have the new one probe against the old one's
        // records, which mdns-sd takes for another device's and renames this
        // one ("ID (2)"), which nobody finds by its ID.
        let mut txt = vec![("v", "1"), ("g", tag)];
        if !dials && !as_phone {
            txt.push(("r", "listen"));
        }
        if window {
            txt.push(("p", "1"));
        }
        let host = format!("{}.", me.host_name());
        let info = match at {
            Some(addrs) => mdns_sd::ServiceInfo::new(SERVICE, me.as_str(), &host, &addrs[..], port, &txt[..])?,
            None => mdns_sd::ServiceInfo::new(SERVICE, me.as_str(), &host, "", port, &txt[..])?.enable_addr_auto(),
        };
        registered = Some(info.get_fullname().to_string());
        // Each change of what is published, so that a member nobody finds
        // can be told from its log.
        log(&format!(
            "cbb: publishing this device by mDNS at {}{}",
            match at {
                Some(a) => a.iter().map(ToString::to_string).collect::<Vec<_>>().join(", "),
                None => "every address".into(),
            },
            if window { ", with the pairing window open" } else { "" }
        ));
        daemon.register(info)
    };
    let mut window = node.window_open();
    let mut at = where_();
    publish(window, &at)?;
    let mut checked = Instant::now();
    let mut published = Instant::now();
    let mut cache_checked = Instant::now();
    let events = daemon.browse(SERVICE)?;
    let mut untold = Untold::default();
    loop {
        let ev = events.recv_timeout(CACHE_CHECK);
        if node.is_closed() {
            break;
        }
        if cache_checked.elapsed() >= CACHE_CHECK {
            cache_checked = Instant::now();
            if flood.check(cached(daemon)) {
                return Ok(true);
            }
        }
        let away = elsewhere(&me);
        if !away && untold.due(Instant::now()) {
            ask_again();
        }
        if away && !found.is_empty() {
            for (_, a) in found.drain() {
                *a.lock().unwrap() = None;
            }
        }
        if (node.window_open() != window
            || checked.elapsed() >= RECHECK
            || away != at.as_ref().is_some_and(Vec::is_empty))
            && published.elapsed() >= REPUBLISH_GAP
        {
            checked = Instant::now();
            let now = where_();
            if node.window_open() != window || now != at {
                (window, at) = (node.window_open(), now);
                published = Instant::now();
                if let Err(e) = publish(window, &at) {
                    log(&format!("cbb: announcing this device failed: {e}"));
                }
            }
        }
        let Ok(ev) = ev else {
            if events.is_disconnected() {
                log("cbb: looking for the members by mDNS ended: the mDNS daemon stopped sending what it finds");
                break;
            }
            continue;
        };
        trace(&format!("{me}: {ev:?}"));
        match ev {
            mdns_sd::ServiceEvent::ServiceResolved(info) => {
                let Some(id) = instance_id(&info.fullname) else { continue };
                if away {
                    continue;
                }
                // One resolved without its TXT record is asked for it
                // again rather than taken for another group's.
                if info.get_properties().is_empty() {
                    if id != me && untold.add(&info.fullname, Instant::now()) {
                        log(&format!("cbb: found {id} by mDNS without its TXT record; asking for it again"));
                    }
                    continue;
                }
                untold.remove(&info.fullname);
                // Members of another group, or of a replaced CA, are ignored.
                let r = info.get_property_val_str("r");
                if id == me || info.get_property_val_str("g") != Some(tag) {
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
                // A phone dials every member, and a member that dials
                // every member that does not; of two members that dial, the
                // lower ID dials, and the other later. A member that does
                // not dial waits.
                if !as_phone && !dials {
                    continue;
                }
                let later = dials_later(as_phone, port.is_some(), r, &id, &me);
                let addrs = order(dial_addrs(&info).into_iter());
                if addrs.is_empty() {
                    log(&format!(
                        "cbb: found {id} by mDNS with no address of a home network ({}); not dialed",
                        info.get_addresses().iter().map(|a| a.to_ip_addr().to_string()).collect::<Vec<_>>().join(", ")
                    ));
                    continue;
                }
                let addrs = if test_fallback().is_some() && id > me {
                    addrs.into_iter().map(|a| SocketAddr::new(a.ip(), 1)).collect()
                } else {
                    addrs
                };
                // Anyone on the network can announce the group's tag, so
                // the members dialed are bounded, as in Go; a device the
                // records name takes the place of one they do not.
                if !found.contains_key(&id) && found.len() >= MAX_FOUND {
                    let known = node.records().lock().unwrap().known();
                    match evicts(found.keys(), &known, &id) {
                        Some(k) => {
                            if let Some(a) = found.remove(&k) {
                                *a.lock().unwrap() = None;
                            }
                        }
                        None => continue,
                    }
                }
                match found.get(&id) {
                    Some(cur) => {
                        node.found(&id, true);
                        // mDNS may first resolve a member with only some of
                        // its addresses (a link-local one from the interface
                        // the answer came on, which another interface's scope
                        // can make unreachable); its dial loop, maybe backing
                        // off after failing those, tries the new ones at once.
                        // Anyone may answer for the member's name, so the new
                        // addresses join those known rather than replace them,
                        // and a connected member's stay as they are.
                        if node.connected(&id) {
                            continue;
                        }
                        let mut cur = cur.lock().unwrap();
                        let merged = merge_addrs(&addrs, cur.as_deref().unwrap_or_default());
                        if cur.as_ref() != Some(&merged) {
                            *cur = Some(merged);
                            node.kick();
                        }
                    }
                    None => {
                        node.found(&id, true);
                        log(&format!("cbb: found {id} at {}", addrs[0]));
                        let cur: Addrs = Arc::new(Mutex::new(Some(addrs)));
                        found.insert(id.clone(), cur.clone());
                        let node = node.clone();
                        std::thread::spawn(move || dial_loop_as(node, cur, Some(id), later));
                    }
                }
            }
            mdns_sd::ServiceEvent::ServiceRemoved(_, fullname) => {
                untold.remove(&fullname);
                // Anyone may say goodbye for a member: a device the records
                // name keeps its dial loop, which its own connection and
                // the loop's back-off pace.
                let Some(id) = instance_id(&fullname) else { continue };
                let known = node.records().lock().unwrap().known();
                if goodbye_stops(&known, &id) {
                    node.found(&id, false);
                    if let Some(cur) = found.remove(&id) {
                        *cur.lock().unwrap() = None;
                    }
                }
            }
            _ => {}
        }
    }
    Ok(false)
}

/// The most addresses kept for one member found by mDNS.
const MAX_ADDRS: usize = 8;

/// The addresses of a member resolved again: up to half of MAX_ADDRS new
/// ones first, then those known before, then the other new ones, at most
/// MAX_ADDRS; anyone may answer for a member, so new addresses never push
/// out all of those known.
fn merge_addrs(new: &[SocketAddr], known: &[SocketAddr]) -> Vec<SocketAddr> {
    let first = new.len().min(MAX_ADDRS / 2);
    let mut out: Vec<SocketAddr> = Vec::new();
    for a in new[..first].iter().chain(known).chain(&new[first..]) {
        if !out.contains(a) {
            out.push(*a);
        }
    }
    out.truncate(MAX_ADDRS);
    out
}

/// Which member found by mDNS gives its place to id when MAX_FOUND are
/// found: one the records do not name, and only to one they name (known,
/// sorted); None leaves id out.
fn evicts<'a>(found: impl Iterator<Item = &'a DeviceId>, known: &[String], id: &DeviceId) -> Option<DeviceId> {
    let names = |d: &DeviceId| known.binary_search(&d.to_string()).is_ok();
    if !names(id) {
        return None;
    }
    let mut found = found;
    found.find(|d| !names(d)).cloned()
}

/// Whether an mDNS goodbye for id stops its dial loop: only for a device
/// the records (known, sorted) do not name. Anyone may send one, so a
/// member of the group stops being dialed only as its own connection says.
fn goodbye_stops(known: &[String], id: &DeviceId) -> bool {
    known.binary_search(&id.to_string()).is_err()
}

/// Reports whether a TXT `r` value names a member that does not dial,
/// which every other member dials; keys and values are compared without
/// regard to case.
/// Reports whether a member dials one it found with the TXT `r` and the
/// device ID `id` only after FALLBACK: when that one also dials and has the
/// lower ID, so that it is the one to dial. A phone dials everyone at once,
/// and so does a member that does not listen (-no-listen), which no one
/// else can reach.
fn dials_later(as_phone: bool, listening: bool, r: Option<&str>, id: &DeviceId, me: &DeviceId) -> bool {
    !as_phone && listening && !listens_only(r) && id < me
}

fn listens_only(r: Option<&str>) -> bool {
    r.is_some_and(|v| v.eq_ignore_ascii_case("listen"))
}

/// Reports whether a TXT `r` value names a phone, the group's hub while its
/// app is open.
fn phone(r: Option<&str>) -> bool {
    r.is_some_and(|v| v.eq_ignore_ascii_case("phone"))
}

/// The device ID in an instance name, <device ID>._cbb._tcp.local.
fn instance_id(fullname: &str) -> Option<DeviceId> {
    let label = fullname.strip_suffix(SERVICE)?.strip_suffix('.')?;
    // Without the " (n)" that mDNS adds when the name conflicts, as when
    // the device's own registration answered for it before an update.
    DeviceId::parse(&instance(label)).ok()
}

/// The addresses a resolved member is dialed at. A link-local address
/// takes the scope of the interface the answer came on, except one of this
/// device's own (another member on the same device, as in tests), which is
/// reached only through the interface that has it.
fn dial_addrs(info: &mdns_sd::ResolvedService) -> Vec<SocketAddr> {
    let own = std::sync::OnceLock::new();
    info.get_addresses()
        .iter()
        .map(|ip| match ip {
            mdns_sd::ScopedIp::V6(v6) if v6.addr().is_unicast_link_local() => {
                let ifs: &Vec<interfaces::Iface> = own.get_or_init(interfaces::system);
                let scope = link_scope(*v6.addr(), v6.scope_id().index, ifs);
                SocketAddr::V6(SocketAddrV6::new(*v6.addr(), info.port, 0, scope))
            }
            other => SocketAddr::new(other.to_ip_addr(), info.port),
        })
        .collect()
}

/// The scope of a link-local address that came on the interface arrived:
/// that interface's, or, for an address of this device's own, the index of
/// the interface that has it.
fn link_scope(a: std::net::Ipv6Addr, arrived: u32, own: &[interfaces::Iface]) -> u32 {
    own.iter().find(|i| i.ip == IpAddr::V6(a)).and_then(|i| i.index).unwrap_or(arrived)
}

/// The addresses that would be published, IPv4 first, then routable IPv6,
/// then link-local IPv6. An IPv4 address written as IPv6 (::ffff:a.b.c.d)
/// is taken as the IPv4 address it is, so every test here sees one form and
/// one host is dialed once.
fn order(addrs: impl Iterator<Item = SocketAddr>) -> Vec<SocketAddr> {
    let mut out: Vec<SocketAddr> = Vec::new();
    for a in addrs {
        let a = match a.ip().to_canonical() {
            ip @ IpAddr::V4(_) => SocketAddr::new(ip, a.port()),
            IpAddr::V6(_) => a,
        };
        if home_address(a.ip()) && !a.ip().is_loopback() && !out.contains(&a) {
            out.push(a);
        }
    }
    out.sort_by_key(|a| match a.ip() {
        IpAddr::V4(_) => 0,
        IpAddr::V6(v6) if !v6.is_unicast_link_local() => 1,
        IpAddr::V6(_) => 2,
    });
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A code alone admits only when one device waits: two would give a
    /// device that only pretends to wait a guess at the code.
    #[test]
    fn a_code_alone_needs_one_waiting_device() {
        let addr = |i: u8| SocketAddr::from(([192, 168, 1, i], 8764));
        assert!(the_one_joiner(Vec::new()).is_err());
        let many: Vec<SocketAddr> = (1..=9).map(addr).collect();
        let (addrs, fp) = the_one_joiner(vec![(many, "f1".into())]).unwrap();
        assert_eq!((addrs.len(), fp.as_str()), (cbb_core::pair::MAX_ADDRS, "f1"));
        let two = vec![(vec![addr(1)], "f1".to_string()), (vec![addr(2)], "f2".to_string())];
        let e = the_one_joiner(two).unwrap_err();
        assert!(e.message().contains("2 devices wait to join"), "{e:?}");
    }

    /// One source holds at most MAX_HANDSHAKES_PER_SOURCE of the
    /// handshake slots, so idle connections from one device leave the
    /// others room; loopback connections only count in all.
    #[test]
    fn handshakes_by_source() {
        let mut h = Handshakes::default();
        let a: IpAddr = "192.168.1.7".parse().unwrap();
        let a6: IpAddr = "2001:db8:2:3::1".parse().unwrap();
        for _ in 0..MAX_HANDSHAKES_PER_SOURCE {
            assert!(h.take(a));
            assert!(h.take(a6));
        }
        assert!(!h.take(a));
        // Another address of the same global IPv6 /64 is the same source;
        // the devices of the home network's unique-local /64 are not.
        assert!(!h.take("2001:db8:2:3::99".parse().unwrap()));
        assert!(h.take("fd00:1:2:3::1".parse().unwrap()));
        assert!(h.take("fd00:1:2:3::2".parse().unwrap()));
        h.give("fd00:1:2:3::1".parse().unwrap());
        h.give("fd00:1:2:3::2".parse().unwrap());
        h.give(a);
        assert!(h.take(a));
        let lo: IpAddr = "127.0.0.1".parse().unwrap();
        while h.take(lo) {}
        assert_eq!(h.all, MAX_HANDSHAKES);
        assert!(!h.take("192.168.1.8".parse().unwrap()));
        for _ in 0..MAX_HANDSHAKES_PER_SOURCE {
            h.give(a6);
        }
        assert!(!h.by_source.contains_key(&crate::pair::source(a6)));
        assert!(h.take("192.168.1.8".parse().unwrap()));
    }

    /// A connection that sends nothing gives its slot back after
    /// HELLO_TIMEOUT, not after the handshake's whole time.
    #[test]
    fn a_silent_connection_is_closed_soon() {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let _silent = TcpStream::connect(l.local_addr().unwrap()).unwrap();
        let (sock, _) = l.accept().unwrap();
        let other: IpAddr = "192.168.1.7".parse().unwrap();
        let t = Instant::now();
        assert!(!hello_comes(&sock, other));
        assert!(t.elapsed() < HELLO_TIMEOUT + Duration::from_secs(2));
        // From the loopback address it waits for the handshake instead.
        assert!(hello_comes(&sock, "127.0.0.1".parse().unwrap()));
    }

    /// A link-local address of this device's own is dialed through the
    /// interface that has it, whichever interface mDNS heard it on; another
    /// device's through the interface it was heard on.
    /// The cache is checked often; a daemon too busy to answer counts as
    /// flooded after MAX_MISSES checks; floods that keep coming pause
    /// browsing longer each time, and a calm spell starts again.
    #[test]
    fn floods_of_the_mdns_cache() {
        let mut f = Flood::default();
        assert!(!f.check(Some(10)));
        assert!(f.check(Some(MAX_CACHED + 1)));
        for _ in 1..MAX_MISSES {
            assert!(!f.check(None));
        }
        assert!(!f.check(Some(10)), "an answer starts the count again");
        for _ in 1..MAX_MISSES {
            assert!(!f.check(None));
        }
        assert!(f.check(None));
        assert!(CACHE_CHECK * MAX_MISSES <= Duration::from_secs(1));

        let t = Instant::now();
        assert_eq!(f.pause(t), Duration::ZERO);
        assert_eq!(f.misses, 0);
        let mut at = t + Duration::from_secs(1);
        let mut want = FIRST_PAUSE;
        for _ in 0..8 {
            assert_eq!(f.pause(at), want);
            at += want + Duration::from_secs(1);
            want = (want * 2).min(MAX_PAUSE);
        }
        assert_eq!(f.pause, MAX_PAUSE);
        assert_eq!(f.pause(at + MAX_PAUSE + CALM), Duration::ZERO);
    }

    /// Anyone may answer for a member: its new addresses never push out all
    /// of those known, and the list stays bounded.
    #[test]
    fn new_addresses_join_those_known() {
        let a = |n: u8| SocketAddr::from(([192, 168, 1, n], 8764));
        let known: Vec<_> = (1..=4).map(a).collect();
        let forged: Vec<_> = (100..120).map(a).collect();
        let merged = merge_addrs(&forged, &known);
        assert_eq!(merged.len(), MAX_ADDRS);
        assert!(known.iter().all(|k| merged.contains(k)), "{merged:?}");
        assert_eq!(&merged[..MAX_ADDRS / 2], &forged[..MAX_ADDRS / 2]);
        // A member that moved is tried at its new address first.
        assert_eq!(merge_addrs(&[a(9)], &known), [a(9), a(1), a(2), a(3), a(4)]);
        assert_eq!(merge_addrs(&[a(2)], &known), [a(2), a(1), a(3), a(4)]);
    }

    /// An mDNS goodbye stops dialing only a device the records do not
    /// name; when MAX_FOUND are found, one the records name takes the place
    /// of one they do not, and no other.
    #[test]
    fn goodbyes_and_places_of_found_members() {
        let ids: Vec<DeviceId> = (0..4).map(|_| DeviceId::random()).collect();
        let mut known: Vec<String> = ids[..2].iter().map(|d| d.to_string()).collect();
        known.sort();
        assert!(!goodbye_stops(&known, &ids[0]));
        assert!(goodbye_stops(&known, &ids[2]));

        let found = [ids[0].clone(), ids[2].clone()];
        assert_eq!(evicts(found.iter(), &known, &ids[1]), Some(ids[2].clone()));
        assert_eq!(evicts(found.iter(), &known, &ids[3]), None, "an unknown device takes no place");
        assert_eq!(evicts(found[..1].iter(), &known, &ids[1]), None, "only known devices found");
    }

    #[test]
    fn own_link_local_takes_its_interface() {
        let own = vec![
            interfaces::Iface { name: "end0".into(), ip: "fe80::9e13".parse().unwrap(), prefix: 64, index: Some(2) },
            interfaces::Iface { name: "veth1".into(), ip: "fe80::280e".parse().unwrap(), prefix: 64, index: Some(12) },
        ];
        assert_eq!(link_scope("fe80::9e13".parse().unwrap(), 12, &own), 2);
        assert_eq!(link_scope("fe80::280e".parse().unwrap(), 2, &own), 12);
        assert_eq!(link_scope("fe80::77".parse().unwrap(), 12, &own), 12);
    }

    /// A name mDNS made unique by " (n)" names the same device.
    #[test]
    fn instance_drops_the_conflict_suffix() {
        assert_eq!(instance("abc._cbb._tcp.local."), "abc");
        assert_eq!(instance("abc (3)._cbb._tcp.local."), "abc");
        assert_eq!(instance("abc (x)._cbb._tcp.local."), "abc (x)");
        assert_eq!(instance("abc ()._cbb._tcp.local."), "abc ()");
        let id = "90571e1e690522fc4764f498f647e534";
        let want = DeviceId::parse(id).ok();
        assert_eq!(instance_id(&format!("{id} (9).{SERVICE}")), want);
        assert_eq!(instance_id(&format!("{id}.{SERVICE}")), want);
    }

    /// The members the app finds and dials are bounded: past MAX_FOUND a
    /// new one is not dialed, while one found again takes its new addresses.
    #[test]
    fn dials_at_most_max_found() {
        use super::{MAX_FOUND, remember};
        let addr = |i: usize| vec![std::net::SocketAddr::from(([192, 168, 0, (i % 250) as u8], 7000))];
        let mut found = std::collections::HashMap::new();
        for i in 0..MAX_FOUND {
            assert!(remember(&mut found, i.to_string(), addr(i)).is_some(), "member {i}");
        }
        assert!(remember(&mut found, MAX_FOUND.to_string(), addr(1)).is_none());
        assert_eq!(found.len(), MAX_FOUND);
        assert!(remember(&mut found, "3".into(), addr(9)).is_none());
        assert_eq!(*found["3"].lock().unwrap(), Some(addr(9)));
        found.remove("0");
        assert!(remember(&mut found, MAX_FOUND.to_string(), addr(1)).is_some());
    }

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

    /// A member resolved without its TXT record is asked for it after
    /// ASK_FIRST, then again with a doubling wait up to ASK_MAX, until every
    /// such member has its TXT or is gone.
    #[test]
    fn asks_again_for_a_missing_txt() {
        let t0 = Instant::now();
        let mut u = Untold::default();
        assert!(!u.due(t0 + ASK_MAX * 10), "nothing to ask for");
        assert!(u.add("a", t0));
        assert!(!u.add("a", t0), "the same member again");
        assert!(!u.due(t0));
        assert!(u.due(t0 + ASK_FIRST));
        assert!(!u.due(t0 + ASK_FIRST), "once per wait");
        let mut at = t0 + ASK_FIRST;
        let mut gap = ASK_GAP;
        for _ in 0..8 {
            assert!(!u.due(at + gap - Duration::from_millis(1)));
            at += gap;
            assert!(u.due(at));
            gap = (gap * 2).min(ASK_MAX);
        }
        assert_eq!(gap, ASK_MAX);
        assert!(ASK_GAP > ASK_FOR, "one asker at a time");
        // A second member keeps the schedule; asking stops when both are told.
        assert!(u.add("b", at));
        u.remove("a");
        assert!(u.due(at + ASK_MAX));
        u.remove("b");
        assert!(!u.due(at + ASK_MAX * 10));
        // At most MAX_FOUND of them.
        let mut many = Untold::default();
        for i in 0..MAX_FOUND {
            assert!(many.add(&i.to_string(), t0));
        }
        assert!(!many.add("one more", t0));
        assert_eq!(many.names.len(), MAX_FOUND);
        // A member found without TXT later starts again from ASK_FIRST.
        let t1 = at + ASK_MAX * 20;
        assert!(u.add("c", t1));
        assert!(!u.due(t1 + ASK_FIRST - Duration::from_millis(1)));
        assert!(u.due(t1 + ASK_FIRST));
        assert!(u.due(t1 + ASK_FIRST + ASK_GAP));
    }

    /// A daemon that starts browsing within the second after a member
    /// multicast its TXT record resolves it without one, since mdns-sd's
    /// responder leaves the TXT out of its answer, and never asks for it;
    /// ask_again gets it. TestFreezeAnAdmin failed so on the Rust cbb once:
    /// a member restarted browsing just after another asked for the root's
    /// TXT, and never dialed the root.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_missing_txt_comes_when_asked() {
        use std::net::{Ipv4Addr, SocketAddrV4};
        start_trace();
        let Some(ip) = if_addrs::get_if_addrs().unwrap_or_default().into_iter().find_map(|f| match f.ip() {
            IpAddr::V4(v4) if !f.is_loopback() && interfaces::allowed(&f.name) => Some(v4),
            _ => None,
        }) else {
            eprintln!("no interface for mDNS; skipped");
            return;
        };
        let daemon = || {
            let d = mdns_sd::ServiceDaemon::new().unwrap();
            set_interfaces(&d);
            d
        };
        let responder = daemon();
        let nanos = std::time::SystemTime::UNIX_EPOCH.elapsed().unwrap_or_default().as_nanos() as u64;
        let name = format!("{:016x}{nanos:016x}", std::process::id());
        let txt = [("v", "1"), ("g", "txt-test")];
        let info =
            mdns_sd::ServiceInfo::new(SERVICE, &name, "cb-txt-test.local.", IpAddr::V4(ip), 4242, &txt[..]).unwrap();
        let fullname = info.get_fullname().to_string();
        responder.register(info).unwrap();
        // Past its announcements and their second.
        std::thread::sleep(Duration::from_millis(3500));
        // Another device asks for the TXT record alone, as a daemon does
        // that has the member's PTR and not its SRV, from port 5353, so that
        // the answer is multicast.
        let sock = socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::DGRAM, None).unwrap();
        sock.set_reuse_address(true).unwrap();
        sock.set_reuse_port(true).unwrap();
        sock.bind(&SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 5353).into()).unwrap();
        sock.set_multicast_if_v4(&ip).unwrap();
        let mut q = vec![0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0];
        for label in fullname.trim_end_matches('.').split('.') {
            q.push(label.len() as u8);
            q.extend_from_slice(label.as_bytes());
        }
        q.extend_from_slice(&[0, 0, 16, 0, 1]);
        sock.send_to(&q, &SocketAddrV4::new(Ipv4Addr::new(224, 0, 0, 251), 5353).into()).unwrap();
        drop(sock);
        std::thread::sleep(Duration::from_millis(300));
        // A daemon that starts browsing now: resolved with no TXT.
        let browser = daemon();
        let rx = browser.browse(SERVICE).unwrap();
        let resolved = |wait: Duration| {
            let end = Instant::now() + wait;
            let mut txt = None;
            while let Some(left) = end.checked_duration_since(Instant::now()) {
                let Ok(ev) = rx.recv_timeout(left) else { break };
                if let mdns_sd::ServiceEvent::ServiceResolved(i) = ev
                    && i.fullname == fullname
                {
                    txt = Some(i.get_property_val_str("g").map(str::to_string));
                    if txt == Some(Some("txt-test".into())) {
                        break;
                    }
                }
            }
            txt
        };
        assert_eq!(resolved(Duration::from_secs(4)), Some(None), "resolved at first without the TXT");
        ask_again();
        assert_eq!(resolved(ASK_FOR + Duration::from_secs(2)), Some(Some("txt-test".into())), "the TXT after asking");
        for d in [browser, responder] {
            let _ = d.shutdown();
        }
    }

    #[test]
    fn instance_names() {
        let id = "0123456789abcdef0123456789abcdef";
        assert_eq!(instance_id(&format!("{id}._cbb._tcp.local.")).unwrap().as_str(), id);
        assert!(instance_id("printer._cbb._tcp.local.").is_none());
        assert!(instance_id(&format!("{id}._http._tcp.local.")).is_none());
    }

    #[test]
    fn who_dials_later() {
        let low = DeviceId::parse("00000000000000000000000000000001").unwrap();
        let high = DeviceId::parse("fffffffffffffffffffffffffffffffe").unwrap();
        // Of two that dial, the higher ID waits for the lower one.
        assert!(dials_later(false, true, None, &low, &high));
        assert!(!dials_later(false, true, None, &high, &low));
        // Not for one that never dials, nor as a phone.
        assert!(!dials_later(false, true, Some("listen"), &low, &high));
        assert!(!dials_later(true, true, None, &low, &high));
        // A member that does not listen cannot be dialed: it dials at once.
        assert!(!dials_later(false, false, None, &low, &high));
    }

    #[test]
    fn txt_roles() {
        assert!(
            listens_only(Some("listen"))
                && listens_only(Some("LISTEN"))
                && !listens_only(Some("dial"))
                && !listens_only(None)
        );
        assert!(phone(Some("phone")) && phone(Some("Phone")) && !phone(Some("listen")) && !phone(None));
        assert!(!listens_only(Some("linux")) && !listens_only(Some("")));
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

    #[test]
    fn an_ipv4_address_written_as_ipv6_is_ordered_as_ipv4() {
        let got = order(
            [
                "[fd00::2]:8764",
                "[::ffff:192.168.1.5]:8764",
                "192.168.1.5:8764",
                "[::ffff:127.0.0.1]:8764",
                "127.0.0.1:8764",
                "[::1]:8764",
                "[::ffff:8.8.8.8]:8764",
                "192.168.1.6:8764",
                "[fd00::2]:8764",
            ]
            .iter()
            .map(|s| s.parse().unwrap()),
        );
        let want: Vec<SocketAddr> =
            ["192.168.1.5:8764", "192.168.1.6:8764", "[fd00::2]:8764"].iter().map(|s| s.parse().unwrap()).collect();
        assert_eq!(got, want);
        // A link-local address keeps its scope.
        let scoped: SocketAddr = "[fe80::1%3]:8764".parse().unwrap();
        assert_eq!(order([scoped].into_iter()), vec![scoped]);
    }
}
