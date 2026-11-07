// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The lite member's end of the group's WireGuard tunnel (docs/protocol.md,
//! section 11): its key and the hub's offer in tunnel.json, and the link to
//! the hub. The link runs GotaTun's WireGuard over a UDP socket and
//! smoltcp's TCP inside it, in one thread, and opens a port on the loopback
//! address that leads to the hub's member port: the node dials that port
//! with member TLS, as the phone apps do (docs/design.md, "Members").

use std::collections::VecDeque;
use std::io::{self, Read, Write};
use std::net::{Ipv6Addr, Shutdown, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::os::fd::AsRawFd;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use bytes::BytesMut;
use gotatun::noise::index_table::IndexTable;
use gotatun::noise::rate_limiter::RateLimiter;
use gotatun::noise::{Tunn, TunnResult};
use gotatun::packet::Packet;
use gotatun::x25519::{PublicKey, StaticSecret};
use serde::{Deserialize, Serialize};
use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::tcp;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr};

use crate::certs::{DeviceId, b64};
use crate::error::{Context, Error, Result};
use crate::files;
use crate::wire::TunnelOffer;

/// The tunnel state's file in the state directory.
pub const FILE_NAME: &str = "tunnel.json";
/// Inside the tunnel the hub serves the member protocol on this port only.
const MEMBER_PORT: u16 = 8764;
const KEEPALIVE: u16 = 25;
/// The MTU inside the tunnel: IPv6's minimum, which fits in a UDP datagram
/// on any path, so nothing is fragmented.
const MTU: usize = 1280;
/// How long the link waits for the hub's answer at one endpoint before it
/// tries the next.
const ENDPOINT_WAIT: Duration = Duration::from_secs(10);
const MAX_ENDPOINTS: usize = 8;
const TCP_BUFFER: usize = 64 << 10;
/// The connections through the tunnel's local port at once; this member
/// makes one or two.
const MAX_BRIDGES: usize = 32;
const HANDSHAKE_RATE_LIMIT: u64 = 100;
const MAX_POLL: Duration = Duration::from_millis(250);

/// The tunnel state, kept while sync away from home is on: the device's own
/// key and preshared key, made on it, and the offers of the group's hubs.
#[derive(Serialize, Deserialize, Clone)]
pub struct State {
    #[serde(rename = "v")]
    pub version: u32,
    /// The group this state belongs to; a state of another group is dropped.
    pub group: String,
    #[serde(with = "b64")]
    key: Vec<u8>,
    /// The preshared key every hub uses for this device (docs/protocol.md,
    /// section 11, "Several hubs").
    #[serde(with = "b64")]
    pub psk: Vec<u8>,
    /// The offers of the group's hubs, one per hub.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hubs: Vec<Hub>,
}

/// The offer of one of the group's hubs, as this member keeps it.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct Hub {
    pub device: String,
    #[serde(with = "b64")]
    pub key: Vec<u8>,
    #[serde(with = "b64")]
    pub psk: Vec<u8>,
    #[serde(default)]
    pub endpoints: Vec<SocketAddr>,
    /// The key the hub serves with in its next period, which this member
    /// tries after `key`; empty for none.
    #[serde(with = "b64", default, skip_serializing_if = "Vec::is_empty")]
    pub next: Vec<u8>,
}

impl State {
    /// A new state with a new key and preshared key.
    pub fn new(group: &str) -> Result<State> {
        Ok(State { version: 1, group: group.to_string(), key: random_key()?, psk: random_key()?, hubs: vec![] })
    }

    /// Reads dir/tunnel.json; None if there is none.
    pub fn load(dir: &Path) -> Result<Option<State>> {
        let path = dir.join(FILE_NAME);
        let data = match std::fs::read(&path) {
            Ok(d) => d,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(Error::with(format!("cannot read {}", path.display()), e)),
        };
        let st: State = serde_json::from_slice(&data).context(format!("{} is damaged", path.display()))?;
        if st.key.len() != 32 {
            return Err(Error::msg(format!("{} is damaged: the key is not 32 bytes", path.display())));
        }
        if st.psk.len() != 32 {
            return Err(Error::msg(format!("{} is damaged: the preshared key is not 32 bytes", path.display())));
        }
        Ok(Some(st))
    }

    /// The offer of the hub `device`, if this member keeps one.
    pub fn hub(&self, device: &str) -> Option<&Hub> {
        self.hubs.iter().find(|h| h.device == device)
    }

    /// The offers this member tries, in the group's order of hubs `order`:
    /// those of hubs in the order, with an address, each hub that gave its
    /// key for the next period once more with that key, right after.
    pub fn hubs_to_try(&self, order: &[String]) -> Vec<Hub> {
        let mut hubs: Vec<&Hub> =
            self.hubs.iter().filter(|h| order.contains(&h.device) && !h.endpoints.is_empty()).collect();
        hubs.sort_by_key(|h| order.iter().position(|d| *d == h.device));
        let mut out = Vec::new();
        for h in hubs {
            out.push(h.clone());
            if !h.next.is_empty() {
                out.push(Hub { key: h.next.clone(), next: Vec::new(), ..h.clone() });
            }
        }
        out
    }

    /// Writes dir/tunnel.json, readable only by its owner.
    pub fn save(&self, dir: &Path) -> Result<()> {
        let data = serde_json::to_vec_pretty(self).context("cannot encode the tunnel state")?;
        files::write_atomic(&dir.join(FILE_NAME), &data, 0o600)
    }

    /// Removes dir/tunnel.json, if there is one.
    pub fn remove(dir: &Path) -> Result<()> {
        let path = dir.join(FILE_NAME);
        match std::fs::remove_file(&path) {
            Err(e) if e.kind() != io::ErrorKind::NotFound => {
                Err(Error::with(format!("cannot remove {}", path.display()), e))
            }
            _ => Ok(()),
        }
    }

    fn secret(&self) -> StaticSecret {
        let mut k = [0u8; 32];
        k.copy_from_slice(&self.key);
        StaticSecret::from(k)
    }

    /// The device's public key, which its hellos offer the hub.
    pub fn public_key(&self) -> Vec<u8> {
        PublicKey::from(&self.secret()).as_bytes().to_vec()
    }
}

/// 32 random bytes, for a key.
fn random_key() -> Result<Vec<u8>> {
    let mut key = vec![0u8; 32];
    getrandom::fill(&mut key).map_err(|_| Error::msg("cannot make a key: the system has no randomness"))?;
    Ok(key)
}

/// Checks the offer of the hub `from` and returns what this member keeps of
/// it. An obfuscated hub or one reached over VLESS is refused: the lite
/// member speaks plain WireGuard only.
pub fn hub_from_offer(from: &DeviceId, o: &TunnelOffer) -> Result<Hub> {
    if o.obfuscation.is_some() || o.vless.is_some() {
        return Err(Error::msg(
            "the group's hub hides its tunnel (AmneziaWG or VLESS), which the lite member cannot speak yet; it syncs at home only",
        ));
    }
    if o.hub_key.len() != 32 || o.psk.len() != 32 || !o.next_key.is_empty() && o.next_key.len() != 32 {
        return Err(Error::msg("the hub's offer does not have 32-byte keys"));
    }
    // As in Go: a key of zeros is no key.
    if o.hub_key.iter().all(|&b| b == 0) || o.psk.iter().all(|&b| b == 0) {
        return Err(Error::msg("the hub's offer has a key of zeros"));
    }
    if o.endpoints.len() > MAX_ENDPOINTS {
        return Err(Error::msg(format!("the hub's offer has more than {MAX_ENDPOINTS} addresses")));
    }
    let endpoints = o
        .endpoints
        .iter()
        .map(|e| match e.parse::<SocketAddr>() {
            Ok(a) if a.port() != 0 => Ok(a),
            _ => Err(Error::msg(format!("the hub's offer has a bad address {e:?}"))),
        })
        .collect::<Result<Vec<_>>>()?;
    addr(from.as_str()).ok_or_else(|| Error::msg(format!("{from} is not a device ID")))?;
    Ok(Hub {
        device: from.to_string(),
        key: o.hub_key.clone(),
        psk: o.psk.clone(),
        endpoints,
        next: o.next_key.clone(),
    })
}

/// The tunnel address of a device: fd00:cbb::/32 followed by the first 96
/// bits of its ID (32 lowercase hex characters).
pub fn addr(id: &str) -> Option<Ipv6Addr> {
    if !crate::certs::is_id(id) {
        return None;
    }
    let mut a = [0u8; 16];
    a[0..4].copy_from_slice(&[0xfd, 0x00, 0x0c, 0xbb]);
    for (i, b) in a[4..].iter_mut().enumerate() {
        *b = u8::from_str_radix(&id[2 * i..2 * i + 2], 16).ok()?;
    }
    Some(Ipv6Addr::from(a))
}

/// The running link to the hub. Dropping it stops it.
pub struct Link {
    port: u16,
    stop: Arc<AtomicBool>,
    answered: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl Link {
    /// Starts the link of this device (me) to the hub.
    pub fn start(st: &State, hub: &Hub, me: &DeviceId, log: Arc<dyn Fn(&str) + Send + Sync>) -> Result<Link> {
        if hub.endpoints.is_empty() {
            return Err(Error::msg("the group's hub has no address away from home yet"));
        }
        let own = addr(me.as_str()).ok_or_else(|| Error::msg(format!("{me} is not a device ID")))?;
        let peer = addr(&hub.device).ok_or_else(|| Error::msg(format!("{} is not a device ID", hub.device)))?;
        let ln = TcpListener::bind("127.0.0.1:0").context("cannot open the tunnel's local port")?;
        ln.set_nonblocking(true).context("cannot open the tunnel's local port")?;
        let port = ln.local_addr().context("cannot open the tunnel's local port")?.port();

        let secret = st.secret();
        let public = PublicKey::from(&secret);
        let mut hub_key = [0u8; 32];
        hub_key.copy_from_slice(&hub.key);
        let mut psk = [0u8; 32];
        psk.copy_from_slice(&hub.psk);
        let limiter = Arc::new(RateLimiter::new(&public, HANDSHAKE_RATE_LIMIT));
        let tunn = Tunn::new(
            secret,
            PublicKey::from(hub_key),
            Some(psk),
            Some(KEEPALIVE),
            IndexTable::from_os_rng(),
            limiter.clone(),
        );
        let stop = Arc::new(AtomicBool::new(false));
        let answered = Arc::new(AtomicBool::new(false));
        let mut pump = Pump::new(tunn, limiter, hub.endpoints.clone(), ln, own, peer, answered.clone(), log)?;
        let thread = {
            let stop = stop.clone();
            std::thread::spawn(move || pump.run(&stop))
        };
        Ok(Link { port, stop, answered, thread: Some(thread) })
    }

    /// The local port that leads to the hub's member port.
    pub fn local(&self) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], self.port))
    }

    /// Reports whether the hub has answered through the tunnel.
    pub fn answered(&self) -> bool {
        self.answered.load(Ordering::SeqCst)
    }
}

impl Drop for Link {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

/// The IP packets between smoltcp and the tunnel.
#[derive(Default)]
struct Queues {
    rx: VecDeque<Vec<u8>>,
    tx: VecDeque<Vec<u8>>,
}

struct Rx(Vec<u8>);
struct Tx<'a>(&'a mut VecDeque<Vec<u8>>);

impl RxToken for Rx {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(&self.0)
    }
}

impl TxToken for Tx<'_> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let mut buf = vec![0u8; len];
        let r = f(&mut buf);
        self.0.push_back(buf);
        r
    }
}

impl Device for Queues {
    type RxToken<'a> = Rx;
    type TxToken<'a> = Tx<'a>;

    fn receive(&mut self, _: smoltcp::time::Instant) -> Option<(Rx, Tx<'_>)> {
        let p = self.rx.pop_front()?;
        Some((Rx(p), Tx(&mut self.tx)))
    }

    fn transmit(&mut self, _: smoltcp::time::Instant) -> Option<Tx<'_>> {
        Some(Tx(&mut self.tx))
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut c = DeviceCapabilities::default();
        c.medium = Medium::Ip;
        c.max_transmission_unit = MTU;
        c
    }
}

/// One connection from the loopback port to the hub's member port.
struct Bridge {
    local: TcpStream,
    handle: SocketHandle,
    /// Read from the local side, not yet taken by smoltcp.
    up: Vec<u8>,
    /// From the hub, not yet written to the local side.
    down: Vec<u8>,
    local_eof: bool,
    done: bool,
}

struct Pump {
    tunn: Tunn,
    limiter: Arc<RateLimiter>,
    endpoints: Vec<SocketAddr>,
    current: usize,
    since: Instant,
    udp: UdpSocket,
    ln: TcpListener,
    iface: Interface,
    dev: Queues,
    sockets: SocketSet<'static>,
    bridges: Vec<Bridge>,
    peer: Ipv6Addr,
    next_port: u16,
    answered: Arc<AtomicBool>,
    log: Arc<dyn Fn(&str) + Send + Sync>,
    said: bool,
}

/// A UDP socket of the endpoint's family.
fn udp_for(ep: &SocketAddr) -> Result<UdpSocket> {
    let any: SocketAddr = if ep.is_ipv4() { "0.0.0.0:0".parse().unwrap() } else { "[::]:0".parse().unwrap() };
    let s = UdpSocket::bind(any).context("cannot open the tunnel's UDP socket")?;
    s.set_nonblocking(true).context("cannot open the tunnel's UDP socket")?;
    Ok(s)
}

fn now() -> smoltcp::time::Instant {
    smoltcp::time::Instant::now()
}

impl Pump {
    #[allow(clippy::too_many_arguments)]
    fn new(
        tunn: Tunn,
        limiter: Arc<RateLimiter>,
        endpoints: Vec<SocketAddr>,
        ln: TcpListener,
        own: Ipv6Addr,
        peer: Ipv6Addr,
        answered: Arc<AtomicBool>,
        log: Arc<dyn Fn(&str) + Send + Sync>,
    ) -> Result<Pump> {
        let udp = udp_for(&endpoints[0])?;
        let mut dev = Queues::default();
        let mut iface = Interface::new(Config::new(HardwareAddress::Ip), &mut dev, now());
        // The hub's address is in the same /32, so it is reached directly.
        iface.update_ip_addrs(|a| {
            let _ = a.push(IpCidr::new(IpAddress::Ipv6(own), 32));
        });
        Ok(Pump {
            tunn,
            limiter,
            endpoints,
            current: 0,
            since: Instant::now(),
            udp,
            ln,
            iface,
            dev,
            sockets: SocketSet::new(Vec::new()),
            bridges: Vec::new(),
            peer,
            next_port: 49152,
            answered,
            log,
            said: false,
        })
    }

    fn run(&mut self, stop: &AtomicBool) {
        // Start the handshake at once, so the first dial does not wait for it.
        if let Some(p) = self.tunn.format_handshake_initiation(false) {
            self.send(Packet::from(gotatun::packet::WgKind::from(p)).as_ref());
        }
        while !stop.load(Ordering::SeqCst) {
            let busy = self.step();
            if !busy {
                self.wait();
            }
        }
        for b in &self.bridges {
            let _ = b.local.shutdown(Shutdown::Both);
        }
    }

    /// Does what can be done now; reports whether anything moved.
    fn step(&mut self) -> bool {
        let mut busy = false;
        self.accept();
        busy |= self.receive();
        if let Ok(Some(p)) = self.tunn.update_timers() {
            self.send(Packet::from(p).as_ref());
        }
        self.next_endpoint();
        busy |= self.bridge();
        self.iface.poll(now(), &mut self.dev, &mut self.sockets);
        busy |= self.bridge();
        busy |= self.transmit();
        busy
    }

    fn send(&mut self, data: &[u8]) {
        let ep = self.endpoints[self.current];
        if let Err(e) = self.udp.send_to(data, ep)
            && !self.said
        {
            (self.log)(&format!("cbb: sending to the hub at {ep}: {e}"));
            self.said = true;
        }
    }

    /// Tries the next endpoint while the hub does not answer at this one.
    fn next_endpoint(&mut self) {
        if self.tunn.has_active_session() || self.endpoints.len() < 2 || self.since.elapsed() < ENDPOINT_WAIT {
            return;
        }
        self.current = (self.current + 1) % self.endpoints.len();
        self.since = Instant::now();
        let ep = self.endpoints[self.current];
        if self.endpoints[(self.current + self.endpoints.len() - 1) % self.endpoints.len()].is_ipv4() != ep.is_ipv4() {
            match udp_for(&ep) {
                Ok(s) => self.udp = s,
                Err(e) => (self.log)(&format!("cbb: {}", e.for_log())),
            }
        }
        if let Some(p) = self.tunn.format_handshake_initiation(true) {
            self.send(Packet::from(gotatun::packet::WgKind::from(p)).as_ref());
        }
    }

    fn accept(&mut self) {
        while let Ok((s, from)) = self.ln.accept() {
            // The port is on the loopback, where every local user may
            // connect: only this member's own user is let through, and only
            // so many at once.
            if self.bridges.len() >= MAX_BRIDGES || !own_user(&tcp_table(), from, self.ln.local_addr().ok()) {
                let _ = s.shutdown(Shutdown::Both);
                continue;
            }
            if s.set_nonblocking(true).is_err() {
                continue;
            }
            let _ = s.set_nodelay(true);
            let mut sock = tcp::Socket::new(
                tcp::SocketBuffer::new(vec![0; TCP_BUFFER]),
                tcp::SocketBuffer::new(vec![0; TCP_BUFFER]),
            );
            sock.set_nagle_enabled(false);
            sock.set_timeout(Some(smoltcp::time::Duration::from_secs(30)));
            let port = self.next_port;
            self.next_port = if self.next_port == u16::MAX { 49152 } else { self.next_port + 1 };
            if sock.connect(self.iface.context(), (IpAddress::Ipv6(self.peer), MEMBER_PORT), port).is_err() {
                let _ = s.shutdown(Shutdown::Both);
                continue;
            }
            let handle = self.sockets.add(sock);
            self.bridges.push(Bridge {
                local: s,
                handle,
                up: Vec::new(),
                down: Vec::new(),
                local_eof: false,
                done: false,
            });
        }
    }

    /// Takes the datagrams from the hub through WireGuard.
    fn receive(&mut self) -> bool {
        let mut busy = false;
        let mut buf = [0u8; 2048];
        loop {
            let (n, from) = match self.udp.recv_from(&mut buf) {
                Ok(r) => r,
                Err(_) => return busy,
            };
            busy = true;
            let packet = Packet::from_bytes(BytesMut::from(&buf[..n]));
            let wg = match self.limiter.verify_packet(from, packet) {
                Ok(wg) => wg,
                Err(TunnResult::WriteToNetwork(p)) => {
                    self.send(Packet::from(p).as_ref());
                    continue;
                }
                Err(_) => continue,
            };
            match self.tunn.handle_incoming_packet(wg) {
                TunnResult::WriteToNetwork(p) => {
                    self.answered.store(true, Ordering::SeqCst);
                    self.send(Packet::from(p).as_ref());
                    // A new session sends what waited for it.
                    let mut mtu = gotatun::tun::MtuWatcher::new(MTU as u16);
                    let queued: Vec<_> = self.tunn.get_queued_packets(&mut mtu).collect();
                    for p in queued {
                        self.send(Packet::from(p).as_ref());
                    }
                }
                TunnResult::WriteToTunnel(p) => {
                    self.answered.store(true, Ordering::SeqCst);
                    let ip: &[u8] = p.as_ref();
                    // Only what comes from the hub's own address, as
                    // WireGuard's allowed IPs would have it.
                    if ip.len() >= 40 && ip[0] >> 4 == 6 && ip[8..24] == self.peer.octets() {
                        self.dev.rx.push_back(ip.to_vec());
                    }
                }
                TunnResult::Done | TunnResult::Err(_) => {}
            }
        }
    }

    /// Sends what smoltcp wrote through WireGuard.
    fn transmit(&mut self) -> bool {
        let mut busy = false;
        while let Some(ip) = self.dev.tx.pop_front() {
            busy = true;
            if let Some(p) = self.tunn.handle_outgoing_packet(Packet::from_bytes(BytesMut::from(&ip[..])), None) {
                self.send(Packet::from(p).as_ref());
            }
        }
        busy
    }

    /// Moves bytes between the local connections and smoltcp's sockets.
    fn bridge(&mut self) -> bool {
        let mut busy = false;
        let mut buf = [0u8; 16 << 10];
        for b in &mut self.bridges {
            let s = self.sockets.get_mut::<tcp::Socket>(b.handle);
            // Local to the hub.
            if !b.local_eof && b.up.len() < TCP_BUFFER {
                match b.local.read(&mut buf) {
                    Ok(0) => b.local_eof = true,
                    Ok(n) => {
                        b.up.extend_from_slice(&buf[..n]);
                        busy = true;
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                    Err(_) => b.done = true,
                }
            }
            if !b.up.is_empty()
                && s.can_send()
                && let Ok(n) = s.send_slice(&b.up)
            {
                b.up.drain(..n);
                busy |= n > 0;
            }
            if b.local_eof && b.up.is_empty() && s.may_send() {
                s.close();
            }
            // The hub to local.
            if b.down.len() < TCP_BUFFER
                && s.can_recv()
                && let Ok(n) = s.recv_slice(&mut buf)
            {
                b.down.extend_from_slice(&buf[..n]);
                busy |= n > 0;
            }
            if !b.down.is_empty() {
                match b.local.write(&b.down) {
                    Ok(n) => {
                        b.down.drain(..n);
                        busy |= n > 0;
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                    Err(_) => b.done = true,
                }
            }
            if b.down.is_empty() && !s.may_recv() && !s.can_recv() && s.state() != tcp::State::SynSent {
                let _ = b.local.shutdown(Shutdown::Write);
                if !s.is_open() || b.local_eof {
                    b.done = true;
                }
            }
            if b.done {
                s.abort();
                let _ = b.local.shutdown(Shutdown::Both);
            }
        }
        let sockets = &mut self.sockets;
        self.bridges.retain(|b| {
            if b.done {
                sockets.remove(b.handle);
            }
            !b.done
        });
        busy
    }

    /// Waits for a datagram, a local connection or byte, or smoltcp's next
    /// timer, at most MAX_POLL.
    fn wait(&mut self) {
        let delay = self.iface.poll_delay(now(), &self.sockets).map(|d| Duration::from_micros(d.total_micros()));
        let timeout = delay.map_or(MAX_POLL, |d| d.min(MAX_POLL));
        let mut fds = vec![
            libc::pollfd { fd: self.udp.as_raw_fd(), events: libc::POLLIN, revents: 0 },
            libc::pollfd { fd: self.ln.as_raw_fd(), events: libc::POLLIN, revents: 0 },
        ];
        for b in &self.bridges {
            let mut events = 0;
            if !b.local_eof && b.up.len() < TCP_BUFFER {
                events |= libc::POLLIN;
            }
            if !b.down.is_empty() {
                events |= libc::POLLOUT;
            }
            fds.push(libc::pollfd { fd: b.local.as_raw_fd(), events, revents: 0 });
        }
        // SAFETY: fds is a valid array of pollfd of the given length.
        unsafe {
            libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, timeout.as_millis() as libc::c_int);
        }
    }
}

/// The kernel's table of IPv4 TCP sockets, or "" where there is none.
fn tcp_table() -> String {
    std::fs::read_to_string("/proc/net/tcp").unwrap_or_default()
}

/// Reports whether the socket at from, connected to the listener at to,
/// belongs to this process's user by table, the text of /proc/net/tcp.
/// Without the table (a system without /proc) it cannot tell and lets the
/// connection through.
fn own_user(table: &str, from: SocketAddr, to: Option<SocketAddr>) -> bool {
    let (SocketAddr::V4(from), Some(SocketAddr::V4(to))) = (from, to) else { return true };
    if table.is_empty() {
        return true;
    }
    // Addresses are written as the kernel holds them: the IPv4 address in
    // the host's byte order, the port in network order.
    let hex = |a: std::net::SocketAddrV4| format!("{:08X}:{:04X}", u32::from_ne_bytes(a.ip().octets()), a.port());
    let (local, remote) = (hex(from), hex(to));
    // SAFETY: geteuid has no preconditions.
    let me = unsafe { libc::geteuid() };
    table.lines().skip(1).any(|l| {
        let f: Vec<&str> = l.split_whitespace().collect();
        f.len() > 7 && f[1] == local && f[2] == remote && f[7].parse::<u32>().ok() == Some(me)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_port_takes_its_own_user() {
        let ln = TcpListener::bind("127.0.0.1:0").unwrap();
        let c = TcpStream::connect(ln.local_addr().unwrap()).unwrap();
        let (_s, from) = ln.accept().unwrap();
        assert_eq!(from, c.local_addr().unwrap());
        let to = ln.local_addr().ok();
        let table = tcp_table();
        if !table.is_empty() {
            assert!(own_user(&table, from, to), "this process's own connection");
        }
        // The same connection under another user's uid, and an unknown one.
        let hex = |a: SocketAddr| match a {
            SocketAddr::V4(a) => format!("{:08X}:{:04X}", u32::from_ne_bytes(a.ip().octets()), a.port()),
            _ => unreachable!(),
        };
        // SAFETY: geteuid has no preconditions.
        let other = unsafe { libc::geteuid() } + 1;
        let line = |uid: u32| {
            format!(
                "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n   0: {} {} 01 00000000:00000000 00:00000000 00000000 {uid:5} 0 1 1\n",
                hex(from),
                hex(to.unwrap())
            )
        };
        assert!(!own_user(&line(other), from, to));
        assert!(own_user(&line(other - 1), from, to));
        assert!(!own_user("header\n", from, to), "a connection the table does not show");
        assert!(own_user("", from, to), "no table");
    }

    #[test]
    fn addresses() {
        assert_eq!(
            addr("0123456789abcdef0123456789abcdef").unwrap().to_string(),
            "fd00:cbb:123:4567:89ab:cdef:123:4567"
        );
        assert!(addr("0123456789ABCDEF0123456789abcdef").is_none());
        assert!(addr("0123").is_none());
    }

    #[test]
    fn offers() {
        let id = DeviceId::parse("0123456789abcdef0123456789abcdef").unwrap();
        // As Go encodes node.TunnelOffer.
        let go = r#"{"hub_key":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=","psk":"AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=","endpoints":["192.0.2.1:8764","[2001:db8::1]:51820"]}"#;
        let o: TunnelOffer = serde_json::from_str(go).unwrap();
        let hub = hub_from_offer(&id, &o).unwrap();
        assert_eq!(hub.key, vec![1; 32]);
        assert_eq!(hub.psk, vec![2; 32]);
        assert_eq!(hub.endpoints, vec!["192.0.2.1:8764".parse().unwrap(), "[2001:db8::1]:51820".parse().unwrap()]);
        let hidden = r#"{"hub_key":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=","psk":"AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=","obfuscation":{"jc":4}}"#;
        let o: TunnelOffer = serde_json::from_str(hidden).unwrap();
        assert!(hub_from_offer(&id, &o).unwrap_err().message().contains("AmneziaWG"));
        let short = r#"{"hub_key":"AQE=","psk":"AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI="}"#;
        assert!(hub_from_offer(&id, &serde_json::from_str(short).unwrap()).is_err());

        // The key for the next period is tried right after the key now.
        let next = r#"{"hub_key":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=","psk":"AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=","endpoints":["192.0.2.1:8764"],"next_key":"AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM="}"#;
        let hub = hub_from_offer(&id, &serde_json::from_str(next).unwrap()).unwrap();
        assert_eq!(hub.next, vec![3; 32]);
        let mut st = State::new("abc").unwrap();
        st.hubs.push(hub);
        let tried = st.hubs_to_try(&[id.to_string()]);
        assert_eq!(tried.iter().map(|h| h.key[0]).collect::<Vec<_>>(), vec![1, 3]);
        assert!(tried[1].next.is_empty());
        let bad = r#"{"hub_key":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=","psk":"AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=","next_key":"AQE="}"#;
        assert!(hub_from_offer(&id, &serde_json::from_str(bad).unwrap()).is_err());
        // Keys of zeros and a port 0, which Go refuses too.
        let zero = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
        for bad in [
            format!(r#"{{"hub_key":"{zero}","psk":"AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI="}}"#),
            format!(r#"{{"hub_key":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=","psk":"{zero}"}}"#),
            r#"{"hub_key":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=","psk":"AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=","endpoints":["192.0.2.1:0"]}"#.to_string(),
        ] {
            assert!(hub_from_offer(&id, &serde_json::from_str(&bad).unwrap()).is_err(), "{bad}");
        }
    }

    #[test]
    fn state_keeps_its_key() {
        let dir = std::env::temp_dir().join(format!("cbb-tunnel-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let st = State::new("abc").unwrap();
        st.save(&dir).unwrap();
        let back = State::load(&dir).unwrap().unwrap();
        assert_eq!(back.public_key(), st.public_key());
        assert_eq!(back.group, "abc");
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(dir.join(FILE_NAME)).unwrap().permissions().mode() & 0o777, 0o600);
        State::remove(&dir).unwrap();
        assert!(State::load(&dir).unwrap().is_none());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The internet checksum over the IPv6 pseudo-header and the segment.
    fn checksum6(src: &Ipv6Addr, dst: &Ipv6Addr, proto: u8, seg: &[u8]) -> u16 {
        let mut sum: u32 = 0;
        let mut add = |b: &[u8]| {
            for c in b.chunks(2) {
                sum += u32::from(u16::from_be_bytes([c[0], *c.get(1).unwrap_or(&0)]));
            }
        };
        add(&src.octets());
        add(&dst.octets());
        add(&(seg.len() as u32).to_be_bytes());
        add(&[0, 0, 0, proto]);
        add(seg);
        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        !(sum as u16)
    }

    /// An IPv6 packet from src to dst carrying seg of protocol proto, its
    /// checksum filled in at sum_at.
    fn ip6(src: Ipv6Addr, dst: Ipv6Addr, proto: u8, mut seg: Vec<u8>, sum_at: usize) -> Vec<u8> {
        let c = checksum6(&src, &dst, proto, &seg);
        seg[sum_at..sum_at + 2].copy_from_slice(&c.to_be_bytes());
        let mut p = vec![0x60, 0, 0, 0];
        p.extend_from_slice(&(seg.len() as u16).to_be_bytes());
        p.extend_from_slice(&[proto, 64]);
        p.extend_from_slice(&src.octets());
        p.extend_from_slice(&dst.octets());
        p.extend_from_slice(&seg);
        p
    }

    fn syn(src: Ipv6Addr, dst: Ipv6Addr, port: u16) -> Vec<u8> {
        let mut t = vec![0u8; 20];
        t[0..2].copy_from_slice(&40000u16.to_be_bytes());
        t[2..4].copy_from_slice(&port.to_be_bytes());
        t[4..8].copy_from_slice(&1u32.to_be_bytes());
        t[12] = 5 << 4;
        t[13] = 0x02; // SYN
        t[14..16].copy_from_slice(&65535u16.to_be_bytes());
        ip6(src, dst, 6, t, 16)
    }

    fn udp(src: Ipv6Addr, dst: Ipv6Addr, port: u16) -> Vec<u8> {
        let mut u = vec![0u8; 8];
        u[0..2].copy_from_slice(&40000u16.to_be_bytes());
        u[2..4].copy_from_slice(&port.to_be_bytes());
        u.extend_from_slice(b"a packet");
        let n = u.len() as u16;
        u[4..6].copy_from_slice(&n.to_be_bytes());
        ip6(src, dst, 17, u, 6)
    }

    /// The hub, or anyone holding its key, sends TCP and UDP through the
    /// tunnel to the lite member's address on any port, to other addresses
    /// and as IPv4: nothing is accepted, nothing answered but a reset, and
    /// nothing reaches the computer the member runs on. The member's end
    /// only dials the hub's member port and forwards nothing.
    #[test]
    fn link_reaches_nothing_from_the_tunnel() {
        // The computer's own services.
        let host_tcp = TcpListener::bind("127.0.0.1:0").unwrap();
        host_tcp.set_nonblocking(true).unwrap();
        let host_udp = UdpSocket::bind("127.0.0.1:0").unwrap();
        host_udp.set_nonblocking(true).unwrap();
        let (tcp_port, udp_port) = (host_tcp.local_addr().unwrap().port(), host_udp.local_addr().unwrap().port());

        let st = State::new("g").unwrap();
        let me = DeviceId::parse("0123456789abcdef0123456789abcdef").unwrap();
        let hub_dev = "fedcba9876543210fedcba9876543210";
        let mut raw = [0u8; 32];
        raw.copy_from_slice(&random_key().unwrap());
        let hub_secret = StaticSecret::from(raw);
        let hub_public = PublicKey::from(&hub_secret);
        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        sock.set_read_timeout(Some(Duration::from_millis(200))).unwrap();
        let hub = Hub {
            device: hub_dev.into(),
            key: hub_public.as_bytes().to_vec(),
            psk: st.psk.clone(),
            endpoints: vec![sock.local_addr().unwrap()],
            next: vec![],
        };
        let link = Link::start(&st, &hub, &me, Arc::new(|_: &str| {})).unwrap();
        let (own, peer) = (addr(me.as_str()).unwrap(), addr(hub_dev).unwrap());

        let mut psk = [0u8; 32];
        psk.copy_from_slice(&st.psk);
        let limiter = Arc::new(RateLimiter::new(&hub_public, HANDSHAKE_RATE_LIMIT));
        let mut tunn = Tunn::new(
            hub_secret,
            PublicKey::from(&st.secret()),
            Some(psk),
            None,
            IndexTable::from_os_rng(),
            limiter.clone(),
        );
        let mut lite: Option<SocketAddr> = None;
        // Takes what the member sends: answers the handshake and returns
        // the IP packets that came through the tunnel.
        let take = |tunn: &mut Tunn, lite: &mut Option<SocketAddr>, until: Instant| -> Vec<Vec<u8>> {
            let mut got = Vec::new();
            let mut buf = [0u8; 2048];
            while Instant::now() < until {
                let Ok((n, from)) = sock.recv_from(&mut buf) else { continue };
                *lite = Some(from);
                let Ok(wg) = limiter.verify_packet(from, Packet::from_bytes(BytesMut::from(&buf[..n]))) else {
                    continue;
                };
                match tunn.handle_incoming_packet(wg) {
                    TunnResult::WriteToNetwork(p) => {
                        let _ = sock.send_to(Packet::from(p).as_ref(), from);
                    }
                    TunnResult::WriteToTunnel(p) => got.push(AsRef::<[u8]>::as_ref(&p).to_vec()),
                    _ => {}
                }
            }
            got
        };
        // The handshake, and the member's first packet, which makes the
        // session the hub's to send in.
        let deadline = Instant::now() + Duration::from_secs(10);
        while !(tunn.has_active_session() && link.answered()) && Instant::now() < deadline {
            take(&mut tunn, &mut lite, Instant::now() + Duration::from_millis(300));
        }
        assert!(tunn.has_active_session(), "no session with the member");
        let to = lite.unwrap();

        let v4 = {
            // An IPv4 header to the computer's own TCP port.
            let mut p = vec![0x45, 0, 0, 40, 0, 0, 0, 0, 64, 6, 0, 0, 10, 0, 0, 1, 127, 0, 0, 1];
            p.extend_from_slice(&[0x9c, 0x40]);
            p.extend_from_slice(&tcp_port.to_be_bytes());
            p.extend_from_slice(&[0, 0, 0, 1, 0, 0, 0, 0, 0x50, 0x02, 0xff, 0xff, 0, 0, 0, 0]);
            p
        };
        let packets = vec![
            syn(peer, own, MEMBER_PORT),
            syn(peer, own, 22),
            syn(peer, own, tcp_port),
            syn(peer, Ipv6Addr::LOCALHOST, tcp_port),
            syn(peer, "2606:4700:4700::1111".parse().unwrap(), 443),
            udp(peer, own, udp_port),
            udp(peer, Ipv6Addr::LOCALHOST, udp_port),
            v4,
        ];
        for p in &packets {
            if let Some(w) = tunn.handle_outgoing_packet(Packet::from_bytes(BytesMut::from(&p[..])), None) {
                sock.send_to(Packet::from(w).as_ref(), to).unwrap();
            }
        }
        let mut resets = 0;
        for ip in take(&mut tunn, &mut lite, Instant::now() + Duration::from_secs(3)) {
            if ip.len() >= 54 && ip[6] == 6 {
                resets += usize::from(ip[40 + 13] & 0x04 != 0);
                // A reset may come back, never a SYN-ACK.
                assert_ne!(ip[40 + 13] & 0x12, 0x12, "the member accepted a stream through the tunnel");
            } else if ip.len() > 40 {
                assert_ne!(ip[6], 17, "the member answered a UDP packet through the tunnel");
            }
        }
        // The packets did arrive: the member's own ports answered with resets.
        assert!(resets > 0, "nothing came back through the tunnel");
        assert!(host_tcp.accept().is_err(), "a stream from the tunnel reached the computer");
        assert!(host_udp.recv_from(&mut [0u8; 64]).is_err(), "a packet from the tunnel reached the computer");
        drop(link);
    }
}
