// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! A device as the group's hub (docs/protocol.md, section 11; docs/design.md,
//! "The phone as the hub"): the end of every client's WireGuard tunnel, on
//! GotaTun with AmneziaWG when the group hides its tunnel, with smoltcp's
//! TCP behind it. A connection a client opens through its tunnel to the
//! hub's member port goes to a loopback port the caller names for the
//! client's tunnel address: the app's member listener, or a guest's pairing
//! window. The phones' apps run it through ffi/ in place of the Go hub.

use std::collections::{HashMap, HashSet};
use std::net::{Ipv6Addr, Shutdown, SocketAddr, TcpStream, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use bytes::BytesMut;
use gotatun::noise::handshake::parse_handshake_anon;
use gotatun::noise::index_table::IndexTable;
use gotatun::noise::rate_limiter::RateLimiter;
use gotatun::noise::{Tunn, TunnResult};
use gotatun::packet::{Packet, WgKind};
use gotatun::x25519::{PublicKey, StaticSecret};
use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::socket::tcp;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr};

use crate::error::{Context, Error, Result};
use crate::sys;
use crate::tunnel::{
    Bridge, HANDSHAKE_RATE_LIMIT, MAX_BRIDGES, MAX_POLL, MEMBER_PORT, MTU, Queues, TCP_BUFFER, move_bytes, now,
};

/// The listening sockets kept open on the member port, so that clients
/// connecting at once each find one.
const LISTENERS: usize = 4;
/// How long a connection from a client to the app's loopback port may take.
const DIAL_TIMEOUT: Duration = Duration::from_secs(5);
/// The prefix of the guests' tunnel addresses (docs/protocol.md, section 12).
const GUEST_PREFIX: [u8; 4] = [0xfd, 0x00, 0x0c, 0xbc];

/// Handshake initiations a second, from all sources together, past which
/// the hub is under load, as WireGuard has it: every initiation must then
/// carry a cookie, which only a source that receives at its address can
/// have, before the hub spends a Diffie-Hellman on it.
const UNDER_LOAD: u32 = 128;
/// The initiations a second the hub spends a Diffie-Hellman on: under load,
/// for one IPv4 /24 or IPv6 /64, and in all. One takes about 50
/// microseconds of the pump's thread, which carries every client's data.
const DH_PER_NETWORK: u32 = 32;
const DH_ALL: u32 = 2048;

/// One client of the hub: its WireGuard public key, the preshared key the
/// hub's offer gave it, its one tunnel address, and for a guest when it goes.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Peer {
    pub key: [u8; 32],
    pub psk: [u8; 32],
    pub addr: Ipv6Addr,
    pub until: Option<Instant>,
}

impl Peer {
    /// Whether two clients are one tunnel: the same keys and address, when
    /// they go aside.
    fn same_tunnel(&self, o: &Peer) -> bool {
        self.key == o.key && self.psk == o.psk && self.addr == o.addr
    }
}

/// The tunnel address each connection the hub made to a loopback port came
/// from, by the port it came from there, while it lasts.
type Dialed = Arc<Mutex<HashMap<u16, Ipv6Addr>>>;

/// The loopback port a connection through the tunnel from a client's address
/// goes to, or None to close it.
pub type Target = Arc<dyn Fn(Ipv6Addr) -> Option<u16> + Send + Sync>;

/// The tunnel address of a guest with the public key `key`: the guest prefix
/// followed by the first 96 bits of its SHA-256.
pub fn guest_addr(key: &[u8; 32]) -> Ipv6Addr {
    let sum = crate::certs::sha256(key);
    let mut a = [0u8; 16];
    let (prefix, rest) = a.split_at_mut(4);
    prefix.copy_from_slice(&GUEST_PREFIX);
    rest.copy_from_slice(&sum[..12]);
    Ipv6Addr::from(a)
}

/// Reports whether a is a guest's tunnel address.
pub fn is_guest(a: &Ipv6Addr) -> bool {
    a.octets()[..4] == GUEST_PREFIX
}

/// The running hub. Dropping it stops it and every connection through it.
pub struct Hub {
    port: u16,
    out: Arc<UdpSocket>,
    dialed: Dialed,
    peers: Arc<Mutex<Option<Vec<Peer>>>>,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl Hub {
    /// Starts the hub of the device `device` with its WireGuard private key,
    /// the group's AmneziaWG settings as the offers carry them (None for
    /// plain WireGuard), its clients, and where connections go. It listens
    /// for WireGuard on `listen`, port 0 for any.
    pub fn start(
        key: &[u8; 32],
        device: &str,
        obfuscation: Option<&serde_json::Value>,
        peers: Vec<Peer>,
        listen: SocketAddr,
        target: Target,
        log: Arc<dyn Fn(&str) + Send + Sync>,
    ) -> Result<Hub> {
        let own = crate::tunnel::addr(device).ok_or_else(|| Error::msg(format!("{device} is not a device ID")))?;
        Hub::start_at(key, own, obfuscation, peers, listen, target, log)
    }

    /// Starts the hub as start does, at the tunnel address own in place of
    /// a device's: the blind relay's.
    pub fn start_at(
        key: &[u8; 32],
        own: Ipv6Addr,
        obfuscation: Option<&serde_json::Value>,
        peers: Vec<Peer>,
        listen: SocketAddr,
        target: Target,
        log: Arc<dyn Fn(&str) + Send + Sync>,
    ) -> Result<Hub> {
        check_peers(&peers, own)?;
        let obf = obfuscation.map(crate::awg::Obfuscation::from_offer).transpose()?;
        let udp = UdpSocket::bind(listen).context("cannot open the hub's UDP port")?;
        udp.set_nonblocking(true).context("cannot open the hub's UDP port")?;
        let port = udp.local_addr().context("cannot open the hub's UDP port")?.port();
        let out = Arc::new(udp.try_clone().context("cannot open the hub's UDP port")?);
        let secret = StaticSecret::from(*key);
        let public = PublicKey::from(&secret);
        let listen_awg = obf.clone().map(|o| crate::awg::Awg::new(o, public.as_bytes(), public.as_bytes()));
        let mut dev = Queues::default();
        let mut iface = Interface::new(Config::new(HardwareAddress::Ip), &mut dev, now());
        iface.update_ip_addrs(|a| {
            let _ = a.push(IpCidr::new(IpAddress::Ipv6(own), 128));
        });
        // The clients and the guests are behind the tunnel, each a peer.
        let _ = iface.routes_mut().add_default_ipv6_route(own);
        let shared = Arc::new(Mutex::new(Some(peers)));
        let stop = Arc::new(AtomicBool::new(false));
        let dialed: Dialed = Arc::default();
        let mut pump = Pump {
            secret,
            public,
            limiter: Arc::new(RateLimiter::new(&public, HANDSHAKE_RATE_LIMIT)),
            strict: RateLimiter::new(&public, 0),
            second: Second::default(),
            index: IndexTable::from_os_rng(),
            obf,
            listen_awg,
            udp,
            own,
            peers: HashMap::new(),
            by_index: HashMap::new(),
            wanted: shared.clone(),
            iface,
            dev,
            sockets: SocketSet::new(Vec::new()),
            listening: Vec::new(),
            bridges: Vec::new(),
            target,
            dialed: dialed.clone(),
            log,
        };
        let thread = {
            let stop = stop.clone();
            std::thread::spawn(move || pump.run(&stop))
        };
        Ok(Hub { port, out, dialed, peers: shared, stop, thread: Some(thread) })
    }

    /// The client's tunnel address a connection to a loopback port came
    /// from, by the port it came from there: the caller checks that the
    /// device of the connection is the one of that address.
    pub fn tunnel_addr(&self, from_port: u16) -> Option<Ipv6Addr> {
        self.dialed.lock().ok()?.get(&from_port).copied()
    }

    /// The hub's WireGuard UDP port.
    pub fn udp_port(&self) -> u16 {
        self.port
    }

    /// Sends datagrams from the hub's WireGuard port, as the hellos to the
    /// forwarder go; one that cannot go out now is dropped.
    pub fn sender(&self) -> crate::forward::SendFn {
        let out = self.out.clone();
        let v6 = out.local_addr().is_ok_and(|a| a.is_ipv6());
        Arc::new(move |to: SocketAddr, data: &[u8]| {
            // An IPv4 address, as the loopback port of the way over VLESS,
            // goes mapped from the hub's IPv6 socket, which not every system
            // takes as it is.
            let to = match to {
                SocketAddr::V4(a) if v6 => SocketAddr::new(a.ip().to_ipv6_mapped().into(), a.port()),
                a => a,
            };
            let _ = out.send_to(data, to);
        })
    }

    /// Replaces the hub's clients; a client left out is cut off at once.
    pub fn set_peers(&self, peers: Vec<Peer>, device: &str) -> Result<()> {
        let own = crate::tunnel::addr(device).ok_or_else(|| Error::msg(format!("{device} is not a device ID")))?;
        self.set_peers_at(peers, own)
    }

    /// Replaces the hub's clients as set_peers does, for a hub at the
    /// tunnel address own.
    pub fn set_peers_at(&self, peers: Vec<Peer>, own: Ipv6Addr) -> Result<()> {
        check_peers(&peers, own)?;
        *self.peers.lock().map_err(|_| Error::msg("the hub's clients are broken"))? = Some(peers);
        Ok(())
    }
}

impl Drop for Hub {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

/// Refuses clients that share a key or an address, or take the hub's.
fn check_peers(peers: &[Peer], own: Ipv6Addr) -> Result<()> {
    let mut keys = HashSet::new();
    let mut addrs = HashSet::new();
    for p in peers {
        if p.key == [0; 32] || p.psk == [0; 32] {
            return Err(Error::msg("a client of the hub has a key of zeros"));
        }
        if !keys.insert(p.key) || !addrs.insert(p.addr) || p.addr == own {
            return Err(Error::msg(format!("the hub's client at {} is there twice", p.addr)));
        }
    }
    Ok(())
}

/// One client's end of the tunnel.
struct PeerState {
    peer: Peer,
    tunn: Tunn,
    /// Where its datagrams last came from, where the hub's go.
    endpoint: Option<SocketAddr>,
    /// AmneziaWG to this client, for a group that hides its tunnel.
    awg: Option<crate::awg::Awg>,
}

/// A connection from a client through the tunnel, before it is joined to
/// the app's loopback port.
struct Listening {
    handle: SocketHandle,
}

/// What the hub counted of the handshake initiations in the current second.
struct Second {
    began: Instant,
    initiations: u32,
    dh: u32,
    by_network: HashMap<[u8; 9], u32>,
}

impl Default for Second {
    fn default() -> Second {
        Second { began: Instant::now(), initiations: 0, dh: 0, by_network: HashMap::new() }
    }
}

/// The IPv4 /24 or the IPv6 /64 of an address, as the key of its count.
fn network_of(ip: std::net::IpAddr) -> [u8; 9] {
    let mut k = [0u8; 9];
    let v4 = match ip {
        std::net::IpAddr::V4(a) => Some(a),
        std::net::IpAddr::V6(a) => a.to_ipv4_mapped(),
    };
    match (v4, ip) {
        (Some(a), _) => {
            k[0] = 4;
            k[1..4].copy_from_slice(&a.octets()[..3]);
        }
        (None, std::net::IpAddr::V6(a)) => {
            k[0] = 6;
            k[1..].copy_from_slice(&a.octets()[..8]);
        }
        (None, std::net::IpAddr::V4(_)) => {}
    }
    k
}

struct Pump {
    secret: StaticSecret,
    public: PublicKey,
    limiter: Arc<RateLimiter>,
    /// The limiter under load, which asks every initiation for a cookie.
    strict: RateLimiter,
    second: Second,
    index: IndexTable,
    obf: Option<crate::awg::Obfuscation>,
    /// AmneziaWG for what comes in, before the client is known.
    listen_awg: Option<crate::awg::Awg>,
    udp: UdpSocket,
    own: Ipv6Addr,
    peers: HashMap<[u8; 32], PeerState>,
    /// The hub's session indices, by the client they belong to.
    by_index: HashMap<u32, [u8; 32]>,
    /// The clients set_peers asked for, taken by the pump's thread.
    wanted: Arc<Mutex<Option<Vec<Peer>>>>,
    iface: Interface,
    dev: Queues,
    sockets: SocketSet<'static>,
    listening: Vec<Listening>,
    bridges: Vec<Bridge>,
    target: Target,
    dialed: Dialed,
    log: Arc<dyn Fn(&str) + Send + Sync>,
}

impl Pump {
    fn run(&mut self, stop: &AtomicBool) {
        while !stop.load(Ordering::SeqCst) {
            self.take_peers();
            self.expire();
            let busy = self.step();
            if !busy {
                self.wait();
            }
        }
        for b in &self.bridges {
            let _ = b.local.shutdown(Shutdown::Both);
        }
    }

    /// Takes the clients set_peers asked for: a new one gets its tunnel, a
    /// changed one a new tunnel, one left out goes with its connections.
    fn take_peers(&mut self) {
        let Some(want) = self.wanted.lock().ok().and_then(|mut w| w.take()) else { return };
        let keep: HashMap<[u8; 32], Peer> = want.into_iter().map(|p| (p.key, p)).collect();
        let before = self.peers.len();
        self.peers.retain(|k, s| keep.get(k).is_some_and(|p| p.same_tunnel(&s.peer)));
        let gone = before.saturating_sub(self.peers.len());
        for (k, p) in keep {
            if let Some(s) = self.peers.get_mut(&k) {
                s.peer.until = p.until;
                continue;
            }
            let tunn = Tunn::new(
                self.secret.clone(),
                PublicKey::from(p.key),
                Some(p.psk),
                None,
                self.index.clone(),
                self.limiter.clone(),
            );
            let awg = self.obf.clone().map(|o| crate::awg::Awg::new(o, &p.key, self.public.as_bytes()));
            self.peers.insert(k, PeerState { peer: p, tunn, endpoint: None, awg });
        }
        if gone > 0 {
            self.cut_off();
            (self.log)(&format!("cbb: the hub cut off {gone} client(s)"));
        }
    }

    /// Drops the guests whose time is up.
    fn expire(&mut self) {
        let now = Instant::now();
        let before = self.peers.len();
        self.peers.retain(|_, s| s.peer.until.is_none_or(|u| u > now));
        if self.peers.len() < before {
            self.cut_off();
        }
    }

    /// Ends the connections of the clients that are gone (a client cut off
    /// loses its connections at once), and forgets their session indices.
    fn cut_off(&mut self) {
        let peers = &self.peers;
        self.by_index.retain(|_, k| peers.contains_key(k));
        let addrs: HashSet<Ipv6Addr> = self.peers.values().map(|s| s.peer.addr).collect();
        for b in &mut self.bridges {
            let s = self.sockets.get::<tcp::Socket>(b.handle);
            if let Some(ep) = s.remote_endpoint()
                && let IpAddress::Ipv6(a) = ep.addr
                && !addrs.contains(&a)
            {
                b.done = true;
            }
        }
    }

    fn step(&mut self) -> bool {
        let mut busy = self.receive();
        self.timers();
        self.listen();
        busy |= self.bridge();
        self.iface.poll(now(), &mut self.dev, &mut self.sockets);
        busy |= self.accept();
        busy |= self.bridge();
        busy |= self.transmit();
        busy
    }

    /// Sends one message of a client's tunnel to the client.
    fn send(&mut self, key: &[u8; 32], wg: &[u8]) {
        // The hub's session index, which the client's answers name.
        if let (Some(&t), Some(idx)) = (wg.first(), wg.get(4..8))
            && (t == 1 || t == 2)
            && let Ok(i) = <[u8; 4]>::try_from(idx)
        {
            self.by_index.insert(u32::from_le_bytes(i), *key);
        }
        let Some(s) = self.peers.get_mut(key) else { return };
        let Some(ep) = s.endpoint else { return };
        let datagrams = match s.awg.as_mut() {
            Some(a) => a.outgoing(wg),
            None => vec![wg.to_vec()],
        };
        for d in datagrams {
            let _ = self.udp.send_to(&d, ep);
        }
    }

    /// Checks a handshake initiation from the network before the hub
    /// spends a Diffie-Hellman on it, as WireGuard's DoS protection has it:
    /// its mac1 under the hub's key; under load, from all sources together,
    /// a cookie (mac2), which the hub sends to a source that has none; and
    /// within what the hub spends a second, on a source's network under
    /// load and in all. None drops it.
    fn admit_initiation(&mut self, from: SocketAddr, wg: &[u8]) -> Option<Packet<gotatun::packet::WgHandshakeInit>> {
        if self.second.began.elapsed() >= Duration::from_secs(1) {
            self.second = Second::default();
            self.limiter.try_reset_count();
            self.strict.try_reset_count();
        }
        self.second.initiations = self.second.initiations.saturating_add(1);
        // AmneziaWG checked mac1 itself and has no cookie replies: only the
        // group's devices know the settings that reach the hub.
        let under = self.second.initiations > UNDER_LOAD && self.listen_awg.is_none();
        let limiter = if under { &self.strict } else { &*self.limiter };
        let init = match limiter.verify_packet(from, Packet::from_bytes(BytesMut::from(wg))) {
            Ok(WgKind::HandshakeInit(p)) => p,
            Err(TunnResult::WriteToNetwork(p)) => {
                // The cookie goes back to where the initiation came from,
                // whoever sent it: it is the size of the initiation's mac
                // and only a source that receives there can use it.
                if self.listen_awg.is_none() {
                    let _ = self.udp.send_to(Packet::from(p).as_ref(), from);
                }
                return None;
            }
            _ => return None,
        };
        if self.second.dh >= DH_ALL {
            return None;
        }
        if under {
            let n = self.second.by_network.entry(network_of(from.ip())).or_insert(0);
            if *n >= DH_PER_NETWORK {
                return None;
            }
            *n += 1;
        }
        self.second.dh += 1;
        Some(init)
    }

    /// The client of an initiation the hub let through, by the key in it.
    fn client_of_init(&self, init: &Packet<gotatun::packet::WgHandshakeInit>) -> Option<[u8; 32]> {
        let half = parse_handshake_anon(&self.secret, &self.public, init).ok()?;
        Some(half.peer_static_public).filter(|k| self.peers.contains_key(k))
    }

    /// Which client a message from the network other than an initiation is
    /// for: by the hub's session index.
    fn client_of(&self, wg: &[u8]) -> Option<[u8; 32]> {
        let idx = |at: usize| wg.get(at..at + 4).and_then(|b| <[u8; 4]>::try_from(b).ok()).map(u32::from_le_bytes);
        match wg.first()? {
            2 => self.by_index.get(&idx(8)?).copied(),
            3 | 4 => self.by_index.get(&idx(4)?).copied(),
            _ => None,
        }
    }

    /// Takes the datagrams from the clients through WireGuard.
    fn receive(&mut self) -> bool {
        let mut busy = false;
        let mut buf = BytesMut::zeroed(2048);
        loop {
            let (n, from) = match self.udp.recv_from(&mut buf) {
                Ok(r) => r,
                Err(_) => return busy,
            };
            busy = true;
            let Some(data) = buf.get(..n) else { continue };
            let wg = match self.listen_awg.as_mut() {
                Some(a) => match a.incoming(data) {
                    Some(wg) => wg,
                    None => continue,
                },
                None => data.to_vec(),
            };
            let (key, packet) = if wg.first() == Some(&1) {
                // An initiation is checked, and paid for, before the hub
                // spends a Diffie-Hellman on finding its client.
                let Some(init) = self.admit_initiation(from, &wg) else { continue };
                let Some(key) = self.client_of_init(&init) else { continue };
                (key, WgKind::HandshakeInit(init))
            } else {
                let Some(key) = self.client_of(&wg) else { continue };
                let packet = match self.limiter.verify_packet(from, Packet::from_bytes(BytesMut::from(&wg[..]))) {
                    Ok(p) => p,
                    Err(TunnResult::WriteToNetwork(p)) => {
                        // A cookie reply under load, to where the message came from.
                        if let Some(s) = self.peers.get_mut(&key) {
                            s.endpoint.get_or_insert(from);
                        }
                        self.send(&key, Packet::from(p).as_ref());
                        continue;
                    }
                    Err(_) => continue,
                };
                (key, packet)
            };
            let Some(s) = self.peers.get_mut(&key) else { continue };
            let result = s.tunn.handle_incoming_packet(packet);
            match result {
                TunnResult::WriteToNetwork(p) => {
                    s.endpoint = Some(from);
                    let mut out = vec![Packet::from(p).as_ref().to_vec()];
                    let mut mtu = gotatun::tun::MtuWatcher::new(MTU as u16);
                    out.extend(s.tunn.get_queued_packets(&mut mtu).map(|p| Packet::from(p).as_ref().to_vec()));
                    for p in out {
                        self.send(&key, &p);
                    }
                }
                TunnResult::WriteToTunnel(p) => {
                    s.endpoint = Some(from);
                    let ip: &[u8] = p.as_ref();
                    // Only what comes from the client's own address, as
                    // WireGuard's allowed IPs would have it, to the hub's.
                    if ip.len() >= 40
                        && ip.first().is_some_and(|b| b >> 4 == 6)
                        && ip.get(8..24) == Some(&s.peer.addr.octets()[..])
                        && ip.get(24..40) == Some(&self.own.octets()[..])
                    {
                        self.dev.rx.push_back(ip.to_vec());
                    }
                }
                TunnResult::Done | TunnResult::Err(_) => {}
            }
        }
    }

    fn timers(&mut self) {
        let mut out = Vec::new();
        for (k, s) in &mut self.peers {
            if let Ok(Some(p)) = s.tunn.update_timers() {
                out.push((*k, Packet::from(p).as_ref().to_vec()));
            }
        }
        for (k, p) in out {
            self.send(&k, &p);
        }
    }

    /// Sends what smoltcp wrote through the tunnel of the client it is for.
    fn transmit(&mut self) -> bool {
        let mut busy = false;
        while let Some(ip) = self.dev.tx.pop_front() {
            busy = true;
            let Some(dst) = ip.get(24..40).and_then(|d| <[u8; 16]>::try_from(d).ok()).map(Ipv6Addr::from) else {
                continue;
            };
            let Some((k, s)) = self.peers.iter_mut().find(|(_, s)| s.peer.addr == dst) else { continue };
            let k = *k;
            if let Some(p) = s.tunn.handle_outgoing_packet(Packet::from_bytes(BytesMut::from(&ip[..])), None) {
                let p = Packet::from(p).as_ref().to_vec();
                self.send(&k, &p);
            }
        }
        busy
    }

    /// Keeps LISTENERS sockets listening on the member port.
    fn listen(&mut self) {
        while self.listening.len() < LISTENERS && self.bridges.len() + self.listening.len() < MAX_BRIDGES {
            let mut sock = tcp::Socket::new(
                tcp::SocketBuffer::new(vec![0; TCP_BUFFER]),
                tcp::SocketBuffer::new(vec![0; TCP_BUFFER]),
            );
            sock.set_nagle_enabled(false);
            crate::tunnel::set_tcp_timeouts(&mut sock);
            if sock.listen((IpAddress::Ipv6(self.own), MEMBER_PORT)).is_err() {
                return;
            }
            let handle = self.sockets.add(sock);
            self.listening.push(Listening { handle });
        }
    }

    /// Joins each connection a client opened to the loopback port its
    /// address goes to.
    fn accept(&mut self) -> bool {
        let mut busy = false;
        let mut still = Vec::new();
        for l in std::mem::take(&mut self.listening) {
            let s = self.sockets.get_mut::<tcp::Socket>(l.handle);
            if s.state() == tcp::State::Listen || s.state() == tcp::State::SynReceived {
                still.push(l);
                continue;
            }
            busy = true;
            let from = match s.remote_endpoint().map(|e| e.addr) {
                Some(IpAddress::Ipv6(a)) => a,
                _ => {
                    s.abort();
                    self.sockets.remove(l.handle);
                    continue;
                }
            };
            let Some(port) = (self.target)(from) else {
                (self.log)(&format!("cbb: the hub closed a connection from {from}, which it does not know"));
                s.abort();
                self.sockets.remove(l.handle);
                continue;
            };
            let local = match TcpStream::connect_timeout(&SocketAddr::from(([127, 0, 0, 1], port)), DIAL_TIMEOUT) {
                Ok(c) if c.set_nonblocking(true).is_ok() => c,
                Ok(_) | Err(_) => {
                    (self.log)(&format!("cbb: the hub: a connection from {from} cannot reach the app on port {port}"));
                    s.abort();
                    self.sockets.remove(l.handle);
                    continue;
                }
            };
            let _ = local.set_nodelay(true);
            if let (Ok(a), Ok(mut d)) = (local.local_addr(), self.dialed.lock()) {
                d.insert(a.port(), from);
            }
            self.bridges.push(Bridge {
                local,
                handle: l.handle,
                up: Vec::new(),
                down: Vec::new(),
                local_eof: false,
                done: false,
            });
        }
        self.listening = still;
        busy
    }

    fn bridge(&mut self) -> bool {
        let mut busy = false;
        let mut buf = [0u8; 16 << 10];
        for b in &mut self.bridges {
            busy |= move_bytes(b, self.sockets.get_mut::<tcp::Socket>(b.handle), &mut buf);
        }
        let sockets = &mut self.sockets;
        let mut dialed = self.dialed.lock().ok();
        self.bridges.retain(|b| {
            if b.done {
                sockets.remove(b.handle);
                if let (Some(d), Ok(a)) = (dialed.as_mut(), b.local.local_addr()) {
                    d.remove(&a.port());
                }
            }
            !b.done
        });
        busy
    }

    /// Waits for a datagram, a byte from the app, or smoltcp's or
    /// WireGuard's next timer, at most MAX_POLL.
    fn wait(&mut self) {
        let delay = self.iface.poll_delay(now(), &self.sockets).map(|d| Duration::from_micros(d.total_micros()));
        let timeout = delay.map_or(MAX_POLL, |d| d.min(MAX_POLL));
        let mut socks = vec![(sys::raw(&self.udp), true, false)];
        for b in &self.bridges {
            socks.push((sys::raw(&b.local), !b.local_eof && b.up.len() < TCP_BUFFER, !b.down.is_empty()));
        }
        sys::poll(&socks, timeout);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guest_addresses() {
        let a = guest_addr(&[7; 32]);
        assert!(is_guest(&a));
        assert!(!is_guest(&crate::tunnel::addr("00112233445566778899aabbccddeeff").unwrap()));
        assert_eq!(a.octets()[4..], crate::certs::sha256(&[7; 32])[..12]);
    }

    #[test]
    fn refuses_clients_twice() {
        let own = crate::tunnel::addr("00112233445566778899aabbccddeeff").unwrap();
        let p = Peer {
            key: [1; 32],
            psk: [2; 32],
            addr: crate::tunnel::addr("ffeeddccbbaa99887766554433221100").unwrap(),
            until: None,
        };
        assert!(check_peers(std::slice::from_ref(&p), own).is_ok());
        assert!(check_peers(&[p.clone(), p.clone()], own).is_err());
        assert!(check_peers(&[Peer { addr: own, ..p.clone() }], own).is_err());
        assert!(check_peers(&[Peer { key: [0; 32], ..p }], own).is_err());
    }

    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::atomic::AtomicUsize;

    /// A loopback port that writes a byte to each connection and keeps it,
    /// and how many it took.
    fn target() -> (u16, Arc<AtomicUsize>) {
        let ln = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = ln.local_addr().unwrap().port();
        let took = Arc::new(AtomicUsize::new(0));
        let n = took.clone();
        std::thread::spawn(move || {
            let mut keep = Vec::new();
            for c in ln.incoming() {
                let Ok(mut c) = c else { continue };
                let _ = c.write_all(b"y");
                n.fetch_add(1, Ordering::SeqCst);
                keep.push(c);
            }
        });
        (port, took)
    }

    /// A hub with n clients, and a link of each client to it.
    fn hub_and_links(n: usize, port: u16) -> (Hub, PublicKey, Vec<crate::tunnel::Link>) {
        let hub_key = crate::certs::random_bytes::<32>();
        let hub_pub = PublicKey::from(&StaticSecret::from(hub_key));
        let own = crate::tunnel::addr("00112233445566778899aabbccddeeff").unwrap();
        let mut peers = Vec::new();
        let mut clients = Vec::new();
        for i in 0..n {
            let k = crate::certs::random_bytes::<32>();
            let psk = crate::certs::random_bytes::<32>();
            let addr = crate::tunnel::addr(&format!("10112233445566778899aabb{i:08x}")).unwrap();
            peers.push(Peer { key: *PublicKey::from(&StaticSecret::from(k)).as_bytes(), psk, addr, until: None });
            clients.push((k, psk, addr));
        }
        let hub = Hub::start_at(
            &hub_key,
            own,
            None,
            peers,
            "127.0.0.1:0".parse().unwrap(),
            Arc::new(move |_| Some(port)),
            Arc::new(|_| {}),
        )
        .unwrap();
        let ep: SocketAddr = format!("127.0.0.1:{}", hub.udp_port()).parse().unwrap();
        let links = clients
            .iter()
            .map(|(k, psk, addr)| {
                let h = crate::tunnel::Hub {
                    device: "hub".into(),
                    key: hub_pub.as_bytes().to_vec(),
                    psk: psk.to_vec(),
                    endpoints: vec![ep],
                    next: Vec::new(),
                    obfuscation: None,
                    vless: None,
                };
                let st = crate::tunnel::State::with_key(k).unwrap();
                crate::tunnel::Link::start_at(&st, &h, *addr, own, Arc::new(|_| {})).unwrap()
            })
            .collect();
        (hub, hub_pub, links)
    }

    /// Opens a connection through a link and waits for the target's byte.
    fn reach(l: &crate::tunnel::Link, wait: Duration) -> std::io::Result<TcpStream> {
        let mut c = TcpStream::connect(l.local())?;
        c.set_read_timeout(Some(wait))?;
        let mut b = [0u8; 1];
        c.read_exact(&mut b)?;
        Ok(c)
    }

    /// Initiations without a valid mac1 and initiations of strangers, sent
    /// over and over, cost the hub no Diffie-Hellman it cannot afford: past
    /// the load, the strangers are asked for a cookie, and a client of the
    /// hub still gets through.
    #[test]
    fn initiations_are_checked_before_the_hub_pays_for_them() {
        let (port, _) = target();
        let (hub, hub_pub, links) = hub_and_links(1, port);
        let ep: SocketAddr = format!("127.0.0.1:{}", hub.udp_port()).parse().unwrap();
        // Strangers' initiations, valid but for keys the hub does not know.
        let mut packets: Vec<Vec<u8>> = (0..32)
            .map(|_| {
                let mut t = Tunn::new(
                    StaticSecret::from(crate::certs::random_bytes::<32>()),
                    hub_pub,
                    None,
                    None,
                    IndexTable::from_os_rng(),
                    Arc::new(RateLimiter::new(&hub_pub, HANDSHAKE_RATE_LIMIT)),
                );
                let p: Packet = t.format_handshake_initiation(true).unwrap().into();
                p.as_ref().to_vec()
            })
            .collect();
        for i in 0..32u8 {
            let mut g = vec![i; 148];
            g[..4].copy_from_slice(&[1, 0, 0, 0]);
            packets.push(g);
        }
        let stop = Arc::new(AtomicBool::new(false));
        let cookies = Arc::new(AtomicUsize::new(0));
        let sent = Arc::new(AtomicUsize::new(0));
        let flood: Vec<_> = (0..2)
            .map(|_| {
                let (stop, cookies, sent, packets) = (stop.clone(), cookies.clone(), sent.clone(), packets.clone());
                std::thread::spawn(move || {
                    let u = UdpSocket::bind("127.0.0.1:0").unwrap();
                    u.set_nonblocking(true).unwrap();
                    let mut buf = [0u8; 256];
                    while !stop.load(Ordering::SeqCst) {
                        for p in &packets {
                            let _ = u.send_to(p, ep);
                        }
                        sent.fetch_add(packets.len(), Ordering::Relaxed);
                        while let Ok((n, _)) = u.recv_from(&mut buf) {
                            if n == 64 && buf[0] == 3 {
                                cookies.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                        std::thread::sleep(Duration::from_micros(200));
                    }
                })
            })
            .collect();
        std::thread::sleep(Duration::from_millis(500));
        let start = Instant::now();
        let r = reach(&links[0], Duration::from_secs(25));
        let took = start.elapsed();
        stop.store(true, Ordering::SeqCst);
        for f in flood {
            f.join().unwrap();
        }
        assert!(r.is_ok(), "the client did not get through in {took:?}: {r:?}");
        assert!(sent.load(Ordering::Relaxed) > 10_000, "the flood sent {}", sent.load(Ordering::Relaxed));
        assert!(cookies.load(Ordering::Relaxed) > 0, "the hub asked no stranger for a cookie under load");
    }
}
