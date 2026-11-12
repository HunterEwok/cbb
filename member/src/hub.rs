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
use crate::relayd::budget::{Caps, Count, Level};
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

/// The Diffie-Hellmans a second on handshake initiations, of initiations
/// whose mac1 was right, past which the hub is under load, as WireGuard has
/// it: every initiation must then carry a cookie, which only a source that
/// receives at its address can have, before the hub spends one more.
const UNDER_LOAD: usize = 512;
/// The Diffie-Hellmans a second the hub spends on initiations, by the
/// source's network (an IPv4 /24 or IPv6 /64), wide network (/16 or /48)
/// and provider (an IPv6 /32), and in all; one takes about 50 microseconds
/// of the pump's thread, which carries every client's data. DH_KNOWN more
/// are kept for initiations from the address a client last spoke from, so
/// that strangers who spend the rest hold up no client that rekeys.
const DH_CAPS: Caps = Caps { address: 0, network: 32, wide: 128, provider: 512, all: 1536 };
/// The part kept for clients' addresses, shared by address and network: a
/// client rekeys once in two minutes, so 4 a second is plenty for one
/// address, even one many clients share.
const DH_KNOWN: Caps = Caps { address: 4, network: 32, wide: 0, provider: 0, all: 512 };

/// How long a connection a client opens may wait for the hub's answer to
/// be acknowledged, and a client's opening that no socket took be counted.
const SYN_TIMEOUT: Duration = Duration::from_secs(5);
const OPENING_FOR: Duration = Duration::from_secs(3);

/// The connections through a hub's tunnels at once, those being opened
/// counted: in all, and of one client. A device's hub holds per_client for
/// each of its clients, at least MAX_BRIDGES and at most bridges; the
/// relay, one hub for the devices of many groups, holds bridges. A client
/// past its share has its new connections ignored; the others' go on.
///
/// Every client may hold its first floor connections whatever the others
/// hold, so a full hub still takes each client's few. A connection being
/// opened, whose client has not acknowledged the hub's answer yet, counts
/// besides against opening_per_client of its client and against openings,
/// by the source each client came from (Peer::source) at each level.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub bridges: usize,
    pub per_client: usize,
    pub floor: usize,
    pub opening_per_client: usize,
    pub openings: Caps,
    /// The connections past the floors, being opened or open, by source.
    pub sources: Caps,
}

/// A device's hub: its clients each open one or two connections, and a
/// guest one; a phone or a computer holds a few hundred clients at most.
pub const DEVICE_LIMITS: Limits = Limits {
    bridges: 1024,
    per_client: 8,
    floor: 2,
    opening_per_client: 4,
    openings: Caps { address: 0, network: 0, wide: 0, provider: 0, all: 256 },
    sources: Caps { address: 0, network: 0, wide: 0, provider: 0, all: 0 },
};

/// Whether ip, a packet from a client, opens a connection to the member
/// port: an IPv6 packet without extension headers whose TCP segment is a
/// SYN to that port, and the port it comes from.
fn opening(ip: &[u8]) -> Option<u16> {
    const SYN: u8 = 0x02;
    const ACK: u8 = 0x10;
    let (Some(&6), Some(dst), Some(&flags), Some(src)) = (ip.get(6), ip.get(42..44), ip.get(53), ip.get(40..42)) else {
        return None;
    };
    (dst == MEMBER_PORT.to_be_bytes() && flags & (SYN | ACK) == SYN).then(|| u16::from_be_bytes([src[0], src[1]]))
}

/// One client of the hub: its WireGuard public key, the preshared key the
/// hub's offer gave it, its one tunnel address, and for a guest when it goes.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Peer {
    pub key: [u8; 32],
    pub psk: [u8; 32],
    pub addr: Ipv6Addr,
    pub until: Option<Instant>,
    /// Where the client came from when it registered, for the shares of a
    /// hub that serves many sources (the relay); None for a device's hub.
    pub source: Option<std::net::IpAddr>,
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
        Hub::start_at(key, own, obfuscation, peers, listen, target, DEVICE_LIMITS, log)
    }

    /// Starts the hub as start does, at the tunnel address own in place of
    /// a device's, and within limits: the blind relay's, which passes the
    /// connections of many devices at once.
    #[allow(clippy::too_many_arguments)]
    pub fn start_at(
        key: &[u8; 32],
        own: Ipv6Addr,
        obfuscation: Option<&serde_json::Value>,
        peers: Vec<Peer>,
        listen: SocketAddr,
        target: Target,
        limits: Limits,
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
            second: Second::new(HashSet::new()),
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
            limits,
            held: HashMap::new(),
            total: 0,
            floors: 0,
            charges: HashMap::new(),
            half: HashMap::new(),
            openings: Count::new(limits.openings),
            by_source: Count::new(limits.sources),
            sources: HashMap::new(),
            opening: HashMap::new(),
            owners: HashMap::new(),
            owned: HashSet::new(),
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
/// the app's loopback port, and since when it is being opened.
struct Listening {
    handle: SocketHandle,
    since: Option<Instant>,
}

/// A connection of a client: its tunnel address and the port it comes from.
type Conn = (Ipv6Addr, u16);

/// What the hub spent on handshake initiations in the current second: the
/// Diffie-Hellmans on strangers' by source, those on known addresses, and
/// the addresses its clients last spoke from, as of the second's start.
struct Second {
    began: Instant,
    dh: Count,
    known_dh: Count,
    known: HashSet<std::net::IpAddr>,
}

impl Second {
    fn new(known: HashSet<std::net::IpAddr>) -> Second {
        Second { began: Instant::now(), dh: Count::new(DH_CAPS), known_dh: Count::new(DH_KNOWN), known }
    }

    /// The Diffie-Hellmans spent this second.
    fn spent(&self) -> usize {
        self.dh.held(None, Level::All) + self.known_dh.held(None, Level::All)
    }

    /// Whether an address a client last spoke from sent it.
    fn is_known(&self, from: std::net::IpAddr) -> bool {
        self.known.contains(&from)
    }

    /// Charges a Diffie-Hellman on an initiation from the address from to
    /// its source's shares, or to the part kept for clients' addresses
    /// when from is one; false when neither has room.
    fn admit(&mut self, from: std::net::IpAddr) -> bool {
        if self.is_known(from) && self.known_dh.take(Some(from), 1) {
            return true;
        }
        self.dh.take(Some(from), 1)
    }
}

/// What the hub counted of a connection a client opened: the client's
/// source, whether it is still being opened, and whether it is one of the
/// client's floor.
struct Charge {
    source: Option<std::net::IpAddr>,
    opening: bool,
    floor: bool,
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
    limits: Limits,
    /// The connections each client holds, those being opened counted; all
    /// of them but the floors, and the floors; what each connection was
    /// counted for; the connections each client is opening, and those of
    /// all clients by source.
    held: HashMap<Ipv6Addr, usize>,
    total: usize,
    floors: usize,
    charges: HashMap<Conn, Charge>,
    half: HashMap<Ipv6Addr, usize>,
    openings: Count,
    /// The connections past the floors, by source; and each client's
    /// source, by its tunnel address.
    by_source: Count,
    sources: HashMap<Ipv6Addr, Option<std::net::IpAddr>>,
    /// The openings counted that no socket took yet, since when.
    opening: HashMap<Conn, Instant>,
    /// The connection each socket that took one holds, and those
    /// connections.
    owners: HashMap<SocketHandle, Conn>,
    owned: HashSet<Conn>,
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
                s.peer.source = p.source;
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
        self.sources = self.peers.values().map(|s| (s.peer.addr, s.peer.source)).collect();
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
    /// its mac1 under the hub's key; under load, a cookie (mac2), which the
    /// hub sends to a source that has none; and within what the hub spends
    /// a second, by the source's network, wide network and provider and in
    /// all, with a part kept for the addresses its clients last spoke from.
    /// None drops it.
    fn admit_initiation(&mut self, from: SocketAddr, wg: &[u8]) -> Option<Packet<gotatun::packet::WgHandshakeInit>> {
        if self.second.began.elapsed() >= Duration::from_secs(1) {
            let known = self.peers.values().filter_map(|s| s.endpoint.map(|e| e.ip())).collect();
            self.second = Second::new(known);
            self.limiter.try_reset_count();
            self.strict.try_reset_count();
        }
        // Only what the hub spent counts toward the load, so packets with
        // a wrong mac1 never put it there. AmneziaWG checked mac1 itself
        // and has no cookie replies: only the group's devices know the
        // settings that reach the hub, and the shares below hold anyway.
        // A client that rekeys from the address it last spoke from needs no
        // cookie: its rekeys go on while strangers are asked for one.
        let under = self.second.spent() >= UNDER_LOAD && self.listen_awg.is_none() && !self.second.is_known(from.ip());
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
        self.second.admit(from.ip()).then_some(init)
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
                        let ip = ip.to_vec();
                        let addr = s.peer.addr;
                        // A client past its share, or a hub that is full,
                        // ignores a new connection: the client tries again.
                        if opening(&ip).is_none_or(|port| self.take((addr, port))) {
                            self.dev.rx.push_back(ip);
                        }
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

    /// The connections the hub holds at once: per_client for each client,
    /// at least MAX_BRIDGES, at most the limit.
    fn cap(&self) -> usize {
        self.limits
            .per_client
            .saturating_mul(self.peers.len())
            .clamp(MAX_BRIDGES.min(self.limits.bridges), self.limits.bridges)
    }

    /// Counts a connection a client opens; false when the client or the
    /// hub holds as many as it may. A client's first floor connections
    /// are taken whatever the hub holds; past them, one being opened needs
    /// room in its client's and its source's shares of openings. An
    /// opening already counted, which the client sent again, is let
    /// through.
    fn take(&mut self, c: Conn) -> bool {
        if self.opening.contains_key(&c) || self.owned.contains(&c) {
            return true;
        }
        let held = self.held.get(&c.0).copied().unwrap_or(0);
        let floor = held < self.limits.floor;
        if !floor
            && (held >= self.limits.per_client
                || self.total >= self.cap()
                || self.half.get(&c.0).copied().unwrap_or(0) >= self.limits.opening_per_client)
        {
            return false;
        }
        let source = self.sources.get(&c.0).copied().flatten();
        if floor {
            self.floors += 1;
        } else if self.by_source.full(source, 1).is_none() && self.openings.take(source, 1) {
            self.by_source.add(source, 1);
            self.total += 1;
        } else {
            return false;
        }
        self.held.insert(c.0, held + 1);
        *self.half.entry(c.0).or_insert(0) += 1;
        self.charges.insert(c, Charge { source, opening: true, floor });
        self.opening.insert(c, Instant::now());
        true
    }

    /// The connection c is open: it no longer counts as being opened.
    fn opened(&mut self, c: Conn) {
        let Some(ch) = self.charges.get_mut(&c) else { return };
        if !std::mem::replace(&mut ch.opening, false) {
            return;
        }
        let (source, floor) = (ch.source, ch.floor);
        if !floor {
            self.openings.remove(source, 1);
        }
        if let Some(n) = self.half.get_mut(&c.0) {
            *n -= 1;
            if *n == 0 {
                self.half.remove(&c.0);
            }
        }
    }

    /// Stops counting the connection c.
    fn discharge(&mut self, c: Conn) {
        self.opened(c);
        let Some(ch) = self.charges.remove(&c) else { return };
        if let Some(n) = self.held.get_mut(&c.0) {
            *n -= 1;
            if *n == 0 {
                self.held.remove(&c.0);
            }
        }
        if ch.floor {
            self.floors = self.floors.saturating_sub(1);
        } else {
            self.by_source.remove(ch.source, 1);
            self.total = self.total.saturating_sub(1);
        }
    }

    /// Stops counting what the socket handle held.
    fn release(&mut self, handle: SocketHandle) {
        if let Some(c) = self.owners.remove(&handle) {
            self.owned.remove(&c);
            self.discharge(c);
        }
    }

    /// The socket handle took the connection c: it holds what its opening
    /// was counted for, or is counted now, as for an opening counted long
    /// ago; false when it may not have it.
    fn own(&mut self, handle: SocketHandle, c: Conn) -> bool {
        if self.owned.contains(&c) {
            return false;
        }
        if self.opening.remove(&c).is_none() {
            if !self.take(c) {
                return false;
            }
            self.opening.remove(&c);
        }
        self.owners.insert(handle, c);
        self.owned.insert(c);
        true
    }

    /// Keeps a socket listening on the member port for each connection the
    /// clients are opening, at least LISTENERS, within the hub's limits.
    fn listen(&mut self) {
        // The openings no socket took in time are not counted any more.
        let now = Instant::now();
        let stale: Vec<Conn> =
            self.opening.iter().filter(|(_, at)| now.duration_since(**at) >= OPENING_FOR).map(|(c, _)| *c).collect();
        for c in stale {
            self.opening.remove(&c);
            self.discharge(c);
        }
        let want = LISTENERS.max(self.opening.len());
        let sockets = &mut self.sockets;
        let mut free = 0;
        // The sockets a burst left listening go once it is over.
        self.listening.retain(|l| {
            if sockets.get::<tcp::Socket>(l.handle).state() != tcp::State::Listen {
                return true;
            }
            free += 1;
            if free > want {
                sockets.remove(l.handle);
                return false;
            }
            true
        });
        while free < want && self.bridges.len() + self.listening.len() < self.cap() + self.floors + LISTENERS {
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
            self.listening.push(Listening { handle, since: None });
            free += 1;
        }
    }

    /// Takes a socket that stopped listening away, and what it held.
    fn drop_listening(&mut self, handle: SocketHandle) {
        self.sockets.get_mut::<tcp::Socket>(handle).abort();
        self.sockets.remove(handle);
        self.release(handle);
    }

    /// Joins each connection a client opened to the loopback port its
    /// address goes to.
    fn accept(&mut self) -> bool {
        let mut busy = false;
        let mut still = Vec::new();
        for mut l in std::mem::take(&mut self.listening) {
            let s = self.sockets.get_mut::<tcp::Socket>(l.handle);
            let state = s.state();
            let remote = s.remote_endpoint().and_then(|e| match e.addr {
                IpAddress::Ipv6(a) => Some((a, e.port)),
                // Only IPv6 runs in the tunnel.
                #[allow(unreachable_patterns)]
                _ => None,
            });
            if state == tcp::State::Listen {
                still.push(l);
                continue;
            }
            // The socket took a connection: it holds what its opening was
            // counted for, or goes.
            if l.since.is_none() {
                l.since = Some(Instant::now());
                match remote {
                    Some(c) if self.owned.contains(&c) => {
                        // An opening the client sent again, which another
                        // socket holds: this one goes without a word, so
                        // that the connection is not reset.
                        self.sockets.remove(l.handle);
                        continue;
                    }
                    Some(c) if self.own(l.handle, c) => {}
                    _ => {
                        self.drop_listening(l.handle);
                        continue;
                    }
                }
            }
            if state == tcp::State::SynReceived {
                // A client that never acknowledges the hub's answer holds
                // the socket only a moment.
                if l.since.is_some_and(|t| t.elapsed() >= SYN_TIMEOUT) {
                    self.drop_listening(l.handle);
                } else {
                    still.push(l);
                }
                continue;
            }
            busy = true;
            if let Some(c) = remote {
                self.opened(c);
            }
            let Some((from, _)) = remote else {
                self.drop_listening(l.handle);
                continue;
            };
            let Some(port) = (self.target)(from) else {
                (self.log)(&format!("cbb: the hub closed a connection from {from}, which it does not know"));
                self.drop_listening(l.handle);
                continue;
            };
            let local = match TcpStream::connect_timeout(&SocketAddr::from(([127, 0, 0, 1], port)), DIAL_TIMEOUT) {
                Ok(c) if c.set_nonblocking(true).is_ok() => c,
                Ok(_) | Err(_) => {
                    (self.log)(&format!("cbb: the hub: a connection from {from} cannot reach the app on port {port}"));
                    self.drop_listening(l.handle);
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
                closed_at: None,
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
        let mut gone = Vec::new();
        self.bridges.retain(|b| {
            if b.done {
                sockets.remove(b.handle);
                gone.push(b.handle);
                if let (Some(d), Ok(a)) = (dialed.as_mut(), b.local.local_addr()) {
                    d.remove(&a.port());
                }
            }
            !b.done
        });
        drop(dialed);
        for h in gone {
            self.release(h);
        }
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
            source: None,
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
    fn hub_and_links(n: usize, port: u16, limits: Limits) -> (Hub, PublicKey, Vec<crate::tunnel::Link>) {
        hub_and_links_from(&vec![None; n], port, limits)
    }

    /// A hub with a client from each of sources, and a link of each.
    fn hub_and_links_from(
        sources: &[Option<std::net::IpAddr>],
        port: u16,
        limits: Limits,
    ) -> (Hub, PublicKey, Vec<crate::tunnel::Link>) {
        let hub_key = crate::certs::random_bytes::<32>();
        let hub_pub = PublicKey::from(&StaticSecret::from(hub_key));
        let own = crate::tunnel::addr("00112233445566778899aabbccddeeff").unwrap();
        let mut peers = Vec::new();
        let mut clients = Vec::new();
        for (i, source) in sources.iter().enumerate() {
            let k = crate::certs::random_bytes::<32>();
            let psk = crate::certs::random_bytes::<32>();
            let addr = crate::tunnel::addr(&format!("{:02x}112233445566778899aabbccddee00", i + 0x10)).unwrap();
            peers.push(Peer {
                key: *PublicKey::from(&StaticSecret::from(k)).as_bytes(),
                psk,
                addr,
                until: None,
                source: *source,
            });
            clients.push((k, psk, addr));
        }
        let hub = Hub::start_at(
            &hub_key,
            own,
            None,
            peers,
            "127.0.0.1:0".parse().unwrap(),
            Arc::new(move |_| Some(port)),
            limits,
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
        let (hub, hub_pub, links) = hub_and_links(1, port, DEVICE_LIMITS);
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

    /// One hub holds the connections of all its clients past MAX_BRIDGES,
    /// within its limits, and a client past its share holds only its own:
    /// the others' connections go on (the relay runs one hub for the
    /// devices of every group).
    #[test]
    fn connections_are_held_per_client() {
        let (port, took) = target();
        let limits = Limits { bridges: 256, per_client: 16, ..DEVICE_LIMITS };
        let (_hub, _, links) = hub_and_links(4, port, limits);
        let mut held = Vec::new();
        for i in 0..60 {
            let c = reach(&links[i % 4], Duration::from_secs(10));
            assert!(c.is_ok(), "connection {} of 60 did not get through: {c:?}", i + 1);
            held.push(c.unwrap());
        }
        assert_eq!(took.load(Ordering::SeqCst), 60);
        // The first client takes the rest of its share, then no more.
        for _ in 0..1 {
            held.push(reach(&links[0], Duration::from_secs(10)).unwrap());
        }
        let past = TcpStream::connect(links[0].local()).unwrap();
        past.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let mut b = [0u8; 1];
        assert!((&past).read_exact(&mut b).is_err(), "a client got more than its share");
        let others = reach(&links[1], Duration::from_secs(10));
        assert!(others.is_ok(), "another client lost its share to the first: {others:?}");
        assert_eq!(took.load(Ordering::SeqCst), 62);
    }

    /// An IPv6 packet with a TCP SYN from (src, sport) to the member port
    /// of dst, with its checksum.
    fn syn(src: Ipv6Addr, dst: Ipv6Addr, sport: u16) -> Vec<u8> {
        let mut p = vec![0u8; 60];
        p[0] = 0x60;
        p[4..6].copy_from_slice(&20u16.to_be_bytes());
        p[6] = 6;
        p[7] = 64;
        p[8..24].copy_from_slice(&src.octets());
        p[24..40].copy_from_slice(&dst.octets());
        let t = &mut p[40..];
        t[0..2].copy_from_slice(&sport.to_be_bytes());
        t[2..4].copy_from_slice(&MEMBER_PORT.to_be_bytes());
        t[4..8].copy_from_slice(&u32::from(sport).wrapping_mul(7919).to_be_bytes());
        t[12] = 5 << 4;
        t[13] = 0x02;
        t[14..16].copy_from_slice(&u16::MAX.to_be_bytes());
        let mut sum: u32 = 0;
        let mut add = |b: &[u8]| {
            for w in b.chunks(2) {
                sum += u32::from(u16::from_be_bytes([w[0], *w.get(1).unwrap_or(&0)]));
            }
        };
        add(&src.octets());
        add(&dst.octets());
        add(&20u32.to_be_bytes());
        add(&[0, 0, 0, 6]);
        add(&p[40..60]);
        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        p[56..58].copy_from_slice(&(!(sum as u16)).to_be_bytes());
        p
    }

    /// A client that opens connections and never completes them, from
    /// many ports at once, holds its own share for a moment and nothing of
    /// the others'.
    #[test]
    fn half_open_connections_hold_a_client_s_share_only() {
        let (port, _) = target();
        let hub_key = crate::certs::random_bytes::<32>();
        let hub_pub = PublicKey::from(&StaticSecret::from(hub_key));
        let own = crate::tunnel::addr("00112233445566778899aabbccddeeff").unwrap();
        let (ka, kb) = (crate::certs::random_bytes::<32>(), crate::certs::random_bytes::<32>());
        let (pa, pb) = (crate::certs::random_bytes::<32>(), crate::certs::random_bytes::<32>());
        let a = crate::tunnel::addr("21112233445566778899aabbccddee01").unwrap();
        let b = crate::tunnel::addr("22112233445566778899aabbccddee02").unwrap();
        let pubkey = |k: [u8; 32]| *PublicKey::from(&StaticSecret::from(k)).as_bytes();
        let peers = vec![
            Peer { key: pubkey(ka), psk: pa, addr: a, until: None, source: None },
            Peer { key: pubkey(kb), psk: pb, addr: b, until: None, source: None },
        ];
        let hub = Hub::start_at(
            &hub_key,
            own,
            None,
            peers,
            "127.0.0.1:0".parse().unwrap(),
            Arc::new(move |_| Some(port)),
            Limits { bridges: 64, per_client: 8, ..DEVICE_LIMITS },
            Arc::new(|_| {}),
        )
        .unwrap();
        let ep: SocketAddr = format!("127.0.0.1:{}", hub.udp_port()).parse().unwrap();

        // The first client, by hand: a handshake, then SYNs it never
        // completes.
        let u = UdpSocket::bind("127.0.0.1:0").unwrap();
        u.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let sa = StaticSecret::from(ka);
        let mut t = Tunn::new(
            sa.clone(),
            hub_pub,
            Some(pa),
            None,
            IndexTable::from_os_rng(),
            Arc::new(RateLimiter::new(&PublicKey::from(&sa), HANDSHAKE_RATE_LIMIT)),
        );
        let init: Packet = t.format_handshake_initiation(true).unwrap().into();
        u.send_to(init.as_ref(), ep).unwrap();
        let mut buf = [0u8; 2048];
        let (n, _) = u.recv_from(&mut buf).unwrap();
        let kind = Packet::from_bytes(BytesMut::from(&buf[..n])).try_into_wg().unwrap();
        if let TunnResult::WriteToNetwork(p) = t.handle_incoming_packet(kind) {
            u.send_to(Packet::from(p).as_ref(), ep).unwrap();
        }
        for sport in 0..400u16 {
            if let Some(p) =
                t.handle_outgoing_packet(Packet::from_bytes(BytesMut::from(&syn(a, own, 10_000 + sport)[..])), None)
            {
                u.send_to(Packet::from(p).as_ref(), ep).unwrap();
            }
        }
        // The hub answers the openings it counted, and only those.
        u.set_read_timeout(Some(Duration::from_millis(500))).unwrap();
        let mut answered = 0;
        while let Ok((n, _)) = u.recv_from(&mut buf) {
            let kind = Packet::from_bytes(BytesMut::from(&buf[..n])).try_into_wg().unwrap();
            if let TunnResult::WriteToTunnel(ip) = t.handle_incoming_packet(kind) {
                let ip: &[u8] = ip.as_ref();
                if ip.len() >= 54 && ip[53] & 0x12 == 0x12 {
                    answered += 1;
                }
            }
        }
        assert!((1..=8).contains(&answered), "the hub answered {answered} openings of a client whose share is 8");

        // The second client gets through all the while.
        let h = crate::tunnel::Hub {
            device: "hub".into(),
            key: hub_pub.as_bytes().to_vec(),
            psk: pb.to_vec(),
            endpoints: vec![ep],
            next: Vec::new(),
            obfuscation: None,
            vless: None,
        };
        let link =
            crate::tunnel::Link::start_at(&crate::tunnel::State::with_key(&kb).unwrap(), &h, b, own, Arc::new(|_| {}))
                .unwrap();
        let mut held = Vec::new();
        for i in 0..8 {
            let c = reach(&link, Duration::from_secs(10));
            assert!(c.is_ok(), "connection {} of the other client did not get through: {c:?}", i + 1);
            held.push(c.unwrap());
        }
    }

    /// The Diffie-Hellmans on initiations are shared by source: the
    /// networks of one wide network take its share and no more, strangers
    /// of many providers take what is left in all, and clients that rekey
    /// from their addresses still get through, none taking more than its
    /// address's share of the part kept for them.
    #[test]
    fn handshakes_are_shared_by_source() {
        use std::net::IpAddr;
        let clients: Vec<IpAddr> =
            (0..200u16).map(|i| IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0xff00 + i, 0, 0, 0, 0, 1))).collect();
        let mut s = Second::new(clients.iter().copied().collect());
        let mut got = 0;
        for n in 0..256u16 {
            for _ in 0..DH_CAPS.network + 1 {
                got += usize::from(s.admit(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 1, n, 0, 0, 0, 1))));
            }
        }
        assert_eq!(got, DH_CAPS.wide, "the networks of one wide network");
        for p in 0..64u16 {
            for n in 0..16u16 {
                for _ in 0..DH_CAPS.network {
                    s.admit(IpAddr::V6(Ipv6Addr::new(0x2001, 0x1000 + p, n, 0, 0, 0, 0, 1)));
                }
            }
        }
        assert_eq!(s.dh.held(None, Level::All), DH_CAPS.all, "strangers in all");
        for i in 0..DH_KNOWN.address {
            assert!(s.admit(clients[0]), "a client's rekey {i} found no room");
        }
        assert!(!s.admit(clients[0]), "one address took more than its share of the part kept for clients");
        let got: usize = clients[1..].iter().map(|c| usize::from(s.admit(*c))).sum();
        assert_eq!(got, clients.len() - 1, "the other clients' rekeys");
        // IPv4: a /16 is its own provider.
        let mut s = Second::new(HashSet::new());
        let got: usize = (0..=255u8)
            .flat_map(|c| (0..DH_CAPS.network).map(move |_| c))
            .map(|c| usize::from(s.admit(IpAddr::V4(std::net::Ipv4Addr::new(198, 18, c, 1)))))
            .sum();
        assert_eq!(got, DH_CAPS.wide, "the /24s of one /16");
    }

    /// Initiations with a wrong mac1, however many, do not put the hub
    /// under load: a client's handshake needs no cookie round.
    #[test]
    fn garbage_does_not_put_the_hub_under_load() {
        let (port, _) = target();
        let (hub, _, links) = hub_and_links(1, port, DEVICE_LIMITS);
        let ep: SocketAddr = format!("127.0.0.1:{}", hub.udp_port()).parse().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let sent = Arc::new(AtomicUsize::new(0));
        let flood = {
            let (stop, sent) = (stop.clone(), sent.clone());
            std::thread::spawn(move || {
                let u = UdpSocket::bind("127.0.0.2:0").unwrap();
                let mut g = vec![7u8; 148];
                g[..4].copy_from_slice(&[1, 0, 0, 0]);
                while !stop.load(Ordering::SeqCst) {
                    for _ in 0..64 {
                        let _ = u.send_to(&g, ep);
                    }
                    sent.fetch_add(64, Ordering::Relaxed);
                    std::thread::sleep(Duration::from_millis(1));
                }
            })
        };
        std::thread::sleep(Duration::from_millis(500));
        let start = Instant::now();
        let r = reach(&links[0], Duration::from_secs(20));
        let took = start.elapsed();
        stop.store(true, Ordering::SeqCst);
        flood.join().unwrap();
        assert!(r.is_ok(), "the client did not get through: {r:?}");
        assert!(sent.load(Ordering::Relaxed) > 1_000, "the flood sent {}", sent.load(Ordering::Relaxed));
        assert!(took < Duration::from_secs(3), "the client waited {took:?}, a cookie round");
    }

    /// A client by hand: a handshake with the hub at ep, after which it
    /// sends what it likes through the returned tunnel and socket.
    fn raw_client(key: [u8; 32], psk: [u8; 32], hub_pub: PublicKey, ep: SocketAddr) -> (Tunn, UdpSocket) {
        let u = UdpSocket::bind("127.0.0.1:0").unwrap();
        u.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let sk = StaticSecret::from(key);
        let mut t = Tunn::new(
            sk.clone(),
            hub_pub,
            Some(psk),
            None,
            IndexTable::from_os_rng(),
            Arc::new(RateLimiter::new(&PublicKey::from(&sk), HANDSHAKE_RATE_LIMIT)),
        );
        let init: Packet = t.format_handshake_initiation(true).unwrap().into();
        u.send_to(init.as_ref(), ep).unwrap();
        let mut buf = [0u8; 2048];
        let (n, _) = u.recv_from(&mut buf).unwrap();
        let kind = Packet::from_bytes(BytesMut::from(&buf[..n])).try_into_wg().unwrap();
        if let TunnResult::WriteToNetwork(p) = t.handle_incoming_packet(kind) {
            u.send_to(Packet::from(p).as_ref(), ep).unwrap();
        }
        u.set_nonblocking(true).unwrap();
        (t, u)
    }

    /// Clients of one source that open connections without end and never
    /// complete them fill neither the hub nor its openings: their source's
    /// share holds them, and a client of another source gets its
    /// connections all the while.
    #[test]
    fn a_full_hub_still_takes_each_client_s_few() {
        let (port, _) = target();
        let hub_key = crate::certs::random_bytes::<32>();
        let hub_pub = PublicKey::from(&StaticSecret::from(hub_key));
        let own = crate::tunnel::addr("00112233445566778899aabbccddeeff").unwrap();
        let pubkey = |k: [u8; 32]| *PublicKey::from(&StaticSecret::from(k)).as_bytes();
        let mut peers = Vec::new();
        let mut many = Vec::new();
        for i in 0..6u16 {
            let (k, psk) = (crate::certs::random_bytes::<32>(), crate::certs::random_bytes::<32>());
            let addr = crate::tunnel::addr(&format!("{:02x}112233445566778899aabbccddee00", i + 0x30)).unwrap();
            let source = Some(std::net::IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 1, i, 0, 0, 0, 1)));
            peers.push(Peer { key: pubkey(k), psk, addr, until: None, source });
            many.push((k, psk, addr));
        }
        let (kb, pb) = (crate::certs::random_bytes::<32>(), crate::certs::random_bytes::<32>());
        let b = crate::tunnel::addr("22112233445566778899aabbccddee02").unwrap();
        let source = Some(std::net::IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 2, 0, 0, 0, 0, 1)));
        peers.push(Peer { key: pubkey(kb), psk: pb, addr: b, until: None, source });
        let limits = Limits {
            bridges: 48,
            per_client: 80,
            floor: 2,
            opening_per_client: 4,
            openings: Caps { address: 0, network: 0, wide: 8, provider: 0, all: 16 },
            sources: Caps::default(),
        };
        let hub = Hub::start_at(
            &hub_key,
            own,
            None,
            peers,
            "127.0.0.1:0".parse().unwrap(),
            Arc::new(move |_| Some(port)),
            limits,
            Arc::new(|_| {}),
        )
        .unwrap();
        let ep: SocketAddr = format!("127.0.0.1:{}", hub.udp_port()).parse().unwrap();
        let mut raws: Vec<_> = many.iter().map(|(k, psk, a)| (raw_client(*k, *psk, hub_pub, ep), *a)).collect();
        let stop = Arc::new(AtomicBool::new(false));
        let flood = {
            let stop = stop.clone();
            std::thread::spawn(move || {
                let mut sport = 10_000u16;
                let mut buf = [0u8; 2048];
                while !stop.load(Ordering::SeqCst) {
                    for ((t, u), a) in &mut raws {
                        for _ in 0..20 {
                            sport = sport.wrapping_add(1).max(10_000);
                            if let Some(p) = t.handle_outgoing_packet(
                                Packet::from_bytes(BytesMut::from(&syn(*a, own, sport)[..])),
                                None,
                            ) {
                                let _ = u.send_to(Packet::from(p).as_ref(), ep);
                            }
                        }
                        // The hub's answers are read and never acknowledged.
                        while u.recv_from(&mut buf).is_ok() {}
                    }
                    std::thread::sleep(Duration::from_millis(20));
                }
            })
        };
        std::thread::sleep(Duration::from_secs(1));
        let h = crate::tunnel::Hub {
            device: "hub".into(),
            key: hub_pub.as_bytes().to_vec(),
            psk: pb.to_vec(),
            endpoints: vec![ep],
            next: Vec::new(),
            obfuscation: None,
            vless: None,
        };
        let link =
            crate::tunnel::Link::start_at(&crate::tunnel::State::with_key(&kb).unwrap(), &h, b, own, Arc::new(|_| {}))
                .unwrap();
        let mut held = Vec::new();
        for i in 0..6 {
            let c = reach(&link, Duration::from_secs(10));
            assert!(c.is_ok(), "connection {} of the other source's client did not get through: {c:?}", i + 1);
            held.push(c.unwrap());
        }
        stop.store(true, Ordering::SeqCst);
        flood.join().unwrap();
    }

    /// A client that keeps its half of a connection open after the app
    /// ended it, acknowledging and answering the keep-alives but never
    /// closing, holds it only a few seconds: then the hub cuts it, and the
    /// client's share is free again.
    #[test]
    fn a_closed_connection_is_not_held_open() {
        let ln = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = ln.local_addr().unwrap().port();
        let took = Arc::new(AtomicUsize::new(0));
        let n = took.clone();
        // The app ends every connection at once.
        std::thread::spawn(move || {
            for c in ln.incoming() {
                drop(c);
                n.fetch_add(1, Ordering::SeqCst);
            }
        });
        let limits = Limits { bridges: 64, per_client: 4, floor: 0, ..DEVICE_LIMITS };
        let (_hub, _, links) = hub_and_links(1, port, limits);
        // The client reads the end and keeps its own half open.
        let mut held = Vec::new();
        for _ in 0..4 {
            let mut c = TcpStream::connect(links[0].local()).unwrap();
            c.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
            assert!(matches!(c.read(&mut [0u8; 1]), Ok(0)), "the app's end did not come");
            held.push(c);
        }
        assert_eq!(took.load(Ordering::SeqCst), 4);
        let start = Instant::now();
        let mut more = Vec::new();
        while took.load(Ordering::SeqCst) == 4 {
            assert!(
                start.elapsed() < crate::tunnel::CLOSE_WAIT + Duration::from_secs(10),
                "connections the client never closed held its share"
            );
            let c = TcpStream::connect(links[0].local()).unwrap();
            more.push(c);
            std::thread::sleep(Duration::from_millis(500));
        }
        assert!(start.elapsed() >= Duration::from_secs(2), "the client's share was not full");
    }

    /// The connections past the floors are shared by the source each
    /// client came from: the clients of one wide network hold its share,
    /// and a client of another still gets its own.
    #[test]
    fn open_connections_are_shared_by_source() {
        let (port, took) = target();
        let ip = |w: u16, h: u16| Some(std::net::IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, w, h, 0, 0, 0, 1)));
        let limits = Limits {
            bridges: 64,
            per_client: 16,
            floor: 2,
            opening_per_client: 4,
            openings: Caps::default(),
            sources: Caps { address: 0, network: 0, wide: 12, provider: 0, all: 0 },
        };
        let (_hub, _, links) = hub_and_links_from(&[ip(1, 1), ip(1, 2), ip(1, 3), ip(2, 1)], port, limits);
        let mut held = Vec::new();
        for l in &links[..3] {
            for _ in 0..16 {
                match reach(l, Duration::from_secs(2)) {
                    Ok(c) => held.push(c),
                    Err(_) => break,
                }
            }
        }
        assert_eq!(held.len(), 3 * 2 + 12, "the clients of one wide network: their floors and its share");
        for i in 0..14 {
            let c = reach(&links[3], Duration::from_secs(10));
            assert!(c.is_ok(), "connection {} of another source's client did not get through: {c:?}", i + 1);
            held.push(c.unwrap());
        }
        assert_eq!(took.load(Ordering::SeqCst), held.len());
    }
}
