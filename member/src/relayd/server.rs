// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The running relay: the registrations' TCP port, the
//! WireGuard hub on the UDP port of the same number, and the connections the
//! devices open through their tunnels to the relay's member port, which it
//! joins two by two within one group. Each member registers with its member
//! certificate (or the group's credentials) and proves its WireGuard key;
//! the member protocol's TLS then runs between two members, and the relay
//! passes only its ciphertext.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv6Addr, Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender, TrySendError};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use cbb_core::certs::{self, Cert, KeyHash};

use super::budget::{Caps, Count, Rates};
use super::keys::Keys;
use super::limits::{self, ByteRate, Limits};
use super::records::{Period, RecordSet, TagLock};
use super::wire::{self, Note};
use crate::error::{Context, Error, Result};
use crate::hub::{Hub, Peer};

pub use crate::relay::RELAY_ADDR;

/// Limits of one group on the relay, which the user runs for their own
/// groups; they keep one misbehaving device from taking the relay's memory.
pub const MAX_MEMBERS: usize = 64;
pub const MAX_CALLS: usize = 16;
pub const MAX_PAIRS: usize = 256;

/// Limits of the setups, which strangers can start: a registration is set
/// up before the relay knows its device, so the registrations being set up
/// are counted by the address and the network they come from, and apart
/// from the requests the registered devices send in their tunnels. On an
/// open relay a stranger registers devices too, so those are counted by the
/// address and network the device registered from and by its group, as
/// well as by device.
pub const SETUP_CAPS: Caps = Caps { address: 16, network: 64, wide: 128, provider: 128, all: 256 };
pub const REQUEST_CAPS: Caps = Caps { address: 32, network: 64, wide: 64, provider: 128, all: 256 };
/// Requests being read of one device and of one group.
pub const MAX_REQUESTS_ONE: usize = 16;
pub const MAX_REQUESTS_GROUP: usize = 32;

/// How often the list of refused groups is read again.
pub const REFUSED_EVERY: Duration = Duration::from_secs(10);

/// How long a registration may take; the first line of a connection in a
/// tunnel (a device sends it as soon as the connection is open, so five
/// seconds leave room for a phone on a slow link that loses a packet or
/// two); the called device's answer; and a note to a device that stopped
/// reading.
pub const SETUP_TIMEOUT: Duration = Duration::from_secs(15);
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
pub const CALL_TIMEOUT: Duration = Duration::from_secs(10);
pub const NOTE_TIMEOUT: Duration = Duration::from_secs(10);

/// The stack of each of the relay's threads: they read frames and copy
/// bytes, and a relay holds thousands of them.
const STACK: usize = 256 << 10;

/// The log, which never names a device or an address.
pub type Log = Arc<dyn Fn(&str) + Send + Sync>;

/// A relay's configuration.
pub struct Config {
    /// The address of its port, the same for UDP (WireGuard) and TCP
    /// (registrations); port 0 for any.
    pub listen: SocketAddr,
    pub keys: Keys,
    /// The tags of the groups the relay serves; it refuses every other
    /// group. The user runs it for their own groups.
    pub groups: Vec<String>,
    /// Serve any group that registers, in place of groups, within limits:
    /// the project's relay, or one a user runs for others.
    pub open: bool,
    pub limits: Limits,
    pub log: Log,
    /// Also log the tunnel's own messages, without their addresses.
    pub verbose: bool,
    /// The groups the operator refuses after an abuse report
    /// (docs/relay-budget.md, "Abuse reports"), read again when the file
    /// changes; None refuses none.
    pub refused: Option<Arc<super::refused::List>>,
}

/// What a group's devices share: its joined connections, its requests being
/// read and, on an open relay, the rate it is copied at.
pub(super) struct GroupShare {
    pub pairs: AtomicUsize,
    pub reads: AtomicUsize,
    pub bytes: Option<Arc<ByteRate>>,
}

/// A registered device, what does not change while it is registered.
pub(super) struct Member {
    pub id: u64,
    pub tag: String,
    pub device: String,
    /// The key of its member certificate (or server certificate), and that
    /// certificate with the ones it came with.
    pub leaf: KeyHash,
    pub chain: Vec<Cert>,
    pub key: [u8; 32],
    pub psk: [u8; 32],
    /// The address it registered from.
    pub from: Option<IpAddr>,
    /// Its registration's TCP connection, open while it is registered.
    pub raw: TcpStream,
    pub share: Arc<GroupShare>,
}

/// What changes of a registered device, under the relay's lock.
#[derive(Default)]
pub(super) struct MemberState {
    pub addr: Option<Ipv6Addr>,
    /// Its connections in the tunnel, by number.
    pub streams: HashMap<u64, TcpStream>,
    /// The one that takes the notes, and where its notes go.
    pub watch: Option<u64>,
    pub notes: Option<SyncSender<Note>>,
    /// Calls waiting for its answer, and its requests being read.
    pub calls: usize,
    pub reading: usize,
    pub dropped: bool,
}

/// A device's dial, waiting for the other device to answer.
struct Call {
    from: u64,
    to: u64,
    answered: SyncSender<(u64, TcpStream)>,
}

/// Everything the relay holds, under one lock.
pub(super) struct State {
    pub groups: HashMap<String, HashMap<String, Arc<Member>>>,
    pub members: HashMap<u64, MemberState>,
    pub by_addr: HashMap<Ipv6Addr, Arc<Member>>,
    calls: HashMap<String, Call>,
    /// An open relay's registrations by the source they came from; the
    /// registrations being set up; and the requests being read, by the
    /// address the device registered from.
    pub held: Count,
    pub setups: Count,
    pub requests: Count,
    /// Each group's authority records, from all its members'
    /// registrations, verified once and kept in memory while the relay
    /// runs, and what they take by the source that brought them.
    pub records: HashMap<String, Arc<Mutex<RecordSet>>>,
    pub record_bytes: Count,
    /// Keep the registrations of one group one at a time while they check
    /// its records.
    pub tag_locks: HashMap<String, Arc<TagLock>>,
    /// What each source may still start.
    pub allow: Rates,
    /// What it holds of the groups that registered with credentials, by
    /// their period's tag.
    pub periods: HashMap<String, Period>,
    next_id: u64,
    /// How long a registration may take to be set up, and a connection in
    /// a tunnel to send its request: longer in tests.
    pub setup_wait: Duration,
    pub request_wait: Duration,
    /// The relay's clock for the allowance, which tests set.
    pub now: Option<Instant>,
}

impl State {
    pub fn now(&self) -> Instant {
        self.now.unwrap_or_else(Instant::now)
    }

    pub fn next_id(&mut self) -> u64 {
        self.next_id += 1;
        self.next_id
    }
}

/// The shared part of a running relay.
pub(super) struct Inner {
    pub cfg: Config,
    pub allowed: Vec<String>,
    pub limits: Limits,
    pub tls: Arc<rustls::ServerConfig>,
    pub hub: Mutex<Option<Hub>>,
    pub state: Mutex<State>,
    pub stop: AtomicBool,
    pub threads: Mutex<Vec<JoinHandle<()>>>,
}

/// A running relay. Dropping it stops it and drops every member.
pub struct Relay {
    inner: Arc<Inner>,
    addr: SocketAddr,
    accept: Vec<JoinHandle<()>>,
}

impl Relay {
    /// Opens the relay's port: TCP for the registrations, UDP for the
    /// tunnels, both with the same number, and starts serving.
    pub fn start(cfg: Config) -> Result<Relay> {
        match (cfg.open, cfg.groups.is_empty()) {
            (true, false) => return Err(Error::msg("relay: an open relay serves every group; give no group's tag")),
            (false, true) => {
                return Err(Error::msg(
                    "relay: no group to serve; give the tags of your groups (cbb status shows them)",
                ));
            }
            _ => {}
        }
        for g in &cfg.groups {
            if g.len() != 16 || !g.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err(Error::msg(format!(
                    "relay: {g:?} is not a group's tag, 16 hex characters as cbb status shows it"
                )));
            }
        }
        let clock: cbb_core::tls::Clock = Arc::new(crate::forward::SystemClock);
        let tls = cbb_core::tls::registration_server(&cfg.keys.cert, &cfg.keys.key, crate::relay::PROTOCOL, &clock)?;
        let (tcp, local) = listen(cfg.listen)?;
        let limits = if cfg.open { cfg.limits.with_defaults() } else { Limits::default() };
        let (held, record_bytes) = if cfg.open {
            (Count::new(limits.registration_caps()), Count::new(limits.record_caps()))
        } else {
            (Count::new(Caps::default()), Count::new(Caps::default()))
        };
        let state = State {
            groups: HashMap::new(),
            members: HashMap::new(),
            by_addr: HashMap::new(),
            calls: HashMap::new(),
            held,
            setups: Count::new(SETUP_CAPS),
            requests: Count::new(REQUEST_CAPS),
            records: HashMap::new(),
            record_bytes,
            tag_locks: HashMap::new(),
            allow: limits::allowance(),
            periods: HashMap::new(),
            next_id: 0,
            setup_wait: SETUP_TIMEOUT,
            request_wait: REQUEST_TIMEOUT,
            now: None,
        };
        let allowed = cfg.groups.iter().map(|g| g.to_ascii_lowercase()).collect();
        let inner = Arc::new(Inner {
            cfg,
            allowed,
            limits,
            tls: Arc::new(tls),
            hub: Mutex::new(None),
            state: Mutex::new(state),
            stop: AtomicBool::new(false),
            threads: Mutex::new(Vec::new()),
        });
        // The connections through the tunnels come to a loopback port,
        // which tells by the port they come from which tunnel address, and
        // so which device, each is from.
        let streams = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).context("cannot open the relay's port")?;
        let streams_port = streams.local_addr().context("cannot open the relay's port")?.port();
        let hub_log: Arc<dyn Fn(&str) + Send + Sync> = {
            let log = inner.cfg.log.clone();
            let verbose = inner.cfg.verbose;
            Arc::new(move |line: &str| {
                if verbose {
                    log(&redact(line));
                }
            })
        };
        let hub = Hub::start_at(
            &inner.cfg.keys.wireguard,
            RELAY_ADDR,
            None,
            Vec::new(),
            SocketAddr::new(local.ip(), local.port()),
            Arc::new(move |_| Some(streams_port)),
            hub_log,
        )?;
        *inner.hub.lock().map_err(|_| Error::msg("relay: broken"))? = Some(hub);
        let mut accept = vec![
            spawn({
                let inner = inner.clone();
                move || inner.accept_registrations(tcp)
            })?,
            spawn({
                let inner = inner.clone();
                move || inner.accept_streams(streams)
            })?,
        ];
        if inner.cfg.refused.is_some() {
            accept.push(spawn({
                let inner = inner.clone();
                move || {
                    let mut last = Instant::now();
                    while !inner.stopping() {
                        std::thread::sleep(Duration::from_millis(100));
                        if last.elapsed() >= REFUSED_EVERY {
                            last = Instant::now();
                            inner.reload_refused();
                        }
                    }
                }
            })?);
        }
        Ok(Relay { inner, addr: local, accept })
    }

    /// The address of the relay's port.
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// What the relay holds now: the groups and the devices.
    pub fn stats(&self) -> (usize, usize) {
        let st = self.inner.lock();
        (st.groups.len(), st.by_addr.len())
    }

    /// Whether the relay stopped by itself, as when its port broke.
    pub fn stopped(&self) -> bool {
        self.inner.stop.load(Ordering::SeqCst)
    }

    #[cfg(test)]
    pub(super) fn inner(&self) -> &Arc<Inner> {
        &self.inner
    }
}

impl Drop for Relay {
    fn drop(&mut self) {
        self.inner.stop.store(true, Ordering::SeqCst);
        // The accept loops wake on a connection of their own.
        let _ = TcpStream::connect_timeout(&wake(self.addr), Duration::from_secs(1));
        {
            let mut st = self.inner.lock();
            let all: Vec<Arc<Member>> = st.by_addr.values().cloned().collect();
            for m in all {
                self.inner.drop_locked(&mut st, &m);
            }
        }
        for t in self.accept.drain(..) {
            let _ = t.join();
        }
        let threads: Vec<_> = self.inner.threads.lock().map(|mut t| t.drain(..).collect()).unwrap_or_default();
        for t in threads {
            let _ = t.join();
        }
        if let Ok(mut h) = self.inner.hub.lock() {
            h.take();
        }
    }
}

/// The address to reach a listener on addr at, from this host.
fn wake(addr: SocketAddr) -> SocketAddr {
    match addr.ip() {
        IpAddr::V4(a) if a.is_unspecified() => SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, addr.port())),
        IpAddr::V6(a) if a.is_unspecified() => SocketAddr::from((Ipv6Addr::LOCALHOST, addr.port())),
        _ => addr,
    }
}

/// Opens the TCP port of the registrations. Where any free port will do,
/// it takes one whose UDP twin is free too, which the hub then opens.
fn listen(want: SocketAddr) -> Result<(TcpListener, SocketAddr)> {
    if want.port() != 0 {
        let tcp = TcpListener::bind(want).map_err(|e| Error::msg(format!("relay: cannot listen on {want}: {e}")))?;
        return Ok((tcp, want));
    }
    for _ in 0..40 {
        let udp = std::net::UdpSocket::bind(want).context("relay: cannot open a port")?;
        let port = udp.local_addr().context("relay: cannot open a port")?.port();
        drop(udp);
        let at = SocketAddr::new(want.ip(), port);
        if let Ok(tcp) = TcpListener::bind(at) {
            return Ok((tcp, at));
        }
    }
    Err(Error::msg("relay: no port free for both UDP and TCP"))
}

/// Starts one of the relay's threads.
pub(super) fn spawn(f: impl FnOnce() + Send + 'static) -> Result<JoinHandle<()>> {
    std::thread::Builder::new().stack_size(STACK).spawn(f).context("relay: cannot start a thread")
}

/// Takes the addresses out of a line of the tunnel's log: the relay keeps
/// no logs about the devices.
pub fn redact(line: &str) -> String {
    line.split(' ')
        .map(|w| {
            let t = w.trim_matches(|c: char| ",;()".contains(c));
            let addr = t.parse::<IpAddr>().is_ok()
                || t.parse::<SocketAddr>().is_ok()
                || t.trim_start_matches('[').trim_end_matches(']').parse::<IpAddr>().is_ok();
            if addr { "[address]" } else { w }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

impl Inner {
    pub fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn stopping(&self) -> bool {
        self.stop.load(Ordering::SeqCst)
    }

    /// Keeps a thread to join when the relay stops; finished ones are let
    /// go.
    pub fn keep(&self, t: JoinHandle<()>) {
        if let Ok(mut ts) = self.threads.lock() {
            ts.retain(|t| !t.is_finished());
            ts.push(t);
        }
    }

    fn log(&self, line: &str) {
        (self.cfg.log)(line);
    }

    /// Reads the list of refused groups again when its file changed, and
    /// drops the devices of the groups now on it. The list changes before
    /// the relay's lock is taken, and admit_locked asks it under that lock,
    /// so a registration that passed the list just before is either
    /// dropped here or refused when it is added.
    pub fn reload_refused(&self) {
        let Some(list) = &self.cfg.refused else { return };
        match list.reload() {
            Ok(true) => {}
            Ok(false) => return,
            Err(e) => {
                self.log(&format!("cbb relay: the list of refused groups, kept as it was: {e}"));
                return;
            }
        }
        self.log(&format!("cbb relay: the list of refused groups has {} now", list.len()));
        let mut st = self.lock();
        let gone: Vec<Arc<Member>> =
            st.groups.iter().filter(|(tag, _)| list.refused(tag)).flat_map(|(_, g)| g.values().cloned()).collect();
        for m in gone {
            self.drop_locked(&mut st, &m);
        }
    }

    /// Counts a registration being set up from the address from; false
    /// when there are too many, from there or in all.
    pub fn take_slot(&self, from: Option<IpAddr>) -> bool {
        let mut st = self.lock();
        if st.setups.full(from, 1).is_some() {
            return false;
        }
        // Setups are also paid for by the second, so a source that sets up
        // and closes over and over does not cost the relay more than its
        // share.
        let now = st.now();
        if !st.allow.take(from, limits::SETUP_COST, now) {
            return false;
        }
        st.setups.add(from, 1);
        true
    }

    pub fn free_slot(&self, from: Option<IpAddr>) {
        self.lock().setups.remove(from, 1);
    }

    /// Counts a request of m being read; false when there are too many, of
    /// m, of its group, of the address or network it registered from, or in
    /// all.
    pub fn take_request_locked(st: &mut State, m: &Member) -> bool {
        let Some(ms) = st.members.get(&m.id) else { return false };
        if ms.dropped
            || ms.reading >= MAX_REQUESTS_ONE
            || m.share.reads.load(Ordering::SeqCst) >= MAX_REQUESTS_GROUP
            || !st.requests.take(m.from, 1)
        {
            return false;
        }
        if let Some(ms) = st.members.get_mut(&m.id) {
            ms.reading += 1;
        }
        m.share.reads.fetch_add(1, Ordering::SeqCst);
        true
    }

    pub fn free_request(&self, m: &Member) {
        let mut st = self.lock();
        st.requests.remove(m.from, 1);
        if let Some(ms) = st.members.get_mut(&m.id) {
            ms.reading = ms.reading.saturating_sub(1);
        }
        m.share.reads.fetch_sub(1, Ordering::SeqCst);
    }

    /// Whether the relay would register m, in place of the same device's
    /// earlier registration and of the devices of its group that leaving
    /// tells go with it; it changes nothing, so a refused registration
    /// leaves the relay as it was.
    pub fn admit_locked(
        &self,
        st: &mut State,
        m: &Member,
        leaving: Option<&dyn Fn(&Member) -> bool>,
    ) -> std::result::Result<(), String> {
        if self.cfg.refused.as_ref().is_some_and(|l| l.refused(&m.tag)) {
            return Err(super::refused::MESSAGE.into());
        }
        if st.by_addr.values().any(|o| o.key == m.key && (o.tag != m.tag || o.device != m.device)) {
            return Err("another device registered that WireGuard key".into());
        }
        let g = st.groups.get(&m.tag);
        // The devices that m takes the place of free what they hold while
        // the count is asked, and hold it again after.
        let gone: Vec<Arc<Member>> = g
            .map(|g| {
                g.iter()
                    .filter(|(dev, o)| **dev == m.device || leaving.is_some_and(|l| l(o)))
                    .map(|(_, o)| o.clone())
                    .collect()
            })
            .unwrap_or_default();
        let members = g.map_or(0, |g| g.len());
        let has_group = g.is_some();
        let mut full = false;
        if self.cfg.open {
            for o in &gone {
                st.held.remove(o.from, 1);
            }
            full = st.held.full(m.from, 1).is_some();
            for o in &gone {
                st.held.add(o.from, 1);
            }
        }
        if members - gone.len() >= MAX_MEMBERS {
            return Err("the relay holds as many devices of this group as it can".into());
        }
        if self.cfg.open {
            if !has_group && st.groups.len() >= self.limits.groups {
                return Err("the relay serves as many groups as it can; try again later, or run your own relay".into());
            }
            if full {
                return Err("too many devices registered from this network; try again later".into());
            }
        }
        Ok(())
    }

    /// The share of the group tag: that of its devices, or a new one.
    pub fn share_locked(&self, st: &State, tag: &str) -> Arc<GroupShare> {
        if let Some(o) = st.groups.get(tag).and_then(|g| g.values().next()) {
            return o.share.clone();
        }
        let bytes = self.cfg.open.then(|| ByteRate::new(self.limits.byte_rate));
        Arc::new(GroupShare { pairs: AtomicUsize::new(0), reads: AtomicUsize::new(0), bytes })
    }

    /// Registers m, which admit_locked let through, in place of the same
    /// device's earlier registration, and gives the tunnel its key; it
    /// returns m's tunnel address.
    pub fn add_locked(&self, st: &mut State, m: &Arc<Member>) -> Result<Ipv6Addr> {
        if let Some(old) = st.groups.get(&m.tag).and_then(|g| g.get(&m.device)).cloned() {
            self.drop_locked(st, &old);
        }
        let addr = loop {
            let a = crate::tunnel::addr(&certs::random_id()).ok_or_else(|| Error::msg("relay: no tunnel address"))?;
            if !st.by_addr.contains_key(&a) && a != RELAY_ADDR {
                break a;
            }
        };
        st.groups.entry(m.tag.clone()).or_default().insert(m.device.clone(), m.clone());
        st.by_addr.insert(addr, m.clone());
        st.members.insert(m.id, MemberState { addr: Some(addr), ..MemberState::default() });
        if let Err(e) = self.set_peers_locked(st) {
            if let Some(g) = st.groups.get_mut(&m.tag) {
                g.remove(&m.device);
                if g.is_empty() {
                    st.groups.remove(&m.tag);
                }
            }
            st.by_addr.remove(&addr);
            st.members.remove(&m.id);
            return Err(e);
        }
        if self.cfg.open {
            st.held.add(m.from, 1);
        }
        Ok(addr)
    }

    fn set_peers_locked(&self, st: &State) -> Result<()> {
        let peers = st.by_addr.iter().map(|(a, m)| Peer { key: m.key, psk: m.psk, addr: *a, until: None }).collect();
        match self.hub.lock().ok().as_deref() {
            Some(Some(h)) => h.set_peers_at(peers, RELAY_ADDR),
            _ => Ok(()),
        }
    }

    /// Forgets m: its tunnel and its connections go at once.
    pub fn drop_locked(&self, st: &mut State, m: &Arc<Member>) {
        let Some(ms) = st.members.get_mut(&m.id) else { return };
        if ms.dropped {
            return;
        }
        ms.dropped = true;
        let _ = m.raw.shutdown(Shutdown::Both);
        for c in ms.streams.values() {
            let _ = c.shutdown(Shutdown::Both);
        }
        ms.notes = None;
        let addr = ms.addr;
        st.calls.retain(|_, c| c.from != m.id && c.to != m.id);
        let mut emptied = false;
        if let Some(g) = st.groups.get_mut(&m.tag)
            && g.get(&m.device).is_some_and(|o| Arc::ptr_eq(o, m))
        {
            g.remove(&m.device);
            if g.is_empty() {
                st.groups.remove(&m.tag);
                emptied = true;
            }
        }
        if emptied {
            // An open relay forgets a group once its last device goes, so
            // groups that come and go do not fill its memory.
            if self.cfg.open && !st.tag_locks.contains_key(&m.tag) {
                drop_records_locked(st, &m.tag);
            }
            st.periods.remove(&m.tag);
        }
        if let Some(a) = addr
            && st.by_addr.get(&a).is_some_and(|o| Arc::ptr_eq(o, m))
        {
            st.by_addr.remove(&a);
            if self.cfg.open {
                st.held.remove(m.from, 1);
            }
        }
        if self.set_peers_locked(st).is_err() {
            self.log("cbb relay: cannot set the tunnels");
        }
        self.announce_locked(st, &m.tag);
    }

    /// Tells each watching device of the group which others are on the
    /// relay now.
    fn announce_locked(&self, st: &mut State, tag: &str) {
        let Some(g) = st.groups.get(tag) else { return };
        let list: Vec<(u64, String)> = g.values().map(|m| (m.id, m.device.clone())).collect();
        for (id, dev) in &list {
            let mut others: Vec<String> = list.iter().filter(|(_, d)| d != dev).map(|(_, d)| d.clone()).collect();
            others.sort();
            Self::note_locked(st, *id, Note { online: Some(others), ..Note::default() });
        }
    }

    /// Queues a note for the device id; a device that does not take its
    /// notes loses its watch, and comes back with a new one.
    fn note_locked(st: &mut State, id: u64, n: Note) -> bool {
        let Some(ms) = st.members.get_mut(&id) else { return false };
        let Some(tx) = ms.notes.as_ref() else { return false };
        match tx.try_send(n) {
            Ok(()) => true,
            Err(TrySendError::Full(_)) => {
                if let Some(c) = ms.watch.and_then(|w| ms.streams.get(&w)) {
                    let _ = c.shutdown(Shutdown::Both);
                }
                false
            }
            Err(TrySendError::Disconnected(_)) => false,
        }
    }

    /// Takes the connections that come through the tunnels to the relay's
    /// member port.
    fn accept_streams(self: Arc<Self>, ln: TcpListener) {
        let _ = ln.set_nonblocking(true);
        while !self.stopping() {
            let (c, from) = match ln.accept() {
                Ok(x) => x,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(5));
                    continue;
                }
                Err(_) => continue,
            };
            let _ = c.set_nonblocking(false);
            let _ = c.set_nodelay(true);
            // The tunnel address names the device; a connection is served
            // only while its device is registered and within its share. The
            // hub notes the address as soon as its connection is made.
            let mut addr = None;
            for _ in 0..50 {
                addr = self.hub.lock().ok().and_then(|h| h.as_ref().and_then(|h| h.tunnel_addr(from.port())));
                if addr.is_some() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(2));
            }
            let mut st = self.lock();
            let m = addr.and_then(|a| st.by_addr.get(&a).cloned());
            let Some(m) = m.filter(|m| Self::take_request_locked(&mut st, m)) else {
                drop(st);
                let _ = c.shutdown(Shutdown::Both);
                continue;
            };
            let sid = st.next_id();
            let Ok(clone) = c.try_clone() else {
                drop(st);
                self.free_request(&m);
                continue;
            };
            if let Some(ms) = st.members.get_mut(&m.id) {
                ms.streams.insert(sid, clone);
            }
            let wait = st.request_wait;
            drop(st);
            let inner = self.clone();
            match spawn(move || inner.serve_stream(&m, sid, c, wait)) {
                Ok(t) => self.keep(t),
                Err(_) => continue,
            }
        }
    }

    /// Reads the request of m's connection c, waiting for it at most wait,
    /// and does what it asks.
    fn serve_stream(self: &Arc<Self>, m: &Arc<Member>, sid: u64, c: TcpStream, wait: Duration) {
        let req = match wire::read_request(&c, wait) {
            Ok(r) => r,
            Err(_) => {
                self.free_request(m);
                self.close_stream(m, sid, &c);
                return;
            }
        };
        if req.watch {
            self.free_request(m);
            self.serve_watch(m, sid, c);
        } else if !req.dial.is_empty() {
            self.serve_dial(m, sid, c, &req.dial);
        } else if !req.answer.is_empty() {
            self.free_request(m);
            self.serve_answer(m, sid, c, &req.answer);
        } else {
            self.free_request(m);
            let _ = wire::send_note(&c, &Note::error("an unknown request"), NOTE_TIMEOUT);
            self.close_stream(m, sid, &c);
        }
    }

    pub fn close_stream(&self, m: &Member, sid: u64, c: &TcpStream) {
        let _ = c.shutdown(Shutdown::Both);
        if let Some(ms) = self.lock().members.get_mut(&m.id) {
            ms.streams.remove(&sid);
        }
    }

    /// Sends m its notes on c until c or the registration ends.
    fn serve_watch(self: &Arc<Self>, m: &Arc<Member>, sid: u64, c: TcpStream) {
        let (tx, rx) = mpsc::sync_channel::<Note>(32);
        {
            let mut st = self.lock();
            let Some(ms) = st.members.get_mut(&m.id).filter(|ms| !ms.dropped) else {
                drop(st);
                self.close_stream(m, sid, &c);
                return;
            };
            if let Some(old) = ms.watch.and_then(|w| ms.streams.get(&w)) {
                let _ = old.shutdown(Shutdown::Both);
            }
            ms.watch = Some(sid);
            ms.notes = Some(tx);
            self.announce_locked(&mut st, &m.tag);
        }
        let gone = Arc::new(AtomicBool::new(false));
        // The device sends nothing more here; reading tells when it goes.
        let reader = c.try_clone().ok().and_then(|mut r| {
            let gone = gone.clone();
            spawn(move || {
                let _ = std::io::copy(&mut r, &mut std::io::sink());
                let _ = r.shutdown(Shutdown::Both);
                gone.store(true, Ordering::SeqCst);
            })
            .ok()
        });
        self.write_notes(&c, &rx, &gone);
        let _ = c.shutdown(Shutdown::Both);
        if let Some(r) = reader {
            let _ = r.join();
        }
        let mut st = self.lock();
        if let Some(ms) = st.members.get_mut(&m.id) {
            ms.streams.remove(&sid);
            if ms.watch == Some(sid) {
                ms.watch = None;
                ms.notes = None;
            }
        }
    }

    fn write_notes(&self, c: &TcpStream, rx: &Receiver<Note>, gone: &AtomicBool) {
        loop {
            match rx.recv_timeout(Duration::from_millis(200)) {
                Ok(n) => {
                    if wire::send_note(c, &n, NOTE_TIMEOUT).is_err() {
                        return;
                    }
                }
                Err(RecvTimeoutError::Timeout) if !gone.load(Ordering::SeqCst) && !self.stopping() => {}
                Err(_) => return,
            }
        }
    }

    /// Calls the device to and, once it answers, joins c to its connection.
    fn serve_dial(self: &Arc<Self>, m: &Arc<Member>, sid: u64, c: TcpStream, to: &str) {
        let ticket = {
            use base64::Engine;
            base64::engine::general_purpose::STANDARD.encode(certs::random_bytes::<16>())
        };
        let (tx, rx) = mpsc::sync_channel(1);
        let mut st = self.lock();
        let t = st.groups.get(&m.tag).and_then(|g| g.get(to)).cloned();
        let dropped = st.members.get(&m.id).is_none_or(|ms| ms.dropped);
        let msg = match &t {
            _ if dropped => "this device is not registered",
            None => "that device is not on the relay",
            Some(t) if Arc::ptr_eq(t, m) => "that device is not on the relay",
            Some(t) if st.members.get(&t.id).is_none_or(|ts| ts.notes.is_none()) => "that device is not listening yet",
            Some(t) if st.members.get(&t.id).is_some_and(|ts| ts.calls >= MAX_CALLS) => {
                "that device has too many calls waiting"
            }
            Some(_) if m.share.pairs.load(Ordering::SeqCst) >= MAX_PAIRS => {
                "this group has as many connections as the relay joins"
            }
            Some(_) => "",
        };
        let mut msg = msg.to_string();
        if msg.is_empty()
            && let Some(t) = &t
        {
            st.calls.insert(ticket.clone(), Call { from: m.id, to: t.id, answered: tx });
            if let Some(ts) = st.members.get_mut(&t.id) {
                ts.calls += 1;
            }
            if !Self::note_locked(
                &mut st,
                t.id,
                Note { call: m.device.clone(), ticket: ticket.clone(), ..Note::default() },
            ) {
                msg = "that device is not listening".into();
                st.calls.remove(&ticket);
                if let Some(ts) = st.members.get_mut(&t.id) {
                    ts.calls -= 1;
                }
            }
        }
        drop(st);
        self.free_request(m);
        let refuse = |msg: &str| {
            let _ = wire::send_note(&c, &Note::error(msg), NOTE_TIMEOUT);
            self.close_stream(m, sid, &c);
        };
        let (true, Some(t)) = (msg.is_empty(), t) else {
            refuse(&msg);
            return;
        };
        let deadline = Instant::now() + CALL_TIMEOUT;
        let mut other = None;
        while other.is_none() && Instant::now() < deadline && !self.stopping() {
            match rx.recv_timeout(Duration::from_millis(100).min(deadline - Instant::now())) {
                Ok(o) => other = Some(o),
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => break,
            }
        }
        let mut st = self.lock();
        if st.calls.get(&ticket).is_some_and(|cl| cl.from == m.id) {
            st.calls.remove(&ticket);
        } else if other.is_none() {
            // The answer came just as the wait ended.
            other = rx.try_recv().ok();
        }
        if let Some(ts) = st.members.get_mut(&t.id) {
            ts.calls = ts.calls.saturating_sub(1);
        }
        let live = |id: u64| st.members.get(&id).is_some_and(|ms| !ms.dropped);
        let ok = other.is_some() && live(m.id) && live(t.id) && m.share.pairs.load(Ordering::SeqCst) < MAX_PAIRS;
        if ok {
            m.share.pairs.fetch_add(1, Ordering::SeqCst);
        }
        drop(st);
        let (osid, other) = match other {
            Some(o) if ok => o,
            o => {
                if let Some((osid, o)) = o {
                    self.close_stream(&t, osid, &o);
                }
                refuse("that device did not answer");
                return;
            }
        };
        let joined = wire::send_note(&other, &Note { ok: true, ..Note::default() }, NOTE_TIMEOUT).is_ok()
            && wire::send_note(&c, &Note { ok: true, ..Note::default() }, NOTE_TIMEOUT).is_ok();
        if joined {
            let _ = c.set_write_timeout(None);
            let _ = other.set_write_timeout(None);
            splice(&c, &other, m.share.bytes.clone(), &self.stop);
        }
        m.share.pairs.fetch_sub(1, Ordering::SeqCst);
        self.close_stream(m, sid, &c);
        self.close_stream(&t, osid, &other);
    }

    /// Hands c to the call it answers; the dialing side joins them.
    fn serve_answer(&self, m: &Member, sid: u64, c: TcpStream, ticket: &str) {
        let mut st = self.lock();
        if st.calls.get(ticket).is_some_and(|cl| cl.to == m.id)
            && let Some(cl) = st.calls.remove(ticket)
            && let Ok(mine) = c.try_clone()
        {
            let _ = cl.answered.try_send((sid, mine));
            return;
        }
        drop(st);
        let _ = wire::send_note(&c, &Note::error("no such call"), NOTE_TIMEOUT);
        self.close_stream(m, sid, &c);
    }
}

/// Forgets the records of the group tag.
pub(super) fn drop_records_locked(st: &mut State, tag: &str) {
    if let Some(rs) = st.records.remove(tag) {
        let paid: Vec<(Option<IpAddr>, usize)> =
            rs.lock().map(|r| r.paid.iter().map(|(a, n)| (*a, *n)).collect()).unwrap_or_default();
        for (a, n) in paid {
            st.record_bytes.remove(a, n);
        }
    }
}

/// Copies between two connections until either ends, at the group's rate
/// when it has one.
fn splice(a: &TcpStream, b: &TcpStream, rate: Option<Arc<ByteRate>>, stop: &AtomicBool) {
    let (Ok(mut a_in), Ok(mut b_out)) = (a.try_clone(), b.try_clone()) else { return };
    let (Ok(mut b_in), Ok(mut a_out)) = (b.try_clone(), a.try_clone()) else { return };
    let done = Arc::new(AtomicBool::new(false));
    let back = {
        let rate = rate.clone();
        let done = done.clone();
        std::thread::Builder::new().stack_size(STACK).spawn(move || {
            limits::limited_copy(&mut a_out, &mut b_in, rate.as_deref(), &done);
            let _ = a_out.shutdown(Shutdown::Both);
            let _ = b_in.shutdown(Shutdown::Both);
        })
    };
    limits::limited_copy(&mut b_out, &mut a_in, rate.as_deref(), stop);
    done.store(true, Ordering::SeqCst);
    let _ = a.shutdown(Shutdown::Both);
    let _ = b.shutdown(Shutdown::Both);
    if let Ok(t) = back {
        let _ = t.join();
    }
}
