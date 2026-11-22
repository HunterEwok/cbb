// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! A member's link to the group's blind relay (docs/protocol.md, section
//! 14; `cbb-relay/3`, format section 9.4): the registration over TLS to the
//! relay known by its pin, with the certificate of the device's server key
//! for the period alone, the proof of a WireGuard key made for this
//! registration and the period's credentials (`Credentialed`), then the
//! tunnel to the relay (`tunnel::Link`), the watch that hears which devices
//! of the group are on the relay and who calls, and the connections the
//! relay joins end to end: the device with the lower name dials, the other
//! answers. The relay knows a device only by its pseudonym, the hash of its
//! server key; the link names the other devices to the app by the device
//! IDs their pseudonyms stand for. The member protocol's TLS runs over the
//! connections between the two devices; here they are only passed to the
//! app's own ports. The phones' kits (ffi/) use it.

pub(crate) mod v3;

use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::{Ipv6Addr, Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use serde::Serialize;

use crate::certs;
use crate::error::{Error, Result};
use crate::forward::{Registrar, prove};
use crate::identity::ExternalKey;
use crate::relayd::wire3::Register;
use crate::tunnel::{self, Link, State};

/// The registration's protocol.
pub use crate::relayd::wire3::PROTOCOL;
const PROOF_LABEL: &[u8] = b"cbb relay key";
/// The relay's own address inside the tunnels.
pub const RELAY_ADDR: Ipv6Addr = Ipv6Addr::new(0xfd00, 0x0cbb, 0, 0, 0, 0, 0, 1);

const MIN_BACKOFF: Duration = Duration::from_secs(1);
const MAX_BACKOFF: Duration = Duration::from_secs(60);
/// How often a dialer looks again whether to connect, while the device is
/// connected another way.
const WANT_CHECK: Duration = Duration::from_secs(5);
const SETUP_TIMEOUT: Duration = Duration::from_secs(15);
const CALL_TIMEOUT: Duration = Duration::from_secs(10);
/// How long a dial's port waits for the app's connection.
const DIAL_WAIT: Duration = Duration::from_secs(10);
const MAX_MEMBERS: usize = 64;
const MAX_CALLS: usize = 16;
/// The most pseudonyms the app names.
const MAX_NAMES: usize = 1024;
/// How often a registered link looks whether its credentials changed.
const CREDENTIAL_CHECK: Duration = Duration::from_secs(1);
/// The largest frame in the tunnel.
const MAX_NOTE: usize = 16 << 10;
const TICK: Duration = Duration::from_millis(100);

/// What the app does for the link: whether to connect to a device through
/// the relay now (false while it is connected another way), the ports of
/// the connections the relay joined, how the link stands, and its log.
pub trait Events: Send + Sync {
    fn wanted(&self, peer: &str) -> bool;
    /// A connection to peer waits at the loopback port: the app dials it
    /// and runs the member protocol as the TLS client.
    fn dial(&self, peer: &str, port: u16);
    /// A connection from peer comes to the app's member listener from this
    /// loopback port, before a byte of TLS, so that the app knows whose it
    /// is and checks it.
    fn calling(&self, peer: &str, port: u16);
    fn changed(&self, report: &Report);
    fn log(&self, line: &str);
}

/// What the link needs.
pub struct Config {
    /// The relay's address, the same for UDP and TCP, and the pins its key
    /// may have.
    pub endpoint: SocketAddr,
    pub pins: Vec<certs::KeyHash>,
    /// The app's member listener on the loopback address.
    pub member_port: u16,
    /// What the device registers with; None until the period's members'
    /// credential lists its server key, and the link waits. Each
    /// registration takes it as it is, and a change ends the registration,
    /// so that the next one uses it.
    pub credentials: Arc<Mutex<Option<Arc<Credentialed>>>>,
}

/// What a device registers with: its server key for the period and the
/// period's credentials (`cbb_core::blind::credential`).
pub struct Credentialed {
    /// The certificate of the server key, which the relay reads it from.
    cert: Vec<u8>,
    key: Arc<dyn ExternalKey>,
    /// The hubs' and the members' credentials, as envelopes.
    creds: Vec<Vec<u8>>,
    /// The period credential and the root's key that signed it, shown only
    /// to a relay that serves a list of groups.
    period: Vec<u8>,
    root: Vec<u8>,
    /// The device's pseudonym, and the device each pseudonym of the
    /// group's other devices stands for.
    name: String,
    names: HashMap<String, String>,
}

impl Credentialed {
    /// Takes the device's server key for the period, the period's hubs'
    /// and members' credentials, which must list the key, the period
    /// credential, the root's key that signed it, and the pseudonyms of the
    /// group's other devices with their device IDs; checked as the relay
    /// checks them, at now_ms.
    pub fn new(
        key: Arc<dyn ExternalKey>,
        creds: Vec<Vec<u8>>,
        period: Vec<u8>,
        root: Vec<u8>,
        names: HashMap<String, String>,
        now_ms: u64,
    ) -> Result<Credentialed> {
        let point = key.public();
        if point.len() != 65 || certs::p256_spki(&certs::p256_spki_of(&point)).is_none() {
            return Err(Error::msg("the server key is not a P-256 key"));
        }
        let leaf = cbb_core::records::key::Key::es256(point.clone()).hash().0;
        let mut all = creds.clone();
        all.push(period.clone());
        crate::relayd::register3::check(&all, &leaf, Some(&root), None, now_ms).map_err(Error::msg)?;
        if names.len() > MAX_NAMES {
            return Err(Error::msg("too many pseudonyms"));
        }
        if !names.iter().all(|(n, d)| valid_name(n) && certs::is_id(d)) {
            return Err(Error::msg("a pseudonym or its device ID is not valid"));
        }
        let cert = certs::server_cert_by(&point, &mut |tbs| crate::identity::sign_external(&*key, tbs))?;
        Ok(Credentialed { cert, key, creds, period, root, name: b64(&leaf), names })
    }

    /// What it registers with: the name and the credentials' hashes. Only a
    /// change of these makes the link register again.
    fn id(&self) -> String {
        let mut k = self.name.clone();
        for c in self.creds.iter().chain([&self.period]) {
            k.push(' ');
            k.push_str(&certs::hex(&certs::sha256(c)));
        }
        k
    }
}

fn b64(b: &[u8]) -> String {
    base64::Engine::encode(&base64::engine::general_purpose::STANDARD, b)
}

/// How the link stands.
#[derive(Clone, Default, Serialize, Debug, PartialEq)]
pub struct Report {
    /// Registered, with its tunnel and its watch.
    pub connected: bool,
    /// The other devices of the group on the relay.
    pub online: Vec<String>,
    /// The member connections through the relay now.
    pub through: usize,
    /// Why it is not connected.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// The running link; dropping it stops it and its connections.
pub struct Relay {
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl Relay {
    /// Keeps the device registered with the relay until dropped,
    /// registering again whenever the registration ends.
    pub fn start(cfg: Config, events: Arc<dyn Events>) -> Relay {
        let stop = Arc::new(AtomicBool::new(false));
        let thread = {
            let stop = stop.clone();
            std::thread::spawn(move || run(&Arc::new(cfg), &events, &stop))
        };
        Relay { stop, thread: Some(thread) }
    }
}

impl Drop for Relay {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

/// Sleeps d, or until stop.
fn pause(d: Duration, stop: &[&AtomicBool]) {
    let until = Instant::now() + d;
    while Instant::now() < until && !stop.iter().any(|s| s.load(Ordering::SeqCst)) {
        std::thread::sleep(TICK.min(until.saturating_duration_since(Instant::now())));
    }
}

/// Why the link waits: the device has nothing to register with yet.
const NOT_LISTED: &str = "the group's credentials do not list this device yet";

fn run(cfg: &Arc<Config>, events: &Arc<dyn Events>, stop: &Arc<AtomicBool>) {
    let mut backoff = MIN_BACKOFF;
    let mut waiting = false;
    while !stop.load(Ordering::SeqCst) {
        let Some(cred) = cfg.credentials.lock().ok().and_then(|c| c.clone()) else {
            if !waiting {
                waiting = true;
                events.log(&format!("cbb: sync away from home: the relay: {NOT_LISTED}"));
                events.changed(&Report { error: Some(NOT_LISTED.into()), ..Report::default() });
            }
            pause(CREDENTIAL_CHECK, &[stop]);
            continue;
        };
        waiting = false;
        let start = Instant::now();
        let err = match once(cfg, &cred, events, stop) {
            Ok(false) => return,
            Ok(true) => {
                events
                    .log("cbb: sync away from home: the group's credentials changed; registering with the relay again");
                backoff = MIN_BACKOFF;
                continue;
            }
            Err(e) => e,
        };
        if stop.load(Ordering::SeqCst) {
            return;
        }
        let msg = err.for_log();
        events.log(&format!("cbb: sync away from home: the relay: {msg}"));
        events.changed(&Report { error: Some(msg), ..Report::default() });
        if start.elapsed() > MAX_BACKOFF {
            backoff = MIN_BACKOFF;
        }
        pause(backoff, &[stop]);
        backoff = (backoff * 2).min(MAX_BACKOFF);
    }
}

/// A request in the tunnel: the watch, a dial of a device's name at the
/// relay, or the answer of a call's ticket (base64, as the link keeps
/// them).
#[derive(Default)]
pub(crate) struct Request<'a> {
    watch: bool,
    dial: &'a str,
    answer: &'a str,
}

/// A note of the relay in the tunnel.
#[derive(Default, Debug)]
pub(crate) struct Note {
    pub(crate) online: Option<Vec<String>>,
    pub(crate) call: String,
    pub(crate) ticket: String,
    pub(crate) ok: bool,
    pub(crate) error: String,
}

/// One registration with its tunnel and watch, until it ends or stop
/// (false), or until the credentials change (true).
fn once(cfg: &Arc<Config>, cred: &Credentialed, events: &Arc<dyn Events>, stop: &Arc<AtomicBool>) -> Result<bool> {
    // The relay gets a fresh WireGuard key at each registration, so the
    // key links no two of them.
    let wg_key: [u8; 32] = tunnel::new_key()?.try_into().map_err(|_| Error::msg("a bad WireGuard key"))?;
    let mut reg =
        Registrar::connect(cfg.endpoint, &cfg.pins, core::slice::from_ref(&cred.cert), &cred.key, PROTOCOL, "relay")?;
    let proof_key = reg.export(PROOF_LABEL)?;
    let stopped = || Error::msg("registering with the relay: stopped");
    let (e, wants_root) = v3::challenge(&reg.next_frame(stop)?.ok_or_else(stopped)?)?;
    let (public, proof) =
        prove(&wg_key, &e, &proof_key).ok_or_else(|| Error::msg("registering with the relay: a bad challenge"))?;
    let proof: [u8; 32] = proof.try_into().map_err(|_| Error::msg("registering with the relay: a bad proof"))?;
    let mut credentials = cred.creds.clone();
    if wants_root {
        // A relay that serves a list of groups knows them by their roots.
        credentials.push(cred.period.clone());
    }
    let root = wants_root.then(|| cred.root.clone());
    reg.send(&Register { key: public, proof, credentials, root }.write())?;
    let (key, psk, addr) = v3::welcome(&reg.next_frame(stop)?.ok_or_else(stopped)?)?;
    let own: Ipv6Addr = addr.parse().map_err(|_| Error::msg("the relay gave a bad tunnel address"))?;
    reg.set_waiting()?;
    let hub = tunnel::Hub {
        device: "relay".into(),
        key: key.to_vec(),
        psk: psk.to_vec(),
        endpoints: vec![cfg.endpoint],
        next: Vec::new(),
        obfuscation: None,
        vless: None,
        ..Default::default()
    };
    let log = {
        let events = events.clone();
        Arc::new(move |line: &str| events.log(line))
    };
    let link = Link::start_at(&State::with_key(&wg_key)?, &hub, own, RELAY_ADDR, log)?;
    let s = Arc::new(Session {
        cfg: cfg.clone(),
        name: cred.name.clone(),
        names: cred.names.clone(),
        was: cred.id(),
        events: events.clone(),
        at: link.local(),
        stop: AtomicBool::new(false),
        state: Mutex::new(SessionState::default()),
        conns: Mutex::new(HashMap::new()),
        threads: Mutex::new(Vec::new()),
    });
    let r = s.watch(&mut reg, &link, stop);
    s.end();
    r
}

#[derive(Default)]
struct SessionState {
    online: Vec<String>,
    dialers: HashMap<String, Arc<AtomicBool>>,
    through: usize,
    calls: usize,
}

/// A registration's connections: the dialers, the answers and what they
/// pass, all ended with it.
struct Session {
    cfg: Arc<Config>,
    /// The device's name at the relay, the device each pseudonym there
    /// stands for, and what the registration was made with.
    name: String,
    names: HashMap<String, String>,
    was: String,
    events: Arc<dyn Events>,
    /// The tunnel's loopback port to the relay's member port.
    at: SocketAddr,
    stop: AtomicBool,
    state: Mutex<SessionState>,
    /// Every connection open now, which end shuts down.
    conns: Mutex<HashMap<u64, TcpStream>>,
    threads: Mutex<Vec<JoinHandle<()>>>,
}

static NEXT_CONN: AtomicU64 = AtomicU64::new(1);

impl Session {
    fn watch(self: &Arc<Self>, reg: &mut Registrar, link: &Link, stop: &AtomicBool) -> Result<bool> {
        let mut w = TcpStream::connect_timeout(&self.at, SETUP_TIMEOUT)
            .map_err(|e| Error::msg(format!("the relay's tunnel does not answer: {e}")))?;
        w.set_write_timeout(Some(SETUP_TIMEOUT)).map_err(io_err)?;
        w.write_all(&v3::request(&Request { watch: true, ..Request::default() })?)
            .map_err(|e| Error::msg(format!("the relay's tunnel does not answer: {e}")))?;
        w.set_read_timeout(Some(Duration::from_millis(250))).map_err(io_err)?;
        let started = Instant::now();
        let mut checked = started;
        let mut heard = false;
        let mut inbox = Vec::new();
        let mut buf = [0u8; 4096];
        loop {
            if stop.load(Ordering::SeqCst) {
                return Ok(false);
            }
            if checked.elapsed() >= CREDENTIAL_CHECK {
                checked = Instant::now();
                if self.credentials_changed() {
                    return Ok(true);
                }
            }
            if reg.next_frame(stop).is_err() {
                return Err(Error::msg("the relay ended the registration"));
            }
            while let Some(f) = take_frame(&mut inbox)? {
                heard = true;
                self.note(v3::note(&f)?)?;
            }
            if !heard && !link.answered() && started.elapsed() > SETUP_TIMEOUT {
                return Err(Error::msg("the relay's tunnel does not answer"));
            }
            match w.read(&mut buf) {
                Ok(0) => return Err(Error::msg("the relay's watch ended")),
                Ok(n) => inbox.extend_from_slice(buf.get(..n).unwrap_or_default()),
                Err(e) if matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut) => {}
                Err(e) => return Err(Error::msg(format!("the relay's watch ended: {e}"))),
            }
        }
    }

    /// Whether the app changed what the device registers with since this
    /// registration.
    fn credentials_changed(&self) -> bool {
        let Ok(c) = self.cfg.credentials.lock() else { return false };
        c.as_ref().map(|c| c.id()) != Some(self.was.clone())
    }

    /// The device a name at the relay stands for: the device of a pseudonym
    /// the app named, or the name itself.
    fn device(&self, name: &str) -> String {
        self.names.get(name).cloned().unwrap_or_else(|| name.to_string())
    }

    fn note(self: &Arc<Self>, n: Note) -> Result<()> {
        if let Some(online) = n.online {
            // The relay holds at most MAX_MEMBERS devices of a group and
            // names them by pseudonym; a relay that says
            // otherwise is not one to trust.
            if online.len() > MAX_MEMBERS || !online.iter().all(|p| valid_name(p)) {
                return Err(Error::msg("the relay's watch sent a list of devices that is not valid"));
            }
            self.set_online(online);
        } else if !n.call.is_empty() && !n.ticket.is_empty() {
            if !valid_name(&n.call) || !valid_ticket(&n.ticket) || !self.take_call() {
                return Ok(());
            }
            let s = self.clone();
            self.spawn(move || {
                s.answer(&n.call, &n.ticket);
                if let Ok(mut st) = s.state.lock() {
                    st.calls = st.calls.saturating_sub(1);
                }
            });
        }
        Ok(())
    }

    fn take_call(&self) -> bool {
        let Ok(mut st) = self.state.lock() else { return false };
        if st.calls >= MAX_CALLS {
            return false;
        }
        st.calls += 1;
        true
    }

    fn spawn(&self, f: impl FnOnce() + Send + 'static) {
        let t = std::thread::spawn(f);
        if let Ok(mut ts) = self.threads.lock() {
            ts.retain(|t| !t.is_finished());
            ts.push(t);
        }
    }

    /// Keeps a dialer for each device on the relay that this one dials: the
    /// ones with a higher name.
    fn set_online(self: &Arc<Self>, online: Vec<String>) {
        let mut start = Vec::new();
        if let Ok(mut st) = self.state.lock() {
            st.dialers.retain(|p, stop| {
                let keep = online.contains(p);
                if !keep {
                    stop.store(true, Ordering::SeqCst);
                }
                keep
            });
            for p in &online {
                if st.dialers.contains_key(p) || self.name.as_str() >= p.as_str() {
                    continue;
                }
                let stop = Arc::new(AtomicBool::new(false));
                st.dialers.insert(p.clone(), stop.clone());
                start.push((p.clone(), stop));
            }
            st.online = online;
        }
        for (p, stop) in start {
            let s = self.clone();
            self.spawn(move || s.dial(&p, &stop));
        }
        self.report();
    }

    fn report(&self) {
        let r = match self.state.lock() {
            Ok(st) => Report {
                connected: true,
                online: st.online.iter().map(|p| self.device(p)).collect(),
                through: st.through,
                error: None,
            },
            Err(_) => return,
        };
        self.events.changed(&r);
    }

    /// Connects to peer through the relay whenever it is not connected
    /// another way, until stop or the session ends.
    fn dial(&self, peer: &str, stop: &AtomicBool) {
        let mut backoff = MIN_BACKOFF;
        while !stop.load(Ordering::SeqCst) && !self.stop.load(Ordering::SeqCst) {
            let mut wait = WANT_CHECK;
            if self.events.wanted(&self.device(peer)) {
                let start = Instant::now();
                let r = self.open(&Request { dial: peer, ..Request::default() }).and_then(|c| self.run(peer, c, true));
                if stop.load(Ordering::SeqCst) || self.stop.load(Ordering::SeqCst) {
                    return;
                }
                if let Err(e) = r {
                    self.events.log(&format!(
                        "cbb: sync away from home: connecting to {} through the relay: {}",
                        self.device(peer),
                        e.for_log()
                    ));
                }
                if start.elapsed() > MAX_BACKOFF {
                    backoff = MIN_BACKOFF;
                }
                wait = backoff;
                backoff = (backoff * 2).min(MAX_BACKOFF);
            }
            pause(wait, &[stop, &self.stop]);
        }
    }

    /// Takes a call from peer and passes it to the app.
    fn answer(&self, peer: &str, ticket: &str) {
        let r = self.open(&Request { answer: ticket, ..Request::default() }).and_then(|c| self.run(peer, c, false));
        if let Err(e) = r
            && !self.stop.load(Ordering::SeqCst)
        {
            self.events.log(&format!(
                "cbb: sync away from home: answering {} through the relay: {}",
                self.device(peer),
                e.for_log()
            ));
        }
    }

    /// Opens a connection to the relay's member port, sends req and waits
    /// until the relay joined it.
    fn open(&self, req: &Request) -> Result<(u64, TcpStream)> {
        let mut c = TcpStream::connect_timeout(&self.at, SETUP_TIMEOUT).map_err(io_err)?;
        let id = self.hold(&c)?;
        let r = (|| {
            c.set_write_timeout(Some(SETUP_TIMEOUT)).map_err(io_err)?;
            c.write_all(&v3::request(req)?).map_err(io_err)?;
            c.set_read_timeout(Some(CALL_TIMEOUT + SETUP_TIMEOUT)).map_err(io_err)?;
            // Exactly one frame: the member protocol follows it.
            let mut head = [0u8; 4];
            c.read_exact(&mut head).map_err(io_err)?;
            let mut f = vec![0u8; v3::length(head, MAX_NOTE)?];
            c.read_exact(&mut f).map_err(io_err)?;
            let n = v3::note(&f)?;
            if !n.ok {
                let why = if n.error.is_empty() { "no answer".to_string() } else { n.error };
                return Err(Error::msg(format!("the relay: {why}")));
            }
            c.set_read_timeout(None).map_err(io_err)?;
            c.set_write_timeout(None).map_err(io_err)?;
            Ok(())
        })();
        match r {
            Ok(()) => Ok((id, c)),
            Err(e) => {
                self.drop_conn(id);
                Err(e)
            }
        }
    }

    /// Runs a connection the relay joined, counting it: dialed, through a
    /// port the app dials; called, to the app's member listener.
    fn run(&self, peer: &str, (id, c): (u64, TcpStream), dialed: bool) -> Result<()> {
        if let Ok(mut st) = self.state.lock() {
            st.through += 1;
        }
        self.report();
        let r = if dialed { self.dialed(peer, &c) } else { self.called(peer, &c) };
        self.drop_conn(id);
        if let Ok(mut st) = self.state.lock() {
            st.through = st.through.saturating_sub(1);
        }
        self.report();
        r
    }

    fn dialed(&self, peer: &str, c: &TcpStream) -> Result<()> {
        let ln = TcpListener::bind("127.0.0.1:0").map_err(io_err)?;
        ln.set_nonblocking(true).map_err(io_err)?;
        self.events.dial(&self.device(peer), ln.local_addr().map_err(io_err)?.port());
        let until = Instant::now() + DIAL_WAIT;
        let k = loop {
            if let Some(k) = accept_own(&ln, crate::tunnel::tcp_table).map_err(io_err)? {
                break k;
            }
            if Instant::now() >= until || self.stop.load(Ordering::SeqCst) {
                return Err(Error::msg(format!("the app did not take the connection to {}", self.device(peer))));
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        k.set_nonblocking(false).map_err(io_err)?;
        self.splice(c, k)
    }

    fn called(&self, peer: &str, c: &TcpStream) -> Result<()> {
        let k = TcpStream::connect_timeout(&SocketAddr::from(([127, 0, 0, 1], self.cfg.member_port)), SETUP_TIMEOUT)
            .map_err(io_err)?;
        // The app learns whose connection it is before a byte of TLS
        // reaches it.
        self.events.calling(&self.device(peer), k.local_addr().map_err(io_err)?.port());
        self.splice(c, k)
    }

    /// Copies between the relay's connection and the app's until either
    /// ends or the session does.
    fn splice(&self, c: &TcpStream, k: TcpStream) -> Result<()> {
        let id = self.hold(&k)?;
        let (mut c_in, mut k_out) = (c.try_clone().map_err(io_err)?, k.try_clone().map_err(io_err)?);
        let up = std::thread::spawn(move || {
            let _ = io::copy(&mut c_in, &mut k_out);
            let _ = k_out.shutdown(Shutdown::Write);
        });
        let (mut k_in, mut c_out) = (k, c.try_clone().map_err(io_err)?);
        let _ = io::copy(&mut k_in, &mut c_out);
        let _ = c_out.shutdown(Shutdown::Write);
        let _ = up.join();
        self.drop_conn(id);
        Ok(())
    }

    /// Keeps c to shut down when the session ends.
    fn hold(&self, c: &TcpStream) -> Result<u64> {
        let id = NEXT_CONN.fetch_add(1, Ordering::SeqCst);
        let mut conns = self.conns.lock().map_err(|_| Error::msg("the relay's connections are broken"))?;
        if self.stop.load(Ordering::SeqCst) {
            return Err(Error::msg("the registration ended"));
        }
        conns.insert(id, c.try_clone().map_err(io_err)?);
        Ok(id)
    }

    fn drop_conn(&self, id: u64) {
        if let Some(c) = self.conns.lock().ok().and_then(|mut m| m.remove(&id)) {
            let _ = c.shutdown(Shutdown::Both);
        }
    }

    /// Ends the session: every dialer, answer and connection.
    fn end(&self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Ok(st) = self.state.lock() {
            for stop in st.dialers.values() {
                stop.store(true, Ordering::SeqCst);
            }
        }
        if let Ok(mut m) = self.conns.lock() {
            for (_, c) in m.drain() {
                let _ = c.shutdown(Shutdown::Both);
            }
        }
        let threads: Vec<JoinHandle<()>> = self.threads.lock().map(|mut t| t.drain(..).collect()).unwrap_or_default();
        for t in threads {
            let _ = t.join();
        }
    }
}

fn io_err(e: io::Error) -> Error {
    Error::msg(format!("a connection through the relay: {e}"))
}

/// A whole frame from the front of inbox, if one is there.
fn take_frame(inbox: &mut Vec<u8>) -> Result<Option<Vec<u8>>> {
    let Some(head) = inbox.get(..4).and_then(|h| <[u8; 4]>::try_from(h).ok()) else { return Ok(None) };
    let n = v3::length(head, MAX_NOTE)?;
    let Some(f) = inbox.get(4..4 + n).map(<[u8]>::to_vec) else { return Ok(None) };
    inbox.drain(..4 + n);
    Ok(Some(f))
}

/// Whether s is a device's name at the relay: its pseudonym, 32 bytes in
/// standard base64.
pub fn valid_name(s: &str) -> bool {
    canonical_b64(s, 32)
}

/// Whether s is a call's ticket: 16 bytes in standard base64.
pub fn valid_ticket(s: &str) -> bool {
    canonical_b64(s, 16)
}

fn canonical_b64(s: &str, len: usize) -> bool {
    use base64::Engine;
    let e = &base64::engine::general_purpose::STANDARD;
    e.decode(s).is_ok_and(|b| b.len() == len && e.encode(&b) == s)
}

/// Takes a connection to ln, a loopback listener that does not block, when
/// one of this process's user is waiting: the port is on the loopback, where
/// every local user may connect, and another's connection is closed, so it
/// neither takes the call nor ends the wait for the app's. table gives the
/// kernel's tables of TCP sockets.
fn accept_own(ln: &TcpListener, table: impl Fn() -> String) -> io::Result<Option<TcpStream>> {
    let to = ln.local_addr().ok();
    loop {
        match ln.accept() {
            Ok((k, from)) if crate::tunnel::own_user(&table(), from, to) => return Ok(Some(k)),
            Ok((k, _)) => drop(k),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Ok(None),
            Err(e) => return Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The app's port for a dialed call takes this user's connection only.
    #[test]
    fn dialed_port_takes_its_own_user() {
        let ln = TcpListener::bind("127.0.0.1:0").unwrap();
        ln.set_nonblocking(true).unwrap();
        assert!(accept_own(&ln, crate::tunnel::tcp_table).unwrap().is_none());
        let c = TcpStream::connect(ln.local_addr().unwrap()).unwrap();
        // Another user's connection, as the kernel's table would show it.
        let hex = |a: SocketAddr| match a {
            SocketAddr::V4(a) => format!("{:08X}:{:04X}", u32::from_ne_bytes(a.ip().octets()), a.port()),
            _ => unreachable!(),
        };
        let (from, to) = (c.local_addr().unwrap(), ln.local_addr().unwrap());
        let other = crate::sys::euid() + 1;
        let table = move || {
            format!(
                "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n   0: {} {} 01 00000000:00000000 00:00000000 00000000 {other:5} 0 1 1\n",
                hex(from),
                hex(to)
            )
        };
        // The stranger's connection is closed, never taken, and the wait goes on.
        c.set_read_timeout(Some(Duration::from_millis(20))).unwrap();
        let until = Instant::now() + Duration::from_secs(5);
        loop {
            assert!(accept_own(&ln, table).unwrap().is_none(), "a stranger's connection took the call");
            if matches!((&c).read(&mut [0u8; 1]), Ok(0)) {
                break;
            }
            assert!(Instant::now() < until, "a stranger's connection was not closed");
        }
        let _c2 = TcpStream::connect(ln.local_addr().unwrap()).unwrap();
        let until = Instant::now() + Duration::from_secs(5);
        loop {
            if accept_own(&ln, crate::tunnel::tcp_table).unwrap().is_some() {
                break;
            }
            assert!(Instant::now() < until, "this user's connection was not taken");
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    #[test]
    fn names_and_tickets() {
        // A device ID is no name at the relay: it names devices by pseudonym.
        assert!(!valid_name("00112233445566778899aabbccddeeff"));
        assert!(valid_name(&("A".repeat(43) + "=")));
        assert!(!valid_name("relay"));
        assert!(valid_ticket("AAAAAAAAAAAAAAAAAAAAAA=="));
        assert!(!valid_ticket("AAAAAAAAAAAAAAAAAAAAAA"));
        let ok = v3::request(&Request { watch: true, ..Request::default() }).unwrap();
        let mut inbox = ok.clone();
        inbox.extend_from_slice(&[0, 0]);
        assert_eq!(take_frame(&mut inbox).unwrap(), Some(ok[4..].to_vec()));
        assert_eq!(take_frame(&mut inbox).unwrap(), None);
        assert_eq!(inbox, vec![0, 0]);
    }
}

#[cfg(test)]
#[path = "nettest/relay.rs"]
mod net_tests;
