// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The member protocol (docs/protocol.md, section 4) on a lite member: it
//! dials the computers, and takes the connections of phones and of the
//! lite members with a lower device ID; it sends its hello, forwards each
//! event the first time the engine sees it to every other connection,
//! exchanges the group's records and keeps a renewed certificate.
//!
//! Each connection has two threads: the one that dialed or accepted reads, and a writer
//! sends what is queued, and a ping after 5 seconds of silence. Both use
//! the TLS state under a lock; only the reader waits on the socket without
//! it.

use std::collections::{HashMap, VecDeque};
use std::io::{self, Read};
use std::net::{Shutdown, SocketAddr, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError, SyncSender, TryRecvError, TrySendError};
use std::sync::{Arc, Condvar, Mutex, RwLock};
use std::time::Duration;

use crate::certs::{Cert, DeviceId, Usage};
use cbb_core::copy::{self, Content, Sealed};

use crate::clip::{Engine, Event, Hello, Kind, Outcome, SealFn, Via};
use crate::content::{Source, Store};
use crate::entries::{self, Entries};
use crate::error::{Context, Error, Result};
use crate::identity::Identity;
use crate::identity::Stored as _;
use crate::pair::home_address;
use crate::records::Stored as _;
use crate::records::{Record, Records, Refusal};
use crate::tls;
use crate::uptime;
use crate::wire::{self, Message};
use cbb_core::media::{Manifest, Part};

/// How long a device that discovery finds counts as at home without a
/// connection to it (docs/protocol.md, section 11).
#[cfg_attr(not(feature = "tunnel"), allow(dead_code))] // used by sync away from home
const NEAR_GRACE: Duration = Duration::from_secs(30);
/// The devices found at home that are remembered, as many as a home group
/// has and more.
const MAX_HOME: usize = 64;

const PING_EVERY: Duration = Duration::from_secs(5);
const TIMEOUT: Duration = Duration::from_secs(15);
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const QUEUE_LEN: usize = 256;
const RECORDS_CHUNK: usize = 1 << 20;
/// The slowest transfer a frame is given time for.
const MIN_RATE: usize = 16 << 10;
/// The most gets a peer may have waiting on a connection.
const MAX_GETS: usize = 64;
/// How far ahead a fetch asks, and how long it waits for a chunk.
const FETCH_AHEAD: u64 = 4 << 20;
const FETCH_IDLE: Duration = Duration::from_secs(15);

/// A text to put into the member's own clipboard.
#[derive(Clone, Debug)]
pub struct WriteReq {
    /// The copy's ID, which a phone's app fetches images or files by.
    pub id: String,
    pub text: String,
    /// The manifest of a copy with images or files.
    pub media: Option<Manifest>,
    pub kind: Kind,
    pub via: Via,
    pub seq: u64,
    /// For a secret: how long it may stay in the clipboard.
    pub ttl: Option<Duration>,
}

/// A connected member, as its hello and its reach messages present it:
/// shown, never trusted.
#[derive(Clone, Debug)]
pub struct Peer {
    pub id: DeviceId,
    pub role: String,
    pub name: String,
    /// Its operating system, from its hello; empty when it sent none.
    pub os: String,
    /// Where its keys live: `file`, `hardware` or `rootless`; empty if unknown.
    pub key_store: String,
    /// Its sync mode: `own`, `shared`, `receive` or `send`; empty if unknown.
    pub mode: String,
    /// Whether it is muted, and for how many milliseconds more (0: until
    /// the mute is lifted).
    pub muted: bool,
    pub muted_for_ms: i64,
    /// The quick actions that are on there.
    pub actions: Vec<String>,
    pub device: cbb_core::wire::DeviceInfo,
    /// The admin key a full member that is not an admin yet offers.
    pub admin_key: Option<Vec<u8>>,
    /// The tunnel key and preshared key it offers the group's hubs.
    pub tunnel_key: Option<(Vec<u8>, Vec<u8>)>,
    /// The members it says it is connected to (docs/protocol.md, section 4,
    /// "Reach").
    pub reach: Vec<DeviceId>,
    /// Whether the connection carries records only: no device record lets
    /// the peer in yet.
    pub records_only: bool,
    /// What it supports beyond its protocol version: `media` from one that
    /// serves the content of media events.
    pub features: Vec<String>,
}

/// The most device IDs a reach message is read for.
const MAX_REACH: usize = 256;
/// The most commands remembered as passed on, as Go's.
const MAX_PASSED: usize = 4096;

/// Gets the messages a peer sends that the node does not handle itself:
/// `admin`, `hubs` and `credentials` for a phone's app, which keeps them.
pub type OnMessage = Box<dyn Fn(&DeviceId, &Message) + Send + Sync>;

/// Called with a tunnel offer and the device that sent it.
/// Gets a tunnel offer from the group's root or an admin, and whether the
/// records make a device the root or an admin, by its ID alone.
pub type OnTunnel = Box<dyn Fn(&DeviceId, &serde_json::Value, &dyn Fn(&str) -> bool) + Send + Sync>;

/// Carries out a command a peer sent (docs/protocol.md, section 15) and
/// gives the answer. It runs on a thread of its own: a remote paste waits
/// for its target.
pub type OnCommand = Arc<dyn Fn(&DeviceId, &Record) -> wire::CommandResult + Send + Sync>;

/// The tunnel key and preshared key a hello offers; None while sync away
/// from home is off.
type TunnelKeys = Option<(Vec<u8>, Vec<u8>)>;

/// The lite member's set of connections.
/// How the member presents itself in its hellos: the lite member, or a
/// phone's app that runs it (crate::phone).
#[derive(Clone)]
pub struct Presence {
    pub role: String,
    pub name: String,
    pub os: String,
    /// Where the device key is: "file", "rootless" or "hardware".
    pub key_store: String,
    pub device: cbb_core::wire::DeviceInfo,
}

pub struct Node {
    ident: RwLock<Arc<Identity>>,
    presence: Arc<Presence>,
    pub engine: Arc<Engine>,
    records: Arc<Mutex<Records>>,
    state_dir: PathBuf,
    conns: Mutex<HashMap<DeviceId, Arc<Conn>>>,
    on_write: Box<dyn Fn(WriteReq) + Send + Sync>,
    log: Arc<dyn Fn(&str) + Send + Sync>,
    closed: AtomicBool,
    /// The tunnel key and preshared key the hellos offer the group's hubs;
    /// None while sync away from home is off.
    tunnel_key: Arc<RwLock<TunnelKeys>>,
    on_tunnel: RwLock<Option<OnTunnel>>,
    on_command: RwLock<Option<OnCommand>>,
    /// The quick actions that are on here, which the hellos name.
    actions: RwLock<Vec<String>>,
    /// The members discovery finds on the home network now.
    /// The devices discovery finds on the home network, by the uptime they
    /// were first found.
    home: Mutex<HashMap<DeviceId, Duration>>,
    /// The signed entry points this member holds and passes on.
    entries: Arc<Entries>,
    /// Keeps the identity when it changes (a renewed certificate, a new
    /// root), where identity.json cannot: a phone's app whose key is
    /// outside the core keeps its own file.
    keep_identity: Option<KeepIdentity>,
    /// Paused: the connections are closed and no new one is made, while a
    /// phone's app is in the background.
    paused: AtomicBool,
    /// Wakes the dial loops early: the member resumed or found an address.
    kick: (Mutex<u64>, Condvar),
    /// The commands this member sent, by ID, waiting for their results.
    waiting: Mutex<HashMap<String, Waiting>>,
    /// The commands a phone passed on, by ID: where each came from, and
    /// when it expires (docs/protocol.md, section 15).
    passed: Mutex<HashMap<String, (DeviceId, i64)>>,
    on_message: RwLock<Option<OnMessage>>,
    /// The sealed blobs of copies with images or files, for a phone's app,
    /// which makes, fetches and serves them; None on the lite member.
    content: Option<Arc<Store>>,
    /// Gets each copy that becomes the group's current one from a peer,
    /// for a phone's app, which shows it and fetches images or files.
    on_change: RwLock<Option<OnChange>>,
}

/// Gets a copy that became the group's current one.
pub type OnChange = Box<dyn Fn(&Event) + Send + Sync>;

/// A piece of a fetch a connection's reader hands on.
enum Piece {
    Chunk(wire::Chunk),
    Missing,
}

/// A frame as it arrives: a message, or a chunk of a blob.
enum Frame {
    Message(Box<Message>),
    Chunk(wire::Chunk),
}

/// Keeps a changed identity in place of identity.json.
pub type KeepIdentity = Box<dyn Fn(&Identity) -> Result<()> + Send + Sync>;

enum Out {
    Hello(Hello, Duration, crate::clip::Mode, Option<i64>, Vec<String>),
    Event(Event, Duration),
    Records(Vec<Record>),
    Result(wire::CommandResult),
    Entries(serde_json::Value),
    /// A message made before it was queued: a command, a cert, an offer.
    Message(Message),
    Wake, // makes the writer look at the closed flag
}

/// A command this member sent, waiting for its result.
struct Waiting {
    to: DeviceId,
    tx: SyncSender<wire::CommandResult>,
}

/// The header of a command's body, for sending and passing it on.
#[derive(serde::Deserialize, Default)]
struct CommandHead {
    #[serde(rename = "type", default)]
    kind: String,
    #[serde(default)]
    to: String,
    #[serde(default)]
    id: String,
    #[serde(default)]
    expires_ms: i64,
}

impl CommandHead {
    fn of(r: &Record) -> Option<CommandHead> {
        serde_json::from_slice::<CommandHead>(&r.body).ok().filter(|h| !h.id.is_empty() && h.id.len() <= 64)
    }
}

struct Conn {
    id: DeviceId,
    sock: TcpStream,
    tls: Mutex<tls::Session>,
    tx: SyncSender<Out>,
    peer: Mutex<Option<Peer>>, // from the hello
    chain: Vec<Cert>,
    /// No device record that counts names the peer's key yet: the
    /// connection carries records and nothing else, until the records let
    /// the peer in and it connects again as a member.
    records_only: bool,
    closed: AtomicBool,
    bye: AtomicBool,
    /// The gets the peer asked for, served in order a chunk at a time.
    gets: Mutex<VecDeque<wire::Get>>,
    /// The fetches waiting for the peer's chunks, by blob.
    sinks: Mutex<HashMap<[u8; 32], SyncSender<Piece>>>,
}

impl Node {
    pub fn new(
        ident: Identity,
        name: &str,
        engine: Arc<Engine>,
        records: Records,
        state_dir: PathBuf,
        on_write: Box<dyn Fn(WriteReq) + Send + Sync>,
        log: Arc<dyn Fn(&str) + Send + Sync>,
    ) -> Node {
        let entries = Arc::new(Entries::open(&state_dir, crate::update::release_roots(), uptime::wall_ms(), &*log));
        engine.set_live_window(live_window(&records));
        Node {
            ident: RwLock::new(Arc::new(ident)),
            presence: Arc::new(Presence {
                role: "lite".into(),
                name: name.to_string(),
                os: "linux".into(),
                key_store: if crate::rootless::is() { "rootless" } else { "file" }.into(),
                device: crate::device::own().clone(),
            }),
            engine,
            records: Arc::new(Mutex::new(records)),
            state_dir,
            conns: Mutex::new(HashMap::new()),
            on_write,
            log,
            closed: AtomicBool::new(false),
            tunnel_key: Arc::new(RwLock::new(None)),
            on_tunnel: RwLock::new(None),
            on_command: RwLock::new(None),
            actions: RwLock::new(Vec::new()),
            home: Mutex::new(HashMap::new()),
            entries,
            keep_identity: None,
            paused: AtomicBool::new(false),
            kick: (Mutex::new(0), Condvar::new()),
            waiting: Mutex::new(HashMap::new()),
            passed: Mutex::new(HashMap::new()),
            on_message: RwLock::new(None),
            content: None,
            on_change: RwLock::new(None),
        }
    }

    /// Sets what gets each copy that becomes the group's current one from
    /// a peer.
    pub fn on_change(&self, f: OnChange) {
        *self.on_change.write().unwrap() = Some(f);
    }

    /// The node keeping, fetching and serving the blobs of copies with
    /// images or files in its state folder, as a phone's app does.
    pub fn with_content(mut self) -> Node {
        self.content = Some(Arc::new(Store::open(&self.state_dir)));
        self
    }

    /// The node keeping its identity through f, not in identity.json.
    pub fn keeping_identity(mut self, f: KeepIdentity) -> Node {
        self.keep_identity = Some(f);
        self
    }

    fn save_identity(&self, id: &Identity) -> Result<()> {
        match &self.keep_identity {
            Some(f) => f(id),
            None => id.save(&self.state_dir),
        }
    }

    /// The node presenting itself as p in its hellos, before it connects.
    pub fn presenting(mut self, p: Presence) -> Node {
        self.presence = Arc::new(p);
        self
    }

    /// Sets the tunnel key and preshared key the hellos offer from now on,
    /// and connects to the full members again, so that the group's hubs get
    /// them.
    pub fn set_tunnel_key(&self, key: TunnelKeys) {
        *self.tunnel_key.write().unwrap() = key;
        for c in self.conns.lock().unwrap().values() {
            if c.peer.lock().unwrap().as_ref().is_some_and(|p| p.role == "full") {
                c.close(true);
            }
        }
    }

    /// Connects to every member again, so that the hellos say what changed.
    pub fn reconnect(&self) {
        for c in self.conns.lock().unwrap().values() {
            c.close(true);
        }
    }

    /// Sets the quick actions the hellos name from now on; a peer sees a
    /// change at its next connection.
    pub fn set_actions(&self, on: Vec<String>) {
        *self.actions.write().unwrap() = on;
    }

    /// Sets what carries out the commands peers send.
    pub fn on_command(&self, f: OnCommand) {
        *self.on_command.write().unwrap() = Some(f);
    }

    /// The group's records.
    pub fn records(&self) -> Arc<Mutex<Records>> {
        self.records.clone()
    }

    /// Sets what is called with the tunnel offers of full members.
    pub fn on_tunnel(&self, f: OnTunnel) {
        *self.on_tunnel.write().unwrap() = Some(f);
    }

    /// Records whether discovery finds the device on the home network.
    pub fn found(&self, id: &DeviceId, here: bool) {
        remember_found(&mut self.home.lock().unwrap(), id, here, uptime::now);
    }

    /// Reports whether discovery found the device on the home network within
    /// NEAR_GRACE. Anyone on a network can announce a device's name and the
    /// group's tag, so past that only a connection to it counts.
    #[cfg_attr(not(feature = "tunnel"), allow(dead_code))] // used by sync away from home
    pub fn at_home(&self, id: &DeviceId) -> bool {
        self.home.lock().unwrap().get(id).is_some_and(|at| uptime::now().saturating_sub(*at) < NEAR_GRACE)
    }

    pub fn identity(&self) -> Arc<Identity> {
        self.ident.read().unwrap().clone()
    }

    pub fn logf(&self, s: &str) {
        (self.log)(s)
    }

    /// Reports whether a connection to the device is up.
    pub fn connected(&self, id: &DeviceId) -> bool {
        self.conns.lock().unwrap().contains_key(id)
    }

    /// How far the records stop the exchange: "secrets" or "full", empty
    /// when nothing stops.
    pub fn stop(&self) -> String {
        let s = self.records.lock().unwrap().stop();
        if s == cbb_core::authority::STOP_NONE { String::new() } else { s }
    }

    /// Whether the records stop secrets to this member (docs/protocol.md,
    /// section 10, "Stopping the exchange"): it then takes no secret paste.
    pub fn secrets_stopped(&self) -> bool {
        let id = self.ident.read().unwrap().id.clone();
        self.records.lock().unwrap().no_secrets_to(id.as_str())
    }

    /// The connected members that sent their hello, sorted by device ID.
    pub fn peers(&self) -> Vec<Peer> {
        let mut out: Vec<Peer> = self.all_peers().into_iter().filter(|p| !p.records_only).collect();
        out.sort_by(|a, b| a.id.cmp(&b.id));
        out
    }

    /// The certificate chains the members connected sent, leaf first, by
    /// device: those an admin's app renews.
    pub fn peer_chains(&self) -> Vec<(DeviceId, Vec<Cert>)> {
        let conns = self.conns.lock().unwrap();
        conns.values().filter(|c| !c.records_only).map(|c| (c.id.clone(), c.chain.clone())).collect()
    }

    /// The connected members that sent their hello, those whose connection
    /// carries records only among them, sorted by device ID.
    pub fn all_peers(&self) -> Vec<Peer> {
        let conns = self.conns.lock().unwrap();
        let mut out: Vec<Peer> = conns.values().filter_map(|c| c.peer.lock().unwrap().clone()).collect();
        out.sort_by(|a, b| a.id.cmp(&b.id));
        out
    }

    /// Sets what gets the messages the node leaves to its app.
    pub fn on_message(&self, f: OnMessage) {
        *self.on_message.write().unwrap() = Some(f);
    }

    /// Closes every connection with a goodbye and makes no new one until
    /// resume: a phone's app going to the background.
    pub fn pause(&self) {
        self.paused.store(true, Ordering::SeqCst);
        for c in self.conns.lock().unwrap().values() {
            c.close(true);
        }
    }

    /// Lets the member connect again after pause, at once.
    pub fn resume(&self) {
        self.paused.store(false, Ordering::SeqCst);
        self.kick();
    }

    pub fn is_paused(&self) -> bool {
        self.paused.load(Ordering::SeqCst)
    }

    /// Wakes whatever waits in nap.
    pub fn kick(&self) {
        let (m, cv) = &self.kick;
        *m.lock().unwrap() += 1;
        cv.notify_all();
    }

    /// Waits up to d, or until kick; reports whether it was kicked.
    pub fn nap(&self, d: Duration) -> bool {
        let (m, cv) = &self.kick;
        let g = m.lock().unwrap();
        let start = *g;
        let (g, _) = cv.wait_timeout_while(g, d, |n| *n == start && !self.is_closed()).unwrap();
        *g != start
    }

    /// Waits up to timeout for a member to connect and say its hello;
    /// reports whether one did.
    pub fn wait_connected(&self, timeout: Duration) -> bool {
        let end = uptime::now() + timeout;
        loop {
            if !self.peers().is_empty() {
                return true;
            }
            let now = uptime::now();
            if now >= end || self.is_closed() {
                return false;
            }
            std::thread::sleep((end - now).min(Duration::from_millis(100)));
        }
    }

    /// Queues a message for the member id; reports whether it is
    /// connected as a member.
    pub fn send_to(&self, id: &DeviceId, m: Message) -> bool {
        let c = self.conns.lock().unwrap().get(id).cloned();
        match c {
            Some(c) if !c.records_only => {
                self.enqueue(&c, Out::Message(m));
                true
            }
            _ => false,
        }
    }

    /// Queues a message for every member connected; returns those it went
    /// to.
    pub fn broadcast(&self, m: &Message, only: impl Fn(&Peer) -> bool) -> Vec<DeviceId> {
        let conns: Vec<Arc<Conn>> = self.conns.lock().unwrap().values().cloned().collect();
        let mut to = Vec::new();
        for c in conns.iter().filter(|c| !c.records_only) {
            let ok = c.peer.lock().unwrap().as_ref().is_some_and(&only);
            if ok {
                self.enqueue(c, Out::Message(m.clone()));
                to.push(c.id.clone());
            }
        }
        to
    }

    /// Makes a copy of images or files from the parts the app hands in:
    /// seals their blob, keeps it to serve, and sends the copy.
    pub fn send_media(&self, text: &str, parts: Vec<(Part, Source)>) -> Result<Event> {
        let store = self.content.as_ref().ok_or_else(|| Error::msg("this member keeps no images or files"))?;
        let key = copy::new_key();
        let (manifest, blob) = store.seal(parts, &key)?;
        let ev = self.engine.send_media(text, manifest, Via::Phone, key, blob)?;
        self.forward(&ev, None);
        Ok(ev)
    }

    /// Fetches the sealed blob of the media copy ev from the members that
    /// serve content, its origin first, unless it is held already or larger
    /// than max bytes (docs/protocol.md, section 4, "Content").
    pub fn fetch(&self, ev: &Event, max: u64) -> Result<()> {
        let store = self.content.as_ref().ok_or_else(|| Error::msg("this member keeps no images or files"))?;
        let Some(blob) = ev.sealed.as_ref().and_then(|s| s.blob.clone()) else { return Ok(()) };
        let sum: [u8; 32] = blob.sha256.clone().try_into().map_err(|_| Error::msg("the copy's blob has no hash"))?;
        let size = u64::try_from(blob.size).map_err(|_| Error::msg("the copy's blob has no size"))?;
        if size > max {
            return Err(Error::msg(format!(
                "the copy's images or files are {} MiB, more than the {} MiB this phone fetches",
                size.div_ceil(1 << 20),
                max >> 20
            )));
        }
        if store.held(&sum) == Some(size) {
            return Ok(());
        }
        let mut peers: Vec<Arc<Conn>> = self
            .conns
            .lock()
            .unwrap()
            .values()
            .filter(|c| !c.records_only)
            .filter(|c| c.peer.lock().unwrap().as_ref().is_some_and(|p| p.features.iter().any(|f| f == "media")))
            .cloned()
            .collect();
        peers.sort_by_key(|c| c.id.as_str() != ev.origin);
        let mut last = Error::msg("no member that serves images or files is connected");
        for c in peers {
            match self.fetch_from(&c, store, &sum, size) {
                Ok(()) => return store.finish(&sum, size),
                Err(e) => {
                    self.logf(&format!("cbb: fetching a copy's content from {}: {}", c.id, e.for_log()));
                    last = e;
                }
            }
        }
        Err(last)
    }

    /// Fetches the blob sum from one peer into the store's partial file,
    /// continuing from what it holds.
    fn fetch_from(&self, c: &Arc<Conn>, store: &Store, sum: &[u8; 32], size: u64) -> Result<()> {
        use std::io::{Seek, Write};
        let path = store.partial(sum);
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).context("make the folder of the copies' content")?;
        }
        let mut f = std::fs::OpenOptions::new().create(true).append(true).open(&path).context("keep a fetch")?;
        let mut have = f.metadata().map(|m| m.len()).unwrap_or(0);
        if have > size {
            f.set_len(0).context("keep a fetch")?;
            f.seek(std::io::SeekFrom::Start(0)).context("keep a fetch")?;
            have = 0;
        }
        let (tx, rx) = mpsc::sync_channel(16);
        c.sinks.lock().unwrap().insert(*sum, tx);
        let get = |offset: u64, length: u64| {
            wire::get(wire::Get { sha256: sum.to_vec(), offset: offset as i64, length: length as i64 })
        };
        let mut asked = have;
        let mut idle = Duration::ZERO;
        let res = loop {
            while asked < size && asked - have < FETCH_AHEAD {
                let len = (size - asked).min(wire::MAX_GET as u64);
                self.enqueue(c, Out::Message(get(asked, len)));
                asked += len;
            }
            if have == size {
                break Ok(());
            }
            if c.closed.load(Ordering::SeqCst) || self.is_closed() {
                break Err(Error::msg("the connection ended"));
            }
            match rx.recv_timeout(Duration::from_secs(1)) {
                Ok(Piece::Chunk(ch)) if ch.offset == have && !ch.data.is_empty() => {
                    let n = (ch.data.len() as u64).min(size - have) as usize;
                    if let Err(e) = f.write_all(&ch.data[..n]) {
                        break Err(Error::msg(format!("keep a fetch: {e}")));
                    }
                    have += n as u64;
                    idle = Duration::ZERO;
                }
                Ok(Piece::Chunk(_)) => {}
                Ok(Piece::Missing) => break Err(Error::msg("it does not hold the copy's content")),
                Err(_) => {
                    idle += Duration::from_secs(1);
                    if idle >= FETCH_IDLE {
                        break Err(Error::msg("no chunk came for 15 s"));
                    }
                }
            }
        };
        c.sinks.lock().unwrap().remove(sum);
        if res.is_err() {
            self.enqueue(c, Out::Message(get(0, 0)));
        }
        res
    }

    /// Opens the media copy ev, fetched with fetch, into the new folder out;
    /// each part with where it is.
    pub fn open_media(&self, ev: &Event, out: &std::path::Path) -> Result<Vec<(Part, PathBuf)>> {
        let store = self.content.as_ref().ok_or_else(|| Error::msg("this member keeps no images or files"))?;
        let m = ev.media.as_ref().ok_or_else(|| Error::msg("the copy holds no images or files"))?;
        let key = ev.key.as_ref().ok_or_else(|| Error::msg("the copy is not sealed to this phone"))?;
        let sum = ev.sealed.as_ref().and_then(|s| s.blob.as_ref()).map(|b| b.sha256.as_slice());
        store.open_into(sum, m, key, out)
    }

    /// Queues a message for the group's hubs connected: the full members
    /// the records make the root or an admin, by the key they proved
    /// (docs/protocol.md, section 11, "Several hubs"); returns those it
    /// went to.
    pub fn send_to_hubs(&self, m: &Message) -> Vec<DeviceId> {
        let conns: Vec<Arc<Conn>> = self.conns.lock().unwrap().values().cloned().collect();
        let mut to = Vec::new();
        for c in conns.iter().filter(|c| !c.records_only) {
            let full = c.peer.lock().unwrap().as_ref().is_some_and(|p| p.role == "full");
            if full && self.records.lock().unwrap().admin_peer(c.id.as_str(), &c.chain) {
                self.enqueue(c, Out::Message(m.clone()));
                to.push(c.id.clone());
            }
        }
        to
    }

    /// Takes records this member's app signed (an admin's or the root's),
    /// keeps them and sends them to every peer.
    pub fn add_own_records(&self, rs: &[Record]) {
        let me = self.identity().id.clone();
        self.add_records(rs, &me);
    }

    /// Sends a command an admin signed and waits up to timeout for its
    /// result (docs/protocol.md, section 15): straight to its receiver when
    /// connected, else to the group's hubs connected, which pass it on; a
    /// `hub` command only goes straight.
    pub fn command(&self, r: &Record, timeout: Duration) -> Result<wire::CommandResult> {
        let head = CommandHead::of(r).ok_or_else(|| Error::msg("the command does not decode"))?;
        let to = DeviceId::parse(&head.to)?;
        let (tx, rx) = mpsc::sync_channel(1);
        self.waiting.lock().unwrap().insert(head.id.clone(), Waiting { to: to.clone(), tx });
        let m = wire::command(r);
        let sent = if self.send_to(&to, m.clone()) {
            true
        } else if head.kind == "hub" {
            false
        } else {
            !self.send_to_hubs(&m).is_empty()
        };
        let res = if sent {
            rx.recv_timeout(timeout).map_err(|_| Error::msg(format!("{to} did not answer in time")))
        } else {
            Err(Error::msg(format!("{to} is not connected, nor is a hub of the group")))
        };
        self.waiting.lock().unwrap().remove(&head.id);
        res
    }

    /// Takes a result: one for a command this member sent, from its
    /// receiver; or one for a command it passed on, which goes back to
    /// where the command came from, once.
    fn take_result(&self, mut res: wire::CommandResult, from: &DeviceId) {
        if let Some(w) = self.waiting.lock().unwrap().get(&res.id) {
            if res.by == w.to.as_str() || (res.by.is_empty() && from == &w.to) {
                let _ = w.tx.try_send(res);
            }
            return;
        }
        let back = self.passed.lock().unwrap().get_mut(&res.id).map(|(origin, exp)| {
            *exp = i64::MIN; // passed back once
            origin.clone()
        });
        if let Some(origin) = back {
            if res.by.is_empty() {
                res.by = from.to_string();
            }
            if let Some(c) = self.conns.lock().unwrap().get(&origin).cloned() {
                self.enqueue(&c, Out::Result(res));
            }
        }
    }

    /// Passes on a command for another device, as a phone does: only when
    /// connected to it and not passed before.
    fn pass(&self, r: Record, head: &CommandHead, from: &DeviceId) {
        let Ok(to) = DeviceId::parse(&head.to) else { return };
        let now = uptime::wall_ms();
        {
            let mut passed = self.passed.lock().unwrap();
            passed.retain(|_, (_, exp)| *exp > now);
            if passed.contains_key(&head.id) || passed.len() >= MAX_PASSED {
                return;
            }
            let c = self.conns.lock().unwrap().get(&to).cloned();
            let Some(c) = c.filter(|c| !c.records_only && &c.id != from) else { return };
            let exp = head.expires_ms.min(now + cbb_core::command::COMMAND_LIFETIME_MS + 1000);
            passed.insert(head.id.clone(), (from.clone(), exp));
            self.enqueue(&c, Out::Message(wire::command(&r)));
        }
        self.logf(&format!("cbb: passed a command from {from} on to {to}"));
    }

    /// The devices list from the records.
    pub fn devices(&self) -> Vec<crate::records::Device> {
        self.records.lock().unwrap().devices()
    }

    /// The group's order of hubs (docs/protocol.md, section 11, "Several
    /// hubs").
    #[cfg_attr(not(feature = "tunnel"), allow(dead_code))] // used by sync away from home
    pub fn hub_order(&self) -> Vec<String> {
        self.records.lock().unwrap().hub_order()
    }

    /// Ends the connection to the member id, if there is one, with bye.
    #[cfg_attr(not(feature = "tunnel"), allow(dead_code))] // used by sync away from home
    pub fn disconnect(&self, id: &DeviceId) {
        if let Some(c) = self.conns.lock().unwrap().get(id) {
            c.close(true);
        }
    }

    /// Makes an event from a deliberate action and sends it.
    pub fn send(&self, text: &str, kind: Kind, via: Via) -> Result<()> {
        let (ev, out) = self.engine.send(text, kind, via)?;
        self.forward(&ev, None);
        if out.write {
            self.write(&ev, out.seq);
        }
        Ok(())
    }

    /// Passes a change a clipboard watcher reported to the engine and sends
    /// the event, if any.
    pub fn copied(&self, text: &str, kind: Kind, via: Via) -> Result<()> {
        if let Some(ev) = self.engine.copied(text, kind, via)? {
            self.forward(&ev, None);
        }
        Ok(())
    }

    fn write(&self, ev: &Event, seq: u64) {
        let ttl = (ev.kind == Kind::Secret)
            .then(|| {
                self.engine
                    .local()
                    .map(|(_, _, age)| Duration::from_secs(60).saturating_sub(age).max(Duration::from_millis(1)))
            })
            .flatten();
        (self.on_write)(WriteReq {
            id: ev.id.clone(),
            text: ev.text.clone(),
            media: ev.media.clone(),
            kind: ev.kind,
            via: ev.via,
            seq,
            ttl,
        });
    }

    fn apply(&self, out: Outcome, from: &DeviceId) {
        let Some(ev) = out.forward else { return };
        self.forward(&ev, Some(from));
        if let Some(f) = self.on_change.read().unwrap().as_ref() {
            f(&ev);
        }
        if out.write {
            self.write(&ev, out.seq);
        }
    }

    /// What the engine seals this member's copies with: the readers the
    /// records name, the member certificate and key, which signs
    /// (docs/protocol.md, section 4, "Sealing").
    pub fn sealer(self: &Arc<Self>) -> SealFn {
        let node = Arc::downgrade(self);
        Box::new(move |ev: &Event| {
            let n = node.upgrade().ok_or_else(|| cbb_core::error::Error::msg("the member stopped"))?;
            let ident = n.identity();
            let readers = copy::readers(&n.records.lock().unwrap(), ev.kind == Kind::Secret);
            let content = Content { kind: ev.kind, via: ev.via, text: ev.text.clone(), media: ev.media.clone() };
            let issuer = ident.issuer.as_ref().map(|c| c.der.clone()).unwrap_or_default();
            // A media copy's key sealed its blob already.
            let key = ev.key.unwrap_or_else(copy::new_key);
            let mut d = copy::seal(
                &ev.id,
                &ev.origin,
                ev.time,
                &ident.cert.der,
                &issuer,
                &readers,
                &content,
                ev.blob.clone(),
                &key,
            )?;
            d.sealed.sig = ident.sign(&d.to_sign)?;
            Ok(d.sealed)
        })
    }

    /// Checks a copy a peer sent against the records and opens it when it
    /// is sealed to this member (docs/protocol.md, section 4, "Opening"); a
    /// copy that is not is kept unread, to order and pass on. None drops a
    /// copy the records refuse, which is logged.
    fn take(&self, s: Sealed, from: &DeviceId) -> Option<Event> {
        let checked = s.check(&self.records.lock().unwrap(), uptime::wall_ms().div_euclid(1000));
        if let Err(e) = checked {
            self.logf(&format!("cbb: dropped a copy from {from}: {}", e.for_log()));
            return None;
        }
        let me = self.identity().id.to_string();
        let mut ev = Event::of(s);
        let Some(s) = ev.sealed.as_ref() else { return Some(ev) };
        if s.is_mark() || !s.wraps.iter().any(|w| w.to == me) {
            return Some(ev);
        }
        // A copy sealed to this member that does not open stays unread, as
        // the others may read theirs.
        match crate::sealkey::secret().map(|secret| s.open(&me, secret)) {
            Some(Ok((c, key))) => {
                (ev.kind, ev.via, ev.text, ev.media, ev.key, ev.unread) =
                    (c.kind, c.via, c.text, c.media, Some(key), false);
            }
            Some(Err(e)) => self.logf(&format!("cbb: a copy from {from} does not open: {}", e.for_log())),
            None => {
                self.logf(&format!("cbb: a copy from {from} is not read: this member has no key for sealed messages"))
            }
        }
        Some(ev)
    }

    fn forward(&self, ev: &Event, from: Option<&DeviceId>) {
        if ev.sealed.is_none() {
            self.logf("cbb: a copy that is not sealed is not sent");
            return;
        }
        let now = uptime::now();
        let records = self.records.lock().unwrap();
        for c in self.conns.lock().unwrap().values() {
            if Some(&c.id) != from && !c.records_only {
                // A peer the records stop secrets to gets the mark of a
                // secret, never its payload (docs/protocol.md, section 10,
                // "Stopping the exchange").
                let ev = if ev.kind == Kind::Secret && !ev.unread && records.no_secrets_to(c.id.as_str()) {
                    ev.mark()
                } else {
                    ev.clone()
                };
                self.enqueue(c, Out::Event(ev, now));
            }
        }
    }

    fn enqueue(&self, c: &Arc<Conn>, o: Out) {
        if c.closed.load(Ordering::SeqCst) {
            return;
        }
        if let Err(TrySendError::Full(_)) = c.tx.try_send(o) {
            self.logf(&format!("cbb: {} is too slow; closing the connection", c.id));
            c.close(false);
        }
    }

    /// Closes every connection with a goodbye and refuses new ones.
    /// Reports whether the group's records revoke this device: it was
    /// removed, and joins again only after cbb leave.
    pub fn removed(&self) -> bool {
        let ident = self.identity();
        let own: Vec<Cert> = std::iter::once(ident.cert.clone()).chain(ident.issuer.clone()).collect();
        matches!(self.records.lock().unwrap().refused(&own), Some(Refusal::Refused(_)))
    }

    pub fn close(&self) {
        self.closed.store(true, Ordering::SeqCst);
        self.kick();
        for c in self.conns.lock().unwrap().values() {
            c.close(true);
        }
    }

    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::SeqCst)
    }

    /// Connects to the member at addr and runs the connection until it ends.
    /// peer is the device that discovery found there, or None for an
    /// address given by hand; the device is then the one the certificate
    /// names. A device already connected is not connected twice.
    pub fn dial(&self, addr: SocketAddr, peer: Option<DeviceId>) -> Result<()> {
        if self.is_closed() {
            return Err(Error::msg("the service is stopping"));
        }
        if self.is_paused() {
            return Err(Error::msg("the member is paused"));
        }
        // Away from home the member protocol goes only through the group's
        // tunnel, whose port is on the loopback address.
        if !home_address(addr.ip()) {
            return Err(Error::msg(format!(
                "{addr} is not on the home network; away from home this device reaches the group only through its tunnel (cbb global on)"
            )));
        }
        let sock = TcpStream::connect_timeout(&addr, HANDSHAKE_TIMEOUT).context(format!("cannot connect to {addr}"))?;
        let _ = sock.set_nodelay(true);
        sock.set_read_timeout(Some(HANDSHAKE_TIMEOUT)).context("the connection broke")?;
        sock.set_write_timeout(Some(HANDSHAKE_TIMEOUT)).context("the connection broke")?;
        let ident = self.identity();
        let cfg = tls::member_client(&ident, peer.clone(), tls::refused(&self.records), &tls::clock())?;
        let conn = tls::Session::client(Arc::new(cfg), tls::server_name(peer.as_ref()))?;
        let (conn, id, chain) = self.handshake(&sock, conn, addr, Usage::Server)?;
        if self.connected(&id) {
            let _ = sock.shutdown(Shutdown::Both);
            return Ok(());
        }
        self.run(sock, conn, id, chain, addr)
    }

    /// Runs a connection that a member (a phone or a lite member)
    /// opened to this one until it ends. It replaces an older connection
    /// to the same device. handshaken is called once the handshake is over,
    /// whether it worked or not.
    pub fn accept(&self, sock: TcpStream, addr: SocketAddr, handshaken: &mut dyn FnMut()) -> Result<()> {
        if self.is_closed() {
            return Err(Error::msg("the service is stopping"));
        }
        if self.is_paused() {
            return Err(Error::msg("the member is paused"));
        }
        let _ = sock.set_nodelay(true);
        sock.set_read_timeout(Some(HANDSHAKE_TIMEOUT)).context("the connection broke")?;
        sock.set_write_timeout(Some(HANDSHAKE_TIMEOUT)).context("the connection broke")?;
        let cfg = tls::member_server(&self.identity(), tls::refused(&self.records), &tls::clock())?;
        let conn = tls::Session::server(Arc::new(cfg))?;
        let res = self.handshake(&sock, conn, addr, Usage::Client);
        handshaken();
        let (conn, id, chain) = res?;
        self.run(sock, conn, id, chain, addr)
    }

    /// Completes the TLS handshake and checks the peer: usage is the side
    /// it is on.
    fn handshake(
        &self,
        sock: &TcpStream,
        mut conn: tls::Session,
        addr: SocketAddr,
        usage: Usage,
    ) -> Result<(tls::Session, DeviceId, Vec<Cert>)> {
        tls::handshake(&mut conn, sock, &format!("the TLS handshake with {addr} failed"))?;
        if conn.alpn_protocol() != Some(tls::MEMBER_PROTOCOL)
            || conn.protocol_version() != Some(tls::rustls::ProtocolVersion::TLSv1_3)
        {
            return Err(Error::msg(format!("{addr} does not speak the member protocol")));
        }
        let presented = conn.peer_certificates().unwrap_or_default().to_vec();
        let ident = self.identity();
        let (id, chain) = tls::check_member(
            &presented,
            &ident.trusted(),
            ident.root().not_before,
            &tls::refused(&self.records),
            usage,
            uptime::wall_ms() / 1000,
        )?;
        Ok((conn, id, chain))
    }

    fn run(&self, sock: TcpStream, conn: tls::Session, id: DeviceId, chain: Vec<Cert>, addr: SocketAddr) -> Result<()> {
        sock.set_read_timeout(Some(TIMEOUT)).context("the connection broke")?;
        let why = self.records.lock().unwrap().refused(&chain);
        let records_only = matches!(why, Some(Refusal::NotListed | Refusal::Stopped));
        let (tx, rx) = mpsc::sync_channel(QUEUE_LEN);
        let c = Arc::new(Conn {
            id: id.clone(),
            sock,
            tls: Mutex::new(conn),
            tx,
            peer: Mutex::new(None),
            chain,
            records_only,
            closed: AtomicBool::new(false),
            bye: AtomicBool::new(false),
            gets: Mutex::new(VecDeque::new()),
            sinks: Mutex::new(HashMap::new()),
        });
        {
            let mut conns = self.conns.lock().unwrap();
            if self.is_closed() || self.is_paused() {
                return Err(Error::msg("the service is stopping"));
            }
            if let Some(old) = conns.insert(id.clone(), c.clone()) {
                old.close(false);
            }
            if records_only {
                // Its hello offers nothing but the records' digest.
                let hello = Hello { wall: uptime::wall_ms(), current: None };
                let _ = c.tx.try_send(Out::Hello(
                    hello,
                    uptime::now(),
                    self.engine.mode(),
                    self.engine.mute_left(),
                    Vec::new(),
                ));
            } else {
                // The connection is in the forwarding set before the engine
                // makes the hello, so no event falls between the two.
                let hello = self.engine.connected(id.as_str());
                let actions = self.actions.read().unwrap().clone();
                let _ = c.tx.try_send(Out::Hello(
                    hello,
                    uptime::now(),
                    self.engine.mode(),
                    self.engine.mute_left(),
                    actions,
                ));
            }
        }
        if records_only {
            let why = why.map_or("", |w| w.why());
            self.logf(&format!("cbb: {id} at {addr}: {why}; exchanging records only"));
        } else {
            self.logf(&format!("cbb: connected to {id} at {addr}"));
        }
        let writer = {
            let c = c.clone();
            let records = self.records.clone();
            let who = self.presence.clone();
            let key = self.tunnel_key.clone();
            let log = self.log.clone();
            let entries = self.entries.clone();
            let content = self.content.clone();
            std::thread::spawn(move || writer(&c, rx, &records, &who, &key, &entries, content.as_deref(), &*log))
        };
        let res = self.reader(&c);
        c.close(false);
        let _ = writer.join();
        {
            let mut conns = self.conns.lock().unwrap();
            if conns.get(&id).is_some_and(|cur| Arc::ptr_eq(cur, &c)) {
                conns.remove(&id);
            }
        }
        if !c.records_only {
            self.engine.disconnected(id.as_str());
        }
        match &res {
            Ok(()) => self.logf(&format!("cbb: {id} said goodbye")),
            Err(e) => self.logf(&format!("cbb: the connection to {id} ended: {}", e.for_log())),
        }
        res
    }

    fn reader(&self, c: &Arc<Conn>) -> Result<()> {
        let mut r = TlsReader { c, buf: Vec::new() };
        let mut first = true;
        loop {
            let m: Message = match read_any(&mut r) {
                Ok(Frame::Message(m)) => *m,
                Ok(Frame::Chunk(ch)) if !first => {
                    // A chunk nothing waits for is left from a cancelled fetch.
                    let tx = c.sinks.lock().unwrap().get(&ch.sha256).cloned();
                    if let Some(tx) = tx {
                        let _ = tx.send(Piece::Chunk(ch));
                    }
                    continue;
                }
                Ok(Frame::Chunk(_)) => return Err(Error::msg(format!("{} did not start with a hello", c.id))),
                Err(_) if c.closed.load(Ordering::SeqCst) => return Ok(()),
                Err(e) => return Err(e),
            };
            if c.closed.load(Ordering::SeqCst) {
                return Ok(());
            }
            if first {
                first = false;
                if m.kind != "hello" || !wire::known_role(&m.role) {
                    return Err(Error::msg(format!("{} did not start with a hello", c.id)));
                }
                let (mut h, body) = wire::decode_hello(m.hello.as_ref())?;
                h.current = h.current.and_then(|e| e.sealed).and_then(|s| self.take(s, &c.id));
                *c.peer.lock().unwrap() = Some(peer_of(&c.id, &m.role, &body, c.records_only));
                if !c.records_only {
                    let out = self
                        .engine
                        .reconcile(c.id.as_str(), h)
                        .map_err(|e| e.context(format!("bad hello from {}", c.id)))?;
                    self.apply(out, &c.id);
                }
                let st = self.records.lock().unwrap();
                let mine = st.digest();
                if !mine.is_empty() && mine != body.records {
                    for chunk in chunk_records(st.all()) {
                        self.enqueue(c, Out::Records(chunk));
                    }
                }
                drop(st);
                // A peer that holds older entry points, or none, gets ours
                // (docs/protocol.md, section 16, "Entry points").
                let now = uptime::wall_ms();
                if !c.records_only
                    && entries::newer(self.entries.order(now), (body.entries_keys_seq, body.entries_seq))
                    && let Some(set) = self.entries.current(now)
                {
                    self.enqueue(c, Out::Entries(set));
                }
                continue;
            }
            if c.records_only {
                match m.kind.as_str() {
                    "records" if !m.records.is_empty() => self.add_records(&m.records, &c.id),
                    "bye" => return Ok(()),
                    _ => {}
                }
                continue;
            }
            let me = self.identity().id.clone();
            match m.kind.as_str() {
                "event" => {
                    let Some(s) = m.event.and_then(|v| serde_json::from_value::<Sealed>(v).ok()) else {
                        self.logf(&format!("cbb: dropped an event from {} that does not decode", c.id));
                        continue;
                    };
                    let Some(ev) = self.take(s, &c.id) else { continue };
                    match self.engine.received(ev) {
                        Ok(out) => self.apply(out, &c.id),
                        Err(e) => self.logf(&format!("cbb: dropped a bad event from {}: {}", c.id, e.for_log())),
                    }
                }
                "cert" => {
                    if let Some(cert) = m.cert
                        && let Err(e) = self.renewed(&cert, m.issuer.as_deref())
                    {
                        self.logf(&format!("cbb: a renewed certificate from {}: {}", c.id, e.for_log()));
                    }
                }
                "records" if !m.records.is_empty() => self.add_records(&m.records, &c.id),
                "entries" if m.entries.is_some() => self.add_entries(m.entries.as_ref().unwrap(), &c.id),
                // Only the group's root, an admin or a device that only
                // passes copies on can be its hub, by the records and the key
                // it proved, not by the role its hello claims
                // (docs/protocol.md, section 11).
                "tunnel" if m.tunnel.is_some() => {
                    if !self.records.lock().unwrap().hub_peer(c.id.as_str(), &c.chain) {
                        self.logf(&format!(
                            "cbb: ignored a tunnel offer from {}: only the group's root, an admin or a hub its records name can be its hub",
                            c.id
                        ));
                    } else if let (Some(v), Some(f)) = (m.tunnel.as_ref(), self.on_tunnel.read().unwrap().as_ref()) {
                        f(&c.id, v, &|dev| self.records.lock().unwrap().may_host(dev));
                    }
                }
                "command" if m.command.is_some() => {
                    let cmd = m.command.unwrap();
                    // A phone passes a command for another device on
                    // (docs/protocol.md, section 15); the lite member
                    // refuses it for itself.
                    if self.presence.role == "phone"
                        && let Some(head) = CommandHead::of(&cmd)
                        && head.to != me.as_str()
                    {
                        self.pass(cmd, &head, &c.id);
                        continue;
                    }
                    match self.on_command.read().unwrap().clone() {
                        Some(f) => {
                            // The reader goes on meanwhile, so the peer's
                            // copies still come in while a paste waits for
                            // its target.
                            let c = c.clone();
                            std::thread::spawn(move || {
                                let mut res = f(&c.id, &cmd);
                                res.by = me.to_string();
                                if !c.closed.load(Ordering::SeqCst) {
                                    let _ = c.tx.try_send(Out::Result(res));
                                }
                            });
                        }
                        None => self.enqueue(
                            c,
                            Out::Result(wire::CommandResult {
                                id: CommandHead::of(&cmd).map(|h| h.id).unwrap_or_default(),
                                by: me.to_string(),
                                status: "refused".into(),
                                reason: "this device takes no commands".into(),
                            }),
                        ),
                    }
                }
                "result" if m.result.is_some() => self.take_result(m.result.unwrap(), &c.id),
                "get" if self.content.is_some() => {
                    let Some(g) = m.get.filter(wire::Get::valid) else { continue };
                    let mut gets = c.gets.lock().unwrap();
                    if g.length == 0 {
                        gets.retain(|q| q.sha256 != g.sha256);
                        continue;
                    }
                    if gets.len() >= MAX_GETS {
                        return Err(Error::msg(format!("{} asked for more than {MAX_GETS} ranges at once", c.id)));
                    }
                    gets.push_back(g);
                    drop(gets);
                    let _ = c.tx.try_send(Out::Wake);
                }
                "missing" => {
                    let sum: Option<[u8; 32]> = m.get.and_then(|g| g.sha256.try_into().ok());
                    let tx = sum.and_then(|s| c.sinks.lock().unwrap().get(&s).cloned());
                    if let Some(tx) = tx {
                        let _ = tx.send(Piece::Missing);
                    }
                }
                "reach" => {
                    let reach = reach_of(m.reach.as_ref());
                    if let Some(p) = c.peer.lock().unwrap().as_mut() {
                        p.reach = reach;
                    }
                }
                "admin" | "hubs" | "credentials" => {
                    if let Some(f) = self.on_message.read().unwrap().as_ref() {
                        f(&c.id, &m);
                    }
                }
                "bye" => return Ok(()),
                _ => {} // a ping, or a message from a newer version
            }
        }
    }

    /// Takes the entry points a peer sent when they check out and are newer
    /// than those held, and passes them on to the other peers.
    fn add_entries(&self, set: &serde_json::Value, from: &DeviceId) {
        match self.entries.take(set, uptime::wall_ms()) {
            Ok(true) => {
                self.logf(&format!("cbb: took newer entry points from {from}"));
                let conns: Vec<Arc<Conn>> = self.conns.lock().unwrap().values().cloned().collect();
                for c in conns.iter().filter(|c| &c.id != from && !c.records_only) {
                    self.enqueue(c, Out::Entries(set.clone()));
                }
            }
            Ok(false) => {}
            Err(e) => self.logf(&format!("cbb: dropped the entry points {from} sent: {}", e.for_log())),
        }
    }

    /// Keeps a certificate an admin renewed for this member, or this
    /// member's app for itself.
    pub fn renewed(&self, der: &[u8], issuer: Option<&[u8]>) -> Result<()> {
        let mut ident = self.ident.write().unwrap();
        let next = ident.with_cert_from(der, issuer)?;
        let chain: Vec<Cert> = std::iter::once(next.cert.clone()).chain(next.issuer.clone()).collect();
        let records = self.records.lock().unwrap();
        // Its own device record may come after it, as right after joining:
        // the key is this member's, so that refuses nothing.
        if let Some(Refusal::Refused(why)) = records.refused(&chain) {
            return Err(Error::msg(why));
        }
        // A removed admin's or an old root's certificates stay valid for
        // the devices its removal keeps (docs/protocol.md, section 10), but
        // it renews none.
        let by = next.issuer.clone().or_else(|| next.trusted().into_iter().find(|r| next.cert.signed_by(r)));
        if by.is_some_and(|c| records.revoked(&c.key_hash())) {
            return Err(Error::msg("its issuer was removed from the group"));
        }
        drop(records);
        self.save_identity(&next)?;
        self.logf(&format!("cbb: got a renewed certificate, valid until {}", date(next.cert.not_after)));
        *ident = Arc::new(next);
        Ok(())
    }

    /// Gives the engine what the records say about the group's copies: how
    /// long an incoming copy stays live (docs/protocol.md, section 10, "The
    /// copies setting"), and whether the current event's origin is still a
    /// member. A copy from a device removed since, or from a root an admin
    /// took the group over from, is dropped then and never written later.
    fn apply_copy_rules(&self) {
        let current = self.engine.current_copy();
        let (window, refused) = {
            let st = self.records.lock().unwrap();
            let refused = match &current {
                Some((_, Some(s))) => s.check(&st, uptime::wall_ms().div_euclid(1000)).err(),
                _ => None,
            };
            (live_window(&st), refused)
        };
        self.engine.set_live_window(window);
        if let (Some((id, _)), Some(e)) = (current, refused)
            && self.engine.forget(&id)
        {
            self.logf(&format!("cbb: the group's last copy no longer counts and is dropped: {}", e.for_log()));
        }
    }

    fn add_records(&self, rs: &[Record], from: &DeviceId) {
        let fresh = {
            let mut st = self.records.lock().unwrap();
            let (fresh, errs) = st.add_all(rs);
            for e in errs {
                self.logf(&format!("cbb: dropped a record from {from}: {}", e.for_log()));
            }
            if fresh.is_empty() {
                return;
            }
            if let Err(e) = st.save(&self.state_dir) {
                self.logf(&format!("cbb: {}", e.for_log()));
            }
            // A new root that took the group over is trusted from now on.
            let roots = st.roots();
            let mut ident = self.ident.write().unwrap();
            if roots.iter().map(|c| &c.der).ne(ident.roots.iter().map(|c| &c.der)) {
                let mut next = (**ident).clone();
                next.roots = roots;
                match self.save_identity(&next) {
                    Ok(()) => *ident = Arc::new(next),
                    Err(e) => self.logf(&format!("cbb: keeping the group's new root: {}", e.for_log())),
                }
            }
            let own: Vec<Cert> = std::iter::once(ident.cert.clone()).chain(ident.issuer.clone()).collect();
            if matches!(st.refused(&own), Some(Refusal::Refused(_))) {
                self.logf("cbb: this device was removed from the group; to join again, run cbb leave, then cbb pair");
            }
            fresh
        };
        self.apply_copy_rules();
        // Pass them on, and drop the connections that are refused now.
        let st = self.records.lock().unwrap();
        for c in self.conns.lock().unwrap().values() {
            match st.refused(&c.chain) {
                Some(Refusal::Refused(why)) => {
                    self.logf(&format!("cbb: closing the connection to {}: {why}", c.id));
                    c.close(false);
                    continue;
                }
                None if c.records_only => {
                    self.logf(&format!("cbb: the records let {} in; it connects again as a member", c.id));
                    c.close(false);
                    continue;
                }
                Some(Refusal::Stopped) if !c.records_only => {
                    self.logf(&format!(
                        "cbb: {}; the connection to {} carries records only from now on",
                        Refusal::Stopped.why(),
                        c.id
                    ));
                    c.close(false);
                    continue;
                }
                _ => {}
            }
            if &c.id != from && c.peer.lock().unwrap().is_some() {
                for chunk in chunk_records(fresh.clone()) {
                    self.enqueue(c, Out::Records(chunk));
                }
            }
        }
    }
}

impl Conn {
    /// Ends the connection: with bye, the writer first sends what is queued
    /// and a goodbye; without, at once.
    fn close(&self, bye: bool) {
        if self.closed.swap(true, Ordering::SeqCst) {
            return;
        }
        if bye {
            self.bye.store(true, Ordering::SeqCst);
            let _ = self.sock.set_write_timeout(Some(Duration::from_secs(1)));
            let _ = self.tx.try_send(Out::Wake);
        } else {
            let _ = self.sock.shutdown(Shutdown::Both);
            let _ = self.tx.try_send(Out::Wake);
        }
    }

    /// Writes one frame through TLS.
    fn send(&self, frame: &[u8]) -> io::Result<()> {
        let mut tls = self.tls.lock().unwrap();
        tls.write(frame).map_err(|e| io::Error::other(e.for_log()))?;
        tls::flush(&mut tls, &self.sock)
    }
}

/// Reads plaintext from the connection, waiting on the socket without the
/// TLS lock.
struct TlsReader<'a> {
    c: &'a Conn,
    buf: Vec<u8>,
}

impl Read for TlsReader<'_> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        loop {
            {
                let tls = &mut *self.c.tls.lock().unwrap();
                let n = tls.read(out);
                if n > 0 || out.is_empty() || tls.peer_closed() {
                    return Ok(n);
                }
            }
            self.buf.resize(16 << 10, 0);
            let n = (&self.c.sock).read(&mut self.buf)?;
            if n == 0 {
                return Ok(0);
            }
            let mut tls = self.c.tls.lock().unwrap();
            let fed = tls.feed(&self.buf[..n]);
            // Replies rustls queued (a key update, an alert) go out first.
            tls::flush(&mut tls, &self.c.sock)?;
            fed.map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.for_log()))?;
        }
    }
}

#[allow(clippy::too_many_arguments, reason = "the connection's parts the writer reads")]
fn writer(
    c: &Conn,
    rx: mpsc::Receiver<Out>,
    records: &Mutex<Records>,
    who: &Presence,
    key: &RwLock<TunnelKeys>,
    entries: &Entries,
    content: Option<&Store>,
    log: &(dyn Fn(&str) + Send + Sync),
) {
    let message = |o: Out| -> Option<Message> {
        match o {
            Out::Hello(mut h, queued, mode, mute, actions) => {
                if let Some(ev) = h.current.as_mut() {
                    ev.age = add_age(ev.age, uptime::now().saturating_sub(queued));
                }
                let m = wire::hello(
                    &h,
                    records.lock().unwrap().digest(),
                    &who.role,
                    &who.name,
                    &who.os,
                    &who.device,
                    key.read().unwrap().as_ref().filter(|_| !c.records_only).map(|(k, p)| (k.as_slice(), p.as_slice())),
                    mode.name(),
                    mute,
                    &actions,
                    &who.key_store,
                    crate::sealkey::public(),
                    if c.records_only { (0, 0) } else { entries.order(uptime::wall_ms()) },
                );
                Some(wire::with_features(m, if content.is_some() && !c.records_only { &["media"] } else { &[] }))
            }
            Out::Event(ev, queued) => {
                let mut s = ev.sealed?;
                s.age = add_age(ev.age, uptime::now().saturating_sub(queued));
                Some(wire::event(&s))
            }
            Out::Records(rs) => Some(Message { kind: "records".into(), records: rs, ..Default::default() }),
            Out::Result(r) => Some(wire::result(r)),
            Out::Entries(set) => Some(wire::entries(&set)),
            Out::Message(m) => Some(m),
            Out::Wake => None,
        }
    };
    let write_frame = |f: &[u8]| -> bool {
        if !c.bye.load(Ordering::SeqCst) {
            let _ = c.sock.set_write_timeout(Some(TIMEOUT + Duration::from_secs((f.len() / MIN_RATE) as u64)));
        }
        if let Err(e) = c.send(f) {
            if !c.closed.load(Ordering::SeqCst) {
                log(&format!("cbb: writing to {}: {e}", c.id));
            }
            c.close(false);
            return false;
        }
        true
    };
    let write = |m: &Message| -> bool {
        match wire::frame(m) {
            Ok(f) => write_frame(&f),
            Err(e) => {
                log(&format!("cbb: to {}: {}", c.id, e.for_log()));
                true // drop this one message
            }
        }
    };
    loop {
        if c.closed.load(Ordering::SeqCst) {
            if c.bye.load(Ordering::SeqCst) {
                // Send what is still queued, then the goodbye.
                while let Ok(o) = rx.try_recv() {
                    if let Some(m) = message(o)
                        && !write(&m)
                    {
                        return;
                    }
                }
                write(&wire::bare("bye"));
                let _ = c.sock.shutdown(Shutdown::Both);
            }
            return;
        }
        // Messages first; a chunk of a blob only while none waits.
        match rx.try_recv() {
            Ok(o) => {
                if let Some(m) = message(o)
                    && !write(&m)
                {
                    return;
                }
                continue;
            }
            Err(TryRecvError::Disconnected) => return,
            Err(TryRecvError::Empty) => {}
        }
        if let Some(store) = content
            && let Some(frame) = next_piece(c, store)
        {
            if !write_frame(&frame) {
                return;
            }
            continue;
        }
        match rx.recv_timeout(PING_EVERY) {
            Ok(o) => {
                if let Some(m) = message(o)
                    && !write(&m)
                {
                    return;
                }
            }
            Err(RecvTimeoutError::Timeout) => {
                if !write(&wire::bare("ping")) {
                    return;
                }
            }
            Err(RecvTimeoutError::Disconnected) => return,
        }
    }
}

/// The next chunk frame of the gets a connection's peer asked for, or the
/// frame of the missing message for a blob this member does not hold;
/// None when no get waits.
fn next_piece(c: &Conn, store: &Store) -> Option<Vec<u8>> {
    let mut gets = c.gets.lock().unwrap();
    let g = gets.front_mut()?;
    let want = usize::try_from(g.length).unwrap_or(0).min(wire::MAX_CHUNK_DATA);
    match store.read(&g.sha256, g.offset as u64, want) {
        Some(data) if !data.is_empty() => {
            let sum: [u8; 32] = g.sha256.clone().try_into().ok()?;
            let ch = wire::Chunk { sha256: sum, offset: g.offset as u64, data };
            g.offset += ch.data.len() as i64;
            g.length -= ch.data.len() as i64;
            if g.length <= 0 {
                gets.pop_front();
            }
            wire::chunk_frame(&ch).ok()
        }
        _ => gets.pop_front().and_then(|g| wire::frame(&wire::missing(g)).ok()),
    }
}

/// Reads one frame: a message, or a chunk frame, whose length word has its
/// top bit set ("Content" in docs/protocol.md, section 4).
fn read_any(r: &mut impl Read) -> Result<Frame> {
    let mut head = [0u8; 4];
    r.read_exact(&mut head).context("the connection broke")?;
    if head[0] & 0x80 != 0 {
        let n = (u32::from_be_bytes(head) & 0x7fff_ffff) as usize;
        if n > wire::MAX_CHUNK_FRAME {
            return Err(Error::msg("a chunk frame is too large"));
        }
        let mut b = vec![0u8; n];
        r.read_exact(&mut b).context("the connection broke in the middle of a chunk")?;
        return Ok(Frame::Chunk(wire::decode_chunk(&b)?));
    }
    let size = wire::frame_len(head, wire::MAX_FRAME)?;
    let mut data = Vec::new();
    r.take(size as u64).read_to_end(&mut data).context("the connection broke")?;
    if data.len() != size {
        return Err(Error::msg("the connection broke in the middle of a frame"));
    }
    Ok(Frame::Message(Box::new(wire::decode(&data)?)))
}

/// A peer as its hello presents it, with what is not valid left out.
fn peer_of(id: &DeviceId, role: &str, body: &wire::HelloBody, records_only: bool) -> Peer {
    let valid = |s: &str, ok: &[&str]| if ok.contains(&s) { s.to_string() } else { String::new() };
    Peer {
        id: id.clone(),
        role: role.to_string(),
        name: if crate::records::valid_name(&body.name) { body.name.clone() } else { String::new() },
        os: if crate::records::valid_os(&body.os) { body.os.clone() } else { String::new() },
        key_store: valid(&body.key_store, &["file", "hardware", "rootless"]),
        mode: valid(&body.mode, &["own", "shared"]),
        muted: body.muted,
        muted_for_ms: body.muted_for_ms.max(0),
        actions: body.actions.iter().filter(|a| cbb_core::command::valid_action_name(a)).take(64).cloned().collect(),
        device: cbb_core::wire::DeviceInfo::of(body),
        admin_key: body.admin_key.clone().filter(|k| !k.is_empty() && k.len() <= 1024),
        tunnel_key: match (&body.tunnel_key, &body.tunnel_psk) {
            (Some(k), Some(p)) if k.len() == 32 && p.len() == 32 => Some((k.clone(), p.clone())),
            _ => None,
        },
        reach: Vec::new(),
        records_only,
        features: body.features.iter().take(32).filter(|f| f.len() <= 32).cloned().collect(),
    }
}

/// The valid device IDs of a reach message, at most MAX_REACH.
fn reach_of(v: Option<&serde_json::Value>) -> Vec<DeviceId> {
    let Some(list) = v.and_then(|v| v.as_array()) else { return Vec::new() };
    list.iter().take(MAX_REACH).filter_map(|x| x.as_str().and_then(|s| DeviceId::parse(s).ok())).collect()
}

/// Adds the time an event waited to its age, without overflowing.
fn add_age(age: i64, d: Duration) -> i64 {
    age.saturating_add(d.as_millis().min(i64::MAX as u128) as i64)
}

/// Splits records into groups whose encoded size stays near 1 MiB.
fn chunk_records(rs: Vec<Record>) -> Vec<Vec<Record>> {
    let mut out = Vec::new();
    let mut cur = Vec::new();
    let mut size = 0;
    for r in rs {
        let n = (r.body.len() + r.sig.len() + r.chain.iter().map(Vec::len).sum::<usize>()) * 4 / 3 + 64;
        if !cur.is_empty() && size + n > RECORDS_CHUNK {
            out.push(std::mem::take(&mut cur));
            size = 0;
        }
        cur.push(r);
        size += n;
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

/// A Unix time as a date, YYYY-MM-DD.
pub fn date(secs: i64) -> String {
    // Days since the epoch to a civil date (Howard Hinnant's algorithm).
    let z = secs.div_euclid(86400) + 719468;
    let era = z.div_euclid(146097);
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + if m <= 2 { 1 } else { 0 };
    format!("{y:04}-{m:02}-{d:02}")
}

/// Records in home when discovery found a device or lost it. Anyone can
/// announce the group's tag: past MAX_HOME devices a new name counts for
/// nothing.
fn remember_found(home: &mut HashMap<DeviceId, Duration>, id: &DeviceId, here: bool, now: impl FnOnce() -> Duration) {
    if !here {
        home.remove(id);
    } else if home.len() < MAX_HOME || home.contains_key(id) {
        home.entry(id.clone()).or_insert_with(now);
    }
}

/// How long a copy from another device stays live, as the records set it;
/// zero when they set nothing (the engine's default, a minute).
fn live_window(records: &Records) -> Duration {
    Duration::from_millis(records.state().incoming_ms.unwrap_or(0).max(0) as u64)
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::time::Duration;

    use super::{MAX_HOME, remember_found};
    use crate::certs::DeviceId;
    #[test]
    fn found_is_bounded() {
        let mut home = HashMap::new();
        let id = |i: usize| DeviceId::parse(&format!("{i:032x}")).unwrap();
        for i in 0..MAX_HOME + 10 {
            remember_found(&mut home, &id(i), true, || Duration::from_secs(i as u64));
        }
        assert_eq!(home.len(), MAX_HOME);
        assert!(!home.contains_key(&id(MAX_HOME)));
        // A known device is found again, and a lost one makes room.
        remember_found(&mut home, &id(1), true, || Duration::ZERO);
        assert_eq!(home[&id(1)], Duration::from_secs(1));
        remember_found(&mut home, &id(0), false, || Duration::ZERO);
        remember_found(&mut home, &id(MAX_HOME), true, || Duration::ZERO);
        assert!(home.contains_key(&id(MAX_HOME)));
    }

    #[test]
    fn dates() {
        assert_eq!(super::date(0), "1970-01-01");
        assert_eq!(super::date(1761024000), "2025-10-21");
    }
}
