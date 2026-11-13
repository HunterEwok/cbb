// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The member protocol (docs/protocol.md, section 4) on a Rust member: it
//! dials the members its caps and their device IDs say it dials, and takes
//! the connections of phones and the other members; it sends its hello, forwards each
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
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError, SyncSender, TryRecvError, TrySendError};
use std::sync::{Arc, Condvar, Mutex, RwLock};
use std::time::{Duration, Instant};

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
use crate::releases::{self, Releases};
use crate::tls;
use crate::uptime;
use crate::wire::{self, Message};
use cbb_core::media::{Manifest, Part};

/// What a hub that only passes copies on refuses, as Go's errForwardOnly.
pub const FORWARD_ONLY: &str =
    "this computer is a hub of the group that only passes the copies on: it makes, reads and pastes none";

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
/// How long a dial waits for a member's TCP connection, much longer than it
/// takes on a home network: a member is found at several addresses, and one
/// that does not answer (an interface the peer cannot be reached through)
/// holds up the next only this long.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const QUEUE_LEN: usize = 256;
const RECORDS_CHUNK: usize = 1 << 20;
/// The slowest transfer a frame is given time for.
const MIN_RATE: usize = 16 << 10;
/// The most gets a peer may have waiting on a connection.
/// How long a hub command waits for its receiver to connect again.
const RECONNECT_WAIT: Duration = Duration::from_secs(5);
const MAX_GETS: usize = 64;
/// The most peers whose release archive a member keeps.
const MAX_ARCHIVES: usize = 256;
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
    /// For a copy with images or files, its event, which fetch and
    /// open_media take.
    pub event: Option<Arc<Event>>,
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
    /// What its hello says it can do, the names this member knows, sorted.
    pub caps: Vec<String>,
    /// Its certificate chain as the handshake checked it, leaf first, DER:
    /// for a phone's app, which renews it and checks what it may do.
    pub chain: Vec<Vec<u8>>,
}

/// The most device IDs a reach message is read for or sent with.
const MAX_REACH: usize = 256;
/// The most commands remembered as passed on, as Go's.
const MAX_PASSED: usize = 4096;

/// Gets the messages a peer sends that the node does not handle itself:
/// `admin`, `hubs`, `credentials` and `evidence` for a phone's app, which
/// keeps them.
pub type OnMessage = Box<dyn Fn(&DeviceId, &Message) + Send + Sync>;

/// Called with each member's hello, its peer and verified chain, once the
/// hello is in; returns the messages to send it back first, such as a hub's
/// offers for the tunnel key it offered.
pub type OnHello = Box<dyn Fn(&DeviceId, &Peer, &[Cert]) -> Vec<Message> + Send + Sync>;
/// Gets each peer once its hello is taken, for a phone's app, which may
/// answer it: renew its certificate, send it an admin CA or tunnel offers.
pub type OnPeer = Box<dyn Fn(&Peer) + Send + Sync>;

/// Called with a tunnel offer and the device that sent it.
/// Gets a tunnel offer from the group's root or an admin, and whether the
/// records make a device the root or an admin, by its ID alone.
pub type OnTunnel = Box<dyn Fn(&DeviceId, &serde_json::Value, &dyn Fn(&str) -> bool) + Send + Sync>;

/// Carries out a command a peer sent (docs/protocol.md, section 15) and
/// gives the answer. It runs on a thread of its own: a remote paste waits
/// for its target.
pub type OnCommand = Arc<dyn Fn(&DeviceId, &Record) -> wire::CommandResult + Send + Sync>;

/// Takes, on a hub, a guest message from an admin that makes a remote
/// invitation through it (docs/protocol.md, section 12, "Through the hub"),
/// with the chain the admin proved.
pub type OnGuest = Box<dyn Fn(&Node, &DeviceId, &[Cert], wire::Guest) + Send + Sync>;

/// The tunnel key and preshared key a hello offers; None while sync away
/// from home is off.
type TunnelKeys = Option<(Vec<u8>, Vec<u8>)>;

/// The member's set of connections.
/// How the member presents itself in its hellos: cbb, or a
/// phone's app that runs it (crate::phone).
#[derive(Clone)]
pub struct Presence {
    /// `member`, or `phone` for a phone's app.
    pub role: String,
    /// What this member can do (cbb_core::authority::CAPS), sent in its
    /// hellos; none from a phone.
    pub caps: Vec<String>,
    pub name: String,
    pub os: String,
    /// Where the device key is: "file", "rootless" or "hardware".
    pub key_store: String,
    pub device: cbb_core::wire::DeviceInfo,
    /// The SubjectPublicKeyInfo of the admin key the hellos offer, for the
    /// root to certify: a computer's that is no admin yet.
    pub admin_key: Arc<RwLock<Option<Vec<u8>>>>,
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
    on_hello: RwLock<Option<OnHello>>,
    /// The networks where this device met its group, on a computer's
    /// service: the member port takes connections only on those.
    networks: RwLock<Option<Arc<crate::networks::Networks>>>,
    on_command: RwLock<Option<OnCommand>>,
    /// The quick actions that are on here, which the hellos name.
    actions: RwLock<Vec<String>>,
    /// The members discovery finds on the home network now.
    /// The devices discovery finds on the home network, by the uptime they
    /// were first found.
    home: Mutex<HashMap<DeviceId, Duration>>,
    /// The signed entry points this member holds and passes on.
    entries: Arc<Entries>,
    /// One fetch of a blob at a time, by its SHA-256: a second one (cbb
    /// paste -o while the copy is fetched in the background) waits for the
    /// first, then finds the blob held, as both would write one file and
    /// the peer's chunks go to one sink.
    fetching: Mutex<HashMap<[u8; 32], Arc<Mutex<()>>>>,
    /// The newest signed release the group passed around (section 16).
    releases: Arc<Releases>,
    /// The release archive each peer's hello says it updates from, which
    /// a hub fetches for them.
    archives: Mutex<HashMap<DeviceId, String>>,
    /// Keeps the identity when it changes (a renewed certificate, a new
    /// root), where identity.json cannot: a phone's app whose key is
    /// outside the core keeps its own file.
    keep_identity: Option<KeepIdentity>,
    /// Paused: the connections are closed and no new one is made, while a
    /// phone's app is in the background.
    paused: AtomicBool,
    /// Wakes the dial loops early: the member resumed or found an address.
    kick: (Mutex<u64>, Condvar),
    /// Counts the times new records came, for records_nap.
    changed: (Mutex<u64>, Condvar),
    /// Counts redial: the records may let in devices refused until now.
    redials: AtomicUsize,
    /// The commands this member sent, by ID, waiting for their results.
    waiting: Mutex<HashMap<String, Waiting>>,
    /// The commands a phone passed on, by ID: where each came from, and
    /// when it expires (docs/protocol.md, section 15).
    passed: Mutex<HashMap<String, Passed>>,
    on_message: RwLock<Option<OnMessage>>,
    on_peer: RwLock<Option<OnPeer>>,
    /// The hub's side of the remote invitations admins make through it.
    on_guest: RwLock<Option<OnGuest>>,
    /// The remote invitations this admin makes through a hub.
    pub inviter: crate::inviter::Inviter,
    /// Counts the times this member closed its connections to connect again
    /// (reconnect, a new tunnel key): the dial loops dial those at once.
    reconnects: AtomicUsize,
    /// The attestations of this member's keys, which every peer gets after
    /// its hello (docs/protocol.md, section 17, "Evidence"): a phone's app
    /// sets them.
    evidence: RwLock<Vec<serde_json::Value>>,
    /// The sealed blobs of copies with images or files, for a phone's app,
    /// which makes, fetches and serves them; None without the helper.
    content: Option<Arc<Store>>,
    /// Gets each copy that becomes the group's current one from a peer,
    /// for a phone's app, which shows it and fetches images or files.
    on_change: RwLock<Option<OnChange>>,
    on_relay: RwLock<Option<OnChange>>,
    /// Takes the pairing connections joiners dial to the member port, on
    /// a computer that may open a pairing window; None elsewhere, where
    /// the port speaks only the member protocol.
    on_pairing: RwLock<Option<OnPairing>>,
    /// A pairing window is open here, which mDNS announces (TXT p=1).
    window_open: AtomicBool,
    /// The members with a lower device ID that did not dial this one, so
    /// that it dialed them after FALLBACK (discovery's later dialer).
    unreached: Mutex<std::collections::BTreeSet<DeviceId>>,
}

/// The ID of a command as its body names it, for the result of one that
/// is refused before it is verified: the sender takes a result by its
/// command's ID, and one without it waits until it times out. Empty when
/// the body names none.
pub fn command_id(r: &Record) -> String {
    CommandHead::of(r).map(|h| h.id).unwrap_or_default()
}

/// How a dial ended (Node::dial_ended).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Dialed {
    /// The connection came up (or one to the peer was up already).
    pub up: bool,
    /// This member ended it to connect again: dial at once.
    pub again: bool,
}

/// A command a phone passed on: where it came from, when it expires, and
/// whether its result went back already. It is passed on once until it
/// expires, whatever its result.
struct Passed {
    from: DeviceId,
    expires_ms: i64,
    answered: bool,
}

/// Checks a connection a listener took, by the source port of its loopback
/// connection and the device its certificate names, before it is served:
/// a blind relay's calls only from the device the relay announced.
pub type Admit = Arc<dyn Fn(u16, &DeviceId) -> bool + Send + Sync>;

/// Gets a copy that became the group's current one.
pub type OnChange = Box<dyn Fn(&Event) + Send + Sync>;

/// Serves a pairing connection whose handshake is done: the socket, its
/// TLS session, the exporter of its secrets and the joiner's address.
pub type OnPairing = Arc<dyn Fn(TcpStream, tls::Session, Arc<tls::Exporter>, SocketAddr) -> Result<()> + Send + Sync>;

/// Where a connection through the hub's tunnel came from: a client's tunnel
/// address, or an invitation's guest, with its pairing and the device it
/// admitted.
enum Tunneled {
    Member(std::net::Ipv6Addr),
    Guest(OnPairing, Option<DeviceId>),
}

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
    Entries(Box<serde_json::value::RawValue>),
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
    /// The peer's address: a loopback one for a tunnel's or relay's
    /// connection.
    addr: SocketAddr,
    sock: TcpStream,
    tls: Mutex<tls::Session>,
    tx: SyncSender<Out>,
    peer: Mutex<Option<Peer>>, // from the hello
    chain: Vec<Cert>,
    /// No device record that counts names the peer's key yet: the
    /// connection carries records and nothing else, until the records let
    /// the peer in and it connects again as a member.
    records_only: bool,
    /// The peer's own key is removed or frozen (Refusal::Removed): the
    /// connection carries records only, the records go out when the peer's
    /// digest differs, and it closes after them; the peer's records are
    /// not taken.
    removed: bool,
    /// The peer came through this hub's tunnel.
    tunneled: bool,
    closed: AtomicBool,
    bye: AtomicBool,
    /// The member with the lower device ID dialed it.
    lower_dialed: bool,
    /// The gets the peer asked for, served in order a chunk at a time.
    gets: Mutex<VecDeque<wire::Get>>,
    /// The fetches waiting for the peer's chunks, by blob.
    sinks: Mutex<HashMap<[u8; 32], SyncSender<Piece>>>,
    /// The reach message last sent to it, a phone (send_reach).
    reach_sent: Mutex<Option<Vec<DeviceId>>>,
    /// Tells this connection from the peer's earlier and later ones.
    serial: u64,
}

/// The serial of the last connection; a lock, since 32-bit MIPS has no
/// 64-bit atomics.
static CONN_SERIAL: Mutex<u64> = Mutex::new(0);

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
        let releases = Arc::new(Releases::open(&state_dir, crate::update::release_roots(), uptime::wall_ms(), &*log));
        engine.set_live_window(live_window(&records));
        Node {
            ident: RwLock::new(Arc::new(ident)),
            presence: Arc::new(Presence {
                role: "member".into(),
                caps: Vec::new(),
                name: name.to_string(),
                os: "linux".into(),
                key_store: if crate::rootless::is() { "rootless" } else { "file" }.into(),
                device: crate::device::own().clone(),
                admin_key: Default::default(),
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
            on_hello: RwLock::new(None),
            networks: RwLock::new(None),
            on_command: RwLock::new(None),
            actions: RwLock::new(Vec::new()),
            home: Mutex::new(HashMap::new()),
            entries,
            fetching: Mutex::new(HashMap::new()),
            releases,
            archives: Mutex::new(HashMap::new()),
            keep_identity: None,
            paused: AtomicBool::new(false),
            kick: (Mutex::new(0), Condvar::new()),
            changed: (Mutex::new(0), Condvar::new()),
            redials: AtomicUsize::new(0),
            waiting: Mutex::new(HashMap::new()),
            passed: Mutex::new(HashMap::new()),
            on_message: RwLock::new(None),
            on_peer: RwLock::new(None),
            on_guest: RwLock::new(None),
            inviter: crate::inviter::Inviter::default(),
            reconnects: AtomicUsize::new(0),
            evidence: RwLock::new(Vec::new()),
            content: None,
            on_change: RwLock::new(None),
            on_relay: RwLock::new(None),
            on_pairing: RwLock::new(None),
            window_open: AtomicBool::new(false),
            unreached: Mutex::new(Default::default()),
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

    /// The role its hellos present: `member` or `phone`.
    pub fn role(&self) -> &str {
        &self.presence.role
    }

    /// What its hellos say it can do.
    pub fn caps(&self) -> &[String] {
        &self.presence.caps
    }

    /// Whether its hellos say it can do c.
    pub fn can(&self, c: &str) -> bool {
        cbb_core::authority::has_cap(&self.presence.caps, c)
    }

    /// The name its hellos present.
    pub fn name(&self) -> &str {
        &self.presence.name
    }

    /// The system its hellos present.
    pub fn os(&self) -> &str {
        &self.presence.os
    }

    /// The node presenting itself as p in its hellos, before it connects.
    pub fn presenting(mut self, p: Presence) -> Node {
        self.presence = Arc::new(p);
        self
    }

    /// Sets the tunnel key and preshared key the hellos offer from now on
    /// and tells the members, so that the group's hubs get them. Without a
    /// key, sync away from home is off: the connections through a tunnel's
    /// or relay's loopback port, and those that came through this hub's
    /// tunnel, close, since their way is gone.
    pub fn set_tunnel_key(&self, key: TunnelKeys) {
        let off = key.is_none();
        *self.tunnel_key.write().unwrap() = key;
        if off {
            for c in self.conns.lock().unwrap().values() {
                if c.tunneled || c.addr.ip().to_canonical().is_loopback() {
                    c.close(true);
                }
            }
        }
        // The peers take the key from a presence message, without
        // connecting again: a hub answers it with its offer as it answers
        // a hello, and this member sends its own offers if it is a hub now.
        self.announce(true);
    }

    /// Tells every connected peer what this member's hello would say now
    /// about its sync, its mute and its tunnel key, in a `presence`
    /// message (docs/protocol.md, section 4, "Presence"), so that a change
    /// shows without connecting again. With offers it also runs what a
    /// hello runs here for each peer once more (on_hello), as a device
    /// that just became a hub does to send its offer to the members
    /// already connected.
    pub fn announce(&self, offers: bool) {
        let m = self.presence_message();
        let conns: Vec<Arc<Conn>> = self.conns.lock().unwrap().values().filter(|c| !c.records_only).cloned().collect();
        for c in conns {
            self.enqueue(&c, Out::Message(m.clone()));
            let peer = c.peer.lock().unwrap().clone();
            if offers
                && let Some(peer) = peer
                && let Some(f) = self.on_hello.read().unwrap().as_ref()
            {
                for out in f(&c.id, &peer, &c.chain) {
                    self.enqueue(&c, Out::Message(out));
                }
            }
        }
    }

    /// The presence message for this member now.
    fn presence_message(&self) -> Message {
        let key = self.tunnel_key.read().unwrap().clone();
        let mute = self.engine.mute_left();
        let body = wire::HelloBody {
            mode: self.engine.mode().name().to_string(),
            muted: mute.is_some(),
            muted_for_ms: mute.unwrap_or(0),
            tunnel_psk: key.as_ref().map(|(_, p)| p.clone()),
            tunnel_key: key.map(|(k, _)| k),
            ..Default::default()
        };
        Message { kind: "presence".into(), hello: serde_json::to_value(&body).ok(), ..Default::default() }
    }

    /// Takes a peer's presence message: its sync, mute and tunnel key
    /// replace what its hello said, and a new tunnel key runs what a hello
    /// runs (on_hello), so that a hub admits it as its hello would have.
    fn take_presence(&self, c: &Arc<Conn>, v: Option<&serde_json::Value>) {
        let Some(body) =
            v.filter(|v| v.is_object()).and_then(|v| serde_json::from_value::<wire::HelloBody>(v.clone()).ok())
        else {
            self.logf(&format!("cbb: dropped a presence message from {} that does not decode", c.id));
            return;
        };
        let fresh = peer_of(&c.id, "", &body, false);
        let (peer, rekeyed) = {
            let mut cur = c.peer.lock().unwrap();
            let Some(p) = cur.as_mut() else { return };
            let rekeyed = p.tunnel_key != fresh.tunnel_key;
            (p.mode, p.muted, p.muted_for_ms, p.tunnel_key) =
                (fresh.mode, fresh.muted, fresh.muted_for_ms, fresh.tunnel_key);
            (p.clone(), rekeyed)
        };
        if rekeyed && let Some(f) = self.on_hello.read().unwrap().as_ref() {
            for out in f(&c.id, &peer, &c.chain) {
                self.enqueue(c, Out::Message(out));
            }
        }
        if let Some(f) = self.on_peer.read().unwrap().as_ref() {
            f(&peer);
        }
    }

    /// Connects to every member again, so that the hellos say what changed.
    pub fn reconnect(&self) {
        self.reconnects.fetch_add(1, Ordering::SeqCst);
        for c in self.conns.lock().unwrap().values() {
            c.close(true);
        }
    }

    /// Sets the quick actions the hellos name from now on; a peer sees a
    /// change at its next connection.
    pub fn set_actions(&self, on: Vec<String>) {
        *self.actions.write().unwrap() = on;
    }

    /// Lets the member port take pairing connections, which f serves.
    pub fn on_pairing(&self, f: OnPairing) {
        *self.on_pairing.write().unwrap() = Some(f);
    }

    /// Sets the admin key the hellos offer, or stops offering one.
    pub fn offer_admin_key(&self, spki: Option<Vec<u8>>) {
        *self.presence.admin_key.write().unwrap() = spki;
    }

    /// Says whether a pairing window is open here, for mDNS.
    pub fn set_window_open(&self, open: bool) {
        self.window_open.store(open, Ordering::SeqCst);
    }

    /// Whether a pairing window is open here.
    pub fn window_open(&self) -> bool {
        self.window_open.load(Ordering::SeqCst)
    }

    /// Sets what carries out the commands peers send.
    pub fn on_command(&self, f: OnCommand) {
        *self.on_command.write().unwrap() = Some(f);
    }

    /// The project's signed entry points this member holds.
    pub fn entries(&self) -> &Entries {
        &self.entries
    }

    pub fn releases(&self) -> &Releases {
        &self.releases
    }

    /// The release archives the peers seen update from.
    pub fn archives(&self) -> Vec<String> {
        let mut out: Vec<String> = self.archives.lock().unwrap().values().cloned().collect();
        out.sort();
        out.dedup();
        out
    }

    /// The group's records.
    pub fn records(&self) -> Arc<Mutex<Records>> {
        self.records.clone()
    }

    /// Sets what is called with each member's hello.
    pub fn on_hello(&self, f: OnHello) {
        *self.on_hello.write().unwrap() = Some(f);
    }

    /// Keeps the known networks: the member port then takes connections
    /// only on them, or while a pairing window is open, and each member
    /// connection that comes up makes its network known.
    pub fn set_networks(&self, n: Arc<crate::networks::Networks>) {
        *self.networks.write().unwrap() = Some(n);
    }

    /// The known networks, on a computer's service.
    pub fn networks(&self) -> Option<Arc<crate::networks::Networks>> {
        self.networks.read().unwrap().clone()
    }

    /// Whether the member port takes a connection that came to the local
    /// address a, as Go's takesOn: from loopback, while a pairing window is
    /// open, on a known network, or always without known networks (a
    /// phone's app).
    pub fn takes_on(&self, local: SocketAddr, from: SocketAddr) -> bool {
        let Some(n) = self.networks.read().unwrap().clone() else { return true };
        from.ip().is_loopback() || from.ip().to_canonical().is_loopback() || self.window_open() || n.knows(local.ip())
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
        near(self.home.lock().unwrap().get(id).copied(), uptime::now())
    }

    /// The state directory.
    pub fn state_dir(&self) -> &std::path::Path {
        &self.state_dir
    }

    pub fn identity(&self) -> Arc<Identity> {
        self.ident.read().unwrap().clone()
    }

    pub fn logf(&self, s: &str) {
        (self.log)(s)
    }

    /// The identity member connections present, as Go's memberTLSCert: on
    /// the admin that took the group over, the certificate from before the
    /// takeover (prev_cert) while that lasts, so that a member that missed
    /// the takeover, which knows only the old root, verifies it and takes
    /// the root record over the connection. It stops 240 days before that
    /// certificate ends, so that no admin renews the root's certificate
    /// from its admin CA.
    fn tls_identity(&self) -> Arc<Identity> {
        let ident = self.identity();
        let Ok(f) = crate::identity::admin_fields(&self.state_dir) else { return ident };
        let der = |k: &str| -> Option<Vec<u8>> { cbb_core::certs::b64::deserialize(f.get(k)?.clone()).ok() };
        let Some(prev) = der("prev_cert").and_then(|d| Cert::parse(&d).ok()) else { return ident };
        const RENEW_BEFORE: i64 = 240 * 24 * 3600;
        if uptime::wall_ms() / 1000 >= prev.not_after.saturating_sub(cbb_core::benchtime::d(RENEW_BEFORE))
            || prev.public_key() != ident.cert.public_key()
        {
            return ident;
        }
        let mut shown = (*ident).clone();
        shown.issuer = der("prev_issuer").and_then(|d| Cert::parse(&d).ok());
        shown.cert = prev;
        Arc::new(shown)
    }

    /// Marks whether the member did not dial this one, so that this one
    /// dials it, as Go's trackSeen and waitUnconnected.
    pub fn set_unreached(&self, id: &DeviceId, unreached: bool) {
        let mut u = self.unreached.lock().unwrap();
        if unreached {
            u.insert(id.clone());
        } else {
            u.remove(id);
        }
    }

    /// The members connected only because this one dialed them back after
    /// they did not dial it, sorted.
    pub fn unreached(&self) -> Vec<String> {
        let u = self.unreached.lock().unwrap().clone();
        u.into_iter().filter(|id| self.connected(id)).map(|id| id.to_string()).collect()
    }

    /// Reports whether a connection to the device is up.
    pub fn connected(&self, id: &DeviceId) -> bool {
        self.conns.lock().unwrap().contains_key(id)
    }

    /// Reports whether a connection to the device is up that a dial to
    /// addr would not replace: any one for a home address; for a loopback
    /// one (a tunnel's or relay's port), only one through a loopback port,
    /// since a connection at home may have gone quiet once the peer took
    /// the way through the tunnel, and the tunnel's then replaces it.
    pub fn connected_for(&self, id: &DeviceId, addr: &SocketAddr) -> bool {
        self.conns.lock().unwrap().get(id).is_some_and(|c| !replaces(addr, &c.addr))
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

    /// Renews the member certificates that are due, as an admin with the
    /// signer s, as Go's renew and the phone kits' renewal: each connected
    /// member's, sent to it, and this member's own, kept. It returns how
    /// many it renewed.
    pub fn renew_due(&self, s: &cbb_core::manage::Signer) -> Result<usize> {
        let now = uptime::wall_ms() / 1000;
        let ident = self.identity();
        let mut roots = self.records.lock().unwrap().roots();
        if roots.is_empty() {
            roots.push(ident.root().clone());
        }
        let issuer = (!roots.iter().any(|r| r == s.ca)).then(|| s.ca.der.clone());
        let mut n = 0;
        for (to, chain) in self.peer_chains() {
            match cbb_core::manage::renewal(&chain, &roots, s, now) {
                Ok(Some(cert)) => {
                    if self.send_to(&to, wire::cert(&cert, issuer.as_deref())) {
                        self.logf(&format!("cbb: renewed the certificate of {to}"));
                        n += 1;
                    }
                }
                Ok(None) => {}
                Err(e) => self.logf(&format!("cbb: renewing the certificate of {to}: {}", e.for_log())),
            }
        }
        let own: Vec<_> = std::iter::once(ident.cert.clone()).chain(ident.issuer.clone()).collect();
        if let Some(cert) = cbb_core::manage::renewal(&own, &roots, s, now)? {
            self.renewed(&cert, issuer.as_deref())?;
            n += 1;
        }
        Ok(n)
    }

    /// Whether this device's newest record makes it a hub that only passes
    /// copies on: it makes no copies, and takes no paste or action command
    /// (docs/protocol.md, section 11, "Two kinds of hub").
    pub fn forward_only(&self) -> bool {
        let me = self.identity().id.to_string();
        self.records.lock().unwrap().devices().iter().any(|d| d.id == me && d.forward_only)
    }

    /// The certificate chain the member id presented, leaf first; empty
    /// while it is not connected.
    pub fn chain_of(&self, id: &DeviceId) -> Vec<Cert> {
        self.conns.lock().unwrap().get(id).map(|c| c.chain.clone()).unwrap_or_default()
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

    /// Sets what gets each peer once its hello is taken.
    /// Sets what takes, on a hub, the guest messages of the admins that
    /// make remote invitations through it.
    pub fn on_guest(&self, f: OnGuest) {
        *self.on_guest.write().unwrap() = Some(f);
    }

    pub fn on_peer(&self, f: OnPeer) {
        *self.on_peer.write().unwrap() = Some(f);
    }

    /// Sets the attestations every peer gets after its hello from now on.
    pub fn set_evidence(&self, list: Vec<serde_json::Value>) {
        *self.evidence.write().unwrap() = list;
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

    /// Makes the dial loops of the members not connected try at once, the
    /// ones that wait for the other member to dial too, as Go's redial: the
    /// records may let in devices refused until now, as a thaw does, and a
    /// refused member would otherwise wait out its backoff.
    pub fn redial(&self) {
        self.redials.fetch_add(1, Ordering::SeqCst);
        self.kick();
    }

    /// How many times redial was called.
    pub fn redials(&self) -> usize {
        self.redials.load(Ordering::SeqCst)
    }

    /// Waits up to d, or until kick; reports whether it was kicked.
    pub fn nap(&self, d: Duration) -> bool {
        let (m, cv) = &self.kick;
        let g = m.lock().unwrap();
        let start = *g;
        let (g, _) = cv.wait_timeout_while(g, d, |n| *n == start && !self.is_closed()).unwrap();
        *g != start
    }

    /// Waits up to d, or until new records come; reports whether they
    /// did. What follows from the records (the server credentials, a
    /// takeover) is brought up to date at once, as Go does in
    /// settleRecords.
    pub fn records_nap(&self, d: Duration) -> bool {
        let (m, cv) = &self.changed;
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
    /// The serial of the member connection to id, which a connection after
    /// it does not share; None when it is not connected.
    pub fn connection(&self, id: &DeviceId) -> Option<u64> {
        self.conns.lock().unwrap().get(id).filter(|c| !c.records_only).map(|c| c.serial)
    }

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

    /// Makes a copy of images or files from the parts handed in, as a
    /// deliberate action: seals their blob, keeps it to serve, and sends the
    /// copy; on a member that takes media, writes it to its own clipboard
    /// unless that holds it already.
    pub fn send_media(&self, text: &str, parts: Vec<(Part, Source)>, via: Via) -> Result<Event> {
        let store = self.content.as_ref().ok_or_else(|| Error::msg("this member keeps no images or files"))?;
        let key = copy::new_key();
        let (manifest, blob) = store.seal(parts, &key)?;
        let (ev, out) = self.engine.send_media(text, manifest, via, key, blob)?;
        self.forward(&ev, None);
        if out.write {
            self.write(&ev, out.seq);
        }
        Ok(ev)
    }

    /// Passes images or files a clipboard watcher reported to the engine,
    /// sealed and kept to serve, and sends the event, if any.
    pub fn copied_media(&self, text: &str, parts: Vec<(Part, Source)>, via: Via) -> Result<Option<Event>> {
        let store = self.content.as_ref().ok_or_else(|| Error::msg("this member keeps no images or files"))?;
        let key = copy::new_key();
        let (manifest, blob) = store.seal(parts, &key)?;
        let ev = self.engine.copied_media(text, manifest, via, key, blob)?;
        if let Some(ev) = &ev {
            self.forward(ev, None);
        }
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
        let lock = self.fetch_lock(&sum);
        let _one = lock.lock().unwrap_or_else(|e| e.into_inner());
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
            match self.fetch_from(&c, &store.partial(&sum), &sum, size) {
                Ok(()) => return store.finish(&sum, size),
                Err(e) => {
                    self.logf(&format!("cbb: fetching a copy's content from {}: {}", c.id, e.for_log()));
                    last = e;
                }
            }
        }
        Err(last)
    }

    /// The lock that keeps fetches of the blob sum one at a time; it is
    /// dropped from the table when no fetch holds or waits for it.
    fn fetch_lock(&self, sum: &[u8; 32]) -> Arc<Mutex<()>> {
        let mut m = self.fetching.lock().unwrap();
        m.retain(|_, l| Arc::strong_count(l) > 1);
        Arc::clone(m.entry(*sum).or_default())
    }

    /// Fetches the archive sha of the release held from the connected peers
    /// that serve content, unless this member holds it whole, as Go's
    /// fetchReleaseFile.
    pub fn fetch_release_file(&self, sha: &str) -> Result<()> {
        let now = uptime::wall_ms();
        let a = self
            .releases
            .file(sha, now)
            .ok_or_else(|| Error::msg("the release this device holds lists no such file"))?;
        if self.releases.held(sha, now).is_some() {
            return Ok(());
        }
        let sum: [u8; 32] = releases::unhex(sha)
            .and_then(|b| b.try_into().ok())
            .ok_or_else(|| Error::msg(format!("{sha:?} is not a SHA-256")))?;
        let lock = self.fetch_lock(&sum);
        let _one = lock.lock().unwrap_or_else(|e| e.into_inner());
        if self.releases.held(sha, now).is_some() {
            return Ok(());
        }
        let size = u64::try_from(a.size).map_err(|_| Error::msg("the archive has no size"))?;
        let part = self.releases.files_dir()?.join(format!(".part-{sha}"));
        let peers: Vec<Arc<Conn>> = self
            .conns
            .lock()
            .unwrap()
            .values()
            .filter(|c| !c.records_only)
            .filter(|c| c.peer.lock().unwrap().as_ref().is_some_and(|p| p.features.iter().any(|f| f == "media")))
            .cloned()
            .collect();
        let mut last = Error::msg("no member that serves files is connected");
        for c in peers {
            let _ = std::fs::remove_file(&part);
            let res = self.fetch_from(&c, &part, &sum, size).and_then(|()| self.releases.keep_file(sha, &part, now));
            match res {
                Ok(()) => {
                    let name = c.peer.lock().unwrap().as_ref().map(|p| p.name.clone()).unwrap_or_default();
                    self.logf(&format!("cbb: fetched {} from {name} for cbb update", a.name));
                    return Ok(());
                }
                Err(e) => last = e.context(format!("from {}", c.id)),
            }
        }
        let _ = std::fs::remove_file(&part);
        Err(last)
    }

    /// Fetches the blob sum from one peer into the partial file at path,
    /// continuing from what it holds.
    fn fetch_from(&self, c: &Arc<Conn>, path: &std::path::Path, sum: &[u8; 32], size: u64) -> Result<()> {
        use std::io::{Seek, Write};
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).context("make the folder of the copies' content")?;
        }
        let mut f = std::fs::OpenOptions::new().create(true).append(true).open(path).context("keep a fetch")?;
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
        // Measured, not counted in waits: a wait may end early, as under
        // an emulator.
        let mut last = Instant::now();
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
                    last = Instant::now();
                }
                Ok(Piece::Chunk(_)) => {}
                Ok(Piece::Missing) => break Err(Error::msg("it does not hold the blob")),
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    if last.elapsed() >= FETCH_IDLE {
                        break Err(Error::msg("no chunk came for 15 s"));
                    }
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    break Err(Error::msg("another fetch took the blob's chunks"));
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

    /// Queues a message for the group's hubs connected: the members
    /// the records make the root or an admin, by the key they proved
    /// (docs/protocol.md, section 11, "Several hubs"); returns those it
    /// went to.
    pub fn send_to_hubs(&self, m: &Message) -> Vec<DeviceId> {
        let conns: Vec<Arc<Conn>> = self.conns.lock().unwrap().values().cloned().collect();
        let mut to = Vec::new();
        for c in conns.iter().filter(|c| !c.records_only) {
            let member = c.peer.lock().unwrap().as_ref().is_some_and(|p| p.role == "member");
            if member && self.records.lock().unwrap().admin_peer(c.id.as_str(), &c.chain) {
                self.enqueue(c, Out::Message(m.clone()));
                to.push(c.id.clone());
            }
        }
        to
    }

    /// Sends a command to the members that pass it on (docs/protocol.md,
    /// section 15): the group's hubs connected, members, and the
    /// phones among the root and the admins, as the phone that is the hub;
    /// returns those it went to.
    fn send_to_passers(&self, m: &Message) -> Vec<DeviceId> {
        let conns: Vec<Arc<Conn>> = self.conns.lock().unwrap().values().cloned().collect();
        let mut to = Vec::new();
        for c in conns.iter().filter(|c| !c.records_only) {
            let role = c.peer.lock().unwrap().as_ref().map(|p| p.role.clone()).unwrap_or_default();
            if (role == "member" || role == "phone") && self.records.lock().unwrap().admin_peer(c.id.as_str(), &c.chain)
            {
                self.enqueue(c, Out::Message(m.clone()));
                to.push(c.id.clone());
            }
        }
        to
    }

    /// Takes records this member's app signed (an admin's or the root's),
    /// keeps them and sends them to every peer.
    pub fn add_own_records(&self, rs: &[Record]) {
        crate::signed::note(&self.state_dir, rs, &|s| self.logf(s));
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
        // A hub command goes only straight, and a peer that ended its
        // connection to connect again, as with a new hello, is back within
        // moments.
        let connected = || {
            let until = std::time::Instant::now() + RECONNECT_WAIT;
            loop {
                if self.send_to(&to, m.clone()) {
                    return true;
                }
                if head.kind != "hub" || std::time::Instant::now() >= until {
                    return false;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
        };
        let sent = if connected() {
            true
        } else if head.kind == "hub" {
            false
        } else {
            !self.send_to_passers(&m).is_empty()
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
        res.reason = wire::clean_reason(&res.reason);
        if let Some(w) = self.waiting.lock().unwrap().get(&res.id) {
            if res.by == w.to.as_str() || (res.by.is_empty() && from == &w.to) {
                let _ = w.tx.try_send(res);
            }
            return;
        }
        let back = self.passed.lock().unwrap().get_mut(&res.id).filter(|p| !p.answered).map(|p| {
            p.answered = true; // passed back once
            p.from.clone()
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
            passed.retain(|_, p| p.expires_ms > now);
            // An expired command, or one that claims to live longer than a
            // command may, is not passed on (docs/protocol.md, section 15).
            let lifetime = cbb_core::command::COMMAND_LIFETIME_MS + cbb_core::command::COMMAND_AHEAD_MS;
            if head.expires_ms <= now
                || head.expires_ms.saturating_sub(now) > lifetime
                || passed.contains_key(&head.id)
                || passed.len() >= MAX_PASSED
            {
                return;
            }
            let c = self.conns.lock().unwrap().get(&to).cloned();
            let Some(c) = c.filter(|c| !c.records_only && &c.id != from) else { return };
            passed.insert(head.id.clone(), Passed { from: from.clone(), expires_ms: head.expires_ms, answered: false });
            self.enqueue(&c, Out::Message(wire::command(&r)));
        }
        self.logf(&format!("cbb: passed a command from {from} on to {to}"));
    }

    /// How far the peers read the sealed blob of the current copy id, and
    /// its size; None when id is not the current copy or has no blob.
    pub fn served(&self, id: &str) -> Option<(u64, u64)> {
        let ev = self.engine.current().filter(|e| e.id == id)?;
        let blob = ev.blob?;
        let store = self.content.as_ref()?;
        Some((store.served(&blob.sha256), u64::try_from(blob.size).unwrap_or(0)))
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
    /// The members connected through this hub's tunnel.
    pub fn tunneled(&self) -> Vec<DeviceId> {
        self.conns.lock().unwrap().values().filter(|c| c.tunneled).map(|c| c.id.clone()).collect()
    }

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
            event: ev.media.is_some().then(|| Arc::new(ev.clone())),
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
        } else if let Some(f) = self.on_relay.read().unwrap().as_ref() {
            f(&ev);
        }
    }

    /// Sets what gets each event this member passes on without writing it,
    /// as Go's OnRelay.
    pub fn on_relay(&self, f: OnChange) {
        *self.on_relay.write().unwrap() = Some(f);
    }

    /// Sets the largest blob served through the group's tunnel.
    pub fn set_away_limit(&self, n: u64) {
        if let Some(s) = &self.content {
            s.set_away_limit(n);
        }
    }

    /// What the engine seals this member's copies with: the readers the
    /// records name, the member certificate and key, which signs
    /// (docs/protocol.md, section 4, "Sealing").
    pub fn sealer(self: &Arc<Self>) -> SealFn {
        let node = Arc::downgrade(self);
        Box::new(move |ev: &Event| {
            let n = node.upgrade().ok_or_else(|| cbb_core::error::Error::msg("the member stopped"))?;
            if n.forward_only() {
                return Err(cbb_core::error::Error::msg(FORWARD_ONLY));
            }
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

    /// Tells each connected phone, when this member is a computer, the
    /// other members it is connected to now, whenever that changes for the
    /// phone (docs/protocol.md, section 4, "Reach"), as Go's sendReach:
    /// away from home a phone connects only to a hub, which passes its
    /// commands on to the members behind it, so that the phone shows them
    /// as online.
    fn send_reach(&self) {
        if self.presence.role != "member" {
            return;
        }
        let conns: Vec<Arc<Conn>> = self.conns.lock().unwrap().values().cloned().collect();
        let mut all = Vec::new();
        let mut phones = Vec::new();
        for c in &conns {
            let Some(role) = c.peer.lock().unwrap().as_ref().map(|p| p.role.clone()) else { continue };
            if c.closed.load(Ordering::SeqCst) || c.records_only {
                continue;
            }
            if role == "phone" {
                phones.push(c);
            }
            all.push(c.id.clone());
        }
        all.sort_by(|a, b| a.as_str().cmp(b.as_str()));
        for c in phones {
            let reach: Vec<DeviceId> = all.iter().filter(|id| **id != c.id).take(MAX_REACH).cloned().collect();
            {
                let mut sent = c.reach_sent.lock().unwrap();
                if sent.as_ref() == Some(&reach) {
                    continue;
                }
                *sent = Some(reach.clone());
            }
            let ids: Vec<&str> = reach.iter().map(|id| id.as_str()).collect();
            self.enqueue(c, Out::Message(wire::reach(&ids)));
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
        self.changed.1.notify_all();
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
        self.dial_ended(addr, peer).map(|_| ())
    }

    /// As dial, telling how the dial ended: whether the connection came up
    /// (its end afterwards, a goodbye or a broken connection, is logged and
    /// is no failure to dial), and whether this member ended it to connect
    /// again (reconnect, a new tunnel key), so that it is dialed at once.
    pub fn dial_ended(&self, addr: SocketAddr, peer: Option<DeviceId>) -> Result<Dialed> {
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
        let sock = TcpStream::connect_timeout(&addr, CONNECT_TIMEOUT).context(format!("cannot connect to {addr}"))?;
        let _ = sock.set_nodelay(true);
        sock.set_read_timeout(Some(HANDSHAKE_TIMEOUT)).context("the connection broke")?;
        sock.set_write_timeout(Some(HANDSHAKE_TIMEOUT)).context("the connection broke")?;
        let ident = self.tls_identity();
        let cfg = tls::member_client(&ident, peer.clone(), tls::refused(&self.records), &tls::clock())?;
        let conn = tls::Session::client(Arc::new(cfg), tls::server_name(peer.as_ref()))?;
        let (conn, id, chain) = self.handshake(&sock, conn, addr, Usage::Server)?;
        if self.connected_for(&id, &addr) {
            let _ = sock.shutdown(Shutdown::Both);
            return Ok(Dialed { up: true, again: false });
        }
        let before = self.reconnects.load(Ordering::SeqCst);
        // A connection that only tells a removed device so, or that this
        // removed device gets, is dialed again as after a failure: the
        // records went over once, and the wait grows.
        let told = matches!(self.records.lock().unwrap().refused_peer(&chain), Some(Refusal::Removed(_)));
        // How it ended is logged; a connection that came up and ended is
        // dialed again at once when this member ended it to connect again,
        // else after a second.
        let _ = self.run(sock, conn, id, chain, addr, true);
        let up = !told && !self.removed();
        Ok(Dialed { up, again: up && self.reconnects.load(Ordering::SeqCst) != before })
    }

    /// Runs a connection that a member (a phone or another member)
    /// opened to this one until it ends. It replaces an older connection
    /// to the same device. handshaken is called once the handshake is over,
    /// whether it worked or not.
    pub fn accept(&self, sock: TcpStream, addr: SocketAddr, handshaken: &mut dyn FnMut()) -> Result<()> {
        self.accept_from(sock, addr, None, handshaken, None)
    }

    /// As accept, with the listener's check of the peer (Admit), which
    /// refuses the connection before it is served.
    pub fn accept_checked(
        &self,
        sock: TcpStream,
        addr: SocketAddr,
        handshaken: &mut dyn FnMut(),
        admit: Option<&Admit>,
    ) -> Result<()> {
        self.accept_from(sock, addr, None, handshaken, admit)
    }

    /// Runs a member connection that came through the hub's tunnel from
    /// the tunnel address from: the member protocol only, from the device
    /// whose address that is, as Go's serveTunnelMember.
    pub fn accept_tunneled(&self, sock: TcpStream, from: std::net::Ipv6Addr) -> Result<()> {
        let addr = SocketAddr::from((from, 0));
        self.accept_from(sock, addr, Some(Tunneled::Member(from)), &mut || {}, None)
    }

    /// Runs a connection that came through an invitation's guest tunnel
    /// from the guest address from, as Go's serveGuest: the invitation's
    /// pairing, which pairing serves, and once that admitted a device, that
    /// device's member connection, nothing else.
    pub fn accept_guest(
        &self,
        sock: TcpStream,
        from: std::net::Ipv6Addr,
        pairing: OnPairing,
        admitted: Option<DeviceId>,
    ) -> Result<()> {
        let addr = SocketAddr::from((from, 0));
        self.accept_from(sock, addr, Some(Tunneled::Guest(pairing, admitted)), &mut || {}, None)
    }

    fn accept_from(
        &self,
        sock: TcpStream,
        addr: SocketAddr,
        tunneled: Option<Tunneled>,
        handshaken: &mut dyn FnMut(),
        admit: Option<&Admit>,
    ) -> Result<()> {
        if self.is_closed() {
            return Err(Error::msg("the service is stopping"));
        }
        if self.is_paused() {
            return Err(Error::msg("the member is paused"));
        }
        let _ = sock.set_nodelay(true);
        sock.set_read_timeout(Some(HANDSHAKE_TIMEOUT)).context("the connection broke")?;
        sock.set_write_timeout(Some(HANDSHAKE_TIMEOUT)).context("the connection broke")?;
        let pairing = match &tunneled {
            None => self.on_pairing.read().unwrap().clone(),
            Some(Tunneled::Member(_)) => None,
            Some(Tunneled::Guest(p, _)) => Some(p.clone()),
        };
        let (refused, clock) = (tls::refused(&self.records), tls::clock());
        // A pairing binds the certificate that the admitting member knows
        // as its own, so an open window, or a guest's invitation, presents
        // the current one.
        let (cfg, exporter) = match pairing {
            Some(_) => {
                let pairs = self.window_open.load(Ordering::SeqCst) || matches!(tunneled, Some(Tunneled::Guest(..)));
                let ident = if pairs { self.identity() } else { self.tls_identity() };
                tls::member_or_pair_server(&ident, refused, &clock)?
            }
            None => (tls::member_server(&self.tls_identity(), refused, &clock)?, Arc::new(tls::Exporter::default())),
        };
        let mut conn = tls::Session::server(Arc::new(cfg))?;
        let res = tls::handshake(&mut conn, &sock, &format!("the TLS handshake with {addr} failed"));
        if res.is_ok()
            && conn.alpn_protocol() == Some(tls::PAIR_PROTOCOL)
            && let Some(serve) = pairing
        {
            handshaken();
            return serve(sock, conn, exporter, addr);
        }
        let res = res.and_then(|()| self.check(conn, addr, Usage::Client));
        handshaken();
        let (conn, id, chain) = res?;
        match tunneled {
            Some(Tunneled::Member(from)) if crate::tunnel_addr(id.as_str()) != Some(from) => {
                let _ = sock.shutdown(Shutdown::Both);
                return Err(Error::msg(format!(
                    "a member connection through the tunnel from {from} is not from the device of that key; closed"
                )));
            }
            Some(Tunneled::Guest(_, admitted)) if admitted.as_ref() != Some(&id) => {
                let _ = sock.shutdown(Shutdown::Both);
                return Err(Error::msg(
                    "a member connection through a guest tunnel is not from the device it admitted; closed",
                ));
            }
            _ => {}
        }
        if let Some(admit) = admit
            && !admit(addr.port(), &id)
        {
            return Err(Error::msg(format!("{id} at {addr} is not the caller this listener expects")));
        }
        self.run(sock, conn, id, chain, addr, false)
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
        self.check(conn, addr, usage)
    }

    /// Checks the peer of a connection whose handshake is done: the member
    /// protocol, and a member chain the records take.
    fn check(&self, conn: tls::Session, addr: SocketAddr, usage: Usage) -> Result<(tls::Session, DeviceId, Vec<Cert>)> {
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

    /// Runs a member connection until it ends; dialed says this member
    /// dialed it. A new connection to a peer replaces the old one, as a
    /// reconnect does, unless the old one was dialed by the member with the
    /// lower device ID and this one was not, as Go's: when both dial at once
    /// (a redial), the two keep the same connection.
    fn run(
        &self,
        sock: TcpStream,
        conn: tls::Session,
        id: DeviceId,
        chain: Vec<Cert>,
        addr: SocketAddr,
        dialed: bool,
    ) -> Result<()> {
        let lower_dialed = dialed == (self.ident.read().unwrap().id < id);
        sock.set_read_timeout(Some(TIMEOUT)).context("the connection broke")?;
        let why = self.records.lock().unwrap().refused_peer(&chain);
        let removed = matches!(why, Some(Refusal::Removed(_)));
        let records_only = removed || matches!(why, Some(Refusal::NotListed | Refusal::Stopped | Refusal::TakenOver));
        if !records_only
            && !addr.ip().to_canonical().is_loopback()
            && let (Some(n), Ok(local)) = (self.networks.read().unwrap().clone(), sock.local_addr())
            && n.learn(local.ip())
        {
            self.logf(&format!("cbb: {id} connected on a network new to this device; it is known now"));
        }
        let (tx, rx) = mpsc::sync_channel(QUEUE_LEN);
        let c = Arc::new(Conn {
            id: id.clone(),
            addr,
            sock,
            tls: Mutex::new(conn),
            tx,
            peer: Mutex::new(None),
            chain,
            records_only,
            removed,
            tunneled: matches!(addr.ip(), std::net::IpAddr::V6(a) if a.octets()[..4] == [0xfd, 0x00, 0x0c, 0xbb]),
            closed: AtomicBool::new(false),
            bye: AtomicBool::new(false),
            lower_dialed,
            gets: Mutex::new(VecDeque::new()),
            sinks: Mutex::new(HashMap::new()),
            reach_sent: Mutex::new(None),
            serial: {
                let mut n = CONN_SERIAL.lock().unwrap();
                *n += 1;
                *n
            },
        });
        {
            let mut conns = self.conns.lock().unwrap();
            if self.is_closed() || self.is_paused() {
                return Err(Error::msg("the service is stopping"));
            }
            if let Some(old) = conns.get(&id)
                && old.lower_dialed
                && !lower_dialed
                && !old.closed.load(Ordering::SeqCst)
                && !replaces(&addr, &old.addr)
            {
                let _ = c.sock.shutdown(Shutdown::Both);
                return Err(Error::msg("the connection the lower device ID dialed is up"));
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
        if removed {
            let why = why.map_or("", |w| w.why());
            self.logf(&format!("cbb: {id} at {addr}: {why}; it gets the records that say so"));
        } else if records_only {
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
            let releases = self.releases.clone();
            let content = self.content.clone();
            std::thread::spawn(move || {
                writer(&c, rx, &records, &who, &key, (&entries, &releases), content.as_deref(), &*log)
            })
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
        self.send_reach();
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
                // The records a peer sends before it ends the connection, as
                // those that remove or freeze this device, still count when
                // this side's writer has failed meanwhile (the peer hung up
                // while this member was still answering its hello): dropped,
                // this member would never hear it was removed, since its next
                // connection is refused.
                if !first && !c.removed && m.kind == "records" && !m.records.is_empty() {
                    self.add_records(&m.records, &c.id);
                    continue;
                }
                return Ok(());
            }
            if first {
                first = false;
                if m.kind != "hello" || !wire::known_role(&m.role) {
                    return Err(Error::msg(format!("{} did not start with a hello", c.id)));
                }
                let (mut h, body) = wire::decode_hello(m.hello.as_ref())?;
                h.current = h.current.and_then(|e| e.sealed).and_then(|s| self.take(s, &c.id));
                let mut peer = peer_of(&c.id, &m.role, &body, c.records_only);
                peer.chain = c.chain.iter().map(|x| x.der.clone()).collect();
                *c.peer.lock().unwrap() = Some(peer.clone());
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
                if c.removed {
                    // The records that say it was removed went out above,
                    // unless it holds them; the bye follows them.
                    c.close(true);
                    continue;
                }
                // After the records, as Go's: the credentials and the offers
                // that follow are checked against them, and a device that
                // just joined finds its own device record there.
                if !c.records_only
                    && let Some(f) = self.on_hello.read().unwrap().as_ref()
                {
                    for out in f(&c.id, &peer, &c.chain) {
                        self.enqueue(c, Out::Message(out));
                    }
                }
                if !c.records_only {
                    for e in self.evidence.read().unwrap().iter() {
                        self.enqueue(c, Out::Message(wire::evidence(e)));
                    }
                }
                if let Some(f) = self.on_peer.read().unwrap().as_ref() {
                    f(&peer);
                }
                self.send_reach();
                if !c.records_only && !peer.device.archive.is_empty() {
                    let mut a = self.archives.lock().unwrap();
                    if a.len() < MAX_ARCHIVES || a.contains_key(&c.id) {
                        a.insert(c.id.clone(), peer.device.archive.clone());
                    }
                }
                // A peer that holds older entry points, or none, gets ours
                // (docs/protocol.md, section 16, "Entry points").
                let now = uptime::wall_ms();
                if !c.records_only
                    && entries::newer(self.entries.order(now), (body.entries_keys_seq, body.entries_seq))
                    && let Some(set) = self.entries.current(now)
                {
                    self.enqueue(c, Out::Entries(set));
                }
                // A computer that holds an older release, or none, gets ours;
                // phones update from their stores (section 16, "In the
                // group").
                if !c.records_only
                    && m.role == cbb_core::authority::ROLE_MEMBER
                    && releases::newer(self.releases.order(now), (body.release_keys_seq, body.release_seq))
                    && let Some(set) = self.releases.current(now)
                {
                    self.enqueue(c, Out::Message(wire::release(&set)));
                }
                continue;
            }
            if c.records_only {
                match m.kind.as_str() {
                    "records" if !m.records.is_empty() && !c.removed => self.add_records(&m.records, &c.id),
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
                "presence" => self.take_presence(c, m.hello.as_ref()),
                "entries" if m.entries.is_some() => self.add_entries(m.entries.as_ref().unwrap(), &c.id),
                "release" if m.release.is_some() && self.presence.role != "phone" => {
                    self.add_release(m.release.as_ref().unwrap(), &c.id)
                }
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
                    // (docs/protocol.md, section 15); cbb
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
                                tunnel: None,
                            }),
                        ),
                    }
                }
                "result" if m.result.is_some() => self.take_result(m.result.unwrap(), &c.id),
                "get" if self.content.is_some() => {
                    let Some(g) = m.get.filter(wire::Get::valid) else { continue };
                    if queue_get(&mut c.gets.lock().unwrap(), g).map_err(|e| Error::msg(format!("{} {e}", c.id)))? {
                        let _ = c.tx.try_send(Out::Wake);
                    }
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
                // A hub share only from a device that may be a hub, by the
                // records and the chain it proved (docs/protocol.md, section
                // 11, "Several hubs").
                "hubs" if !self.records.lock().unwrap().hub_peer(c.id.as_str(), &c.chain) => {
                    self.logf(&format!("cbb: ignored a hub share from {}: it may not be a hub of the group", c.id));
                }
                "admin" | "hubs" | "credentials" | "evidence" => {
                    if let Some(f) = self.on_message.read().unwrap().as_ref() {
                        f(&c.id, &m);
                    }
                }
                // A remote invitation through the hub (docs/protocol.md,
                // section 12, "Through the hub"): the admin's side takes
                // what comes for its invitations, the hub's side the rest.
                "guest" => {
                    let Some(g) = m.guest.as_ref().and_then(wire::Guest::decode) else { continue };
                    if self.inviter.handles(&g) {
                        self.inviter.take(&c.id, g);
                    } else if let Some(f) = self.on_guest.read().unwrap().as_ref() {
                        f(self, &c.id, &c.chain, g);
                    }
                }
                "bye" => return Ok(()),
                _ => {} // a ping, or a message from a newer version
            }
        }
    }

    /// Takes the entry points a peer sent when they check out and are newer
    /// than those held, and passes them on to the other peers.
    fn add_entries(&self, set: &serde_json::value::RawValue, from: &DeviceId) {
        match self.entries.take(set, uptime::wall_ms()) {
            Ok(true) => {
                self.logf(&format!("cbb: took newer entry points from {from}"));
                let conns: Vec<Arc<Conn>> = self.conns.lock().unwrap().values().cloned().collect();
                for c in conns.iter().filter(|c| &c.id != from && !c.records_only) {
                    self.enqueue(c, Out::Entries(set.to_owned()));
                }
            }
            Ok(false) => {}
            Err(e) => self.logf(&format!("cbb: dropped the entry points {from} sent: {}", e.for_log())),
        }
    }

    /// Takes the release a peer sent when it checks out and is newer than
    /// the one held, and passes it on to the other computers.
    fn add_release(&self, set: &serde_json::value::RawValue, from: &DeviceId) {
        match self.releases.take(set, uptime::wall_ms()) {
            Ok(true) => {
                self.release_taken();
                self.send_release(set, Some(from));
            }
            Ok(false) => {}
            Err(e) => self.logf(&format!("cbb: dropped the release {from} sent: {}", e.for_log())),
        }
    }

    /// Takes a release cbb update fetched, as Go's putRelease: kept when it
    /// checks out and is newer than the one held, and passed on to the
    /// peers.
    pub fn put_release(&self, set: &serde_json::value::RawValue) -> Result<()> {
        if self.releases.take(set, uptime::wall_ms()).map_err(|e| e.context("the release does not check out"))? {
            self.release_taken();
            self.send_release(set, None);
        }
        Ok(())
    }

    fn release_taken(&self) {
        if let Some(v) = self.releases.version(uptime::wall_ms())
            && releases::offered(&v)
        {
            self.logf(&format!("cbb: CBB {v} is available; cbb update installs it"));
        }
    }

    /// Sends the release to the computers connected, but from.
    fn send_release(&self, set: &serde_json::value::RawValue, from: Option<&DeviceId>) {
        let conns: Vec<Arc<Conn>> = self.conns.lock().unwrap().values().cloned().collect();
        for c in conns.iter().filter(|c| Some(&c.id) != from && !c.records_only) {
            let computer = c.peer.lock().unwrap().as_ref().is_some_and(|p| p.role == cbb_core::authority::ROLE_MEMBER);
            if computer {
                self.enqueue(c, Out::Message(wire::release(set)));
            }
        }
    }

    /// Takes entry points this device fetched or the user gave, as Go's
    /// putEntries: kept when they check out and are newer than those held,
    /// and passed on to the peers; reports whether they were newer.
    pub fn put_entries(&self, set: &serde_json::value::RawValue) -> Result<bool> {
        let newer =
            self.entries.take(set, uptime::wall_ms()).map_err(|e| e.context("the entry points do not check out"))?;
        if newer {
            let conns: Vec<Arc<Conn>> = self.conns.lock().unwrap().values().cloned().collect();
            for c in conns.iter().filter(|c| !c.records_only) {
                self.enqueue(c, Out::Entries(set.to_owned()));
            }
        }
        Ok(newer)
    }

    /// Keeps a certificate an admin renewed for this member, or this
    /// member's app for itself.
    pub fn renewed(&self, der: &[u8], issuer: Option<&[u8]>) -> Result<()> {
        self.take_cert(self.identity().with_cert_from(der, issuer)?)
    }

    /// Takes a member certificate issued again for this device that need
    /// not end later than the current one, as the one from its new admin
    /// CA (admin::become_admin).
    pub fn reissued(&self, der: &[u8], issuer: Option<&[u8]>) -> Result<()> {
        self.take_cert(self.identity().with_cert_any_end(der, issuer)?)
    }

    /// Takes the member certificate that this device, whose claim made it
    /// the group's root, issued itself from the new root.
    pub fn took_over(&self, der: &[u8]) -> Result<()> {
        self.take_cert(self.identity().with_cert_of_takeover(der)?)
    }

    fn take_cert(&self, mut next: Identity) -> Result<()> {
        // The records are checked before the identity is locked: the
        // records' holders lock them first and the identity after
        // (add_records, settle).
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
        let mut ident = self.ident.write().unwrap();
        // Roots adopted meanwhile stay.
        next.roots = ident.roots.clone();
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

    /// Trusts the roots the records lead to now: a new root that took the
    /// group over is trusted from now on.
    fn adopt_roots(&self, st: &Records) {
        // A set that is empty, as after a records file that could not be
        // read, says nothing yet: the peers give the records again.
        if st.is_empty() {
            return;
        }
        let roots = st.roots();
        let mut ident = self.ident.write().unwrap();
        if roots.iter().map(|c| &c.der).eq(ident.roots.iter().map(|c| &c.der)) {
            return;
        }
        let own: Vec<Cert> = std::iter::once(ident.cert.clone()).chain(ident.issuer.clone()).collect();
        if st.taken_over(&own).is_some() {
            // A root an admin took the group over from keeps its root key,
            // so that removing that admin undoes the takeover.
            return;
        }
        let mut next = (**ident).clone();
        next.roots = roots;
        match self.save_identity(&next) {
            Ok(()) => {
                match next.roots.last() {
                    None => self.logf("cbb: the group's root is its first one again"),
                    Some(r) => self.logf(&format!(
                        "cbb: the group has a new root, {}",
                        r.common_name.as_deref().unwrap_or_default()
                    )),
                }
                *ident = Arc::new(next);
            }
            Err(e) => self.logf(&format!("cbb: keeping the group's new root: {}", e.for_log())),
        }
    }

    /// Applies what the records say now without a new record, as Go's
    /// settleClaims: a claim takes effect when its delay ends, so the new
    /// root is trusted, and the connections the state refuses now close.
    pub fn settle(&self) {
        self.adopt_roots(&self.records.lock().unwrap());
        self.apply_copy_rules();
        let st = self.records.lock().unwrap();
        for c in self.conns.lock().unwrap().values() {
            if let Some(Refusal::Refused(why) | Refusal::Removed(why)) = st.refused_peer(&c.chain) {
                self.logf(&format!("cbb: closing the connection to {}: {why}", c.id));
                // The records go first, so that it hears why, as in
                // add_records.
                if c.peer.lock().unwrap().is_some() {
                    for chunk in chunk_records(st.all()) {
                        self.enqueue(c, Out::Records(chunk));
                    }
                }
                c.close(true);
            }
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
            self.adopt_roots(&st);
            let ident = self.ident.read().unwrap();
            let own: Vec<Cert> = std::iter::once(ident.cert.clone()).chain(ident.issuer.clone()).collect();
            if matches!(st.refused(&own), Some(Refusal::Refused(_))) {
                self.logf("cbb: this device was removed from the group; to join again, run cbb leave, then cbb pair");
            }
            fresh
        };
        self.apply_copy_rules();
        // A thaw lets in devices refused until now, and a claim, a resolve,
        // a settings, a checkpoint or a recovery record may, as Go's
        // updateRecords.
        use cbb_core::authority::{
            Body, TYPE_CHECKPOINT, TYPE_CLAIM, TYPE_RECOVERY, TYPE_RESOLVE, TYPE_SETTINGS, TYPE_THAW,
        };
        let lets_in = [TYPE_THAW, TYPE_CLAIM, TYPE_RESOLVE, TYPE_SETTINGS, TYPE_CHECKPOINT, TYPE_RECOVERY];
        if fresh.iter().any(|r| Body::parse(&r.body).is_ok_and(|b| lets_in.contains(&b.kind.as_str()))) {
            self.redial();
        }
        // Pass them on, and drop the connections that are refused now.
        let st = self.records.lock().unwrap();
        for c in self.conns.lock().unwrap().values() {
            match st.refused_peer(&c.chain) {
                Some(Refusal::Refused(why) | Refusal::Removed(why)) if !c.removed => {
                    // The records that refuse it go first, so that it
                    // hears it was removed or frozen, as Go's settleRecords.
                    self.logf(&format!("cbb: closing the connection to {}: {why}", c.id));
                    if &c.id != from && c.peer.lock().unwrap().is_some() {
                        for chunk in chunk_records(fresh.clone()) {
                            self.enqueue(c, Out::Records(chunk));
                        }
                    }
                    c.close(true);
                    continue;
                }
                None if c.records_only => {
                    self.logf(&format!("cbb: the records let {} in; it connects again as a member", c.id));
                    c.close(false);
                    continue;
                }
                Some(why @ (Refusal::Stopped | Refusal::TakenOver)) if !c.records_only => {
                    self.logf(&format!(
                        "cbb: {}; the connection to {} carries records only from now on",
                        why.why(),
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
        drop(st);
        // Only now are those waiting for a change woken: the service's
        // loop may settle at once, and a connection it closes must have the
        // records that refuse it queued first.
        let (m, cv) = &self.changed;
        *m.lock().unwrap() += 1;
        cv.notify_all();
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
            // The read timeout is EAGAIN (WouldBlock) on Linux and Android,
            // ETIMEDOUT elsewhere: either means nothing came for TIMEOUT,
            // although the peer pings every 5 s.
            let n = (&self.c.sock).read(&mut self.buf).map_err(|e| match e.kind() {
                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut => io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("nothing came for {} s, not even a ping", TIMEOUT.as_secs()),
                ),
                _ => e,
            })?;
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
    (entries, releases): (&Entries, &Releases),
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
                    who.admin_key.read().unwrap().as_deref(),
                );
                let m = wire::with_caps(m, &who.caps);
                let m = wire::with_features(m, if content.is_some() && !c.records_only { &["media"] } else { &[] });
                let m = wire::with_release(m, if c.records_only { (0, 0) } else { releases.order(uptime::wall_ms()) });
                // A member hands the group's first root to a device no
                // record names, as a phone restoring the group with the
                // recovery key, which builds the group's path from it.
                let rs = records.lock().unwrap();
                Some(if c.records_only && rs.refused_peer(&c.chain) == Some(Refusal::NotListed) {
                    wire::with_group_ca(m, &rs.group_ca().der)
                } else {
                    m
                })
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
            && let Some(frame) = next_piece(c, store, releases)
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
fn next_piece(c: &Conn, store: &Store, releases: &Releases) -> Option<Vec<u8>> {
    let mut gets = c.gets.lock().unwrap();
    let g = gets.front_mut()?;
    let want = usize::try_from(g.length).unwrap_or(0).min(wire::MAX_CHUNK_DATA);
    // Through the group's tunnel only the blobs within the limit away from
    // home; the archives of a signed release go there too.
    let read = (!c.tunneled || store.serves_away(&g.sha256))
        .then(|| store.read(&g.sha256, g.offset as u64, want))
        .flatten()
        .or_else(|| releases.read(&g.sha256, g.offset as u64, want, uptime::wall_ms()));
    match read {
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

/// Takes a peer's get into its queue and reports whether there is a new
/// range to serve. A cancel (length 0) drops the queued ranges of its blob
/// and is kept nowhere, so cancels of other blobs hold nothing; more than
/// MAX_GETS ranges at once end the connection.
fn queue_get(gets: &mut VecDeque<wire::Get>, g: wire::Get) -> Result<bool> {
    if g.length == 0 {
        gets.retain(|q| q.sha256 != g.sha256);
        return Ok(false);
    }
    if gets.len() >= MAX_GETS {
        return Err(Error::msg(format!("asked for more than {MAX_GETS} ranges at once")));
    }
    gets.push_back(g);
    Ok(true)
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

/// Whether a dial to addr replaces the connection up at up: a dial
/// through a loopback port (a tunnel's, a relay's) replaces one at home,
/// which may have gone quiet once the peer took the tunnel; nothing else
/// replaces a connection that is up.
fn replaces(addr: &SocketAddr, up: &SocketAddr) -> bool {
    addr.ip().is_loopback() && !up.ip().is_loopback()
}

/// A peer as its hello presents it, with what is not valid left out.
pub(crate) fn peer_of(id: &DeviceId, role: &str, body: &wire::HelloBody, records_only: bool) -> Peer {
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
        caps: wire::clean_caps(&body.caps),
        chain: Vec::new(),
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

/// Reports whether a device found by discovery at `found` (uptime) still
/// counts as on the home network at `now`.
#[cfg_attr(not(feature = "tunnel"), allow(dead_code))]
fn near(found: Option<Duration>, now: Duration) -> bool {
    found.is_some_and(|at| now.saturating_sub(at) < NEAR_GRACE)
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

    use super::{MAX_GETS, MAX_HOME, queue_get, read_any, remember_found};
    use crate::certs::DeviceId;
    use crate::wire;

    /// A peer's cancels of blobs it is not served are kept nowhere, a
    /// cancel drops only its own blob's ranges, and the ranges a peer asks
    /// for at once are bounded.
    #[test]
    fn gets_are_bounded() {
        let get = |b: u8, offset: i64, length: i64| wire::Get { sha256: vec![b; 32], offset, length };
        let mut gets = std::collections::VecDeque::new();
        assert!(queue_get(&mut gets, get(1, 0, 10)).unwrap());
        assert!(queue_get(&mut gets, get(2, 0, 10)).unwrap());
        for b in 3..=255 {
            assert!(!queue_get(&mut gets, get(b, 0, 0)).unwrap());
        }
        assert_eq!(gets.len(), 2);
        assert!(!queue_get(&mut gets, get(1, 0, 0)).unwrap());
        assert_eq!(gets.iter().map(|g| g.sha256[0]).collect::<Vec<_>>(), [2]);
        for i in 1..MAX_GETS {
            assert!(queue_get(&mut gets, get(2, i as i64 * 10, 10)).unwrap());
        }
        assert!(queue_get(&mut gets, get(2, 0, 10)).is_err());
        assert_eq!(gets.len(), MAX_GETS);
    }

    /// A frame's length is checked before its body is read: a message frame
    /// past MAX_FRAME and a chunk frame past MAX_CHUNK_FRAME end the
    /// connection, as does one cut short.
    #[test]
    fn frames_are_bounded() {
        let read = |head: u32, body: &[u8]| {
            let mut b = head.to_be_bytes().to_vec();
            b.extend_from_slice(body);
            read_any(&mut std::io::Cursor::new(b))
        };
        let ping = br#"{"t":"ping"}"#;
        assert!(matches!(read(ping.len() as u32, ping), Ok(super::Frame::Message(_))));
        assert!(read(ping.len() as u32 + 1, ping).is_err());
        // A message padded past MAX_FRAME would decode: only its length refuses it.
        let mut big = ping.to_vec();
        big.resize(wire::MAX_FRAME, b' ');
        assert!(matches!(read(big.len() as u32, &big), Ok(super::Frame::Message(_))));
        big.push(b' ');
        assert!(read(big.len() as u32, &big).is_err());
        assert!(read(0x8000_0000 | (wire::MAX_CHUNK_FRAME as u32 + 1), &[]).is_err());
        assert!(read(u32::MAX, &[]).is_err());
    }
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

    /// The tunnel's port replaces a connection at home to the same device,
    /// which a peer that took the tunnel leaves quiet (the Android
    /// emulator's c2_awayThroughHub waited 15 s for it); nothing else
    /// replaces a connection that is up.
    #[test]
    fn a_tunnel_replaces_a_connection_at_home() {
        let a = |s: &str| s.parse::<std::net::SocketAddr>().unwrap();
        assert!(super::replaces(&a("127.0.0.1:4000"), &a("10.0.2.2:8764")));
        assert!(super::replaces(&a("[::1]:4000"), &a("192.168.1.5:8764")));
        assert!(!super::replaces(&a("127.0.0.1:4000"), &a("127.0.0.1:5000")));
        assert!(!super::replaces(&a("10.0.2.2:8764"), &a("127.0.0.1:4000")));
        assert!(!super::replaces(&a("10.0.2.2:8764"), &a("10.0.2.3:8764")));
    }

    /// A command refused before it is verified (expired, or signed by no
    /// admin) still answers with its ID, which the sender takes the result
    /// by; it waited until it timed out.
    #[test]
    fn a_refused_command_keeps_its_id() {
        let rec = |body: &[u8]| crate::records::Record { body: body.to_vec(), sig: Vec::new(), chain: Vec::new() };
        assert_eq!(super::command_id(&rec(br#"{"type":"mode","to":"aa","id":"c1","expires_ms":5}"#)), "c1");
        assert_eq!(super::command_id(&rec(b"not json")), "");
    }

    /// An announcement alone keeps a device "on this network" only for
    /// NEAR_GRACE: anyone can announce a hub's name and the group's tag on a
    /// foreign network.
    #[test]
    fn near_only_for_a_while() {
        let now = Duration::from_secs(1000);
        assert!(super::near(Some(now), now), "a device just found does not count as near");
        assert!(
            !super::near(Some(now - super::NEAR_GRACE - Duration::from_secs(1)), now),
            "a device found long ago without a connection still counts as near"
        );
        assert!(!super::near(None, now), "a device never found counts as near");
    }

    #[test]
    fn dates() {
        assert_eq!(super::date(0), "1970-01-01");
        assert_eq!(super::date(1761024000), "2025-10-21");
    }
}
