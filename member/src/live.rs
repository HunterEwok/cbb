// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The member of 0.6 that a computer's service runs: the member connection
//! (`mesh`), the clipboard state (`board`) and the glue between them, and
//! what discovery needs to find, dial and take its peers
//! (`discovery::Peers`). A copy a peer brings goes through the board's
//! rule; one to write goes to the service's clipboard watchers (`OnWrite`).

use std::collections::{HashMap, HashSet};
use std::net::{SocketAddr, TcpStream};
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, RwLock, Weak};
use std::time::Duration;

use cbb_core::certs;
use cbb_core::clip::{Kind, Via};
use cbb_core::content::{Content, TYPE_FILES, TYPE_MEDIA};
use cbb_core::media::{Manifest, Part};
use cbb_core::records::body::CAP_DIALS;
use cbb_core::records::{DeviceId, State};
use cbb_core::rule::Verdict;

use crate::board::{Board, LIVE_WINDOW_MS};
use crate::content::Source;
use crate::discovery::{Admit, Dialed, Peers};
use crate::error::{Error, Result};
use crate::mesh::{Arrived, Mesh, SentMedia};
use crate::networks::Networks;
use crate::own::Own;
use crate::pair::home_address;
use crate::roster::id_text;
use crate::sealed::Blob;
use crate::uptime;

/// How long a device that discovery found still counts as at home: anyone
/// on a network can announce a device and the group's tag, so past that
/// only a connection to it counts.
const NEAR_GRACE: Duration = Duration::from_secs(30);
/// The devices found at home that are remembered, as many as a group has.
const MAX_HOME: usize = 256;
/// How often a hub tries to fetch a copy's blob for its clients.
const FETCH_TRIES: usize = 5;

/// A copy from the group to write to this device's clipboard.
#[derive(Clone, Debug)]
pub struct Write {
    /// The copy's ID, which a paste of its images or files names.
    pub id: [u8; 16],
    pub text: String,
    pub kind: Kind,
    /// The manifest of a copy with images or files, whose blob is fetched
    /// before they are written.
    pub media: Option<Manifest>,
    pub blob: Option<Blob>,
    /// The member it came from, which a fetch asks first.
    pub from: DeviceId,
    /// For a secret: how long it may stay in the clipboard.
    pub ttl: Option<Duration>,
}

/// Gets each copy to write.
pub type OnWrite = Box<dyn Fn(Write) + Send + Sync>;

/// What the service does on a group of 0.5 and does not do yet on the
/// records of 0.6, while its parts move over: the cause of the error it
/// answers with, which debug mode shows.
#[derive(Debug)]
pub struct NotYet(pub String);

impl std::fmt::Display for NotYet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} is not on the records of 0.6 yet", self.0)
    }
}

impl std::error::Error for NotYet {}

/// The error for `what` that this build does not do on the records of 0.6
/// yet: never a silent no-op.
pub fn not_yet(what: &str) -> Error {
    Error::with(
        format!(
            "{what} does not work in this build yet: this device's group is on the records of 0.6, and {what} is still moving to them"
        ),
        NotYet(what.to_string()),
    )
}

/// The group's tag as mDNS publishes it (`g`): the first 8 bytes of the
/// group ID in hex.
pub fn tag(state: &State) -> String {
    certs::hex(&state.group.0[..8])
}

/// A device ID as discovery and the old member name it.
fn shown(id: &DeviceId) -> certs::DeviceId {
    // 16 bytes in hex are always a device ID.
    certs::DeviceId::parse(&id_text(id)).unwrap_or_else(|_| certs::DeviceId::random())
}

/// A device ID in hex, as `tunnel.json` keeps it.
pub(crate) fn id_of_hex(s: &str) -> Option<DeviceId> {
    of(&certs::DeviceId::parse(s).ok()?)
}

/// A device ID discovery names.
fn of(id: &certs::DeviceId) -> Option<DeviceId> {
    let s = id.as_str();
    let mut b = [0u8; 16];
    for (i, out) in b.iter_mut().enumerate() {
        *out = u8::from_str_radix(s.get(i * 2..i * 2 + 2)?, 16).ok()?;
    }
    Some(DeviceId(b))
}

/// The member of 0.6 on a computer.
pub struct Live {
    pub mesh: Arc<Mesh>,
    pub board: Board,
    me: DeviceId,
    on_write: RwLock<Option<OnWrite>>,
    kick: (Mutex<u64>, Condvar),
    redials: AtomicUsize,
    paused: AtomicBool,
    closed: AtomicBool,
    window_open: AtomicBool,
    /// The open window's ID, which its mDNS announcement carries as `i`.
    window_id: Mutex<Option<[u8; 16]>>,
    unreached: Mutex<HashSet<DeviceId>>,
    /// The devices discovery found at home, and when (uptime).
    home: Mutex<HashMap<DeviceId, Duration>>,
    networks: RwLock<Option<Arc<Networks>>>,
    /// The images or files this member copied last, which a paste opens,
    /// and when, on the wall clock.
    own_media: Mutex<Option<(SentMedia, i64)>>,
    /// Sync away from home, once the service gave it (`with_away`).
    #[cfg(feature = "tunnel")]
    away: std::sync::OnceLock<Arc<crate::away::Away>>,
    /// The hub's tunnel, while this device serves as a hub of 0.6.
    #[cfg(feature = "tunnel")]
    hub: Mutex<Option<away::HubRun>>,
    /// The hubs above this one that said they serve, while it is a hub.
    #[cfg(feature = "tunnel")]
    ladder: Mutex<away::Ladder>,
    /// When this member last sent `tunnel` to each device connected that
    /// may be a hub.
    #[cfg(feature = "tunnel")]
    toward: Mutex<HashMap<DeviceId, std::time::Instant>>,
    /// Whether this hub stands by, a hub above it serving.
    #[cfg(feature = "tunnel")]
    standing_by: std::sync::atomic::AtomicBool,
    /// The hub this one moves to, while it still serves its clients away
    /// from home (`Live::hand_hub_to`).
    #[cfg(feature = "tunnel")]
    handoff: Mutex<Option<DeviceId>>,
    /// A thread signs again what a resolve voided (`resign_soon`).
    resigning: std::sync::atomic::AtomicBool,
    /// The attestations of member keys, once the service started them
    /// (`with_attestations`).
    attest: std::sync::OnceLock<evidence::Attest>,
    /// The link to the group's blind relay, while the device meets the
    /// group there.
    #[cfg(feature = "tunnel")]
    meeting: Mutex<Option<relay::Meeting>>,
    /// The guests of the invitations this hub keeps open.
    #[cfg(feature = "tunnel")]
    guests: invite::Guests,
    /// The invitations this admin makes through hubs.
    #[cfg(feature = "tunnel")]
    through: through::Throughs,
    log: Arc<dyn Fn(&str) + Send + Sync>,
}

/// Where the images or files a paste opens come from.
pub enum MediaFrom {
    /// This member's own copy, kept here.
    Own(SentMedia),
    /// A copy from the group: its blob, fetched from the member it came
    /// from, and that member.
    Group { manifest: Manifest, blob: Option<Blob>, from: DeviceId },
}

impl MediaFrom {
    pub fn manifest(&self) -> &Manifest {
        match self {
            MediaFrom::Own(m) => &m.manifest,
            MediaFrom::Group { manifest, .. } => manifest,
        }
    }
}

impl Live {
    /// Opens the member of the group kept in dir; an error when the device
    /// is in no group of 0.6.
    pub fn open(dir: &Path, own: Own, log: Arc<dyn Fn(&str) + Send + Sync>) -> Result<Arc<Live>> {
        let mesh = Mesh::open(dir, own, log.clone())?;
        let board = Board::new(Box::new(uptime::wall_ms));
        // Images and files go to the clipboard watchers that take them.
        board.set_takes_media(true);
        let live = Arc::new(Live {
            me: mesh.device(),
            mesh,
            board,
            on_write: RwLock::new(None),
            kick: (Mutex::new(0), Condvar::new()),
            redials: AtomicUsize::new(0),
            paused: AtomicBool::new(false),
            closed: AtomicBool::new(false),
            window_open: AtomicBool::new(false),
            window_id: Mutex::new(None),
            unreached: Mutex::new(HashSet::new()),
            home: Mutex::new(HashMap::new()),
            networks: RwLock::new(None),
            own_media: Mutex::new(None),
            #[cfg(feature = "tunnel")]
            away: std::sync::OnceLock::new(),
            #[cfg(feature = "tunnel")]
            hub: Mutex::new(None),
            #[cfg(feature = "tunnel")]
            ladder: Mutex::new(away::Ladder::default()),
            #[cfg(feature = "tunnel")]
            toward: Mutex::new(HashMap::new()),
            #[cfg(feature = "tunnel")]
            standing_by: std::sync::atomic::AtomicBool::new(false),
            #[cfg(feature = "tunnel")]
            handoff: Mutex::new(None),
            resigning: std::sync::atomic::AtomicBool::new(false),
            attest: std::sync::OnceLock::new(),
            #[cfg(feature = "tunnel")]
            meeting: Mutex::new(None),
            #[cfg(feature = "tunnel")]
            guests: Default::default(),
            #[cfg(feature = "tunnel")]
            through: Default::default(),
            log,
        });
        live.settle(&live.mesh.state());
        if let Err(e) = live.mesh.rotate() {
            live.logf(&format!("cbb: {}", e.for_log()));
        }
        let w = Arc::downgrade(&live);
        live.mesh.on_copy(Box::new(move |a| {
            if let Some(l) = w.upgrade() {
                l.arrived(a);
            }
        }));
        let w: Weak<Live> = Arc::downgrade(&live);
        live.mesh.on_set(Box::new(move |set| {
            if let Some(l) = w.upgrade() {
                let st = set.state();
                l.settle(&st);
                if let Some(a) = l.away() {
                    a.drop_held_gone(&|id| st.device(id).is_some());
                }
                // The records may let in devices refused until now.
                l.redial();
                // A root's resolve may have voided both histories of this
                // device's admin key: what it signed, it signs again, off
                // the set's lock.
                if l.mesh.own().admin.is_some() {
                    l.resign_soon();
                }
            }
        }));
        Ok(live)
    }

    /// Sets what gets the copies to write.
    pub fn on_write(&self, f: OnWrite) {
        *self.on_write.write().unwrap() = Some(f);
    }

    /// The group's tag, which mDNS publishes.
    pub fn tag(&self) -> String {
        tag(&self.mesh.state())
    }

    /// What follows from the records: the window for incoming copies.
    fn settle(&self, state: &State) {
        let (_, secret_ms) = self.board.lifetimes();
        self.board.set_lifetimes(state.incoming_ms.unwrap_or(LIVE_WINDOW_MS), secret_ms);
        // The group's last copy, made on a device removed since, no longer
        // counts here and is never written later (docs/protocol.md,
        // section 10, "The copies setting").
        if let Some(c) = self.board.current()
            && state.device(&c.origin).is_none()
            && self.board.forget(&c.id)
        {
            self.logf(&format!(
                "cbb: the group's last copy no longer counts and is dropped: {} is no device of the group",
                id_text(&c.origin)
            ));
        }
    }

    /// A copy a peer brought, which the core found new.
    fn arrived(self: &Arc<Self>, a: &Arrived) {
        let verdict = self.board.received(a);
        if verdict != Verdict::Write {
            self.fetch_for_clients(a);
        }
        match verdict {
            Verdict::Write => {}
            Verdict::Mode | Verdict::Held | Verdict::Unread => return,
            v => {
                self.logf(&format!("cbb: a copy from {} stays out of the clipboard: {v:?}", id_text(&a.origin)));
                return;
            }
        }
        let c = &a.content;
        let secret = c.is_secret();
        let (_, secret_ms) = self.board.lifetimes();
        let w = Write {
            id: a.id,
            text: c.text.clone().unwrap_or_default(),
            kind: if c.manifest.is_some() {
                Kind::Media
            } else if secret {
                Kind::Secret
            } else {
                Kind::Text
            },
            media: c.manifest.clone(),
            blob: a.blob,
            from: a.from,
            ttl: secret.then(|| Duration::from_millis(secret_ms.saturating_sub(a.age_ms))),
        };
        if let Some(f) = &*self.on_write.read().unwrap() {
            f(w);
        }
    }

    /// A hub, or a device that only passes the copies on, fetches the blob
    /// of a copy it does not write within its limit away from home, so
    /// that its clients away from home can get it (docs/protocol.md,
    /// section 4, "Content"); a copy it writes the service fetches.
    fn fetch_for_clients(self: &Arc<Self>, a: &Arrived) {
        let Some(b) = a.blob else { return };
        let forward_only =
            self.mesh.state().device(&self.me).is_some_and(|d| crate::writers::is_forward_only(d.rights));
        if !(forward_only || self.away().is_some_and(|w| w.is_hub_now())) || b.size > self.mesh.away_limit() {
            return;
        }
        let (w, from) = (Arc::downgrade(self), a.from);
        std::thread::spawn(move || {
            // Again after a pause while no member gives it yet.
            for _ in 0..FETCH_TRIES {
                let Some(l) = w.upgrade() else { return };
                match l.mesh.fetch(&b, &from, l.mesh.away_limit()) {
                    Ok(()) => return,
                    Err(e) => l.logf(&format!("cbb: fetching a copy for the hub's clients: {}", e.details())),
                }
                drop(l);
                std::thread::sleep(Duration::from_secs(2));
            }
        });
    }

    /// A clipboard watcher saw the clipboard change: it goes to the group
    /// unless the board keeps it here.
    pub fn copied(&self, text: &str, kind: Kind, via: Via) -> Result<()> {
        if let Some(c) = self.board.copied(text, kind, via)? {
            self.mesh.copy(&c)?;
        }
        Ok(())
    }

    /// A deliberate send (cbb copy): to the group, unless muted.
    /// A hub that only passes the copies on makes, reads and pastes none
    /// (`writers::is_forward_only`).
    pub fn refuse_forward_only(&self) -> Result<()> {
        let st = self.mesh.state();
        if st.device(&self.me).is_some_and(|d| crate::writers::is_forward_only(d.rights)) {
            return Err(crate::error::Error::msg(crate::node::FORWARD_ONLY));
        }
        Ok(())
    }

    pub fn send(&self, text: &str, kind: Kind, via: Via) -> Result<()> {
        self.refuse_forward_only()?;
        let (c, write) = self.board.send(text, kind, via)?;
        // A group with no other reader yet (this device alone) keeps the
        // copy here, as the board did; nothing goes out.
        self.mesh.copy(&c)?;
        if write {
            let (_, secret_ms) = self.board.lifetimes();
            let w = Write {
                // A text names no copy: only a paste of images or files does.
                id: [0; 16],
                text: text.to_string(),
                kind,
                media: None,
                blob: None,
                from: self.me,
                ttl: (kind == Kind::Secret).then(|| Duration::from_millis(secret_ms)),
            };
            if let Some(f) = &*self.on_write.read().unwrap() {
                f(w);
            }
        }
        Ok(())
    }

    /// Images or files a watcher reported (deliberate false) or cbb copy
    /// FILE handed in (true), with their plain-text alternative: sealed
    /// and kept to serve, the clipboard's content here, and sent to the
    /// group as Board::sends_media says.
    pub fn copy_media(&self, text: &str, parts: Vec<(Part, Source)>, via: Via, deliberate: bool) -> Result<()> {
        self.refuse_forward_only()?;
        let send = self.board.sends_media(deliberate)?;
        let files = parts.iter().any(|(p, _)| !p.path.is_empty() || p.dir);
        let c = Content {
            kind: if files { TYPE_FILES } else { TYPE_MEDIA },
            text: (!text.is_empty()).then(|| text.to_string()),
            via: match via {
                Via::Phone => 1,
                Via::Universal => 2,
                _ => 0,
            },
            ..Content::default()
        };
        let m = self.mesh.copy_media(&c, parts, send)?;
        self.board.copied_media(&m.manifest, text);
        let w = deliberate.then(|| Write {
            id: m.id.unwrap_or_default(),
            text: text.to_string(),
            kind: Kind::Media,
            media: Some(m.manifest.clone()),
            // Kept here: nothing to fetch.
            blob: None,
            from: self.me,
            ttl: None,
        });
        *self.own_media.lock().unwrap() = Some((m, uptime::wall_ms()));
        // cbb copy FILE puts them in this device's own clipboard too, as a
        // text cbb copy does (Live::send); a paste opens its own copy.
        if let (Some(w), Some(f)) = (w, &*self.on_write.read().unwrap()) {
            f(w);
        }
        Ok(())
    }

    /// The ID of the group's newest copy of images or files that this
    /// device reads: its own last one, when it went to the group after the
    /// group's current copy came, else that current copy.
    pub fn media_copy(&self) -> Option<[u8; 16]> {
        let current = self.board.current().filter(|c| c.content.manifest.is_some() && c.content.writable());
        let own = self.own_media.lock().unwrap().clone().and_then(|(m, at)| Some((m.id?, at)));
        match (own, current) {
            (Some((id, at)), Some(c)) if at >= c.at_ms => Some(id),
            (_, Some(c)) => Some(c.id),
            (Some((id, _)), None) => Some(id),
            (None, None) => None,
        }
    }

    /// The images or files a paste opens: the group's copy `copy` (its ID
    /// in hex) while it is the current one; else, in a mode that receives,
    /// this member's own clipboard (its own copy, or the group's that was
    /// written to it); else the group's current copy.
    pub fn media_to_paste(&self, copy: &str) -> Result<MediaFrom> {
        let group = |c: crate::board::Current| -> Option<MediaFrom> {
            Some(MediaFrom::Group { manifest: c.content.manifest.clone()?, blob: c.blob, from: c.from })
        };
        if !copy.is_empty() {
            let c = self.board.current().filter(|c| certs::hex(&c.id) == copy && c.content.writable());
            return c
                .and_then(group)
                .ok_or_else(|| Error::msg("the copy to paste is no longer the group's current copy"));
        }
        if self.board.mode().receives() {
            let (m, _, _) =
                self.board.local_media().ok_or_else(|| Error::msg("the clipboard holds no images or files"))?;
            if let Some((own, _)) = self.own_media.lock().unwrap().clone().filter(|o| o.0.manifest == m) {
                return Ok(MediaFrom::Own(own));
            }
            return self
                .board
                .current()
                .filter(|c| c.content.manifest.as_ref() == Some(&m))
                .and_then(group)
                .ok_or_else(|| Error::msg("the copy's images or files are no longer kept here; copy them again"));
        }
        self.board.current().and_then(group).ok_or_else(|| Error::msg("the group's copy is no images or files"))
    }

    /// Opens the images or files of `from` into the new folder `out`, the
    /// group's fetched first (at most `max` bytes).
    pub fn open_media(&self, from: &MediaFrom, max: u64, out: &Path) -> Result<Vec<(Part, std::path::PathBuf)>> {
        match from {
            MediaFrom::Own(m) => self.mesh.open_media(m.blob.as_ref(), &m.manifest, out),
            MediaFrom::Group { manifest, blob, from } => {
                if let Some(b) = blob {
                    self.mesh.fetch(b, from, max)?;
                }
                self.mesh.open_media(blob.as_ref(), manifest, out)
            }
        }
    }

    /// The known networks, where the member port takes connections and
    /// mDNS publishes this device.
    /// On a hub, the archives of the release held that the devices seen
    /// update from and this device does not hold whole, at most
    /// `releases::MAX_WANTED`, for its cbb update to download; elsewhere none
    /// (docs/protocol.md, section 16, "In the group").
    pub fn wanted_release_files(&self) -> Option<Vec<String>> {
        if !self.away().is_some_and(|a| a.is_hub_now()) {
            return None;
        }
        let r = self.mesh.releases()?;
        Some(r.wanted(&self.mesh.archives(), crate::uptime::wall_ms())).filter(|w| !w.is_empty())
    }

    pub fn set_networks(&self, n: Arc<Networks>) {
        *self.networks.write().unwrap() = Some(n);
    }

    /// A home window opened with its ID, or closed (None).
    pub fn set_window(&self, id: Option<[u8; 16]>) {
        *self.window_id.lock().unwrap() = id;
        self.window_open.store(id.is_some(), Ordering::SeqCst);
        self.kick();
    }

    /// Stops dialing and taking connections until resume.
    pub fn pause(&self) {
        self.paused.store(true, Ordering::SeqCst);
        self.mesh.close_connections();
        self.kick();
    }

    pub fn resume(&self) {
        self.paused.store(false, Ordering::SeqCst);
        self.kick();
    }

    /// Makes the dial loops try at once.
    /// Signs again, on a thread of its own and one at a time, what the
    /// root's resolve voided of this device's records (`Mesh::resign_voided`).
    fn resign_soon(self: &Arc<Self>) {
        if self.resigning.swap(true, std::sync::atomic::Ordering::SeqCst) {
            return;
        }
        let w = Arc::downgrade(self);
        std::thread::spawn(move || {
            let Some(l) = w.upgrade() else { return };
            l.mesh.resign_voided();
            l.resigning.store(false, std::sync::atomic::Ordering::SeqCst);
        });
    }

    pub fn redial(&self) {
        self.redials.fetch_add(1, Ordering::SeqCst);
        self.kick();
    }

    /// Whether discovery found the device at home within NEAR_GRACE.
    pub fn at_home(&self, id: &DeviceId) -> bool {
        self.home.lock().unwrap().get(id).is_some_and(|at| uptime::now().saturating_sub(*at) < NEAR_GRACE)
    }

    /// Whether discovery found any device of the group at home within
    /// NEAR_GRACE.
    pub fn any_at_home(&self) -> bool {
        self.home.lock().unwrap().values().any(|at| uptime::now().saturating_sub(*at) < NEAR_GRACE)
    }

    /// The members connected only because this one dialed them back.
    pub fn unreached(&self) -> Vec<String> {
        let connected = self.mesh.connected();
        let mut out: Vec<String> =
            self.unreached.lock().unwrap().iter().filter(|id| connected.contains(id)).map(id_text).collect();
        out.sort();
        out
    }

    /// Stops the member: every connection ends with a goodbye.
    pub fn close(&self) {
        self.closed.store(true, Ordering::SeqCst);
        self.mesh.close();
        self.kick();
    }
}

impl Peers for Live {
    fn me(&self) -> certs::DeviceId {
        shown(&self.me)
    }

    fn is_closed(&self) -> bool {
        self.closed.load(Ordering::SeqCst) || self.mesh.is_closed()
    }

    fn is_paused(&self) -> bool {
        self.paused.load(Ordering::SeqCst)
    }

    fn redials(&self) -> usize {
        self.redials.load(Ordering::SeqCst)
    }

    fn nap(&self, d: Duration) -> bool {
        let (m, cv) = &self.kick;
        let g = m.lock().unwrap();
        let start = *g;
        let (g, _) = cv.wait_timeout_while(g, d, |n| *n == start && !self.is_closed()).unwrap();
        *g != start
    }

    fn kick(&self) {
        let (m, cv) = &self.kick;
        *m.lock().unwrap() += 1;
        cv.notify_all();
    }

    fn connected(&self, id: &certs::DeviceId) -> bool {
        of(id).is_some_and(|d| self.mesh.connected().contains(&d))
    }

    /// Any connection up counts: the member of 0.6 dials only at home, so
    /// no dial to a tunnel's port replaces one.
    fn connected_for(&self, id: &certs::DeviceId, _addr: &SocketAddr) -> bool {
        Peers::connected(self, id)
    }

    fn set_unreached(&self, id: &certs::DeviceId, unreached: bool) {
        let Some(d) = of(id) else { return };
        let mut u = self.unreached.lock().unwrap();
        if unreached {
            u.insert(d);
        } else {
            u.remove(&d);
        }
    }

    fn dial_ended(&self, addr: SocketAddr, peer: Option<certs::DeviceId>) -> Result<Dialed> {
        if self.is_closed() {
            return Err(Error::msg("the service is stopping"));
        }
        if self.is_paused() {
            return Err(Error::msg("the member is paused"));
        }
        if !home_address(addr.ip()) {
            return Err(Error::msg(format!(
                "{addr} is not on the home network; on the records of 0.6 this device reaches its group only at home for now"
            )));
        }
        let expect = match &peer {
            Some(p) => Some(of(p).ok_or_else(|| Error::msg(format!("{p} is not a device ID")))?),
            None => None,
        };
        let id = self.mesh.dial(addr, expect)?;
        Ok(Dialed { up: true, again: false, id: Some(shown(&id)) })
    }

    fn accept_checked(
        &self,
        sock: TcpStream,
        addr: SocketAddr,
        handshaken: &mut dyn FnMut(),
        admit: Option<&Admit>,
    ) -> Result<()> {
        if self.is_closed() {
            return Err(Error::msg("the service is stopping"));
        }
        if self.is_paused() {
            return Err(Error::msg("the member is paused"));
        }
        if let Some(admit) = admit {
            // A blind relay's call: a member connection from the device the
            // relay said calls from that port, and nothing else.
            handshaken();
            return self
                .mesh
                .accept_checked(sock, &|id| {
                    crate::certs::DeviceId::parse(&id_text(id)).is_ok_and(|d| admit(addr.port(), &d))
                })
                .map(|_| ());
        }
        self.mesh.accept_port_with(sock, handshaken).map(|_| ())
    }

    fn takes_on(&self, local: SocketAddr, from: SocketAddr) -> bool {
        let Some(n) = self.networks.read().unwrap().clone() else { return true };
        from.ip().to_canonical().is_loopback() || self.window_open.load(Ordering::SeqCst) || n.knows(local.ip())
    }

    fn logf(&self, s: &str) {
        (self.log)(s)
    }

    fn can_dial(&self) -> bool {
        let st = self.mesh.state();
        st.devices.iter().find(|d| d.id == self.me).is_none_or(|d| d.caps & CAP_DIALS != 0)
    }

    fn networks(&self) -> Option<Arc<Networks>> {
        self.networks.read().unwrap().clone()
    }

    fn window_open(&self) -> bool {
        self.window_open.load(Ordering::SeqCst)
    }

    fn window_fingerprint(&self) -> String {
        certs::hex(&self.mesh.own().hash().0)
    }

    fn window_id(&self) -> String {
        self.window_id.lock().unwrap().map(|id| certs::hex(&id)).unwrap_or_default()
    }

    fn found(&self, id: &certs::DeviceId, here: bool) {
        let Some(d) = of(id) else { return };
        let mut home = self.home.lock().unwrap();
        if !here {
            home.remove(&d);
        } else if home.len() < MAX_HOME || home.contains_key(&d) {
            home.entry(d).or_insert_with(uptime::now);
        }
    }

    fn known(&self) -> Vec<String> {
        let mut out: Vec<String> = self.mesh.state().devices.iter().map(|d| id_text(&d.id)).collect();
        out.sort();
        out
    }
}

/// The first four bytes of a device ID in hex, as the log names a device.
#[cfg_attr(not(feature = "tunnel"), allow(dead_code))]
fn id_text4(id: &DeviceId) -> String {
    certs::hex(&id.0[..4])
}

#[cfg(feature = "tunnel")]
mod away;
mod evidence;
pub mod invite;
#[cfg(not(feature = "tunnel"))]
mod off;
#[cfg(feature = "tunnel")]
mod relay;
mod relays;
#[cfg(feature = "tunnel")]
mod through;

#[cfg(test)]
mod tests;
