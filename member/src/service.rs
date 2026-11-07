// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The lite member's service: the control socket, the identity, the sync
//! engine and the connections to the other members.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError, SyncSender};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use crate::actions;
use crate::away::Away;
use crate::clip::{Engine, Event, Kind, Mode, Via};
use crate::control::{self, Device, Header, Message, Status};
use crate::copies;
use crate::discovery;
use crate::error::{Context, Error, Result};
use crate::files;
use crate::hlc::{self, Clock, Timestamp};
use crate::identity::Identity;
use crate::identity::Stored as _;
use crate::node::{Node, WriteReq};
use crate::peer;
use crate::records::Records;
use crate::records::Stored as _;
use crate::remotepaste;
use crate::uptime;
use crate::window::{self, Window};
use crate::wire;
use cbb_core::media::Manifest;

/// The release's version, such as "0.3.0", which the release build passes in
/// `CBB_VERSION`; other builds say "dev", as the Go service does.
pub const VERSION: &str = match option_env!("CBB_VERSION") {
    Some(v) => v,
    None => "dev",
};
const MARK_FILE: &str = "hlc.mark";
/// The sync mode, in the state directory. A device that joined its group
/// gets one at once, with own; without it, the device joined before sync
/// modes existed and keeps sharing as it did.
const MODE_FILE: &str = "mode";
/// The most command IDs the replay cache keeps; a command lives at most 30
/// seconds, so this many in that time is far more than any admin sends.
const MAX_COMMANDS: usize = 4096;
const WATCH_QUEUE: usize = 16;
/// How long the service waits before it restarts at an admin's request,
/// so that the result reaches the sender first.
const RESTART_AFTER: Duration = Duration::from_millis(500);

/// The targets a watcher offers for remote paste, as its watch request
/// names them (docs/protocol.md, section 8). The lite member has no desktop
/// of its own, but a full member's desktop connector may watch it.
pub(crate) const DESKTOP: &str = "desktop";
pub(crate) const TMUX: &str = "tmux";
pub(crate) const CONSOLE: &str = "console";
/// The ZX Spectrum Next's keyboard, through `cbb next link` and the Next's
/// driver on a Next's Pi.
pub(crate) const NEXT: &str = "next";

/// How long a watcher may take to put a paste in; typing takes TYPE_WAIT
/// more for each byte, as on a full member.
const INJECT_WAIT: Duration = Duration::from_secs(5);
const TYPE_WAIT: Duration = Duration::from_millis(5);

/// What the service sends a watcher: a write for its clipboard, or a paste
/// to put where the focus is.
enum ToWatcher {
    Write(WriteReq),
    Inject(Inject),
}

/// A remote paste for a watcher, with where its answer goes: the status,
/// done, refused or failed, and the reason.
struct Inject {
    text: String,
    method: String,
    enter: bool,
    /// The target may paste where nothing tells whether the session is
    /// locked (remotepaste::Settings).
    no_lock_check: bool,
    kind: String,
    name: String,
    done: SyncSender<(String, String)>,
}

/// The pastes sent to a watcher that wait for its answer, by their seq.
type Waiting = HashMap<u64, SyncSender<(String, String)>>;

/// A watcher connected to the control socket.
struct Watcher {
    id: usize,
    /// The paste target it offers; empty for none.
    target: String,
    /// It holds a clipboard: tmux, the console and paste-only watchers do
    /// not, so they get no writes and report no copies.
    board: bool,
    /// Its user, read when it offers a target (peer.rs).
    uid: Option<u32>,
    /// Its clipboard takes images, files and formatted text whole.
    images: bool,
    files: bool,
    html: bool,
    tx: SyncSender<ToWatcher>,
}

impl Watcher {
    /// Whether its clipboard takes the copy m whole, as on a full member.
    fn takes(&self, m: &Manifest) -> bool {
        let has = |t: &str| m.parts.iter().any(|p| p.kind == t);
        if m.files() {
            return self.files;
        }
        self.images && (has("image/png") || has("image/jpeg")) || self.html && has("text/html")
    }
}

/// How the service runs.
pub struct Config {
    pub state_dir: PathBuf,
    pub socket: PathBuf,
    pub name: String,
    /// Members to dial by address, for networks where multicast does not
    /// reach.
    pub peers: Vec<SocketAddr>,
    /// Find the members with mDNS, and publish this one.
    pub mdns: bool,
    /// The member port, where phones and other lite members dial
    /// this one; None listens nowhere.
    pub port: Option<u16>,
    /// Where the tunnel sends its packets instead of the hub's addresses: a
    /// local UDP port that leads to the hub, such as `cbb next link -udp`.
    pub tunnel_via: Option<SocketAddr>,
    /// It runs as a computer's service, a full member that may become an
    /// admin, even before its own device record arrives.
    pub full: bool,
}

struct Service {
    node: RwLock<Option<Arc<Node>>>,
    away: RwLock<Option<Arc<Away>>>,
    watchers: Mutex<Vec<Watcher>>,
    next_watcher: AtomicUsize,
    /// The limits of remote paste per sender.
    pastes: Mutex<remotepaste::Limiter>,
    /// The limits of quick actions per sender, as remote paste's.
    acts: Mutex<remotepaste::Limiter>,
    pending: Mutex<Option<WriteReq>>, // a write decided while no watcher was connected
    /// The seq of the latest write: a copy of images or files fetched after
    /// a newer write is not written. A mutex, as 32-bit MIPS has no 64-bit
    /// atomics.
    latest: Mutex<u64>,
    /// The latest copy of images or files this member made or wrote, which
    /// paste-media opens.
    media: Mutex<Option<Arc<Event>>>,
    /// This device's largest copy of images or files (cbb config).
    limits: Mutex<copies::Limits>,
    state_dir: PathBuf,
    /// The replay cache: the IDs of the commands carried out, until they
    /// expire, in milliseconds since the Unix epoch.
    commands: Mutex<HashMap<String, i64>>,
    /// When the service started: the replay cache starts empty, so a
    /// command signed before is refused.
    started_ms: i64,
    log: Arc<dyn Fn(&str) + Send + Sync>,
    /// cbb-helper, where it is beside cbb (helper.rs): what needs Go.
    #[allow(dead_code, reason = "the operations that need Go come in the next steps of the Rust service")]
    helper: Option<Arc<crate::helper::Helper>>,
    /// This device's name, for the group it makes with cbb new.
    name: String,
    /// One cbb new at a time, so two requests cannot make two groups.
    creating: Mutex<()>,
    /// The pairing running here: a window for a code, or an admission by
    /// a QR code; one at a time.
    pairing: Mutex<Option<Pairing>>,
    /// The member port, for the address a pairing window shows.
    port: Mutex<Option<u16>>,
}

/// A pairing that runs on this device.
enum Pairing {
    Window(Arc<Window>),
    Qr,
}

/// Frees the pairing slot when dropped.
struct PairingSlot<'a> {
    svc: &'a Service,
    node: Arc<Node>,
}

static STOP: AtomicBool = AtomicBool::new(false);
/// An admin had the service restart: it stops with an error, after which
/// systemd starts it again.
static RESTART: AtomicBool = AtomicBool::new(false);
/// The device left its group (cbb leave): the service stops as for a
/// restart, and starts again in no group.
static LEFT: AtomicBool = AtomicBool::new(false);

extern "C" fn on_signal(_: libc::c_int) {
    STOP.store(true, Ordering::SeqCst);
}

/// Logs to standard error, which systemd or procd keeps.
pub fn log_line(s: &str) {
    eprintln!("{s}");
}

/// Runs the service until SIGTERM or SIGINT.
pub fn run(cfg: Config) -> Result<()> {
    // SAFETY: the handler only stores to an atomic.
    unsafe {
        libc::signal(libc::SIGTERM, on_signal as *const () as libc::sighandler_t);
        libc::signal(libc::SIGINT, on_signal as *const () as libc::sighandler_t);
        libc::signal(libc::SIGPIPE, libc::SIG_IGN);
    }
    std::fs::create_dir_all(&cfg.state_dir).context(format!("cannot create {}", cfg.state_dir.display()))?;
    let log: Arc<dyn Fn(&str) + Send + Sync> = Arc::new(log_line);
    if crate::records::leave_version1_group(&cfg.state_dir)? {
        log(&format!(
            "cbb: this device's group was made before 0.6, whose records 0.6 does not read, so it left that group (its files are in {}); set the group up again and join it with the phone's QR code",
            crate::records::OLD_GROUP_DIR
        ));
    }
    let svc = Arc::new(Service {
        node: RwLock::new(None),
        away: RwLock::new(None),
        watchers: Mutex::new(Vec::new()),
        next_watcher: AtomicUsize::new(0),
        pastes: Mutex::new(remotepaste::Limiter::default()),
        acts: Mutex::new(remotepaste::Limiter::default()),
        pending: Mutex::new(None),
        latest: Mutex::new(0),
        media: Mutex::new(None),
        limits: Mutex::new(copies::Limits::load(&cfg.state_dir).unwrap_or_else(|e| {
            log(&format!("cbb: {}; the largest copy is the default", e.for_log()));
            copies::Limits::default()
        })),
        state_dir: cfg.state_dir.clone(),
        commands: Mutex::new(HashMap::new()),
        started_ms: uptime::wall_ms(),
        log: log.clone(),
        helper: crate::helper::shared(),
        name: cfg.name.clone(),
        creating: Mutex::new(()),
        pairing: Mutex::new(None),
        port: Mutex::new(None),
    });
    if let Some(h) = svc.helper.clone() {
        // Started at once, so that a helper that cannot run shows in the
        // log at the start rather than at the first request.
        let log = log.clone();
        std::thread::spawn(move || {
            if let Err(e) = h.hello() {
                log(&format!("cbb: {}", e.for_log()));
            }
        });
    }
    // Parts of copies on their way when the service last stopped.
    let _ = std::fs::remove_dir_all(cfg.state_dir.join("tmp"));
    let only = crate::interfaces::only();
    if !only.is_empty() {
        log(&format!("cbb: the member port and mDNS work only on {} (CBB_INTERFACES)", only.join(", ")));
    }
    let admin_socket = control::admin_socket(&cfg.socket);
    for (ln, admin) in [(listen(&cfg.socket, false)?, false), (listen(&admin_socket, true)?, true)] {
        let svc = svc.clone();
        std::thread::spawn(move || accept_control(ln, move |conn| svc.serve(conn, admin)));
    }

    // Wait until the device is in a group: cbb pair may run meanwhile.
    let mut said = false;
    let ident = loop {
        if STOP.load(Ordering::SeqCst) {
            let _ = std::fs::remove_file(&cfg.socket);
            let _ = std::fs::remove_file(&admin_socket);
            return Ok(());
        }
        match Identity::load(&cfg.state_dir)? {
            Some(id) => break id,
            None => {
                if !said {
                    log("cbb: this device is in no group yet; run cbb pair");
                    said = true;
                }
                std::thread::sleep(Duration::from_secs(2));
            }
        }
    };
    match crate::sealkey::load(&cfg.state_dir).and_then(crate::sealkey::set) {
        Ok(()) => {}
        Err(e) => log(&format!("cbb: the key for sealed commands: {}; commands come unsealed", e.for_log())),
    }
    let records = Records::load(&cfg.state_dir, &ident.group_ca)?;
    let ident = with_roots(ident, &records, &cfg.state_dir, &*log);
    log(&format!("cbb: device {} in group {}, version {VERSION}", ident.id, ident.tag()));
    let engine = Arc::new(Engine::new(
        ident.id.as_str(),
        clock(&cfg.state_dir),
        Box::new(uptime::wall_ms),
        Box::new(uptime::now),
    ));
    let tag = ident.tag();
    let away =
        Arc::new(Away::new(cfg.state_dir.clone(), tag.clone(), ident.id.clone(), log.clone()).via(cfg.tunnel_via));
    let presence = presence_of(&ident, &records, &cfg.name, cfg.full);
    let node = {
        let svc = svc.clone();
        Arc::new(
            Node::new(
                ident,
                &cfg.name,
                engine.clone(),
                records,
                cfg.state_dir.clone(),
                Box::new(move |w| svc.deliver(w)),
                log.clone(),
            )
            .with_content()
            .presenting(presence),
        )
    };
    // Images and files go to the clipboard watchers that take them, as on
    // a full member.
    engine.set_takes_media(true);
    // The copies this member makes are sealed to the group's readers and
    // signed (docs/protocol.md, section 4).
    engine.set_seal(node.sealer());
    engine.set_mode(load_mode(&cfg.state_dir)?);
    log(&format!("cbb: the sync mode is {}", engine.mode().name()));
    if let Err(e) = crate::mute::load(&cfg.state_dir, &engine) {
        log(&format!("cbb: the mute: {}; not muted", e.for_log()));
    }
    {
        let svc = svc.clone();
        node.on_command(Arc::new(move |peer, c| svc.command(peer, c)));
    }
    // A computer that is no admin offers an admin key for the root to
    // certify, and keeps the admin CA the root sends for it.
    if node.role() == "full" {
        match crate::admin::admin_key_offer(&cfg.state_dir, &node.identity()) {
            Ok(offer) => node.offer_admin_key(offer),
            Err(e) => log(&format!("cbb: making the admin key: {}", e.for_log())),
        }
        let (dir, n, log, away) = (cfg.state_dir.clone(), Arc::downgrade(&node), log.clone(), away.clone());
        node.on_message(Box::new(move |from, m| {
            let Some(node) = n.upgrade() else { return };
            if let Some(der) = m.admin_ca.as_deref().filter(|_| m.kind == "admin")
                && let Err(e) = crate::admin::become_admin(&dir, &node, der)
            {
                log(&format!("cbb: the admin CA from {from}: {}", e.for_log()));
            }
            // What another of the group's hubs shares (docs/protocol.md,
            // section 11, "Several hubs").
            if let (Some(v), "hubs") = (m.hubs.as_ref(), m.kind.as_str()) {
                away.hubs_shared(&node, from, &node.chain_of(from), v);
            }
        }));
    }
    {
        let svc = svc.clone();
        node.on_pairing(Arc::new(move |sock, session, exporter, addr| svc.pair_conn(sock, session, exporter, addr)));
    }
    node.set_actions(actions::load(&cfg.state_dir)?.on());
    node.set_tunnel_key(away.key());
    {
        let away = away.clone();
        let n = Arc::downgrade(&node);
        node.on_tunnel(Box::new(move |from, v, may_host| {
            if let (Some(hub), Some(node)) = (away.offered(from, v, may_host), n.upgrade()) {
                away.retry(&node, &hub);
            }
        }));
    }
    {
        // On a hub, a member's hello brings its tunnel key, which the hub
        // admits, and gets the hub's offers back.
        let (away, n) = (away.clone(), Arc::downgrade(&node));
        node.on_hello(Box::new(move |from, peer, chain| match n.upgrade() {
            Some(node) => away.hello(&node, from, peer, chain),
            None => Vec::new(),
        }));
    }
    *svc.node.write().unwrap() = Some(node.clone());
    {
        // The claims to take the group over: one takes effect when its
        // delay ends, without a new record, and this admin's own makes it
        // the root then. A root also renews the admin CAs of the admins
        // connected that have one from an earlier root, and a hub forgets
        // the clients the records remove.
        let (node, dir, name, log, away) =
            (node.clone(), cfg.state_dir.clone(), cfg.name.clone(), log.clone(), away.clone());
        std::thread::spawn(move || {
            let (mut last, mut failed) = (String::new(), String::new());
            let renewed = std::sync::Mutex::new(std::collections::HashMap::new());
            while !node.is_closed() {
                crate::admin::renew_admin_cas(&dir, &node, &renewed);
                // A hub drops the clients the records now refuse, and every
                // member the offers of devices that may no longer be hubs.
                away.prune(&node);
                let now = claim_states(&node);
                if now != last {
                    last = now;
                    node.settle();
                }
                match crate::admin::finish_takeover(&dir, &node, &name) {
                    Err(e) if e.for_log() != failed => {
                        failed = e.for_log();
                        log(&format!("cbb: taking the group over: {failed}"));
                    }
                    Err(_) => {}
                    Ok(_) => failed.clear(),
                }
                std::thread::sleep(CLAIM_CHECK);
            }
        });
    }
    *svc.away.write().unwrap() = Some(away.clone());
    let port = cfg.port.and_then(|p| discovery::listen(node.clone(), p, log.clone()));
    *svc.port.lock().unwrap() = port;
    if let Some(p) = port {
        log(&format!("cbb: listening on port {p}"));
    }
    discovery::start(node.clone(), tag, cfg.peers.clone(), cfg.mdns, port, log.clone());
    {
        let node = node.clone();
        std::thread::spawn(move || away.run(node));
    }

    while !STOP.load(Ordering::SeqCst) {
        std::thread::sleep(Duration::from_millis(200));
    }
    log("cbb: stopping");
    node.close();
    std::thread::sleep(Duration::from_millis(500));
    let _ = std::fs::remove_file(&cfg.socket);
    let _ = std::fs::remove_file(&admin_socket);
    if LEFT.load(Ordering::SeqCst) {
        return Err(Error::msg("restarting after leaving the group"));
    }
    if RESTART.load(Ordering::SeqCst) {
        return Err(Error::msg("restarting at an admin's request"));
    }
    Ok(())
}

/// How this member presents itself in its hellos: as a computer with the
/// service (`full`) when its own device record says so, as the group's
/// root on a computer made it; as a lite member otherwise. Its keys are in
/// the hardware when cbb-helper holds the device key.
/// How often the claims to take the group over are looked at again.
const CLAIM_CHECK: Duration = Duration::from_secs(2);

/// Every claim of the records with its state: what changes when a claim
/// takes effect.
fn claim_states(node: &Node) -> String {
    let st = node.records().lock().unwrap().state();
    st.claims.iter().map(|c| format!("{}={} ", cbb_core::certs::hex(&c.record.0), c.state)).collect()
}

fn presence_of(ident: &Identity, records: &Records, name: &str, computer: bool) -> crate::node::Presence {
    let full = computer || records.devices().iter().any(|d| d.id == ident.id.as_str() && d.role == "full");
    crate::node::Presence {
        role: if full { "full" } else { "lite" }.into(),
        name: name.to_string(),
        os: if full { crate::admin::os_name() } else { "linux" }.into(),
        key_store: if ident.external.is_some() {
            "hardware"
        } else if crate::rootless::is() {
            "rootless"
        } else {
            "file"
        }
        .into(),
        device: crate::device::own().clone(),
        admin_key: Default::default(),
    }
}

/// Takes the roots that the records lead to when they differ from the
/// identity's, compared by content, so a root the records do not name never
/// stays trusted; an empty set says nothing yet.
fn with_roots(ident: Identity, records: &Records, dir: &Path, log: &dyn Fn(&str)) -> Identity {
    let roots = records.roots();
    if records.is_empty() || roots.iter().map(|c| &c.der).eq(ident.roots.iter().map(|c| &c.der)) {
        return ident;
    }
    let mut next = ident.clone();
    next.roots = roots;
    match next.save(dir) {
        Ok(()) => next,
        Err(e) => {
            log(&format!("cbb: {}", e.for_log()));
            ident
        }
    }
}

/// Reads the sync mode from dir: shared when there is no mode file.
pub fn load_mode(dir: &Path) -> Result<Mode> {
    match std::fs::read_to_string(dir.join(MODE_FILE)) {
        Ok(s) => Mode::parse(s.trim()).map_err(|e| e.context(MODE_FILE)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Mode::Shared),
        Err(e) => Err(e).context(format!("cannot read {}", dir.join(MODE_FILE).display())),
    }
}

fn save_mode(dir: &Path, m: Mode) -> Result<()> {
    files::write_atomic(&dir.join(MODE_FILE), format!("{}\n", m.name()).as_bytes(), 0o600)
        .map_err(|e| e.context("saving the sync mode"))
}

/// Gives a device that just joined a group the sync mode of a new device,
/// own, unless it has a mode from an earlier group.
pub fn new_device_mode(dir: &Path) -> Result<()> {
    if dir.join(MODE_FILE).exists() {
        return Ok(());
    }
    save_mode(dir, Mode::Own)
}

/// The hybrid clock, which never goes back before the mark it saved.
pub(crate) fn clock(dir: &Path) -> Clock {
    let path = dir.join(MARK_FILE);
    let mark = std::fs::read_to_string(&path).ok().and_then(|s| Timestamp::parse(s.trim())).unwrap_or_default();
    let (floor, reset) = hlc::floor(mark, uptime::wall_ms());
    if reset {
        log_line(&format!(
            "cbb: the clock's saved mark ({mark}) is more than 7 days ahead of this device's clock; this device's clock was ahead and is right now, so it starts from it"
        ));
    }
    let log_path = path.display().to_string();
    Clock::new(
        Box::new(uptime::wall_ms),
        floor,
        Some(Box::new(move |t| match files::write_atomic(&path, format!("{t}\n").as_bytes(), 0o600) {
            Ok(()) => true,
            Err(e) => {
                log_line(&format!("cbb: saving {log_path}: {}", e.for_log()));
                false
            }
        })),
    )
}

/// Listens on the control socket: mode 0660, in its own directory; the
/// admin socket gets mode 0600, for root and the service's user only.
fn listen(path: &Path, admin: bool) -> Result<UnixListener> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).context(format!("cannot create {}", dir.display()))?;
    }
    if UnixStream::connect(path).is_ok() {
        return Err(Error::msg(format!("another lite member service runs at {}", path.display())));
    }
    let _ = std::fs::remove_file(path);
    // The socket is made in a new directory that only the service can enter,
    // narrowed there and then moved into place, so nobody can connect before
    // its mode is right, whatever the umask.
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    let dir = path.parent().unwrap_or(Path::new("."));
    let tmp = dir.join(format!(".c{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::DirBuilder::new().mode(0o700).create(&tmp).context(format!("cannot create {}", tmp.display()))?;
    let made = (|| {
        let tmp_path = tmp.join("s");
        let ln = UnixListener::bind(&tmp_path).context(format!("cannot listen at {}", path.display()))?;
        std::fs::set_permissions(&tmp_path, std::fs::Permissions::from_mode(if admin { 0o600 } else { 0o660 }))
            .context("cannot set the socket's mode")?;
        std::fs::rename(&tmp_path, path).context(format!("cannot move the socket to {}", path.display()))?;
        Ok(ln)
    })();
    let _ = std::fs::remove_dir_all(&tmp);
    made
}

fn kind_of(s: &str) -> Result<Kind> {
    match s {
        "" | "text" => Ok(Kind::Text),
        "secret" => Ok(Kind::Secret),
        _ => Err(Error::msg(format!("unknown kind {s:?}"))),
    }
}

fn via_of(s: &str) -> Result<Via> {
    match s {
        "" | "copy" => Ok(Via::Copy),
        "phone" => Ok(Via::Phone),
        "universal-clipboard" => Ok(Via::Universal),
        _ => Err(Error::msg(format!("unknown via {s:?}"))),
    }
}

fn kind_name(k: Kind) -> &'static str {
    match k {
        // A write of images or files goes as kind media (watch); elsewhere
        // such a copy is its text.
        Kind::Text | Kind::Media => "text",
        Kind::Secret => "secret",
    }
}

fn via_name(v: Via) -> &'static str {
    match v {
        Via::Copy => "copy",
        Via::Phone => "phone",
        Via::Universal => "universal-clipboard",
    }
}

impl Service {
    fn node(&self) -> Result<Arc<Node>> {
        self.node.read().unwrap().clone().ok_or_else(|| Error::msg("this device is in no group; run cbb pair"))
    }

    fn away(&self) -> Result<Arc<Away>> {
        self.away.read().unwrap().clone().ok_or_else(|| Error::msg("this device is in no group; run cbb pair"))
    }

    /// cbb global: shows sync away from home, or turns it on or off. The
    /// lite member keeps its keys in files, so turning it on needs the
    /// user's consent.
    fn global(&self, h: &Header) -> Result<Message> {
        let (node, away) = (self.node()?, self.away()?);
        match h.name.as_str() {
            "" => {}
            "on" if !h.consent => {
                return Err(Error::msg(
                    "this device keeps its keys in files, so sync away from home needs your consent; run cbb global on and read what it says",
                ));
            }
            "on" => node.set_tunnel_key(Some(away.turn_on()?)),
            "off" if !h.device.is_empty() => self.admin(|a| a.away_off_on(&h.device))?,
            "off" => {
                away.turn_off()?;
                node.set_tunnel_key(None);
            }
            "hub" if !h.device.is_empty() => self.admin(|a| {
                away.make_hub_on(a, &h.device, &h.addrs, (&h.forwarder, &h.forwarder_key), h.forward_only)
            })?,
            "hub-off" if !h.device.is_empty() => self.admin(|a| away.stop_hub_on(a, &h.device, h.force))?,
            "move" if h.device.is_empty() => {
                return Err(Error::msg("cbb global move names the device to move the hub to"));
            }
            "move" => self.admin(|a| away.move_hub(a, &h.device, &h.addrs, (&h.forwarder, &h.forwarder_key)))?,
            "hub" => {
                crate::admin::may_be_hub(&self.state_dir, &node)?;
                node.set_tunnel_key(Some(away.make_hub(h)?));
                // The members connect again, so their hellos carry the key
                // and get the hub's offer.
                node.reconnect();
            }
            "hub-off" => away.stop_hub(&node, h.force)?,
            "relay" => {
                return Err(Error::msg("meeting at a relay is not on the Rust service yet; use a hub of the group"));
            }
            n => return Err(Error::msg(format!("unknown cbb global {n:?}"))),
        }
        let status = Status { away: away.status(&node), ..Default::default() };
        Ok(control::reply(Header { status: Some(status), ..Default::default() }, Vec::new()))
    }

    /// Mutes this member at the admin `by`'s order until `until` (0 for
    /// until an admin lifts it), or ends
    /// its mute, saves it, and connects to the members again once a
    /// command's result had a moment to go back, so that their hellos show
    /// it.
    fn set_muted(&self, node: &Arc<Node>, on: bool, until: i64, by: &str) -> Result<()> {
        if on {
            node.engine.set_mute(until);
        } else {
            node.engine.unmute();
        }
        crate::mute::save(&self.state_dir, &node.engine)?;
        (self.log)(&match (on, until) {
            (false, _) => format!("cbb: {by} ended the mute: this device's copies reach the group again"),
            (true, 0) => format!("cbb: {by} muted this device until an admin unmutes it"),
            (true, _) => format!("cbb: {by} muted this device for {} s", (until - uptime::wall_ms()) / 1000),
        });
        let node = node.clone();
        std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(500));
            node.reconnect();
        });
        Ok(())
    }

    /// The control operations mute and unmute: without a device, this
    /// device's user pauses receiving or resumes it; with one, an admin
    /// mutes that device or ends its mute (Go's muteOp).
    fn mute_op(&self, h: &Header) -> Result<()> {
        let node = self.node()?;
        let on = h.op == "mute";
        if !h.device.is_empty() {
            // An admin mutes another device with a command, or this one at
            // once.
            let until = crate::mute::until(h.for_ms)?;
            if self.admin(|a| a.mute(&h.device, on, h.for_ms))?.is_none() {
                let me = node.identity().id.to_string();
                self.set_muted(&node, on, until, &me)?;
            }
            return Ok(());
        }
        if on {
            node.engine.pause(crate::mute::until(h.for_ms)?);
            (self.log)("cbb: this device takes no copies from the group now");
        } else {
            node.engine.resume();
            (self.log)("cbb: this device takes the group's copies again");
        }
        crate::mute::save(&self.state_dir, &node.engine)
    }

    /// Changes the sync mode and saves it.
    fn set_mode(&self, name: &str) -> Result<()> {
        let m = Mode::parse(name)?;
        let node = self.node()?;
        save_mode(&self.state_dir, m)?;
        node.engine.set_mode(m);
        (self.log)(&format!("cbb: the sync mode is {} now", m.name()));
        Ok(())
    }

    /// Carries out a command a member sent (docs/protocol.md, section 15):
    /// one that an admin signed for this device in its group, that has not
    /// expired and was not carried out before. The lite member takes mode,
    /// paste, action and the commands that turn things off; it is never the
    /// group's hub, so it refuses hub commands.
    fn command(&self, peer: &crate::certs::DeviceId, c: &crate::records::Record) -> wire::CommandResult {
        let refused = |id: &str, why: String| {
            (self.log)(&format!("cbb: refused a command from {peer}: {why}"));
            wire::CommandResult {
                id: id.to_string(),
                by: String::new(),
                status: "refused".into(),
                reason: why,
                tunnel: None,
            }
        };
        let node = match self.node() {
            Ok(n) => n,
            Err(e) => return refused(&crate::node::command_id(c), e.message().to_string()),
        };
        let now = uptime::wall_ms();
        let me = node.identity().id.to_string();
        let (verified, sealed_to_me) = {
            let records = node.records();
            let rs = records.lock().unwrap();
            let sealed_to_me = rs.devices().iter().any(|d| d.id == me && !d.seal.is_empty());
            (rs.verify_command(c, &me, now), sealed_to_me)
        };
        let mut body = match verified {
            Ok(b) => b,
            Err(e) => return refused(&crate::node::command_id(c), e.message().to_string()),
        };
        if body.sealed() {
            let Some(secret) = crate::sealkey::secret() else {
                return refused(
                    &body.id,
                    "the command is sealed, and this device has no key for sealed commands".into(),
                );
            };
            if let Err(e) = body.open(secret) {
                return refused(&body.id, e.message().to_string());
            }
            (self.log)(&format!("cbb: opened a sealed {} command from {peer}", body.kind));
        }
        if body.kind == "paste" && !body.opened && sealed_to_me {
            // The records give this member a key for sealed messages, so
            // every sender seals a paste to it: one in the open was read on
            // its way (docs/protocol.md, section 15, "Sealed commands").
            return refused(
                &body.id,
                "a paste for this device must be sealed to its key, and this one came in the open".into(),
            );
        }
        if body.time_ms < self.started_ms {
            // It may have been carried out before the restart, which the
            // replay cache does not remember.
            return refused(
                &body.id,
                "this device started after the command was signed, so it may have carried it out already; send it again"
                    .into(),
            );
        }
        {
            let mut seen = self.commands.lock().unwrap();
            seen.retain(|_, exp| *exp > now);
            if seen.contains_key(&body.id) {
                return refused(&body.id, "this command was carried out already".into());
            }
            if seen.len() >= MAX_COMMANDS {
                return refused(&body.id, "too many commands; try again in a minute".into());
            }
            seen.insert(body.id.clone(), body.expires_ms);
        }
        match body.kind.as_str() {
            "paste" | "action" if node.forward_only() => {
                return refused(&body.id, crate::node::FORWARD_ONLY.into());
            }
            "hub" => return self.hub_command(&node, body),
            "paste" => return self.pasted(&node, c, body),
            "action" => return self.act(&node, c, body),
            "actions-off" => {
                let mut res = wire::CommandResult {
                    id: body.id.clone(),
                    by: String::new(),
                    status: "done".into(),
                    reason: String::new(),
                    tunnel: None,
                };
                match self.all_actions_off(&node) {
                    Ok(()) => (self.log)(&format!("cbb: {} turned the quick actions off here", body.by)),
                    Err(e) => {
                        (self.log)(&format!("cbb: turning the quick actions off: {}", e.for_log()));
                        res.status = "failed".into();
                        res.reason = e.message().to_string();
                    }
                }
                return res;
            }
            "away-off" => {
                let mut res = wire::CommandResult {
                    id: body.id.clone(),
                    by: String::new(),
                    status: "done".into(),
                    reason: String::new(),
                    tunnel: None,
                };
                match self.away().and_then(|a| a.turn_off()) {
                    Ok(()) => {
                        (self.log)(&format!("cbb: {} turned sync away from home off here", body.by));
                        // The members connect again once the result has gone
                        // back on the connection that brought the command.
                        let node = node.clone();
                        std::thread::spawn(move || {
                            std::thread::sleep(std::time::Duration::from_millis(500));
                            node.set_tunnel_key(None);
                        });
                    }
                    Err(e) => {
                        (self.log)(&format!("cbb: turning sync away from home off: {}", e.for_log()));
                        res.status = "failed".into();
                        res.reason = e.message().to_string();
                    }
                }
                return res;
            }
            "mute" | "unmute" => {
                let mut res = wire::CommandResult {
                    id: body.id.clone(),
                    by: String::new(),
                    status: "done".into(),
                    reason: String::new(),
                    tunnel: None,
                };
                let until = if body.for_ms == 0 { 0 } else { uptime::wall_ms() + body.for_ms };
                if let Err(e) = self.set_muted(&node, body.kind == "mute", until, &body.by) {
                    (self.log)(&format!("cbb: a mute from {peer}: {}", e.for_log()));
                    res.status = "failed".into();
                    res.reason = e.message().to_string();
                }
                return res;
            }
            "paste-off" => {
                let mut res = wire::CommandResult {
                    id: body.id.clone(),
                    by: String::new(),
                    status: "done".into(),
                    reason: String::new(),
                    tunnel: None,
                };
                match remotepaste::save(&self.state_dir, remotepaste::Settings::default()) {
                    Ok(()) => (self.log)(&format!("cbb: {} turned remote paste off here", body.by)),
                    Err(e) => {
                        (self.log)(&format!("cbb: turning remote paste off: {}", e.for_log()));
                        res.status = "failed".into();
                        res.reason = e.message().to_string();
                    }
                }
                return res;
            }
            _ => {}
        }
        if let Err(e) = Mode::parse(&body.mode) {
            return refused(&body.id, e.message().to_string());
        }
        if let Err(e) = self.set_mode(&body.mode) {
            (self.log)(&format!("cbb: a command from {peer}: {}", e.for_log()));
            return wire::CommandResult {
                id: body.id,
                by: String::new(),
                status: "failed".into(),
                reason: e.message().to_string(),
                tunnel: None,
            };
        }
        (self.log)(&format!("cbb: {} set the sync mode to {}", body.by, body.mode));
        wire::CommandResult {
            id: body.id,
            by: String::new(),
            status: "done".into(),
            reason: String::new(),
            tunnel: None,
        }
    }

    /// Carries out a hub command that verify_command took, as Go's takeHub
    /// and hubStopped: this device, which may be a hub by the records,
    /// becomes one, or with a stop order stops being one once the result
    /// has gone back.
    fn hub_command(&self, node: &Arc<Node>, body: crate::records::Command) -> wire::CommandResult {
        let mut res = wire::CommandResult { id: body.id.clone(), status: "done".into(), ..Default::default() };
        let order = body.hub.clone().unwrap_or_default();
        let fail = |mut res: wire::CommandResult, status: &str, why: String| {
            (self.log)(&format!("cbb: did not do what the hub command from {} asked: {why}", body.by));
            (res.status, res.reason) = (status.into(), why);
            res
        };
        let away = match self.away() {
            Ok(a) => a,
            Err(e) => return fail(res, "refused", e.message().to_string()),
        };
        if crate::away::is_stop(&order) {
            if !away.is_hub() {
                return fail(res, "refused", "this device is no hub of the group".into());
            }
            (self.log)(&format!("cbb: {} asked this hub to stop being one", body.by));
            let node = node.clone();
            std::thread::spawn(move || {
                // Its clients' connections end, after the result went back.
                std::thread::sleep(std::time::Duration::from_millis(500));
                if let Err(e) = away.stop_hub(&node, true) {
                    node.logf(&format!("cbb: stopping being the hub: {}", e.for_log()));
                }
            });
            return res;
        }
        // A computer the admin just made a hub that only passes copies on
        // gets the record that makes it one just before the command.
        let me = node.identity().id.to_string();
        let until = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while !node.records().lock().unwrap().may_host(&me) {
            if std::time::Instant::now() > until {
                return fail(
                    res,
                    "refused",
                    "this computer is no admin, and its record does not make it a hub that only passes copies on; only the group's root, an admin, or such a computer can be a hub".into(),
                );
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        match away.take_hub(node, &body.by, &order) {
            Ok(o) => res.tunnel = serde_json::to_value(&o).ok(),
            Err(e) => {
                let status = if e.message().starts_with("saving") { "failed" } else { "refused" };
                res = fail(res, status, e.message().to_string());
            }
        }
        res
    }

    /// Carries out an action command that verify_command took, as a full
    /// member does (internal/service/actions.go): one of the presets that
    /// this device's user turned on, for that kind of signer, within the
    /// limits per sender.
    fn act(&self, node: &Node, c: &crate::records::Record, body: crate::records::Command) -> wire::CommandResult {
        let from = Sender::of(node, c, &body);
        let mut res = wire::CommandResult {
            id: body.id.clone(),
            by: String::new(),
            status: "refused".into(),
            reason: String::new(),
            tunnel: None,
        };
        match actions::load(&self.state_dir) {
            Err(e) => {
                res.status = "failed".into();
                res.reason = format!("reading the quick actions: {}", e.for_log());
            }
            Ok(_) if !actions::PRESETS.contains(&body.action.as_str()) => {
                res.reason = format!("this device has no action {:?}", body.action);
            }
            Ok(set) => {
                let (dev, root) = node.records().lock().unwrap().command_signer(c);
                let signer = actions::Signer {
                    root,
                    role: dev.as_ref().map(|d| d.role.clone()).unwrap_or_default(),
                    store: dev.map(|d| d.store).unwrap_or_default(),
                };
                if let Some(why) = actions::check(&set.get(&body.action), &signer) {
                    res.reason = why;
                } else if !self.acts.lock().unwrap().allow(&from.key, uptime::wall_ms()) {
                    res.reason = "too many actions: at most one a second and 30 a minute from one device".into();
                } else {
                    res = self.run_action(&body);
                }
            }
        }
        if res.status == "done" {
            (self.log)(&format!("cbb: {} ran the action {} here", from.who(&body), body.action));
        } else {
            (self.log)(&format!(
                "cbb: the action {} from {}: {}: {}",
                body.action,
                from.who(&body),
                res.status,
                res.reason
            ));
        }
        let e = actions::Entry {
            time_ms: uptime::wall_ms(),
            by: body.by.clone(),
            name: from.name,
            unverified: !from.verified,
            action: body.action.clone(),
            result: res.status.clone(),
            reason: res.reason.clone(),
        };
        if let Err(e) = actions::append(&self.state_dir, e) {
            (self.log)(&format!("cbb: keeping the action log: {}", e.for_log()));
        }
        res
    }

    /// Runs a preset that passed the checks.
    fn run_action(&self, body: &crate::records::Command) -> wire::CommandResult {
        let mut res = wire::CommandResult {
            id: body.id.clone(),
            by: String::new(),
            status: "done".into(),
            reason: String::new(),
            tunnel: None,
        };
        if body.action == actions::RESTART {
            std::thread::spawn(|| {
                std::thread::sleep(RESTART_AFTER);
                RESTART.store(true, Ordering::SeqCst);
                STOP.store(true, Ordering::SeqCst);
            });
            return res;
        }
        match actions::run(&body.action) {
            Ok(()) => {}
            Err(actions::Failure::Refused(why)) => (res.status, res.reason) = ("refused".into(), why),
            Err(actions::Failure::Failed(e)) => (res.status, res.reason) = ("failed".into(), e.for_log()),
        }
        res
    }

    /// Turns every quick action off here; the rights the user granted stay
    /// until cbb action enable or disable runs here again, as root, and
    /// with the actions off the service uses none of them.
    fn all_actions_off(&self, node: &Node) -> Result<()> {
        let mut set = actions::load(&self.state_dir)?;
        set.all_off();
        actions::save(&self.state_dir, &set)?;
        node.set_actions(Vec::new());
        Ok(())
    }

    /// cbb action enable and disable: only this device's own user sets its
    /// actions, on the admin socket.
    fn set_action(&self, h: &Header) -> Result<Message> {
        let node = self.node()?;
        let [a] = h.actions.as_slice() else {
            return Err(Error::msg("set one quick action at a time"));
        };
        if !a.command.is_empty() {
            return Err(Error::msg(
                "the lite member has only the presets reboot, cancel-shutdown and restart; actions of your own need a full member",
            ));
        }
        if !actions::PRESETS.contains(&a.name.as_str()) {
            return Err(Error::msg(format!(
                "this device has no action {:?}: the lite member has reboot, cancel-shutdown and restart",
                a.name
            )));
        }
        for k in &a.by {
            if !actions::KINDS.contains(&k.as_str()) {
                return Err(Error::msg(format!("{k:?} is not a kind of admin: root, phone, computer or watch")));
            }
        }
        let mut set = actions::load(&self.state_dir)?;
        set.set(actions::Action {
            name: a.name.clone(),
            on: a.on,
            by: a.by.clone(),
            any_key: a.any_key,
            ..Default::default()
        });
        actions::save(&self.state_dir, &set).map_err(|e| e.context("saving the quick actions"))?;
        node.set_actions(set.on());
        (self.log)(&format!("cbb: the action {} is {} here", a.name, if a.on { "on" } else { "off" }));
        Ok(self.action_reply(&set))
    }

    fn action_reply(&self, set: &actions::Settings) -> Message {
        let status = Status { actions: action_status(set), ..Default::default() };
        control::reply(Header { status: Some(status), ..Default::default() }, Vec::new())
    }

    /// Carries out a paste command that verify_command took, as a full
    /// member does (internal/service/paste.go).
    fn pasted(&self, node: &Node, c: &crate::records::Record, body: crate::records::Command) -> wire::CommandResult {
        let from = Sender::of(node, c, &body);
        let mut res = wire::CommandResult {
            id: body.id.clone(),
            by: String::new(),
            status: "refused".into(),
            reason: String::new(),
            tunnel: None,
        };
        match remotepaste::load(&self.state_dir) {
            Err(e) => {
                res.status = "failed".into();
                res.reason = format!("reading the remote paste settings: {}", e.for_log());
            }
            Ok(set) if !set.on => {
                res.reason = format!(
                    "remote paste is off on this device; its user turns it on there with {}cbb paste-receive on",
                    crate::rootless::sudo()
                );
            }
            Ok(set) if body.enter && !set.enter => {
                res.reason = format!(
                    "this device takes pastes without Enter only; its user allows Enter with {}cbb paste-receive on -enter",
                    crate::rootless::sudo()
                );
            }
            Ok(_) if body.paste_kind == "secret" && node.secrets_stopped() => {
                res.reason = "the group's records stop secrets until its root decides (cbb status says why)".into();
            }
            Ok(_) if !self.pastes.lock().unwrap().allow(&from.key, uptime::wall_ms()) => {
                res.reason = "too many pastes: at most one a second and 30 a minute from one device".into();
            }
            Ok(set) => res = self.inject(&body, &remotepaste::clean(&body.text), set, &from.name),
        }
        if res.status == "done" {
            (self.log)(&format!("cbb: {} pasted {} bytes here", from.who(&body), body.text.len()));
        } else {
            (self.log)(&format!("cbb: a paste from {}: {}: {}", from.who(&body), res.status, res.reason));
        }
        if body.paste_kind != "secret" {
            let e = remotepaste::Entry {
                time_ms: uptime::wall_ms(),
                by: body.by.clone(),
                name: from.name.clone(),
                unverified: !from.verified,
                len: body.text.len(),
                method: body.mode.clone(),
                enter: body.enter,
                result: res.status.clone(),
                reason: res.reason.clone(),
            };
            if let Err(e) = remotepaste::append(&self.state_dir, e) {
                (self.log)(&format!("cbb: keeping the paste log: {}", e.for_log()));
            }
        }
        res
    }

    /// Hands the text to the watchers that can put it in, best target
    /// first, until one did: a desktop session, then tmux, then a text
    /// console when the user allowed consoles.
    fn inject(
        &self,
        body: &crate::records::Command,
        text: &str,
        set: remotepaste::Settings,
        name: &str,
    ) -> wire::CommandResult {
        let mut res = wire::CommandResult {
            id: body.id.clone(),
            by: String::new(),
            status: "refused".into(),
            reason: String::new(),
            tunnel: None,
        };
        if text.is_empty() {
            res.reason = "the text has nothing that may be pasted: only control characters".into();
            return res;
        }
        // A line break runs what comes before it wherever the focused
        // program does not take a paste bracketed: a typed text, tmux, a
        // console, and on a desktop a shell or console window that does not
        // ask for it, which no target can tell. So a text with one needs the
        // user's leave for Enter on every target.
        if text.contains('\n') && !set.enter {
            res.reason = format!(
                "the text has a line break, which may run what comes before it, and this device takes pastes without Enter only; send it as one line, or its user allows Enter with {}cbb paste-receive on -enter",
                crate::rootless::sudo()
            );
            return res;
        }
        let mut order = vec![DESKTOP, TMUX, NEXT];
        if set.console {
            order.push(CONSOLE);
        }
        let (targets, console) = {
            let ws = self.watchers.lock().unwrap();
            let targets: Vec<(String, Option<u32>, SyncSender<ToWatcher>)> = order
                .iter()
                .flat_map(|t| ws.iter().filter(move |w| w.target == *t))
                .map(|w| (w.target.clone(), w.uid, w.tx.clone()))
                .collect();
            let console = ws.iter().any(|w| w.target == CONSOLE);
            (targets, console)
        };
        if targets.is_empty() {
            res.reason = if console && !set.console {
                "only a text console is here, and its user did not allow consoles (sudo cbb paste-receive on -console)"
            } else {
                "nothing on this device can paste: no tmux or console helper of CBB, nor cbb next link, runs here"
            }
            .into();
            return res;
        }
        // Only the user at the screen takes them, and a secret only where
        // the system tells who that is.
        let secret = body.paste_kind == "secret";
        let mut why = "";
        let targets: Vec<(String, SyncSender<ToWatcher>)> = targets
            .into_iter()
            .filter(|(t, uid, _)| match peer::may_take(*uid, t, peer::at_screen) {
                peer::Verdict::Allowed => true,
                peer::Verdict::Unchecked if !secret => true,
                peer::Verdict::Unchecked => {
                    why = "this device cannot tell which user is at its screen, so it takes no secret pastes; send it as a paste or a typed text";
                    false
                }
                peer::Verdict::Refused => {
                    if why.is_empty() {
                        why = "the paste targets here run as users who are not at the screen";
                    }
                    false
                }
            })
            .map(|(t, _, tx)| (t, tx))
            .collect();
        if targets.is_empty() {
            res.reason = why.into();
            return res;
        }
        let wait = if body.mode == "type" { INJECT_WAIT + TYPE_WAIT * text.len() as u32 } else { INJECT_WAIT };
        let mut reasons: Vec<String> = Vec::new();
        for (target, tx) in targets {
            let (done, answer) = mpsc::sync_channel(1);
            let i = Inject {
                text: text.to_string(),
                method: body.mode.clone(),
                enter: body.enter,
                no_lock_check: set.no_lock_check,
                kind: body.paste_kind.clone(),
                name: name.to_string(),
                done,
            };
            if tx.try_send(ToWatcher::Inject(i)).is_err() {
                continue;
            }
            let reason = match answer.recv_timeout(wait) {
                Ok((status, _)) if status == "done" => {
                    res.status = status;
                    return res;
                }
                Ok((status, reason)) => {
                    res.status = status;
                    reason
                }
                Err(RecvTimeoutError::Timeout) => format!("the {target} target did not answer"),
                Err(RecvTimeoutError::Disconnected) => {
                    res.status = "failed".into();
                    "the connection to the paste target closed".into()
                }
            };
            if reasons.last() != Some(&reason) {
                reasons.push(reason);
            }
        }
        if reasons.is_empty() {
            reasons.push("the paste targets here are busy; try again".into());
        }
        res.reason = reasons.join("; ");
        res
    }

    /// Remote paste here, for the status: the switches and the targets that
    /// run.
    fn paste_status(&self) -> Option<control::Paste> {
        let set = remotepaste::load(&self.state_dir).ok()?;
        let mut targets: Vec<String> =
            self.watchers.lock().unwrap().iter().filter(|w| !w.target.is_empty()).map(|w| w.target.clone()).collect();
        targets.sort();
        targets.dedup();
        Some(control::Paste {
            on: set.on,
            enter: set.enter,
            console: set.console,
            no_lock_check: set.no_lock_check,
            targets,
        })
    }

    /// cbb paste-receive on or off: only this device's own user turns
    /// remote paste on here; the lite member is never an admin, so it turns
    /// it off on no other device.
    fn set_receive(&self, h: &Header) -> Result<Message> {
        match h.name.as_str() {
            "on" | "off" => {}
            n => return Err(Error::msg(format!("remote paste is on or off, not {n:?}"))),
        }
        if !h.device.is_empty() {
            return Err(Error::msg(if h.name == "on" {
                "only a device's own user turns remote paste on there"
            } else {
                "only an admin turns remote paste off on another device; the lite member is never one: use the phone app or a full member"
            }));
        }
        if h.name == "off" && (h.enter || h.console || h.no_lock_check) {
            return Err(Error::msg("-enter, -console and -no-lock-check go with on"));
        }
        self.node()?;
        let set = remotepaste::Settings {
            on: h.name == "on",
            enter: h.enter,
            console: h.console,
            no_lock_check: h.no_lock_check,
        };
        remotepaste::save(&self.state_dir, set).map_err(|e| e.context("saving the remote paste settings"))?;
        (self.log)(&format!(
            "cbb: remote paste is {} here (enter {}, console {}, no lock check {})",
            h.name, set.enter, set.console, set.no_lock_check
        ));
        let status = Status { paste: self.paste_status(), ..Default::default() };
        Ok(control::reply(Header { status: Some(status), ..Default::default() }, Vec::new()))
    }

    /// Passes a write the engine decided on to every watcher that holds a
    /// clipboard; with none, it waits for the next one.
    ///
    /// A copy of images or files goes whole to the watchers that take it,
    /// once fetched; the others get its plain-text alternative, if any.
    fn deliver(self: &Arc<Self>, w: WriteReq) {
        {
            let mut latest = self.latest.lock().unwrap();
            *latest = (*latest).max(w.seq);
        }
        let Some(ev) = w.event.clone() else {
            if !self.send_writes(|_| Some(w.clone())) {
                *self.pending.lock().unwrap() = Some(w);
            }
            return;
        };
        *self.media.lock().unwrap() = Some(ev.clone());
        let Some(m) = ev.media.clone() else { return };
        let alt = (!w.text.is_empty()).then(|| WriteReq { kind: Kind::Text, media: None, event: None, ..w.clone() });
        let node = self.node().ok().filter(|_| self.watchers.lock().unwrap().iter().any(|x| x.board && x.takes(&m)));
        let takers = node.is_some();
        if let Some(node) = node {
            let svc = self.clone();
            let (alt, m) = (alt.clone(), m.clone());
            std::thread::spawn(move || {
                let limit = svc.limits.lock().unwrap().home as u64;
                let fetched = node.fetch(&ev, limit);
                if *svc.latest.lock().unwrap() != w.seq {
                    return; // a newer write came
                }
                if let Err(e) = &fetched {
                    (svc.log)(&format!("cbb: fetching a copy's images or files: {}", e.for_log()));
                }
                let whole = fetched.is_ok().then_some(w);
                svc.send_writes(|x| if x.takes(&m) { whole.clone().or_else(|| alt.clone()) } else { None });
            });
        }
        let Some(alt) = alt else { return };
        if !self.send_writes(|x| if x.takes(&m) && takers { None } else { Some(alt.clone()) }) && !takers {
            *self.pending.lock().unwrap() = Some(alt);
        }
    }

    /// Sends each watcher that holds a clipboard the write pick gives it;
    /// reports whether there is such a watcher.
    fn send_writes(&self, pick: impl Fn(&Watcher) -> Option<WriteReq>) -> bool {
        let mut ws = self.watchers.lock().unwrap();
        let mut boards = false;
        ws.retain(|x| {
            if !x.board {
                return true;
            }
            boards = true;
            let Some(w) = pick(x) else { return true };
            !matches!(x.tx.try_send(ToWatcher::Write(w)), Err(mpsc::TrySendError::Disconnected(_)))
        });
        boards
    }

    fn serve(&self, conn: UnixStream, admin: bool) {
        let mut out = match conn.try_clone() {
            Ok(c) => c,
            Err(_) => return,
        };
        // A connection waits for its first request this long at most.
        let _ = conn.set_read_timeout(Some(FIRST_REQUEST_TIME));
        let idle = conn.try_clone();
        let mut r = control::Reader::new(conn);
        let m = match r.read() {
            Ok(Some(m)) => m,
            _ => return,
        };
        if let Ok(c) = idle {
            let _ = c.set_read_timeout(None);
        }
        if control::is_admin(&m.header.op) && !admin {
            let e = Error::msg(format!(
                "{:?} changes the group, so the service takes it only on its admin socket, which only the administrator reaches",
                m.header.op
            ));
            let _ = control::write(&mut out, &control::failure(&e));
            return;
        }
        if m.header.op == "watch" {
            self.watch(m, r, out);
            return;
        }
        if m.header.op == "copy-media" || m.header.op == "copied-media" {
            let answer = match self.copy_media(&m, &mut r) {
                Ok(()) => control::reply(Header::default(), Vec::new()),
                Err(e) => {
                    (self.log)(&format!("cbb: {}: {}", m.header.op, e.for_log()));
                    // What the client still sends is read before the
                    // answer, so that closing the socket does not reset it.
                    if let Ok(c) = out.try_clone() {
                        let _ = c.set_read_timeout(Some(Duration::from_secs(5)));
                    }
                    while let Ok(Some(_)) = r.read() {}
                    control::failure(&e)
                }
            };
            let _ = control::write(&mut out, &answer);
            return;
        }
        if m.header.op == "pair" && m.header.addrs.is_empty() {
            if let Err(e) = self.pair_window(&m, r, &mut out) {
                (self.log)(&format!("cbb: pair: {}", e.for_log()));
                let _ = control::write(&mut out, &control::failure(&e));
            }
            return;
        }
        if m.header.op == "paste-media" {
            if let Err(e) = self.paste_media(&mut out) {
                let _ = control::write(&mut out, &control::failure(&e));
            }
            return;
        }
        let answer = match self.request(&m) {
            Ok(a) => a,
            Err(e) => {
                (self.log)(&format!("cbb: {}: {}", m.header.op, e.for_log()));
                control::failure(&e)
            }
        };
        let _ = control::write(&mut out, &answer);
    }

    /// Takes cbb copy FILE, or a watcher's copied image: the parts and their
    /// bytes come in part and data messages after the request, which
    /// carries the plain-text alternative. The copy is sealed, kept to
    /// serve, and sent to the group.
    fn copy_media(&self, m: &Message, r: &mut control::Reader<UnixStream>) -> Result<()> {
        let node = self.node()?;
        let limit = self.limits.lock().unwrap().home;
        let mut got = copies::receive(r, &m.payload, limit, &self.tmp_dir()?)?;
        let parts = std::mem::take(&mut got.parts);
        let ev = if m.header.op == "copied-media" {
            node.copied_media(&got.text, parts, Via::Copy)?
        } else {
            Some(node.send_media(&got.text, parts, Via::Copy)?)
        };
        if let Some(ev) = ev {
            *self.media.lock().unwrap() = Some(Arc::new(ev));
        }
        Ok(())
    }

    /// Answers cbb paste -o and a watcher's fetch: the images or files of
    /// the member's own clipboard, or of the group's copy in a mode that
    /// keeps its clipboard to itself, once fetched; the plain-text
    /// alternative, then each part and its bytes.
    fn paste_media(&self, out: &mut UnixStream) -> Result<()> {
        let node = self.node()?;
        let engine = &node.engine;
        let ev = if engine.mode().receives() {
            let (m, _, _) = engine.local_media().ok_or_else(|| Error::msg("the clipboard holds no images or files"))?;
            let ev = self.media.lock().unwrap().clone();
            ev.filter(|ev| ev.media.as_ref().is_some_and(|e| e.key() == m.key()))
                .ok_or_else(|| Error::msg("the copy's images or files are no longer kept here; copy them again"))?
        } else {
            let ev = engine.current().filter(|ev| ev.media.is_some());
            Arc::new(ev.ok_or_else(|| Error::msg("the group's copy is no images or files"))?)
        };
        node.fetch(&ev, self.limits.lock().unwrap().home as u64)?;
        let dir = self.tmp_dir()?.join(format!("paste-{}", files::random_name()));
        let parts = node.open_media(&ev, &dir);
        let sent = parts.and_then(|parts| copies::send(out, &ev.text, &parts));
        let _ = std::fs::remove_dir_all(&dir);
        sent
    }

    /// The folder for the parts of copies on their way, in the state
    /// folder, which only the service reads.
    fn tmp_dir(&self) -> Result<PathBuf> {
        let dir = self.state_dir.join("tmp");
        std::fs::create_dir_all(&dir).context("cannot make the folder for copies on their way")?;
        Ok(dir)
    }

    /// Images and files in cbb status and cbb config.
    fn media_status(&self) -> control::Media {
        let l = *self.limits.lock().unwrap();
        control::Media { max_copy: l.home, max_copy_away: l.away }
    }

    fn request(&self, m: &Message) -> Result<Message> {
        let h = &m.header;
        match h.op.as_str() {
            // Shows this device's settings, or sets the setting name to
            // value: max-copy or max-copy-away.
            "config" => {
                if !h.name.is_empty() {
                    let l = copies::Limits::set(&self.state_dir, &h.name, &h.value)?;
                    *self.limits.lock().unwrap() = l;
                    (self.log)(&format!(
                        "cbb: the largest copy is {} at home and {} away from home now",
                        copies::size_text(l.home),
                        copies::size_text(l.away)
                    ));
                }
                let status = Status { media: Some(self.media_status()), ..Default::default() };
                Ok(control::reply(Header { status: Some(status), ..Default::default() }, Vec::new()))
            }
            "copy" => {
                let text = String::from_utf8(m.payload.clone()).context("the text is not UTF-8")?;
                if self.node()?.forward_only() {
                    return Err(Error::msg(crate::node::FORWARD_ONLY));
                }
                self.node()?.send(&text, kind_of(&h.kind)?, via_of(&h.via)?)?;
                Ok(control::reply(Header::default(), Vec::new()))
            }
            "paste" => {
                // The local clipboard's text in a mode that takes the
                // group's copies, and the group's current text in one that
                // keeps its clipboard to itself, as on a full member.
                let engine = self.node()?.engine.clone();
                let got = if engine.mode().receives() {
                    engine.local()
                } else {
                    engine.current().filter(|ev| !ev.text.is_empty()).map(|ev| (ev.text, ev.kind, Duration::ZERO))
                };
                let Some((text, kind, _)) = got else {
                    let media = if engine.mode().receives() {
                        engine.local_media().is_some()
                    } else {
                        engine.current().is_some_and(|ev| ev.media.is_some())
                    };
                    return Err(Error::msg(if media {
                        "the clipboard holds images or files without a text; cbb paste -o DIR saves them"
                    } else {
                        "the clipboard is empty"
                    }));
                };
                Ok(control::reply(Header { kind: kind_name(kind).into(), ..Default::default() }, text.into_bytes()))
            }
            // The version the service runs, in a group or not: cbb update's
            // check that the new one started.
            "version" => Ok(control::reply(
                Header {
                    status: Some(Status {
                        role: "lite".into(),
                        os: "linux".into(),
                        version: VERSION.into(),
                        ..Default::default()
                    }),
                    ..Default::default()
                },
                Vec::new(),
            )),
            "status" => {
                let node = self.node()?;
                let id = node.identity();
                let skews = node.engine.skews();
                let peers = node
                    .peers()
                    .into_iter()
                    .map(|p| Device {
                        skew_ms: skews.get(p.id.as_str()).copied().unwrap_or(0),
                        id: p.id.to_string(),
                        name: p.name,
                        role: p.role,
                        os: p.os,
                        ..Default::default()
                    })
                    .collect();
                let status = Status {
                    device: id.id.to_string(),
                    group: id.tag(),
                    role: node.role().into(),
                    os: node.os().into(),
                    peers,
                    version: VERSION.into(),
                    mode: node.engine.mode().name().into(),
                    muted: node.engine.mute_left().is_some(),
                    muted_until_ms: node.engine.mute_left().filter(|l| *l > 0).map_or(0, |l| uptime::wall_ms() + l),
                    paused: node.engine.pause_left().is_some(),
                    paused_until_ms: node.engine.pause_left().filter(|l| *l > 0).map_or(0, |l| uptime::wall_ms() + l),
                    away: self.away()?.status(&node),
                    paste: self.paste_status(),
                    actions: action_status(&actions::load(&self.state_dir).unwrap_or_default()),
                    stop: node.stop(),
                    removed: node.removed(),
                    media: Some(self.media_status()),
                    key_level: {
                        let l = node.records().lock().unwrap().state().key_level;
                        if l.is_empty() { "hardware".into() } else { l }
                    },
                    key_problem: String::new(),
                    incoming_ms: node
                        .records()
                        .lock()
                        .unwrap()
                        .state()
                        .incoming_ms
                        .unwrap_or(cbb_core::authority::DEFAULT_INCOMING),
                };
                Ok(control::reply(Header { status: Some(status), ..Default::default() }, Vec::new()))
            }
            "devices" => {
                let node = self.node()?;
                let me = node.identity().id.to_string();
                let peers = node.peers();
                let root = node.records().lock().unwrap().state().root_device;
                let mut out: Vec<Device> = node
                    .devices()
                    .into_iter()
                    .map(|d| Device {
                        os: peers
                            .iter()
                            .find(|p| p.id.as_str() == d.id && !p.os.is_empty())
                            .map_or(d.os.clone(), |p| p.os.clone()),
                        online: peers.iter().any(|p| p.id.as_str() == d.id),
                        this: d.id == me,
                        root: d.id == root,
                        listed: true,
                        id: d.id,
                        name: d.name,
                        role: d.role,
                        admin: d.admin,
                        ..Default::default()
                    })
                    .collect();
                for p in peers {
                    if !out.iter().any(|d| d.id == p.id.as_str()) {
                        out.push(Device {
                            id: p.id.to_string(),
                            name: p.name,
                            role: p.role,
                            os: p.os,
                            online: true,
                            ..Default::default()
                        });
                    }
                }
                Ok(control::reply(Header { devices: out, ..Default::default() }, Vec::new()))
            }
            "away" => self.global(h),
            "hubs" => {
                self.admin(|a| a.set_hubs(&h.hubs))?;
                Ok(control::reply(Header::default(), Vec::new()))
            }
            "paste-receive" => self.set_receive(h),
            "action-set" => self.set_action(h),
            "actions-off" if h.device.is_empty() && !h.all => {
                let node = self.node()?;
                self.all_actions_off(&node)?;
                (self.log)("cbb: the quick actions are off here");
                Ok(self.action_reply(&actions::load(&self.state_dir)?))
            }
            "actions-off" | "action-on" => Err(Error::msg(
                "only an admin runs or turns off quick actions on another device; the lite member is never one: use the phone app or a full member",
            )),
            "action-remove" => Err(Error::msg("the lite member has only presets, which cbb action disable turns off")),
            "paste-on" => Err(Error::msg(
                "only an admin pastes on another device; the lite member is never one: use the phone app or a full member",
            )),
            "mute" | "unmute" => {
                self.mute_op(h)?;
                Ok(control::reply(Header::default(), Vec::new()))
            }
            "mode" => {
                if !h.device.is_empty() {
                    return Err(Error::msg(
                        "only an admin sets the sync mode of another device; the lite member is never one: use the phone app or a Linux member",
                    ));
                }
                self.set_mode(&h.name)?;
                Ok(control::reply(Header::default(), Vec::new()))
            }
            "new" => self.new_group(),
            "revoke" => {
                let name = self.admin(|a| a.revoke(&h.name))?;
                Ok(control::reply(Header { name, done: true, ..Default::default() }, Vec::new()))
            }
            "rename" => {
                let name = self.admin(|a| a.rename(&h.name, &h.new_name))?;
                Ok(control::reply(Header { name, done: true, ..Default::default() }, Vec::new()))
            }
            "freeze" | "thaw" => {
                let name = self.admin(|a| a.freeze(&h.name, h.op == "freeze"))?;
                Ok(control::reply(Header { name, done: true, ..Default::default() }, Vec::new()))
            }
            "resolve" => {
                let who = self.admin(|a| a.resolve())?;
                Ok(control::reply(Header { name: who.join(", "), done: true, ..Default::default() }, Vec::new()))
            }
            "admin" => {
                let name = self.admin(|a| a.make_admin(&h.name, h.consent))?;
                Ok(control::reply(Header { name, done: true, ..Default::default() }, Vec::new()))
            }
            "key-level" => {
                let below = self.admin(|a| a.set_key_level(&h.value))?;
                Ok(control::reply(Header { below, done: true, ..Default::default() }, Vec::new()))
            }
            "takeover-delay" => {
                self.admin(|a| a.set_takeover_delay(&h.value))?;
                Ok(control::reply(Header::default(), Vec::new()))
            }
            "incoming" => {
                self.admin(|a| a.set_incoming(&h.value))?;
                Ok(control::reply(Header::default(), Vec::new()))
            }
            "takeover" => {
                let name = self.admin(|a| a.take_over(&h.name))?;
                Ok(control::reply(Header { name, done: true, ..Default::default() }, Vec::new()))
            }
            "recovery" => {
                let text = String::from_utf8_lossy(&m.payload).to_string();
                if h.name == "yubikey" {
                    self.admin(|a| a.recover_with_card(&text))?;
                } else {
                    self.admin(|a| a.recover(&text))?;
                }
                Ok(control::reply(Header::default(), Vec::new()))
            }
            "handover" => {
                let name = self.admin(|a| a.hand_over(&h.name))?;
                Ok(control::reply(Header { name, done: true, ..Default::default() }, Vec::new()))
            }
            "pair" => {
                let _slot = self.take_pairing(|| Ok(Pairing::Qr))?;
                let name = self.admin(|a| a.admit_by_qr(&h.code, &h.addrs, &h.fingerprint, h.admins))?;
                Ok(control::reply(Header { name, done: true, ..Default::default() }, Vec::new()))
            }
            "join" => Err(Error::msg("run cbb pair on this device, with the service stopped or running")),
            "leave" => {
                // The node stops first, so nothing writes the group's files
                // again; the service then restarts in no group.
                self.node.read().unwrap().clone().ok_or_else(|| Error::msg(crate::leave::NOTHING_TO_LEAVE))?.close();
                let res = crate::leave::leave_group(&self.state_dir);
                match &res {
                    Ok(()) => (self.log)(
                        "cbb: this device left its group: its keys and the group's files are deleted; it restarts in no group",
                    ),
                    Err(e) => (self.log)(&format!("cbb: {}", e.for_log())),
                }
                std::thread::spawn(|| {
                    std::thread::sleep(RESTART_AFTER);
                    LEFT.store(true, Ordering::SeqCst);
                    STOP.store(true, Ordering::SeqCst);
                });
                res.map(|()| control::reply(Header::default(), Vec::new()))
            }
            op => Err(Error::msg(format!("unknown operation {op:?}"))),
        }
    }

    /// Runs an admin's operation on the group (admin.rs).
    /// Reserves the pairing slot for what make makes; the slot is free
    /// again once the guard drops.
    fn take_pairing(&self, make: impl FnOnce() -> Result<Pairing>) -> Result<PairingSlot<'_>> {
        let node = self.node()?;
        let mut slot = self.pairing.lock().unwrap();
        if slot.is_some() {
            return Err(Error::msg(
                "a pairing window is already open: stop the cbb pair that opened it (Ctrl+C in its terminal), or wait until it closes, 5 minutes after it opened",
            ));
        }
        let p = make()?;
        if matches!(p, Pairing::Window(_)) {
            node.set_window_open(true);
        }
        *slot = Some(p);
        Ok(PairingSlot { svc: self, node })
    }

    /// Opens a pairing window for cbb pair: the answer gives its code, and
    /// a second one the device it admitted, once it closes. A client that
    /// hangs up closes the window.
    fn pair_window(&self, m: &Message, mut r: control::Reader<UnixStream>, out: &mut UnixStream) -> Result<()> {
        let mut win = None;
        let _slot = self.take_pairing(|| {
            let admitter = self.admin(|a| a.admitter(m.header.admins))?;
            let w = Window::open(admitter, &cbb_core::pair::new_code())?;
            win = Some(w.clone());
            Ok(Pairing::Window(w))
        })?;
        let w = win.ok_or_else(|| Error::msg("no window"))?;
        let port = *self.port.lock().unwrap();
        let address = port.and_then(|p| crate::pair::qr_addresses(p).into_iter().next()).unwrap_or_default();
        let opened = Header {
            code: w.code().to_string(),
            expires: window::LIFETIME.as_secs() as i64,
            address,
            ..Default::default()
        };
        control::write(out, &control::reply(opened, Vec::new()))?;
        let hung = Arc::new(AtomicBool::new(false));
        {
            let (hung, w) = (hung.clone(), w.clone());
            std::thread::spawn(move || {
                // Returns when the client hangs up, or the answer is out
                // and the connection closes.
                while let Ok(Some(_)) = r.read() {}
                hung.store(true, Ordering::SeqCst);
                w.close();
            });
        }
        let end = w.wait(&|| STOP.load(Ordering::SeqCst));
        drop(_slot);
        if hung.load(Ordering::SeqCst) {
            return Ok(());
        }
        match end {
            Ok(j) if j.confirmed => control::write(
                out,
                &control::reply(Header { name: j.name, done: true, ..Default::default() }, Vec::new()),
            ),
            Ok(j) => Err(Error::msg(format!(
                "{} got its certificate but did not confirm that it stored it; check it with cbb status there, and pair it again if needed",
                j.name
            ))),
            Err(why) => Err(Error::with("the pairing failed", why)),
        }
    }

    /// Serves a pairing connection a joiner dialed to the member port:
    /// the open window takes it, or it is refused.
    fn pair_conn(
        &self,
        sock: std::net::TcpStream,
        session: crate::tls::Session,
        exporter: Arc<crate::tls::Exporter>,
        addr: SocketAddr,
    ) -> Result<()> {
        use cbb_core::pair::Refusal;
        let w = match &*self.pairing.lock().unwrap() {
            Some(Pairing::Window(w)) => Ok(w.clone()),
            Some(Pairing::Qr) => Err(Refusal::Busy),
            None => Err(Refusal::Closed),
        };
        match w {
            Ok(w) => w.serve(&*self.node()?, sock, session, exporter, addr),
            Err(why) => {
                window::refuse(sock, session, why);
                Err(Error::with("a device asked to pair", why))
            }
        }
    }

    fn admin<T>(&self, f: impl FnOnce(&crate::admin::Admin) -> Result<T>) -> Result<T> {
        let node = self.node()?;
        f(&crate::admin::Admin { node: &node, dir: &self.state_dir })
    }

    /// Makes a group with this device as its root (cbb new); the service
    /// then starts in it.
    fn new_group(&self) -> Result<Message> {
        let _one = self.creating.lock().unwrap();
        if self.node.read().unwrap().is_some() {
            return Err(Error::msg("this device is already in a group; cbb status shows it"));
        }
        let (ident, why) = crate::admin::new_group(&self.state_dir, &self.name)?;
        (self.log)(&format!("cbb: created a new group {}", ident.tag()));
        let status = Status {
            device: ident.id.to_string(),
            group: ident.tag(),
            role: "full".into(),
            os: crate::admin::os_name().into(),
            version: VERSION.into(),
            key_level: if ident.external.is_some() { "hardware" } else { "files" }.into(),
            key_problem: why,
            ..Default::default()
        };
        Ok(control::reply(Header { status: Some(status), done: true, ..Default::default() }, Vec::new()))
    }

    /// Serves a watcher: what it reports goes to the engine, the writes the
    /// engine decides on go to it, and so do the remote pastes for the
    /// target it offers, each answered with injected.
    fn watch(&self, m: Message, mut r: control::Reader<UnixStream>, mut out: UnixStream) {
        let node = match self.node() {
            Ok(n) => n,
            Err(e) => {
                let _ = control::write(&mut out, &control::failure(&e));
                return;
            }
        };
        let mut target = match m.header.inject.as_str() {
            t @ ("" | DESKTOP | TMUX | CONSOLE | NEXT) => t.to_string(),
            t => {
                (self.log)(&format!("cbb: a watcher offers the paste target {t:?}, which is not known"));
                String::new()
            }
        };
        // Whether the user is at the screen is asked at each paste; a user
        // the system does not name, or a console helper that is not root,
        // never takes one.
        let uid = if target.is_empty() { None } else { peer::uid(&out) };
        let keyboard = target == CONSOLE || target == NEXT;
        if !target.is_empty() && (uid.is_none() || keyboard && !uid.is_some_and(peer::privileged)) {
            (self.log)(&format!(
                "cbb: a watcher offers the paste target {target} as a user that may not take it; it gets no remote pastes"
            ));
            target.clear();
        }
        let board = !m.header.paste_only && target != TMUX && !keyboard;
        let (images, files, html) = (m.header.images, m.header.files, m.header.html);
        if board && let (Ok(text), Ok(kind)) = (String::from_utf8(m.payload), kind_of(&m.header.kind)) {
            node.engine.clipboard_is(&text, kind);
        }
        let (tx, rx) = mpsc::sync_channel::<ToWatcher>(WATCH_QUEUE);
        if control::write(&mut out, &Message::new(Header { op: "reply".into(), ..Default::default() }, Vec::new()))
            .is_err()
        {
            return;
        }
        // A write decided while no watcher was connected, if the member's
        // own text is still that.
        if board
            && let Some(w) = self.pending.lock().unwrap().take()
            && node.engine.local().is_some_and(|(t, _, _)| t == w.text)
        {
            let _ = tx.try_send(ToWatcher::Write(w));
        }
        let id = self.next_watcher.fetch_add(1, Ordering::SeqCst);
        self.watchers.lock().unwrap().push(Watcher { id, target: target.clone(), board, uid, images, files, html, tx });
        let waiting: Arc<Mutex<Waiting>> = Arc::default();
        {
            let waiting = waiting.clone();
            std::thread::spawn(move || {
                let mut seq = 0;
                while let Ok(o) = rx.recv() {
                    let m = match o {
                        ToWatcher::Write(w) => Message::new(
                            Header {
                                op: "write".into(),
                                kind: if w.media.is_some() { "media".into() } else { kind_name(w.kind).into() },
                                via: if w.via == Via::Copy { String::new() } else { via_name(w.via).into() },
                                seq: w.seq,
                                ttl_ms: w.ttl.map(|d| d.as_millis() as i64).unwrap_or(0),
                                ..Default::default()
                            },
                            w.text.into_bytes(),
                        ),
                        ToWatcher::Inject(i) => {
                            seq += 1;
                            waiting.lock().unwrap().insert(seq, i.done);
                            Message::new(
                                Header {
                                    op: "inject".into(),
                                    seq,
                                    method: i.method,
                                    enter: i.enter,
                                    no_lock_check: i.no_lock_check,
                                    kind: i.kind,
                                    name: i.name,
                                    ..Default::default()
                                },
                                i.text.into_bytes(),
                            )
                        }
                    };
                    if control::write(&mut out, &m).is_err() {
                        // The paste waiting, if any, hears that the
                        // connection closed.
                        waiting.lock().unwrap().clear();
                        return;
                    }
                }
            });
        }
        while let Ok(Some(m)) = r.read() {
            if m.header.op == "injected" {
                if let Some(done) = waiting.lock().unwrap().remove(&m.header.seq) {
                    let _ = done.try_send(injected(&m.header));
                }
                continue;
            }
            if !board {
                (self.log)(&format!("cbb: the {target} paste target sent {:?}, which it does not send", m.header.op));
                continue;
            }
            let text = String::from_utf8(m.payload).unwrap_or_default();
            let (Ok(kind), Ok(via)) = (kind_of(&m.header.kind), via_of(&m.header.via)) else {
                (self.log)(&format!(
                    "cbb: a watcher reported an unknown kind {:?} or via {:?}",
                    m.header.kind, m.header.via
                ));
                continue;
            };
            match m.header.op.as_str() {
                "copied" => {
                    if let Err(e) = node.copied(&text, kind, via) {
                        (self.log)(&format!("cbb: a copy from a watcher: {}", e.for_log()));
                    }
                }
                "clipboard" => node.engine.clipboard_is(&text, kind),
                op => (self.log)(&format!("cbb: a watcher sent {op:?}")),
            }
        }
        // Its sender goes, so the writer ends; the pastes waiting hear that
        // the connection closed.
        self.watchers.lock().unwrap().retain(|w| w.id != id);
        waiting.lock().unwrap().clear();
    }
}

/// The status and reason of an injected answer, as a full member reads it.
fn injected(h: &Header) -> (String, String) {
    if h.error.is_empty() {
        return ("done".into(), String::new());
    }
    let status = if h.refused { "refused" } else { "failed" };
    let reason = if h.detail.is_empty() { h.error.clone() } else { format!("{}: {}", h.error, h.detail) };
    (status.into(), reason)
}

/// The name of the group's device id, empty when unknown.
/// The presets as cbb action shows them.
fn action_status(set: &actions::Settings) -> Vec<control::Action> {
    set.all()
        .into_iter()
        .map(|a| control::Action { name: a.name, on: a.on, by: a.by, any_key: a.any_key, ..Default::default() })
        .collect()
}

/// Whom a command counts for in the limits per sender and the logs
/// (Records::command_sender), with the name of its device when the records
/// show that it signed.
struct Sender {
    key: String,
    verified: bool,
    name: String,
}

impl Sender {
    fn of(node: &Node, c: &crate::records::Record, body: &crate::records::Command) -> Sender {
        let (key, verified) = node.records().lock().unwrap().command_sender(c, &body.by);
        let name = if verified { device_name(node, &body.by) } else { String::new() };
        Sender { key, verified, name }
    }

    /// The sender in the service's log: by, marked when the records do not
    /// show that its device signed.
    fn who(&self, body: &crate::records::Command) -> String {
        if self.verified { body.by.clone() } else { format!("{} (unverified)", body.by) }
    }
}

fn device_name(node: &Node, id: &str) -> String {
    node.devices().into_iter().find(|d| d.id == id).map(|d| d.name).unwrap_or_default()
}
/// One user's open connections to a control socket at most, so that one
/// user of the group cannot use up the service's threads; a user's watchers
/// and commands need a few.
const MAX_CONTROL_PER_USER: usize = 64;

/// Takes the connections to a control socket and serves each on a thread of
/// its own, closing one of a user who has MAX_CONTROL_PER_USER open.
fn accept_control(ln: UnixListener, serve: impl Fn(UnixStream) + Send + Sync + 'static) {
    let serve = Arc::new(serve);
    let users = Arc::new(ControlUsers::default());
    for conn in ln.incoming().flatten() {
        let user = crate::peer::uid(&conn);
        if !users.add(user) {
            continue; // drops conn
        }
        let (serve, users) = (serve.clone(), users.clone());
        std::thread::spawn(move || {
            serve(conn);
            users.done(user);
        });
    }
}

/// How long a control connection may wait before its first request.
const FIRST_REQUEST_TIME: Duration = Duration::from_secs(30);

/// The open connections of each user of a control socket.
#[derive(Default)]
struct ControlUsers(Mutex<HashMap<Option<u32>, usize>>);

impl ControlUsers {
    fn add(&self, user: Option<u32>) -> bool {
        let mut n = self.0.lock().unwrap();
        let c = n.entry(user).or_default();
        if *c >= MAX_CONTROL_PER_USER {
            return false;
        }
        *c += 1;
        true
    }

    fn done(&self, user: Option<u32>) {
        let mut n = self.0.lock().unwrap();
        if let Some(c) = n.get_mut(&user) {
            *c -= 1;
            if *c == 0 {
                n.remove(&user);
            }
        }
    }
}

impl Drop for PairingSlot<'_> {
    fn drop(&mut self) {
        if let Some(Pairing::Window(w)) = self.svc.pairing.lock().unwrap().take() {
            w.close();
            self.node.set_window_open(false);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{ControlUsers, MAX_CONTROL_PER_USER, accept_control};
    use std::io::Read;
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::time::Duration;

    #[test]
    fn control_users_are_bounded() {
        let u = ControlUsers::default();
        for _ in 0..MAX_CONTROL_PER_USER {
            assert!(u.add(Some(1000)));
        }
        assert!(!u.add(Some(1000)));
        assert!(u.add(Some(1001)) && u.add(None));
        u.done(Some(1000));
        assert!(u.add(Some(1000)));
    }

    /// The control socket closes a user's connection past the limit at
    /// once, and keeps the ones before it open.
    #[test]
    fn control_socket_bounds_each_user() {
        let dir = std::env::temp_dir().join(format!("cbb-control-users-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("control.sock");
        let ln = UnixListener::bind(&path).unwrap();
        std::thread::spawn(move || {
            accept_control(ln, |mut c| {
                let _ = c.read(&mut [0u8; 1]);
            })
        });
        let open: Vec<UnixStream> = (0..MAX_CONTROL_PER_USER).map(|_| UnixStream::connect(&path).unwrap()).collect();
        let mut past = UnixStream::connect(&path).unwrap();
        past.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        assert_eq!(past.read(&mut [0u8; 1]).unwrap(), 0, "the connection past the limit stays open");
        let mut first = &open[0];
        first.set_read_timeout(Some(Duration::from_millis(100))).unwrap();
        assert!(first.read(&mut [0u8; 1]).is_err(), "a connection within the limit was closed");
        drop(open);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
