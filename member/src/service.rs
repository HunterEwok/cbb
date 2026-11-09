// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The lite member's service: the control socket, the identity, the sync
//! engine and the connections to the other members.

use crate::sys::{UnixListener, UnixStream};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError, SyncSender};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

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

/// How often a paste typed after its answer checks that it may go on.
const TYPING_CHECK: Duration = Duration::from_millis(500);

/// How long a watcher may take to put a paste in; typing takes TYPE_WAIT
/// more for each byte, as on a full member.
/// The most archives a hub asks cbb update for at a time.
const MAX_WANTED: usize = 16;

/// How long a request waits for a device in a group to start.
/// How long a copy's images or files are fetched before they are given
/// up, and the pause before a fetch that no peer gave is tried again, as
/// Go's fetchFor and fetchRetry.
const FETCH_FOR: Duration = Duration::from_secs(30 * 60);
const FETCH_RETRY: Duration = Duration::from_secs(2);
const START_WAIT: Duration = Duration::from_secs(10);
const INJECT_WAIT: Duration = Duration::from_secs(5);
/// A paste of images or files: how long its copy has to arrive and be
/// fetched, and how long a watcher has to write it and press the keys,
/// within a command's lifetime, as on a full member.
const COPY_WAIT: Duration = Duration::from_secs(20);
const COPY_PASTE_WAIT: Duration = Duration::from_secs(8);
const TYPE_WAIT: Duration = Duration::from_millis(5);

/// What the service sends a watcher: a write for its clipboard, or a paste
/// to put where the focus is.
enum ToWatcher {
    Write(WriteReq),
    Inject(Inject),
    Act(Act),
}

/// A quick action for an agent to run in the user's session: a preset by
/// its name, or with command the user's own; the answer goes to done.
struct Act {
    name: String,
    command: Vec<String>,
    done: SyncSender<(String, String)>,
}

/// The quick actions in peer::may_take, as Go's targetAct.
const ACT: &str = "act";

/// A remote paste for a watcher, with where its answer goes: the status,
/// done, refused or failed, and the reason.
struct Inject {
    text: String,
    method: String,
    enter: bool,
    /// The target may paste where nothing tells whether the session is
    /// locked (remotepaste::Settings).
    no_lock_check: bool,
    /// The grant for the uinput helper, for a desktop session.
    keys: String,
    kind: String,
    name: String,
    done: SyncSender<(String, String)>,
}

/// A grant lets the uinput helper press the keys of one remote paste for
/// the user of the desktop session the service handed it to, as Go's
/// keysGrant: the paste keys once, then Enter once if the command asked for
/// it. The helper presses keys anywhere, so it presses none the service did
/// not ask for, after the paste switches and the checks on the signer.
struct Grant {
    uid: peer::Who,
    enter: bool,
    pasted: bool,
    done: bool,
    until: Instant,
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
    /// Its user, read when it offers a target or the actions (peer.rs).
    uid: Option<peer::Who>,
    /// It runs the quick actions in its user's session (CBB's agent).
    act: bool,
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
        self.images && (has("image/png") || has("image/jpeg") || has("image/gif")) || self.html && has("text/html")
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
    /// What this member says it can do in its hellos (cbb_core::authority::
    /// CAPS) until its own device record names its caps.
    pub caps: Vec<String>,
}

struct Service {
    node: RwLock<Option<Arc<Node>>>,
    away: RwLock<Option<Arc<Away>>>,
    watchers: Mutex<Vec<Watcher>>,
    /// The grants of the remote pastes handed to desktop sessions, for the
    /// uinput helper's keys, by their tokens.
    grants: Mutex<HashMap<String, Grant>>,
    /// The Bluetooth keyboard and the TVs' remotes, through cbb-helper.
    peripherals: Arc<crate::peripheral::Peripherals>,
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
    /// Why the last copy's images or files were not fetched.
    fetch_failed: Mutex<String>,
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
    /// What a join says this member can do (Config::caps).
    caps: Vec<String>,
    /// The device left a group made before 0.6 at this start, which status
    /// says while it is in no group, as Go's leftOld.
    left_old: bool,
    /// Why identity.json cannot be read: the service then runs without
    /// its group and takes only cbb leave, as Go's.
    broken: Mutex<Option<String>>,
    /// One cbb new at a time, so two requests cannot make two groups.
    creating: Mutex<()>,
    /// The address this device joined at, given by hand, as an SSH forward
    /// or a VPN address that discovery cannot find: the group that starts
    /// next keeps a connection there (keep_joined).
    joined_at: Mutex<Option<SocketAddr>>,
    /// The pairing running here: a window for a code, or an admission by
    /// a QR code; one at a time.
    pairing: Mutex<Option<Pairing>>,
    /// The member port, for the address a pairing window shows.
    port: Mutex<Option<u16>>,
    /// The bug report of a panic before the last restart (src/bugs.rs).
    bugs: crate::bugs::Bugs,
    tiles: crate::view::Tiles,
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

/// Whether the service is stopping.
#[cfg_attr(not(feature = "tunnel"), allow(dead_code))]
pub(crate) fn stopping() -> bool {
    STOP.load(Ordering::SeqCst)
}
/// An admin had the service restart: it stops with an error, after which
/// systemd starts it again.
static RESTART: AtomicBool = AtomicBool::new(false);
/// The device left its group (cbb leave): the service stops as for a
/// restart, and starts again in no group.
static LEFT: AtomicBool = AtomicBool::new(false);

extern "C" fn on_signal(_: libc::c_int) {
    STOP.store(true, Ordering::SeqCst);
}

/// Sleeps for d, or less once the service is stopping, so that SIGTERM
/// stops it at once: launchctl bootout returns before the process has
/// exited, and uninstall.sh checks right after.
fn wait_unless_stopping(d: Duration) {
    let until = std::time::Instant::now() + d;
    while !STOP.load(Ordering::SeqCst) && std::time::Instant::now() < until {
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Has the service stop, as SIGTERM does; Windows' service manager asks
/// with it.
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn request_stop() {
    STOP.store(true, Ordering::SeqCst);
}

/// Logs to the service's log file where it has one (crate::logfile), else
/// to standard error, which systemd or procd keeps.
pub fn log_line(s: &str) {
    crate::bugs::remember(s);
    if !crate::logfile::line(s) {
        eprintln!("{s}");
    }
}

/// Runs the service until SIGTERM or SIGINT.
/// What the user sees when the device's group file cannot be read, as Go's
/// errBroken.
const BROKEN: &str = "this device's group file (identity.json in the service's state directory) is damaged, so the service does not start the group; restore the file from a backup, or leave the group (cbb leave) and join again";

pub fn run(cfg: Config) -> Result<()> {
    // SAFETY: the handler only stores to an atomic.
    unsafe {
        libc::signal(libc::SIGTERM, on_signal as *const () as libc::sighandler_t);
        libc::signal(libc::SIGINT, on_signal as *const () as libc::sighandler_t);
        #[cfg(unix)]
        libc::signal(libc::SIGPIPE, libc::SIG_IGN);
    }
    std::fs::create_dir_all(&cfg.state_dir).context(format!("cannot create {}", cfg.state_dir.display()))?;
    let log: Arc<dyn Fn(&str) + Send + Sync> = Arc::new(log_line);
    // A panic ends the service (panic = "abort"); the hook keeps what broke
    // for the bug report after the restart (src/bugs.rs).
    crate::bugs::install(&cfg.state_dir);
    let left_old = crate::records::leave_version1_group(&cfg.state_dir)?;
    if left_old {
        log(&format!(
            "cbb: this device's group was made before 0.6, whose records 0.6 does not read, so it left that group (its files are in {}); set the group up again and join it with the phone's QR code",
            crate::records::OLD_GROUP_DIR
        ));
    }
    let svc = Arc::new(Service {
        node: RwLock::new(None),
        away: RwLock::new(None),
        watchers: Mutex::new(Vec::new()),
        grants: Mutex::new(HashMap::new()),
        peripherals: Arc::new(crate::peripheral::Peripherals::new(&cfg.state_dir, &cfg.name)),
        next_watcher: AtomicUsize::new(0),
        pastes: Mutex::new(remotepaste::Limiter::default()),
        acts: Mutex::new(remotepaste::Limiter::default()),
        pending: Mutex::new(None),
        latest: Mutex::new(0),
        media: Mutex::new(None),
        fetch_failed: Mutex::new(String::new()),
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
        caps: cfg.caps.clone(),
        left_old,
        broken: Mutex::new(None),
        creating: Mutex::new(()),
        joined_at: Mutex::new(None),
        pairing: Mutex::new(None),
        port: Mutex::new(None),
        bugs: crate::bugs::Bugs::new(&cfg.state_dir),
        tiles: crate::view::Tiles::new(&cfg.state_dir),
    });
    {
        // The helper puts a keyboard that is on back on BlueZ.
        let p = svc.peripherals.clone();
        std::thread::spawn(move || p.status());
    }
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
    // Out of a group the member port is the one cbb pair waits on for the
    // phone (its firewall rule opens it, OpenWrt's init script passes it),
    // so the status says it until the service listens there itself.
    *svc.port.lock().unwrap() = cfg.port;
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
            if LEFT.load(Ordering::SeqCst) {
                return Err(Error::msg("restarting after leaving the group"));
            }
            return Ok(());
        }
        match Identity::load(&cfg.state_dir) {
            Ok(Some(id)) => break id,
            Err(e) => {
                let mut broken = svc.broken.lock().unwrap();
                if broken.is_none() {
                    log(&format!("cbb: {BROKEN} ({})", e.for_log()));
                    *broken = Some(e.for_log());
                }
                drop(broken);
                wait_unless_stopping(Duration::from_secs(2));
            }
            Ok(None) => {
                *svc.broken.lock().unwrap() = None;
                if !said {
                    log("cbb: this device is in no group yet; run cbb pair");
                    said = true;
                }
                wait_unless_stopping(Duration::from_secs(2));
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
    let presence = presence_of(&ident, &records, &cfg.name, &cfg.caps);
    // The blobs of the copies are a cache that a service starts empty, as
    // Go's: the group's current copy is fetched again when it is pasted.
    crate::content::empty(&cfg.state_dir, &|s| log(s));
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
    if let Err(e) = crate::sync::load(&cfg.state_dir, &engine) {
        log(&format!("cbb: sync on or off: {}; sync is on", e.for_log()));
    }
    log(&crate::sync::line(&engine));
    if let Err(e) = crate::mute::load(&cfg.state_dir, &engine) {
        log(&format!("cbb: the mute: {}; not muted", e.for_log()));
    }
    {
        let svc = svc.clone();
        node.on_command(Arc::new(move |peer, c| svc.command(peer, c)));
    }
    {
        let svc = svc.clone();
        node.on_relay(Box::new(move |ev| svc.relayed(ev)));
    }
    node.set_away_limit(u64::try_from(svc.limits.lock().unwrap().away).unwrap_or(0));
    // The group's server credentials (docs/protocol.md, section 18), which
    // the relays check.
    let creds = crate::credentials::Credentials::load(&cfg.state_dir, &node, log.clone());
    away.set_credentials(creds.clone());
    // A computer that is no admin offers an admin key for the root to
    // certify, and keeps the admin CA the root sends for it.
    let (may_admin, may_hub) = (node.can(cbb_core::authority::CAP_ADMIN), node.can(cbb_core::authority::CAP_HUB));
    if may_admin {
        match crate::admin::admin_key_offer(&cfg.state_dir, &node.identity()) {
            Ok(offer) => node.offer_admin_key(offer),
            Err(e) => log(&format!("cbb: making the admin key: {}", e.for_log())),
        }
    }
    {
        let attest = crate::evidence::Attestations::new(&cfg.state_dir);
        attest.send_own(&node);
        attest.status_loop(Arc::downgrade(&node));
        let (dir, n, log, away, creds) =
            (cfg.state_dir.clone(), Arc::downgrade(&node), log.clone(), away.clone(), creds.clone());
        node.on_message(Box::new(move |from, m| {
            let Some(node) = n.upgrade() else { return };
            if let (Some(v), "credentials") = (m.credentials.as_ref(), m.kind.as_str()) {
                creds.received(&node, from, v);
                return;
            }
            if let (Some(e), "evidence") = (m.evidence.as_ref(), m.kind.as_str()) {
                attest.received(&node, from, e);
                return;
            }
            if let Some(der) = m.admin_ca.as_deref().filter(|_| may_admin && m.kind == "admin")
                && let Err(e) = crate::admin::become_admin(&dir, &node, der)
            {
                log(&format!("cbb: the admin CA from {from}: {}", e.for_log()));
            }
            // What another of the group's hubs shares (docs/protocol.md,
            // section 11, "Several hubs").
            if let (Some(v), "hubs", true) = (m.hubs.as_ref(), m.kind.as_str(), may_hub) {
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
    // The member port takes connections, and mDNS publishes this device,
    // only on the networks where it met its group (networks.rs).
    node.set_networks(crate::networks::Networks::load(&cfg.state_dir, true, log.clone()));
    {
        // On a hub, a member's hello brings its tunnel key, which the hub
        // admits, and gets the hub's offers back.
        // Every peer gets the group's server credentials after its hello.
        let (away, n, creds, dir, log) =
            (away.clone(), Arc::downgrade(&node), creds.clone(), cfg.state_dir.clone(), log.clone());
        node.on_hello(Box::new(move |from, peer, chain| match n.upgrade() {
            Some(node) => {
                // The root records what the hello says about the device,
                // as Go's ensureListed, away from the connection's thread.
                if peer.role == cbb_core::authority::ROLE_MEMBER {
                    let (node, dir, peer, log) = (node.clone(), dir.clone(), peer.clone(), log.clone());
                    std::thread::spawn(move || {
                        if let Err(e) = (crate::admin::Admin { node: &node, dir: &dir }).list_from_hello(&peer) {
                            log(&format!("cbb: recording {} in the devices list: {}", peer.id, e.for_log()));
                        }
                    });
                }
                let mut out = away.hello(&node, from, peer, chain);
                out.extend(creds.message());
                out
            }
            None => Vec::new(),
        }));
    }
    *svc.node.write().unwrap() = Some(node.clone());
    {
        // A panic before this start: sent by itself when the user allowed
        // always, else asked about by the apps (status `bug`).
        let (svc, names) = (svc.clone(), device_names(&node));
        std::thread::spawn(move || svc.bugs.start(&names, &*svc.log));
    }
    {
        // The claims to take the group over: one takes effect when its
        // delay ends, without a new record, and this admin's own makes it
        // the root then. A root also renews the admin CAs of the admins
        // connected that have one from an earlier root, and a hub forgets
        // the clients the records remove.
        let (node, dir, name, log, away, creds) =
            (node.clone(), cfg.state_dir.clone(), cfg.name.clone(), log.clone(), away.clone(), creds.clone());
        std::thread::spawn(move || {
            let (mut last, mut failed) = (String::new(), String::new());
            // The server credentials are brought up to date when the records
            // or the credentials change, and twice a day for the period.
            let (mut cred_seen, mut cred_at) = ((String::new(), usize::MAX), std::time::Instant::now());
            // A root's resolve may have voided both histories of this
            // device's key: what it signed is signed again (signed.rs).
            let mut resign_seen = String::new();
            // Certificates are renewed at the start, when a member connects
            // and twice a day, as Go's renewLoop.
            let (mut renew_peers, mut renew_at, every) = (None, std::time::Instant::now(), renew_every());
            while !node.is_closed() {
                let peers: Vec<_> = node.peer_chains().into_iter().map(|(id, _)| id).collect();
                if renew_peers.as_ref() != Some(&peers) || renew_at.elapsed() >= every {
                    crate::admin::renew_certificates(&dir, &node);
                    (renew_peers, renew_at) = (Some(peers), std::time::Instant::now());
                }
                let digest = node.records().lock().unwrap().digest();
                if digest != resign_seen {
                    resign_seen = digest;
                    crate::signed::resign_voided(&dir, &node);
                }
                crate::admin::renew_admin_cas(&dir, &node);
                let seen = (node.records().lock().unwrap().digest(), creds.changes());
                if seen != cred_seen || cred_at.elapsed() >= credential_check() {
                    creds.refresh(&node);
                    cred_seen = (node.records().lock().unwrap().digest(), creds.changes());
                    cred_at = std::time::Instant::now();
                }
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
                node.records_nap(CLAIM_CHECK);
            }
        });
    }
    *svc.away.write().unwrap() = Some(away.clone());
    if let Some(addr) = svc.joined_at.lock().unwrap().take() {
        keep_joined(node.clone(), away.clone(), addr, log.clone());
    }
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

/// How often the claims to take the group over are looked at again.
const CLAIM_CHECK: Duration = Duration::from_secs(2);
/// How often the root and the admins check whether certificates are due
/// for renewal besides when a member connects: the renewal periods are
/// months long, so twice a day is plenty, as Go's renewEvery. The Go
/// service's tests shorten it with CBB_TEST_RENEW_EVERY (milliseconds).
fn renew_every() -> Duration {
    std::env::var("CBB_TEST_RENEW_EVERY")
        .ok()
        .and_then(|v| v.parse().ok())
        .map_or_else(scaled_twice_a_day, Duration::from_millis)
}

/// Twelve hours, or in the bench's time-scaled build that scaled and at
/// least five seconds, as Go's renewEvery.
fn scaled_twice_a_day() -> Duration {
    Duration::from_secs((cbb_core::benchtime::d(12 * 3600) as u64).max(if cbb_core::benchtime::scale() > 1 {
        5
    } else {
        0
    }))
}

/// How often the server credentials are looked at when nothing changed, as
/// Go's renewEvery.
fn credential_check() -> Duration {
    scaled_twice_a_day()
}

/// Every claim of the records with its state: what changes when a claim
/// takes effect.
fn claim_states(node: &Node) -> String {
    let st = node.records().lock().unwrap().state();
    st.claims.iter().map(|c| format!("{}={} ", cbb_core::certs::hex(&c.record.0), c.state)).collect()
}

/// How this member presents itself in its hellos: as a member with the
/// caps its own device record names, or those it was started with while
/// no record names it. Its keys are in the hardware when cbb-helper holds
/// the device key.
fn presence_of(ident: &Identity, records: &Records, name: &str, caps: &[String]) -> crate::node::Presence {
    let own = records.devices().into_iter().find(|d| d.id == ident.id.as_str());
    crate::node::Presence {
        role: "member".into(),
        caps: own.map(|d| d.caps).unwrap_or_else(|| caps.to_vec()),
        name: name.to_string(),
        os: crate::admin::os_name().into(),
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

/// Listens on the control socket on Windows, its folder's access list set
/// first (sys/acl_windows.rs).
#[cfg(windows)]
fn listen(path: &Path, admin: bool) -> Result<UnixListener> {
    if UnixStream::connect(path).is_ok() {
        return Err(Error::msg(format!("another cbb service runs at {}", path.display())));
    }
    crate::sys::listen_windows(path, admin)
}

/// Listens on the control socket: mode 0660, in its own directory; the
/// admin socket gets mode 0600, for root and the service's user only.
#[cfg(unix)]
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
        self.started(|| self.node.read().unwrap().clone())
    }

    fn away(&self) -> Result<Arc<Away>> {
        self.started(|| self.away.read().unwrap().clone())
    }

    /// What get returns once the service has started in its group: a
    /// request that comes while a device in a group is still starting, its
    /// sockets open first, waits for it rather than hearing that the device
    /// is in no group.
    fn started<T>(&self, get: impl Fn() -> Option<T>) -> Result<T> {
        let deadline = std::time::Instant::now() + START_WAIT;
        loop {
            if let Some(v) = get() {
                return Ok(v);
            }
            let in_group = matches!(Identity::load(&self.state_dir), Ok(Some(_)));
            if !in_group || std::time::Instant::now() >= deadline || STOP.load(Ordering::SeqCst) {
                return Err(Error::msg(if in_group {
                    "this device is still starting; try again in a moment"
                } else {
                    "this device is in no group; run cbb new here to start one, or cbb pair to join one"
                }));
            }
            std::thread::sleep(Duration::from_millis(20));
        }
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
                away.serve_if_first(&node);
                // The members connect again, so their hellos carry the key
                // and get the hub's offer.
                node.reconnect();
            }
            "hub-off" => away.stop_hub(&node, h.force)?,
            "relay" => node.set_tunnel_key(Some(away.meet_at(&node, h)?)),
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

    /// The control operations mute and unmute, an admin's only: it mutes
    /// the device -on names or ends its mute (Go's muteOp).
    fn mute_op(&self, h: &Header) -> Result<()> {
        if h.device.is_empty() {
            return Err(Error::msg(
                "cbb mute and cbb unmute name a device with -on, as an admin; cbb sync off turns this device's own sync off",
            ));
        }
        let node = self.node()?;
        let on = h.op == "mute";
        // An admin mutes another device with a command, or this one at once.
        let until = crate::mute::until(h.for_ms)?;
        if self.admin(|a| a.mute(&h.device, on, h.for_ms))?.is_none() {
            let me = node.identity().id.to_string();
            self.set_muted(&node, on, until, &me)?;
        }
        Ok(())
    }

    /// The answer to sync and muted, as the phone's member gives it.
    fn standing(&self) -> Result<Message> {
        let standing = crate::sync::standing(&self.node()?.engine);
        Ok(control::reply(Header { standing: Some(standing), done: true, ..Default::default() }, Vec::new()))
    }

    /// Turns sync on, or off for ms milliseconds (0 for until it is
    /// turned on), and saves it.
    fn set_sync(&self, on: bool, ms: i64) -> Result<()> {
        let node = self.node()?;
        crate::sync::set(&self.state_dir, &node.engine, on, ms)?;
        (self.log)(&crate::sync::line(&node.engine));
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
        if let Err(why) = remember_command(&mut self.commands.lock().unwrap(), &body.id, body.expires_ms, now) {
            return refused(&body.id, why.into());
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
        if let Err(e) = Mode::parse(&body.mode).and_then(|m| self.set_sync(m == Mode::Shared, 0)) {
            (self.log)(&format!("cbb: a command from {peer}: {}", e.for_log()));
            return wire::CommandResult {
                id: body.id,
                by: String::new(),
                status: "failed".into(),
                reason: e.message().to_string(),
                tunnel: None,
            };
        }
        (self.log)(&format!("cbb: {} turned sync {} here", body.by, if body.mode == "own" { "off" } else { "on" }));
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
            Ok(set) if !set.has(&body.action) => {
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
                    res = self.run_action(&body, &set.get(&body.action).command);
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

    /// Runs an action that passed the checks: the user's own (command) and,
    /// but on Linux, the presets of the system in the signed-in user's
    /// session through CBB's agent, as Go's sessionRunner; on Linux the
    /// presets through logind.
    fn run_action(&self, body: &crate::records::Command, command: &[String]) -> wire::CommandResult {
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
        let ran = if body.action == actions::LAYOUT {
            self.next_keyboard_layout()
        } else if !command.is_empty() || !cfg!(target_os = "linux") {
            self.in_session(&body.action, command)
        } else {
            actions::run(&body.action)
        };
        match ran {
            Ok(()) => {}
            Err(actions::Failure::Refused(why)) => (res.status, res.reason) = ("refused".into(), why),
            Err(actions::Failure::Failed(e)) => (res.status, res.reason) = ("failed".into(), e.for_log()),
        }
        res
    }

    /// Hands the action name, with command the user's own, to an agent
    /// that offers to run the actions as the user at the screen, as Go's
    /// sessionRunner: the first that answers decides.
    fn in_session(&self, name: &str, command: &[String]) -> std::result::Result<(), actions::Failure> {
        let ws: Vec<(Option<peer::Who>, SyncSender<ToWatcher>)> =
            self.watchers.lock().unwrap().iter().filter(|w| w.act).map(|w| (w.uid, w.tx.clone())).collect();
        if ws.is_empty() {
            return Err(actions::Failure::Refused(
                "nobody is signed in here with CBB's agent running, and the actions run in the user's session".into(),
            ));
        }
        let ws = act_takers(ws, peer::at_screen);
        if ws.is_empty() {
            return Err(actions::Failure::Refused(
                "CBB's agent runs here only as users who are not signed in at the screen, and the actions run in that user's session".into(),
            ));
        }
        let mut reasons: Vec<String> = Vec::new();
        for tx in ws {
            let (done, answer) = mpsc::sync_channel(1);
            let a = Act { name: name.into(), command: command.to_vec(), done };
            if tx.try_send(ToWatcher::Act(a)).is_err() {
                continue;
            }
            let Ok((status, reason)) = answer.recv_timeout(crate::admin::ACTION_WAIT) else {
                return Err(actions::Failure::Failed(Error::msg("the agent did not answer")));
            };
            match status.as_str() {
                "done" => return Ok(()),
                "refused" => return Err(actions::Failure::Refused(reason)),
                _ => reasons.push(reason),
            }
        }
        if reasons.is_empty() {
            return Err(actions::Failure::Failed(Error::msg("the agent is busy")));
        }
        reasons.dedup();
        Err(actions::Failure::Failed(Error::msg(reasons.join("; "))))
    }

    /// The keyboard-layout preset: the Bluetooth keyboard types in the next
    /// layout.
    fn next_keyboard_layout(&self) -> std::result::Result<(), actions::Failure> {
        self.peripherals.next_layout()
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
        let by = actions::parse_kinds(&a.by.join(","))?;
        let mut set = actions::load(&self.state_dir)?;
        let command = if !a.command.is_empty() {
            if let Some(why) = actions::check_own(&a.name, &a.command) {
                return Err(Error::msg(why));
            }
            if !set.has(&a.name) && set.own().len() >= actions::MAX_OWN {
                return Err(Error::msg(format!(
                    "this device has {} actions of its user's own already, the most it keeps",
                    actions::MAX_OWN
                )));
            }
            a.command.clone()
        } else if actions::PRESETS.contains(&a.name.as_str()) {
            Vec::new()
        } else if set.has(&a.name) {
            set.get(&a.name).command // enable or disable keeps it
        } else {
            return Err(Error::msg(format!(
                "this device has no action {:?}; the presets are {}, and cbb action add adds your own",
                a.name,
                actions::PRESETS.join(", ")
            )));
        };
        set.set(actions::Action { name: a.name.clone(), on: a.on, by: by.clone(), any_key: a.any_key, command });
        actions::save(&self.state_dir, &set).map_err(|e| e.context("saving the quick actions"))?;
        node.set_actions(set.on());
        (self.log)(&format!(
            "cbb: the action {} is {} here (by {by:?}, any key {})",
            a.name,
            if a.on { "on" } else { "off" },
            a.any_key
        ));
        Ok(self.action_reply(&set))
    }

    /// cbb action remove: the user's own action goes.
    fn remove_action(&self, h: &Header) -> Result<Message> {
        let node = self.node()?;
        let mut set = actions::load(&self.state_dir)?;
        if !set.remove(&h.name) {
            if actions::PRESETS.contains(&h.name.as_str()) {
                return Err(Error::msg(format!(
                    "{} is a preset, which stays; cbb action disable {} turns it off",
                    h.name, h.name
                )));
            }
            return Err(Error::msg(format!("this device has no action of its user's own named {:?}", h.name)));
        }
        actions::save(&self.state_dir, &set).map_err(|e| e.context("saving the quick actions"))?;
        node.set_actions(set.on());
        (self.log)(&format!("cbb: the action {} is removed here", h.name));
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
            Ok(set) if body.paste_kind == "media" => res = self.paste_copy(node, &body, set, &from.name),
            Ok(set) => {
                let text = remotepaste::clean(&body.text);
                match (!text.is_empty()).then(|| self.peripherals.paste(&text, set.enter, body.enter)).flatten() {
                    Some((status, reason)) => {
                        (res.status, res.reason) = (status, reason);
                        if res.status == "done" {
                            self.watch_typing(c, &body, text.len());
                        }
                    }
                    None => res = self.inject(&body, &text, set, &from.name),
                }
            }
        }
        if res.status == "done" && body.paste_kind == "media" {
            (self.log)(&format!("cbb: {} pasted the group's copy {} here", from.who(&body), body.text));
        } else if res.status == "done" {
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

    /// Watches a paste the keyboard's host or a Roku types after its
    /// answer, as Go's stillAllowed: once the records no longer take its
    /// command c from its signer, removed or frozen meanwhile, the helper
    /// stops typing; it stops by itself when remote paste goes off.
    fn watch_typing(&self, c: &crate::records::Record, body: &crate::records::Command, len: usize) {
        let Ok(node) = self.node() else { return };
        let (c, at, p) = (c.clone(), body.time_ms, self.peripherals.clone());
        // At most as long as the slowest typing: a Roku's pace, or the
        // keyboard's slowest rate.
        let until = Instant::now() + Duration::from_secs(60) + Duration::from_millis(200) * len as u32;
        std::thread::spawn(move || {
            while Instant::now() < until && !STOP.load(Ordering::SeqCst) {
                std::thread::sleep(TYPING_CHECK);
                let me = node.identity().id.to_string();
                if node.records().lock().unwrap().verify_command(&c, &me, at).is_err() {
                    p.stop();
                    return;
                }
            }
        });
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
            let targets: Vec<(String, Option<peer::Who>, SyncSender<ToWatcher>)> = order
                .iter()
                .flat_map(|t| ws.iter().filter(move |w| w.target == *t))
                .map(|w| (w.target.clone(), w.uid, w.tx.clone()))
                .collect();
            let console = ws.iter().any(|w| w.target == CONSOLE);
            (targets, console)
        };
        if targets.is_empty() {
            res.reason = no_target(console, set.console, cfg!(target_os = "macos")).into();
            return res;
        }
        // Only the user at the screen takes them, and a secret only where
        // the system tells who that is.
        let targets = match paste_takers(targets, body.paste_kind == "secret", peer::at_screen) {
            Ok(t) => t,
            Err(why) => {
                res.reason = why.into();
                return res;
            }
        };
        let wait = if body.mode == "type" { INJECT_WAIT + TYPE_WAIT * text.len() as u32 } else { INJECT_WAIT };
        let mut reasons: Vec<String> = Vec::new();
        for (target, uid, tx) in targets {
            let (done, answer) = mpsc::sync_channel(1);
            let keys = match uid {
                Some(uid) if target == DESKTOP => self.grant_keys(uid, body.enter, wait),
                _ => String::new(),
            };
            let i = Inject {
                text: text.to_string(),
                method: body.mode.clone(),
                enter: body.enter,
                no_lock_check: set.no_lock_check,
                keys: keys.clone(),
                kind: body.paste_kind.clone(),
                name: name.to_string(),
                done,
            };
            if tx.try_send(ToWatcher::Inject(i)).is_err() {
                self.grants.lock().unwrap().remove(&keys);
                continue;
            }
            let answered = answer.recv_timeout(wait);
            // The grant ends with the session's answer.
            self.grants.lock().unwrap().remove(&keys);
            let reason = match answered {
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

    /// Makes the grant of a remote paste for uid, a desktop session's user,
    /// valid for wait, as Go's grantKeys.
    fn grant_keys(&self, uid: peer::Who, enter: bool, wait: Duration) -> String {
        grant_keys(&mut self.grants.lock().unwrap(), uid, enter, wait)
    }

    /// Answers the uinput helper's keys (Go's takeKeys): whether it may
    /// press the keys req, paste or enter, for the user uid under the grant.
    fn take_keys(&self, grant: &str, req: &str, uid: &str) -> Result<()> {
        if take_keys(&mut self.grants.lock().unwrap(), grant, req, uid) {
            Ok(())
        } else {
            Err(Error::msg("no remote paste asked for these keys now"))
        }
    }

    /// Carries out a paste of the group's copy of images or files that body
    /// names, as a full member does (internal/service/pastemedia.go): it
    /// waits for the copy, which must be sealed to the sender too, fetches
    /// it, and hands the paste to a desktop watcher whose clipboard takes
    /// it, which fetches it with paste-media and presses the paste keys.
    fn paste_copy(
        &self,
        node: &Node,
        body: &crate::records::Command,
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
        let until = std::time::Instant::now() + COPY_WAIT;
        let ev = loop {
            if let Some(ev) = node.engine.current().filter(|ev| ev.id == body.text) {
                break ev;
            }
            if std::time::Instant::now() >= until {
                res.reason = "the copy to paste did not arrive here, or a newer copy replaced it".into();
                return res;
            }
            std::thread::sleep(Duration::from_millis(50));
        };
        let sealed_to_sender = ev.sealed.as_ref().is_some_and(|s| s.wraps.iter().any(|w| w.to == body.by));
        let Some(m) = ev.media.clone().filter(|_| !ev.unread && sealed_to_sender) else {
            res.reason = if ev.unread {
                "this device cannot read the copy to paste"
            } else if ev.media.is_none() {
                "the copy to paste holds no images or files"
            } else {
                "the copy to paste was not sealed to the device that sent the paste"
            }
            .into();
            return res;
        };
        let (targets, text_only) = {
            let ws = self.watchers.lock().unwrap();
            let targets: Vec<(String, Option<peer::Who>, SyncSender<ToWatcher>)> = ws
                .iter()
                .filter(|w| w.target == DESKTOP && w.takes(&m))
                .map(|w| (w.target.clone(), w.uid, w.tx.clone()))
                .collect();
            (targets, ws.iter().any(|w| !w.target.is_empty()))
        };
        let targets: Vec<(Option<peer::Who>, SyncSender<ToWatcher>)> = targets
            .into_iter()
            .filter(|(t, uid, _)| !matches!(peer::may_take(*uid, t, peer::at_screen), peer::Verdict::Refused))
            .map(|(_, uid, tx)| (uid, tx))
            .collect();
        if targets.is_empty() {
            res.reason = if text_only {
                "the paste targets here take only text: tmux, a text console, the ZX Spectrum Next, or a desktop whose clipboard takes no images or files, or whose user is not at the screen"
            } else {
                "nothing on this device can paste images or files: no desktop session of CBB runs here"
            }
            .into();
            return res;
        }
        let ev = Arc::new(ev);
        if let Err(e) = node.fetch(&ev, self.limits.lock().unwrap().home as u64) {
            res.status = "failed".into();
            res.reason = format!("the copy's images or files did not arrive here: {}", e.for_log());
            return res;
        }
        *self.media.lock().unwrap() = Some(ev);
        let mut reasons: Vec<String> = Vec::new();
        for (uid, tx) in targets {
            let (done, answer) = mpsc::sync_channel(1);
            let keys = uid.map(|uid| self.grant_keys(uid, body.enter, COPY_PASTE_WAIT)).unwrap_or_default();
            let i = Inject {
                text: body.text.clone(),
                method: body.mode.clone(),
                enter: body.enter,
                no_lock_check: set.no_lock_check,
                keys: keys.clone(),
                kind: body.paste_kind.clone(),
                name: name.to_string(),
                done,
            };
            if tx.try_send(ToWatcher::Inject(i)).is_err() {
                self.grants.lock().unwrap().remove(&keys);
                continue;
            }
            let reason = match answer.recv_timeout(COPY_PASTE_WAIT) {
                Ok((status, _)) if status == "done" => {
                    res.status = status;
                    return res;
                }
                Ok((status, reason)) => {
                    res.status = status;
                    reason
                }
                Err(RecvTimeoutError::Timeout) => "the desktop target did not answer".into(),
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
        targets.extend(self.peripherals.status().map(|p| p.targets).unwrap_or_default());
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
        if h.name == "on" && (!h.device.is_empty() || h.all) {
            return Err(Error::msg("only a device's own user turns remote paste on there"));
        }
        if h.name == "off" && (h.enter || h.console || h.no_lock_check) {
            return Err(Error::msg("-enter, -console and -no-lock-check go with on"));
        }
        self.node()?;
        if !h.device.is_empty() || h.all {
            let off_here = || {
                remotepaste::save(&self.state_dir, remotepaste::Settings::default())
                    .map_err(|e| e.context("saving the remote paste settings"))?;
                (self.log)("cbb: remote paste is off here");
                Ok(())
            };
            self.admin(|a| a.off_on(&h.device, h.all, true, &off_here))?;
            let status = Status { paste: self.paste_status(), ..Default::default() };
            return Ok(control::reply(Header { status: Some(status), ..Default::default() }, Vec::new()));
        }
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

    /// cbb paste -on: signs a paste command for the member h.device and
    /// waits for its result, as Go's sendPaste.
    fn paste_on(&self, h: &Header, payload: &[u8]) -> Result<Message> {
        let mode = if h.method.is_empty() { "paste" } else { h.method.as_str() };
        let kind = if h.kind.is_empty() { "text" } else { h.kind.as_str() };
        if kind == "media" {
            return self.paste_copy_on(h);
        }
        let text = remotepaste::clean(&String::from_utf8_lossy(payload));
        if text.is_empty() {
            return Err(Error::msg("nothing to paste: the text is empty or only control characters"));
        }
        let wait = if mode == "type" { INJECT_WAIT + TYPE_WAIT * text.len() as u32 } else { INJECT_WAIT };
        let o = cbb_core::manage::Order::Paste { mode: mode.into(), kind: kind.into(), text, enter: h.enter };
        self.admin(|a| a.paste_on(&h.device, o, wait))?;
        Ok(control::reply(Header { done: true, ..Default::default() }, Vec::new()))
    }

    /// cbb paste -on with images or files, as Go's sendCopyPaste: a paste
    /// command that names the group's current copy, which must be images or
    /// files that this device reads.
    fn paste_copy_on(&self, h: &Header) -> Result<Message> {
        if !h.method.is_empty() && h.method != "paste" {
            return Err(Error::msg("images and files are pasted, not typed"));
        }
        let node = self.node()?;
        let Some(ev) = node.engine.current().filter(|ev| ev.media.is_some() && !ev.unread) else {
            return Err(Error::msg("the group's current copy is no images or files that this device reads"));
        };
        let o =
            cbb_core::manage::Order::Paste { mode: "paste".into(), kind: "media".into(), text: ev.id, enter: h.enter };
        self.admin(|a| a.paste_on(&h.device, o, COPY_WAIT + COPY_PASTE_WAIT))?;
        Ok(control::reply(Header { done: true, ..Default::default() }, Vec::new()))
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
        // The parts are fetched as Go's setMedia does, whether or not a
        // watcher takes them, and a copy over the limit is refused.
        let node = self.node().ok();
        let takers = node.is_some()
            && self.watchers.lock().unwrap().iter().any(|x| (x.board || x.target == NEXT) && x.takes(&m));
        if let Some(node) = node {
            let svc = self.clone();
            let (alt, m) = (alt.clone(), m.clone());
            std::thread::spawn(move || {
                let limit = svc.limits.lock().unwrap().home;
                let size = ev.sealed.as_ref().and_then(|s| s.blob.as_ref()).map_or(0, |b| b.size);
                let fetched = if size > limit {
                    Err(Error::msg(format!(
                        "a {} copy from {} is over this device's limit of {}",
                        copies::size_text(size),
                        ev.origin,
                        copies::size_text(limit)
                    )))
                } else {
                    // Until a newer write comes.
                    Self::fetch_retrying(&node, &ev, limit, || *svc.latest.lock().unwrap() == w.seq)
                };
                if *svc.latest.lock().unwrap() != w.seq {
                    return; // a newer write came
                }
                if fetched.is_ok() {
                    (svc.log)(&format!("cbb: fetched a copy of {}", copies::size_text(size)));
                }
                let mut failed = svc.fetch_failed.lock().unwrap();
                match &fetched {
                    Ok(()) => failed.clear(),
                    Err(e) => {
                        (svc.log)(&format!("cbb: fetching a copy's images or files: {}", e.for_log()));
                        *failed = e.message().to_string();
                    }
                }
                drop(failed);
                if takers {
                    let whole = fetched.is_ok().then_some(w);
                    svc.send_writes(|x| if x.takes(&m) { whole.clone().or_else(|| alt.clone()) } else { None });
                    if let Some(w) = whole {
                        svc.tell_next(&m, w);
                    }
                }
            });
        }
        let Some(alt) = alt else { return };
        if !self.send_writes(|x| if x.takes(&m) && takers { None } else { Some(alt.clone()) }) && !takers {
            *self.pending.lock().unwrap() = Some(alt);
        }
    }

    /// Tells the Next's link of a copy of images it fetched, which the Next
    /// shows over the program in front (docs: apps/zxnext/README.md).
    fn tell_next(&self, m: &Manifest, w: WriteReq) {
        for x in self.watchers.lock().unwrap().iter().filter(|x| x.target == NEXT && x.takes(m)) {
            let _ = x.tx.try_send(ToWatcher::Write(w.clone()));
        }
    }

    /// Fetches the blob of ev, as Go's fetchAll: again after a pause while
    /// no peer gives it, as when the hub has yet to fetch it, until it
    /// arrives, wanted says it is wanted no more, or FETCH_FOR passes.
    fn fetch_retrying(node: &Node, ev: &Event, limit: i64, wanted: impl Fn() -> bool) -> Result<()> {
        let start = std::time::Instant::now();
        loop {
            let res = node.fetch(ev, limit as u64);
            if res.is_ok() || !wanted() || start.elapsed() >= FETCH_FOR {
                return res;
            }
            std::thread::sleep(FETCH_RETRY);
        }
    }

    /// Takes an event this member passes on without writing it, as Go's
    /// relayed: a hub fetches the blob of the group's current copy within
    /// its limit away from home, so that the members that reach only it
    /// can fetch it from its cache.
    fn relayed(self: &Arc<Self>, ev: &Event) {
        let Some(size) = ev.sealed.as_ref().and_then(|s| s.blob.as_ref()).map(|b| b.size) else { return };
        let (Ok(node), Ok(away)) = (self.node(), self.away()) else { return };
        if !away.is_hub() || node.engine.current_copy().is_none_or(|(id, _)| id != ev.id) {
            return;
        }
        let limit = self.limits.lock().unwrap().away;
        if size > limit {
            (self.log)(&format!(
                "cbb: not passing a copy of {} on to the members away from home: it is over this hub's limit of {} away from home",
                copies::size_text(size),
                copies::size_text(limit)
            ));
            return;
        }
        let (ev, svc) = (ev.clone(), self.clone());
        std::thread::spawn(move || {
            // While it is the group's current copy.
            let current = || node.engine.current_copy().is_some_and(|(id, _)| id == ev.id);
            match Self::fetch_retrying(&node, &ev, limit, current) {
                Ok(()) => {
                    (svc.log)(&format!("cbb: fetched a copy of {} to pass on away from home", copies::size_text(size)))
                }
                Err(e) => (svc.log)(&format!("cbb: fetching a copy to pass on away from home: {}", e.for_log())),
            }
        });
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
        if control::needs_admin(&m.header) && !admin {
            let e = Error::msg(format!(
                "{:?} changes the group, so the service takes it only on its admin socket, which only the administrator reaches",
                m.header.op
            ));
            let _ = control::write(&mut out, &control::failure(&e));
            return;
        }
        let broken = self.broken.lock().unwrap().clone();
        if let Some(detail) = broken.filter(|_| m.header.op != "leave") {
            let h = Header { error: BROKEN.to_string(), detail, done: true, ..Default::default() };
            let _ = control::write(&mut out, &control::reply(h, Vec::new()));
            return;
        }
        if m.header.op == "watch" {
            self.watch(m, r, out);
            return;
        }
        if m.header.op == "copy_media" || m.header.op == "copied_media" {
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
        if m.header.op == "pair" && m.header.addrs.is_empty() && m.header.code.is_empty() {
            if let Err(e) = self.pair_window(&m, r, &mut out) {
                (self.log)(&format!("cbb: pair: {}", e.for_log()));
                let _ = control::write(&mut out, &control::failure(&e));
            }
            return;
        }
        if m.header.op == "keys" {
            let answer = if peer::uid(&out).is_some_and(peer::privileged) {
                self.take_keys(&m.header.keys, &m.header.name, &m.header.value)
                    .map(|()| control::reply(Header::default(), Vec::new()))
                    .unwrap_or_else(|e| control::failure(&e))
            } else {
                control::failure(&Error::msg("only the uinput helper, as root, asks for a paste's keys"))
            };
            let _ = control::write(&mut out, &answer);
            return;
        }
        if m.header.op == "join" {
            if let Err(e) = self.join(&m, r, &mut out) {
                (self.log)(&format!("cbb: join: {}", e.for_log()));
                let _ = control::write(&mut out, &control::failure(&e));
            }
            return;
        }
        if m.header.op == "invite" {
            let res = self
                .admin(|a| a.admitter(false))
                .and_then(|admitter| self.away()?.invite(admitter, m.header.expires, r, &mut out));
            if let Err(e) = res {
                (self.log)(&format!("cbb: invite: {}", e.for_log()));
                let _ = control::write(&mut out, &control::failure(&e));
            }
            return;
        }
        if m.header.op == "release_file" {
            let answer = match self.receive_release_file(&m, &mut r) {
                Ok(()) => control::reply(Header::default(), Vec::new()),
                Err(e) => {
                    (self.log)(&format!("cbb: release-file: {}", e.for_log()));
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
        if m.header.op == "release_get" {
            if let Err(e) = self.send_release_file(&m.header.value, &mut out) {
                (self.log)(&format!("cbb: release-get: {}", e.for_log()));
                let _ = control::write(&mut out, &control::failure(&e));
            }
            return;
        }
        if m.header.op == "paste_media" {
            if let Err(e) = self.paste_media(&mut out, &m.header.value) {
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
        let ev = if m.header.op == "copied_media" {
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
    ///
    /// With `copy`, the group's copy of a remote paste that paste_copy
    /// fetched, while it is the current one.
    fn paste_media(&self, out: &mut UnixStream, copy: &str) -> Result<()> {
        let node = self.node()?;
        let engine = &node.engine;
        let ev = if !copy.is_empty() {
            let ev = engine.current().filter(|ev| ev.id == copy && ev.media.is_some() && !ev.unread);
            Arc::new(ev.ok_or_else(|| Error::msg("the copy to paste is no longer the group's current copy"))?)
        } else if engine.mode().receives() {
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

    /// Takes an archive of the release held from cbb update, which
    /// installed it (Go's receiveReleaseFile): Value its SHA-256 and Part
    /// its size, its bytes in data messages; it must be listed, whole and
    /// match its hash.
    fn receive_release_file(&self, m: &Message, r: &mut control::Reader<UnixStream>) -> Result<()> {
        use std::io::Write;
        let node = self.node()?;
        let releases = node.releases();
        let sha = m.header.value.to_ascii_lowercase();
        let now = uptime::wall_ms();
        let a =
            releases.file(&sha, now).ok_or_else(|| Error::msg("the release this device holds lists no such file"))?;
        if m.header.part.as_ref().map(|p| p.size) != Some(a.size) {
            return Err(Error::msg(format!("{} is {} bytes, not as said", a.name, a.size)));
        }
        let tmp = releases.files_dir()?.join(format!(".part-{}", files::random_name()));
        let res = (|| {
            let mut f = std::fs::File::create(&tmp).context("cannot keep the archive")?;
            let mut got: i64 = 0;
            while got < a.size {
                let d = r.read()?.filter(|d| d.header.op == "data" && !d.payload.is_empty());
                let d = d.filter(|d| i64::try_from(d.payload.len()).is_ok_and(|n| n <= a.size - got));
                let d = d.ok_or_else(|| Error::msg(format!("the bytes of {} did not come as said", a.name)))?;
                f.write_all(&d.payload).context("cannot keep the archive")?;
                got += d.payload.len() as i64;
            }
            drop(f);
            releases.keep_file(&sha, &tmp, now)
        })();
        let _ = std::fs::remove_file(&tmp);
        res
    }

    /// Answers release-get (Go's sendReleaseFile): the archive of the
    /// release held whose SHA-256 is sha, from this member or its peers, as
    /// a part and its bytes, then done.
    fn send_release_file(&self, sha: &str, out: &mut UnixStream) -> Result<()> {
        use std::io::Read;
        let node = self.node()?;
        let sha = sha.to_ascii_lowercase();
        node.fetch_release_file(&sha)?;
        let path = node.releases().path_of(&sha);
        let mut f = std::fs::File::open(&path).context("the file left this device")?;
        let size =
            node.releases().held(&sha, uptime::wall_ms()).ok_or_else(|| Error::msg("the file left this device"))?;
        let reply = |h: Header, payload: Vec<u8>| Message::new(Header { op: "reply".into(), ..h }, payload);
        let part = control::Part { size: size as i64, ..Default::default() };
        control::write(out, &reply(Header { part: Some(part), ..Default::default() }, Vec::new()))?;
        let mut buf = vec![0; 1 << 20];
        let mut sent = 0u64;
        while sent < size {
            let n = f.read(&mut buf).context("cannot read the archive")?;
            if n == 0 {
                return Err(Error::msg("the archive changed its size"));
            }
            sent += n as u64;
            control::write(out, &reply(Header::default(), buf[..n].to_vec()))?;
        }
        control::write(out, &reply(Header { done: true, ..Default::default() }, Vec::new()))
    }

    /// On a hub, the archives of the release held that the group's members
    /// update from and this device does not hold whole, at most
    /// MAX_WANTED, for its cbb update to download (Go's
    /// wantedReleaseFiles); elsewhere none.
    fn wanted_release_files(&self) -> Result<Option<Vec<String>>> {
        let node = self.node()?;
        if !self.away()?.is_hub() {
            return Ok(None);
        }
        let now = uptime::wall_ms();
        let names = node.archives();
        let wanted: Vec<String> = node
            .releases()
            .files(now)
            .into_iter()
            .filter(|a| names.contains(&a.name) && node.releases().held(&a.sha256, now).is_none())
            .map(|a| a.name)
            .take(MAX_WANTED)
            .collect();
        Ok(Some(wanted).filter(|w| !w.is_empty()))
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
        control::Media { max_copy: l.home, max_copy_away: l.away, failed: self.fetch_failed.lock().unwrap().clone() }
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
                    if let Ok(node) = self.node() {
                        node.set_away_limit(u64::try_from(l.away).unwrap_or(0));
                    }
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
                        role: "member".into(),
                        os: crate::admin::os_name().into(),
                        version: VERSION.into(),
                        ..Default::default()
                    }),
                    ..Default::default()
                },
                Vec::new(),
            )),
            "status" => {
                let peripherals = self.peripherals.status();
                // A device in no group still answers, with what needs no
                // group: its version, a TV's remote and the keyboard.
                let node = match self.node() {
                    Ok(node) => node,
                    Err(_) if !matches!(Identity::load(&self.state_dir), Ok(Some(_))) => {
                        let status = Status {
                            version: VERSION.into(),
                            os: crate::admin::os_name().into(),
                            keyboard: peripherals.as_ref().and_then(|p| p.keyboard.clone()),
                            tvs: peripherals.map(|p| p.tvs).unwrap_or_default(),
                            left_old_group: self.left_old,
                            port: self.port.lock().unwrap().map_or(0, i64::from),
                            ..Default::default()
                        };
                        return Ok(control::reply(Header { status: Some(status), ..Default::default() }, Vec::new()));
                    }
                    Err(e) => return Err(e),
                };
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
                // Read apart: a guard in the literal would live through it,
                // and group_status takes the records too.
                let (key_level, incoming_ms) = {
                    let records = node.records();
                    let st = records.lock().unwrap().state();
                    (st.key_level, st.incoming_ms)
                };
                let group = group_status(&node);
                let status = Status {
                    device: id.id.to_string(),
                    group: id.tag(),
                    role: node.role().into(),
                    os: node.os().into(),
                    peers,
                    version: VERSION.into(),
                    left_old_group: false,
                    mode: node.engine.mode().name().into(),
                    muted: node.engine.mute_left().is_some(),
                    muted_until_ms: node.engine.mute_left().filter(|l| *l > 0).map_or(0, |l| uptime::wall_ms() + l),
                    sync_until_ms: node.engine.sync().1,
                    away: self.away()?.status(&node),
                    paste: self.paste_status(),
                    keyboard: peripherals.as_ref().and_then(|p| p.keyboard.clone()),
                    tvs: peripherals.map(|p| p.tvs).unwrap_or_default(),
                    release: node.releases().version(uptime::wall_ms()).unwrap_or_default(),
                    update: node
                        .releases()
                        .version(uptime::wall_ms())
                        .filter(|v| crate::releases::offered(v))
                        .unwrap_or_default(),
                    actions: action_status(&actions::load(&self.state_dir).unwrap_or_default()),
                    stop: node.stop(),
                    removed: node.removed() && !group.frozen && group.taken_over_by.is_empty(),
                    media: Some(self.media_status()),
                    key_level: if key_level.is_empty() { "hardware".into() } else { key_level },
                    key_problem: String::new(),
                    incoming_ms: incoming_ms.unwrap_or(cbb_core::authority::DEFAULT_INCOMING),
                    unreached: node.unreached(),
                    port: self.port.lock().unwrap().map_or(0, i64::from),
                    quiet: node.networks().map(|n| n.unknown()).unwrap_or_default(),
                    cert_ends_ms: id.cert.not_after * 1000,
                    bug: self.bugs.waiting(),
                    ..group
                };
                Ok(control::reply(Header { status: Some(status), ..Default::default() }, Vec::new()))
            }
            "devices" => {
                let node = self.node()?;
                let hubs = self.away().map(|a| a.known_hubs(&node.hub_order())).unwrap_or_default();
                Ok(control::reply(Header { devices: devices(&node, &hubs), ..Default::default() }, Vec::new()))
            }
            // The tiles to draw, and the user's change of their order.
            "view" | "arrange" => {
                let node = self.node()?;
                let hubs = self.away().map(|a| a.known_hubs(&node.hub_order())).unwrap_or_default();
                let op = match (&*h.op, &h.arrange) {
                    ("arrange", Some(v)) => Some(
                        serde_json::from_value::<cbb_core::arrange::Op>(v.clone())
                            .map_err(|e| Error::msg(format!("arrange: the change does not read: {e}")))?,
                    ),
                    ("arrange", None) => return Err(Error::msg("arrange: which change?")),
                    _ => None,
                };
                let view = self.tiles.view(&node.identity().tag(), devices(&node, &hubs), op.as_ref())?;
                let view = serde_json::to_value(view).context("cannot encode the view")?;
                Ok(control::reply(Header { view: Some(view), ..Default::default() }, Vec::new()))
            }
            "away" => self.global(h),
            // The networks this device is on now are known: the user says
            // the group is here (cbb network).
            "network" => {
                let node = self.node()?;
                if let Some(n) = node.networks()
                    && n.learn_all()
                {
                    (self.log)("cbb: the networks this device is on now are known; it publishes itself on them");
                }
                let status =
                    Message { header: Header { op: "status".into(), ..Default::default() }, payload: Vec::new() };
                let mut res = self.request(&status)?;
                res.header.done = true;
                Ok(res)
            }
            // Signed entry points the user gives (cbb update brings them on
            // a Go member), kept and passed on as Go's putEntries.
            "entries" => {
                let set: serde_json::Value = serde_json::from_slice(&m.payload)
                    .map_err(|e| Error::with("the request carries no entry points", e))?;
                self.node()?.put_entries(&set)?;
                Ok(control::reply(Header { done: true, ..Default::default() }, Vec::new()))
            }
            "entries_get" => {
                let set = self
                    .node()?
                    .entries()
                    .current(uptime::wall_ms())
                    .ok_or_else(|| Error::msg("this device holds no signed entry points"))?;
                let data = serde_json::to_vec(&set).context("cannot encode the entry points")?;
                Ok(control::reply(Header { done: true, ..Default::default() }, data))
            }
            "hubs" => {
                self.admin(|a| a.set_hubs(&h.hubs))?;
                Ok(control::reply(Header::default(), Vec::new()))
            }
            "release" => {
                let set: serde_json::Value =
                    serde_json::from_slice(&m.payload).map_err(|e| Error::with("the request carries no release", e))?;
                self.node()?.put_release(&set)?;
                Ok(control::reply(Header { done: true, ..Default::default() }, Vec::new()))
            }
            "release_want" => {
                let data = serde_json::to_vec(&self.wanted_release_files()?).context("cannot encode the files")?;
                Ok(control::reply(Header { done: true, ..Default::default() }, data))
            }
            "release_held" => {
                let set = self
                    .node()?
                    .releases()
                    .current(uptime::wall_ms())
                    .ok_or_else(|| Error::msg("this device holds no signed release"))?;
                let data = serde_json::to_vec(&set).context("cannot encode the release")?;
                Ok(control::reply(Header { done: true, ..Default::default() }, data))
            }
            "update_way" => {
                let node = self.node()?;
                let data = match self.away()?.update_way(&node) {
                    Some(v) => serde_json::to_vec(&v).context("cannot encode the way")?,
                    None => Vec::new(),
                };
                Ok(control::reply(Header { done: true, ..Default::default() }, data))
            }
            "paste_receive" => self.set_receive(h),
            "keyboard" | "remote" => {
                let p = self.peripherals.serve(&h.op, h, &m.payload)?;
                // With the paste targets, which a TV that pastes joins, as
                // Go's status.
                let status =
                    Status { keyboard: p.keyboard, tvs: p.tvs, paste: self.paste_status(), ..Default::default() };
                Ok(control::reply(Header { status: Some(status), done: true, ..Default::default() }, Vec::new()))
            }
            "action_set" => self.set_action(h),
            "actions_off" => {
                let node = self.node()?;
                let off_here = || {
                    self.all_actions_off(&node)?;
                    (self.log)("cbb: the quick actions are off here");
                    Ok(())
                };
                if h.device.is_empty() && !h.all {
                    off_here()?;
                } else {
                    self.admin(|a| a.off_on(&h.device, h.all, false, &off_here))?;
                }
                Ok(self.action_reply(&actions::load(&self.state_dir)?))
            }
            "action_on" => {
                self.admin(|a| a.action_on(&h.device, &h.name))?;
                Ok(control::reply(Header { done: true, ..Default::default() }, Vec::new()))
            }
            "action_remove" => self.remove_action(h),
            "paste_on" => self.paste_on(h, &m.payload),
            "mute" | "unmute" => {
                self.mute_op(h)?;
                Ok(control::reply(Header::default(), Vec::new()))
            }
            "sync" => {
                let on = h.on.ok_or_else(|| Error::msg("sync needs on, true or false"))?;
                if !h.device.is_empty() {
                    if h.for_ms != 0 {
                        return Err(Error::msg("-on turns another device's sync on or off with no time"));
                    }
                    if let Some(name) = self.admin(|a| a.sync_on(&h.device, on))? {
                        return Ok(control::reply(Header { name, done: true, ..Default::default() }, Vec::new()));
                    }
                }
                if on && h.for_ms != 0 {
                    return Err(Error::msg("a time goes only with cbb sync off"));
                }
                self.set_sync(on, h.for_ms)?;
                self.standing()
            }
            "muted" => self.standing(),
            // The bug report of the panic before the last restart
            // (docs/core-api.md, "Bug reports"): what the core made of it,
            // the user's Allow (payload `{"always"}`) or Cancel.
            "bug" => {
                let names = self.node().map(|n| device_names(&n)).unwrap_or_default();
                let data = match self.bugs.offer(&names)? {
                    Some(o) => serde_json::to_vec(&o).context("cannot encode the report")?,
                    None => Vec::new(),
                };
                Ok(control::reply(Header { done: true, ..Default::default() }, data))
            }
            "bug_allow" => {
                let always = serde_json::from_slice::<serde_json::Value>(&m.payload)
                    .ok()
                    .and_then(|v| v.get("always").and_then(serde_json::Value::as_bool))
                    .unwrap_or(false);
                let names = self.node().map(|n| device_names(&n)).unwrap_or_default();
                self.bugs.allow(always, &names)?;
                Ok(control::reply(Header { done: true, ..Default::default() }, Vec::new()))
            }
            "bug_cancel" => {
                self.bugs.cancel();
                Ok(control::reply(Header { done: true, ..Default::default() }, Vec::new()))
            }
            "new" => self.new_group(),
            "remove" => {
                let name = self.admin(|a| a.revoke(&h.device))?;
                Ok(control::reply(Header { name, done: true, ..Default::default() }, Vec::new()))
            }
            "rename" => {
                let name = self.admin(|a| a.rename(&h.device, &h.name))?;
                Ok(control::reply(Header { name, done: true, ..Default::default() }, Vec::new()))
            }
            "freeze" | "thaw" => {
                let name = self.admin(|a| a.freeze(&h.device, h.op == "freeze"))?;
                Ok(control::reply(Header { name, done: true, ..Default::default() }, Vec::new()))
            }
            "resolve" => {
                let who = self.admin(|a| a.resolve())?;
                Ok(control::reply(Header { name: who.join(", "), done: true, ..Default::default() }, Vec::new()))
            }
            "make_admin" => {
                let name = self.admin(|a| a.make_admin(&h.device, h.allow_file_key))?;
                Ok(control::reply(Header { name, done: true, ..Default::default() }, Vec::new()))
            }
            "key_level" => {
                let below = self.admin(|a| a.set_key_level(&h.value))?;
                Ok(control::reply(Header { below, done: true, ..Default::default() }, Vec::new()))
            }
            "takeover_delay" => {
                self.admin(|a| a.set_takeover_delay(&h.value))?;
                Ok(control::reply(Header::default(), Vec::new()))
            }
            "incoming" => {
                self.admin(|a| a.set_incoming(&h.value))?;
                Ok(control::reply(Header::default(), Vec::new()))
            }
            "take_over" => {
                let name = self.admin(|a| a.take_over(&h.device))?;
                Ok(control::reply(Header { name, done: true, ..Default::default() }, Vec::new()))
            }
            "recover" => {
                let text = String::from_utf8_lossy(&m.payload).to_string();
                if h.name == "yubikey" {
                    self.admin(|a| a.recover_with_card(&text))?;
                } else {
                    self.admin(|a| a.recover(&text))?;
                }
                Ok(control::reply(Header::default(), Vec::new()))
            }
            "hand_over" => {
                let name = self.admin(|a| a.hand_over(&h.device))?;
                Ok(control::reply(Header { name, done: true, ..Default::default() }, Vec::new()))
            }
            "pair" => {
                let _slot = self.take_pairing(|| Ok(Pairing::Qr))?;
                let name = if h.addrs.is_empty() && h.fingerprint.is_empty() {
                    // A code alone: the device that shows it waits on the
                    // network, as Go's pairFind.
                    cbb_core::pair::normalize_code(&h.code)?;
                    let waiting = crate::discovery::find_joiners(crate::discovery::PAIRING_BROWSE)?;
                    let mut tried = Vec::new();
                    let mut name = None;
                    for (addrs, fp) in waiting {
                        let addrs: Vec<String> = addrs.iter().map(|a| a.to_string()).collect();
                        match self.admin(|a| a.admit_by_qr(&h.code, &addrs, &fp, h.admins)) {
                            Ok(n) => {
                                name = Some(n);
                                break;
                            }
                            Err(e) => tried.push(e.for_log()),
                        }
                    }
                    name.ok_or_else(|| Error::msg(tried.join("; ")))?
                } else {
                    self.admin(|a| a.admit_by_qr(&h.code, &h.addrs, &h.fingerprint, h.admins))?
                };
                Ok(control::reply(Header { name, done: true, ..Default::default() }, Vec::new()))
            }
            "leave" => {
                // The node stops first, so nothing writes the group's files
                // again; the service then restarts in no group.
                let node = self.node.read().unwrap().clone();
                if node.is_none() && self.broken.lock().unwrap().is_some() {
                    // A damaged identity.json: leaving deletes it with the
                    // rest, and the service starts again in no group.
                    let res = crate::leave::leave_group(&self.state_dir);
                    if res.is_ok() {
                        *self.broken.lock().unwrap() = None;
                        (self.log)(
                            "cbb: this device left its damaged group: the group's files are deleted; it restarts in no group",
                        );
                        std::thread::spawn(|| {
                            std::thread::sleep(RESTART_AFTER);
                            LEFT.store(true, Ordering::SeqCst);
                            STOP.store(true, Ordering::SeqCst);
                        });
                    }
                    return res.map(|()| control::reply(Header::default(), Vec::new()));
                }
                let node = node.ok_or_else(|| Error::msg(crate::leave::NOTHING_TO_LEAVE))?;
                // The group's root leaves only alone, as Go's leave: nobody
                // could add or remove a device after it.
                let me = node.identity().id.to_string();
                if node.records().lock().unwrap().root_member().is_some_and(|(id, _)| id == me) {
                    let others: Vec<String> =
                        node.devices().into_iter().filter(|d| d.id != me).map(|d| d.name).collect();
                    if !others.is_empty() {
                        return Err(Error::msg(format!(
                            "this device is the group's root, and the group has other devices ({}): make one of them an admin (cbb admin) and hand the group over to it (cbb handover) first, or remove them",
                            others.join(", ")
                        )));
                    }
                }
                node.close();
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
    /// cbb pair -code, and cbb pair waiting for a computer to type the code
    /// this device shows (Go's join): dials the member whose window takes
    /// the code, found by mDNS or at the address given, or listens for it,
    /// announced so that a computer finds it by the code alone. The service
    /// takes the group it saves as it would after cbb pair, and the answer
    /// comes once it runs in it. A remote invitation joins through cbb
    /// pair -invite itself.
    fn join(&self, m: &Message, r: control::Reader<UnixStream>, out: &mut UnixStream) -> Result<()> {
        let h = &m.header;
        if matches!(Identity::load(&self.state_dir), Ok(Some(_))) {
            return Err(Error::msg("this device is already in a group"));
        }
        let code = if h.invite.is_empty() {
            cbb_core::pair::normalize_code(&h.code).map_err(|r| Error::msg(r.message()))?
        } else {
            String::new()
        };
        let _one = self.creating.try_lock().map_err(|_| Error::msg("a join or a pairing is already running here"))?;
        let (joiner, save) = crate::joiner(&self.state_dir, &self.name)?;
        let joiner =
            joiner.as_member(crate::admin::os_name(), &self.caps.iter().map(String::as_str).collect::<Vec<_>>());
        let log = self.log.clone();
        let id = if !h.invite.is_empty() {
            // A remote invitation, as Go's joinInvite: sync away from home
            // goes on with it, which a key in a file needs the user's
            // consent for.
            if !joiner.key.is_empty() && !h.consent {
                return Err(Error::msg(
                    "a device that joins with an invitation syncs away from home, and this one keeps its keys in files, so it needs your consent; run cbb pair -invite and read what it says",
                ));
            }
            let shared: &UnixStream = out;
            let shown = |fp: &str| {
                let _ = control::write(
                    &mut &*shared,
                    &control::reply(Header { fingerprint: fp.to_string(), ..Default::default() }, Vec::new()),
                );
            };
            // The client may hang up; the join goes on.
            let mut r = r;
            std::thread::spawn(move || while r.read().is_ok() {});
            crate::away::join_invite(&self.state_dir, &joiner, &*save, &h.invite, &shown, log)?
        } else if h.listen {
            let mut r = r;
            let ln = std::net::TcpListener::bind(("::", 0))
                .or_else(|_| std::net::TcpListener::bind(("0.0.0.0", 0)))
                .context("cannot listen for the member that adds this device")?;
            let port = ln.local_addr().context("cannot listen")?.port();
            let fp = joiner.fingerprint();
            let _announced = crate::discovery::announce_joiner(&joiner.id, port, &fp);
            let addrs = crate::pair::qr_addresses(port);
            control::write(
                out,
                &control::reply(Header { addrs: addrs.clone(), fingerprint: fp, ..Default::default() }, Vec::new()),
            )?;
            let wait = match h.expires {
                n if n > 0 => crate::pair::LIFETIME.min(Duration::from_secs(n as u64)),
                _ => crate::pair::LIFETIME,
            };
            // The client may hang up; the window still ends at wait.
            std::thread::spawn(move || while r.read().is_ok() {});
            crate::pair::listen(&joiner, ln, Some(addrs), &code, wait, &|_| {}, &*save, &|s| log(s))?
        } else {
            let addrs = if h.address.is_empty() {
                crate::discovery::find_pairing(crate::discovery::PAIRING_BROWSE)?
            } else {
                let a = crate::resolve(&h.address)?;
                *self.joined_at.lock().unwrap() = Some(a);
                vec![a]
            };
            let mut last = Error::msg("no address to dial");
            let mut joined = None;
            for a in addrs.iter().take(crate::pair::MAX_FAILURES as usize) {
                let sock = match std::net::TcpStream::connect_timeout(a, Duration::from_secs(10)) {
                    Ok(s) => s,
                    Err(e) => {
                        last = Error::with(format!("cannot connect to {a}"), e);
                        continue;
                    }
                };
                match crate::pair::join(&joiner, sock, &code, &*save) {
                    Ok(id) => {
                        joined = Some(id);
                        break;
                    }
                    // The other side checked the code: one guess only.
                    Err(e) => {
                        last = e;
                        break;
                    }
                }
            }
            joined.ok_or(last)?
        };
        (self.log)(&format!("cbb: joined the group {} as {}", id.tag(), id.id));
        // The group starts from the saved identity; the answer waits for it.
        // Joined at home: the networks it is on are the home's, as Go's.
        if let Some(n) = self.node()?.networks() {
            n.learn_all();
        }
        control::write(out, &control::reply(Header { done: true, ..Default::default() }, Vec::new()))
    }

    fn pair_window(&self, m: &Message, mut r: control::Reader<UnixStream>, out: &mut UnixStream) -> Result<()> {
        let mut win = None;
        let _slot = self.take_pairing(|| {
            let admitter = self.admin(|a| a.admitter(m.header.admins))?;
            let w = Window::open(admitter, &cbb_core::pair::new_code())?;
            win = Some(w.clone());
            Ok(Pairing::Window(w))
        })?;
        let w = win.ok_or_else(|| Error::msg("no window"))?;
        // The user opens a window where the group is.
        if let Some(n) = self.node()?.networks() {
            n.learn_all();
        }
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
            Err(why) => Err(Error::with(format!("pair: {}", why), why)),
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
            role: "member".into(),
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
        let mut act = m.header.act;
        let uid = if target.is_empty() && !act { None } else { peer::uid(&out) };
        let keyboard = target == CONSOLE || target == NEXT;
        if !target.is_empty() && (uid.is_none() || keyboard && !uid.is_some_and(peer::privileged)) {
            (self.log)(&format!(
                "cbb: a watcher offers the paste target {target} as a user that may not take it; it gets no remote pastes"
            ));
            target.clear();
        }
        if act && uid.is_none() {
            (self.log)(
                "cbb: a watcher offers to run the quick actions as a user the system does not name; it runs none",
            );
            act = false;
        }
        let board = !m.header.paste_only && target != TMUX && !keyboard;
        let (images, files, html) = (m.header.images, m.header.files, m.header.html);
        // A write decided while no watcher was connected, if the member's
        // own text is still that, goes to this watcher in place of the
        // stale text its clipboard holds, as Go's.
        let missed = if board {
            self.pending.lock().unwrap().take().filter(|w| node.engine.local().is_some_and(|(t, _, _)| t == w.text))
        } else {
            None
        };
        if board
            && missed.is_none()
            && let (Ok(text), Ok(kind)) = (String::from_utf8(m.payload), kind_of(&m.header.kind))
        {
            node.engine.clipboard_is(&text, kind);
        }
        let (tx, rx) = mpsc::sync_channel::<ToWatcher>(WATCH_QUEUE);
        if control::write(&mut out, &Message::new(Header { op: "reply".into(), ..Default::default() }, Vec::new()))
            .is_err()
        {
            return;
        }
        if let Some(w) = missed {
            let _ = tx.try_send(ToWatcher::Write(w));
        }
        let id = self.next_watcher.fetch_add(1, Ordering::SeqCst);
        self.watchers.lock().unwrap().push(Watcher {
            id,
            target: target.clone(),
            board,
            uid,
            act,
            images,
            files,
            html,
            tx,
        });
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
                                    keys: i.keys,
                                    kind: i.kind,
                                    name: i.name,
                                    ..Default::default()
                                },
                                i.text.into_bytes(),
                            )
                        }
                        ToWatcher::Act(a) => {
                            seq += 1;
                            waiting.lock().unwrap().insert(seq, a.done);
                            Message::new(
                                Header {
                                    op: "act".into(),
                                    seq,
                                    name: a.name,
                                    command: a.command,
                                    ..Default::default()
                                },
                                Vec::new(),
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
            if m.header.op == "injected" || m.header.op == "acted" {
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
        .map(|a| control::Action { name: a.name, on: a.on, by: a.by, any_key: a.any_key, command: a.command })
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
struct ControlUsers(Mutex<HashMap<Option<crate::peer::Who>, usize>>);

impl ControlUsers {
    fn add(&self, user: Option<crate::peer::Who>) -> bool {
        let mut n = self.0.lock().unwrap();
        let c = n.entry(user).or_default();
        if *c >= MAX_CONTROL_PER_USER {
            return false;
        }
        *c += 1;
        true
    }

    fn done(&self, user: Option<crate::peer::Who>) {
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

/// The names of the group's devices, which a bug report replaces.
fn device_names(node: &Node) -> Vec<String> {
    node.devices().into_iter().map(|d| d.name).filter(|n| !n.is_empty()).collect()
}

/// The claims, conflicts and newer records of the group's state for
/// status, as Go's groupStatus.
fn group_status(node: &Node) -> Status {
    let ident = node.identity();
    let own: Vec<cbb_core::certs::Cert> = std::iter::once(ident.cert.clone()).chain(ident.issuer.clone()).collect();
    let records = node.records();
    let rs = records.lock().unwrap();
    let st = rs.state();
    // An old root that an admin took the group over from, or a frozen
    // admin, is refused but not removed, as Go's statusWithRemoved says.
    let taken = rs.taken_over(&own);
    let refused = matches!(rs.refused(&own), Some(cbb_core::group::Refusal::Refused(_)));
    let frozen = taken.is_none() && refused && own.iter().any(|c| rs.frozen(&c.key_hash()));
    // A signer's device for the user, as Go's SignerName.
    let name = |k: &cbb_core::authority::Hash| -> String {
        st.devices
            .iter()
            .find(|d| d.admin.as_ref() == Some(k))
            .or_else(
                || if st.roots.contains(k) { st.devices.iter().find(|d| d.device == st.root_device) } else { None },
            )
            .map_or_else(|| k.text(), |d| d.name.clone())
    };
    Status {
        claims: st
            .claims
            .iter()
            .filter(|c| matches!(c.state, "pending" | "competing" | "disputed"))
            .map(|c| control::Claim { by: name(&c.claimant), state: c.state.into(), left_ms: c.left_ms })
            .collect(),
        conflicts: st
            .conflicts
            .iter()
            .map(|c| control::Conflict { kind: c.kind.into(), devices: c.signers.iter().map(name).collect() })
            .collect(),
        newer: st.newer.len(),
        frozen,
        taken_over_by: taken
            .map(|(dev, _)| st.devices.iter().find(|d| d.device == dev).map_or(dev, |d| d.name.clone()))
            .unwrap_or_default(),
        ..Default::default()
    }
}

/// Keeps a member connection up to the member that admitted this device at
/// addr, the address the user gave for the join, as Go's dialJoined: that
/// member syncs with it at once, and when it is the group's hub it learns
/// this device's tunnel key as soon as sync away from home is turned on
/// here. It stops once this device knows a hub of the group, whose tunnel
/// reaches it from then on, or when the member stops.
fn keep_joined(node: Arc<Node>, away: Arc<Away>, addr: SocketAddr, log: Arc<dyn Fn(&str) + Send + Sync>) {
    const MIN: Duration = Duration::from_secs(1);
    const MAX: Duration = Duration::from_secs(30);
    std::thread::spawn(move || {
        let mut backoff = MIN;
        while !node.is_closed() && away.known_hubs(&node.hub_order()).is_empty() {
            let start = std::time::Instant::now();
            // While another way connects this device to the group, as
            // discovery, it waits.
            if !node.peers().is_empty() {
                std::thread::sleep(MIN);
                continue;
            }
            if let Err(e) = node.dial(addr, None) {
                log(&format!("cbb: connection at {addr}, where this device joined: {}", e.for_log()));
            }
            if start.elapsed() > MAX {
                backoff = MIN;
            }
            std::thread::sleep(backoff);
            backoff = (backoff * 2).min(MAX);
        }
    });
}

/// The group's devices as cbb devices lists them, as Go's devices: the
/// records' devices, this device if no record lists it yet, then the
/// connected members no record lists, with what their hellos say.
fn devices(node: &Node, hubs: &[String]) -> Vec<Device> {
    let ident = node.identity();
    let me = ident.id.to_string();
    let peers = node.peers();
    let now = uptime::wall_ms();
    let (list, root, may_hub) = {
        let records = node.records();
        let rs = records.lock().unwrap();
        let list = rs.devices();
        let may_hub: Vec<bool> = list.iter().map(|d| rs.may_host(&d.id)).collect();
        (list, rs.state().root_device, may_hub)
    };
    let fill = |mut d: Device| {
        d.this = d.id == me;
        d.root = d.id == root;
        d.hub = hubs.contains(&d.id);
        let peer = peers.iter().find(|p| p.id.as_str() == d.id);
        if peer.is_some() || d.this {
            d.online = true;
            d.last_seen_ms = now;
        }
        if d.this {
            let own = crate::device::own();
            (d.form, d.os_version, d.version, d.mac) =
                (own.form.clone(), own.os_version.clone(), own.version.clone(), own.mac.clone());
            d.mode = node.engine.mode().name().into();
            if let Some(left) = node.engine.mute_left() {
                d.muted = true;
                d.muted_until_ms = if left > 0 { now + left } else { 0 };
            }
        }
        if let Some(p) = peer {
            (d.form, d.os_version, d.version, d.mac) =
                (p.device.form.clone(), p.device.os_version.clone(), p.device.version.clone(), p.device.mac.clone());
            d.mode.clone_from(&p.mode);
            d.muted = p.muted;
            d.muted_until_ms = if p.muted && p.muted_for_ms > 0 { now + p.muted_for_ms } else { 0 };
        }
        d
    };
    let mut out: Vec<Device> = list
        .into_iter()
        .zip(may_hub)
        .map(|(d, may_hub)| {
            let os =
                peers.iter().find(|p| p.id.as_str() == d.id && !p.os.is_empty()).map_or(d.os.clone(), |p| p.os.clone());
            fill(Device {
                os,
                store: d.store,
                admin: d.admin,
                frozen: d.frozen,
                forward_only: d.forward_only,
                listed: true,
                may_hub,
                id: d.id,
                name: d.name,
                role: d.role,
                caps: d.caps,
                ..Default::default()
            })
        })
        .collect();
    if !out.iter().any(|d| d.id == me) {
        out.push(fill(Device {
            id: me.clone(),
            name: node.name().into(),
            role: node.role().into(),
            caps: node.caps().to_vec(),
            os: node.os().into(),
            store: crate::admin::own_store(&ident).into(),
            ..Default::default()
        }));
    }
    for p in &peers {
        if !out.iter().any(|d| d.id == p.id.as_str()) {
            out.push(fill(Device {
                id: p.id.to_string(),
                name: p.name.clone(),
                role: p.role.clone(),
                caps: p.caps.clone(),
                os: p.os.clone(),
                store: p.key_store.clone(),
                ..Default::default()
            }));
        }
    }
    out
}

/// Makes a grant of a remote paste for uid, a desktop session's user,
/// valid for wait, as Go's grantKeys; its token, empty when none.
fn grant_keys(grants: &mut HashMap<String, Grant>, uid: peer::Who, enter: bool, wait: Duration) -> String {
    let mut b = [0u8; 16];
    if getrandom::fill(&mut b).is_err() {
        return String::new();
    }
    let token: String = b.iter().map(|x| format!("{x:02x}")).collect();
    let now = Instant::now();
    grants.retain(|_, g| g.until > now);
    grants.insert(token.clone(), Grant { uid, enter, pasted: false, done: false, until: now + wait });
    token
}

/// Whether the uinput helper may press the keys req, paste or enter, for
/// the user uid under the grant, as Go's takeKeys: the paste keys once,
/// then Enter once when the paste asked for it.
fn take_keys(grants: &mut HashMap<String, Grant>, grant: &str, req: &str, uid: &str) -> bool {
    match grants.get_mut(grant) {
        Some(g) if g.until > Instant::now() && g.uid.to_string() == uid => match req {
            "paste" if !g.pasted => {
                g.pasted = true;
                true
            }
            "enter" if g.enter && g.pasted && !g.done => {
                g.done = true;
                true
            }
            _ => false,
        },
        _ => false,
    }
}

/// A paste target: its kind, its user, and what reaches it.
type Target<T> = (String, Option<peer::Who>, T);

/// The paste targets that take a remote paste: those of the user at the
/// screen, as at_screen tells, and of root and the service's own user, and
/// where the system cannot tell who is at the screen, those that are no
/// secret's. None left, it gives why, as Go's.
fn paste_takers<T>(
    targets: Vec<Target<T>>,
    secret: bool,
    at_screen: impl Fn(peer::Who, &str) -> peer::Verdict + Copy,
) -> std::result::Result<Vec<Target<T>>, &'static str> {
    let mut why = "";
    let out: Vec<_> = targets
        .into_iter()
        .filter(|(t, uid, _)| match peer::may_take(*uid, t, at_screen) {
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
        .collect();
    if out.is_empty() { Err(why) } else { Ok(out) }
}

/// Why nothing pastes here: only a console its user did not allow, a Mac
/// without the app, or no paste target at all.
fn no_target(console_here: bool, consoles_allowed: bool, macos: bool) -> &'static str {
    if console_here && !consoles_allowed {
        "only a text console is here, and its user did not allow consoles (sudo cbb paste-receive on -console)"
    } else if macos {
        // Only the app pastes on a Mac, as Go's: macOS lets an app press
        // keys once its user allowed it in Accessibility, and the service
        // and its agent are not apps.
        "a Mac pastes through the CBB app, and it is not open here; its user opens it and allows it in System Settings, Privacy & Security, Accessibility"
    } else {
        "nothing on this device can paste: no tmux or console helper of CBB, nor cbb next link, runs here"
    }
}

/// Remembers the command id until it expires at expires_ms, so it is
/// carried out once; refuses one seen before, and a new one while
/// MAX_COMMANDS that have not expired are held.
fn remember_command(seen: &mut HashMap<String, i64>, id: &str, expires_ms: i64, now: i64) -> Result<(), &'static str> {
    seen.retain(|_, exp| *exp > now);
    if seen.contains_key(id) {
        return Err("this command was carried out already");
    }
    if seen.len() >= MAX_COMMANDS {
        return Err("too many commands; try again in a minute");
    }
    seen.insert(id.to_string(), expires_ms);
    Ok(())
}

/// The agents that run the quick actions: only those of the user at the
/// screen, as Go's sessionRunner, never where the system cannot tell.
fn act_takers<T>(
    agents: Vec<(Option<peer::Who>, T)>,
    at_screen: impl Fn(peer::Who, &str) -> peer::Verdict + Copy,
) -> Vec<T> {
    agents
        .into_iter()
        .filter(|(uid, _)| peer::may_take(*uid, ACT, at_screen) == peer::Verdict::Allowed)
        .map(|(_, tx)| tx)
        .collect()
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    use super::{CONSOLE, DESKTOP, TMUX, act_takers, grant_keys, paste_takers, peer, take_keys};

    /// Users that the tests' fake system names, far from real accounts', as
    /// Go's uidAtScreen and friends.
    #[cfg(unix)]
    const AT_SCREEN: peer::Who = 2_000_000_000;
    #[cfg(unix)]
    const AWAY: peer::Who = 2_000_000_001;
    #[cfg(unix)]
    const UNKNOWN: peer::Who = 2_000_000_002;

    #[cfg(unix)]
    fn fake_screen(uid: peer::Who, _: &str) -> peer::Verdict {
        match uid {
            AT_SCREEN => peer::Verdict::Allowed,
            UNKNOWN => peer::Verdict::Unchecked,
            _ => peer::Verdict::Refused,
        }
    }

    /// As Go's TestPasteTargetUser: pastes go only to the user at the
    /// screen, a console's only to root, a secret only where the system
    /// tells who is at the screen, and none to another user or to a
    /// connection whose user the system does not name.
    #[cfg(unix)]
    #[test]
    fn paste_goes_to_the_user_at_the_screen() {
        let t = |target: &str, uid: Option<peer::Who>, n: u8| (target.to_string(), uid, n);
        let others = vec![t(DESKTOP, Some(AWAY), 1), t(CONSOLE, Some(AWAY), 2), t(TMUX, None, 3)];
        let why = paste_takers(others.clone(), false, fake_screen).unwrap_err();
        assert!(why.contains("not at the screen"), "{why}");

        let mut unknown = others.clone();
        unknown.push(t(DESKTOP, Some(UNKNOWN), 4));
        let got: Vec<u8> =
            paste_takers(unknown.clone(), false, fake_screen).unwrap().into_iter().map(|x| x.2).collect();
        assert_eq!(got, [4]);
        let why = paste_takers(unknown.clone(), true, fake_screen).unwrap_err();
        assert!(why.contains("takes no secret pastes"), "{why}");

        let mut screen = unknown;
        screen.push(t(DESKTOP, Some(AT_SCREEN), 5));
        let got: Vec<u8> = paste_takers(screen.clone(), true, fake_screen).unwrap().into_iter().map(|x| x.2).collect();
        assert_eq!(got, [5]);
        let got: Vec<u8> = paste_takers(screen, false, fake_screen).unwrap().into_iter().map(|x| x.2).collect();
        assert_eq!(got, [4, 5]);

        // Root takes the console.
        let got = paste_takers(vec![t(CONSOLE, Some(0), 6)], true, fake_screen).unwrap();
        assert_eq!(got.len(), 1);
    }

    /// As Go's TestKeysGrant: the helper presses keys only under a grant
    /// the service made, for its user, the paste keys once and Enter once
    /// when the paste asked for it, and none once the grant is gone.
    #[cfg(unix)]
    #[test]
    fn keys_only_under_a_grant() {
        for enter in [true, false] {
            let mut gs = std::collections::HashMap::new();
            let g = grant_keys(&mut gs, AT_SCREEN, enter, std::time::Duration::from_secs(60));
            assert!(!g.is_empty());
            let (me, away) = (AT_SCREEN.to_string(), AWAY.to_string());
            assert!(!take_keys(&mut gs, &g, "paste", &away), "another user's paste keys");
            assert!(!take_keys(&mut gs, &g, "enter", &me), "Enter before the paste");
            assert!(take_keys(&mut gs, &g, "paste", &me), "the paste keys");
            assert!(!take_keys(&mut gs, &g, "paste", &me), "the paste keys again");
            assert_eq!(take_keys(&mut gs, &g, "enter", &me), enter, "Enter");
            assert!(!take_keys(&mut gs, &g, "enter", &me), "Enter again");
            gs.remove(&g);
            assert!(!take_keys(&mut gs, &g, "paste", &me), "after the session answered");
            assert!(!take_keys(&mut gs, "00", "paste", &me), "a grant the service did not make");
        }
        let mut gs = std::collections::HashMap::new();
        let g = grant_keys(&mut gs, AT_SCREEN, false, std::time::Duration::ZERO);
        assert!(!take_keys(&mut gs, &g, "paste", &AT_SCREEN.to_string()), "an ended grant");
    }

    /// As Go's TestActionsAgentUser: the actions go only to an agent of the
    /// user at the screen, not where the system cannot tell.
    #[cfg(unix)]
    #[test]
    fn actions_go_to_the_agent_at_the_screen() {
        assert!(act_takers(vec![(Some(AWAY), 1), (Some(UNKNOWN), 2), (None, 3)], fake_screen).is_empty());
        assert_eq!(act_takers(vec![(Some(AWAY), 1), (Some(AT_SCREEN), 2)], fake_screen), [2]);
    }

    #[cfg(unix)]
    use super::ControlUsers;
    use super::{MAX_COMMANDS, MAX_CONTROL_PER_USER, accept_control, remember_command};

    /// Without the app a Mac says that it pastes through it; a console its
    /// user did not allow is named as such.
    #[test]
    fn why_nothing_pastes() {
        assert!(super::no_target(false, false, true).contains("a Mac pastes through the CBB app"));
        assert!(super::no_target(true, false, true).contains("did not allow consoles"));
        assert!(super::no_target(false, false, false).contains("nothing on this device can paste"));
        assert!(super::no_target(true, true, false).contains("nothing on this device can paste"));
    }

    /// A command is carried out once, until it expires; the commands held
    /// are bounded, and an expired one makes room.
    #[test]
    fn a_command_is_carried_out_once() {
        let mut seen = std::collections::HashMap::new();
        assert!(remember_command(&mut seen, "c1", 2000, 1000).is_ok());
        assert!(remember_command(&mut seen, "c1", 2000, 1500).unwrap_err().contains("already"));
        for i in 1..MAX_COMMANDS {
            assert!(remember_command(&mut seen, &format!("d{i}"), 5000, 1500).is_ok());
        }
        assert!(remember_command(&mut seen, "one-more", 5000, 1500).unwrap_err().contains("too many"));
        // c1 expired: it makes room.
        assert!(remember_command(&mut seen, "one-more", 5000, 2500).is_ok());
    }
    use crate::sys::{UnixListener, UnixStream};
    use std::io::Read;
    use std::time::Duration;

    #[test]
    #[cfg(unix)]
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
