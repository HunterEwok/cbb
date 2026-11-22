// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! cbb's service: the control socket, the identity, the sync
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
use crate::clip::{Kind, Mode, Via};
use crate::control::{self, Device, Header, Message, Status};
use crate::copies;
use crate::discovery;
use crate::error::{Context, Error, Result};
use crate::files;
use crate::identity::Identity;
use crate::identity::Stored as _;
use crate::peer;
use crate::remotepaste;
use crate::uptime;
use crate::wire;
use cbb_core::media::Manifest;

/// A text to put into the member's own clipboard.
#[derive(Clone, Debug)]
pub struct WriteReq {
    pub text: String,
    /// The manifest of a copy with images or files.
    pub media: Option<Manifest>,
    pub kind: Kind,
    pub via: Via,
    pub seq: u64,
    /// For a secret: how long it may stay in the clipboard.
    pub ttl: Option<Duration>,
}

/// The release's version, such as "0.3.0", which the release build passes in
/// `CBB_VERSION`; other builds say "dev", as the Go service does.
pub const VERSION: &str = match option_env!("CBB_VERSION") {
    Some(v) => v,
    None => "dev",
};
const WATCH_QUEUE: usize = 16;
/// How long the service waits before it restarts at an admin's request,
/// so that the result reaches the sender first.
const RESTART_AFTER: Duration = Duration::from_millis(500);

/// The targets a watcher offers for remote paste, as its watch request
/// names them (docs/protocol.md, section 8). cbb has no desktop
/// connector of its own, but a full member's desktop connector may watch it.
pub(crate) const DESKTOP: &str = "desktop";
pub(crate) const TMUX: &str = "tmux";
pub(crate) const CONSOLE: &str = "console";
/// The ZX Spectrum Next's keyboard, through `cbb next link` and the Next's
/// driver on a Next's Pi.
pub(crate) const NEXT: &str = "next";

/// How often a paste typed after its answer checks that it may go on.
const TYPING_CHECK: Duration = Duration::from_millis(500);

/// How long a copy's images or files are fetched before they are given
/// up, and the pause before a fetch that no peer gave is tried again, as
/// Go's fetchFor and fetchRetry.
const FETCH_FOR: Duration = Duration::from_secs(30 * 60);
/// How long a request waits for a device in a group to start.
const START_WAIT: Duration = Duration::from_secs(10);
/// How long a watcher may take to put a paste in; typing takes TYPE_WAIT
/// more for each byte, as on a full member.
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
    /// The member port, where phones and other members dial
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
    /// The member of 0.6, on a group kept in its records (on_live.rs); the
    /// old member does not run then.
    live: RwLock<Option<Arc<crate::live::Live>>>,
    watchers: Mutex<Vec<Watcher>>,
    /// The pace of each user's confirmation prompts (confirm.rs).
    prompts: crate::confirm::Pace,
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
    /// Why the last copy's images or files were not fetched.
    fetch_failed: Mutex<String>,
    /// This device's largest copy of images or files (cbb config).
    limits: Mutex<copies::Limits>,
    state_dir: PathBuf,
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
    /// The pairing window open here; one at a time.
    pairing: Mutex<Option<Pairing>>,
    /// The member port, for the address a pairing window shows.
    port: Mutex<Option<u16>>,
    /// The bug report of a panic before the last restart (src/bugs.rs).
    bugs: crate::bugs::Bugs,
    tiles: crate::view::Tiles,
}

/// A pairing that runs on this device: a window of the member of 0.6
/// (on_live.rs).
enum Pairing {
    Live,
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

/// The operations that need the device's group, which only the member of
/// 0.6 answers (`on_live`).
const GROUP_OPS: &[&str] = &[
    "copy",
    "paste",
    "devices",
    "view",
    "arrange",
    "away",
    "network",
    "entries",
    "entries_get",
    "hubs",
    "release",
    "release_want",
    "release_held",
    "update_way",
    "mute",
    "unmute",
    "sync",
    "muted",
    "remove",
    "rename",
    "freeze",
    "thaw",
    "resolve",
    control::op::MAKE_ADMIN,
    control::op::KEY_LEVEL,
    control::op::TAKEOVER_DELAY,
    "incoming",
    control::op::TAKE_OVER,
    control::op::RECOVER,
    control::op::HAND_OVER,
    control::op::LEAVE,
    "pair",
    "action_on",
    "actions_off",
    "paste_on",
];
/// What the user sees while the device's group files do not open.
const BROKEN_LIVE: &str = "this device's group files (group.cbor and the keys beside it in the service's state directory) do not open, so the service does not start the group; restore them from a backup, or leave the group (cbb leave) and join again";

/// Runs the service until SIGTERM or SIGINT.
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
    let note = crate::testbuild::version_note();
    if !note.is_empty() {
        log(&format!("cbb: a build for tests{note}: it reads the test hooks; never install it"));
    }
    // A panic ends the service (panic = "abort"); the hook keeps what broke
    // for the bug report after the restart (src/bugs.rs).
    crate::bugs::install(&cfg.state_dir);
    // A group made before 0.6 (its identity.json or records.json, and no
    // group.cbor) moves aside: 0.6 runs only groups of its own (D-126).
    let dir = &cfg.state_dir;
    let left_old = !dir.join(crate::set::FILE_NAME).exists()
        && ["identity.json", "records.json"].iter().any(|n| dir.join(n).exists())
        && crate::set::leave_group_before_0_6(dir)?;
    if left_old {
        log(&format!(
            "cbb: this device's group was made before 0.6, which this version no longer runs, so it left that group (its files are in {}); make a new group and join it with the phone's QR code",
            crate::set::OLD_GROUP_DIR
        ));
    }
    let svc = Service::new(&cfg, log.clone(), left_old);
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
    // What a write cut short by a crash or a power cut left behind.
    crate::files::sweep(&cfg.state_dir);
    let only = crate::interfaces::only();
    if !only.is_empty() {
        log(&format!("cbb: the member port and mDNS work only on {} (CBB_INTERFACES)", only.join(", ")));
    }
    // Out of a group the member port is the one cbb pair waits on for the
    // phone (its firewall rule opens it, OpenWrt's init script passes it),
    // so the status says it until the service listens there itself.
    *svc.port.lock().unwrap() = cfg.port;
    let admin_socket = control::admin_socket(&cfg.socket);
    crate::confirm::install(&|l: &str| log(l), &cfg.state_dir);
    for (ln, admin) in [(listen(&cfg.socket, false)?, false), (listen(&admin_socket, true)?, true)] {
        let svc = svc.clone();
        std::thread::spawn(move || accept_control(ln, move |conn| svc.serve(conn, admin)));
    }

    // Wait until the device is in a group: cbb pair may run meanwhile.
    let mut said = false;
    loop {
        if STOP.load(Ordering::SeqCst) {
            let _ = std::fs::remove_file(&cfg.socket);
            let _ = std::fs::remove_file(&admin_socket);
            if LEFT.load(Ordering::SeqCst) {
                return Err(Error::msg("restarting after leaving the group"));
            }
            return Ok(());
        }
        if on_live::in_group(&cfg.state_dir) {
            *svc.broken.lock().unwrap() = None;
            return run_live(&svc, &cfg, &admin_socket);
        }
        *svc.broken.lock().unwrap() = None;
        if !said {
            log("cbb: this device is in no group yet; run cbb pair");
            said = true;
        }
        wait_unless_stopping(Duration::from_secs(2));
    }
}

/// Runs the service on the member of 0.6 until SIGTERM or SIGINT.
fn run_live(svc: &Arc<Service>, cfg: &Config, admin_socket: &Path) -> Result<()> {
    let started = svc.start_live(cfg);
    let live = match started {
        Ok(l) => {
            // A panic before this start: sent by itself when the user
            // allowed always, else asked about by the apps (status `bug`).
            let svc = svc.clone();
            std::thread::spawn(move || svc.bugs.start(&svc.device_names(), &*svc.log));
            Some(l)
        }
        Err(e) => {
            // The group's files do not open: the service keeps answering,
            // with why, until it stops; cbb leave still works.
            (svc.log)(&format!("cbb: {BROKEN_LIVE} ({})", e.for_log()));
            *svc.broken.lock().unwrap() = Some(e.for_log());
            None
        }
    };
    while !STOP.load(Ordering::SeqCst) {
        std::thread::sleep(Duration::from_millis(200));
    }
    (svc.log)("cbb: stopping");
    if let Some(l) = live {
        l.close();
    }
    std::thread::sleep(Duration::from_millis(500));
    let _ = std::fs::remove_file(&cfg.socket);
    let _ = std::fs::remove_file(admin_socket);
    if LEFT.load(Ordering::SeqCst) {
        return Err(Error::msg("restarting after leaving the group"));
    }
    if RESTART.load(Ordering::SeqCst) {
        return Err(Error::msg("restarting at an admin's request"));
    }
    Ok(())
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
        return Err(Error::msg(format!("another cbb service runs at {}", path.display())));
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
    /// A service on cfg's state directory, in no group until it starts its
    /// member.
    fn new(cfg: &Config, log: Arc<dyn Fn(&str) + Send + Sync>, left_old: bool) -> Arc<Service> {
        Arc::new(Service {
            live: RwLock::new(None),
            watchers: Mutex::new(Vec::new()),
            prompts: crate::confirm::Pace::new(),
            grants: Mutex::new(HashMap::new()),
            peripherals: Arc::new(crate::peripheral::Peripherals::new(&cfg.state_dir, &cfg.name)),
            next_watcher: AtomicUsize::new(0),
            pastes: Mutex::new(remotepaste::Limiter::default()),
            acts: Mutex::new(remotepaste::Limiter::default()),
            pending: Mutex::new(None),
            latest: Mutex::new(0),
            fetch_failed: Mutex::new(String::new()),
            limits: Mutex::new(copies::Limits::load(&cfg.state_dir).unwrap_or_else(|e| {
                log(&format!("cbb: {}; the largest copy is the default", e.for_log()));
                copies::Limits::default()
            })),
            state_dir: cfg.state_dir.clone(),
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
        })
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
            let in_group = on_live::in_group(&self.state_dir);
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

    /// Whether the request h only mutes or unmutes this device itself,
    /// which the service also takes on its control socket from the user at
    /// the screen (or root and the service's own user): it changes nothing
    /// for the rest of the group, and only an admin device may do it
    /// (only an admin's key signs the mute), so the app turns its own device
    /// back on without the administrator's password (docs/design.md,
    /// "Muting a device"). A mute another admin set is not the device's own
    /// matter, to end or to set again: it goes through the confirmation, as
    /// does any request when nothing tells that its user is at the screen.
    fn own_device_op(&self, conn: &UnixStream, h: &Header) -> bool {
        if !control::is_own_device_op(&h.op) || h.device.is_empty() {
            return false;
        }
        if let Some(live) = self.live() {
            let me = crate::roster::id_text(&live.mesh.device());
            if !crate::writers::find(&live.mesh.state(), &h.device).is_ok_and(|d| d.id == live.mesh.device()) {
                return false;
            }
            // On the control socket only an admin mutes itself; a member
            // that is no admin turns its own sync off instead.
            if crate::writers::signer(live.mesh.own(), &live.mesh.state()).is_none() {
                return false;
            }
            if peer::may_take(peer::uid(conn), DESKTOP, peer::at_screen_surely) != peer::Verdict::Allowed {
                return false;
            }
            return crate::mute::by(&self.state_dir, &live.board).is_ok_and(|by| by.is_empty() || by == me);
        }
        false
    }

    /// Carries out an action command from `from`, whose signer `signer`
    /// tells, on the old records or on those of 0.6 alike.
    fn act_from(
        &self,
        from: &Sender,
        body: &crate::records::Command,
        signer: impl FnOnce() -> actions::Signer,
    ) -> wire::CommandResult {
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
                let signer = signer();
                if let Some(why) = actions::check(&set.get(&body.action), &signer) {
                    res.reason = why;
                } else if !self.acts.lock().unwrap().allow(&from.key, uptime::wall_ms()) {
                    res.reason = "too many actions: at most one a second and 30 a minute from one device".into();
                } else {
                    res = self.run_action(body, &set.get(&body.action).command);
                }
            }
        }
        if res.status == "done" {
            (self.log)(&format!("cbb: {} ran the action {} here", from.who(body), body.action));
        } else {
            (self.log)(&format!(
                "cbb: the action {} from {}: {}: {}",
                body.action,
                from.who(body),
                res.status,
                res.reason
            ));
        }
        let e = actions::Entry {
            time_ms: uptime::wall_ms(),
            by: body.by.clone(),
            name: from.name.clone(),
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

    /// cbb action enable and disable: only this device's own user sets its
    /// actions, on the admin socket.
    fn set_action(&self, h: &Header) -> Result<Message> {
        self.group()?;
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
        self.announce_actions();
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
        self.group()?;
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
        self.announce_actions();
        (self.log)(&format!("cbb: the action {} is removed here", h.name));
        Ok(self.action_reply(&set))
    }

    /// Says which quick actions are on in this device's hellos, on the
    /// member that runs.
    fn announce_actions(&self) {
        if let Some(l) = self.live() {
            self.live_hello(&l);
        }
    }

    fn action_reply(&self, set: &actions::Settings) -> Message {
        let status = Status { actions: action_status(set), ..Default::default() };
        control::reply(Header { status: Some(status), ..Default::default() }, Vec::new())
    }

    /// Carries out a paste command from `from` on the old records or on
    /// those of 0.6 alike: `media` pastes a copy of images or files, and
    /// `typed` watches a paste a peripheral types after its answer.
    fn paste_from(
        &self,
        from: &Sender,
        body: &crate::records::Command,
        secrets_stopped: bool,
        media: &dyn Fn(remotepaste::Settings) -> wire::CommandResult,
        typed: &dyn Fn(usize),
    ) -> wire::CommandResult {
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
            Ok(_) if body.paste_kind == "secret" && secrets_stopped => {
                res.reason = "the group's records stop secrets until its root decides (cbb status says why)".into();
            }
            Ok(_) if !self.pastes.lock().unwrap().allow(&from.key, uptime::wall_ms()) => {
                res.reason = "too many pastes: at most one a second and 30 a minute from one device".into();
            }
            Ok(set) if body.paste_kind == "media" => res = media(set),
            Ok(set) => {
                let text = remotepaste::clean(&body.text);
                match (!text.is_empty()).then(|| self.peripherals.paste(&text, set.enter, body.enter)).flatten() {
                    Some((status, reason)) => {
                        (res.status, res.reason) = (status, reason);
                        if res.status == "done" {
                            typed(text.len());
                        }
                    }
                    None => res = self.inject(body, &text, set, &from.name),
                }
            }
        }
        if res.status == "done" && body.paste_kind == "media" {
            (self.log)(&format!("cbb: {} pasted the group's copy {} here", from.who(body), body.text));
        } else if res.status == "done" {
            (self.log)(&format!("cbb: {} pasted {} bytes here", from.who(body), body.text.len()));
        } else {
            (self.log)(&format!("cbb: a paste from {}: {}: {}", from.who(body), res.status, res.reason));
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

    /// The rest of a paste of a copy of images or files, on the old
    /// records or on those of 0.6: the desktop targets that take the
    /// manifest m, the copy fetched (`fetch`), then each target asked in
    /// turn until one pastes it.
    fn inject_copy(
        &self,
        body: &crate::records::Command,
        set: remotepaste::Settings,
        name: &str,
        m: &Manifest,
        mut res: wire::CommandResult,
        fetch: impl FnOnce() -> Result<()>,
    ) -> wire::CommandResult {
        let (targets, text_only) = {
            let ws = self.watchers.lock().unwrap();
            let targets: Vec<(String, Option<peer::Who>, SyncSender<ToWatcher>)> = ws
                .iter()
                .filter(|w| w.target == DESKTOP && w.takes(m))
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
        if let Err(e) = fetch() {
            res.status = "failed".into();
            res.reason = format!("the copy's images or files did not arrive here: {}", e.for_log());
            return res;
        }
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

    /// The status op's answer, with why this device does not sync
    /// (crate::why), which the view carries too.
    fn status(&self) -> Result<Status> {
        if on_live::in_group(&self.state_dir) {
            let live = self.started(|| self.live())?;
            return Ok(self.live_status(&live));
        }
        // A device in no group still answers, with what needs no group: its
        // version, a TV's remote and the keyboard.
        let peripherals = self.peripherals.status();
        let status = Status {
            version: VERSION.into(),
            os: crate::admin::os_name().into(),
            keyboard: peripherals.as_ref().and_then(|p| p.keyboard.clone()),
            tvs: peripherals.map(|p| p.tvs).unwrap_or_default(),
            left_old_group: self.left_old,
            port: self.port.lock().unwrap().map_or(0, i64::from),
            ..Default::default()
        };
        Ok(Status { why: crate::why::reasons(&status, &[], uptime::wall_ms()), ..status })
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
    /// remote paste on here; it turns it off on no
    /// other device.
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
        self.group()?;
        if !h.device.is_empty() || h.all {
            // The group turns it off on other devices (on_live/orders.rs).
            return Err(Error::msg("this device is still starting; try again in a moment"));
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
        if !self.send_writes(|_| Some(w.clone())) {
            *self.pending.lock().unwrap() = Some(w);
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
        // When the connection came, which a confirmation checks the calling
        // process against (confirm::check).
        let accepted = crate::confirm::clock();
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
        // Confirming itself (confirm.rs): the challenge to sign, and on the
        // admin socket a user's key.
        if m.header.op == crate::confirm::OP_CHALLENGE || m.header.op == crate::confirm::OP_REGISTER {
            // A user's key is registered only on the admin socket: no
            // confirmation stands in for it.
            let answer = if admin || m.header.op == crate::confirm::OP_CHALLENGE {
                crate::confirm::answer(&out, &m.header).unwrap_or_else(|e| control::failure(&e))
            } else {
                control::failure(&Error::msg(format!(
                    "{:?} is taken only on the admin socket, which only the administrator reaches",
                    m.header.op
                )))
            };
            let _ = control::write(&mut out, &answer);
            return;
        }
        if control::needs_admin(&m.header)
            && !admin
            && control::is_own_device_op(&m.header.op)
            && self.live().is_some_and(|l| crate::writers::signer(l.mesh.own(), &l.mesh.state()).is_none())
        {
            let _ = control::write(&mut out, &control::failure(&Error::msg(on_live::MUTE_NOT_ADMIN)));
            return;
        }
        if control::needs_admin(&m.header) && !admin && !self.own_device_op(&out, &m.header) {
            // The user at the screen confirms it with the system's prompt
            // instead (confirm.rs), where this system has one, one prompt
            // of a user at a time.
            let user = peer::uid(&out).map(|u| u.to_string()).unwrap_or_default();
            let res = if crate::confirm::supported() {
                self.prompts.begin(&user, Instant::now()).and_then(|()| {
                    let res = crate::confirm::check(&out, &m.header, accepted);
                    self.prompts.end(&user, &res, Instant::now());
                    res
                })
            } else {
                Err(Error::msg(format!(
                    "{:?} changes the group, so the service takes it only on its admin socket, which only the administrator reaches",
                    m.header.op
                )))
            };
            match res {
                Ok(()) => (self.log)(&format!(
                    "cbb: {} confirmed by the user {user} at the screen",
                    crate::confirm::action(&m.header)
                )),
                Err(e) => {
                    let _ = control::write(&mut out, &control::failure(&e));
                    return;
                }
            }
        }
        let broken = self.broken.lock().unwrap().clone();
        if let Some(detail) = broken.filter(|_| m.header.op != control::op::LEAVE) {
            let h = Header { error: BROKEN_LIVE.to_string(), detail, done: true, ..Default::default() };
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
        // A window of 0.6: right after cbb new, the group may still be
        // starting, and the window waits for it as any request does.
        if m.header.op == "pair" && m.header.addrs.is_empty() && m.header.code.is_empty() {
            if let Err(e) = self.started(|| self.live()).and_then(|live| self.live_pair_window(&live, r, &mut out)) {
                (self.log)(&format!("cbb: pair: {}", e.for_log()));
                let _ = control::write(&mut out, &control::failure(&e));
            }
            return;
        }
        // A join of 0.6 is by a home window's six digits or its QR code.
        if m.header.op == "join"
            && (m.header.invite.is_empty() || m.header.invite.trim().starts_with(cbb_core::join::invitation::PREFIX))
            && !m.header.listen
        {
            if let Err(e) = self.live_join(&m, r, &mut out) {
                (self.log)(&format!("cbb: join: {}", e.for_log()));
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
            // An invitation of a group made before 0.6, or a device that
            // waits for the group to dial it: both are gone (D-119, D-126).
            let why = if m.header.listen { on_live::LISTENING_JOINER_GONE } else { crate::OLD_INVITATION };
            let _ = control::write(&mut out, &control::failure(&Error::msg(why)));
            return;
        }
        if m.header.op == "invite" {
            if let Err(e) = self.started(|| self.live()).and_then(|live| self.live_invite(&live, &m, r, &mut out)) {
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
        let limit = self.limits.lock().unwrap().home;
        let live = self.started(|| self.live())?;
        let mut got = copies::receive(r, &m.payload, limit, &self.tmp_dir()?)?;
        let parts = std::mem::take(&mut got.parts);
        live.copy_media(&got.text, parts, Via::Copy, m.header.op == "copy_media")
    }

    /// Answers cbb paste -o and a watcher's fetch: the images or files of
    /// the member's own clipboard, or of the group's copy in a mode that
    /// keeps its clipboard to itself, once fetched; the plain-text
    /// alternative, then each part and its bytes.
    ///
    /// With `copy`, the group's copy of a remote paste that paste_copy
    /// fetched, while it is the current one.
    fn paste_media(&self, out: &mut UnixStream, copy: &str) -> Result<()> {
        let live = self.started(|| self.live())?;
        let from = live.media_to_paste(copy)?;
        let dir = self.tmp_dir()?.join(format!("paste-{}", files::random_name()));
        let max = self.limits.lock().unwrap().home as u64;
        let alt = live
            .board
            .local_media()
            .filter(|l| &l.0 == from.manifest())
            .map(|l| l.1)
            .unwrap_or_else(|| live.board.current().and_then(|c| c.content.text).unwrap_or_default());
        let sent = live.open_media(&from, max, &dir).and_then(|parts| copies::send(out, &alt, &parts));
        let _ = std::fs::remove_dir_all(&dir);
        sent
    }

    /// Takes an archive of the release held from cbb update, which
    /// installed it (Go's receiveReleaseFile): Value its SHA-256 and Part
    /// its size, its bytes in data messages; it must be listed, whole and
    /// match its hash.
    fn receive_release_file(&self, m: &Message, r: &mut control::Reader<UnixStream>) -> Result<()> {
        use std::io::Write;
        let releases = self.releases_here()?;
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
        let sha = sha.to_ascii_lowercase();
        let releases = self.releases_here()?;
        self.started(|| self.live())?.mesh.fetch_release_file(&sha)?;
        let path = releases.path_of(&sha);
        let mut f = std::fs::File::open(&path).context("the file left this device")?;
        let size = releases.held(&sha, uptime::wall_ms()).ok_or_else(|| Error::msg("the file left this device"))?;
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

    /// The signed release this device holds.
    fn releases_here(&self) -> Result<Arc<crate::releases::Releases>> {
        self.started(|| self.live())?.mesh.releases().ok_or_else(|| Error::msg("this device keeps no release"))
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
        // A group of 0.6 that is still starting: a request that needs the
        // group waits for it, as on the old member. One whose files do not
        // open never starts: cbb leave, all it takes, is answered below.
        let starting = self.broken.lock().unwrap().is_none()
            && on_live::in_group(&self.state_dir)
            && !on_live::needs_no_group(&m.header.op);
        let live = match self.live() {
            None if starting => Some(self.started(|| self.live())?),
            l => l,
        };
        if let Some(live) = live
            && let Some(res) = self.live_request(&live, m)
        {
            return res;
        }
        let h = &m.header;
        match h.op.as_str() {
            // Shows this device's settings, or sets the setting name to
            // value: max-copy or max-copy-away.
            "config" => {
                if !h.name.is_empty() {
                    let l = copies::Limits::set(&self.state_dir, &h.name, &h.value)?;
                    *self.limits.lock().unwrap() = l;
                    if let Some(live) = self.live() {
                        live.mesh.set_away_limit(u64::try_from(l.away).unwrap_or(0));
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
            "status" => Ok(control::reply(Header { status: Some(self.status()?), ..Default::default() }, Vec::new())),
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
            "action_remove" => self.remove_action(h),
            // The bug report of the panic before the last restart
            // (docs/core-api.md, "Bug reports"): what the core made of it,
            // the user's Allow (payload `{"always"}`) or Cancel.
            "bug" => {
                let names = self.device_names();
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
                let names = self.device_names();
                self.bugs.allow(always, &names)?;
                Ok(control::reply(Header { done: true, ..Default::default() }, Vec::new()))
            }
            "bug_cancel" => {
                self.bugs.cancel();
                Ok(control::reply(Header { done: true, ..Default::default() }, Vec::new()))
            }
            control::op::NEW => self.new_group(),
            // A damaged group: leaving deletes its files, and the service
            // starts again in no group.
            control::op::LEAVE if self.live().is_none() && !on_live::in_group(&self.state_dir) => {
                Err(Error::msg(crate::leave::NOTHING_TO_LEAVE))
            }
            control::op::LEAVE if self.broken.lock().unwrap().is_some() => {
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
                res.map(|()| control::reply(Header::default(), Vec::new()))
            }
            // The group's operations, out of a group or while its files do
            // not open.
            op if GROUP_OPS.contains(&op) => {
                let live = self.started(|| self.live())?;
                self.live_request(&live, m).unwrap_or_else(|| Err(Error::msg(format!("unknown operation {op:?}"))))
            }
            op => Err(Error::msg(format!("unknown operation {op:?}"))),
        }
    }

    /// The names of the group's devices, which a bug report replaces.
    fn device_names(&self) -> Vec<String> {
        let Some(live) = self.live() else { return Vec::new() };
        self.live_devices(&live).into_iter().map(|d| d.name).filter(|n| !n.is_empty()).collect()
    }

    /// Makes a group with this device as its root (cbb new); the service
    /// then starts in it.
    fn new_group(&self) -> Result<Message> {
        let _one = self.creating.lock().unwrap();
        if self.live().is_some() || on_live::in_group(&self.state_dir) {
            return Err(Error::msg("this device is already in a group; cbb status shows it"));
        }
        crate::admin::keys_allowed()?;
        let me = crate::founding::Me {
            name: &self.name,
            os: cbb_core::format::print::os_number(crate::admin::os_name()),
            caps: crate::roster::caps_number(&self.caps),
        };
        let f = crate::founding::found(&self.state_dir, &me, uptime::wall_ms().max(0) as u64)?;
        let st = f.set.state();
        let tag = crate::live::tag(&st);
        (self.log)(&format!("cbb: created a new group {tag} on the records of 0.6"));
        let status = Status {
            device: st.root_device.as_ref().map(crate::roster::id_text).unwrap_or_default(),
            group: tag,
            role: "member".into(),
            os: crate::admin::os_name().into(),
            version: VERSION.into(),
            key_level: if f.root_held { "hardware" } else { "files" }.into(),
            key_problem: f.key_problem.clone(),
            ..Default::default()
        };
        // The recovery sheet goes to the person who made the group, once:
        // the service keeps no copy.
        let sheet = serde_json::to_vec(&serde_json::json!({ "sheet": &*f.sheet, "qr": &*f.qr }))
            .context("cannot encode the recovery sheet")?;
        Ok(control::reply(Header { status: Some(status), done: true, ..Default::default() }, sheet))
    }

    /// Serves a watcher: what it reports goes to the engine, the writes the
    /// engine decides on go to it, and so do the remote pastes for the
    /// target it offers, each answered with injected.
    fn watch(&self, m: Message, mut r: control::Reader<UnixStream>, mut out: UnixStream) {
        let group = match self.group() {
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
            self.pending.lock().unwrap().take().filter(|w| group.local_text().is_some_and(|t| t == w.text))
        } else {
            None
        };
        if board
            && missed.is_none()
            && let (Ok(text), Ok(kind)) = (String::from_utf8(m.payload), kind_of(&m.header.kind))
        {
            group.clipboard_is(&text, kind);
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
                    if let Err(e) = group.copied(&text, kind, via) {
                        (self.log)(&format!("cbb: a copy from a watcher: {}", e.for_log()));
                    }
                }
                "clipboard" => group.clipboard_is(&text, kind),
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
    /// The sender in the service's log: by, marked when the records do not
    /// show that its device signed.
    fn who(&self, body: &crate::records::Command) -> String {
        if self.verified { body.by.clone() } else { format!("{} (unverified)", body.by) }
    }
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

pub(crate) mod on_live;

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
    use super::{MAX_CONTROL_PER_USER, accept_control};

    /// Without the app a Mac says that it pastes through it; a console its
    /// user did not allow is named as such.
    #[test]
    fn why_nothing_pastes() {
        assert!(super::no_target(false, false, true).contains("a Mac pastes through the CBB app"));
        assert!(super::no_target(true, false, true).contains("did not allow consoles"));
        assert!(super::no_target(false, false, false).contains("nothing on this device can paste"));
        assert!(super::no_target(true, true, false).contains("nothing on this device can paste"));
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
