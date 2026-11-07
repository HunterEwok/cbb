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
use crate::clip::{Engine, Kind, Mode, Via};
use crate::control::{self, Device, Header, Message, Status};
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
use crate::wire;

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
    tx: SyncSender<ToWatcher>,
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
    state_dir: PathBuf,
    /// The replay cache: the IDs of the commands carried out, until they
    /// expire, in milliseconds since the Unix epoch.
    commands: Mutex<HashMap<String, i64>>,
    /// When the service started: the replay cache starts empty, so a
    /// command signed before is refused.
    started_ms: i64,
    log: Arc<dyn Fn(&str) + Send + Sync>,
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
        state_dir: cfg.state_dir.clone(),
        commands: Mutex::new(HashMap::new()),
        started_ms: uptime::wall_ms(),
        log: log.clone(),
    });
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
    let node = {
        let svc = svc.clone();
        Arc::new(Node::new(
            ident,
            &cfg.name,
            engine.clone(),
            records,
            cfg.state_dir.clone(),
            Box::new(move |w| svc.deliver(w)),
            log.clone(),
        ))
    };
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
    *svc.node.write().unwrap() = Some(node.clone());
    *svc.away.write().unwrap() = Some(away.clone());
    let port = cfg.port.and_then(|p| discovery::listen(node.clone(), p, log.clone()));
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
        // Of images or files a lite member has only their text.
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
            "off" => {
                away.turn_off()?;
                node.set_tunnel_key(None);
            }
            "hub" | "relay" => {
                return Err(Error::msg(
                    "the lite member is a client of the group's hub; make a full member the hub, or meet at a relay, there",
                ));
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
            wire::CommandResult { id: id.to_string(), by: String::new(), status: "refused".into(), reason: why }
        };
        let node = match self.node() {
            Ok(n) => n,
            Err(e) => return refused("", e.message().to_string()),
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
            Err(e) => return refused("", e.message().to_string()),
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
            "hub" => return refused(&body.id, "the lite member is never the group's hub".into()),
            "paste" => return self.pasted(&node, c, body),
            "action" => return self.act(&node, c, body),
            "actions-off" => {
                let mut res = wire::CommandResult {
                    id: body.id.clone(),
                    by: String::new(),
                    status: "done".into(),
                    reason: String::new(),
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
            };
        }
        (self.log)(&format!("cbb: {} turned sync {} here", body.by, if body.mode == "own" { "off" } else { "on" }));
        wire::CommandResult { id: body.id, by: String::new(), status: "done".into(), reason: String::new() }
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
    fn deliver(&self, w: WriteReq) {
        let mut ws = self.watchers.lock().unwrap();
        let mut got = false;
        ws.retain(|x| {
            if !x.board {
                return true;
            }
            match x.tx.try_send(ToWatcher::Write(w.clone())) {
                Err(mpsc::TrySendError::Disconnected(_)) => false,
                _ => {
                    got = true;
                    true
                }
            }
        });
        if !got {
            *self.pending.lock().unwrap() = Some(w);
        }
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
        let answer = match self.request(&m) {
            Ok(a) => a,
            Err(e) => {
                (self.log)(&format!("cbb: {}: {}", m.header.op, e.for_log()));
                control::failure(&e)
            }
        };
        let _ = control::write(&mut out, &answer);
    }

    fn request(&self, m: &Message) -> Result<Message> {
        let h = &m.header;
        match h.op.as_str() {
            "copy" => {
                let text = String::from_utf8(m.payload.clone()).context("the text is not UTF-8")?;
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
                let (text, kind, _) = got.ok_or_else(|| Error::msg("the clipboard is empty"))?;
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
                    role: "lite".into(),
                    os: "linux".into(),
                    peers,
                    version: VERSION.into(),
                    mode: node.engine.mode().name().into(),
                    muted: node.engine.mute_left().is_some(),
                    muted_until_ms: node.engine.mute_left().filter(|l| *l > 0).map_or(0, |l| uptime::wall_ms() + l),
                    sync_until_ms: node.engine.sync().1,
                    away: self.away()?.status(&node),
                    paste: self.paste_status(),
                    actions: action_status(&actions::load(&self.state_dir).unwrap_or_default()),
                    stop: node.stop(),
                    removed: node.removed(),
                };
                Ok(control::reply(Header { status: Some(status), ..Default::default() }, Vec::new()))
            }
            "devices" => {
                let node = self.node()?;
                let me = node.identity().id.to_string();
                let peers = node.peers();
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
            "mute" | "unmute" => Err(Error::msg(
                "only an admin mutes a device or ends its mute; the lite member is never one: use the phone app or a full member; cbb sync off turns this device's own sync off",
            )),
            "sync" => {
                if !h.device.is_empty() {
                    return Err(Error::msg(
                        "only an admin turns another device's sync on or off; the lite member is never one: use the phone app or a full member",
                    ));
                }
                let on = crate::sync::parse(&h.name)?;
                if on && h.for_ms != 0 {
                    return Err(Error::msg("a time goes only with cbb sync off"));
                }
                self.set_sync(on, h.for_ms)?;
                Ok(control::reply(Header::default(), Vec::new()))
            }
            "pair" | "pair-phone" | "revoke" => {
                Err(Error::msg("a lite member admits and removes no devices; use the phone app or a Linux member"))
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
        self.watchers.lock().unwrap().push(Watcher { id, target: target.clone(), board, uid, tx });
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
                                kind: kind_name(w.kind).into(),
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
