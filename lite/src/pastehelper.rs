// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The paste targets without a clipboard (docs/design.md, "Remote paste"),
//! as the full member's: cbb paste-helper tmux, which cbb's
//! tmux.conf starts in the background, and cbb paste-helper console, which
//! the cbb-console unit runs as root. Each watches the service's
//! control socket for the target it offers and answers every inject.

use std::io::Write;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use crate::control::{self, Header, Message};
use crate::error::{Context, Error, Result};

/// Why a target did not paste: a refusal, whose reason goes to the sender
/// as it is, or a failure, whose cause goes to the log and the detail.
#[derive(Debug)]
pub enum Fail {
    Refused(String),
    Failed(Error),
}

impl From<Error> for Fail {
    fn from(e: Error) -> Fail {
        Fail::Failed(e)
    }
}

pub(crate) fn refuse<T>(why: impl Into<String>) -> std::result::Result<T, Fail> {
    Err(Fail::Refused(why.into()))
}

/// A paste target.
pub trait Target {
    /// Its name in the watch request: tmux, console or next.
    fn name(&self) -> &'static str;
    /// Puts text where the focus is: pasted or typed, with Enter after it;
    /// no_lock_check lets it paste where nothing tells whether the session
    /// is locked.
    fn inject(&self, text: &str, method: &str, enter: bool, no_lock_check: bool) -> std::result::Result<(), Fail>;
}

const MIN_BACKOFF: Duration = Duration::from_secs(1);
const MAX_BACKOFF: Duration = Duration::from_secs(30);

/// Runs cbb paste-helper: args is tmux or console.
pub fn run(socket: &Path, args: &[String]) -> Result<()> {
    match args {
        [a] if a == "tmux" => run_tmux(socket),
        [a] if a == "console" => run_console(socket),
        _ => Err(Error::msg("usage: cbb paste-helper tmux|console")),
    }
}

/// Keeps a watch on the service for target, connecting again whenever the
/// service goes away.
pub(crate) fn serve(socket: &Path, target: &dyn Target, log: &dyn Fn(&str)) -> ! {
    let mut backoff = MIN_BACKOFF;
    loop {
        let start = std::time::Instant::now();
        let err = match session(socket, target, log) {
            Ok(()) => Error::msg("the service closed the connection"),
            Err(e) => e,
        };
        if start.elapsed() > MAX_BACKOFF {
            backoff = MIN_BACKOFF;
        }
        log(&format!("cbb: the service connection ended: {}; trying again in {:?}", err.for_log(), backoff));
        std::thread::sleep(backoff);
        backoff = (backoff * 2).min(MAX_BACKOFF);
    }
}

fn session(socket: &Path, target: &dyn Target, log: &dyn Fn(&str)) -> Result<()> {
    let conn = UnixStream::connect(socket).context(format!("cannot reach the service at {}", socket.display()))?;
    let mut w = conn.try_clone().context("cannot reach the service")?;
    let watch = Header { op: "watch".into(), inject: target.name().into(), ..Default::default() };
    control::write(&mut w, &Message::new(watch, Vec::new()))?;
    let mut r = control::Reader::new(conn);
    let first = r.read()?.ok_or_else(|| Error::msg("the service closed the connection"))?;
    if !first.header.error.is_empty() {
        return Err(Error::msg(first.header.error));
    }
    log(&format!("cbb: pasting as the {} target", target.name()));
    while let Some(m) = r.read()? {
        if m.header.op != "inject" {
            continue;
        }
        let text = String::from_utf8_lossy(&m.payload);
        let res = target.inject(&text, &m.header.method, m.header.enter, m.header.no_lock_check);
        control::write(&mut w, &Message::new(answer(target.name(), m.header.seq, res, log), Vec::new()))?;
    }
    Ok(())
}

/// The injected answer to the inject seq.
fn answer(target: &str, seq: u64, res: std::result::Result<(), Fail>, log: &dyn Fn(&str)) -> Header {
    let mut h = Header { op: "injected".into(), seq, ..Default::default() };
    match res {
        Ok(()) => {}
        Err(Fail::Refused(why)) => {
            h.error = why;
            h.refused = true;
        }
        Err(Fail::Failed(e)) => {
            log(&format!("cbb: a remote paste failed: {}", e.for_log()));
            h.error = format!("the {target} target could not paste");
            h.detail = e.for_log();
        }
    }
    h
}

/// The tmux helper. One runs for each tmux server, until the server ends;
/// it logs to the user's state directory, since tmux shows a background
/// command's output in a pane.
fn run_tmux(socket: &Path) -> Result<()> {
    let tmux_env = std::env::var("TMUX").unwrap_or_default();
    let sock = tmux_env.split(',').next().unwrap_or_default().to_string();
    if sock.is_empty() {
        return Err(Error::msg("not inside tmux: start it from tmux, as cbb's tmux.conf does"));
    }
    let Some(_lock) = lock_helper(&sock) else {
        return Ok(()); // this server has its helper
    };
    let log_file = state_dir().and_then(|d| LogFile::open(d.join("paste-helper.log")));
    let log = move |s: &str| match &log_file {
        Some(f) => f.line(s),
        None => eprintln!("{s}"),
    };
    // SAFETY: geteuid has no preconditions.
    let tm = Tmux { args: vec!["-S".into(), sock.clone()], console: unsafe { libc::geteuid() } == 0 };
    {
        let tm = Tmux { args: tm.args.clone(), console: tm.console };
        std::thread::spawn(move || {
            loop {
                std::thread::sleep(Duration::from_secs(15));
                if !tm.alive() {
                    std::process::exit(0);
                }
            }
        });
    }
    log(&format!("cbb: pasting into tmux at {sock} as the {} target", tm.name()));
    serve(socket, &tm, &log)
}

/// The user's directory for cbb's own files, made if missing.
fn state_dir() -> Option<PathBuf> {
    let base = match std::env::var_os("XDG_STATE_HOME") {
        Some(d) if !d.is_empty() => PathBuf::from(d),
        _ => PathBuf::from(std::env::var_os("HOME")?).join(".local").join("state"),
    };
    let dir = base.join("cbb");
    use std::os::unix::fs::DirBuilderExt;
    std::fs::DirBuilder::new().recursive(true).mode(0o700).create(&dir).ok()?;
    Some(dir)
}

/// Whether this is the only helper of the tmux server at sock, since tmux
/// runs the config again on every source-file: Some while it holds the
/// lock, which lasts as long as the file stays open. Without a lock file,
/// running twice beats not running.
fn lock_helper(sock: &str) -> Option<Option<std::fs::File>> {
    let dir = match std::env::var_os("XDG_RUNTIME_DIR") {
        Some(d) if !d.is_empty() => PathBuf::from(d),
        _ => Path::new(sock).parent().map(Path::to_path_buf).unwrap_or_default(),
    };
    // Named as the Go helper names it, so that the two see one lock.
    let sum = cbb_core::certs::sha256(sock.as_bytes());
    let path = dir.join(format!("cbb-tmux-{}.lock", hex8(&sum)));
    use std::os::unix::fs::OpenOptionsExt;
    use std::os::unix::io::AsRawFd;
    let Ok(f) = std::fs::OpenOptions::new().read(true).write(true).create(true).truncate(false).mode(0o600).open(path)
    else {
        return Some(None);
    };
    // SAFETY: flock on a descriptor this function owns.
    if unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        let busy = std::io::Error::last_os_error().raw_os_error() == Some(libc::EWOULDBLOCK);
        return if busy { None } else { Some(None) };
    }
    Some(Some(f))
}

/// The first 8 bytes of sum in hex.
fn hex8(sum: &[u8; 32]) -> String {
    sum[..8].iter().map(|b| format!("{b:02x}")).collect()
}

/// The largest the helper's log grows before it starts again, keeping the
/// last one beside it, as the Go helper's.
const MAX_LOG: u64 = 1 << 20;

/// The helper's log: only the user's (0600), and bounded.
struct LogFile {
    path: PathBuf,
    f: std::sync::Mutex<(std::fs::File, u64)>,
}

impl LogFile {
    fn open(path: PathBuf) -> Option<LogFile> {
        let f = Self::file(&path)?;
        Some(LogFile { path, f: std::sync::Mutex::new(f) })
    }

    fn file(path: &Path) -> Option<(std::fs::File, u64)> {
        use std::os::unix::fs::OpenOptionsExt;
        let f = std::fs::OpenOptions::new().create(true).append(true).mode(0o600).open(path).ok()?;
        let size = f.metadata().ok()?.len();
        Some((f, size))
    }

    fn line(&self, s: &str) {
        let mut g = self.f.lock().unwrap();
        if g.1 >= MAX_LOG {
            let old = self.path.with_extension("log.1");
            let _ = std::fs::rename(&self.path, old);
            match Self::file(&self.path) {
                Some(f) => *g = f,
                None => return,
            }
        }
        let line = format!("{s}\n");
        if g.0.write_all(line.as_bytes()).is_ok() {
            g.1 += line.len() as u64;
        }
    }
}

/// Pastes into a tmux server: into the active pane of the client the user
/// used last, as tmux's own paste-buffer puts it there, bracketed when the
/// program asked for it; typing sends the keys literally. With no client
/// attached, or the client locked, it refuses.
pub struct Tmux {
    /// Go before each tmux command, such as -S and the socket.
    pub args: Vec<String>,
    /// Offer the target as console: the tmux of root, whose keys may run
    /// anything, is held to the console's rule.
    pub console: bool,
}

/// The paste buffer it loads, deleted by the paste.
const BUFFER: &str = "cbb-remote";

impl Target for Tmux {
    fn name(&self) -> &'static str {
        if self.console { "console" } else { "tmux" }
    }

    fn inject(&self, text: &str, method: &str, enter: bool, _no_lock_check: bool) -> std::result::Result<(), Fail> {
        let pane = pane(&self.output(&["list-clients", "-F", "#{client_activity} #{client_flags} #{pane_id}"])?)?;
        match method {
            "paste" => {
                self.run(text, &["load-buffer", "-b", BUFFER, "-"])?;
                if let Err(e) = self.run("", &["paste-buffer", "-p", "-d", "-b", BUFFER, "-t", &pane]) {
                    let _ = self.run("", &["delete-buffer", "-b", BUFFER]);
                    return Err(e.into());
                }
            }
            // The keys go on standard input, as tmux commands, never in the
            // arguments, which any user here can read.
            "type" => self.run(&type_script(&pane, text), &["source-file", "-"])?,
            m => return refuse(format!("tmux pastes or types, not {m:?}")),
        }
        if enter {
            self.run("", &["send-keys", "-t", &pane, "Enter"])?;
        }
        Ok(())
    }
}

impl Tmux {
    /// Whether the tmux server still runs.
    fn alive(&self) -> bool {
        self.output(&["list-sessions", "-F", "#{session_id}"]).is_ok()
    }

    fn command(&self, args: &[&str]) -> Command {
        let mut c = Command::new("tmux");
        c.args(&self.args).args(args);
        c
    }

    fn output(&self, args: &[&str]) -> Result<String> {
        let out = self.command(args).stdin(Stdio::null()).output().context("cannot run tmux")?;
        if !out.status.success() {
            return Err(Error::msg(format!(
                "tmux {}: {}: {}",
                args[0],
                out.status,
                String::from_utf8_lossy(&out.stderr).trim()
            )));
        }
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    }

    fn run(&self, stdin: &str, args: &[&str]) -> Result<()> {
        let mut child = self
            .command(args)
            .stdin(if stdin.is_empty() { Stdio::null() } else { Stdio::piped() })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .context("cannot run tmux")?;
        if let Some(mut w) = child.stdin.take() {
            w.write_all(stdin.as_bytes()).context(format!("tmux {}", args[0]))?;
        }
        let out = child.wait_with_output().context(format!("tmux {}", args[0]))?;
        if !out.status.success() {
            let mut msg = String::from_utf8_lossy(&out.stderr).into_owned();
            msg.push_str(&String::from_utf8_lossy(&out.stdout));
            return Err(Error::msg(format!("tmux {}: {}: {}", args[0], out.status, msg.trim())));
        }
        Ok(())
    }
}

/// The active pane of the attached client with the latest activity, from
/// tmux list-clients.
fn pane(clients: &str) -> std::result::Result<String, Fail> {
    let mut best: i64 = -1;
    let (mut pane, mut locked) = (String::new(), false);
    for line in clients.lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() != 3 {
            continue;
        }
        let at = f[0].parse().unwrap_or(0);
        if at > best {
            best = at;
            pane = f[2].to_string();
            locked = f[1].split(',').any(|x| x == "suspended");
        }
    }
    if pane.is_empty() {
        return refuse("no one is attached to tmux here");
    }
    if locked {
        return refuse("the tmux client is locked");
    }
    Ok(pane)
}

/// The tmux commands that type text into pane: each line sent literally,
/// and Enter for each line break.
fn type_script(pane: &str, text: &str) -> String {
    let mut b = String::new();
    for (i, line) in text.split('\n').enumerate() {
        if i > 0 {
            b.push_str(&format!("send-keys -t {pane} Enter\n"));
        }
        if !line.is_empty() {
            b.push_str(&format!("send-keys -l -t {pane} -- {}\n", quote(line)));
        }
    }
    b
}

/// Quotes s for tmux's command parser: in single quotes, which take
/// everything literally, with each single quote in double quotes.
fn quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', r#"'"'"'"#))
}

/// The console helper, as root.
fn run_console(socket: &Path) -> Result<()> {
    // SAFETY: geteuid has no preconditions.
    if unsafe { libc::geteuid() } != 0 {
        return Err(Error::msg("the console helper runs as root, from the cbb-console unit"));
    }
    let log = |s: &str| eprintln!("{s}");
    log("cbb: pasting into the active text console");
    serve(socket, &Console, &log)
}

/// Types into the active virtual console with TIOCSTI, as if typed there,
/// which works also where the kernel turns unprivileged TIOCSTI off. It
/// pastes only into a text console that a user logged in on, never into a
/// login prompt, a graphical session's console or a locked one.
pub struct Console;

/// Lockers that run only while they lock, for those that do not tell
/// logind, the same as internal/lockcheck's: KDE's greeter is the only sign
/// of its lock screen on FreeBSD.
const LOCKERS: &[&str] = &[
    "swaylock",
    "hyprlock",
    "waylock",
    "gtklock",
    "i3lock",
    "slock",
    "xsecurelock",
    "physlock",
    "vlock",
    "kscreenlocker_greet",
];

impl Target for Console {
    fn name(&self) -> &'static str {
        "console"
    }

    fn inject(&self, text: &str, method: &str, enter: bool, no_lock_check: bool) -> std::result::Result<(), Fail> {
        if method != "paste" && method != "type" {
            return refuse(format!("the console pastes or types, not {method:?}"));
        }
        let Ok(active) = std::fs::read_to_string("/sys/class/tty/tty0/active") else {
            return refuse("this computer has no virtual console");
        };
        let tty = active.trim();
        if let Some(name) = locker() {
            return refuse(format!("the console is locked ({name} runs)"));
        }
        match session_on(tty) {
            Err(e) => return refuse(format!("cannot tell who is logged in on the console: {}", e.message())),
            Ok(None) => return refuse("no one is logged in on the active console"),
            Ok(Some(id)) => {
                let hint = loginctl(&["show-session", &id, "-p", "LockedHint", "--value"]);
                if let Some(why) = lock_refusal(hint.as_deref().ok(), no_lock_check) {
                    return refuse(why);
                }
            }
        }
        type_into(tty, &console_bytes(text, enter))
    }
}

/// The reason a target gives when nothing tells whether the session is
/// locked and its user did not allow pastes without the check, as Go's
/// lockcheck.Unknown.
const UNKNOWN_LOCK: &str = "this device cannot tell whether its session is locked, as logind does not say, so it takes no remote paste; its user may allow pastes without that check with cbb paste-receive on -no-lock-check";

/// Why a session whose LockedHint logind gave as hint (None when loginctl
/// failed) takes no paste: it is locked, or logind did not say yes or no
/// and no_lock_check does not let the paste go on then.
fn lock_refusal(hint: Option<&str>, no_lock_check: bool) -> Option<&'static str> {
    match hint.map(str::trim) {
        Some("yes") => Some("the console's session is locked"),
        Some("no") => None,
        _ if no_lock_check => None,
        _ => Some(UNKNOWN_LOCK),
    }
}

/// What goes into the console: a carriage return for each line break and
/// for Enter, since a console has no clipboard to paste from.
fn console_bytes(text: &str, enter: bool) -> Vec<u8> {
    let mut b = text.replace('\n', "\r").into_bytes();
    if enter {
        b.push(b'\r');
    }
    b
}

#[cfg(target_os = "linux")]
fn type_into(tty: &str, input: &[u8]) -> std::result::Result<(), Fail> {
    use std::os::unix::fs::OpenOptionsExt;
    use std::os::unix::io::AsRawFd;
    const KDGETMODE: libc::c_ulong = 0x4b3b; // KD_TEXT is 0
    let f = std::fs::OpenOptions::new()
        .write(true)
        .custom_flags(libc::O_NOCTTY)
        .open(format!("/dev/{tty}"))
        .context(format!("cannot open /dev/{tty}"))?;
    let mut mode: libc::c_int = 0;
    // SAFETY: KDGETMODE writes one int.
    if unsafe { libc::ioctl(f.as_raw_fd(), KDGETMODE as _, &mut mode) } != 0 {
        return Err(Error::with(format!("reading the mode of {tty}"), std::io::Error::last_os_error()).into());
    }
    if mode != 0 {
        return refuse("the active console shows a graphical session");
    }
    for b in input {
        // SAFETY: TIOCSTI reads one byte.
        if unsafe { libc::ioctl(f.as_raw_fd(), libc::TIOCSTI as _, b as *const u8) } != 0 {
            return Err(Error::with(format!("typing into {tty}"), std::io::Error::last_os_error()).into());
        }
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn type_into(_: &str, _: &[u8]) -> std::result::Result<(), Fail> {
    refuse("the console helper is for the Linux text console")
}

/// The name of a locker that runs, as any user.
fn locker() -> Option<String> {
    for e in std::fs::read_dir("/proc").ok()?.flatten() {
        if !e.file_name().to_string_lossy().bytes().all(|c| c.is_ascii_digit()) {
            continue;
        }
        if let Ok(comm) = std::fs::read_to_string(e.path().join("comm"))
            && LOCKERS.contains(&comm.trim())
        {
            return Some(comm.trim().to_string());
        }
    }
    None
}

/// logind's active text session on tty.
fn session_on(tty: &str) -> Result<Option<String>> {
    let list = loginctl(&["list-sessions", "--no-legend"])?;
    for id in list.lines().filter_map(|l| l.split_whitespace().next()) {
        let props = loginctl(&["show-session", id, "-p", "TTY", "-p", "Type", "-p", "Active"]).unwrap_or_default();
        let has = |kv: &str| props.lines().any(|l| l.trim() == kv);
        if has(&format!("TTY={tty}")) && has("Type=tty") && has("Active=yes") {
            return Ok(Some(id.to_string()));
        }
    }
    Ok(None)
}

fn loginctl(args: &[&str]) -> Result<String> {
    let out = Command::new("loginctl").args(args).stdin(Stdio::null()).output().context("cannot run loginctl")?;
    if !out.status.success() {
        return Err(Error::msg(format!("loginctl {}: {}", args[0], String::from_utf8_lossy(&out.stderr).trim())));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A console pastes only where logind says its session is not locked,
    /// unless its user allowed pastes without the check.
    #[test]
    fn unknown_lock_state() {
        for (hint, want, without) in [
            (Some("yes\n"), Some("the console's session is locked"), Some("the console's session is locked")),
            (Some("no\n"), None, None),
            (Some(""), Some(UNKNOWN_LOCK), None),
            (Some("maybe"), Some(UNKNOWN_LOCK), None),
            (None, Some(UNKNOWN_LOCK), None),
        ] {
            assert_eq!(lock_refusal(hint, false), want, "{hint:?}");
            assert_eq!(lock_refusal(hint, true), without, "{hint:?}, without the check");
        }
    }

    #[test]
    fn helper_files_match_go() {
        // The lock is named as cmd/cbb's lockHelper names it.
        assert_eq!(hex8(&cbb_core::certs::sha256(b"/tmp/tmux-1000/default")), "7cbd633a2afc14ea");
        // The log is the user's alone and starts again past MAX_LOG.
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("cbb-helper-log-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("paste-helper.log");
        let log = LogFile::open(path.clone()).unwrap();
        assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        let line = "x".repeat(1000);
        for _ in 0..(MAX_LOG / 1000 + 2) {
            log.line(&line);
        }
        assert!(std::fs::metadata(&path).unwrap().len() < MAX_LOG);
        assert!(std::fs::metadata(dir.join("paste-helper.log.1")).unwrap().len() >= MAX_LOG);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn types_into_tmux_literally() {
        assert_eq!(
            type_script("%3", "echo 'hi'\n\nls"),
            "send-keys -l -t %3 -- 'echo '\"'\"'hi'\"'\"''\nsend-keys -t %3 Enter\nsend-keys -t %3 Enter\nsend-keys -l -t %3 -- 'ls'\n"
        );
    }

    #[test]
    fn picks_the_pane_used_last() {
        let out = "100 attached,focused %1\n300 attached,focused %7\n200 attached %2\n";
        assert_eq!(pane(out).unwrap(), "%7");
        assert!(matches!(pane(""), Err(Fail::Refused(r)) if r == "no one is attached to tmux here"));
        assert!(matches!(pane("5 attached,suspended %1\n"), Err(Fail::Refused(r)) if r == "the tmux client is locked"));
    }

    #[test]
    fn answers_as_a_full_member() {
        let quiet = |_: &str| {};
        let h = answer("tmux", 4, Ok(()), &quiet);
        assert_eq!((h.op.as_str(), h.seq, h.error.as_str(), h.refused), ("injected", 4, "", false));
        let h = answer("tmux", 5, Err(Fail::Refused("the tmux client is locked".into())), &quiet);
        assert_eq!((h.error.as_str(), h.refused, h.detail.as_str()), ("the tmux client is locked", true, ""));
        let h = answer("console", 6, Err(Fail::Failed(Error::msg("typing into tty2"))), &quiet);
        assert_eq!(
            (h.error.as_str(), h.refused, h.detail.as_str()),
            ("the console target could not paste", false, "typing into tty2")
        );
    }

    #[test]
    fn console_gets_carriage_returns() {
        assert_eq!(console_bytes("a\nb", true), b"a\rb\r");
        assert_eq!(console_bytes("ls", false), b"ls");
    }
}
