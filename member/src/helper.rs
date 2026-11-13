// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The helper channel (docs/design.md, "The service and its helper"): what
//! needs Go runs in cbb-helper, which cbb starts as its child and talks to
//! over the child's standard input and output only, the pipes it inherits.
//! No socket has a name, so no other process can ask the helper for
//! anything. The messages are the control socket's (control.rs); a request
//! carries a seq of cbb's own, and the helper's answer the same seq.
//!
//! A member without the helper beside it, as on a router, runs without what
//! it does. If the helper stops, the next request starts it again, at most
//! once in RESTART_AFTER.
//!
//! The helper may sign with the device's keys, so cbb trusts it no less
//! than itself and checks that much before it starts it: on Unix its file
//! and its directory belong to root, to this process's user or to the
//! owner of cbb's own program, and nobody else may write to them. It starts
//! with only the environment it needs (KEPT_ENV), and a release of cbb
//! takes only the helper of the same release.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::Deserialize;

use crate::control::{self, Header, Message};
use crate::error::{Context, Error, Result};

/// The helper's program name, beside cbb.
pub const PROGRAM: &str = "cbb-helper";

/// How long after a start a stopped helper waits before the next.
const RESTART_AFTER: Duration = Duration::from_secs(2);

/// How long the helper may take to say hello.
const HELLO_TIMEOUT: Duration = Duration::from_secs(10);

/// The variables of cbb's environment the helper gets, besides every one
/// that starts with CBB_: what Go, the TPM, PC/SC, D-Bus and Windows need.
/// Names compare without case, as Windows does.
const KEPT_ENV: &[&str] = &[
    "PATH",
    "HOME",
    "USER",
    "LOGNAME",
    "LANG",
    "LC_ALL",
    "TMPDIR",
    "TMP",
    "TEMP",
    "XDG_RUNTIME_DIR",
    "DBUS_SYSTEM_BUS_ADDRESS",
    "PCSCLITE_CSOCK_NAME",
    "SYSTEMROOT",
    "WINDIR",
    "PROGRAMDATA",
    "PROGRAMFILES",
    "LOCALAPPDATA",
    "APPDATA",
    "USERPROFILE",
    "COMPUTERNAME",
];

/// What the helper says it is, the answer to hello.
#[derive(Deserialize, Debug, Clone, Default)]
pub struct Hello {
    pub version: String,
    #[serde(default)]
    pub ops: Vec<String>,
}

/// The waiting requests, by seq.
type Waiting = Arc<Mutex<HashMap<u64, mpsc::Sender<Message>>>>;

/// The helper, started when first needed.
pub struct Helper {
    path: PathBuf,
    log: Arc<dyn Fn(&str) + Send + Sync>,
    state: Mutex<State>,
    /// Whether it gets cbb's whole environment: the agent's helper, which
    /// needs the session's display and buses.
    whole_env: bool,
}

#[derive(Default)]
struct State {
    running: Option<Running>,
    next_seq: u64,
    started: Option<Instant>,
}

struct Running {
    child: Child,
    stdin: ChildStdin,
    waiting: Waiting,
    hello: Hello,
}

impl Running {
    /// Whether the helper's process still runs.
    fn alive(&mut self) -> bool {
        matches!(self.child.try_wait(), Ok(None))
    }
}

/// The underlying error the helper reported, kept as the details.
#[derive(Debug)]
struct Remote(String);

impl std::fmt::Display for Remote {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Remote {}

/// Where the helper is: in a build with the test hooks CBB_HELPER if set
/// (empty for none), else cbb-helper beside this program, if it is there.
pub fn locate() -> Option<PathBuf> {
    if let Some(p) = crate::testhooks::var_os("CBB_HELPER") {
        return if p.is_empty() { None } else { Some(PathBuf::from(p)) };
    }
    let exe = std::env::current_exe().ok()?;
    let p = exe.with_file_name(format!("{PROGRAM}{}", std::env::consts::EXE_SUFFIX));
    p.is_file().then_some(p)
}

/// This process's helper, made at its first use from [`locate`] and logging
/// to standard error; None without one. It starts when first asked.
pub fn shared() -> Option<Arc<Helper>> {
    static SHARED: std::sync::OnceLock<Option<Arc<Helper>>> = std::sync::OnceLock::new();
    SHARED.get_or_init(|| locate().map(|p| Arc::new(Helper::new(&p, Arc::new(crate::service::log_line))))).clone()
}

impl Helper {
    /// A helper at path, not yet started; log takes its stops and starts.
    pub fn new(path: &Path, log: Arc<dyn Fn(&str) + Send + Sync>) -> Helper {
        Helper { path: path.to_path_buf(), log, state: Mutex::new(State::default()), whole_env: false }
    }

    /// The helper of cbb agent, which runs as the session's user and gets
    /// the whole environment of the session: its display, D-Bus and the
    /// like.
    pub fn for_agent(path: &Path, log: Arc<dyn Fn(&str) + Send + Sync>) -> Helper {
        Helper { path: path.to_path_buf(), log, state: Mutex::new(State::default()), whole_env: true }
    }

    /// Starts the helper if it does not run, and returns its hello.
    pub fn hello(&self) -> Result<Hello> {
        let mut st = self.state.lock().unwrap_or_else(|e| e.into_inner());
        self.ensure(&mut st)?;
        Ok(st.running.as_ref().map(|r| r.hello.clone()).unwrap_or_default())
    }

    /// Sends a request, its op in header, and waits up to timeout for the
    /// answer. A failure the helper reports is an error with its causes as
    /// the details.
    pub fn call(&self, header: Header, payload: Vec<u8>, timeout: Duration) -> Result<Message> {
        let w = {
            let mut st = self.state.lock().unwrap_or_else(|e| e.into_inner());
            self.ensure(&mut st)?;
            self.send(&mut st, header, payload)?
        };
        let op_err = |m: &str| Error::msg(format!("{PROGRAM}: {m}"));
        let ans = match w.rx.recv_timeout(timeout) {
            Ok(m) => m,
            Err(mpsc::RecvTimeoutError::Timeout) => {
                // A late answer then finds nothing waiting, and is logged.
                w.waiting.lock().unwrap_or_else(|e| e.into_inner()).remove(&w.seq);
                return Err(op_err("no answer in time"));
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => return Err(op_err("it stopped before it answered")),
        };
        if !ans.header.error.is_empty() {
            // The detail is the helper's whole error, which the Go service
            // shows as it is, as a TV's name before what the TV said; the
            // short error drops what it wrapped.
            let h = &ans.header;
            return Err(if h.detail.is_empty() {
                Error::msg(h.error.clone())
            } else if h.detail.starts_with(&h.error) {
                Error::msg(h.detail.clone())
            } else {
                Error::with(h.error.clone(), Remote(h.detail.clone()))
            });
        }
        Ok(ans)
    }

    /// Writes a request on the channel and returns where its answer comes.
    fn send(&self, st: &mut State, mut header: Header, payload: Vec<u8>) -> Result<Wait> {
        st.next_seq += 1;
        header.seq = st.next_seq;
        let Some(r) = st.running.as_mut() else { return Err(Error::msg(format!("{PROGRAM} does not run"))) };
        let (tx, rx) = mpsc::channel();
        let seq = header.seq;
        r.waiting.lock().unwrap_or_else(|e| e.into_inner()).insert(seq, tx);
        if let Err(e) = control::write(&mut r.stdin, &Message::new(header, payload)) {
            self.stop(st);
            return Err(e.context(format!("{PROGRAM} stopped")));
        }
        Ok(Wait { rx, seq, waiting: Arc::clone(&r.waiting) })
    }

    /// Starts the helper unless it runs, at most once in RESTART_AFTER.
    fn ensure(&self, st: &mut State) -> Result<()> {
        if let Some(r) = st.running.as_mut() {
            if r.alive() {
                return Ok(());
            }
            let status = r.child.wait().map(|s| s.to_string()).unwrap_or_else(|e| e.to_string());
            (self.log)(&format!("cbb: {PROGRAM} stopped ({status})"));
            st.running = None;
        }
        if st.started.is_some_and(|t| t.elapsed() < RESTART_AFTER) {
            return Err(Error::msg(format!("{PROGRAM} stopped; it starts again in a moment")));
        }
        st.started = Some(Instant::now());
        let path = trusted(&self.path)?;
        let mut cmd = Command::new(&path);
        cmd.env_clear()
            .envs(std::env::vars_os().filter(|(k, _)| self.whole_env || kept(k)))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            // Its log goes where cbb's goes.
            .stderr(Stdio::inherit());
        // Started by cbbw.exe, which has no console, the helper would open
        // a console window of its own.
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            const CREATE_NO_WINDOW: u32 = 0x0800_0000;
            cmd.creation_flags(CREATE_NO_WINDOW);
        }
        let mut child = cmd.spawn().context(format!("cannot start {}", path.display()))?;
        let (Some(stdin), Some(stdout)) = (child.stdin.take(), child.stdout.take()) else {
            let _ = child.kill();
            let _ = child.wait();
            return Err(Error::msg(format!("{PROGRAM} started without its pipes")));
        };
        let waiting: Waiting = Arc::default();
        let w = Arc::clone(&waiting);
        let log = Arc::clone(&self.log);
        std::thread::spawn(move || read_answers(stdout, w, log));
        st.running = Some(Running { child, stdin, waiting, hello: Hello::default() });
        let rx = self.send(st, Header { op: "hello".into(), ..Default::default() }, Vec::new())?;
        let ans = rx.rx.recv_timeout(HELLO_TIMEOUT).map_err(|_| {
            self.stop(st);
            Error::msg(format!("{PROGRAM} did not say hello"))
        })?;
        let hello: Hello = serde_json::from_slice(&ans.payload).map_err(|e| {
            self.stop(st);
            Error::with(format!("{PROGRAM} said hello in a form cbb does not read"), e)
        })?;
        if !same_release(crate::service::VERSION, &hello.version) {
            self.stop(st);
            return Err(Error::msg(format!(
                "{PROGRAM} is {}, not of this release of cbb ({}): install both again",
                hello.version,
                crate::service::VERSION
            )));
        }
        (self.log)(&format!("cbb: {PROGRAM} runs: {} ({})", hello.version, hello.ops.join(", ")));
        if let Some(r) = st.running.as_mut() {
            r.hello = hello;
        }
        Ok(())
    }

    /// Stops the helper: the end of its input tells it to exit.
    fn stop(&self, st: &mut State) {
        if let Some(r) = st.running.take() {
            let Running { mut child, stdin, .. } = r;
            drop(stdin);
            let deadline = Instant::now() + Duration::from_secs(2);
            while matches!(child.try_wait(), Ok(None)) && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(20));
            }
            if matches!(child.try_wait(), Ok(None)) {
                let _ = child.kill();
            }
            // Logged here too: a helper that died as cbb wrote to it ends
            // here, not in ensure.
            let status = child.wait().map(|s| s.to_string()).unwrap_or_else(|e| e.to_string());
            (self.log)(&format!("cbb: {PROGRAM} stopped ({status})"));
        }
    }
}

/// Where a request's answer comes: rx, unless the request is taken out of
/// waiting by its seq.
struct Wait {
    rx: mpsc::Receiver<Message>,
    seq: u64,
    waiting: Waiting,
}

/// Whether the variable name goes into the helper's environment.
fn kept(name: &std::ffi::OsStr) -> bool {
    let Some(name) = name.to_str() else { return false };
    name.get(..4).is_some_and(|p| p.eq_ignore_ascii_case("CBB_"))
        || KEPT_ENV.iter().any(|k| k.eq_ignore_ascii_case(name))
}

/// Whether a helper that says it is helper (Go's version.String, "cbb
/// v0.6.0 linux/amd64") may serve cbb of release ours: any helper serves a
/// build that is not a release, and a release only its own.
fn same_release(ours: &str, helper: &str) -> bool {
    ours == "dev" || helper.split(' ').nth(1).map(|v| v.strip_prefix('v').unwrap_or(v)) == Some(ours)
}

/// The helper's program, its links followed, if cbb may start it: on Unix
/// it and its directory belong to root, to this process's user or to the
/// owner of cbb's own program, and neither its group nor others may write
/// to them, so no other user can put a program there. Elsewhere the
/// installer's folder rights stand for it (Program Files on Windows).
fn trusted(path: &Path) -> Result<PathBuf> {
    let real = std::fs::canonicalize(path).context(format!("cannot find {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let exe = std::env::current_exe().ok().and_then(|e| std::fs::canonicalize(e).ok());
        let exe_owner = exe.as_deref().and_then(|e| std::fs::metadata(e).ok()).map(|m| m.uid());
        // SAFETY: geteuid has no preconditions.
        let euid = unsafe { libc::geteuid() };
        let check = |p: &Path, what: &str| -> Result<()> {
            let m = std::fs::metadata(p).context(format!("cannot read {}", p.display()))?;
            let uid = m.uid();
            if uid != 0 && uid != euid && Some(uid) != exe_owner {
                return Err(Error::msg(format!(
                    "cbb does not start {}: {what} belongs to user {uid}, not to root or cbb's user",
                    real.display()
                )));
            }
            if m.mode() & 0o022 != 0 {
                return Err(Error::msg(format!(
                    "cbb does not start {}: others may write to {what} {}",
                    real.display(),
                    p.display()
                )));
            }
            Ok(())
        };
        if !std::fs::metadata(&real).is_ok_and(|m| m.is_file()) {
            return Err(Error::msg(format!("{} is not a program", real.display())));
        }
        check(&real, "the program")?;
        let dir = real.parent().unwrap_or(Path::new("/"));
        // cbb's own folder is trusted as much as cbb is.
        if exe.as_deref().and_then(Path::parent) != Some(dir) {
            check(dir, "its folder")?;
        }
    }
    Ok(real)
}

impl Drop for Helper {
    fn drop(&mut self) {
        let mut st = self.state.lock().unwrap_or_else(|e| e.into_inner());
        self.stop(&mut st);
    }
}

/// Hands each answer to the request that waits for it, until the channel
/// ends; then every request still waiting learns that the helper stopped.
fn read_answers(stdout: std::process::ChildStdout, waiting: Waiting, log: Arc<dyn Fn(&str) + Send + Sync>) {
    let mut r = control::Reader::new(stdout);
    loop {
        match r.read() {
            Ok(Some(m)) => {
                let tx = waiting.lock().unwrap_or_else(|e| e.into_inner()).remove(&m.header.seq);
                match tx {
                    Some(tx) => {
                        let _ = tx.send(m);
                    }
                    None => log(&format!("cbb: {PROGRAM} answered seq {}, which nothing waits for", m.header.seq)),
                }
            }
            Ok(None) => break,
            Err(e) => {
                log(&format!("cbb: the channel to {PROGRAM} broke: {}", e.for_log()));
                break;
            }
        }
    }
    waiting.lock().unwrap_or_else(|e| e.into_inner()).clear();
}

#[cfg(test)]
mod tests {
    use super::*;

    /// This test program plays the helper when CBB_FAKE_HELPER is set: it
    /// answers hello, echo with its payload, fail with an error, sleep
    /// never, and exit by exiting. It answers on descriptor 3, which the
    /// script below makes the helper's standard output, since the test
    /// harness writes its own lines to standard output.
    #[cfg(unix)]
    #[test]
    fn fake_helper() {
        use std::os::fd::FromRawFd;
        if std::env::var_os("CBB_FAKE_HELPER").is_none() {
            return;
        }
        let mut r = control::Reader::new(std::io::stdin());
        // SAFETY: the script opens descriptor 3 for this process alone.
        let mut out = unsafe { std::fs::File::from_raw_fd(3) };
        while let Ok(Some(m)) = r.read() {
            let h = Header { op: "reply".into(), seq: m.header.seq, done: true, ..Default::default() };
            let ans = match m.header.op.as_str() {
                "hello" => Message::new(h, br#"{"version":"cbb fake","ops":["echo","hello"]}"#.to_vec()),
                "echo" => Message::new(Header { name: m.header.name, ..h }, m.payload),
                "fail" => Message::new(
                    Header { error: "the key is gone".into(), detail: "TPM_RC_HANDLE".into(), ..h },
                    Vec::new(),
                ),
                "sleep" => continue,
                "exit" => std::process::exit(3),
                _ => Message::new(Header { error: "unknown".into(), ..h }, Vec::new()),
            };
            control::write(&mut out, &ans).unwrap();
        }
        std::process::exit(0);
    }

    #[cfg(unix)]
    /// A Helper that runs this test program as fake_helper.
    fn fake(log: Arc<Mutex<Vec<String>>>) -> Helper {
        Helper::new(script(), Arc::new(move |s: &str| log.lock().unwrap().push(s.to_string())))
    }

    /// The script that starts fake_helper, written once for every test: a
    /// script, so that the Helper starts it with no arguments, as cbb starts
    /// cbb-helper. A process another test forks while the script is open
    /// for writing keeps it busy (ETXTBSY) until it execs, so the script is
    /// run once until it starts.
    #[cfg(unix)]
    fn script() -> &'static std::path::Path {
        static SCRIPT: std::sync::OnceLock<std::path::PathBuf> = std::sync::OnceLock::new();
        SCRIPT.get_or_init(|| {
            let dir = std::env::temp_dir().join(format!("cbb-helper-test-{}-{}", std::process::id(), next()));
            std::fs::create_dir_all(&dir).unwrap();
            let script = dir.join(PROGRAM);
            let exe = std::env::current_exe().unwrap();
            std::fs::write(
                &script,
                format!(
                    "#!/bin/sh\n[ \"$1\" = probe ] && exit 0\nCBB_FAKE_HELPER=1 exec '{}' --exact helper::tests::fake_helper --nocapture --quiet --test-threads=1 3>&1 >/dev/null\n",
                    exe.display()
                ),
            )
            .unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
            }
            for _ in 0..100 {
                match Command::new(&script).arg("probe").status() {
                    Err(e) if e.raw_os_error() == Some(libc::ETXTBSY) => {
                        std::thread::sleep(Duration::from_millis(20))
                    }
                    _ => break,
                }
            }
            script
        })
    }

    #[cfg(unix)]
    fn next() -> usize {
        static N: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        N.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
    }

    #[cfg(unix)]
    fn req(op: &str) -> Header {
        Header { op: op.into(), ..Default::default() }
    }

    #[cfg(unix)]
    #[test]
    fn talks_to_its_helper() {
        let log = Arc::new(Mutex::new(Vec::new()));
        let h = fake(Arc::clone(&log));
        let hello = h.hello().unwrap();
        assert_eq!(hello.version, "cbb fake");
        assert_eq!(hello.ops, ["echo", "hello"]);
        let t = Duration::from_secs(10);
        let ans = h.call(Header { name: "n".into(), ..req("echo") }, b"payload".to_vec(), t).unwrap();
        assert_eq!((ans.header.name.as_str(), ans.payload.as_slice()), ("n", &b"payload"[..]));
        let e = h.call(req("fail"), Vec::new(), t).unwrap_err();
        assert_eq!(e.message(), "the key is gone");
        assert!(e.details().contains("TPM_RC_HANDLE"), "{}", e.details());
        assert!(h.call(req("sleep"), Vec::new(), Duration::from_millis(200)).is_err());
        // Requests overlap: one that never ends holds back none after it.
        let ans = h.call(req("echo"), b"again".to_vec(), t).unwrap();
        assert_eq!(ans.payload, b"again");
        assert!(log.lock().unwrap().iter().any(|l| l.contains("cbb-helper runs: cbb fake")));
    }

    #[cfg(unix)]
    #[test]
    fn starts_its_helper_again() {
        let log = Arc::new(Mutex::new(Vec::new()));
        let h = fake(Arc::clone(&log));
        let t = Duration::from_secs(10);
        h.hello().unwrap();
        let e = h.call(req("exit"), Vec::new(), t).unwrap_err();
        assert!(e.message().contains("stopped"), "{}", e.message());
        // Not again at once,
        assert!(h.call(req("echo"), Vec::new(), t).is_err());
        // but after a moment.
        std::thread::sleep(RESTART_AFTER + Duration::from_millis(100));
        let ans = h.call(req("echo"), b"back".to_vec(), t).unwrap();
        assert_eq!(ans.payload, b"back");
        assert!(log.lock().unwrap().iter().any(|l| l.contains("cbb-helper stopped")));
    }

    #[test]
    fn keeps_only_the_environment_it_needs() {
        use std::ffi::OsStr;
        for k in ["PATH", "CBB_TPM", "cbb_tpm_simulator", "SystemRoot", "PCSCLITE_CSOCK_NAME"] {
            assert!(kept(OsStr::new(k)), "{k}");
        }
        for k in ["LD_PRELOAD", "DYLD_INSERT_LIBRARIES", "GODEBUG", "GOTRACEBACK", "CB", "XCBB_TPM"] {
            assert!(!kept(OsStr::new(k)), "{k}");
        }
    }

    #[test]
    fn takes_the_helper_of_its_own_release() {
        assert!(same_release("dev", "cbb fake"));
        assert!(same_release("0.6.0", "cbb v0.6.0 linux/amd64"));
        assert!(same_release("0.6.0", "cbb v0.6.0 linux/arm/v7 (time-scaled bench build)"));
        assert!(!same_release("0.6.0", "cbb v0.5.1 linux/amd64"));
        assert!(!same_release("0.6.0", "cbb dev linux/amd64"));
        assert!(!same_release("0.6.0", ""));
    }

    #[cfg(unix)]
    #[test]
    fn starts_only_a_helper_nobody_else_writes() {
        use std::os::unix::fs::PermissionsExt;
        let mode = |p: &Path, m: u32| std::fs::set_permissions(p, std::fs::Permissions::from_mode(m)).unwrap();
        let dir = std::env::temp_dir().join(format!("cbb-helper-trust-{}-{}", std::process::id(), next()));
        std::fs::create_dir_all(&dir).unwrap();
        mode(&dir, 0o755);
        let prog = dir.join(PROGRAM);
        std::fs::write(&prog, "#!/bin/sh\n").unwrap();
        mode(&prog, 0o755);
        assert_eq!(trusted(&prog).unwrap(), std::fs::canonicalize(&prog).unwrap());
        // Through a link, the program itself is what starts.
        let link = dir.join("link");
        std::os::unix::fs::symlink(&prog, &link).unwrap();
        assert_eq!(trusted(&link).unwrap(), std::fs::canonicalize(&prog).unwrap());
        mode(&prog, 0o775);
        assert!(trusted(&prog).unwrap_err().message().contains("others may write"));
        mode(&prog, 0o755);
        mode(&dir, 0o777);
        assert!(trusted(&prog).unwrap_err().message().contains("folder"));
        mode(&dir, 0o755);
        assert!(trusted(&dir.join("missing")).is_err());
        assert!(trusted(&dir).is_err(), "a folder is not a program");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn locate_takes_the_environment() {
        // Only CBB_HELPER's value is read here; the test sets nothing.
        if crate::testhooks::var_os("CBB_HELPER").is_none() {
            let beside = std::env::current_exe().unwrap().with_file_name(PROGRAM);
            assert_eq!(locate(), beside.is_file().then_some(beside));
        }
    }
}
