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

/// Where the helper is: CBB_HELPER if set (empty for none), else cbb-helper
/// beside this program, if it is there.
pub fn locate() -> Option<PathBuf> {
    if let Some(p) = std::env::var_os("CBB_HELPER") {
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
        Helper { path: path.to_path_buf(), log, state: Mutex::new(State::default()) }
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
        let rx = {
            let mut st = self.state.lock().unwrap_or_else(|e| e.into_inner());
            self.ensure(&mut st)?;
            self.send(&mut st, header, payload)?
        };
        let op_err = |m: &str| Error::msg(format!("{PROGRAM}: {m}"));
        let ans = match rx.recv_timeout(timeout) {
            Ok(m) => m,
            Err(mpsc::RecvTimeoutError::Timeout) => return Err(op_err("no answer in time")),
            Err(mpsc::RecvTimeoutError::Disconnected) => return Err(op_err("it stopped before it answered")),
        };
        if !ans.header.error.is_empty() {
            let msg = ans.header.error.clone();
            return Err(if ans.header.detail.is_empty() {
                Error::msg(msg)
            } else {
                Error::with(msg, Remote(ans.header.detail.clone()))
            });
        }
        Ok(ans)
    }

    /// Writes a request on the channel and returns where its answer comes.
    fn send(&self, st: &mut State, mut header: Header, payload: Vec<u8>) -> Result<mpsc::Receiver<Message>> {
        st.next_seq += 1;
        header.seq = st.next_seq;
        let Some(r) = st.running.as_mut() else { return Err(Error::msg(format!("{PROGRAM} does not run"))) };
        let (tx, rx) = mpsc::channel();
        r.waiting.lock().unwrap_or_else(|e| e.into_inner()).insert(header.seq, tx);
        if let Err(e) = control::write(&mut r.stdin, &Message::new(header, payload)) {
            self.stop(st);
            return Err(e.context(format!("{PROGRAM} stopped")));
        }
        Ok(rx)
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
        let mut child = Command::new(&self.path)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            // Its log goes where cbb's goes.
            .stderr(Stdio::inherit())
            .spawn()
            .context(format!("cannot start {}", self.path.display()))?;
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
        let ans = rx.recv_timeout(HELLO_TIMEOUT).map_err(|_| {
            self.stop(st);
            Error::msg(format!("{PROGRAM} did not say hello"))
        })?;
        let hello: Hello = serde_json::from_slice(&ans.payload).map_err(|e| {
            self.stop(st);
            Error::with(format!("{PROGRAM} said hello in a form cbb does not read"), e)
        })?;
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

    /// A Helper that runs this test program as fake_helper.
    fn fake(log: Arc<Mutex<Vec<String>>>) -> Helper {
        Helper::new(script(), Arc::new(move |s: &str| log.lock().unwrap().push(s.to_string())))
    }

    /// The script that starts fake_helper, written once for every test: a
    /// script, so that the Helper starts it with no arguments, as cbb starts
    /// cbb-helper. A process another test forks while the script is open
    /// for writing keeps it busy (ETXTBSY) until it execs, so the script is
    /// run once until it starts.
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

    fn next() -> usize {
        static N: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        N.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
    }

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
    fn locate_takes_the_environment() {
        // Only CBB_HELPER's value is read here; the test sets nothing.
        if std::env::var_os("CBB_HELPER").is_none() {
            let beside = std::env::current_exe().unwrap().with_file_name(PROGRAM);
            assert_eq!(locate(), beside.is_file().then_some(beside));
        }
    }
}
