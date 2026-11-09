// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! Real `cbb service` processes for the tests: each runs in a folder of its
//! own, without mDNS, listening on a free port of the loopback, and the
//! tests talk to it over its control and admin sockets as the command line
//! does (docs/protocol.md, section 8), with the headers as plain JSON, so
//! that they check the wire contract rather than the crate's own types.

#![cfg(unix)]
#![allow(dead_code, reason = "each test file uses its own part of the harness")]

use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use serde_json::{Value, json};

/// How long one answer may take: the slowest operations wait for a
/// helper that does not answer, up to 30 s for each of two requests.
pub const ANSWER: Duration = Duration::from_secs(90);

/// One message on a control socket: its header and payload.
#[derive(Debug, Clone)]
pub struct Msg {
    pub h: Value,
    pub payload: Vec<u8>,
}

impl Msg {
    pub fn error(&self) -> &str {
        self.h["error"].as_str().unwrap_or("")
    }
    pub fn s(&self, k: &str) -> &str {
        self.h[k].as_str().unwrap_or("")
    }
    pub fn done(&self) -> bool {
        self.h["done"].as_bool().unwrap_or(false)
    }
}

/// Writes one request: the header with its len, a newline, the payload.
pub fn send(conn: &mut UnixStream, h: &Value, payload: &[u8]) {
    let mut h = h.clone();
    if !payload.is_empty() {
        h["len"] = json!(payload.len());
    }
    let mut buf = serde_json::to_vec(&h).unwrap();
    buf.push(b'\n');
    buf.extend_from_slice(payload);
    conn.write_all(&buf).unwrap();
}

/// Reads one message, None at the end of the stream.
pub fn read(r: &mut BufReader<UnixStream>) -> Option<Msg> {
    let mut line = Vec::new();
    match r.read_until(b'\n', &mut line) {
        Ok(0) | Err(_) => return None,
        Ok(_) => {}
    }
    let h: Value = serde_json::from_slice(&line).unwrap_or_else(|e| {
        panic!("the service sent a header that is not JSON ({e}): {:?}", String::from_utf8_lossy(&line))
    });
    let n = h["len"].as_u64().unwrap_or(0) as usize;
    let mut payload = vec![0; n];
    r.read_exact(&mut payload).expect("the payload the header promised");
    Some(Msg { h, payload })
}

static NEXT: AtomicUsize = AtomicUsize::new(0);

/// A `cbb service` in a temporary folder, stopped and deleted when dropped.
pub struct Svc {
    pub dir: PathBuf,
    pub name: String,
    child: Option<Child>,
}

impl Svc {
    /// Starts a member called name with the extra arguments of cbb service
    /// and the environment, without a helper unless env names one.
    pub fn start(name: &str, extra: &[&str], env: &[(&str, &str)]) -> Svc {
        let n = NEXT.fetch_add(1, Ordering::SeqCst);
        // Short: a Unix socket's path has at most 108 bytes.
        let dir = std::env::temp_dir().join(format!("cbbt-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Self::start_in(dir, name, extra, env)
    }

    /// Starts a member in a folder made before, as a restart does.
    pub fn start_in(dir: PathBuf, name: &str, extra: &[&str], env: &[(&str, &str)]) -> Svc {
        let mut svc = Svc { dir, name: name.into(), child: None };
        svc.spawn(extra, env);
        svc
    }

    fn spawn(&mut self, extra: &[&str], env: &[(&str, &str)]) {
        let log = std::fs::OpenOptions::new().create(true).append(true).open(self.dir.join("log")).unwrap();
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_cbb"));
        cmd.arg("-state")
            .arg(self.dir.join("s"))
            .arg("-socket")
            .arg(self.socket(false))
            .args(["service", "-name", &self.name, "-no-mdns", "-port", "0"])
            .args(extra)
            .env("CBB_HELPER", "")
            .env("CBB_DEBUG", "1")
            .env_remove("CBB_CONTAINER")
            .env_remove("CBB_ROOTLESS")
            .env_remove("CBB_STATE")
            .env_remove("CBB_SOCKET")
            .stdin(Stdio::null())
            .stdout(log.try_clone().unwrap())
            .stderr(log);
        for (k, v) in env {
            cmd.env(k, v);
        }
        self.child = Some(cmd.spawn().expect("cbb service starts"));
        let until = Instant::now() + Duration::from_secs(30);
        while UnixStream::connect(self.socket(true)).is_err() {
            if let Some(st) = self.child.as_mut().unwrap().try_wait().unwrap() {
                panic!("cbb service stopped at its start ({st}):\n{}", self.log());
            }
            assert!(Instant::now() < until, "cbb service did not listen:\n{}", self.log());
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// The control socket, or the admin socket beside it.
    pub fn socket(&self, admin: bool) -> PathBuf {
        self.dir.join("r").join(if admin { "admin.sock" } else { "control.sock" })
    }

    pub fn state(&self) -> PathBuf {
        self.dir.join("s")
    }

    pub fn log(&self) -> String {
        std::fs::read_to_string(self.dir.join("log")).unwrap_or_default()
    }

    /// Opens a connection, sends the request and returns the connection
    /// and its reader for what follows.
    pub fn open(&self, admin: bool, h: &Value, payload: &[u8]) -> (UnixStream, BufReader<UnixStream>) {
        let mut conn = UnixStream::connect(self.socket(admin))
            .unwrap_or_else(|e| panic!("cannot connect to {}: {e}\n{}", self.socket(admin).display(), self.log()));
        conn.set_read_timeout(Some(ANSWER)).unwrap();
        send(&mut conn, h, payload);
        let r = BufReader::new(conn.try_clone().unwrap());
        (conn, r)
    }

    /// Every message the service answers to one request, until one that is
    /// done or the end of the connection.
    pub fn ask_all(&self, admin: bool, h: Value, payload: &[u8]) -> Vec<Msg> {
        let (_conn, mut r) = self.open(admin, &h, payload);
        let mut got = Vec::new();
        while let Some(m) = read(&mut r) {
            let done = m.done() || !m.error().is_empty();
            got.push(m);
            if done {
                break;
            }
        }
        got
    }

    /// The last answer to a request, which must come.
    pub fn ask(&self, admin: bool, h: Value, payload: &[u8]) -> Msg {
        let op = h["op"].clone();
        let mut all = self.ask_all(admin, h, payload);
        all.pop().unwrap_or_else(|| panic!("no answer to {op}:\n{}", self.log()))
    }

    /// The answer to a request that must succeed.
    pub fn ok(&self, admin: bool, h: Value) -> Msg {
        self.ok_with(admin, h, b"")
    }

    pub fn ok_with(&self, admin: bool, h: Value, payload: &[u8]) -> Msg {
        let req = h.to_string();
        let m = self.ask(admin, h, payload);
        assert!(m.error().is_empty(), "{req} failed: {} ({})\n{}", m.error(), m.s("details"), self.log());
        assert_eq!(m.s("op"), "reply", "{req}: {:?}", m.h);
        m
    }

    /// The error of a request that must fail.
    pub fn err(&self, admin: bool, h: Value) -> String {
        self.err_with(admin, h, b"")
    }

    pub fn err_with(&self, admin: bool, h: Value, payload: &[u8]) -> String {
        let req = h.to_string();
        let m = self.ask(admin, h, payload);
        assert!(!m.error().is_empty(), "{req} did not fail: {:?}", m.h);
        assert_eq!(m.s("op"), "reply", "{req}: {:?}", m.h);
        m.error().to_string()
    }

    /// The status, once the group that cbb new or a join made started.
    pub fn status(&self) -> Value {
        wait_for(
            &format!("{} answers its status", self.name),
            || {
                let m = self.ask(false, json!({"op": "status"}), b"");
                if m.error().contains("still starting") {
                    return None;
                }
                assert!(m.error().is_empty(), "status: {:?}\n{}", m.h, self.log());
                Some(m.h["status"].clone())
            },
            || self.log(),
        )
    }

    /// The member port it listens on, once its group started.
    pub fn port(&self) -> u16 {
        wait_for(
            &format!("{} listens on its port", self.name),
            || self.status()["port"].as_u64().filter(|p| *p > 0).map(|p| p as u16),
            || self.log(),
        )
    }

    pub fn addr(&self) -> String {
        format!("127.0.0.1:{}", self.port())
    }

    pub fn device(&self) -> String {
        self.status()["device"].as_str().unwrap_or("").to_string()
    }

    /// Makes a group with this member as its root.
    pub fn new_group(&self) -> Value {
        let st = self.ok(true, json!({"op": "new"})).h["status"].clone();
        // The group starts behind the answer.
        self.port();
        st
    }

    /// Admits joiner through a pairing window here, the joiner dialing
    /// this member's port with the window's code; returns the name the
    /// window reports.
    pub fn admit(&self, joiner: &Svc, admins: bool) -> String {
        let (_conn, mut r) = self.open(true, &json!({"op": "pair", "admins": admins}), b"");
        let opened = read(&mut r).unwrap_or_else(|| panic!("no window:\n{}", self.log()));
        assert!(opened.error().is_empty(), "the window: {}\n{}", opened.error(), self.log());
        let code = opened.s("code").to_string();
        assert_eq!(code.len(), 6, "{:?}", opened.h);
        let joined = joiner.ask(true, json!({"op": "join", "code": code, "address": self.addr()}), b"");
        assert!(joined.error().is_empty(), "join: {}\n{}\n{}", joined.error(), joiner.log(), self.log());
        let closed = read(&mut r).unwrap_or_else(|| panic!("the window did not close:\n{}", self.log()));
        assert!(closed.error().is_empty(), "the window: {}", closed.error());
        joiner.port();
        closed.s("name").to_string()
    }

    /// Waits until f holds of this member's status.
    pub fn wait(&self, what: &str, f: impl Fn(&Value) -> bool) -> Value {
        wait_for(what, || Some(self.status()).filter(&f), || self.log())
    }

    /// Waits until the devices list shows name connected.
    pub fn wait_peer(&self, name: &str) {
        self.wait(&format!("{} sees {name}", self.name), |st| {
            st["peers"].as_array().is_some_and(|ps| ps.iter().any(|p| p["name"] == name))
        });
    }

    /// The devices this member lists.
    pub fn devices(&self) -> Vec<Value> {
        self.ok(false, json!({"op": "devices"})).h["devices"].as_array().cloned().unwrap_or_default()
    }

    pub fn find(&self, name: &str) -> Option<Value> {
        self.devices().into_iter().find(|d| d["name"] == name)
    }

    /// Whether the process still runs.
    pub fn running(&mut self) -> bool {
        self.child.as_mut().is_some_and(|c| matches!(c.try_wait(), Ok(None)))
    }

    /// Waits for the process to exit by itself, as after cbb leave.
    pub fn wait_exit(&mut self, within: Duration) -> std::process::ExitStatus {
        let until = Instant::now() + within;
        loop {
            if let Some(st) = self.child.as_mut().unwrap().try_wait().unwrap() {
                return st;
            }
            assert!(Instant::now() < until, "{} did not stop:\n{}", self.name, self.log());
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    /// Stops the process with SIGTERM, as systemd does, and waits.
    pub fn stop(&mut self) {
        if let Some(mut c) = self.child.take() {
            // SAFETY: kill has no memory preconditions.
            unsafe { libc_kill(c.id() as i32, 15) };
            let until = Instant::now() + Duration::from_secs(20);
            while matches!(c.try_wait(), Ok(None)) && Instant::now() < until {
                std::thread::sleep(Duration::from_millis(20));
            }
            let _ = c.kill();
            let _ = c.wait();
        }
    }

    /// Starts the stopped process again in the same folder.
    pub fn restart(&mut self, extra: &[&str], env: &[(&str, &str)]) {
        self.stop();
        self.spawn(extra, env);
    }
}

unsafe extern "C" {
    #[link_name = "kill"]
    fn libc_kill(pid: i32, sig: i32) -> i32;
}

impl Drop for Svc {
    fn drop(&mut self) {
        self.stop();
        if std::thread::panicking() {
            eprintln!("--- {} ({}) ---\n{}", self.name, self.dir.display(), self.log());
        }
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// Polls get until it gives a value, for up to 90 seconds.
pub fn wait_for<T>(what: &str, get: impl Fn() -> Option<T>, log: impl Fn() -> String) -> T {
    let until = Instant::now() + Duration::from_secs(90);
    loop {
        if let Some(v) = get() {
            return v;
        }
        assert!(Instant::now() < until, "timed out: {what}\n{}", log());
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// A root and the members it admitted, all connected to the root.
pub fn group(names: &[&str]) -> Vec<Svc> {
    group_with(names, &[])
}

/// A group whose members (not the root) run with the environment env.
pub fn group_with(names: &[&str], env: &[(&str, &str)]) -> Vec<Svc> {
    let root = Svc::start(names[0], &[], &[]);
    root.new_group();
    let mut all = vec![root];
    for name in &names[1..] {
        let addr = all[0].addr();
        let m = Svc::start(name, &["-peer", &addr], env);
        let got = all[0].admit(&m, false);
        assert_eq!(got, *name);
        all.push(m);
    }
    for m in &all[1..] {
        all[0].wait_peer(&m.name);
        m.wait_peer(&all[0].name);
    }
    settle(&all);
    all
}

/// Waits until no member has connected or lost a connection for two
/// seconds: right after a join both sides dial, and one of the two
/// connections closes, which a command sent then may meet.
pub fn settle(all: &[Svc]) {
    let count = || -> usize {
        all.iter().map(|s| s.log().lines().filter(|l| l.contains("connect") || l.contains("goodbye")).count()).sum()
    };
    let mut last = count();
    let mut quiet = Instant::now();
    let until = Instant::now() + Duration::from_secs(30);
    while quiet.elapsed() < Duration::from_secs(2) && Instant::now() < until {
        std::thread::sleep(Duration::from_millis(100));
        let n = count();
        if n != last {
            last = n;
            quiet = Instant::now();
        }
    }
}

/// Writes text to path, made for this test.
pub fn write(path: &Path, text: &str) {
    std::fs::write(path, text).unwrap();
}
