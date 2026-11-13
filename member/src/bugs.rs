// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! Bug reports on a computer (docs/core-api.md, "Bug reports"). The
//! service is built with `panic = "abort"`: a panic ends it and the system
//! starts it again. Before it ends, the hook installed here writes what
//! broke and the service's recent log lines to `panic.json` in the state
//! folder. After the restart the status says `bug`, and the Mac and tray
//! apps ask the user ("Oops, something broke") through the ops `bug`,
//! `bug_allow` and `bug_cancel`; with "Always allow" the service sends it
//! by itself. The core builds, filters and seals the report and keeps the
//! state, in `bug.json`; the service posts it with curl.

use std::collections::VecDeque;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Mutex;
use std::time::Duration;

use serde_json::{Value, json};

use crate::error::{Context, Error, Result};

/// The file the panic hook writes.
const PANIC_FILE: &str = "panic.json";
/// The core's bug report state.
const STATE_FILE: &str = "bug.json";
/// The log lines kept for a report.
const LINES: usize = cbb_core::bug::MAX_LINES;

static RECENT: Mutex<VecDeque<String>> = Mutex::new(VecDeque::new());

/// Keeps a line of the service's log for a report.
pub fn remember(line: &str) {
    if let Ok(mut r) = RECENT.try_lock() {
        if r.len() >= LINES {
            r.pop_front();
        }
        let mut end = cbb_core::bug::MAX_LINE.min(line.len());
        while !line.is_char_boundary(end) {
            end -= 1;
        }
        r.push_back(line[..end].to_string());
    }
}

/// What broke and where, as the ffi's guard says it.
fn describe(info: &std::panic::PanicHookInfo<'_>) -> String {
    let p = info.payload();
    let what = p
        .downcast_ref::<&str>()
        .map(|s| (*s).to_string())
        .or_else(|| p.downcast_ref::<String>().cloned())
        .unwrap_or_else(|| "a panic without a message".to_string());
    let at = info.location().map(|l| format!(" at {}:{}:{}", l.file(), l.line(), l.column())).unwrap_or_default();
    let t = std::thread::current();
    let name = t.name().map(|n| format!(" in thread {n}")).unwrap_or_default();
    format!("panic: {what}{at}{name}")
}

/// Puts the hook in place for the service's process: a panic writes
/// panic.json in dir before the earlier hook runs and the process ends.
pub fn install(dir: &Path) {
    let dir = dir.to_path_buf();
    let earlier = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let details = describe(info);
        let log: Vec<String> = RECENT.try_lock().map(|r| r.iter().cloned().collect()).unwrap_or_default();
        write_panic(&dir, &details, log);
        earlier(info);
    }));
}

/// Writes panic.json whole or not at all (write_atomic takes no lock, so a
/// panic hook may call it); a power cut while the service dies leaves the
/// report before, never half of one.
fn write_panic(dir: &Path, details: &str, log: Vec<String>) {
    let body = json!({ "details": details, "log": log, "at_ms": crate::uptime::wall_ms() });
    let _ = crate::files::write_atomic(&dir.join(PANIC_FILE), body.to_string().as_bytes(), 0o644);
}

/// The computer's side of the bug reports, in the service's state folder.
pub struct Bugs {
    dir: PathBuf,
    lock: Mutex<()>,
}

impl Bugs {
    pub fn new(dir: &Path) -> Bugs {
        Bugs { dir: dir.to_path_buf(), lock: Mutex::new(()) }
    }

    /// The panic that waits to be reported: its details and log lines.
    fn pending(&self) -> Option<(String, Vec<String>)> {
        let v: Value = serde_json::from_slice(&std::fs::read(self.dir.join(PANIC_FILE)).ok()?).ok()?;
        let details = v.get("details")?.as_str()?.to_string();
        let log = v
            .get("log")
            .and_then(Value::as_array)
            .map(|a| a.iter().filter_map(|l| l.as_str().map(str::to_string)).collect())
            .unwrap_or_default();
        Some((details, log))
    }

    /// Whether a panic waits for the user's answer.
    pub fn waiting(&self) -> bool {
        self.dir.join(PANIC_FILE).exists()
    }

    fn state(&self) -> Value {
        std::fs::read(self.dir.join(STATE_FILE))
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_else(|| json!({}))
    }

    fn keep(&self, answer: &Value) -> Result<()> {
        if let Some(s) = answer.get("state") {
            crate::files::write_atomic(&self.dir.join(STATE_FILE), s.to_string().as_bytes(), 0o600)?;
        }
        Ok(())
    }

    /// The core's answer to op with args, its `ok`.
    fn core(op: &str, args: Value) -> Result<Value> {
        let req = json!({ "abi": cbb_core::api::ABI, "op": op, "args": args });
        let a: Value = serde_json::from_slice(&cbb_core::api::call(req.to_string().as_bytes()))
            .context("the core's answer does not read")?;
        if let Some(e) = a.get("error") {
            return Err(Error::msg(format!(
                "{} ({})",
                e.get("message").and_then(Value::as_str).unwrap_or("the core refused"),
                e.get("details").and_then(Value::as_str).unwrap_or_default()
            )));
        }
        a.get("ok").cloned().ok_or_else(|| Error::msg("the core's answer has no ok"))
    }

    /// The report of the panic that waits, as the core makes it (`ask`,
    /// `send` or `skip` and the report), with names replaced; None when no
    /// panic waits.
    pub fn offer(&self, names: &[String]) -> Result<Option<Value>> {
        let _g = self.lock.lock().unwrap();
        let Some((details, log)) = self.pending() else { return Ok(None) };
        let input = json!({
            "kind": "panic",
            "code": 5,
            "name": "panic",
            "message": "Something in CBB broke, and it started again.",
            "details": details,
            "app": "cbb",
            "version": crate::service::VERSION,
            "os": std::env::consts::OS,
            "arch": std::env::consts::ARCH,
            "log": log,
            "names": names,
            "now_ms": crate::uptime::wall_ms(),
        });
        Self::core("bug_report", json!({ "input": input, "state": self.state() })).map(Some)
    }

    /// The user allowed the report, and maybe always: it goes, and the
    /// panic no longer waits.
    pub fn allow(&self, always: bool, names: &[String]) -> Result<()> {
        let offer = self.offer(names)?;
        {
            let _g = self.lock.lock().unwrap();
            let a = Self::core("bug_allow", json!({ "state": self.state(), "always": always }))?;
            self.keep(&a)?;
            let _ = std::fs::remove_file(self.dir.join(PANIC_FILE));
        }
        if let Some(o) = offer {
            self.send_offer(&o);
        }
        Ok(())
    }

    /// The user cancelled the report: nothing goes, and the panic no longer
    /// waits.
    pub fn cancel(&self) {
        let _g = self.lock.lock().unwrap();
        let _ = std::fs::remove_file(self.dir.join(PANIC_FILE));
    }

    /// At the start: a report the user allowed always goes by itself, one
    /// the core would not make again stops waiting, and the reports that
    /// could not be sent go again.
    pub fn start(&self, names: &[String], log: &(dyn Fn(&str) + Send + Sync)) {
        match self.offer(names) {
            Ok(Some(o)) => match o.get("action").and_then(Value::as_str) {
                Some("send") => {
                    let _ = std::fs::remove_file(self.dir.join(PANIC_FILE));
                    self.send_offer(&o);
                }
                Some("skip") => {
                    log("cbb: the service broke and started again; this break was reported for this version before");
                    let _ = std::fs::remove_file(self.dir.join(PANIC_FILE));
                }
                _ => log("cbb: the service broke and started again; the app asks to send a report"),
            },
            Ok(None) => {}
            Err(e) => log(&format!("cbb: no bug report: {}", e.for_log())),
        }
        let pending = {
            let _g = self.lock.lock().unwrap();
            Self::core("bug_pending", json!({ "state": self.state(), "now_ms": crate::uptime::wall_ms() }))
        };
        if let Ok(p) = pending {
            let _ = self.keep(&p);
            for q in p.get("queue").and_then(Value::as_array).cloned().unwrap_or_default() {
                let s = |k: &str| q.get(k).and_then(Value::as_str).unwrap_or_default().to_string();
                self.send(&s("fingerprint"), &s("version"), &s("post"), cbb_core::bug::URL);
            }
        }
    }

    fn send_offer(&self, o: &Value) {
        let s = |v: Option<&Value>| v.and_then(Value::as_str).unwrap_or_default().to_string();
        self.send(&s(o.get("fingerprint")), &s(o.pointer("/report/version")), &s(o.get("post")), &s(o.get("url")));
    }

    /// Posts a report's body, and keeps whether it went.
    fn send(&self, fingerprint: &str, version: &str, body: &str, url: &str) {
        if body.is_empty() {
            return;
        }
        let fixed = post(url, body.as_bytes()).ok().map(|answer| {
            serde_json::from_slice::<Value>(&answer)
                .ok()
                .and_then(|v| v.get("fixed_in").and_then(Value::as_str).map(str::to_string))
                .unwrap_or_default()
        });
        let _g = self.lock.lock().unwrap();
        let args = json!({
            "state": self.state(),
            "fingerprint": fingerprint,
            "version": version,
            "post": body,
            "ok": fixed.is_some(),
            "fixed_in": fixed.unwrap_or_default(),
            "now_ms": crate::uptime::wall_ms(),
        });
        if let Ok(a) = Self::core("bug_sent", args) {
            let _ = self.keep(&a);
        }
    }
}

/// Posts body to url with curl, https only, and returns the answer.
fn post(url: &str, body: &[u8]) -> Result<Vec<u8>> {
    if !url.starts_with("https://") {
        return Err(Error::msg("a bug report goes only over https"));
    }
    let mut child = Command::new("curl")
        .args([
            "-fsS",
            "--proto",
            "=https",
            "--max-time",
            "30",
            "--max-filesize",
            "4096",
            "-A",
            "cbb",
            "-H",
            "Content-Type: application/json",
            "--data-binary",
            "@-",
            url,
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .context("sending a bug report needs curl")?;
    child
        .stdin
        .take()
        .ok_or_else(|| Error::msg("curl took no input"))?
        .write_all(body)
        .context("cannot hand curl the report")?;
    let out = wait(child, Duration::from_secs(40))?;
    Ok(out)
}

/// Waits for child, at most time, and returns what it wrote.
fn wait(child: std::process::Child, time: Duration) -> Result<Vec<u8>> {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(child.wait_with_output());
    });
    let out = rx.recv_timeout(time).map_err(|_| Error::msg("curl took too long"))?.context("curl did not finish")?;
    if !out.status.success() {
        return Err(Error::msg("the bug report did not go"));
    }
    Ok(out.stdout)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// panic.json cut at every step: the report before stays whole.
    #[test]
    fn a_panic_report_cut_short_leaves_the_one_before() {
        use crate::files::faults::{self, How};
        let dir = std::env::temp_dir().join(format!("cbb-panic-cut-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        write_panic(&dir, "panic: first", vec![]);
        let before = std::fs::read(dir.join(PANIC_FILE)).unwrap();
        for step in 0..200 {
            for how in [How::Dies, How::Fails] {
                faults::at(step, how);
                write_panic(&dir, "panic: second", vec!["a line".into()]);
                let now = std::fs::read(dir.join(PANIC_FILE)).unwrap();
                assert!(now == before || serde_json::from_slice::<Value>(&now).is_ok(), "step {step}: a torn report");
                if now != before {
                    // Renamed: the new report, whole.
                    assert!(String::from_utf8_lossy(&now).contains("panic: second"));
                    std::fs::write(dir.join(PANIC_FILE), &before).unwrap();
                }
            }
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_panic_waits_until_the_user_answers() {
        let dir = std::env::temp_dir().join(format!("cbb-bugs-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let b = Bugs::new(&dir);
        assert!(!b.waiting());
        assert!(b.offer(&[]).unwrap().is_none());
        std::fs::write(
            dir.join(PANIC_FILE),
            json!({"details": "panic: boom at member/src/x.rs:1:2 in thread node", "log": ["dialed 192.168.0.2 for pi"]})
                .to_string(),
        )
        .unwrap();
        assert!(b.waiting());
        let o = b.offer(&["pi".into()]).unwrap().unwrap();
        assert_eq!(o["report"]["where"], "member/src/x.rs:1:2", "{o}");
        assert_eq!(o["report"]["app"], "cbb");
        let log = o["report"]["log"].to_string();
        assert!(!log.contains("192.168.0.2") && !log.contains("pi\""), "{log}");
        // No robot key in this build: allowing posts nothing, and the panic
        // no longer waits.
        b.allow(false, &[]).unwrap();
        assert!(!b.waiting());
        let st: Value = serde_json::from_slice(&std::fs::read(dir.join(STATE_FILE)).unwrap()).unwrap();
        assert_eq!(st["allowed"], 1);
        std::fs::write(dir.join(PANIC_FILE), r#"{"details":"panic: again"}"#).unwrap();
        b.cancel();
        assert!(!b.waiting());
        remember("a line");
        assert!(RECENT.lock().unwrap().iter().any(|l| l == "a line"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The recent lines stay within their bounds however many come: a
    /// service up for months keeps at most LINES lines of MAX_LINE bytes.
    #[test]
    fn the_recent_lines_stay_bounded() {
        let long = "\u{2}ж\"".repeat(cbb_core::bug::MAX_LINE);
        for i in 0..LINES * 4 {
            remember(&format!("{i} {long}"));
        }
        let r = RECENT.lock().unwrap();
        assert!(r.len() <= LINES, "{} lines", r.len());
        assert!(r.iter().all(|l| l.len() <= cbb_core::bug::MAX_LINE));
        assert!(r.iter().map(String::len).sum::<usize>() <= LINES * cbb_core::bug::MAX_LINE);
    }
}
