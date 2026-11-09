// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The command line against a fake service: each case runs `cbb` with its
//! arguments and standard input, the fake answers every request on the
//! control and the admin socket with the case's header, and the case checks
//! what was sent, what was printed and the exit code (2 for a usage error).

#![cfg(unix)]

use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::UnixListener;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{Value, json};

/// A request the fake service took: its header and payload.
#[derive(Debug, Clone)]
struct Sent {
    h: Value,
    payload: Vec<u8>,
}

impl Sent {
    fn op(&self) -> &str {
        self.h["op"].as_str().unwrap_or("")
    }
    fn s(&self, k: &str) -> &str {
        self.h[k].as_str().unwrap_or("")
    }
    fn b(&self, k: &str) -> bool {
        self.h[k].as_bool().unwrap_or(false)
    }
    fn i(&self, k: &str) -> i64 {
        self.h[k].as_i64().unwrap_or(0)
    }
    fn list(&self, k: &str) -> Vec<String> {
        self.h[k]
            .as_array()
            .map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect())
            .unwrap_or_default()
    }
}

type Check = fn(&Sent) -> bool;

struct Case {
    name: &'static str,
    args: &'static [&'static str],
    stdin: &'static str,
    /// The service's answer to every request; op and done are set.
    answer: Value,
    payload: &'static [u8],
    /// The op the command must send and a check of that request; None
    /// when the command must send nothing.
    sent: Option<(&'static str, Option<Check>)>,
    code: i32,
    stdout: &'static str,
    stderr: &'static str,
}

impl Default for Case {
    fn default() -> Case {
        Case {
            name: "",
            args: &[],
            stdin: "",
            answer: json!({}),
            payload: b"",
            sent: None,
            code: 0,
            stdout: "",
            stderr: "",
        }
    }
}

/// The fake service's answers to one request, each a header (op is set to
/// reply) and a payload.
type Answers = Vec<(Value, Vec<u8>)>;
type Handler = Arc<dyn Fn(&Sent) -> Answers + Send + Sync>;

/// A request's envelope, {"op", "args", "len", "seq"}, as one flat object,
/// so that the checks read its fields by name.
fn flatten(v: Value) -> Value {
    let mut flat = v["args"].as_object().cloned().unwrap_or_default();
    for k in ["op", "len", "seq"] {
        if let Some(x) = v.get(k) {
            flat.insert(k.into(), x.clone());
        }
    }
    Value::Object(flat)
}

/// A flat answer put in its envelope: error, detail, done, len and seq
/// beside, the rest in ok unless it failed.
fn answer_envelope(a: Value) -> Value {
    let mut fields = a.as_object().cloned().unwrap_or_default();
    fields.remove("op");
    let mut out = serde_json::Map::new();
    for k in ["error", "detail", "details", "done", "len", "seq"] {
        if let Some(x) = fields.remove(k) {
            out.insert(k.into(), x);
        }
    }
    if !out.contains_key("error") {
        out.insert("ok".into(), Value::Object(fields));
    }
    Value::Object(out)
}

/// Serves one socket: every request on every connection gets handle's
/// answers.
fn serve(l: UnixListener, handle: Handler, got: Arc<Mutex<Vec<Sent>>>) {
    std::thread::spawn(move || {
        for conn in l.incoming() {
            let Ok(conn) = conn else { return };
            let (handle, got) = (handle.clone(), got.clone());
            std::thread::spawn(move || {
                let mut w = conn.try_clone().unwrap();
                let mut r = BufReader::new(conn);
                loop {
                    let mut line = Vec::new();
                    if r.read_until(b'\n', &mut line).unwrap_or(0) == 0 {
                        return;
                    }
                    let Ok(h) = serde_json::from_slice::<Value>(&line).map(flatten) else { return };
                    let mut body = vec![0u8; h["len"].as_u64().unwrap_or(0) as usize];
                    if r.read_exact(&mut body).is_err() {
                        return;
                    }
                    let sent = Sent { h, payload: body };
                    got.lock().unwrap().push(sent.clone());
                    for (mut a, payload) in handle(&sent) {
                        if !payload.is_empty() {
                            a["len"] = json!(payload.len());
                        }
                        let mut out = serde_json::to_vec(&answer_envelope(a)).unwrap();
                        out.push(b'\n');
                        out.extend_from_slice(&payload);
                        if w.write_all(&out).is_err() {
                            return;
                        }
                    }
                }
            });
        }
    });
}

struct Run {
    code: i32,
    stdout: String,
    stderr: String,
    sent: Vec<Sent>,
}

/// Answers every request with answer, done.
fn always(answer: Value, payload: &[u8]) -> Handler {
    let payload = payload.to_vec();
    Arc::new(move |_: &Sent| {
        let mut a = answer.clone();
        a["done"] = json!(true);
        vec![(a, payload.clone())]
    })
}

/// Runs cbb with args against a fake service in dir that answers every
/// request with answer.
fn run_in(dir: &Path, args: &[&str], stdin: &str, answer: Value, payload: &[u8]) -> Run {
    run_with(dir, args, stdin, always(answer, payload), &[])
}

/// Runs cbb with args and env against a fake service in dir.
fn run_with(dir: &Path, args: &[&str], stdin: &str, handle: Handler, env: &[(&str, &str)]) -> Run {
    let sock = dir.join("control.sock");
    let admin = dir.join("admin.sock");
    let _ = std::fs::remove_file(&sock);
    let _ = std::fs::remove_file(&admin);
    let got = Arc::new(Mutex::new(Vec::new()));
    serve(UnixListener::bind(&sock).unwrap(), handle.clone(), got.clone());
    serve(UnixListener::bind(&admin).unwrap(), handle, got.clone());
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_cbb"));
    cmd.args(args)
        .current_dir(dir)
        .env("CBB_SOCKET", &sock)
        .env("CBB_STATE", dir.join("state"))
        .env("LANG", "C")
        .env("LC_ALL", "C")
        .env_remove("LANGUAGE")
        .env_remove("CBB_DEBUG")
        .env("HOME", dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (k, v) in env {
        cmd.env(k, v);
    }
    let mut child = cmd.spawn().unwrap();
    let input = stdin.as_bytes().to_vec();
    let mut pipe = child.stdin.take().unwrap();
    std::thread::spawn(move || pipe.write_all(&input));
    // A command that hangs fails its case rather than the whole run.
    let pid = child.id();
    let watchdog = std::thread::spawn(move || {
        for _ in 0..300 {
            std::thread::sleep(Duration::from_millis(100));
            if !Path::new(&format!("/proc/{pid}")).exists() {
                return;
            }
        }
        let _ = Command::new("kill").arg(pid.to_string()).status();
    });
    let out = child.wait_with_output().unwrap();
    drop(watchdog);
    std::thread::sleep(Duration::from_millis(20));
    let sent = got.lock().unwrap().clone();
    Run {
        code: out.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        sent,
    }
}

fn tempdir(name: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("cbb-cli-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// Runs each case and reports every one that fails.
fn run_cases(group: &str, cases: Vec<Case>) {
    let dir = tempdir(group);
    let mut failed = Vec::new();
    for c in cases {
        let r = run_in(&dir, c.args, c.stdin, c.answer.clone(), c.payload);
        let mut why = Vec::new();
        if r.code != c.code {
            why.push(format!("exit code {}, want {}", r.code, c.code));
        }
        if !r.stdout.contains(c.stdout) {
            why.push(format!("stdout lacks {:?}", c.stdout));
        }
        if !r.stderr.contains(c.stderr) {
            why.push(format!("stderr lacks {:?}", c.stderr));
        }
        // Reading the status to learn whether the device is in a group
        // is no request of the command's own.
        let own: Vec<&Sent> =
            r.sent.iter().filter(|s| c.sent.is_some_and(|(op, _)| s.op() == op) || s.op() != "status").collect();
        match c.sent {
            None if !own.is_empty() => why.push(format!("sent {:?}, want no request", own[0].h)),
            None => {}
            Some((op, check)) => match own.iter().find(|s| s.op() == op) {
                None => why.push(format!("sent no {op}: {:?}", r.sent.iter().map(|s| &s.h).collect::<Vec<_>>())),
                Some(s) if check.is_some_and(|f| !f(s)) => why.push(format!("sent {:?}, want other fields", s.h)),
                Some(_) => {}
            },
        }
        if !why.is_empty() {
            failed.push(format!(
                "{}: cbb {}: {}\n  stdout {:?}\n  stderr {:?}",
                c.name,
                c.args.join(" "),
                why.join("; "),
                r.stdout,
                r.stderr
            ));
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
    assert!(failed.is_empty(), "{}", failed.join("\n"));
}

/// A request's payload as text.
fn text(s: &Sent) -> String {
    String::from_utf8_lossy(&s.payload).into_owned()
}

/// A status as the service sends it: the fields it always has, then st's.
fn status(st: Value) -> Value {
    let mut full = json!({"device": "d1", "role": "full", "version": "0.6.0", "port": 0});
    for (k, v) in st.as_object().unwrap() {
        full[k] = v.clone();
    }
    json!({ "status": full })
}

fn in_group(mut st: Value) -> Value {
    st["os"] = json!("linux");
    st["group"] = json!("g1");
    status(st)
}

fn err(e: &str) -> Value {
    json!({ "error": e })
}

#[test]
fn device_commands() {
    let refused = err("only the group's root makes admins");
    run_cases(
        "device",
        vec![
            Case {
                name: "remove",
                args: &["remove", "laptop"],
                answer: json!({"name": "laptop"}),
                sent: Some(("remove", Some(|s| s.s("device") == "laptop"))),
                stdout: "Removed laptop from the group",
                ..Case::default()
            },
            Case {
                name: "remove refused",
                args: &["remove", "laptop"],
                answer: err("no device laptop in the group"),
                sent: Some(("remove", None)),
                code: 1,
                stderr: "no device laptop in the group",
                ..Case::default()
            },
            Case {
                name: "rename",
                args: &["rename", "laptop", " work "],
                answer: json!({"name": "laptop"}),
                sent: Some(("rename", Some(|s| s.s("device") == "laptop" && s.s("name") == " work "))),
                stdout: "Renamed laptop to work.",
                ..Case::default()
            },
            Case {
                name: "rename without a new name",
                args: &["rename", "laptop"],
                code: 2,
                stderr: "usage: cbb rename",
                ..Case::default()
            },
            Case {
                name: "takeover delay",
                args: &["takeover", "-delay", "24h"],
                sent: Some(("takeover_delay", Some(|s| s.s("value") == "24h"))),
                stdout: "now waits 24h",
                ..Case::default()
            },
            Case {
                name: "takeover delay without a duration",
                args: &["takeover", "-delay"],
                code: 2,
                stderr: "usage: cbb takeover -delay",
                ..Case::default()
            },
            Case {
                name: "key level",
                args: &["keys", "hardware"],
                answer: json!({"below": ["desk"]}),
                sent: Some(("key_level", Some(|s| s.s("value") == "hardware"))),
                stdout: "Below it: desk.",
                ..Case::default()
            },
            Case {
                name: "key level shown",
                args: &["keys"],
                answer: status(json!({"group": "g", "key_level": "files"})),
                sent: Some(("status", None)),
                stdout: "Key level files",
                ..Case::default()
            },
            Case {
                name: "key level with two",
                args: &["keys", "files", "hardware"],
                code: 2,
                stderr: "usage: cbb keys",
                ..Case::default()
            },
            Case {
                name: "incoming",
                args: &["incoming", "90s"],
                sent: Some(("incoming", Some(|s| s.s("value") == "90s"))),
                stdout: "for 1m30s after it arrives",
                ..Case::default()
            },
            Case {
                name: "incoming shown",
                args: &["incoming"],
                answer: status(json!({"group": "g", "incoming_ms": 3_600_000})),
                sent: Some(("status", None)),
                stdout: "for 1h after it arrives",
                ..Case::default()
            },
            Case {
                name: "incoming not a duration",
                args: &["incoming", "soon"],
                code: 2,
                stderr: "usage: cbb incoming",
                ..Case::default()
            },
            Case {
                name: "hubs",
                args: &["global", "hubs", "deck", "pi"],
                sent: Some(("hubs", Some(|s| s.list("hubs") == ["deck", "pi"]))),
                stdout: "deck, pi, in this order",
                ..Case::default()
            },
            Case {
                name: "hubs without a device",
                args: &["global", "hubs"],
                code: 2,
                stderr: "usage: cbb global hubs",
                ..Case::default()
            },
            Case {
                name: "freeze",
                args: &["freeze", "desk"],
                answer: json!({"name": "desk"}),
                sent: Some(("freeze", Some(|s| s.s("device") == "desk"))),
                stdout: "Froze desk",
                ..Case::default()
            },
            Case {
                name: "unfreeze",
                args: &["unfreeze", "desk"],
                answer: json!({"name": "desk"}),
                sent: Some(("thaw", None)),
                stdout: "Unfroze desk: it is an admin again.",
                ..Case::default()
            },
            Case {
                name: "resolve",
                args: &["resolve"],
                answer: json!({"name": "desk"}),
                sent: Some(("resolve", None)),
                stdout: "Voided both histories of desk",
                ..Case::default()
            },
            Case {
                name: "resolve with an argument",
                args: &["resolve", "desk"],
                code: 2,
                stderr: "usage: cbb resolve",
                ..Case::default()
            },
            Case {
                name: "admin",
                args: &["admin", "desk"],
                answer: json!({"name": "desk"}),
                sent: Some(("make_admin", Some(|s| s.s("device") == "desk" && !s.b("allow_file_key")))),
                stdout: "desk is an admin now",
                ..Case::default()
            },
            Case {
                name: "admin with a file key",
                args: &["admin", "-allow-file-key", "desk"],
                answer: json!({"name": "desk"}),
                sent: Some(("make_admin", Some(|s| s.b("allow_file_key")))),
                stdout: "guard it",
                ..Case::default()
            },
            Case {
                name: "admin refused",
                args: &["admin", "desk"],
                answer: refused,
                sent: Some(("make_admin", None)),
                code: 1,
                stderr: "only the group's root",
                ..Case::default()
            },
            Case {
                name: "admin without a device",
                args: &["admin"],
                code: 2,
                stderr: "usage: cbb admin",
                ..Case::default()
            },
            Case { name: "takeover without a device", args: &["takeover"], code: 2, ..Case::default() },
            Case {
                name: "takeover",
                args: &["takeover", "old"],
                answer: json!({"name": "old"}),
                sent: Some(("take_over", Some(|s| s.s("device") == "old"))),
                stdout: "Claimed the group from old",
                ..Case::default()
            },
        ],
    );
}

#[test]
fn sync_and_network() {
    run_cases(
        "sync",
        vec![
            Case {
                name: "sync",
                args: &["sync"],
                answer: in_group(json!({"mode": "shared"})),
                sent: Some(("status", None)),
                stdout: "Sync is on",
                ..Case::default()
            },
            Case {
                name: "sync in no group",
                args: &["sync"],
                answer: status(json!({"role": "full", "os": "linux"})),
                sent: Some(("status", None)),
                code: 1,
                stderr: "in no group",
                ..Case::default()
            },
            Case {
                name: "sync with no status",
                args: &["sync"],
                sent: Some(("status", None)),
                code: 1,
                stderr: "in no group",
                ..Case::default()
            },
            Case {
                name: "sync off",
                args: &["sync", "off"],
                answer: in_group(json!({"mode": "own"})),
                sent: Some(("sync", Some(|s| s.h["on"] == false && s.s("device").is_empty() && s.i("for_ms") == 0))),
                stdout: "Sync is off until cbb sync on",
                ..Case::default()
            },
            Case {
                name: "sync off for an hour",
                args: &["sync", "-for", "1h", "off"],
                answer: in_group(json!({"mode": "own", "sync_until_ms": 1})),
                sent: Some(("sync", Some(|s| s.h["on"] == false && s.i("for_ms") == 3_600_000))),
                stdout: "Sync is off until",
                ..Case::default()
            },
            Case {
                name: "sync off, then the time",
                args: &["sync", "off", "-for", "15m"],
                answer: in_group(json!({"mode": "own", "sync_until_ms": 1})),
                sent: Some(("sync", Some(|s| s.h["on"] == false && s.i("for_ms") == 900_000))),
                stdout: "Sync is off until",
                ..Case::default()
            },
            Case {
                name: "sync on with a time",
                args: &["sync", "on", "-for", "15m"],
                code: 2,
                stderr: "-for goes with cbb sync off",
                ..Case::default()
            },
            Case {
                name: "sync on",
                args: &["sync", "on"],
                answer: in_group(json!({"mode": "shared"})),
                sent: Some(("sync", Some(|s| s.h["on"] == true))),
                stdout: "Sync is on",
                ..Case::default()
            },
            Case {
                name: "sync elsewhere",
                args: &["sync", "-on", "tv", "off"],
                sent: Some(("sync", Some(|s| s.h["on"] == false && s.s("device") == "tv"))),
                stdout: "Sync is off on tv now.",
                ..Case::default()
            },
            Case {
                name: "sync -on without on or off",
                args: &["sync", "-on", "tv"],
                code: 2,
                stderr: "usage: cbb sync",
                ..Case::default()
            },
            Case {
                name: "sync with a mode",
                args: &["sync", "own"],
                code: 2,
                stderr: "usage: cbb sync",
                ..Case::default()
            },
            Case {
                name: "sync on for a while",
                args: &["sync", "-for", "1h", "on"],
                code: 2,
                stderr: "-for goes with cbb sync off",
                ..Case::default()
            },
            Case {
                name: "sync off elsewhere for a while",
                args: &["sync", "-on", "tv", "-for", "1h", "off"],
                code: 2,
                stderr: "-for goes with cbb sync off",
                ..Case::default()
            },
            Case {
                name: "network",
                args: &["network"],
                sent: Some(("network", None)),
                stdout: "publishes itself and takes connections here",
                ..Case::default()
            },
            Case {
                name: "network refused",
                args: &["network"],
                answer: err("this network is not known"),
                sent: Some(("network", None)),
                code: 1,
                stderr: "not known",
                ..Case::default()
            },
            Case {
                name: "network with an argument",
                args: &["network", "x"],
                code: 2,
                stderr: "usage: cbb network",
                ..Case::default()
            },
        ],
    );
}

/// The quick actions' commands and the lines that list them.
#[test]
fn action_commands() {
    let list = in_group(json!({"actions": [
        {"name": "lock", "on": true},
        {"name": "reboot", "on": true, "by": ["root", "phone"]},
        {"name": "shutdown", "on": true, "any_key": true},
        {"name": "sleep"},
        {"name": "backup", "on": true, "command": ["/usr/bin/backup", "--now"]},
        {"name": "hibernate", "on": true, "any_key": true, "by": ["root"]},
    ]}));
    run_cases(
        "action",
        vec![
            Case {
                name: "list",
                args: &["action"],
                answer: list,
                sent: Some(("status", None)),
                stdout: "lock             on, for every admin\n",
                ..Case::default()
            },
            Case {
                name: "list in no group",
                args: &["action"],
                answer: status(json!({})),
                sent: Some(("status", None)),
                code: 1,
                stderr: "in no group",
                ..Case::default()
            },
            Case {
                name: "run on another device",
                args: &["action", "-on", "desk", "lock"],
                sent: Some(("action_on", Some(|s| s.s("device") == "desk" && s.s("name") == "lock"))),
                stdout: "desk ran lock.",
                ..Case::default()
            },
            Case {
                name: "run refused",
                args: &["action", "-on", "desk", "lock"],
                answer: err("lock is off on desk"),
                sent: Some(("action_on", None)),
                code: 1,
                stderr: "lock is off on desk",
                ..Case::default()
            },
            Case {
                name: "a name without -on",
                args: &["action", "lock"],
                code: 2,
                stderr: "usage: cbb action",
                ..Case::default()
            },
            // Answering anything but yes changes nothing and sends nothing.
            Case {
                name: "enable declined",
                args: &["action", "enable", "reboot", "-by", "root"],
                stdin: "no\n",
                code: 1,
                stdout: "Turning reboot on lets the group's admins of the kinds root whose keys are in hardware",
                ..Case::default()
            },
            Case {
                name: "enable a bad kind",
                args: &["action", "enable", "lock", "-by", "toaster"],
                code: 1,
                stderr: "toaster",
                ..Case::default()
            },
            Case {
                name: "enable with an argument",
                args: &["action", "enable", "lock", "extra"],
                code: 2,
                stderr: "usage: cbb action",
                ..Case::default()
            },
            Case {
                name: "disable with -yes",
                args: &["action", "disable", "lock", "-yes"],
                code: 2,
                stderr: "usage: cbb action",
                ..Case::default()
            },
            Case {
                name: "enable without a name",
                args: &["action", "enable"],
                code: 2,
                stderr: "usage: cbb action",
                ..Case::default()
            },
            Case {
                name: "add declined",
                args: &["action", "add", "backup", "--", "/usr/bin/backup"],
                stdin: "\n",
                code: 1,
                stdout: "run /usr/bin/backup here as the user signed in",
                ..Case::default()
            },
            Case {
                name: "add",
                args: &["action", "add", "backup", "-by", "phone", "-yes", "--", "/usr/bin/backup", "--now"],
                sent: Some((
                    "action_set",
                    Some(|s| {
                        let a = &s.h["actions"];
                        a.as_array().map(|a| a.len()) == Some(1)
                            && a[0]["name"] == "backup"
                            && a[0]["on"] == true
                            && a[0]["command"] == json!(["/usr/bin/backup", "--now"])
                            && a[0]["by"] == json!(["phone"])
                    }),
                )),
                stdout: "backup: on, for phone: /usr/bin/backup --now.",
                ..Case::default()
            },
            Case {
                name: "add with yes typed",
                args: &["action", "add", "backup", "--", "/usr/bin/backup"],
                stdin: "YES\n",
                sent: Some(("action_set", None)),
                stdout: "backup: on, for every admin",
                ..Case::default()
            },
            Case {
                name: "add refused",
                args: &["action", "add", "backup", "-yes", "--", "/usr/bin/backup"],
                answer: err("too many actions"),
                sent: Some(("action_set", None)),
                code: 1,
                stderr: "too many actions",
                ..Case::default()
            },
            Case {
                name: "add without a program",
                args: &["action", "add", "backup", "-yes"],
                code: 1,
                ..Case::default()
            },
            Case {
                name: "add without a name",
                args: &["action", "add"],
                code: 2,
                stderr: "usage: cbb action",
                ..Case::default()
            },
            Case {
                name: "remove",
                args: &["action", "remove", "backup"],
                sent: Some(("action_remove", Some(|s| s.s("name") == "backup"))),
                stdout: "backup is removed.",
                ..Case::default()
            },
            Case {
                name: "remove without a name",
                args: &["action", "remove"],
                code: 2,
                stderr: "usage: cbb action",
                ..Case::default()
            },
            Case {
                name: "off elsewhere",
                args: &["action", "off", "-on", "desk"],
                sent: Some(("actions_off", Some(|s| s.s("device") == "desk" && !s.b("all")))),
                stdout: "off on desk.",
                ..Case::default()
            },
            Case {
                name: "off everywhere",
                args: &["action", "off", "-all"],
                sent: Some(("actions_off", Some(|s| s.b("all")))),
                stdout: "off on every device of the group.",
                ..Case::default()
            },
            Case {
                name: "off with both",
                args: &["action", "off", "-all", "-on", "desk"],
                code: 2,
                stderr: "usage: cbb action",
                ..Case::default()
            },
            Case {
                name: "off refused",
                args: &["action", "off", "-all"],
                answer: err("only admins"),
                sent: Some(("actions_off", None)),
                code: 1,
                stderr: "only admins",
                ..Case::default()
            },
        ],
    );
}

/// Each action's line in cbb action: off, its command, who may run it and
/// whether the key must be in hardware.
#[test]
fn action_lines() {
    let list = in_group(json!({"actions": [
        {"name": "lock"},
        {"name": "backup", "command": ["b", "-x"]},
        {"name": "sleep", "on": true},
        {"name": "reboot", "on": true, "by": ["root"], "any_key": true},
        {"name": "shutdown", "on": true},
    ]}));
    let dir = tempdir("action-lines");
    let r = run_in(&dir, &["action"], "", list, b"");
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(r.code, 0, "{}", r.stderr);
    for want in [
        "lock             off\n",
        "backup           off: b -x\n",
        "sleep            on, for every admin\n",
        "reboot           on, for root\n",
        "shutdown         on, for every admin, keys in hardware only\n",
    ] {
        assert!(r.stdout.contains(want), "{want:?} not in {:?}", r.stdout);
    }
}

/// A handler from a closure.
fn handler(f: impl Fn(&Sent) -> Answers + Send + Sync + 'static) -> Handler {
    Arc::new(f)
}

fn done(mut h: Value) -> (Value, Vec<u8>) {
    h["done"] = json!(true);
    (h, Vec::new())
}

/// Answers a status request in group g (none when empty), and every other
/// request with rest.
fn group_then(g: &'static str, rest: impl Fn(&Sent) -> Answers + Send + Sync + 'static) -> Handler {
    handler(move |s| if s.op() == "status" { vec![done(status(json!({"os": "linux", "group": g})))] } else { rest(s) })
}

/// Checks a run and names the case when it fails.
fn want(what: &str, r: &Run, code: i32, stdout: &str, stderr: &str) {
    assert!(
        r.code == code && r.stdout.contains(stdout) && r.stderr.contains(stderr),
        "{what}: exit code {} (want {code}), stdout {:?} (want {stdout:?}), stderr {:?} (want {stderr:?})",
        r.code,
        r.stdout,
        r.stderr
    );
}

fn ops(r: &Run) -> Vec<&str> {
    r.sent.iter().map(|s| s.op()).collect()
}

#[test]
fn copy() {
    run_cases(
        "copy",
        vec![
            Case {
                name: "copy -secret",
                args: &["copy", "-secret"],
                stdin: "hunter2",
                sent: Some(("copy", Some(|s| s.s("kind") == "secret" && s.payload == b"hunter2"))),
                ..Case::default()
            },
            Case {
                name: "copy",
                args: &["copy"],
                stdin: "plain",
                sent: Some(("copy", Some(|s| matches!(s.s("kind"), "" | "text") && s.payload == b"plain"))),
                ..Case::default()
            },
            // An argument is a file to send, never a text.
            Case {
                name: "copy -secret FILE",
                args: &["copy", "-secret", "hello"],
                code: 2,
                stderr: "not for files",
                ..Case::default()
            },
            Case {
                name: "copy -type without a file",
                args: &["copy", "-type", "png"],
                code: 2,
                stderr: "go with FILE",
                ..Case::default()
            },
            Case {
                name: "copy of a missing file",
                args: &["copy", "no-such-file"],
                code: 1,
                stderr: "no-such-file",
                ..Case::default()
            },
        ],
    );
}

/// cbb pair -code takes the code from standard input, never from the
/// command line: without an address the service joins by the window mDNS
/// finds; with one, cbb joins itself before its service starts.
#[test]
fn pair_with_a_code() {
    run_cases(
        "pair-code",
        vec![
            Case {
                name: "pair -code",
                args: &["pair", "-code"],
                stdin: "123 456\n",
                sent: Some(("join", Some(|s| s.s("code") == "123456"))),
                stdout: "Joined the group",
                ..Case::default()
            },
            Case {
                name: "pair -code ADDRESS",
                args: &["pair", "-code", "127.0.0.1:1"],
                stdin: "123 456\n",
                code: 1,
                stderr: "cannot connect to 127.0.0.1:1",
                ..Case::default()
            },
            Case {
                name: "a code as the address",
                args: &["pair", "-code", "123456"],
                code: 2,
                stderr: "usage",
                ..Case::default()
            },
            Case {
                name: "a code in two",
                args: &["pair", "-code", "123", "456"],
                code: 2,
                stderr: "usage",
                ..Case::default()
            },
            Case {
                name: "an address without -code",
                args: &["pair", "192.168.1.5:4000"],
                code: 2,
                stderr: "usage",
                ..Case::default()
            },
            Case {
                name: "-code after -invite",
                args: &["pair", "-invite", "x", "-code"],
                code: 2,
                stderr: "usage",
                ..Case::default()
            },
            // A bad code fails before the service is asked or the address
            // dialed.
            Case {
                name: "five digits",
                args: &["pair", "-code"],
                stdin: "12345\n",
                code: 1,
                stderr: "six digits",
                ..Case::default()
            },
            Case {
                name: "five digits with an address",
                args: &["pair", "-code", "127.0.0.1:1"],
                stdin: "12345\n",
                code: 1,
                stderr: "six digits",
                ..Case::default()
            },
        ],
    );
}

#[test]
fn new_group() {
    let dir = tempdir("new");
    let r = run_with(&dir, &["new"], "", group_then("g1", |_| vec![done(status(json!({"group": "g1"})))]), &[]);
    want("new", &r, 0, "group g1", "");
    assert!(ops(&r).contains(&"new"), "new sent {:?}", ops(&r));
    let r = run_in(&dir, &["new", "x"], "", json!({}), b"");
    want("new with an argument", &r, 2, "", "");
    let _ = std::fs::remove_dir_all(&dir);
}

/// cbb pair in a group opens a window and shows its code and address.
#[test]
fn pair_in_a_group() {
    let dir = tempdir("pair-group");
    let r = run_with(
        &dir,
        &["pair"],
        "",
        group_then("g1", |_| {
            vec![
                (json!({"code": "123456", "expires": 300, "address": "192.168.1.5:8764"}), Vec::new()),
                done(json!({"name": "deck"})),
            ]
        }),
        &[],
    );
    let _ = std::fs::remove_dir_all(&dir);
    want("pair", &r, 0, "Pairing code: 123 456", "");
    want("pair", &r, 0, "cbb pair -code 192.168.1.5:8764", "");
    want("pair", &r, 0, "deck joined", "");
    assert_eq!(ops(&r).first(), Some(&"status"), "pair asked first {:?}", ops(&r));
    assert!(ops(&r).contains(&"pair"), "pair sent {:?}", ops(&r));
}

/// In no group cbb pair listens for the phone itself and shows a QR code
/// with its code, addresses and fingerprint, and the same as text to paste
/// into the app; this test stops it while it waits.
#[test]
fn pair_shows_the_phone_a_code() {
    let dir = tempdir("pair-phone");
    let sock = dir.join("control.sock");
    serve(UnixListener::bind(&sock).unwrap(), always(json!({}), b""), Arc::new(Mutex::new(Vec::new())));
    let mut child = Command::new(env!("CARGO_BIN_EXE_cbb"))
        .args(["pair", "-port", "0", "-addr", "192.0.2.7"])
        .env("CBB_SOCKET", &sock)
        .env("CBB_STATE", dir.join("state"))
        .env("LC_ALL", "C")
        .env("HOME", &dir)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut out = String::new();
    let mut r = BufReader::new(child.stdout.take().unwrap());
    let mut line = String::new();
    while r.read_line(&mut line).unwrap_or(0) > 0 {
        out.push_str(&line);
        line.clear();
        if out.contains("Waiting up to 5 minutes") {
            break;
        }
    }
    child.kill().ok();
    child.wait().ok();
    let _ = std::fs::remove_dir_all(&dir);
    assert!(out.contains("Scan a code") && out.contains("\x1b["), "no QR code: {out:?}");
    let link = out
        .lines()
        .find_map(|l| l.strip_prefix("Or paste this into the app: "))
        .unwrap_or_else(|| panic!("no link: {out:?}"));
    let code = link.split("code=").nth(1).map(|c| c.split('&').next().unwrap()).unwrap_or("");
    assert!(link.starts_with("cbb://join?"), "{link}");
    assert!(code.len() == 6 && code.bytes().all(|b| b.is_ascii_digit()), "the code in {link}");
    assert!(link.contains("addr=192.0.2.7%3A") && link.contains("&fp="), "{link}");
}

#[test]
fn status_lines() {
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as i64;
    let dir = tempdir("status");
    for (st, want_line) in [
        (json!({"os": "linux"}), "Run cbb new here to start one"),
        (json!({"os": "macos"}), "Run cbb new here to start one"),
        (json!({"os": "windows", "device": "d1", "group": "g1"}), "Device d1 (Windows, full), group g1"),
        (
            json!({"os": "macos", "device": "d2", "group": "g1", "removed": true}),
            "This device was removed from the group",
        ),
        (json!({"os": "linux", "device": "d2", "group": "g1", "frozen": true}), "froze this computer's admin key"),
        (
            json!({"os": "linux", "device": "d3", "group": "g1", "cert_ends_ms": now - 3_600_000}),
            "This device's certificate ended on",
        ),
        (
            json!({"os": "linux", "device": "d3", "group": "g1", "cert_ends_ms": now + 7 * 86_400_000}),
            "no admin has renewed it",
        ),
        (json!({"os": "linux", "group": "g1", "mode": "shared"}), "the group's copies come here."),
        (json!({"os": "linux", "group": "g1", "mode": "own"}), "Sync is off until cbb sync on"),
        (
            json!({"os": "linux", "group": "g1", "mode": "own", "sync_until_ms": 1_800_000_000_000i64}),
            "Sync is off until 20",
        ),
        (json!({"os": "linux", "group": "g1", "quiet": ["wlan0", "eth1"]}), "Quiet on wlan0, eth1"),
    ] {
        let r = run_in(&dir, &["status"], "", status(st.clone()), b"");
        want(&format!("status of {st}"), &r, 0, want_line, "");
    }
    // A certificate with a year left, or none, gets no line; quiet
    // interfaces in no group neither.
    for st in [
        json!({"os": "linux", "device": "d3", "group": "g1", "cert_ends_ms": now + 365 * 86_400_000}),
        json!({"os": "linux", "device": "d3", "group": "g1"}),
    ] {
        let r = run_in(&dir, &["status"], "", status(st.clone()), b"");
        assert!(r.code == 0 && !r.stdout.contains("certificate"), "status of {st}: {:?}", r.stdout);
    }
    let r = run_in(&dir, &["status"], "", status(json!({"os": "linux", "quiet": ["wlan0"]})), b"");
    assert!(r.code == 0 && !r.stdout.contains("Quiet"), "quiet in no group: {:?}", r.stdout);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn paste_write_error() {
    let dir = tempdir("paste-full");
    let sock = dir.join("control.sock");
    serve(UnixListener::bind(&sock).unwrap(), always(json!({}), b"text"), Arc::new(Mutex::new(Vec::new())));
    let out = Command::new(env!("CARGO_BIN_EXE_cbb"))
        .arg("paste")
        .env("CBB_SOCKET", &sock)
        .env("LC_ALL", "C")
        .stdout(std::fs::OpenOptions::new().write(true).open("/dev/full").unwrap())
        .output()
        .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.code() == Some(1) && stderr.contains("No space"),
        "paste to a full disk: {:?}, {stderr:?}",
        out.status
    );
}

#[test]
fn paste_terminal() {
    let dir = tempdir("paste-terminal");
    let secret = || handler(|_| vec![(json!({"kind": "secret", "done": true}), b"hunter2\n".to_vec())]);
    let r = run_with(&dir, &["paste", "-terminal"], "", secret(), &[]);
    assert!(r.code == 1 && r.stdout.is_empty(), "a secret without -secret: {} {:?} {:?}", r.code, r.stdout, r.stderr);
    let r = run_with(&dir, &["paste", "-terminal", "-secret"], "", secret(), &[]);
    assert!(r.code == 0 && r.stdout == "hunter2", "a secret with -secret: {} {:?}", r.code, r.stdout);
    let r = run_in(&dir, &["paste", "-terminal"], "", json!({}), b"cd /tmp\nrm -rf *\n");
    assert!(
        r.code == 0 && r.stdout == "cd /tmp" && r.stderr.contains("1 more"),
        "two lines: {} {:?} {:?}",
        r.code,
        r.stdout,
        r.stderr
    );
    let r = run_in(&dir, &["paste", "-lines"], "", json!({}), b"");
    want("-lines without -terminal", &r, 2, "", "");
    let _ = std::fs::remove_dir_all(&dir);
}

/// An error's cause shows in debug mode only, which CBB_DEBUG turns on and
/// off.
#[test]
fn fail_details() {
    let dir = tempdir("fail");
    for (debug, detail) in [("0", false), ("1", true)] {
        let out = Command::new(env!("CARGO_BIN_EXE_cbb"))
            .arg("status")
            .env("CBB_SOCKET", dir.join("none.sock"))
            .env("CBB_DEBUG", debug)
            .env("LC_ALL", "C")
            .output()
            .unwrap();
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(1), "{stderr}");
        assert!(stderr.contains("cannot reach"), "CBB_DEBUG={debug}: {stderr:?}");
        assert_eq!(stderr.contains("details:"), detail, "CBB_DEBUG={debug}: {stderr:?}");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn paste_receive_flags() {
    let answer =
        || json!({"status": {"device": "d1", "role": "full", "version": "0.6.0", "port": 0, "paste": {"on": true}}});
    run_cases(
        "paste_receive",
        vec![
            // The usage's order, on before its flags, and the flags first.
            Case {
                name: "on, then flags",
                args: &["paste-receive", "on", "-console", "-enter"],
                answer: answer(),
                sent: Some(("paste_receive", Some(|s| s.s("name") == "on" && s.b("console") && s.b("enter")))),
                ..Case::default()
            },
            Case {
                name: "flags, then on",
                args: &["paste-receive", "-console", "-enter", "on"],
                answer: answer(),
                sent: Some(("paste_receive", Some(|s| s.s("name") == "on" && s.b("console") && s.b("enter")))),
                ..Case::default()
            },
            Case {
                name: "off elsewhere",
                args: &["paste-receive", "off", "-on", "deck"],
                answer: answer(),
                sent: Some(("paste_receive", Some(|s| s.s("name") == "off" && s.s("device") == "deck"))),
                ..Case::default()
            },
            Case { name: "on and off", args: &["paste-receive", "on", "off"], code: 2, ..Case::default() },
            Case { name: "a flag alone", args: &["paste-receive", "-console"], code: 2, ..Case::default() },
            Case {
                name: "an extra argument",
                args: &["paste-receive", "on", "-console", "x"],
                code: 2,
                ..Case::default()
            },
        ],
    );
}

fn leak(s: String) -> &'static str {
    Box::leak(s.into_boxed_str())
}

#[test]
fn remote_commands() {
    let tvs = || {
        status(json!({"tvs": [
            {"name": "Living room", "kind": "androidtv", "host": "10.0.0.5", "pastes": true},
            {"name": "Bedroom", "kind": "roku", "host": "10.0.0.6"},
            {"kind": "androidtv", "host": "10.0.0.7", "pairing": true},
            {"name": "Lounge", "kind": "appletv", "host": "10.0.0.9"},
            {"kind": "appletv", "host": "10.0.0.10", "pairing": true},
        ]}))
    };
    run_cases(
        "remote",
        vec![
            Case {
                name: "list",
                args: &["remote"],
                answer: tvs(),
                sent: Some(("remote", Some(|s| s.s("name").is_empty()))),
                stdout: "Living room (Android TV) at 10.0.0.5: remote pastes go to it.\nBedroom (Roku, plain HTTP) at 10.0.0.6.\nPairing with the TV at 10.0.0.7: it shows a code for cbb remote code.\nLounge (Apple TV) at 10.0.0.9.\nPairing with the TV at 10.0.0.10: it shows a PIN",
                ..Case::default()
            },
            Case {
                name: "list of none",
                args: &["remote"],
                sent: Some(("remote", None)),
                stdout: "the remote of no TV",
                ..Case::default()
            },
            Case {
                name: "add an Android TV",
                args: &["remote", "add", "-name", "Den", "10.0.0.8"],
                sent: Some((
                    "remote",
                    Some(|s| {
                        s.s("name") == "add"
                            && s.s("address") == "10.0.0.8"
                            && s.s("new_name") == "Den"
                            && s.s("value").is_empty()
                            && !s.b("consent")
                    }),
                )),
                stdout: "The TV shows a code now",
                ..Case::default()
            },
            Case {
                name: "add an Apple TV",
                args: &["remote", "add", "-appletv", "10.0.0.9"],
                sent: Some((
                    "remote",
                    Some(|s| s.s("name") == "add" && s.s("value") == "appletv" && s.s("address") == "10.0.0.9"),
                )),
                stdout: "The Apple TV shows a PIN now",
                ..Case::default()
            },
            Case {
                name: "an Apple TV and a Roku",
                args: &["remote", "add", "-appletv", "-roku", "10.0.0.9"],
                code: 2,
                stderr: "usage: cbb remote",
                ..Case::default()
            },
            // Flags may follow the words.
            Case {
                name: "add a Roku",
                args: &["remote", "add", "10.0.0.6", "-roku", "-consent"],
                answer: tvs(),
                sent: Some((
                    "remote",
                    Some(|s| s.s("value") == "roku" && s.b("consent") && s.s("address") == "10.0.0.6"),
                )),
                stdout: "Bedroom (Roku",
                ..Case::default()
            },
            Case {
                name: "code",
                args: &["remote", "code", "A1B2C3"],
                sent: Some(("remote", Some(|s| s.s("name") == "code" && s.s("code") == "A1B2C3"))),
                ..Case::default()
            },
            Case {
                name: "cancel",
                args: &["remote", "cancel"],
                sent: Some(("remote", Some(|s| s.s("name") == "cancel"))),
                ..Case::default()
            },
            Case {
                name: "remove",
                args: &["remote", "remove", "Bedroom"],
                sent: Some(("remote", Some(|s| s.s("device") == "Bedroom"))),
                ..Case::default()
            },
            Case {
                name: "pastes on",
                args: &["remote", "pastes", "Den", "on"],
                sent: Some(("remote", Some(|s| s.s("device") == "Den" && s.s("value") == "on"))),
                ..Case::default()
            },
            Case {
                name: "type",
                args: &["remote", "type", "-tv", "Den", "hello"],
                sent: Some(("remote", Some(|s| s.s("device") == "Den" && s.payload == b"hello"))),
                stdout: "Typed.",
                ..Case::default()
            },
            Case {
                name: "type from stdin",
                args: &["remote", "type"],
                stdin: "from stdin\n",
                sent: Some(("remote", Some(|s| s.payload == b"from stdin"))),
                stdout: "Typed.",
                ..Case::default()
            },
            Case {
                name: "refused",
                args: &["remote", "code", "000000"],
                answer: err("the TV took no code"),
                sent: Some(("remote", None)),
                code: 1,
                stderr: "took no code",
                ..Case::default()
            },
            Case {
                name: "pastes maybe",
                args: &["remote", "pastes", "Den", "maybe"],
                code: 2,
                stderr: "usage: cbb remote",
                ..Case::default()
            },
            Case {
                name: "roku without add",
                args: &["remote", "-roku"],
                code: 2,
                stderr: "usage: cbb remote",
                ..Case::default()
            },
            Case {
                name: "tv without type",
                args: &["remote", "cancel", "-tv", "Den"],
                code: 2,
                stderr: "usage: cbb remote",
                ..Case::default()
            },
            Case {
                name: "add without an address",
                args: &["remote", "add"],
                code: 2,
                stderr: "usage: cbb remote",
                ..Case::default()
            },
            Case { name: "code without one", args: &["remote", "code"], code: 2, ..Case::default() },
            Case { name: "cancel with an argument", args: &["remote", "cancel", "x"], code: 2, ..Case::default() },
            Case { name: "remove without a TV", args: &["remote", "remove"], code: 2, ..Case::default() },
            Case { name: "type with two texts", args: &["remote", "type", "a", "b"], code: 2, ..Case::default() },
            Case { name: "list with an argument", args: &["remote", "", "x"], code: 2, ..Case::default() },
            Case {
                name: "an unknown verb",
                args: &["remote", "volume"],
                code: 2,
                stderr: "usage: cbb remote",
                ..Case::default()
            },
        ],
    );
}

#[test]
fn keyboard_commands() {
    let on =
        || status(json!({"keyboard": {"on": true, "layout": "ru", "rate": 30, "pastes": true, "connected": true}}));
    run_cases(
        "keyboard",
        vec![
            Case {
                name: "status",
                args: &["keyboard"],
                answer: on(),
                sent: Some(("keyboard", Some(|s| s.s("name").is_empty()))),
                stdout: "on, typing in the ru layout at 30 characters a second; remote pastes go to the device it types into. A device is connected.",
                ..Case::default()
            },
            Case {
                name: "on",
                args: &["keyboard", "-layout", "ru", "-rate", "30", "-pastes", "on"],
                answer: on(),
                sent: Some((
                    "keyboard",
                    Some(|s| {
                        s.s("name") == "on"
                            && s.h["keyboard"]["layout"] == "ru"
                            && s.h["keyboard"]["rate"] == 30
                            && s.h["keyboard"]["pastes"] == true
                    }),
                )),
                ..Case::default()
            },
            Case {
                name: "off",
                args: &["keyboard", "off"],
                answer: status(json!({"keyboard": {}})),
                sent: Some(("keyboard", Some(|s| s.s("name") == "off" && s.h["keyboard"].is_null()))),
                stdout: "The Bluetooth keyboard is off",
                ..Case::default()
            },
            Case {
                name: "on before its flags",
                args: &["keyboard", "on", "-layout", "us"],
                answer: on(),
                sent: Some((
                    "keyboard",
                    Some(|s| {
                        s.s("name") == "on"
                            && s.h["keyboard"]["layout"] == "us"
                            && s.h["keyboard"]["rate"].as_i64().unwrap_or(0) == 0
                            && s.h["keyboard"]["pastes"] != true
                    }),
                )),
                ..Case::default()
            },
            Case {
                name: "type a text like a flag",
                args: &["keyboard", "type", "-rate"],
                sent: Some(("keyboard", Some(|s| s.payload == b"-rate"))),
                stdout: "Typed.",
                ..Case::default()
            },
            Case {
                name: "pair",
                args: &["keyboard", "pair"],
                answer: on(),
                sent: Some(("keyboard", Some(|s| s.s("name") == "pair"))),
                ..Case::default()
            },
            Case {
                name: "type",
                args: &["keyboard", "type", "hi"],
                sent: Some(("keyboard", Some(|s| s.payload == b"hi"))),
                stdout: "Typed.",
                ..Case::default()
            },
            Case {
                name: "type from stdin",
                args: &["keyboard", "type"],
                stdin: "typed\n",
                sent: Some(("keyboard", Some(|s| s.payload == b"typed"))),
                ..Case::default()
            },
            Case {
                name: "no keyboard here",
                args: &["keyboard"],
                answer: status(json!({})),
                sent: Some(("keyboard", None)),
                code: 1,
                stderr: "cannot be a Bluetooth keyboard",
                ..Case::default()
            },
            Case {
                name: "refused",
                args: &["keyboard", "pair"],
                answer: err("Bluetooth is off"),
                sent: Some(("keyboard", None)),
                code: 1,
                stderr: "Bluetooth is off",
                ..Case::default()
            },
            Case {
                name: "layout without on",
                args: &["keyboard", "-layout", "us", "off"],
                code: 2,
                stderr: "usage: cbb keyboard",
                ..Case::default()
            },
            Case {
                name: "unknown verb",
                args: &["keyboard", "loud"],
                code: 2,
                stderr: "usage: cbb keyboard",
                ..Case::default()
            },
            // What the keyboard's line says when it does not run, and while
            // new devices find it.
            Case {
                name: "a problem",
                args: &["keyboard"],
                answer: status(
                    json!({"keyboard": {"on": true, "layout": "us", "rate": 20, "problem": "no Bluetooth adapter"}}),
                ),
                sent: Some(("keyboard", None)),
                stdout: ".\nIt does not run: no Bluetooth adapter",
                ..Case::default()
            },
            Case {
                name: "visible",
                args: &["keyboard"],
                answer: status(
                    json!({"keyboard": {"on": true, "layout": "us", "rate": 20, "visible_until_ms": 4_102_444_800_000i64}}),
                ),
                sent: Some(("keyboard", None)),
                stdout: "No device is connected; pair one with cbb keyboard pair, then connect it from the device. New devices find it until ",
                ..Case::default()
            },
        ],
    );
}

#[test]
fn paste_on_another_device() {
    run_cases(
        "paste_on",
        vec![
            Case {
                name: "paste",
                args: &["paste", "-on", "desk"],
                stdin: "hello",
                sent: Some((
                    "paste_on",
                    Some(|s| {
                        s.s("device") == "desk"
                            && s.s("method") == "paste"
                            && matches!(s.s("kind"), "" | "text")
                            && !s.b("enter")
                            && s.payload == b"hello"
                    }),
                )),
                stdout: "Pasted on desk.",
                ..Case::default()
            },
            Case {
                name: "typed secret with Enter",
                args: &["paste", "-on", "desk", "-type", "-enter", "-secret"],
                stdin: "pw",
                sent: Some(("paste_on", Some(|s| s.s("method") == "type" && s.s("kind") == "secret" && s.b("enter")))),
                ..Case::default()
            },
            Case {
                name: "too long to type",
                args: &["paste", "-on", "desk", "-type"],
                stdin: leak("x".repeat((4 << 10) + 1)),
                code: 1,
                stderr: "too long to type",
                ..Case::default()
            },
            Case {
                name: "larger than 1 MiB",
                args: &["paste", "-on", "desk"],
                stdin: leak("x".repeat((1 << 20) + 1)),
                code: 1,
                stderr: "larger than 1 MiB",
                ..Case::default()
            },
            Case {
                name: "refused",
                args: &["paste", "-on", "desk"],
                stdin: "x",
                answer: err("remote paste is off on desk"),
                sent: Some(("paste_on", None)),
                code: 1,
                stderr: "off on desk",
                ..Case::default()
            },
        ],
    );
}

/// How cbb global tells each state of sync away from home: the hub, its
/// forwarder, the relay and the client's way to the hub; an error's detail
/// only in debug mode.
#[test]
fn away_states() {
    let dir = tempdir("away");
    for (name, debug, away, want, not) in [
        (
            "a hub reached directly",
            "",
            json!({"hub": true, "port": 8764, "clients": 3, "obfuscated": true, "endpoints": ["203.0.113.7:8764"]}),
            &[
                "this device is the hub, on UDP port 8764, for 3 devices.",
                "Obfuscated",
                "Reached at 203.0.113.7:8764.",
                "forward UDP port 8764",
            ][..],
            &[][..],
        ),
        (
            "a hub without an address",
            "",
            json!({"hub": true, "port": 8764}),
            &["The hub has no address away from home"][..],
            &[][..],
        ),
        (
            "registered, port seen",
            "",
            json!({"hub": true, "port": 8764, "vless": true, "forwarder": {"endpoint": "198.51.100.9:8764", "registered": true, "seen": "203.0.113.7:40000"}}),
            &[
                "reach the forwarder over VLESS, which looks like HTTPS",
                "Registered with the forwarder at 198.51.100.9:8764, which reaches this hub at 203.0.113.7:40000.",
            ][..],
            &["tunnel goes inside VLESS"][..],
        ),
        (
            "registered, port not heard",
            "",
            json!({"hub": true, "forwarder": {"endpoint": "f:1", "registered": true}}),
            &["it has not heard the hub's UDP port yet"][..],
            &[][..],
        ),
        (
            "registering",
            "",
            json!({"hub": true, "forwarder": {"endpoint": "f:1"}}),
            &["Registering with the forwarder at f:1."][..],
            &[][..],
        ),
        (
            "not registered, release",
            "0",
            json!({"hub": true, "forwarder": {"endpoint": "f:1", "error": "the forwarder refused the group", "detail": "tls: bad certificate"}}),
            &["Not registered with the forwarder at f:1: the forwarder refused the group."][..],
            &["bad certificate"][..],
        ),
        (
            "not registered, debug",
            "1",
            json!({"hub": true, "forwarder": {"endpoint": "f:1", "error": "the forwarder refused the group", "detail": "tls: bad certificate"}}),
            &["tls: bad certificate"][..],
            &[][..],
        ),
        (
            "a standby hub looking",
            "",
            json!({"hub": true, "standby": true}),
            &["It looks for the hubs above it, and serves if none answers."][..],
            &[][..],
        ),
        (
            "a standby hub with a forwarder",
            "",
            json!({"hub": true, "standby": true, "hub_device": "deck", "port": 8764, "forwarder": {"endpoint": "198.51.100.9:8764", "error": "the hub is not running"}}),
            &["stands by as its client"][..],
            &["this device is the hub", "not running"][..],
        ),
        (
            "relay, through",
            "",
            json!({"through": true, "relay": {"endpoint": "r:1", "connected": true, "online": ["a"]}}),
            &["connected to the relay at r:1 and through it to other devices."][..],
            &[][..],
        ),
        (
            "relay, alone",
            "",
            json!({"relay": {"endpoint": "r:1", "connected": true}}),
            &["no other device of the group is there now."][..],
            &[][..],
        ),
        (
            "relay, with others",
            "",
            json!({"relay": {"endpoint": "r:1", "connected": true, "online": ["a", "b"]}}),
            &["with 2 other devices of the group there."][..],
            &[][..],
        ),
        (
            "relay, connecting",
            "",
            json!({"relay": {"endpoint": "r:1"}}),
            &["connecting to the relay at r:1."][..],
            &[][..],
        ),
        (
            "relay, failed, debug",
            "1",
            json!({"relay": {"endpoint": "r:1", "error": "the relay is full", "detail": "quota"}}),
            &["not connected to the relay at r:1: the relay is full.", "quota"][..],
            &[][..],
        ),
        (
            "relay, failed, release",
            "0",
            json!({"relay": {"endpoint": "r:1", "error": "the relay is full", "detail": "quota"}}),
            &[][..],
            &["quota"][..],
        ),
        ("waiting for the hub", "", json!({}), &["waiting to meet the group's hub on the home network"][..], &[][..]),
        (
            "through the tunnel",
            "",
            json!({"hub_device": "deck", "through": true}),
            &["connected to the hub deck through the tunnel."][..],
            &[][..],
        ),
        (
            "over VLESS",
            "",
            json!({"hub_device": "deck", "vless": true}),
            &["reached over VLESS through its forwarder", "the tunnel goes inside VLESS"][..],
            &[][..],
        ),
        (
            "a problem, keys in files",
            "0",
            json!({"hub_device": "abc", "endpoints": ["203.0.113.7:8764"], "keys_in_file": true, "error": "the hub did not answer at 203.0.113.7:8764", "detail": "i/o timeout"}),
            &["the hub did not answer"][..],
            &["keys in files", "i/o timeout"][..],
        ),
    ] {
        let mut env = vec![];
        if !debug.is_empty() {
            env.push(("CBB_DEBUG", debug));
        }
        let r = run_with(&dir, &["global"], "", always(in_group(json!({"away": away})), b""), &env);
        assert_eq!(r.code, 0, "{name}: {:?}", r.stderr);
        for w in want {
            assert!(r.stdout.contains(w), "{name}: no {w:?} in {:?}", r.stdout);
        }
        for w in not {
            assert!(!r.stdout.contains(w), "{name}: {w:?} in {:?}", r.stdout);
        }
    }
    let r = run_in(&dir, &["global"], "", in_group(json!({})), b"");
    want("off", &r, 0, "Sync away from home: off", "");
    let _ = std::fs::remove_dir_all(&dir);
}

/// cbb global's commands. The project's own servers are a name that needs
/// DNS, which global_cli's project_servers and addresses check without the
/// network; these cases name addresses.
#[test]
fn global_commands() {
    let away = |a: Value| in_group(json!({ "away": a }));
    run_cases(
        "global",
        vec![
            Case {
                name: "status",
                args: &["global"],
                answer: away(json!({"hub_device": "deck", "through": true})),
                sent: Some(("status", None)),
                stdout: "connected to the hub deck",
                ..Case::default()
            },
            Case {
                name: "status in no group",
                args: &["global"],
                answer: status(json!({})),
                sent: Some(("status", None)),
                code: 1,
                stderr: "in no group",
                ..Case::default()
            },
            Case {
                name: "on, declined",
                args: &["global", "on"],
                stdin: "no\n",
                code: 1,
                stdout: "Nothing changed.",
                ..Case::default()
            },
            Case {
                name: "on",
                args: &["global", "on"],
                stdin: "yes\n",
                answer: away(json!({})),
                sent: Some(("away", Some(|s| s.s("name") == "on" && s.b("consent")))),
                stdout: "waiting to meet the group's hub",
                ..Case::default()
            },
            Case {
                name: "off elsewhere",
                args: &["global", "off", "-on", "tv"],
                sent: Some(("away", Some(|s| s.s("name") == "off" && s.s("device") == "tv"))),
                ..Case::default()
            },
            Case {
                name: "hub",
                args: &[
                    "global",
                    "hub",
                    "-port",
                    "9000",
                    "-firewall",
                    "no",
                    "-no-obfuscate",
                    "-no-vless",
                    "203.0.113.7:9000",
                ],
                answer: away(json!({"hub": true, "port": 9000, "endpoints": ["203.0.113.7:9000"]})),
                sent: Some((
                    "away",
                    Some(|s| {
                        s.s("name") == "hub"
                            && s.i("port") == 9000
                            && s.b("obfuscate_off")
                            && s.b("vless_off")
                            && s.list("addrs") == ["203.0.113.7:9000"]
                    }),
                )),
                stdout: "The hub does not have to stay on.",
                ..Case::default()
            },
            Case {
                name: "hub through a forwarder",
                args: &[
                    "global",
                    "hub",
                    "-firewall",
                    "no",
                    "-forwarder",
                    "198.51.100.9:8764",
                    "-forwarder-key",
                    "KEY",
                    "-no-vless",
                ],
                sent: Some((
                    "away",
                    Some(|s| {
                        s.s("forwarder") == "198.51.100.9:8764"
                            && s.s("forwarder_key") == "KEY"
                            && s.b("vless_off")
                            && !s.b("obfuscate_off")
                            && s.list("addrs").is_empty()
                    }),
                )),
                ..Case::default()
            },
            Case {
                name: "the project's forwarder takes no key",
                args: &["global", "hub", "-forwarder", "default", "-forwarder-key", "K"],
                code: 1,
                stderr: "takes no -forwarder-key",
                ..Case::default()
            },
            Case {
                name: "default is no key of another forwarder",
                args: &["global", "hub", "-forwarder", "198.51.100.9:8764", "-forwarder-key", "default"],
                code: 1,
                stderr: "goes with -forwarder default",
                ..Case::default()
            },
            Case {
                name: "hub with sync away from home, declined",
                args: &["global", "hub", "-away-on", "203.0.113.7:9000"],
                stdin: "no\n",
                code: 1,
                stdout: "Nothing changed.",
                ..Case::default()
            },
            Case {
                name: "hub off",
                args: &["global", "hub", "off"],
                answer: away(json!({})),
                sent: Some(("away", Some(|s| s.s("name") == "hub-off" && s.s("device").is_empty() && !s.b("force")))),
                stdout: "no hub of the group any more",
                ..Case::default()
            },
            Case {
                name: "hub off anyway elsewhere",
                args: &["global", "hub", "off", "-on", "desk", "-yes"],
                sent: Some(("away", Some(|s| s.s("name") == "hub-off" && s.s("device") == "desk" && s.b("force")))),
                stdout: "desk is no hub of the group any more.",
                ..Case::default()
            },
            Case {
                name: "hub off takes no address",
                args: &["global", "hub", "off", "203.0.113.8:8764"],
                code: 2,
                ..Case::default()
            },
            Case {
                name: "hub elsewhere at an address",
                args: &["global", "hub", "-on", "desk", "203.0.113.8:8764"],
                sent: Some((
                    "away",
                    Some(|s| {
                        s.s("name") == "hub"
                            && s.s("device") == "desk"
                            && s.s("forwarder").is_empty()
                            && s.list("addrs") == ["203.0.113.8:8764"]
                    }),
                )),
                stdout: "desk is a hub of the group now.",
                ..Case::default()
            },
            Case {
                name: "hub elsewhere takes none of this hub's settings",
                args: &["global", "hub", "-on", "desk", "-no-obfuscate"],
                code: 2,
                stderr: "-on takes only",
                ..Case::default()
            },
            Case {
                name: "hub keeps its settings",
                args: &["global", "hub", "-firewall", "no", "-keep", "-no-obfuscate"],
                sent: Some((
                    "away",
                    Some(|s| {
                        s.s("name") == "hub"
                            && s.b("keep")
                            && s.b("obfuscate_off")
                            && s.s("forwarder").is_empty()
                            && s.list("addrs").is_empty()
                    }),
                )),
                ..Case::default()
            },
            Case {
                name: "-keep is for this hub",
                args: &["global", "hub", "-on", "desk", "-keep"],
                code: 2,
                stderr: "-keep changes this hub",
                ..Case::default()
            },
            Case {
                name: "hub with a strange firewall",
                args: &["global", "hub", "-firewall", "maybe", "a:1"],
                code: 2,
                ..Case::default()
            },
            Case {
                name: "move",
                args: &["global", "move", "desk", "203.0.113.8:8764"],
                sent: Some(("away", Some(|s| s.s("device") == "desk" && s.list("addrs") == ["203.0.113.8:8764"]))),
                ..Case::default()
            },
            Case {
                name: "move without a device",
                args: &["global", "move", "-forwarder", "x:1"],
                code: 2,
                ..Case::default()
            },
            Case {
                name: "relay, declined",
                args: &["global", "relay", "198.51.100.9:8765", "-key", "K"],
                stdin: "no\n",
                answer: away(json!({})),
                code: 1,
                stdout: "A blind relay is a meeting point",
                ..Case::default()
            },
            Case {
                name: "relay",
                args: &["global", "relay", "-key", "K", "-yes", "198.51.100.9:8765"],
                sent: Some((
                    "away",
                    Some(|s| s.s("relay") == "198.51.100.9:8765" && s.s("relay_key") == "K" && s.b("consent")),
                )),
                ..Case::default()
            },
            Case {
                name: "relay without a key",
                args: &["global", "relay", "198.51.100.9:8765"],
                code: 2,
                ..Case::default()
            },
            Case {
                name: "the project's relay takes no key",
                args: &["global", "relay", "default", "-key", "K"],
                code: 2,
                stderr: "takes no -key",
                ..Case::default()
            },
            Case {
                name: "default is no key of another relay",
                args: &["global", "relay", "198.51.100.9:8765", "-key", "default"],
                code: 2,
                stderr: "goes with the project's relay",
                ..Case::default()
            },
            Case { name: "allow with an argument", args: &["global", "allow", "x"], code: 2, ..Case::default() },
            Case { name: "on with an argument", args: &["global", "on", "x"], code: 2, ..Case::default() },
            Case {
                name: "refused",
                args: &["global", "on"],
                stdin: "yes\n",
                answer: err("this device is in no group"),
                sent: Some(("away", None)),
                code: 1,
                stderr: "in no group",
                ..Case::default()
            },
            Case {
                name: "unknown",
                args: &["global", "sideways"],
                code: 2,
                stderr: "usage: cbb global",
                ..Case::default()
            },
        ],
    );
}

/// cbb invite writes the invitation to a file of its own, asks before each
/// device that uses it, and deletes the file at the end.
#[test]
fn invite() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let dir = tempdir("invite");
    let out = dir.join("guest.cbb");
    let seen = Arc::new(Mutex::new(None::<String>));
    let answers = Arc::new(AtomicUsize::new(0));
    let (o, sn, n) = (out.clone(), seen.clone(), answers.clone());
    let joining = json!({"joining": {"id": "0123456789abcdef", "name": "stranger", "os": "linux", "fingerprint": "sha256:00112233445566778899"}});
    let h = handler(move |s| match s.op() {
        "invite" => {
            vec![(json!({"invite": "the-invitation", "expires": 3600}), Vec::new()), (joining.clone(), Vec::new())]
        }
        "answer" => {
            // The command wrote the file before it read what came.
            sn.lock().unwrap().get_or_insert_with(|| std::fs::read_to_string(&o).unwrap_or_default());
            if n.fetch_add(1, Ordering::SeqCst) == 0 {
                vec![(joining.clone(), Vec::new())]
            } else {
                vec![done(json!({"name": "stranger"}))]
            }
        }
        _ => vec![done(json!({}))],
    });
    let r = run_with(&dir, &["invite", "-for", "2h", "-o", out.to_str().unwrap()], "no\nyes\n", h, &[]);
    assert_eq!(r.code, 0, "{:?} {:?}", r.stdout, r.stderr);
    let inv = r.sent.iter().find(|s| s.op() == "invite").expect("no invite");
    assert_eq!(inv.i("expires"), 7200, "{:?}", inv.h);
    let a: Vec<&Sent> = r.sent.iter().filter(|s| s.op() == "answer").collect();
    assert!(
        a.len() == 2 && !a[0].b("consent") && a[1].b("consent"),
        "the answers: {:?}",
        a.iter().map(|s| &s.h).collect::<Vec<_>>()
    );
    assert_eq!(seen.lock().unwrap().as_deref(), Some("the-invitation\n"));
    assert!(!out.exists(), "the invitation file is still there");
    for w in [
        format!("cbb pair -invite {}", out.display()),
        "stranger (Linux, device 0123456789abcdef) used the invitation".into(),
        "Not admitted.".into(),
        "stranger joined the group.".into(),
    ] {
        assert!(r.stdout.contains(&w), "no {w:?} in {:?}", r.stdout);
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn invite_refusals() {
    let dir = tempdir("invite-taken");
    let existing = dir.join("taken.cbb");
    std::fs::write(&existing, "mine").unwrap();
    let path = leak(existing.to_str().unwrap().to_string());
    run_cases(
        "invite-refusals",
        vec![
            Case {
                name: "more than a day",
                args: &["invite", "-for", "25h"],
                code: 2,
                stderr: "valid for up to 24h",
                ..Case::default()
            },
            Case { name: "no time", args: &["invite", "-for", "0s"], code: 2, ..Case::default() },
            Case { name: "an argument", args: &["invite", "x"], code: 2, ..Case::default() },
            Case {
                name: "refused",
                args: &["invite"],
                answer: err("only an admin invites"),
                sent: Some(("invite", None)),
                code: 1,
                stderr: "only an admin invites",
                ..Case::default()
            },
            // A file already there is never overwritten.
            Case {
                name: "the file is there",
                args: leak_args(&["invite", "-o", path]),
                answer: json!({"invite": "x", "expires": 60}),
                sent: Some(("invite", None)),
                code: 1,
                stderr: "writing the invitation",
                ..Case::default()
            },
        ],
    );
    assert_eq!(std::fs::read_to_string(&existing).unwrap(), "mine");
    let _ = std::fs::remove_dir_all(&dir);
}

fn leak_args(a: &[&'static str]) -> &'static [&'static str] {
    Box::leak(a.to_vec().into_boxed_slice())
}

#[test]
fn config_command() {
    let media = || in_group(json!({"media": {"max_copy": 200 << 20, "max_copy_away": 20 << 20}}));
    run_cases(
        "config",
        vec![
            Case {
                name: "show",
                args: &["config"],
                answer: media(),
                sent: Some(("config", Some(|s| s.s("name").is_empty() && s.s("value").is_empty()))),
                stdout: "max-copy       200 MiB",
                ..Case::default()
            },
            Case {
                name: "set",
                args: &["config", "max-copy-away", "20MiB"],
                answer: media(),
                sent: Some(("config", Some(|s| s.s("name") == "max-copy-away" && s.s("value") == "20MiB"))),
                stdout: "max-copy-away  20 MiB",
                ..Case::default()
            },
            Case {
                name: "in no group",
                args: &["config"],
                sent: Some(("config", None)),
                code: 1,
                stderr: "in no group",
                ..Case::default()
            },
            Case {
                name: "refused",
                args: &["config", "max-copy", "lots"],
                answer: err("not a size"),
                sent: Some(("config", None)),
                code: 1,
                stderr: "not a size",
                ..Case::default()
            },
            Case {
                name: "one argument",
                args: &["config", "max-copy"],
                code: 2,
                stderr: "usage: cbb config",
                ..Case::default()
            },
        ],
    );
}

/// The flags of cbb update that are refused before it looks at anything on
/// the system.
#[test]
fn update_usage() {
    run_cases(
        "update",
        vec![
            Case {
                name: "unknown flag",
                args: &["update", "-now"],
                code: 2,
                stderr: "usage: cbb update",
                ..Case::default()
            },
            // There is no -to: cbb update takes no version.
            Case { name: "-to", args: &["update", "-to"], code: 2, stderr: "usage: cbb update", ..Case::default() },
            Case {
                name: "-auto maybe",
                args: &["update", "-auto", "maybe"],
                code: 2,
                stderr: "usage: cbb update -auto [on|off]",
                ..Case::default()
            },
            Case {
                name: "-installed-by a stranger",
                args: &["update", "-installed-by", "snap"],
                code: 2,
                stderr: "usage: cbb update -installed-by get",
                ..Case::default()
            },
            Case {
                name: "two modes",
                args: &["update", "-check", "-auto", "on"],
                code: 2,
                stderr: "usage: cbb update",
                ..Case::default()
            },
            Case {
                name: "check and timer",
                args: &["update", "-check", "-timer"],
                code: 2,
                stderr: "usage: cbb update",
                ..Case::default()
            },
            Case {
                name: "mirror and to",
                args: &["update", "-mirror", "-to", "0.6.1"],
                code: 2,
                stderr: "usage: cbb update",
                ..Case::default()
            },
        ],
    );
}

/// What cbb status says when the records stop the exchange: the stop, each
/// conflict and claim with what ends it, and the records of a later version.
#[test]
fn stop_lines() {
    let dir = tempdir("stop");
    let st = json!({"os": "linux", "device": "d1", "group": "g1", "stop": "full", "newer": 2,
    "conflicts": [{"kind": "admins", "devices": ["Laptop", "Desk"]}, {"kind": "two_histories", "devices": ["Pi"]}],
    "claims": [
        {"by": "Laptop", "state": "pending", "left_ms": 50 * 3_600_000},
        {"by": "Desk", "state": "pending"},
        {"by": "Old", "state": "disputed"},
    ]});
    let r = run_in(&dir, &["status"], "", status(st), b"");
    for w in [
        "exchange records only",
        "Laptop, Desk",
        "cbb remove NAME",
        "Pi signed two histories",
        "cbb resolve",
        "takes effect in 2 days",
        "once this device knows how long",
        "Old claims the group, and another admin removed it",
        "2 records of a later version",
    ] {
        assert!(r.stdout.contains(w), "no {w:?} in {:?}", r.stdout);
    }
    let r = run_in(
        &dir,
        &["status"],
        "",
        status(json!({"os": "linux", "device": "d1", "group": "g1", "stop": "secrets"})),
        b"",
    );
    assert!(r.stdout.contains("no secrets"), "{:?}", r.stdout);
    let r = run_in(&dir, &["status"], "", status(json!({"os": "linux", "device": "d1", "group": "g1"})), b"");
    assert!(!r.stdout.contains("stopped") && !r.stdout.contains("claims"), "{:?}", r.stdout);
    let _ = std::fs::remove_dir_all(&dir);
}

/// The QR code's text that cbb pair -qr reads arrives whole, fingerprint and
/// all, though it is longer than a pairing code's line.
#[test]
fn pair_reads_the_qr_text() {
    let dir = tempdir("pair-qr");
    let text = "cbb://join?code=123456&addr=192.168.0.179%3A8764&addr=10.0.0.2%3A8764&addr=%5Bfe80%3A%3A1%5D%3A8764&addr=172.16.5.5%3A8764&fp=sdyYqdtKW%2BHR%2B0ALkJovRReX54G3FuWvIEXFFSKjNGs%3D\n";
    let r = run_with(&dir, &["pair", "-qr"], text, group_then("g1", |_| vec![done(json!({"name": "phone"}))]), &[]);
    let _ = std::fs::remove_dir_all(&dir);
    want("pair -qr", &r, 0, "phone joined the group.", "");
    let p = r.sent.iter().find(|s| s.op() == "pair").expect("pair -qr sent no pair");
    assert!(
        p.s("code") == "123456"
            && p.list("addrs").len() == 4
            && p.s("fingerprint") == "sdyYqdtKW+HR+0ALkJovRReX54G3FuWvIEXFFSKjNGs=",
        "pair -qr sent {:?}",
        p.h
    );
}

/// cbb pair -app, for a desktop app that runs cbb as the administrator:
/// the QR code's text goes into the app's own file as one line of JSON, and
/// removing the file cancels the wait. cbb writes only over a regular file
/// the app made: never one that is not there, a folder or a link.
#[test]
fn pair_for_an_app() {
    let dir = tempdir("pair-app");
    let sock = dir.join("control.sock");
    serve(UnixListener::bind(&sock).unwrap(), always(json!({}), b""), Arc::new(Mutex::new(Vec::new())));
    let file = dir.join("join.json");
    std::fs::write(&file, "").unwrap();
    let child = Command::new(env!("CARGO_BIN_EXE_cbb"))
        .args(["pair", "-app", file.to_str().unwrap(), "-port", "0", "-addr", "192.0.2.7"])
        .env("CBB_SOCKET", &sock)
        .env("CBB_STATE", dir.join("state"))
        .env("LC_ALL", "C")
        .env("HOME", &dir)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut written = String::new();
    for _ in 0..300 {
        written = std::fs::read_to_string(&file).unwrap_or_default();
        if !written.is_empty() {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let j: Value = serde_json::from_str(written.trim()).unwrap_or_else(|e| panic!("the file holds {written:?}: {e}"));
    let port = j["port"].as_u64().unwrap_or(0);
    assert!(
        j["qr"].as_str().is_some_and(|q| q.starts_with("cbb://join?")) && j["expires"] == 300 && port != 0,
        "the file holds {j}"
    );
    assert!(j["qr"].as_str().unwrap().contains(&format!("addr=192.0.2.7%3A{port}")), "{j}");
    // The app closes its window.
    std::fs::remove_file(&file).unwrap();
    let out = child.wait_with_output().unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.code() == Some(1) && stderr.contains("cancelled"),
        "after the file went: {:?} {stderr:?}",
        out.status
    );

    for (what, path) in [("a file that is not there", dir.join("none")), ("a folder", dir.clone())] {
        let r = run_in(&dir, &["pair", "-app", path.to_str().unwrap(), "-port", "0"], "", json!({}), b"");
        assert!(r.code == 1, "{what}: {} {:?}", r.code, r.stderr);
    }
    let other = dir.join("other");
    std::fs::write(&other, "kept").unwrap();
    let link = dir.join("link");
    std::os::unix::fs::symlink(&other, &link).unwrap();
    let r = run_in(&dir, &["pair", "-app", link.to_str().unwrap(), "-port", "0"], "", json!({}), b"");
    assert!(r.code == 1 && r.stderr.contains("not a regular file"), "a link: {} {:?}", r.code, r.stderr);
    assert_eq!(std::fs::read_to_string(&other).unwrap(), "kept");
    std::fs::write(&file, "").unwrap();
    let r = run_in(&dir, &["pair", "-app", file.to_str().unwrap(), "-code"], "", json!({}), b"");
    want("pair -app -code", &r, 2, "", "usage");
    let _ = std::fs::remove_dir_all(&dir);
}

/// The service's side of cbb copy FILE: it takes the copy-media request, its
/// parts and their bytes, and answers once the last part came (with refused
/// as the error, if any).
fn copy_service(refused: &'static str) -> Handler {
    handler(move |s| match (s.op(), s.b("done")) {
        ("part", true) if refused.is_empty() => vec![done(json!({}))],
        ("part", true) => vec![done(err(refused))],
        _ => vec![],
    })
}

/// What cbb copy sent: the text alternative and each part with its bytes.
fn copied(r: &Run) -> (String, Vec<(Value, Vec<u8>)>) {
    let text = r.sent.iter().find(|s| s.op() == "copy_media").map(text).unwrap_or_default();
    let mut parts: Vec<(Value, Vec<u8>)> = Vec::new();
    for s in &r.sent {
        match s.op() {
            "part" if !s.b("done") => parts.push((s.h["part"].clone(), Vec::new())),
            "data" => parts.last_mut().expect("bytes before a part").1.extend_from_slice(&s.payload),
            _ => {}
        }
    }
    (text, parts)
}

#[test]
fn copy_files() {
    let dir = tempdir("copy-files");
    let write = |name: &str, body: &str| {
        let p = dir.join(name);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, body).unwrap();
        p.to_str().unwrap().to_string()
    };
    let notes = write("notes.txt", "hello");
    write("photos/a.jpg", "jpeg bytes");
    write("photos/deep/b.jpg", "more bytes");
    let photos = dir.join("photos").to_str().unwrap().to_string();

    let r = run_with(&dir, &["copy", "-text", "alt", &notes], "", copy_service(""), &[]);
    want("copy FILE", &r, 0, "Copied notes.txt (5 bytes) to the group.", "");
    let (text, parts) = copied(&r);
    assert!(
        text == "alt" && parts.len() == 1 && parts[0].0["path"] == "notes.txt" && parts[0].1 == b"hello",
        "{text:?} {parts:?}"
    );

    let r = run_with(&dir, &["copy", &photos, &notes], "", copy_service(""), &[]);
    want("copy DIR FILE", &r, 0, "Copied 3 files in 2 folders", "");
    let (_, parts) = copied(&r);
    let body = |p: &str| parts.iter().find(|(h, _)| h["path"] == p).map(|(_, b)| b.clone()).unwrap_or_default();
    assert!(body("photos/deep/b.jpg") == b"more bytes" && body("photos/a.jpg") == b"jpeg bytes", "{parts:?}");

    let r = run_with(&dir, &["copy", "-type", "JPG", &notes], "", copy_service(""), &[]);
    want("copy -type", &r, 0, "Copied the image/jpeg (5 bytes)", "");
    let (_, parts) = copied(&r);
    assert!(parts.len() == 1 && parts[0].0["type"] == "image/jpeg" && parts[0].1 == b"hello", "{parts:?}");

    let r = run_with(&dir, &["copy", &notes], "", copy_service("this device sends copies of at most 1 MiB"), &[]);
    want("a refused copy", &r, 1, "", "at most 1 MiB");

    for (what, args, code, stderr) in [
        ("-type with two files", vec!["copy", "-type", "png", &notes, &notes], 2, "takes one file"),
        ("-type of a stranger", vec!["copy", "-type", "webp", &notes], 2, "-type is png, jpeg, gif or html"),
        ("-type of a folder", vec!["copy", "-type", "html", &photos], 1, "is not a file"),
        ("-type of nothing", vec!["copy", "-type", "png", "none"], 1, ""),
    ] {
        let r = run_with(&dir, &args, "", copy_service(""), &[]);
        want(what, &r, code, "", stderr);
        assert!(r.sent.is_empty(), "{what}: sent {:?}", ops(&r));
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// cbb paste -o saves what the service sends, never over a file that is
/// there; a paste that fails takes away what it made.
#[test]
fn paste_files() {
    let dir = tempdir("paste-files");
    let out = dir.join("out");
    std::fs::create_dir(&out).unwrap();
    let o = out.to_str().unwrap().to_string();
    let serve = |parts: Vec<(Value, &'static [u8])>| {
        handler(move |s| {
            if s.op() != "paste_media" {
                return vec![];
            }
            let mut a = vec![(json!({}), Vec::new())];
            for (h, b) in &parts {
                a.push((h.clone(), b.to_vec()));
            }
            a.push(done(json!({})));
            a
        })
    };
    let part = |p: Value| (json!({ "part": p }), &b""[..]);
    let data = |b: &'static [u8]| (json!({}), b);
    let r = run_with(
        &dir,
        &["paste", "-o", &o],
        "",
        serve(vec![
            part(json!({"path": "docs", "dir": true})),
            part(json!({"path": "docs/a.txt", "size": 3})),
            data(b"abc"),
            part(json!({"type": "image/png", "size": 2})),
            data(b"pn"),
        ]),
        &[],
    );
    want("paste -o", &r, 0, "", "");
    assert_eq!(std::fs::read(out.join("docs/a.txt")).unwrap(), b"abc");
    assert_eq!(std::fs::read(out.join("image.png")).unwrap(), b"pn");
    assert_eq!(r.stdout, format!("{}\n{}\n", out.join("docs").display(), out.join("image.png").display()));

    // Again: image.png is there now, so nothing is replaced and what the
    // second paste made is taken away.
    let r = run_with(
        &dir,
        &["paste", "-o", &o],
        "",
        serve(vec![
            part(json!({"path": "b.txt", "size": 1})),
            data(b"b"),
            part(json!({"type": "image/png", "size": 2})),
            data(b"xx"),
        ]),
        &[],
    );
    assert_eq!(r.code, 1, "paste -o over a file: {:?}", r.stderr);
    assert_eq!(std::fs::read(out.join("image.png")).unwrap(), b"pn");
    assert!(!out.join("b.txt").exists(), "the failed paste left b.txt");
    let a = out.join("docs/a.txt");
    let r = run_in(&dir, &["paste", "-o", a.to_str().unwrap()], "", json!({}), b"");
    want("paste -o FILE", &r, 1, "", "is not a folder");
    let _ = std::fs::remove_dir_all(&dir);
}

/// What cbb status says of a copy of images or files: why the last one was
/// not fetched.
#[test]
fn media_lines() {
    let dir = tempdir("media-lines");
    let media = json!({"max_copy": 1, "max_copy_away": 1, "failed": "it is larger than 1 MiB"});
    let r = run_in(
        &dir,
        &["status"],
        "",
        status(json!({"os": "linux", "device": "d1", "group": "g1", "media": media})),
        b"",
    );
    let line = "The last copy of images or files was not fetched: it is larger than 1 MiB.";
    assert!(r.stdout.contains(line), "no {line:?} in {:?}", r.stdout);
    let r = run_in(
        &dir,
        &["status"],
        "",
        status(json!({"os": "linux", "device": "d1", "group": "g1", "media": {"max_copy": 1, "max_copy_away": 1}})),
        b"",
    );
    assert!(!r.stdout.contains("not fetched"), "{:?}", r.stdout);
    let _ = std::fs::remove_dir_all(&dir);
}

/// cbb global off asks first on a device that reaches its hub only through
/// the tunnel: its new keys would reach the hub only at home.
#[test]
fn global_off_away() {
    let through = || in_group(json!({"away": {"hub_device": "deck", "through": true}}));
    run_cases(
        "global-off",
        vec![
            Case {
                name: "off, answered no",
                args: &["global", "off"],
                stdin: "no\n",
                answer: through(),
                code: 1,
                stdout: "only once it is at home",
                ..Case::default()
            },
            Case {
                name: "off -yes",
                args: &["global", "off", "-yes"],
                answer: through(),
                sent: Some(("away", Some(|s| s.s("name") == "off"))),
                ..Case::default()
            },
        ],
    );
}

/// The program's own words: no command, version, help, an unknown command,
/// the program's name typed twice, and -h after a command.
#[test]
fn run_basics() {
    run_cases(
        "run",
        vec![
            Case { name: "no command", args: &[], code: 2, stderr: "Usage: cbb", ..Case::default() },
            Case { name: "version", args: &["version"], stdout: "cbb ", ..Case::default() },
            Case { name: "version flag", args: &["--version"], stdout: "cbb ", ..Case::default() },
            Case { name: "help", args: &["help"], stdout: "Usage: cbb", ..Case::default() },
            Case { name: "help flag", args: &["-h"], stdout: "Usage: cbb", ..Case::default() },
            Case {
                name: "unknown command",
                args: &["frobnicate"],
                code: 2,
                stderr: "unknown command \"frobnicate\"; cbb help lists the commands",
                ..Case::default()
            },
            Case {
                name: "cbb twice",
                args: &["cbb", "status"],
                code: 2,
                stderr: "the command comes right after the program: cbb status",
                ..Case::default()
            },
            Case {
                name: "remove -h",
                args: &["remove", "-h"],
                code: 2,
                stderr: "usage: cbb remove",
                ..Case::default()
            },
            Case {
                name: "takeover -help",
                args: &["takeover", "-help"],
                code: 2,
                stderr: "usage: cbb takeover",
                ..Case::default()
            },
            Case {
                name: "freeze --help",
                args: &["freeze", "--help"],
                code: 2,
                stderr: "usage: cbb freeze",
                ..Case::default()
            },
            Case {
                name: "unfreeze -h",
                args: &["unfreeze", "-h"],
                code: 2,
                stderr: "usage: cbb unfreeze",
                ..Case::default()
            },
        ],
    );
}

/// Out of a group cbb pair waits for the phone on the service's own port,
/// which its firewall rule opens (OpenWrt's comes from /etc/config/cbb),
/// not on the default one.
#[test]
fn pair_waits_on_the_service_port() {
    let dir = tempdir("pair-port");
    let port = std::net::TcpListener::bind("0.0.0.0:0").unwrap().local_addr().unwrap().port();
    let sock = dir.join("control.sock");
    serve(
        UnixListener::bind(&sock).unwrap(),
        always(status(json!({"port": port})), b""),
        Arc::new(Mutex::new(Vec::new())),
    );
    let file = dir.join("join.json");
    std::fs::write(&file, "").unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_cbb"))
        .args(["pair", "-app", file.to_str().unwrap(), "-addr", "192.0.2.7"])
        .env("CBB_SOCKET", &sock)
        .env("CBB_STATE", dir.join("state"))
        .env("LC_ALL", "C")
        .env("HOME", &dir)
        .env_remove("CBB_PORT")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut written = String::new();
    for _ in 0..300 {
        written = std::fs::read_to_string(&file).unwrap_or_default();
        if !written.is_empty() {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let _ = child.kill();
    let _ = child.wait();
    let _ = std::fs::remove_dir_all(&dir);
    let j: Value = serde_json::from_str(written.trim()).unwrap_or_else(|e| panic!("the file holds {written:?}: {e}"));
    assert_eq!(j["port"].as_u64(), Some(u64::from(port)), "the file holds {j}");
}
