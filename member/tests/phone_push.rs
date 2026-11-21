// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! A phone's push on real services (`crate::pusher`, "Required test"): the
//! phone is ffi's example phone-on-linux, the apps' member on Linux
//! (CBB_PHONE_ON_LINUX names its build; the test is skipped without it), in
//! a group of 0.6 with two computers, and the push service (`pushd`) runs
//! here with a platform that keeps what it is handed. The phone reads its
//! face toward the service, registers as the app does (the core's
//! `push_registration`, then the member's `push`), goes away, and a
//! computer's copy reaches the platform and opens under the phone's push
//! key; a computer that still sends under an older registration asks the
//! phone to register again, which reaches the phone's queue when it is
//! back.

mod common;

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{Receiver, channel};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use cbb_core::push::{self as core_push, Body};
use cbb_core::release::testing::TestKey;
use cbb_member::pushd::{Budgets, Config, Delivery, Outcome, Platform, Service};
use common::*;
use serde_json::{Value, json};

/// A platform that keeps each body it is handed.
#[derive(Default)]
struct Kept(Mutex<Vec<Vec<u8>>>);

impl Platform for Kept {
    fn send(&self, d: &Delivery<'_>) -> Outcome {
        if let Some(b) = d.body {
            self.0.lock().unwrap().push(b.to_vec());
        }
        Outcome::Sent
    }
}

impl Kept {
    fn bodies(&self) -> Vec<Vec<u8>> {
        self.0.lock().unwrap().clone()
    }
}

/// phone-on-linux running: its standard input and the lines it prints,
/// "LOG" lines aside.
struct Phone {
    child: Child,
    stdin: Option<ChildStdin>,
    lines: Receiver<String>,
    log: Arc<Mutex<String>>,
}

impl Phone {
    fn start(bin: &Path, args: &[&str], env: &[(&str, &str)]) -> Phone {
        let mut cmd = Command::new(bin);
        cmd.args(args).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped());
        for (k, v) in env {
            cmd.env(k, v);
        }
        let mut child = cmd.spawn().expect("phone-on-linux starts");
        let stdin = child.stdin.take();
        let out = child.stdout.take().unwrap();
        let err = child.stderr.take().unwrap();
        let (tx, lines) = channel();
        let log = Arc::new(Mutex::new(String::new()));
        let kept = log.clone();
        std::thread::spawn(move || {
            for l in BufReader::new(err).lines() {
                let Ok(l) = l else { break };
                let mut k = kept.lock().unwrap();
                k.push_str(&l);
                k.push('\n');
            }
        });
        let kept = log.clone();
        std::thread::spawn(move || {
            for l in BufReader::new(out).lines() {
                let Ok(l) = l else { break };
                match l.strip_prefix("LOG ") {
                    Some(rest) => {
                        let mut k = kept.lock().unwrap();
                        k.push_str(rest);
                        k.push('\n');
                    }
                    None => {
                        if tx.send(l).is_err() {
                            break;
                        }
                    }
                }
            }
        });
        Phone { child, stdin, lines, log }
    }

    fn log(&self) -> String {
        self.log.lock().unwrap().clone()
    }

    /// The rest of the next line that starts with prefix; the others are
    /// passed over.
    fn next(&self, prefix: &str) -> String {
        let end = Instant::now() + ANSWER;
        loop {
            let left = end.saturating_duration_since(Instant::now());
            match self.lines.recv_timeout(left) {
                Ok(l) => {
                    if let Some(rest) = l.strip_prefix(prefix) {
                        return rest.to_string();
                    }
                }
                Err(_) => panic!("phone-on-linux printed no {prefix:?}:\n{}", self.log()),
            }
        }
    }

    fn say(&mut self, line: &str) {
        let w = self.stdin.as_mut().expect("the phone runs");
        writeln!(w, "{line}").unwrap();
        w.flush().unwrap();
    }

    /// cbb_member_call with the request, its answer.
    fn call(&mut self, req: Value) -> Value {
        self.say(&format!("CALL {req}"));
        serde_json::from_str(&self.next("ANSWER ")).unwrap()
    }

    fn peers(&mut self) -> usize {
        self.say("PEERS");
        self.next("PEERS ").parse().unwrap_or(0)
    }

    /// Ends it as the app ending: the end of its input, a kill if it does
    /// not exit.
    fn stop(&mut self) {
        drop(self.stdin.take());
        let end = Instant::now() + Duration::from_secs(5);
        while self.child.try_wait().unwrap().is_none() {
            if Instant::now() > end {
                let _ = self.child.kill();
                let _ = self.child.wait();
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}

impl Drop for Phone {
    fn drop(&mut self) {
        self.stop();
    }
}

fn b64(b: &[u8]) -> String {
    STANDARD.encode(b)
}

fn unb64(v: &Value) -> Vec<u8> {
    STANDARD.decode(v.as_str().unwrap_or_default()).unwrap_or_default()
}

/// The core's answer to op, as the app's cbb_call gets it.
fn core(op: &str, args: Value) -> Value {
    let req = serde_json::to_vec(&json!({"abi": 1, "op": op, "args": args})).unwrap();
    let a: Value = serde_json::from_slice(&cbb_core::api::call(&req)).unwrap();
    assert!(a.get("error").is_none(), "{op}: {a}");
    a["ok"].clone()
}

/// The roots file the members check release files with, its PEM closed
/// to others' writing as read_roots wants.
fn roots_file(dir: &Path, root: &TestKey) -> PathBuf {
    use std::os::unix::fs::PermissionsExt as _;
    let path = dir.join("roots.pem");
    write(&path, &root.pem("root-1"));
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    path
}

/// keys.json naming the push service by its certificate's key, and an
/// entries.json, signed under the test root, as message `entries` and the
/// control op `entries` carry them.
fn entry_points(root: &TestKey, release: &TestKey, spki: &[u8]) -> Vec<u8> {
    let at = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as i64 - 1000;
    let mut keys = release.keys("release key", "");
    keys.push(cbb_core::release::Key {
        alg: cbb_core::release::ALG_ES256,
        key: spki.to_vec(),
        name: "cbb.tools:8767".into(),
        usage: "push".into(),
    });
    let sign = |k: &TestKey, v: Value| serde_json::to_string(&k.sign(&serde_json::to_vec(&v).unwrap())).unwrap();
    let keys = sign(
        root,
        json!({"v": 1, "type": "keys", "seq": 1, "time_ms": at, "expires_ms": at + 86_400_000, "keys": keys}),
    );
    let entries = sign(
        release,
        json!({"v": 1, "type": "entries", "seq": 1, "time_ms": at, "expires_ms": at + 86_400_000, "forwarders": []}),
    );
    format!(r#"{{"keys":{keys},"entries":{entries}}}"#).into_bytes()
}

/// The root (the group's hub) and lap, both with env, lap connected to the
/// root.
fn computers(env: &[(&str, &str)]) -> Vec<Svc> {
    let root = Svc::start("root", &[], env);
    root.new_group();
    let lap = Svc::start("lap", &["-peer", &root.addr()], env);
    assert_eq!(root.admit(&lap, false), "lap");
    root.wait_peer("lap");
    lap.wait_peer("root");
    let all = vec![root, lap];
    settle(&all);
    all
}

#[test]
fn a_phone_registers_and_gets_a_copy_and_a_renewal_by_push() {
    let Some(bin) = std::env::var_os("CBB_PHONE_ON_LINUX").map(PathBuf::from) else {
        eprintln!("skipped: CBB_PHONE_ON_LINUX is not set");
        return;
    };
    let tmp = std::env::temp_dir().join(format!("cbbt-push-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).unwrap();

    // The push service, with its certificate's key in keys.json.
    let keys = cbb_member::relayd::keys::Keys::new().unwrap();
    let cert = cbb_core::certs::Cert::parse(&keys.cert).unwrap();
    let spki = cbb_core::certs::p256_spki_of(cert.public_key());
    let platform = Arc::new(Kept::default());
    let mut platforms: HashMap<u64, Arc<dyn Platform>> = HashMap::new();
    platforms.insert(core_push::ENV_APNS, platform.clone());
    let service = Service::start(Config {
        listen: "127.0.0.1:0".parse().unwrap(),
        cert: keys.cert.clone(),
        key: keys.key.clone(),
        platforms,
        budgets: Budgets::default(),
        new_state: false,
        state: None,
        log: Arc::new(|_| {}),
    })
    .unwrap();

    let (release_root, release) = (TestKey::new(1), TestKey::new(2));
    let roots = roots_file(&tmp, &release_root);
    let (roots, at) = (roots.to_str().unwrap().to_string(), service.addr().to_string());
    let env = [("CBB_RELEASE_ROOTS", roots.as_str()), ("CBB_TEST_PUSH_AT", at.as_str())];
    let g = computers(&env);
    g[0].ok(true, json!({"op": "hubs", "hubs": ["root"]}));
    g[0].ok_with(true, json!({"op": "entries"}), &entry_points(&release_root, &release, &spki));

    // The phone joins at the root and meets both.
    let phone_dir = tmp.join("phone");
    let phone_dir = phone_dir.to_str().unwrap();
    let (root_addr, lap_addr) = (g[0].addr(), g[1].addr());
    let (mut phone, device) = {
        let (_w, mut r, _, link) = g[0].window(false);
        let p = Phone::start(
            &bin,
            &[
                "-addr",
                "127.0.0.1:0",
                "-name",
                "phone",
                "-dir",
                phone_dir,
                "-join-window",
                &link,
                "-peer",
                &root_addr,
                "-peer",
                &lap_addr,
            ],
            &env,
        );
        let joined = p.next("Joined ");
        let device = joined.split(' ').next().unwrap_or_default().to_string();
        assert!(!device.is_empty(), "the phone joined");
        let closed = read(&mut r).unwrap_or_else(|| panic!("the window did not close:\n{}", g[0].log()));
        assert!(closed.error().is_empty(), "the window: {}", closed.error());
        (p, device)
    };
    let end = Instant::now() + ANSWER;
    while phone.peers() < 2 {
        assert!(Instant::now() < end, "the phone meets both computers:\n{}", phone.log());
        std::thread::sleep(Duration::from_millis(200));
    }

    // Its face toward the push service, once the entry points reached it.
    let end = Instant::now() + ANSWER;
    let face = loop {
        let a = phone.call(json!({"op": "push_face"}));
        let f = unb64(&a["ok"]["face"]);
        if f.len() == 16 {
            break f;
        }
        assert!(Instant::now() < end, "the phone has no face toward the push service: {a}\n{}", phone.log());
        std::thread::sleep(Duration::from_millis(200));
    };

    // It registers as the app does: a push key, a send key and a slot of
    // the core's, the registration's frame, the member's `push`.
    let drawn = core("push_key", Value::Null);
    let push_key = unb64(&drawn["key"]);
    let register = |phone: &mut Phone, highest: u64| -> u64 {
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as u64;
        let mut args = json!({"now_ms": now, "kinds": core_push::KIND_COPIES | core_push::KIND_EVENTS,
            "env": core_push::ENV_APNS, "token": b64(&[5; 32]), "key": drawn["key"], "send_key": drawn["send_key"],
            "slot": drawn["slot"], "face": b64(&face)});
        if highest > 0 {
            args["highest_seq"] = json!(highest);
        }
        let reg = core("push_registration", args);
        let a = phone.call(json!({"op": "push", "args": {"frame": reg["frame"]}}));
        assert!(a.get("error").is_none(), "push: {a}");
        reg["seq"].as_u64().unwrap()
    };
    let first = register(&mut phone, 0);
    std::thread::sleep(Duration::from_secs(2));

    // It goes away; lap's copy reaches the platform and opens under its key.
    phone.stop();
    wait_for(
        "both computers see the phone gone",
        || (g.iter().all(|s| s.status()["peers"].as_array().is_some_and(|p| p.len() == 1))).then_some(()),
        || format!("{}\n{}", g[0].log(), g[1].log()),
    );
    g[1].ok_with(false, json!({"op": "copy"}), b"while the phone is away");
    let key: [u8; 32] = push_key.clone().try_into().unwrap();
    wait_for("the copy's body", || (!platform.bodies().is_empty()).then_some(()), || g[1].log());
    match core_push::open(&key, first, &platform.bodies()[0]) {
        Ok(Body::Copy(_)) => {}
        other => panic!("the body opened as {other:?}"),
    }

    // Back at the root alone, it registers again; lap keeps the first.
    let mut phone = Phone::start(
        &bin,
        &["-addr", "127.0.0.1:0", "-name", "phone", "-dir", phone_dir, "-resume", &device, "-peer", &root_addr],
        &env,
    );
    let end = Instant::now() + ANSWER;
    while phone.peers() < 1 {
        assert!(Instant::now() < end, "the phone is back at the root:\n{}", phone.log());
        std::thread::sleep(Duration::from_millis(200));
    }
    assert_eq!(phone.peers(), 1, "the phone meets the root only");
    let second = register(&mut phone, first);
    assert!(second > first);
    std::thread::sleep(Duration::from_secs(2));
    phone.stop();
    wait_for(
        "the root sees the phone gone",
        || g[0].status()["peers"].as_array().is_some_and(|p| p.len() == 1).then_some(()),
        || g[0].log(),
    );

    // The root's copy goes under the second registration, which the
    // service then holds; lap's next copy goes under the first, which the
    // service answers stale.
    g[0].ok_with(false, json!({"op": "copy"}), b"from the hub");
    let opens = |seq: u64, from: usize| {
        platform.bodies().iter().skip(from).any(|b| matches!(core_push::open(&key, seq, b), Ok(Body::Copy(_))))
    };
    wait_for("the root's body under the second registration", || opens(second, 1).then_some(()), || g[0].log());
    let before = platform.bodies().len();
    g[1].ok_with(false, json!({"op": "copy"}), b"from lap, after the phone registered again");
    wait_for(
        "the hub's body for lap's copy",
        || (platform.bodies().len() > before && opens(second, before)).then_some(()),
        || g[0].log(),
    );

    // Lap holds a push-renew for the phone, which reaches its queue when
    // it connects to lap.
    let slot = drawn["slot"].clone();
    let mut phone = Phone::start(
        &bin,
        &["-addr", "127.0.0.1:0", "-name", "phone", "-dir", phone_dir, "-resume", &device, "-peer", &lap_addr],
        &env,
    );
    let end = Instant::now() + ANSWER;
    loop {
        let a = phone.call(json!({"op": "push_renewals"}));
        if a["ok"]["renewals"].as_array().is_some_and(|r| r.iter().any(|x| x["slot"] == slot)) {
            break;
        }
        assert!(Instant::now() < end, "no push-renew for the phone's slot: {a}\n{}\n{}", phone.log(), g[1].log());
        std::thread::sleep(Duration::from_millis(300));
    }
    phone.stop();
    drop(service);
}
