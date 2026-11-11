// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! Remote paste and quick actions carried out on a member (docs/protocol.md,
//! section 15): the root signs the command, the member checks its user's
//! switches and hands the paste to the watcher that offers a paste target,
//! or runs the action (here into CBB_TEST_ACTIONS' folder), and the result
//! comes back to the root's command line.

#![cfg(unix)]

mod common;

use std::io::BufReader;
use std::os::unix::net::UnixStream;
use std::time::Duration;

use common::*;
use serde_json::json;

fn has(e: &str, part: &str) {
    assert!(e.contains(part), "{e:?} does not say {part:?}");
}

unsafe extern "C" {
    fn geteuid() -> u32;
}

/// Whether the tests run as root, whose watchers take every paste target
/// and the actions whoever sits at the screen; elsewhere logind decides.
fn root_user() -> bool {
    // SAFETY: geteuid has no preconditions.
    unsafe { geteuid() == 0 }
}

/// A watcher on desk that offers target and answers each inject or act
/// with answer, noting what it got.
fn watcher(desk: &Svc, h: serde_json::Value, answer: serde_json::Value) -> std::sync::mpsc::Receiver<Msg> {
    let (mut c, mut r): (UnixStream, BufReader<UnixStream>) = desk.open(false, &h, b"");
    let first = read(&mut r).expect("the watch's answer");
    assert!(first.error().is_empty(), "{:?}", first.h);
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        c.set_read_timeout(None).unwrap();
        while let Some(m) = read(&mut r) {
            let op = m.s("op").to_string();
            if op == "inject" || op == "act" {
                let mut a = answer.clone();
                a["op"] = json!(if op == "inject" { "injected" } else { "acted" });
                a["seq"] = m.h["seq"].clone();
                send(&mut c, &a, b"");
            }
            if tx.send(m).is_err() {
                return;
            }
        }
    });
    rx
}

/// The quick actions: on and off on the member, a preset run by the
/// root's command, one the member refuses, one it does not have.
#[test]
fn runs_a_quick_action_on_a_member() {
    let dir = std::env::temp_dir().join(format!("cbbt-acts-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let acts = dir.to_str().unwrap();
    let g = group_with(&["root", "desk"], &[("CBB_TEST_ACTIONS", acts)]);
    let (root, desk) = (&g[0], &g[1]);
    // Off on desk: refused there.
    has(&root.err(true, json!({"op": "action-on", "device": "desk", "name": "lock"})), "desk");
    let on = |name: &str| {
        let m = desk.ask(true, json!({"op": "action-set", "actions": [{"name": name, "on": true}]}), b"");
        assert!(m.error().is_empty(), "{:?}", m.h);
    };
    on("lock");
    root.ok(true, json!({"op": "action-on", "device": "desk", "name": "lock"}));
    let ran = std::fs::read_to_string(dir.join("ran")).unwrap_or_default();
    assert_eq!(ran, "lock\n");
    // Too fast after it: one a second from one device.
    let e = root.err(true, json!({"op": "action-on", "device": "desk", "name": "lock"}));
    has(&e, "too many actions");
    std::thread::sleep(Duration::from_millis(1100));
    // The system refuses it.
    std::fs::write(dir.join("refuse-lock"), "the screen is locked already").unwrap();
    has(&root.err(true, json!({"op": "action-on", "device": "desk", "name": "lock"})), "locked already");
    // Reboot is for admins with keys in hardware unless the user says
    // otherwise (D-71): the root's key is in a file.
    on("reboot");
    std::thread::sleep(Duration::from_millis(1100));
    let e = root.err(true, json!({"op": "action-on", "device": "desk", "name": "reboot"}));
    assert!(!e.is_empty());
    // An action of desk's user's own runs in the session, through an agent.
    let m = desk.ask(
        true,
        json!({"op": "action-set", "actions": [{"name": "backup", "on": true, "by": ["root"], "command": ["/bin/true"]}]}),
        b"",
    );
    assert!(m.error().is_empty(), "{:?}", m.h);
    std::thread::sleep(Duration::from_millis(1100));
    has(&root.err(true, json!({"op": "action-on", "device": "desk", "name": "backup"})), "agent");
    let got = watcher(desk, json!({"op": "watch", "act": true, "paste_only": true}), json!({"error": ""}));
    std::thread::sleep(Duration::from_millis(1100));
    let m = root.ask(true, json!({"op": "action-on", "device": "desk", "name": "backup"}), b"");
    if root_user() {
        assert!(m.error().is_empty(), "{:?}\n{}", m.h, desk.log());
        let act = got.recv_timeout(Duration::from_secs(10)).expect("the agent's act");
        assert_eq!((act.s("op"), act.s("name")), ("act", "backup"));
        assert_eq!(act.h["command"], json!(["/bin/true"]));
    }
    // The member keeps a log of them.
    has(&desk.log(), "ran the action lock here");
    let _ = std::fs::remove_dir_all(&dir);
}

/// Remote paste: refused while off, without Enter when the user did not
/// allow it, and handed to the watcher that offers a target when on.
#[test]
fn pastes_on_a_member() {
    let g = group(&["root", "desk"]);
    let (root, desk) = (&g[0], &g[1]);
    has(&root.err_with(true, json!({"op": "paste-on", "device": "desk"}), b"hi"), "remote paste is off");
    desk.ok(true, json!({"op": "paste-receive", "name": "on"}));
    // On, with nothing that pastes.
    has(&root.err_with(true, json!({"op": "paste-on", "device": "desk"}), b"hi"), "nothing on this device can paste");
    std::thread::sleep(Duration::from_millis(1100));
    has(&root.err_with(true, json!({"op": "paste-on", "device": "desk", "enter": true}), b"hi"), "without Enter");
    let got = watcher(desk, json!({"op": "watch", "inject": "tmux"}), json!({"error": ""}));
    std::thread::sleep(Duration::from_millis(1100));
    let m = root.ask(true, json!({"op": "paste-on", "device": "desk"}), b"hello there");
    if root_user() {
        assert!(m.error().is_empty(), "{:?}\n{}", m.h, desk.log());
        let inj = got.recv_timeout(Duration::from_secs(10)).expect("the inject");
        assert_eq!((inj.s("op"), inj.payload.as_slice()), ("inject", &b"hello there"[..]));
        // Too fast after it.
        has(&root.err_with(true, json!({"op": "paste-on", "device": "desk"}), b"again"), "too many pastes");
        std::thread::sleep(Duration::from_millis(1100));
        // A line break needs Enter.
        let e = root.err_with(true, json!({"op": "paste-on", "device": "desk"}), b"rm -rf x\nls");
        assert!(!e.is_empty());
        std::thread::sleep(Duration::from_millis(1100));
        // Typed too.
        let m = root.ask(true, json!({"op": "paste-on", "device": "desk", "method": "type"}), b"typed");
        assert!(m.error().is_empty(), "{:?}", m.h);
        let inj = got.recv_timeout(Duration::from_secs(10)).expect("the typed inject");
        assert_eq!(inj.s("method"), "type");
        std::thread::sleep(Duration::from_millis(1100));
        // A secret, on a device that cannot tell who sits at its screen,
        // is refused; as root it is taken.
        let m = root.ask(true, json!({"op": "paste-on", "device": "desk", "kind": "secret"}), b"pin");
        assert!(m.error().is_empty(), "{:?}", m.h);
    }
    // A watcher that fails the paste: its error comes back.
    let _failing = watcher(
        desk,
        json!({"op": "watch", "inject": "desktop", "paste_only": true}),
        json!({"error": "the focused window takes no text", "refused": true}),
    );
    std::thread::sleep(Duration::from_millis(1100));
    let m = root.ask(true, json!({"op": "paste-on", "device": "desk"}), b"to the desktop");
    if root_user() {
        // The desktop goes first and refuses; tmux then takes it.
        assert!(m.error().is_empty() || m.error().contains("focused window"), "{:?}", m.h);
    }
    // Turned off again by an admin's command.
    root.ok(true, json!({"op": "paste-receive", "name": "off", "device": "desk"}));
    wait_for("desk's remote paste is off", || (desk.status()["paste"]["on"] != true).then_some(()), || desk.log());
    let log = std::fs::read_to_string(desk.state().join("paste-log.json")).unwrap_or_default();
    let _ = log;
}
