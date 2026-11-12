// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The control socket's contract (docs/protocol.md, section 8) on a real
//! service: every operation gets answers in the envelope {"ok"} or
//! {"error"}, the last done or an error; the operations that change the group are taken only on the admin
//! socket; a broken or hostile client never stops the service, which still
//! answers the next request.

#![cfg(unix)]

mod common;

use std::io::Write;
use std::os::unix::net::UnixStream;
use std::time::Duration;

use common::*;
use serde_json::{Value, json};

/// Every operation the service takes, from the command line, the apps, the
/// watchers, cbb update and the helpers (service.rs, serve and request).
const OPS: &[&str] = &[
    "action_on",
    "action_remove",
    "action_set",
    "actions_off",
    "arrange",
    "away",
    "bug",
    "bug_allow",
    "bug_cancel",
    "config",
    "copied_media",
    "copy",
    "copy_media",
    "devices",
    "entries",
    "entries_get",
    "freeze",
    "hand_over",
    "hubs",
    "incoming",
    "invite",
    "join",
    "key_level",
    "keyboard",
    "keys",
    "leave",
    "make_admin",
    "mute",
    "muted",
    "network",
    "new",
    "pair",
    "paste",
    "paste_media",
    "paste_on",
    "paste_receive",
    "recover",
    "release",
    "release_file",
    "release_get",
    "release_held",
    "release_want",
    "remote",
    "remove",
    "rename",
    "resolve",
    "status",
    "sync",
    "take_over",
    "takeover_delay",
    "thaw",
    "unmute",
    "update_way",
    "version",
    "view",
    "watch",
];

/// The operations the control socket takes from any local user: reading
/// and writing the clipboard, the status, the watchers, the signed release
/// and entry points cbb update brings, and the uinput helper's keys
/// (control.rs, is_admin). Every other operation needs the admin socket.
const UNPRIVILEGED: &[&str] = &[
    "arrange",
    "bug",
    "bug_allow",
    "bug_cancel",
    "config",
    "copied_media",
    "copy",
    "copy_media",
    "devices",
    "entries",
    "entries_get",
    "keys",
    "muted",
    "paste",
    "paste_media",
    "release",
    "release_get",
    "release_held",
    "status",
    "version",
    "view",
    "watch",
];

/// The operations that would stop the service, wait for a peer or a
/// client, or answer a bug report, so the sweeps leave them to their own
/// tests.
const SWEPT_APART: &[&str] =
    &["leave", "watch", "join", "pair", "invite", "copy_media", "copied_media", "bug", "bug_allow", "bug_cancel"];

fn has(e: &str, part: &str) {
    assert!(e.contains(part), "{e:?} does not say {part:?}");
}

/// What the control socket answers a change of the group from a user it
/// cannot confirm: where the system has a prompt (confirm.rs), that it
/// cannot confirm the action for this user, as polkit refuses the tests'
/// user on Linux; elsewhere, that only the admin socket takes it.
const NOT_CONFIRMED: &str = "cannot confirm the admin action";

fn refused(e: &str) -> bool {
    e.contains("only on its admin socket") || e.contains(NOT_CONFIRMED)
}

fn has_refusal(e: &str) {
    assert!(refused(e), "{e:?} is no refusal of a change of the group on the control socket");
}

/// Sends one request and checks the contract of its answers: each is an
/// answer's envelope (read checks it), and the last is done or carries an
/// error.
fn answer(svc: &Svc, admin: bool, h: Value) -> Msg {
    let all = svc.ask_all(admin, h.clone(), b"");
    let last = all.last().cloned().unwrap_or_else(|| panic!("no answer to {h}:\n{}", svc.log()));
    for m in &all {
        assert_eq!(m.s("op"), "reply", "{h}: {:?}", m.h);
    }
    assert!(last.done() || !last.error().is_empty(), "{h}: the last answer is not done: {:?}", last.h);
    last
}

/// The control socket refuses every operation that changes the group, and
/// takes the others; the admin socket takes them all.
#[test]
fn the_admin_socket_guards_the_group() {
    let svc = Svc::start("desk", &[], &[]);
    svc.new_group();
    for op in OPS.iter().filter(|op| !SWEPT_APART.contains(op)) {
        let m = answer(&svc, false, json!({"op": op}));
        // This device's own sync, without -on, any user turns.
        let free = UNPRIVILEGED.contains(op) || *op == "sync";
        assert_eq!(refused(m.error()), !free, "{op} on the control socket: {:?}", m.h);
        let m = answer(&svc, true, json!({"op": op}));
        assert!(
            !m.error().contains("admin socket") && !m.error().contains(NOT_CONFIRMED),
            "{op} on the admin socket: {:?}",
            m.h
        );
    }
    // Turning this device's own sync on or off changes nothing for the
    // group, so any user may; another device's is an admin's.
    svc.ok(false, json!({"op": "sync", "on": true}));
    has_refusal(&svc.err(false, json!({"op": "sync", "on": true, "device": "x"})));
    for op in SWEPT_APART.iter().filter(|op| !UNPRIVILEGED.contains(op)) {
        has_refusal(&svc.err(false, json!({"op": op})));
    }
}

/// Before a group, every operation answers: those that need none with
/// their result, the others with why not.
#[test]
fn every_operation_answers_outside_a_group() {
    let svc = Svc::start("desk", &[], &[]);
    for op in OPS.iter().filter(|op| !SWEPT_APART.contains(op) && **op != "new") {
        let m = answer(&svc, true, json!({"op": op}));
        match *op {
            "version" | "status" => assert!(m.error().is_empty(), "{op}: {:?}", m.h),
            _ => {}
        }
    }
    let st = svc.status();
    assert_eq!(st["version"], "dev");
    assert!(st["group"].is_null(), "{st}");
    assert!(st["port"].is_null() || st["port"] == 0, "{st}");
    let v = svc.ok(false, json!({"op": "version"})).h["status"].clone();
    assert_eq!((v["role"].as_str(), v["version"].as_str()), (Some("member"), Some("dev")));
    // Nothing to leave, to watch or to admit with.
    assert!(!svc.err(true, json!({"op": "leave"})).is_empty());
    assert!(!svc.err(false, json!({"op": "watch"})).is_empty());
    assert!(!svc.err(true, json!({"op": "pair"})).is_empty());
    assert!(!svc.err(true, json!({"op": "invite"})).is_empty());
    assert!(!svc.err(false, json!({"op": "copy"})).is_empty());
    // A second new makes no second group.
    svc.new_group();
    has(&svc.err(true, json!({"op": "new"})), "already in a group");
}

/// In a group, every operation answers, the service still runs after
/// each, and an operation it does not know is refused by name.
#[test]
fn every_operation_answers_in_a_group() {
    let mut svc = Svc::start("desk", &[], &[]);
    svc.new_group();
    for op in OPS.iter().filter(|op| !SWEPT_APART.contains(op)) {
        answer(&svc, true, json!({"op": op}));
        answer(&svc, true, json!({"op": op, "name": "x", "device": "nobody", "value": "?", "all": true}));
        assert!(svc.running(), "the service stopped after {op}:\n{}", svc.log());
    }
    has(&svc.err(true, json!({"op": "no_such_op"})), "unknown operation \"no_such_op\"");
    has_refusal(&svc.err(false, json!({"op": ""})));
    // A header without op is an answer's envelope, which no client sends.
    has(&svc.err(true, json!({})), "unknown operation \"reply\"");
    assert_eq!(svc.status()["role"], "member");
}

/// What a client that breaks the framing gets: the connection closes, and
/// the service answers the next one.
#[test]
fn a_broken_client_does_not_stop_the_service() {
    let svc = Svc::start("desk", &[], &[]);
    svc.new_group();
    let raw = |bytes: &[u8]| -> Vec<u8> {
        let mut c = UnixStream::connect(svc.socket(false)).unwrap();
        c.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        let _ = c.write_all(bytes);
        let _ = c.shutdown(std::net::Shutdown::Write);
        let mut got = Vec::new();
        let _ = std::io::Read::read_to_end(&mut c, &mut got);
        got
    };
    let cases: Vec<Vec<u8>> = vec![
        b"".to_vec(),
        b"not json\n".to_vec(),
        b"[1,2,3]\n".to_vec(),
        b"{\"op\":\"status\"".to_vec(),
        // A payload longer than any.
        b"{\"op\":\"copy\",\"len\":99999999}\n".to_vec(),
        // A payload shorter than its header says.
        b"{\"op\":\"copy\",\"len\":10}\nabc".to_vec(),
        // A header longer than 64 KiB without its newline.
        vec![b'{'; 70 << 10],
        // A header of a wrong type.
        b"{\"op\":7}\n".to_vec(),
    ];
    for bytes in &cases {
        let got = raw(bytes);
        assert!(got.is_empty(), "{:?}: {:?}", String::from_utf8_lossy(&bytes[..bytes.len().min(40)]), got);
        assert_eq!(svc.status()["role"], "member");
    }
    // A client that hangs up before its answer.
    for _ in 0..20 {
        let mut c = UnixStream::connect(svc.socket(false)).unwrap();
        send(&mut c, &json!({"op": "status"}), b"");
        drop(c);
    }
    // Many clients at once each get their answer.
    let threads: Vec<_> = (0..16)
        .map(|_| {
            let sock = svc.socket(false);
            std::thread::spawn(move || {
                let mut c = UnixStream::connect(sock).unwrap();
                c.set_read_timeout(Some(ANSWER)).unwrap();
                send(&mut c, &json!({"op": "version"}), b"");
                let mut r = std::io::BufReader::new(c);
                read(&mut r).map(|m| m.error().is_empty())
            })
        })
        .collect();
    for t in threads {
        assert_eq!(t.join().unwrap(), Some(true));
    }
    assert_eq!(svc.status()["role"], "member");
}

/// cbb copy and cbb paste: the text, its kind, and what is refused.
#[test]
fn copies_and_pastes_text() {
    let svc = Svc::start("desk", &[], &[]);
    svc.new_group();
    has(&svc.err(false, json!({"op": "paste"})), "the clipboard is empty");
    svc.ok_with(false, json!({"op": "copy"}), "hello, group".as_bytes());
    let m = svc.ok(false, json!({"op": "paste"}));
    assert_eq!((m.payload.as_slice(), m.s("kind")), (&b"hello, group"[..], "text"));
    svc.ok_with(false, json!({"op": "copy", "kind": "secret", "via": "phone"}), b"pin 1234");
    let m = svc.ok(false, json!({"op": "paste"}));
    assert_eq!((m.payload.as_slice(), m.s("kind")), (&b"pin 1234"[..], "secret"));
    assert!(!svc.err_with(false, json!({"op": "copy", "kind": "loud"}), b"x").is_empty());
    assert!(!svc.err_with(false, json!({"op": "copy", "via": "pigeon"}), b"x").is_empty());
    has(&svc.err_with(false, json!({"op": "copy"}), b"\xff\xfe"), "not UTF-8");
}

/// cbb copy FILE and cbb paste -o: the parts of a copy of files, and the
/// framings that are refused.
#[test]
fn copies_and_pastes_files() {
    let svc = Svc::start("desk", &[], &[]);
    svc.new_group();
    has(&svc.err(false, json!({"op": "paste_media"})), "");
    let copy = |alt: &[u8], parts: &[(Value, Vec<&[u8]>)], end: bool| -> Msg {
        let (mut c, mut r) = svc.open(false, &json!({"op": "copy_media"}), alt);
        for (p, data) in parts {
            send(&mut c, &json!({"op": "part", "part": p}), b"");
            for d in data {
                send(&mut c, &json!({"op": "data"}), d);
            }
        }
        if end {
            send(&mut c, &json!({"op": "part", "done": true}), b"");
        }
        let _ = c.shutdown(std::net::Shutdown::Write);
        read(&mut r).expect("an answer")
    };
    let file = json!({"path": "a.txt", "size": 5});
    let m = copy(b"a.txt", &[(file.clone(), vec![b"he", b"llo"])], true);
    assert!(m.error().is_empty(), "{:?}\n{}", m.h, svc.log());
    // paste-media gives the alternative, the part and its bytes.
    let got = svc.ask_all(false, json!({"op": "paste_media"}), b"");
    assert!(got.iter().all(|m| m.error().is_empty()), "{got:?}");
    assert_eq!(got[0].s("kind"), "media");
    assert_eq!(got[0].payload, b"a.txt");
    let bytes: Vec<u8> = got.iter().skip(1).flat_map(|m| m.payload.clone()).collect();
    assert_eq!(bytes, b"hello");
    assert!(got.last().unwrap().done());
    // The status names the limits.
    let media = svc.status()["media"].clone();
    assert!(media["max_copy"].as_i64().unwrap() > 0, "{media}");

    // Refused: no parts, a part of other bytes than it says, a message that
    // is no part, a copy past the limit, a text that is not UTF-8.
    has(copy(b"", &[], true).error(), "no parts");
    has(copy(b"", &[(file.clone(), vec![b"toolong"])], true).error(), "did not come as said");
    has(copy(b"", &[(file.clone(), vec![b"he"])], false).error(), "did not come as said");
    has(copy(b"", &[(json!({"path": "b", "size": -1}), vec![])], true).error(), "without its description");
    has(copy(b"\xff", &[(file.clone(), vec![b"hello"])], true).error(), "not UTF-8");
    has(copy(b"", &[(json!({"path": "b", "size": 1_i64 << 40}), vec![])], true).error(), "larger than");
    let (mut c, mut r) = svc.open(false, &json!({"op": "copy_media"}), b"");
    send(&mut c, &json!({"op": "status"}), b"");
    has(read(&mut r).unwrap().error(), "expected a part");
    // The service still takes copies.
    svc.ok_with(false, json!({"op": "copy"}), b"after");
}

/// cbb config: the largest copy at home and away, and what it refuses.
#[test]
fn sets_the_largest_copy() {
    let svc = Svc::start("desk", &[], &[]);
    svc.new_group();
    let m = svc.ok(false, json!({"op": "config"}));
    let before = m.h["status"]["media"].clone();
    assert!(before["max_copy"].as_i64().unwrap() > 0, "{before}");
    let m = svc.ok(false, json!({"op": "config", "name": "max-copy", "value": "10MiB"}));
    assert_eq!(m.h["status"]["media"]["max_copy"], 10 << 20);
    let m = svc.ok(false, json!({"op": "config", "name": "max-copy-away", "value": "1MiB"}));
    assert_eq!(m.h["status"]["media"]["max_copy_away"], 1 << 20);
    assert!(!svc.err(false, json!({"op": "config", "name": "max-copy", "value": "lots"})).is_empty());
    assert!(!svc.err(false, json!({"op": "config", "name": "colour", "value": "blue"})).is_empty());
    // Kept across a restart.
    let mut svc = svc;
    svc.restart(&[], &[]);
    assert_eq!(svc.status()["media"]["max_copy"], 10 << 20);
}

/// The quick actions a device's user sets: the presets on and off, their
/// own actions added and removed.
#[test]
fn sets_the_quick_actions() {
    let svc = Svc::start("desk", &[], &[]);
    svc.new_group();
    let set = |a: Value| svc.ask(true, json!({"op": "action_set", "actions": [a]}), b"");
    let m = set(json!({"name": "lock", "on": true, "by": ["root"]}));
    assert!(m.error().is_empty(), "{:?}", m.h);
    let lock = m.h["status"]["actions"].as_array().unwrap().iter().find(|a| a["name"] == "lock").cloned().unwrap();
    assert_eq!(lock["on"], true, "{lock}");
    assert!(!set(json!({"name": "nothing-like-it", "on": true})).error().is_empty());
    assert!(!set(json!({"name": "lock", "on": true, "by": ["strangers"]})).error().is_empty());
    has(svc.ask(true, json!({"op": "action_set", "actions": []}), b"").error(), "one quick action at a time");
    let m = set(json!({"name": "backup", "on": true, "command": ["/bin/true"]}));
    assert!(m.error().is_empty(), "{:?}", m.h);
    assert!(m.h["status"]["actions"].as_array().unwrap().iter().any(|a| a["name"] == "backup"));
    // Turned off, an own action keeps its command.
    assert!(set(json!({"name": "backup", "on": false})).error().is_empty());
    svc.ok(true, json!({"op": "action_remove", "name": "backup"}));
    has(&svc.err(true, json!({"op": "action_remove", "name": "backup"})), "no action of its user's own");
    has(&svc.err(true, json!({"op": "action_remove", "name": "lock"})), "is a preset");
    let m = svc.ok(true, json!({"op": "actions_off"}));
    assert!(m.h["status"]["actions"].as_array().unwrap().iter().all(|a| a["on"] != true), "{:?}", m.h);
}

/// cbb paste-receive on this device: the switches, kept in the status.
#[test]
fn sets_remote_paste() {
    let svc = Svc::start("desk", &[], &[]);
    svc.new_group();
    let m = svc.ok(true, json!({"op": "paste_receive", "name": "on", "enter": true, "no_lock_check": true}));
    let p = m.h["status"]["paste"].clone();
    assert_eq!((p["on"].as_bool(), p["enter"].as_bool()), (Some(true), Some(true)), "{p}");
    assert_eq!(svc.status()["paste"]["on"], true);
    let m = svc.ok(true, json!({"op": "paste_receive", "name": "off"}));
    assert_eq!(m.h["status"]["paste"]["on"], false);
}

/// The signed release and entry points cbb update brings, and what a
/// device that holds none answers.
#[test]
fn releases_and_entry_points() {
    let svc = Svc::start("desk", &[], &[]);
    svc.new_group();
    has(&svc.err(false, json!({"op": "entries_get"})), "no signed entry points");
    has(&svc.err(false, json!({"op": "release_held"})), "no signed release");
    has(&svc.err_with(false, json!({"op": "entries"}), b"not json"), "carries no entry points");
    has(&svc.err_with(false, json!({"op": "release"}), b"not json"), "carries no release");
    // Signed by nobody the device trusts: refused.
    assert!(!svc.err_with(false, json!({"op": "entries"}), b"{\"v\":1}").is_empty());
    assert!(!svc.err_with(false, json!({"op": "release"}), b"{\"v\":1}").is_empty());
    // Not a hub: it wants no archives; no way to update away from home.
    let m = svc.ok(true, json!({"op": "release_want"}));
    assert_eq!(m.payload, b"null");
    let m = svc.ok(true, json!({"op": "update_way"}));
    assert!(m.payload.is_empty(), "{:?}", String::from_utf8_lossy(&m.payload));
    assert!(!svc.err(false, json!({"op": "release_get", "value": "00"})).is_empty());
    assert!(!svc.err(true, json!({"op": "release_file"})).is_empty());
}

/// The Bluetooth keyboard and the TVs' remotes need cbb-helper: without it
/// they say so, and the status still answers.
#[test]
fn peripherals_without_the_helper() {
    let svc = Svc::start("desk", &[], &[]);
    for op in ["keyboard", "remote"] {
        has(&svc.err(true, json!({"op": op, "name": "status"})), "cbb-helper");
    }
    svc.new_group();
    for op in ["keyboard", "remote"] {
        has(&svc.err(true, json!({"op": op})), "cbb-helper");
    }
    assert!(svc.status()["keyboard"].is_null());
}

/// A watcher: the copies it reports go to the group, the group's go to it,
/// and a watcher that offers an unknown paste target is still served.
#[test]
fn serves_a_watcher() {
    let svc = Svc::start("desk", &[], &[]);
    svc.new_group();
    let (mut c, mut r) = svc.open(false, &json!({"op": "watch", "inject": "fax"}), b"");
    send(&mut c, &json!({"op": "copied"}), b"from the watcher");
    wait_for(
        "the watcher's copy is the clipboard",
        || {
            let m = svc.ask(false, json!({"op": "paste"}), b"");
            (m.payload == b"from the watcher").then_some(())
        },
        || svc.log(),
    );
    drop((c, r.get_mut().try_clone()));
    let (mut c, _r) = svc.open(false, &json!({"op": "watch", "images": true}), b"");
    send(&mut c, &json!({"op": "clipboard"}), b"local text");
    send(&mut c, &json!({"op": "answer"}), b"");
    std::thread::sleep(Duration::from_millis(200));
    assert_eq!(svc.status()["role"], "member");
    has(svc.log().as_str(), "\"fax\", which is not known");
}

/// A damaged identity.json: the service runs without its group, answers
/// every request with why, and takes only cbb leave, after which it starts
/// again in no group.
#[test]
fn a_damaged_group_file_takes_only_leave() {
    let mut svc = Svc::start("desk", &[], &[]);
    svc.new_group();
    svc.stop();
    write(&svc.state().join("identity.json"), "{ damaged");
    svc.restart(&[], &[]);
    for op in ["status", "devices", "copy", "rename", "pair"] {
        let m = svc.ask(true, json!({"op": op}), b"");
        assert!(m.error().contains("identity.json"), "{op}: {:?}\n{}", m.h, svc.log());
        assert!(!m.s("detail").is_empty(), "{:?}", m.h);
    }
    svc.ok(true, json!({"op": "leave"}));
    svc.wait_exit(Duration::from_secs(20));
    assert!(!svc.state().join("identity.json").exists());
    svc.restart(&[], &[]);
    assert!(svc.status()["group"].is_null());
}

/// The service keeps its group across a restart: the same device, group
/// and settings.
#[test]
fn keeps_its_group_across_a_restart() {
    let mut svc = Svc::start("desk", &[], &[]);
    let made = svc.new_group();
    svc.ok(true, json!({"op": "sync", "on": false, "for_ms": 3_600_000}));
    svc.ok(true, json!({"op": "paste_receive", "name": "on"}));
    svc.restart(&[], &[]);
    let st = svc.status();
    assert_eq!((&st["device"], &st["group"]), (&made["device"], &made["group"]));
    assert!(st["sync_until_ms"].as_i64().unwrap() > 0, "{st}");
    assert_eq!(st["paste"]["on"], true);
    // A second service at the same socket refuses to start.
    let dir = svc.dir.clone();
    let mut second = std::process::Command::new(env!("CARGO_BIN_EXE_cbb"))
        .arg("-state")
        .arg(dir.join("s2"))
        .arg("-socket")
        .arg(svc.socket(false))
        .args(["service", "-name", "two", "-no-mdns", "-no-listen"])
        .env("CBB_HELPER", "")
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let st = second.wait().unwrap();
    assert!(!st.success());
    let mut err = String::new();
    std::io::Read::read_to_string(second.stderr.as_mut().unwrap(), &mut err).unwrap();
    has(&err, "another cbb service runs");
    assert_eq!(svc.status()["device"], made["device"]);
}
