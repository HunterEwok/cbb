// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The admin operations of the control socket on real services, as the
//! command line sends them: a root admits members through its pairing
//! window, signs records for them and sends them commands; a member that
//! is no admin is refused each of them with the reason the user reads.

#![cfg(unix)]

mod common;

use std::time::Duration;

use common::*;
use serde_json::json;

fn has(e: &str, part: &str) {
    assert!(e.contains(part), "{e:?} does not say {part:?}");
}

/// Renaming and removing a device, and what the root refuses.
#[test]
fn renames_and_removes_a_device() {
    let g = group(&["root", "desk", "lap"]);
    let (root, desk, lap) = (&g[0], &g[1], &g[2]);
    // The answer names the device as it was.
    let m = root.ok(true, json!({"op": "rename", "name": "desk", "new_name": "work"}));
    assert_eq!((m.s("name"), m.done()), ("desk", true));
    desk.wait("desk learns its new name", |_| desk.find("work").is_some());
    // The same name signs nothing and still answers.
    let m = root.ok(true, json!({"op": "rename", "name": "WORK", "new_name": "work"}));
    assert_eq!(m.s("name"), "work");
    has(&root.err(true, json!({"op": "rename", "name": "work", "new_name": " "})), "1 to 64 characters");
    has(&root.err(true, json!({"op": "rename", "name": "nobody", "new_name": "x"})), "no device \"nobody\"");
    // By its ID too.
    let lap_id = lap.device();
    let m = root.ok(true, json!({"op": "rename", "name": lap_id, "new_name": "laptop"}));
    assert_eq!(m.s("name"), "lap");

    has(&root.err(true, json!({"op": "revoke", "name": "root"})), "cannot remove itself");
    has(&root.err(true, json!({"op": "freeze", "name": "root"})), "cannot freeze or unfreeze itself");
    has(&root.err(true, json!({"op": "freeze", "name": "work"})), "no admin computer");
    has(&root.err(true, json!({"op": "thaw", "name": "work"})), "no admin computer");
    has(&root.err(true, json!({"op": "resolve"})), "no key of the group signed two histories");

    let m = root.ok(true, json!({"op": "revoke", "name": "work"}));
    assert_eq!(m.s("name"), "work");
    assert!(root.find("work").is_none(), "{:?}", root.devices());
    // The removed device learns it, over the records the root sends.
    desk.wait("desk learns it was removed", |st| st["removed"] == true);
    has(&root.err(true, json!({"op": "revoke", "name": "work"})), "no device");
}

/// What a member that is no admin is refused, each with its reason.
#[test]
fn a_member_is_no_admin() {
    let g = group(&["root", "desk"]);
    let desk = &g[1];
    let refused = [
        (json!({"op": "rename", "name": "root", "new_name": "x"}), "only an admin can change the devices list"),
        (json!({"op": "revoke", "name": "root"}), "only an admin can change the devices list"),
        (json!({"op": "freeze", "name": "root"}), "only an admin can change the devices list"),
        (json!({"op": "resolve"}), "only an admin can change the devices list"),
        (json!({"op": "admin", "name": "root"}), "only the group's root makes admins"),
        (json!({"op": "key-level", "value": "files"}), "only the group's root sets the key level"),
        (json!({"op": "takeover-delay", "value": "1h"}), "only the group's root sets how long a claim waits"),
        (json!({"op": "incoming", "value": "1m"}), "only the group's root or an admin sets"),
        (json!({"op": "hubs", "hubs": ["root"]}), "only the group's root or an admin that may be a hub"),
        (json!({"op": "handover", "name": "root"}), "only the group's root hands the group over"),
        (json!({"op": "takeover", "name": "root"}), "only an admin takes the group over"),
        (json!({"op": "mute", "device": "root"}), "only an admin mutes a device"),
        (json!({"op": "unmute", "device": "root"}), "only an admin mutes a device"),
        (json!({"op": "sync", "name": "off", "device": "root"}), "only an admin turns another device's sync"),
        (json!({"op": "action-on", "device": "root", "name": "lock"}), "only an admin pastes on another device"),
        (json!({"op": "actions-off", "device": "root"}), "only an admin pastes on another device"),
        (json!({"op": "paste-receive", "name": "off", "device": "root"}), "only an admin pastes on another device"),
        (json!({"op": "away", "name": "off", "device": "root"}), "only an admin turns sync away from home off"),
        (json!({"op": "pair"}), "only the group's root or an admin adds devices"),
    ];
    for (h, why) in refused {
        let e = desk.err(true, h.clone());
        assert!(e.contains(why), "{h}: {e:?} does not say {why:?}");
    }
    let e = desk.err_with(true, json!({"op": "paste-on", "device": "root"}), b"hello");
    has(&e, "only an admin pastes on another device");
    // Its own things it does: its sync, its remote paste, its actions.
    let st = desk.ok(false, json!({"op": "sync", "name": "off", "for_ms": 60_000})).h["status"].clone();
    assert!(st["sync_until_ms"].as_i64().unwrap_or(0) > 0, "{st}");
    desk.ok(false, json!({"op": "sync", "name": "on"}));
    assert!(!desk.state().join("sync.json").exists());
    desk.ok(true, json!({"op": "paste-receive", "name": "off"}));
    desk.ok(true, json!({"op": "actions-off"}));
}

/// The root's group settings: the key level, the takeover delay, how long
/// an incoming copy stays live, the main hubs.
#[test]
fn the_roots_settings() {
    let g = group(&["root", "desk"]);
    let (root, desk) = (&g[0], &g[1]);
    has(&root.err(true, json!({"op": "key-level", "value": "maybe"})), "proven, hardware or files");
    // The root's own keys are in a file, below the level hardware.
    assert!(!root.err(true, json!({"op": "key-level", "value": "hardware"})).is_empty());
    let m = root.ok(true, json!({"op": "key-level", "value": "files"}));
    assert!(m.h["below"].as_array().is_none_or(Vec::is_empty), "{:?}", m.h);
    assert_eq!(root.status()["key_level"], "files");

    has(&root.err(true, json!({"op": "takeover-delay", "value": "200h"})), "from 0s to 168h");
    has(&root.err(true, json!({"op": "takeover-delay", "value": "soon"})), "from 0s to 168h");
    root.ok(true, json!({"op": "takeover-delay", "value": "1h30m"}));

    has(&root.err(true, json!({"op": "incoming", "value": "1s"})), "from 5s to 1h");
    has(&root.err(true, json!({"op": "incoming", "value": "2h"})), "from 5s to 1h");
    root.ok(true, json!({"op": "incoming", "value": "5m"}));
    assert_eq!(root.status()["incoming_ms"], 300_000);
    desk.wait("desk takes the copies setting", |st| st["incoming_ms"] == 300_000);

    has(&root.err(true, json!({"op": "hubs", "hubs": []})), "name 1 to");
    has(&root.err(true, json!({"op": "hubs", "hubs": ["root", "ROOT"]})), "named twice");
    has(&root.err(true, json!({"op": "hubs", "hubs": ["nobody"]})), "no device");
    root.ok(true, json!({"op": "hubs", "hubs": ["root", "desk"]}));
}

/// Making a computer an admin, freezing and unfreezing it, and handing the
/// group over to it.
#[test]
fn makes_an_admin_and_hands_the_group_over() {
    let g = group(&["root", "desk", "lap"]);
    let (root, desk, lap) = (&g[0], &g[1], &g[2]);
    // Its keys are in a file: only with the user's consent.
    has(&root.err(true, json!({"op": "admin", "name": "desk"})), "allow-file-key");
    has(&root.err(true, json!({"op": "admin", "name": "root"})), "more than an admin");
    has(&root.err(true, json!({"op": "handover", "name": "desk"})), "is no admin");
    let m = root.ok(true, json!({"op": "admin", "name": "desk", "consent": true}));
    assert_eq!(m.s("name"), "desk");
    has(&root.err(true, json!({"op": "admin", "name": "desk", "consent": true})), "already an admin");
    // The admin CA reaches it over its connection; then it signs.
    wait_for(
        "desk signs as an admin",
        || {
            let m = desk.ask(true, json!({"op": "incoming", "value": "30s"}), b"");
            m.error().is_empty().then_some(())
        },
        || desk.log(),
    );
    // It admits a device through its own window, and renames it: its own
    // record of that device is the one that counts.
    let pad = Svc::start("pad", &["-peer", &desk.addr()], &[]);
    assert_eq!(desk.admit(&pad, false), "pad");
    root.wait("the root learns of pad", |_| root.find("pad").is_some());
    let m = desk.ok(true, json!({"op": "rename", "name": "pad", "new_name": "tablet"}));
    assert_eq!(m.s("name"), "pad");
    root.wait("the root learns pad's new name", |_| root.find("tablet").is_some());
    desk.ok(true, json!({"op": "revoke", "name": "tablet"}));
    root.wait("the root learns pad left", |_| root.find("tablet").is_none());
    let _ = lap;
    // An admin computer does not rename the root's own device, remove
    // the root or take over a device that is not the root.
    has(&desk.err(true, json!({"op": "rename", "name": "root", "new_name": "x"})), "only the group's root renames");
    has(&desk.err(true, json!({"op": "revoke", "name": "root"})), "holds the group's root");
    has(&desk.err(true, json!({"op": "takeover", "name": "lap"})), "not the group's root");
    has(&desk.err(true, json!({"op": "admin", "name": "lap"})), "only the group's root makes admins");
    has(&desk.err(true, json!({"op": "freeze", "name": "root"})), "which nobody freezes");
    has(&desk.err(true, json!({"op": "handover", "name": "lap"})), "only the group's root hands");

    // Frozen, it signs nothing; the root unfreezes it.
    let m = root.ok(true, json!({"op": "freeze", "name": "desk"}));
    assert_eq!(m.s("name"), "desk");
    has(&root.err(true, json!({"op": "freeze", "name": "desk"})), "frozen already");
    desk.wait("desk learns it is frozen", |st| st["frozen"] == true);
    has(&desk.err(true, json!({"op": "rename", "name": "lap", "new_name": "x"})), "froze this computer's admin key");
    has(&desk.err(true, json!({"op": "mute", "device": "lap"})), "froze this computer's admin key");
    has(&desk.err(true, json!({"op": "action-on", "device": "lap", "name": "lock"})), "froze");
    root.ok(true, json!({"op": "thaw", "name": "desk"}));
    has(&root.err(true, json!({"op": "thaw", "name": "desk"})), "is not frozen");
    desk.wait("desk learns it is unfrozen", |st| st["frozen"] != true);

    // Handed over, desk's claim takes effect at once: it is the root, and
    // its device record says so.
    let m = root.ok(true, json!({"op": "handover", "name": "desk"}));
    assert_eq!(m.s("name"), "desk");
    // A claim counts as handed over only when made after the handover
    // reached the admin: a record the root signs after it shows it has.
    root.ok(true, json!({"op": "incoming", "value": "45s"}));
    desk.wait("desk holds the handover", |st| st["incoming_ms"] == 45_000);
    wait_for(
        "desk takes the group over",
        || desk.ask(true, json!({"op": "takeover", "name": "root"}), b"").error().is_empty().then_some(()),
        || desk.log(),
    );
    wait_for(
        "desk becomes the root",
        || desk.devices().into_iter().find(|d| d["self"] == true && d["root"] == true),
        || desk.log(),
    );
    // As the root it makes admins, and the old root can no longer.
    has(&desk.err(true, json!({"op": "takeover", "name": "desk"})), "root already");
    root.wait("the old root learns desk took the group over", |st| st["taken_over_by"] == "desk");
}

/// An admin takes the group over from its lost root, after the delay the
/// root set.
#[test]
fn an_admin_takes_the_group_over() {
    let mut g = group(&["root", "desk"]);
    g[0].ok(true, json!({"op": "takeover-delay", "value": "0s"}));
    wait_for(
        "the root makes desk an admin",
        || {
            g[0].ask(true, json!({"op": "admin", "name": "desk", "consent": true}), b"")
                .error()
                .is_empty()
                .then_some(())
        },
        || g[0].log(),
    );
    let desk_id = g[1].device();
    wait_for(
        "desk holds its admin CA",
        || {
            let m = g[1].ask(true, json!({"op": "incoming", "value": "1m"}), b"");
            m.error().is_empty().then_some(())
        },
        || g[1].log(),
    );
    g[0].stop();
    let desk = &g[1];
    let m = desk.ok(true, json!({"op": "takeover", "name": "root"}));
    assert_eq!(m.s("name"), "root");
    wait_for(
        "desk becomes the root",
        || desk.devices().into_iter().find(|d| d["id"] == desk_id.as_str() && d["root"] == true),
        || desk.log(),
    );
    has(&desk.err(true, json!({"op": "takeover", "name": "desk"})), "root already");
    // The old root is no longer listed.
    assert!(desk.find("root").is_none(), "{:?}", desk.devices());
}

/// Commands a root sends a member: mute, sync, remote paste, quick actions,
/// sync away from home; each comes back with the member's result.
#[test]
fn commands_reach_a_member() {
    let g = group(&["root", "desk"]);
    let (root, desk) = (&g[0], &g[1]);
    has(&root.err(true, json!({"op": "mute"})), "name a device with -on");
    root.ok(true, json!({"op": "mute", "device": "desk", "for_ms": 60_000}));
    desk.wait("desk is muted", |st| st["muted"] == true && st["muted_until_ms"].as_i64().unwrap_or(0) > 0);
    root.ok(true, json!({"op": "unmute", "device": "desk"}));
    desk.wait("desk is unmuted", |st| st["muted"] != true);
    // Its own mute it sets at once.
    root.ok(true, json!({"op": "mute", "device": "root"}));
    assert_eq!(root.status()["muted"], true);
    root.ok(true, json!({"op": "unmute", "device": "root"}));

    has(&root.err(true, json!({"op": "sync", "name": "off", "device": "desk", "for_ms": 1000})), "with no time");
    has(&root.err(true, json!({"op": "sync", "name": "on", "for_ms": 1000})), "only with cbb sync off");
    assert!(!root.err(true, json!({"op": "sync", "name": "sideways"})).is_empty());
    let m = root.ok(true, json!({"op": "sync", "name": "off", "device": "desk"}));
    assert_eq!(m.s("name"), "desk");
    let off = desk.state().join("sync.json");
    wait_for("desk's sync is off", || off.exists().then_some(()), || desk.log());
    root.ok(true, json!({"op": "sync", "name": "on", "device": "desk"}));
    wait_for("desk's sync is on", || (!off.exists()).then_some(()), || desk.log());
    // -on naming this device turns its own sync.
    root.ok(true, json!({"op": "sync", "name": "off", "device": "root", "for_ms": 0}));
    root.ok(true, json!({"op": "sync", "name": "on"}));

    has(&root.err(true, json!({"op": "paste-receive", "name": "maybe"})), "on or off");
    has(&root.err(true, json!({"op": "paste-receive", "name": "on", "device": "desk"})), "own user");
    has(&root.err(true, json!({"op": "paste-receive", "name": "off", "enter": true})), "go with on");
    root.ok(true, json!({"op": "paste-receive", "name": "off", "device": "desk"}));
    root.ok(true, json!({"op": "paste-receive", "name": "off", "all": true}));
    root.ok(true, json!({"op": "actions-off", "device": "desk"}));
    root.ok(true, json!({"op": "actions-off", "all": true}));
    root.ok(true, json!({"op": "actions-off", "device": "root"}));

    // Remote paste is off on desk: refused there, with its reason.
    let e = root.err_with(true, json!({"op": "paste-on", "device": "desk"}), b"hello");
    has(&e, "desk");
    has(&root.err_with(true, json!({"op": "paste-on", "device": "desk"}), b"\x01\x02"), "nothing to paste");
    has(&root.err_with(true, json!({"op": "paste-on", "device": "root"}), b"hi"), "for another device");
    has(&root.err(true, json!({"op": "paste-on", "device": "desk", "kind": "media"})), "no images or files");
    let e = root.err(true, json!({"op": "paste-on", "device": "desk", "kind": "media", "method": "type"}));
    has(&e, "pasted, not typed");
    // Quick actions are off on desk too.
    has(&root.err(true, json!({"op": "action-on", "device": "desk", "name": "lock"})), "desk");
    has(&root.err(true, json!({"op": "action-on", "device": "desk", "name": "no such!"})), "not an action's name");
    has(&root.err(true, json!({"op": "action-on", "device": "root", "name": "lock"})), "runs on another device");
    has(&root.err(true, json!({"op": "away", "name": "off", "device": "root"})), "-on names this device");
    root.ok(true, json!({"op": "away", "name": "off", "device": "desk"}));
}

/// One pairing at a time, a join only outside a group, a join's code
/// checked before it dials.
#[test]
fn pairing_one_at_a_time() {
    let root = Svc::start("root", &[], &[]);
    // Outside a group nothing admits.
    assert!(!root.err(true, json!({"op": "pair"})).is_empty());
    root.new_group();
    let (_conn, mut r) = root.open(true, &json!({"op": "pair"}), b"");
    let opened = read(&mut r).unwrap();
    assert_eq!(opened.h["expires"], 300);
    has(&root.err(true, json!({"op": "pair"})), "already open");
    has(&root.err(true, json!({"op": "pair", "code": "123456", "addrs": ["127.0.0.1:9"]})), "already open");
    has(&root.err(true, json!({"op": "join", "code": "123456"})), "already in a group");
    let other = Svc::start("other", &[], &[]);
    assert!(!other.err(true, json!({"op": "join", "code": "12"})).is_empty());
    // A wrong code: the window takes one guess at a time and stays open.
    let wrong = if opened.s("code") == "000000" { "111111" } else { "000000" };
    let e = other.err(true, json!({"op": "join", "code": wrong, "address": root.addr()}));
    assert!(!e.is_empty());
    drop((_conn, r));
    // Once the client hung up the window closes, and another opens.
    wait_for(
        "the window closes",
        || {
            let (c, mut r) = root.open(true, &json!({"op": "pair"}), b"");
            let m = read(&mut r)?;
            drop(c);
            m.error().is_empty().then_some(())
        },
        || root.log(),
    );
    // A join to a port where nobody listens fails at once.
    let e = other.err(true, json!({"op": "join", "code": "123456", "address": "127.0.0.1:9"}));
    has(&e, "127.0.0.1:9");
}

/// Admission by the joiner's QR code: the joiner listens, and the admin
/// dials it with the code, the addresses and the fingerprint it shows.
#[test]
fn admits_by_qr_code() {
    let root = Svc::start("root", &[], &[]);
    root.new_group();
    let desk = Svc::start("desk", &["-peer", &root.addr()], &[]);
    let code = "482915";
    let (_conn, mut r) = desk.open(true, &json!({"op": "join", "code": code, "listen": true, "expires": 60}), b"");
    let shown = read(&mut r).unwrap();
    assert!(shown.error().is_empty(), "{:?}", shown.h);
    let fp = shown.s("fingerprint").to_string();
    assert!(!fp.is_empty(), "{:?}", shown.h);
    // A container may have no private address for the QR code: the join
    // then ends with why, as the second answer.
    let Some(port) = shown.h["addrs"]
        .as_array()
        .and_then(|a| a.first())
        .and_then(|a| a.as_str())
        .and_then(|a| a.rsplit(':').next())
        .map(String::from)
    else {
        let why = read(&mut r).expect("why the join ended");
        has(why.error(), "no address on the home network");
        eprintln!("admits_by_qr_code: no private address here, so only the refusal is checked");
        return;
    };
    let addr = format!("127.0.0.1:{port}");
    let e = root.err(true, json!({"op": "pair", "code": "000001", "addrs": [addr], "fingerprint": fp}));
    assert!(!e.is_empty());
    let m = root.ok(true, json!({"op": "pair", "code": code, "addrs": [addr], "fingerprint": fp}));
    assert_eq!(m.s("name"), "desk");
    let done = read(&mut r).unwrap();
    assert!(done.error().is_empty() && done.done(), "{:?}", done.h);
    root.wait_peer("desk");
}

/// Leaving: the root only alone; a member leaves and its service stops,
/// with its group's files deleted.
#[test]
fn leaves_the_group() {
    let mut g = group(&["root", "desk"]);
    has(&g[0].err(true, json!({"op": "leave"})), "group's root");
    g[1].ok(true, json!({"op": "leave"}));
    g[1].wait_exit(Duration::from_secs(20));
    assert!(!g[1].state().join("identity.json").exists());
    // Started again, it is in no group, and leaving again says so.
    g[1].restart(&[], &[]);
    assert_eq!(g[1].status()["group"], serde_json::Value::Null);
    has(&g[1].err(true, json!({"op": "leave"})), "");
    g[0].ok(true, json!({"op": "revoke", "name": "desk"}));
    g[0].ok(true, json!({"op": "leave"}));
    g[0].wait_exit(Duration::from_secs(20));
    assert!(!g[0].state().join("identity.json").exists());
}
