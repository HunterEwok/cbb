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
use serde_json::{Value, json};

fn has(e: &str, part: &str) {
    assert!(e.contains(part), "{e:?} does not say {part:?}");
}

/// Renaming and removing a device, and what the root refuses.
#[test]
fn renames_and_removes_a_device() {
    let g = group(&["root", "desk", "lap"]);
    let (root, desk, lap) = (&g[0], &g[1], &g[2]);
    // The answer names the device as it was.
    let m = root.ok(true, json!({"op": "rename", "device": "desk", "name": "work"}));
    assert_eq!((m.s("name"), m.done()), ("desk", true));
    desk.wait("desk learns its new name", |_| desk.find("work").is_some());
    // The same name signs nothing and still answers.
    let m = root.ok(true, json!({"op": "rename", "device": "WORK", "name": "work"}));
    assert_eq!(m.s("name"), "work");
    has(&root.err(true, json!({"op": "rename", "device": "work", "name": " "})), "1 to 64 characters");
    has(&root.err(true, json!({"op": "rename", "device": "nobody", "name": "x"})), "no device \"nobody\"");
    // By its ID too.
    let lap_id = lap.device();
    let m = root.ok(true, json!({"op": "rename", "device": lap_id, "name": "laptop"}));
    assert_eq!(m.s("name"), "lap");

    has(&root.err(true, json!({"op": "remove", "device": "root"})), "cannot remove itself");
    has(&root.err(true, json!({"op": "freeze", "device": "root"})), "cannot freeze or unfreeze itself");
    has(&root.err(true, json!({"op": "freeze", "device": "work"})), "no admin computer");
    has(&root.err(true, json!({"op": "thaw", "device": "work"})), "no admin computer");
    has(&root.err(true, json!({"op": "resolve"})), "no key of the group signed two histories");

    let m = root.ok(true, json!({"op": "remove", "device": "work"}));
    assert_eq!(m.s("name"), "work");
    assert!(root.find("work").is_none(), "{:?}", root.devices());
    // The removed device need not learn it (the owner's rule): the root
    // refuses it and sends it no records.
    root.wait("the root refuses desk", |st| {
        !st["peers"].as_array().is_some_and(|ps| ps.iter().any(|p| p["name"] == "work"))
    });
    assert_ne!(desk.status()["removed"], true, "a removed device was sent its removal");
    has(&root.err(true, json!({"op": "remove", "device": "work"})), "no device");
}

/// What a member that is no admin is refused, each with its reason.
#[test]
fn a_member_is_no_admin() {
    let g = group(&["root", "desk"]);
    let desk = &g[1];
    let refused = [
        (json!({"op": "rename", "device": "root", "name": "x"}), "only an admin can change the devices list"),
        (json!({"op": "remove", "device": "root"}), "only an admin can change the devices list"),
        (json!({"op": "freeze", "device": "root"}), "only an admin can change the devices list"),
        (json!({"op": "resolve"}), "only an admin can change the devices list"),
        (json!({"op": "make_admin", "device": "root"}), "only the group's root makes admins"),
        (json!({"op": "key_level", "value": "files"}), "only the group's root sets the key level"),
        (json!({"op": "takeover_delay", "value": "1h"}), "changes only with its recovery key"),
        (json!({"op": "ttl", "value": "1m"}), "only the group's root or an admin sets"),
        (json!({"op": "hubs", "hubs": ["root"]}), "only the group's root or an admin that may be a hub"),
        (json!({"op": "hand_over", "device": "root"}), "changes only with its recovery key"),
        (json!({"op": "take_over", "device": "root"}), "changes only with its recovery key"),
        (json!({"op": "mute", "device": "root"}), "only an admin mutes a device"),
        (json!({"op": "unmute", "device": "root"}), "only an admin mutes a device"),
        (json!({"op": "sync", "on": false, "device": "root"}), "only an admin turns another device's sync"),
        (json!({"op": "action_on", "device": "root", "name": "lock"}), "only an admin pastes on another device"),
        (json!({"op": "actions_off", "device": "root"}), "only an admin pastes on another device"),
        (json!({"op": "paste_receive", "name": "off", "device": "root"}), "only an admin pastes on another device"),
        (json!({"op": "away", "name": "off", "device": "root"}), "only an admin turns sync away from home off"),
        (json!({"op": "pair"}), "only the group's root or an admin adds devices"),
    ];
    for (h, why) in refused {
        let e = desk.err(true, h.clone());
        assert!(e.contains(why), "{h}: {e:?} does not say {why:?}");
    }
    let e = desk.err_with(true, json!({"op": "paste_on", "device": "root"}), b"hello");
    has(&e, "only an admin pastes on another device");
    // Its own things it does: its sync, its remote paste, its actions.
    let st = desk.ok(false, json!({"op": "sync", "on": false, "for_ms": 60_000})).h;
    assert!(st["sync_off"] == true && st["sync_off_ms"].as_i64().unwrap_or(0) > 0, "{st}");
    desk.ok(false, json!({"op": "sync", "on": true}));
    assert!(!desk.state().join("sync.json").exists());
    desk.ok(true, json!({"op": "paste_receive", "name": "off"}));
    desk.ok(true, json!({"op": "actions_off"}));
}

/// The root's group settings: the key level, the takeover delay, how long
/// a copy lives, the main hubs.
#[test]
fn the_roots_settings() {
    let g = group(&["root", "desk"]);
    let (root, desk) = (&g[0], &g[1]);
    has(&root.err(true, json!({"op": "key_level", "value": "maybe"})), "proven, hardware or files");
    // The root's own keys are in a file, below the level hardware.
    assert!(!root.err(true, json!({"op": "key_level", "value": "hardware"})).is_empty());
    let m = root.ok(true, json!({"op": "key_level", "value": "files"}));
    assert!(m.h["below"].as_array().is_none_or(Vec::is_empty), "{:?}", m.h);
    assert_eq!(root.status()["key_level"], "files");

    // A claim's delay is gone on the records of 0.6: the root changes only
    // with the recovery key (rule 33).
    for value in ["200h", "soon", "1h30m"] {
        has(&root.err(true, json!({"op": "takeover_delay", "value": value})), "changes only with its recovery key");
    }

    has(&root.err(true, json!({"op": "ttl", "value": "30s"})), "a copy lives from 1m to 1h");
    has(&root.err(true, json!({"op": "ttl", "value": "2h"})), "a copy lives from 1m to 1h");
    has(&root.err(true, json!({"op": "ttl", "value": "5m 2m"})), "a secret lives from 5s to 1m");
    root.ok(true, json!({"op": "ttl", "value": "10m 30s"}));
    assert_eq!(
        (root.status()["ttl_ms"].clone(), root.status()["secret_ttl_ms"].clone()),
        (json!(600_000), json!(30_000))
    );
    desk.wait("desk takes the copies setting", |st| st["ttl_ms"] == 600_000 && st["secret_ttl_ms"] == 30_000);

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
    has(&root.err(true, json!({"op": "make_admin", "device": "desk"})), "allow-file-key");
    has(&root.err(true, json!({"op": "make_admin", "device": "root"})), "more than an admin");
    has(&root.err(true, json!({"op": "hand_over", "device": "desk"})), "changes only with its recovery key");
    let m = root.ok(true, json!({"op": "make_admin", "device": "desk", "allow_file_key": true}));
    assert_eq!(m.s("name"), "desk");
    has(&root.err(true, json!({"op": "make_admin", "device": "desk", "allow_file_key": true})), "already an admin");
    // The admin CA reaches it over its connection; then it signs.
    wait_for(
        "desk signs as an admin",
        || {
            let m = desk.ask(true, json!({"op": "ttl", "value": "2m"}), b"");
            m.error().is_empty().then_some(())
        },
        || desk.log(),
    );
    // It admits a device through its own window, and renames it: its own
    // record of that device is the one that counts.
    let pad = Svc::start("pad", &["-peer", &desk.addr()], &[]);
    assert_eq!(desk.admit(&pad, false), "pad");
    root.wait("the root learns of pad", |_| root.find("pad").is_some());
    let m = desk.ok(true, json!({"op": "rename", "device": "pad", "name": "tablet"}));
    assert_eq!(m.s("name"), "pad");
    root.wait("the root learns pad's new name", |_| root.find("tablet").is_some());
    desk.ok(true, json!({"op": "remove", "device": "tablet"}));
    root.wait("the root learns pad left", |_| root.find("tablet").is_none());
    let _ = lap;
    // An admin computer does not rename the root's own device, remove
    // the root or take over a device that is not the root.
    has(&desk.err(true, json!({"op": "rename", "device": "root", "name": "x"})), "only the group's root renames");
    has(&desk.err(true, json!({"op": "remove", "device": "root"})), "holds the group's root");
    has(&desk.err(true, json!({"op": "take_over", "device": "lap"})), "changes only with its recovery key");
    has(&desk.err(true, json!({"op": "make_admin", "device": "lap"})), "only the group's root makes admins");
    has(&desk.err(true, json!({"op": "freeze", "device": "root"})), "which nobody freezes");
    has(&desk.err(true, json!({"op": "hand_over", "device": "lap"})), "changes only with its recovery key");

    // Frozen, it signs nothing; the root unfreezes it.
    let m = root.ok(true, json!({"op": "freeze", "device": "desk"}));
    assert_eq!(m.s("name"), "desk");
    has(&root.err(true, json!({"op": "freeze", "device": "desk"})), "frozen already");
    // A frozen device learns nothing, its freeze included (the owner's
    // rule for removed and frozen devices): the root refuses it.
    root.wait("the root refuses desk", |st| {
        !st["peers"].as_array().is_some_and(|ps| ps.iter().any(|p| p["name"] == "desk"))
    });
    // What desk signs while frozen never counts: it may refuse itself
    // (when the freeze reached it some other way) or sign, but the group
    // takes none of it, not even after the thaw brings desk back.
    for h in [
        json!({"op": "rename", "device": "lap", "name": "x"}),
        json!({"op": "mute", "device": "lap"}),
        json!({"op": "action_on", "device": "lap", "name": "lock"}),
    ] {
        let m = desk.ask(true, h, b"");
        assert_eq!(m.s("op"), "reply", "{:?}", m.h);
    }
    root.ok(true, json!({"op": "thaw", "device": "desk"}));
    has(&root.err(true, json!({"op": "thaw", "device": "desk"})), "is not frozen");
    root.wait_peer("desk");
    desk.wait_peer("root");
    std::thread::sleep(Duration::from_secs(3));
    let lap_at_root =
        root.find("lap").unwrap_or_else(|| panic!("a frozen admin's rename counted: {:?}", root.devices()));
    assert_ne!(lap_at_root["muted"], true, "a frozen admin's mute counted: {lap_at_root:?}");
    assert_ne!(lap.status()["muted"], true, "a frozen admin's mute reached lap");

    // No handover or claim on the records of 0.6: the root changes only
    // with the recovery key (rule 33).
    has(&root.err(true, json!({"op": "hand_over", "device": "desk"})), "changes only with its recovery key");
    has(&desk.err(true, json!({"op": "take_over", "device": "root"})), "changes only with its recovery key");
}

/// An admin does not take the group over from its lost root on the records
/// of 0.6, whatever delay: the root changes only with the recovery key
/// (rule 33).
#[test]
fn an_admin_does_not_take_the_group_over() {
    let mut g = group(&["root", "desk", "lap"]);
    has(&g[0].err(true, json!({"op": "takeover_delay", "value": "0s"})), "changes only with its recovery key");
    wait_for(
        "the root makes desk an admin",
        || {
            g[0].ask(true, json!({"op": "make_admin", "device": "desk", "allow_file_key": true}), b"")
                .error()
                .is_empty()
                .then_some(())
        },
        || g[0].log(),
    );
    wait_for(
        "the root makes lap an admin",
        || {
            g[0].ask(true, json!({"op": "make_admin", "device": "lap", "allow_file_key": true}), b"")
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
            let m = g[1].ask(true, json!({"op": "ttl", "value": "1m"}), b"");
            m.error().is_empty().then_some(())
        },
        || g[1].log(),
    );
    g[0].stop();
    let desk = &g[1];
    has(&desk.err(true, json!({"op": "take_over", "device": "root"})), "changes only with its recovery key");
    // The lost root is still the group's root, as desk's records say.
    assert!(desk.devices().into_iter().any(|d| d["name"] == "root" && d["root"] == true), "{:?}", desk.devices());
    assert!(desk.devices().into_iter().any(|d| d["id"] == desk_id.as_str() && d["root"] != true));
    let _ = &mut g;
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

    has(&root.err(true, json!({"op": "sync", "on": false, "device": "desk", "for_ms": 1000})), "with no time");
    has(&root.err(true, json!({"op": "sync", "on": true, "for_ms": 1000})), "only with cbb sync off");
    assert!(!root.err(true, json!({"op": "sync"})).is_empty());
    let m = root.ok(true, json!({"op": "sync", "on": false, "device": "desk"}));
    assert_eq!(m.s("name"), "desk");
    let off = desk.state().join("sync.json");
    wait_for("desk's sync is off", || off.exists().then_some(()), || desk.log());
    root.ok(true, json!({"op": "sync", "on": true, "device": "desk"}));
    wait_for("desk's sync is on", || (!off.exists()).then_some(()), || desk.log());
    // -on naming this device turns its own sync.
    root.ok(true, json!({"op": "sync", "on": false, "device": "root", "for_ms": 0}));
    root.ok(true, json!({"op": "sync", "on": true}));

    has(&root.err(true, json!({"op": "paste_receive", "name": "maybe"})), "on or off");
    has(&root.err(true, json!({"op": "paste_receive", "name": "on", "device": "desk"})), "own user");
    has(&root.err(true, json!({"op": "paste_receive", "name": "off", "enter": true})), "go with on");
    root.ok(true, json!({"op": "paste_receive", "name": "off", "device": "desk"}));
    root.ok(true, json!({"op": "paste_receive", "name": "off", "all": true}));
    root.ok(true, json!({"op": "actions_off", "device": "desk"}));
    root.ok(true, json!({"op": "actions_off", "all": true}));
    root.ok(true, json!({"op": "actions_off", "device": "root"}));

    // Remote paste is off on desk: refused there, with its reason.
    let e = root.err_with(true, json!({"op": "paste_on", "device": "desk"}), b"hello");
    has(&e, "desk");
    has(&root.err_with(true, json!({"op": "paste_on", "device": "desk"}), b"\x01\x02"), "nothing to paste");
    has(&root.err_with(true, json!({"op": "paste_on", "device": "root"}), b"hi"), "for another device");
    has(&root.err(true, json!({"op": "paste_on", "device": "desk", "kind": "media"})), "no images or files");
    let e = root.err(true, json!({"op": "paste_on", "device": "desk", "kind": "media", "method": "type"}));
    has(&e, "pasted, not typed");
    // Quick actions are off on desk too.
    has(&root.err(true, json!({"op": "action_on", "device": "desk", "name": "lock"})), "desk");
    has(&root.err(true, json!({"op": "action_on", "device": "desk", "name": "no such!"})), "not an action's name");
    has(&root.err(true, json!({"op": "action_on", "device": "root", "name": "lock"})), "runs on another device");
    has(&root.err(true, json!({"op": "away", "name": "off", "device": "root"})), "-on names this device");
    // Sync away from home on at desk, and the root turns it off there.
    desk.ok(true, json!({"op": "away", "name": "on", "consent": true}));
    desk.wait("sync away from home is on at desk", |st| st["away"].is_object());
    root.ok(true, json!({"op": "away", "name": "off", "device": "desk"}));
    desk.wait("sync away from home is off at desk", |st| st["away"].is_null());
}

/// The root makes a member a hub with a hub command, stops it being one,
/// and moves its own hub to it; each comes back with the member's result.
#[test]
fn hub_commands_reach_a_member() {
    let g = group(&["root", "desk"]);
    let (root, desk) = (&g[0], &g[1]);
    let port = || std::net::UdpSocket::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    // A device the records do not make a hub is refused before anything goes.
    has(
        &root.err(true, json!({"op": "away", "name": "hub", "device": "desk", "addrs": ["127.0.0.1:9"]})),
        "do not make desk a hub",
    );
    root.ok(true, json!({"op": "hubs", "hubs": ["root", "desk"]}));
    // Desk has sync away from home off: it refuses, with why, once it took
    // the hubs record.
    let off = json!({"op": "away", "name": "hub", "device": "desk", "addrs": [format!("127.0.0.1:{}", port())]});
    wait_for(
        "desk refuses for sync away from home",
        || root.err(true, off.clone()).contains("sync away from home is off").then_some(()),
        || desk.log(),
    );
    desk.ok(true, json!({"op": "away", "name": "on", "consent": true}));
    has(
        &root
            .err(true, json!({"op": "away", "name": "hub", "device": "desk", "addrs": ["127.0.0.1:1", "127.0.0.1:2"]})),
        "one address",
    );
    has(
        &root.err(true, json!({"op": "away", "name": "hub", "device": "desk"})),
        "an address away from home or a forwarder",
    );
    let m = root
        .ok(true, json!({"op": "away", "name": "hub", "device": "desk", "addrs": [format!("127.0.0.1:{}", port())]}));
    assert_eq!(m.s("name"), "desk");
    desk.wait("desk is a hub", |st| st["away"]["hub"] == true);
    // It stops being one: refused while the group would have no other
    // hub, unless forced.
    root.ok(true, json!({"op": "away", "name": "hub-off", "device": "desk", "force": true}));
    desk.wait("desk is no hub", |st| st["away"]["hub"] != true);
    has(
        &root.err(true, json!({"op": "away", "name": "hub-off", "device": "desk", "force": true})),
        "no hub of the group",
    );
    // The root's own hub moves to desk.
    has(&root.err(true, json!({"op": "away", "name": "move", "device": "desk"})), "no hub of the group");
    root.ok(true, json!({"op": "away", "name": "hub", "consent": true, "addrs": [format!("127.0.0.1:{}", port())], "port": port()}));
    root.wait("root is a hub", |st| st["away"]["hub"] == true);
    has(&root.err(true, json!({"op": "away", "name": "move"})), "names the device");
    root.ok(true, json!({"op": "away", "name": "move", "device": "desk", "addrs": [format!("127.0.0.1:{}", port())]}));
    desk.wait("desk is the hub", |st| st["away"]["hub"] == true);
    root.wait("root is no hub", |st| st["away"]["hub"] != true);
}

/// One pairing at a time, a join only outside a group; a home window
/// takes a wrong code as one of its three tries and tells the window, and
/// the third closes it.
#[test]
fn pairing_one_at_a_time() {
    let root = Svc::start("root", &[], &[]);
    // Outside a group nothing admits.
    assert!(!root.err(true, json!({"op": "pair"})).is_empty());
    root.new_group();
    let (wconn, mut r, digits, link) = root.window(false);
    has(&root.err(true, json!({"op": "pair"})), "already open");
    has(&root.err(true, json!({"op": "join", "address": "127.0.0.1:9", "code": "123456"})), "already in a group");
    let other = Svc::start("other", &[], &[]);
    // Not six digits: refused before anything is dialed.
    has(&other.err(true, json!({"op": "join", "code": "12345", "address": root.addr()})), "six digits");
    // Wrong digits, three times: each refused at the joiner and told at
    // the window; the third closes the window.
    let wrong = if digits == "000000" { "000001" } else { "000000" };
    let wrong_link = link.replace(&format!("c={digits}"), &format!("c={wrong}"));
    for n in 1..=3 {
        has(&other.err(true, json!({"op": "join", "code": wrong_link})), "not the window's");
        let told = read(&mut r).unwrap_or_else(|| panic!("the window said nothing:\n{}", root.log()));
        if n < 3 {
            assert!(told.error().is_empty() && told.h["refused"] == true, "{:?}", told.h);
        } else {
            has(told.error(), "three failed tries");
        }
    }
    // Closed: even the right digits find no window.
    has(&other.err(true, json!({"op": "join", "code": link})), "the pairing window is closed");
    assert!(other.status()["group"].is_null(), "{}", other.log());
    drop((wconn, r));
    // Another window opens.
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
    let e = other.err(true, json!({"op": "join", "address": "127.0.0.1:9", "code": link}));
    has(&e, "127.0.0.1:9");
}

/// Admission by the joiner's QR code is gone on the records of 0.6: no
/// device waits for the group to dial it, and the root says to open a
/// pairing window, which the new device dials (D-119).
#[test]
fn a_qr_admission_is_gone() {
    let root = Svc::start("root", &[], &[]);
    root.new_group();
    let e = root.err(true, json!({"op": "pair", "code": "482915", "addrs": ["192.168.1.2:9"], "fingerprint": "fp"}));
    has(&e, "open a pairing window here with cbb pair");
    // A code alone, which once looked for the device that shows it.
    has(&root.err(true, json!({"op": "pair", "code": "482915"})), "open a pairing window here with cbb pair");
    // The window itself still opens.
    let (_c, mut r) = root.open(true, &json!({"op": "pair"}), b"");
    let opened = read(&mut r).unwrap();
    assert!(opened.error().is_empty(), "{:?}", opened.h);
}

/// What the root answers of a QR code and refuses of a recovery; and that on the
/// records of 0.6 it makes a device that is not connected an admin, as the
/// device's record carries the admin key it offered when it paired.
#[test]
fn refuses_bad_admissions_and_recoveries() {
    let mut g = group(&["root", "desk"]);
    let root = &g[0];
    // No device waits for the group to dial it on 0.6 (D-119): whatever
    // the QR code says, the root points to its pairing window.
    let qr = |addrs: serde_json::Value, fp: &str| {
        root.err(true, json!({"op": "pair", "code": "482915", "addrs": addrs, "fingerprint": fp}))
    };
    for (addrs, fp) in [
        (json!(["192.168.1.2:9"]), ""),
        (json!(["nonsense"]), "fp"),
        (json!(["127.0.0.1:9"]), "fp"),
        (json!(["8.8.8.8:9"]), "fp"),
    ] {
        has(&qr(addrs, fp), "no device waits for the group to dial it");
    }
    has(
        &root.err(true, json!({"op": "pair", "code": "48", "addrs": ["192.168.1.2:9"], "fingerprint": "fp"})),
        "no device waits for the group to dial it",
    );
    // The root claims nothing; a member has no recovery key to claim with.
    has(&root.err_with(true, json!({"op": "recover"}), b"words"), "root already");
    let e = g[1].err_with(true, json!({"op": "recover"}), b"not a recovery sheet");
    assert!(!e.is_empty());
    let e = g[1].err_with(true, json!({"op": "recover", "name": "yubikey"}), b"123456");
    assert!(!e.is_empty());
    // Stopped, desk still becomes an admin: no admin CA travels on 0.6.
    g[1].stop();
    let root = &g[0];
    wait_for(
        "the root sees desk gone",
        || root.status()["peers"].as_array().is_none_or(|p| p.is_empty()).then_some(()),
        || root.log(),
    );
    let m = root.ok(true, json!({"op": "make_admin", "device": "desk", "allow_file_key": true}));
    assert_eq!(m.s("name"), "desk");
    let _ = &mut g;
}

/// The root is lost: another computer becomes the root with the group's
/// recovery sheet (rule 33), restarts to sign with its new root key, and
/// the group's other devices stay.
#[test]
fn recovers_the_group_with_its_sheet() {
    let mut root = Svc::start("root", &[], &[]);
    let made = root.ok(true, json!({"op": "new"}));
    let sheet: Value = serde_json::from_slice(&made.payload).unwrap();
    let sheet = sheet["sheet"].as_str().unwrap().to_string();
    root.port();
    let mut desk = Svc::start("desk", &["-peer", &root.addr()], &[]);
    assert_eq!(root.admit(&desk, false), "desk");
    let lap = Svc::start("lap", &["-peer", &root.addr()], &[]);
    assert_eq!(root.admit(&lap, false), "lap");
    desk.wait("desk learns of lap", |_| desk.find("lap").is_some());
    root.stop();

    // A sheet that is not one, and a key of a sheet with a line changed,
    // claim nothing.
    assert!(!desk.err_with(true, json!({"op": "recover"}), b"not a recovery sheet").is_empty());
    let mut broken = sheet.clone().into_bytes();
    let at = broken.iter().position(u8::is_ascii_alphanumeric).unwrap();
    broken[at] = if broken[at] == b'A' { b'B' } else { b'A' };
    assert!(!desk.err_with(true, json!({"op": "recover"}), &broken).is_empty());

    desk.ok_with(true, json!({"op": "recover"}), sheet.as_bytes());
    // Until it restarts with the new root key the records name it the
    // root already: a second claim would make another root.
    has(&desk.err_with(true, json!({"op": "recover"}), sheet.as_bytes()), "root already");
    // It restarts by itself to sign with the new key; as systemd would,
    // the test starts it again.
    desk.wait_exit(Duration::from_secs(30));
    desk.restart(&["-peer", &lap.addr()], &[]);
    let me = desk.find("desk").unwrap();
    assert_eq!(me["root"], true, "{me}");
    assert_ne!(desk.find("root").unwrap()["root"], true);
    // As the root it signs: it names how long a copy stays live, and lap,
    // which stayed in the group, takes it.
    has(&desk.err_with(true, json!({"op": "recover"}), sheet.as_bytes()), "root already");
    desk.ok(true, json!({"op": "ttl", "value": "- 45s"}));
    lap.wait("lap takes the new root's setting", |st| st["secret_ttl_ms"] == 45_000);
}

/// A stolen root is left out when another computer recovers the group:
/// the group drops it, and once it runs again no member lets it in.
#[test]
fn recovers_without_the_lost_root() {
    let mut root = Svc::start("root", &[], &[]);
    let made = root.ok(true, json!({"op": "new"}));
    let sheet: Value = serde_json::from_slice(&made.payload).unwrap();
    let sheet = sheet["sheet"].as_str().unwrap().to_string();
    root.port();
    let mut desk = Svc::start("desk", &["-peer", &root.addr()], &[]);
    assert_eq!(root.admit(&desk, false), "desk");
    let lap = Svc::start("lap", &["-peer", &root.addr()], &[]);
    assert_eq!(root.admit(&lap, false), "lap");
    desk.wait("desk learns of lap", |_| desk.find("lap").is_some());
    root.stop();

    // This device stays: it becomes the root.
    has(&desk.err_with(true, json!({"op": "recover", "leave": ["desk"]}), sheet.as_bytes()), "it stays");
    has(&desk.err_with(true, json!({"op": "recover", "leave": ["nobody"]}), sheet.as_bytes()), "no device");
    desk.ok_with(true, json!({"op": "recover", "leave": ["root"]}), sheet.as_bytes());
    desk.wait_exit(Duration::from_secs(30));
    desk.restart(&["-peer", &lap.addr()], &[]);
    assert!(desk.find("root").is_none(), "{:?}", desk.devices());
    assert_eq!(desk.find("desk").unwrap()["root"], true);
    lap.wait("lap learns the old root left", |_| lap.find("root").is_none());

    // The old root runs again: neither member lets it in.
    root.restart(&["-peer", &desk.addr(), "-peer", &lap.addr()], &[]);
    for _ in 0..25 {
        for m in [&desk, &lap] {
            let peers = m.status()["peers"].clone();
            assert!(
                peers.as_array().is_none_or(|p| p.iter().all(|x| x["name"] != "root")),
                "{} let the old root in: {peers}",
                m.name
            );
        }
        std::thread::sleep(Duration::from_millis(200));
    }
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
    g[0].ok(true, json!({"op": "remove", "device": "desk"}));
    g[0].ok(true, json!({"op": "leave"}));
    g[0].wait_exit(Duration::from_secs(20));
    assert!(!g[0].state().join("identity.json").exists());
}

/// A device that joins by another window's link is refused before any
/// code: the member's key is not the one the link names; it pairs once
/// this member's window is open. Such a connection tried nothing, so the
/// window hears of no try, also when it reaches a window opened since.
/// (A closed window: pairing_one_at_a_time.)
#[test]
fn a_closed_window_refuses_the_joiner() {
    let root = Svc::start("root", &[], &[]);
    root.new_group();
    let other = Svc::start("other", &[], &[]);
    // Another group's window link, with this root's address.
    let elsewhere = Svc::start("elsewhere", &[], &[]);
    elsewhere.new_group();
    let (_wconn, _r, _, link) = elsewhere.window(false);
    let mut l = cbb_core::join::invitation::WindowLink::parse(&link).unwrap();
    l.addrs = vec![root.addr()];
    let wrong = l.text();
    has(&other.err(true, json!({"op": "join", "code": wrong})), "is not the window's member");
    // The same while this root's window is open: the window's next word
    // is the device that paired, not a try.
    let (_rconn, mut r, _, link) = root.window(false);
    has(&other.err(true, json!({"op": "join", "code": wrong})), "is not the window's member");
    wait_for("the window drops the connection", || root.log().contains("tried nothing").then_some(()), || root.log());
    other.ok(true, json!({"op": "join", "code": link}));
    let closed = read(&mut r).unwrap_or_else(|| panic!("the window did not close:\n{}", root.log()));
    assert!(closed.error().is_empty() && closed.done(), "the window said {:?}\n{}", closed.h, root.log());
    assert_eq!(closed.s("name"), "other");
}
