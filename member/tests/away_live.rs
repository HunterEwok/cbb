// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! Sync away from home on real services of a group of 0.6 (docs/protocol.md,
//! section 11): a member keeps its hub's offer at home, then reaches the hub
//! only through the tunnel and syncs there, also through a local UDP port
//! that leads to the hub; an admin turns it off there; the only hub stops
//! only with the user's word.

#![cfg(all(unix, feature = "tunnel"))]

mod common;

use std::net::UdpSocket;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use common::*;
use serde_json::{Value, json};

fn has(e: &str, part: &str) {
    assert!(e.contains(part), "{e:?} does not say {part:?}");
}

fn free_udp() -> u16 {
    UdpSocket::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

/// A local UDP port that passes each datagram to the hub's port and back,
/// as `cbb next link -udp` does for a ZX Spectrum Next; it counts what it
/// passed.
struct UdpRelay {
    port: u16,
    passed: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
}

impl UdpRelay {
    fn start(hub: u16) -> UdpRelay {
        let near = UdpSocket::bind("127.0.0.1:0").unwrap();
        let far = UdpSocket::bind("127.0.0.1:0").unwrap();
        far.connect(("127.0.0.1", hub)).unwrap();
        for s in [&near, &far] {
            s.set_read_timeout(Some(Duration::from_millis(50))).unwrap();
        }
        let port = near.local_addr().unwrap().port();
        let (passed, stop) = (Arc::new(AtomicUsize::new(0)), Arc::new(AtomicBool::new(false)));
        let (p, st) = (passed.clone(), stop.clone());
        std::thread::spawn(move || {
            let mut from = None;
            let mut buf = vec![0u8; 65536];
            while !st.load(Ordering::SeqCst) {
                if let Ok((n, a)) = near.recv_from(&mut buf) {
                    from = Some(a);
                    p.fetch_add(1, Ordering::SeqCst);
                    let _ = far.send(&buf[..n]);
                }
                if let (Ok(n), Some(a)) = (far.recv(&mut buf), from) {
                    let _ = near.send_to(&buf[..n], a);
                }
            }
        });
        UdpRelay { port, passed, stop }
    }
}

impl Drop for UdpRelay {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
    }
}

fn away(st: &Value) -> &Value {
    &st["away"]
}

/// The root is the group's hub: the member turns sync away from home on and
/// keeps the hub's offer at home, with the group's AmneziaWG settings;
/// started again with no address of the hub, it reaches the hub through the
/// tunnel, and copies go both ways there; through a local UDP port that
/// leads to the hub (-tunnel-via) too. The root turns sync away from home
/// off there (away-off through the tunnel), which takes its keys; its own
/// user turning it off again changes nothing. The only hub refuses to stop
/// without the user's word, then stops, and its tunnel state says it is
/// none.
#[test]
fn a_member_syncs_through_its_hub_away_from_home() {
    let mut g = group(&["root", "small"]);
    let port = free_udp();
    g[0].ok(true, json!({"op": "hubs", "hubs": ["root"]}));
    let root_id = g[0].device();
    g[0].ok(
        true,
        json!({"op": "away", "name": "hub", "consent": true, "addrs": [format!("127.0.0.1:{port}")], "port": port}),
    );
    g[0].wait("the root is a hub", |st| away(st)["hub"] == true);
    g[1].ok(true, json!({"op": "away", "name": "on", "consent": true}));
    g[1].wait("the member keeps the hub's offer", |st| away(st)["hub_device"] == root_id.as_str());
    let tunnel: Value = serde_json::from_slice(&std::fs::read(g[1].state().join("tunnel.json")).unwrap()).unwrap();
    assert!(tunnel["hubs"][0]["obfuscation"].is_object(), "the group's AmneziaWG settings: {tunnel}");

    // Away: no address of the hub but its tunnel's.
    g[1].restart(&[], &[]);
    let through = |st: &Value| away(st)["through"] == true && st["peers"].as_array().is_some_and(|p| p.len() == 1);
    g[1].wait("the member reaches the hub through the tunnel", through);
    g[1].ok_with(false, json!({"op": "copy"}), b"from the member, away");
    wait_for(
        "the hub has it",
        || (g[0].ask(false, json!({"op": "paste"}), b"").payload == b"from the member, away").then_some(()),
        || g[0].log(),
    );
    g[0].ok_with(false, json!({"op": "copy"}), b"to the member, away");
    wait_for(
        "the member has it",
        || (g[1].ask(false, json!({"op": "paste"}), b"").payload == b"to the member, away").then_some(()),
        || g[1].log(),
    );

    // Through a local UDP port that leads to the hub.
    let relay = UdpRelay::start(port);
    g[1].restart(&["-tunnel-via", &format!("127.0.0.1:{}", relay.port)], &[]);
    g[1].wait("the member reaches the hub through the local UDP port", through);
    assert!(relay.passed.load(Ordering::SeqCst) > 0, "no packet went through the local UDP port");

    // Off, from the root, through the tunnel: the keys are gone, and so is
    // the connection through the tunnel.
    g[0].ok(true, json!({"op": "away", "name": "off", "device": "small"}));
    g[1].wait("the member syncs at home only", |st| {
        away(st).is_null() && st["peers"].as_array().is_none_or(Vec::is_empty)
    });
    assert!(!g[1].state().join("tunnel.json").exists(), "tunnel.json after the away-off command");
    g[1].ok(true, json!({"op": "away", "name": "off"}));

    // The only hub stops only with the user's word.
    has(&g[0].err(true, json!({"op": "away", "name": "hub-off"})), "no other hub");
    g[0].ok(true, json!({"op": "away", "name": "hub-off", "force": true}));
    g[0].wait("the root is no hub", |st| away(st)["hub"] != true);
    let raw = std::fs::read_to_string(g[0].state().join("tunnel.json")).unwrap_or_default();
    assert!(!raw.contains("\"is_hub\": true"), "tunnel.json after hub off: {raw}");
}

/// The hubs listed in the member's tunnel state, by device ID.
fn kept(st: &std::path::Path) -> Vec<String> {
    let raw = std::fs::read(st.join("tunnel.json")).unwrap_or_default();
    let v: Value = serde_json::from_slice(&raw).unwrap_or(Value::Null);
    v["hubs"]
        .as_array()
        .map(|a| a.iter().filter_map(|h| h["device"].as_str().map(str::to_string)).collect())
        .unwrap_or_default()
}

/// The root, the hub, moves the hub to desk and becomes its client, and
/// lap, which meets both at home, forgets the root's offer, which said it
/// moved, and keeps desk's (on the records of 0.6 a hub's offer comes only
/// from that hub); the root stops desk being a hub, makes it one again,
/// and keeps its offer.
#[test]
fn the_hub_moves_and_its_clients_follow() {
    let mut g = group(&["root", "desk", "lap"]);
    let (root_addr, desk_addr) = (g[0].addr(), g[1].addr());
    g[2].restart(&["-peer", &root_addr, "-peer", &desk_addr], &[]);
    let (root, desk, lap) = (&g[0], &g[1], &g[2]);
    root.ok(true, json!({"op": "hubs", "hubs": ["root", "desk"]}));
    let (root_id, desk_id) = (root.device(), desk.device());
    let port = free_udp();
    root.ok(
        true,
        json!({"op": "away", "name": "hub", "consent": true, "addrs": [format!("127.0.0.1:{port}")], "port": port}),
    );
    for s in [desk, lap] {
        s.ok(true, json!({"op": "away", "name": "on", "consent": true}));
    }
    lap.wait("lap keeps the root's offer", |st| away(st)["hub_device"] == root_id.as_str());
    root.ok(
        true,
        json!({"op": "away", "name": "move", "device": "desk", "addrs": [format!("127.0.0.1:{}", free_udp())]}),
    );
    desk.wait("desk is the hub", |st| away(st)["hub"] == true);
    root.wait("the root is desk's client", |st| away(st)["hub"] != true && away(st)["hub_device"] == desk_id.as_str());
    wait_for(
        "lap keeps desk's offer only",
        || {
            let k = kept(&lap.state());
            (k.contains(&desk_id) && !k.contains(&root_id)).then_some(())
        },
        || format!("{:?}\n{}", std::fs::read_to_string(lap.state().join("tunnel.json")), lap.log()),
    );
    // The root stops desk, the only hub, being one, then makes it one
    // again and keeps its offer.
    root.ok(true, json!({"op": "away", "name": "hub-off", "device": "desk", "force": true}));
    desk.wait("desk is no hub", |st| away(st)["hub"] != true);
    root.ok(
        true,
        json!({"op": "away", "name": "hub", "device": "desk", "addrs": [format!("127.0.0.1:{}", free_udp())]}),
    );
    desk.wait("desk is a hub again", |st| away(st)["hub"] == true);
    root.wait("the root keeps desk's offer", |st| away(st)["hub_device"] == desk_id.as_str());
}
