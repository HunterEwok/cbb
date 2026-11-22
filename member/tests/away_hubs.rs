// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! Two hubs of a group of 0.6 on real services (docs/protocol.md, section
//! 11, "Several hubs"): the lower one stands by while the one above serves,
//! serves when it is gone, and gives way when it is back; a member away from
//! home follows the hub that serves and syncs through it.

#![cfg(unix)]

mod common;

use std::net::UdpSocket;

use common::*;
use serde_json::{Value, json};

fn free_udp() -> u16 {
    UdpSocket::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

fn away(st: &Value) -> &Value {
    &st["away"]
}

/// Whether the member reaches hub, by its device ID, through the tunnel.
fn through(hub: &str) -> impl Fn(&Value) -> bool + '_ {
    move |st| {
        away(st)["through"] == true
            && away(st)["hub_device"] == hub
            && st["peers"].as_array().is_some_and(|ps| ps.iter().any(|p| p["id"] == hub))
    }
}

/// The root and desk are hubs, the root above: desk stands by as the
/// root's client, and lap keeps both offers. Away from home lap reaches the
/// root; when the root stops, desk serves and lap reaches it and syncs
/// there; when the root is back, desk gives way and lap moves back.
#[test]
fn a_member_follows_the_hub_that_serves() {
    let env = [("CBB_TEST_STANDBY_GRACE", "2")];
    let mut g = group_with(&["root", "desk", "lap"], &env);
    g[0].ok(true, json!({"op": "hubs", "hubs": ["root", "desk"]}));
    let (root_port, desk_port) = (free_udp(), free_udp());
    let (root_id, desk_id) = (g[0].device(), g[1].device());
    g[0].ok(
        true,
        json!({"op": "away", "name": "hub", "consent": true, "addrs": [format!("127.0.0.1:{root_port}")], "port": root_port}),
    );
    wait_for(
        "desk takes the hubs record and is a hub",
        || {
            let h = json!({"op": "away", "name": "hub", "consent": true, "addrs": [format!("127.0.0.1:{desk_port}")], "port": desk_port});
            g[1].ask(true, h, b"").error().is_empty().then_some(())
        },
        || g[1].log(),
    );
    // Lap meets both at home.
    let (root_addr, desk_addr) = (g[0].addr(), g[1].addr());
    g[2].restart(&["-peer", &root_addr, "-peer", &desk_addr], &env);
    g[2].ok(true, json!({"op": "away", "name": "on", "consent": true}));
    let kept = |dir: &std::path::Path| -> Vec<String> {
        let raw = std::fs::read(dir.join("tunnel.json")).unwrap_or_default();
        let v: Value = serde_json::from_slice(&raw).unwrap_or(Value::Null);
        v["hubs"]
            .as_array()
            .map(|a| a.iter().filter_map(|h| h["device"].as_str().map(str::to_string)).collect())
            .unwrap_or_default()
    };
    wait_for(
        "lap keeps both hubs' offers",
        || {
            let k = kept(&g[2].state());
            (k.contains(&root_id) && k.contains(&desk_id)).then_some(())
        },
        || g[2].log(),
    );
    g[1].wait("desk stands by as the root's client", |st| away(st)["hub"] == true && away(st)["standby"] == true);
    assert!(away(&g[0].status())["standby"] != true, "the root, the first hub, serves");

    // Lap leaves home and reaches the root through the tunnel.
    g[2].restart(&[], &env);
    g[2].wait("lap reaches the root through the tunnel", through(&root_id));

    // The root stops: desk serves, and lap reaches it and syncs there.
    g[0].stop();
    g[1].wait("desk serves", |st| away(st)["hub"] == true && away(st)["standby"] != true);
    g[2].wait("lap reaches desk through the tunnel", through(&desk_id));
    g[2].ok_with(false, json!({"op": "copy"}), b"while the root is off");
    wait_for(
        "desk has it",
        || (g[1].ask(false, json!({"op": "paste"}), b"").payload == b"while the root is off").then_some(()),
        || g[1].log(),
    );

    // The root is back where it dials desk: desk gives way, and lap moves
    // back to the root.
    g[0].restart(&["-peer", &desk_addr], &[]);
    g[1].wait("desk gives way to the root", |st| away(st)["standby"] == true);
    g[2].wait("lap reaches the root again", through(&root_id));
    g[2].ok_with(false, json!({"op": "copy"}), b"the root is back");
    wait_for(
        "the root has it",
        || (g[0].ask(false, json!({"op": "paste"}), b"").payload == b"the root is back").then_some(()),
        || g[0].log(),
    );
}
