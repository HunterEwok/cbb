// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! Sync away from home with nodes in the same process: a hub that serves,
//! a member that meets it at home, keeps its offer and then reaches it
//! through the tunnel, the hub's status on both, and stopping the hub.

use std::net::{Ipv4Addr, UdpSocket};

use super::*;
use crate::control::Header;
use crate::nettest::{Group, NodeAt, wait_for};
use cbb_core::certs;

/// A free UDP port on the loopback address, for a hub to listen on.
fn free_udp_port() -> u16 {
    UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap().local_addr().unwrap().port()
}

/// The node's Away, wired as the service wires it: the hellos go to it,
/// the offers come to it, and the hellos carry its key.
pub(crate) fn away_of(g: &Group, n: &NodeAt, i: usize) -> Arc<Away> {
    let away = Arc::new(Away::new(n.dir.0.clone(), certs::tag(&g.root), g.devs[i].id.clone(), n.log()));
    {
        let a = away.clone();
        let w = Arc::downgrade(&n.node);
        n.node.on_hello(Box::new(move |from, peer, chain| match w.upgrade() {
            Some(node) => a.hello(&node, from, peer, chain),
            None => Vec::new(),
        }));
    }
    {
        let a = away.clone();
        let w = Arc::downgrade(&n.node);
        n.node.on_tunnel(Box::new(move |from, v, may_host| {
            if let (Some(hub), Some(node)) = (a.offered(from, v, may_host), w.upgrade()) {
                a.retry(&node, &hub);
            }
        }));
    }
    away
}

fn hub_header(port: u16) -> Header {
    Header {
        op: "hub".into(),
        addrs: vec![format!("127.0.0.1:{port}")],
        port: i64::from(port),
        consent: true,
        ..Header::default()
    }
}

/// The root is the group's hub; the other member meets it at home, which
/// gives it the hub's offer, and once home is gone reaches the hub through
/// the tunnel. Both say so in their status. Stopping the hub anyway ends
/// its serving and the member forgets nothing it was not told to.
#[test]
fn a_member_reaches_its_hub_through_the_tunnel() {
    let g = Group::new(2);
    let (a, b) = (g.node(0), g.node(1));
    let (away_a, away_b) = (away_of(&g, &a, 0), away_of(&g, &b, 1));
    let port = free_udp_port();
    let keys = away_a.make_hub(&hub_header(port)).unwrap();
    a.node.set_tunnel_key(Some(keys));
    assert!(away_a.is_hub());
    away_a.serve_if_first(&a.node);
    let st = away_a.status(&a.node).unwrap();
    assert!(st.error.is_empty(), "{st:?}");

    b.node.set_tunnel_key(Some(away_b.turn_on().unwrap()));
    // At home: B dials A's member port, its hello brings its key, and the
    // hub's offer comes back.
    let member_port = crate::discovery::listen(a.node.clone(), 0, a.log()).unwrap();
    let home = {
        let n = b.node.clone();
        let id = g.devs[0].id.clone();
        std::thread::spawn(move || n.dial(SocketAddr::from((Ipv4Addr::LOCALHOST, member_port)), Some(id)))
    };
    assert!(
        wait_for(Duration::from_secs(20), || away_b.st.lock().unwrap().as_ref().is_some_and(|s| !s.hubs.is_empty())),
        "no offer: {:?} {:?}",
        a.logs.lock().unwrap(),
        b.logs.lock().unwrap()
    );
    assert!(a.logged("can reach this hub away from home"), "{:?}", a.logs.lock().unwrap());
    // Home is gone.
    b.node.disconnect(&g.devs[0].id);
    let _ = home.join();
    let st = away_b.status(&b.node).unwrap();
    assert_eq!(st.hub_device, g.id(0));
    assert!(!st.through);

    let runner = {
        let (aw, n) = (away_b.clone(), b.node.clone());
        std::thread::spawn(move || aw.run(n))
    };
    assert!(
        wait_for(Duration::from_secs(40), || away_b.status(&b.node).is_some_and(|s| s.through)),
        "{:?} {:?}",
        away_b.status(&b.node),
        b.logs.lock().unwrap()
    );
    assert!(wait_for(Duration::from_secs(10), || a.node.tunneled().contains(&g.devs[1].id)), "{:?}", a.node.tunneled());
    assert!(away_b.update_way(&b.node).is_none(), "no VLESS");
    let hs = away_a.status(&a.node).unwrap();
    assert!(hs.error.is_empty(), "{hs:?}");

    // The hub stops anyway: it is no hub any more, and the member's link
    // through it ends.
    away_a.stop_hub(&a.node, true).unwrap();
    assert!(!away_a.is_hub());
    assert!(a.logged("no hub of the group any more"));
    b.node.close();
    a.node.close();
    let _ = runner.join();
}
