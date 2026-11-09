// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! Sync away from home with nodes in the same process: a hub that serves,
//! a member that meets it at home, keeps its offer and then reaches it
//! through the tunnel, the hub's status on both, and stopping the hub.

use std::net::{Ipv4Addr, UdpSocket};

use super::*;
use crate::control::Header;
use crate::nettest::{Group, NodeAt, wait_for};
use cbb_core::certs::{self, Cert, DeviceId};

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
    {
        let a = away.clone();
        let w = Arc::downgrade(&n.node);
        n.node.on_message(Box::new(move |from, m| {
            if let (Some(v), "hubs", Some(node)) = (m.hubs.as_ref(), m.kind.as_str(), w.upgrade()) {
                a.hubs_shared(&node, from, &node.chain_of(from), v);
            }
        }));
    }
    away
}

/// Dials b's member port from a until the returned handle's connection
/// ends.
fn meet_at_home(a: &NodeAt, b: &NodeAt, b_id: &DeviceId) -> std::thread::JoinHandle<Result<()>> {
    let port = crate::discovery::listen(b.node.clone(), 0, b.log()).unwrap();
    let (n, id) = (a.node.clone(), b_id.clone());
    std::thread::spawn(move || n.dial(SocketAddr::from((Ipv4Addr::LOCALHOST, port)), Some(id)))
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

fn relay_server(g: &Group) -> (crate::relayd::server::Relay, String) {
    use base64::Engine;
    let keys = crate::relayd::keys::Keys::new().unwrap();
    let pin =
        base64::engine::general_purpose::STANDARD.encode(cbb_core::certs::Cert::parse(&keys.cert).unwrap().key_hash());
    let s = crate::relayd::server::Relay::start(crate::relayd::server::Config {
        listen: SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
        keys,
        groups: vec![certs::tag(&g.root)],
        open: false,
        limits: Default::default(),
        log: Arc::new(|_| {}),
        verbose: false,
    })
    .unwrap();
    (s, pin)
}

fn relay_header(addr: &str, key: &str, consent: bool) -> Header {
    Header { op: "relay".into(), relay: addr.into(), relay_key: key.into(), consent, ..Header::default() }
}

/// Two devices meet their group at a relay: each registers, sees the
/// other online, and one connects to the other through the relay; both
/// say so in their status. Turning sync away from home off ends it.
#[test]
fn two_devices_meet_at_a_relay() {
    let g = Group::new(2);
    let (s, pin) = relay_server(&g);
    let (a, b) = (g.node(0), g.node(1));
    let (away_a, away_b) = (away_of(&g, &a, 0), away_of(&g, &b, 1));
    let addr = s.addr().to_string();
    // What the request must give.
    assert!(away_a.meet_at(&a.node, &relay_header("nowhere", &pin, true)).is_err());
    assert!(away_a.meet_at(&a.node, &relay_header(&addr, "bad", true)).is_err());
    let e = away_a.meet_at(&a.node, &relay_header(&addr, &pin, false)).unwrap_err();
    assert!(e.to_string().contains("a relay learns"), "{e}");
    for (away, n) in [(&away_a, &a), (&away_b, &b)] {
        let keys = away.meet_at(&n.node, &relay_header(&addr, &pin, true)).unwrap();
        n.node.set_tunnel_key(Some(keys));
    }
    let st = away_a.status(&a.node).unwrap();
    assert!(st.relay.is_some_and(|r| !r.connected && r.error.contains("not running")));
    let runners: Vec<_> = [(away_a.clone(), a.node.clone()), (away_b.clone(), b.node.clone())]
        .into_iter()
        .map(|(aw, n)| std::thread::spawn(move || aw.run(n)))
        .collect();
    assert!(
        wait_for(Duration::from_secs(40), || a.node.connected(&g.devs[1].id) && b.node.connected(&g.devs[0].id)),
        "{:?}\n{:?}",
        a.logs.lock().unwrap(),
        b.logs.lock().unwrap()
    );
    let st = away_a.status(&a.node).unwrap();
    let r = st.relay.unwrap();
    assert!(r.connected && r.online == vec![g.id(1)], "{r:?}");
    assert!(wait_for(Duration::from_secs(5), || away_a.status(&a.node).unwrap().through
        || away_b.status(&b.node).unwrap().through));
    assert!(a.logged("connected to the relay at"));
    away_a.turn_off().unwrap();
    assert!(away_a.status(&a.node).is_none());
    a.node.close();
    b.node.close();
    for r in runners {
        let _ = r.join();
    }
}

/// The relay refuses a group it does not serve; the status says why in
/// short and the whole error in the detail.
#[test]
fn a_relay_of_another_group() {
    let g = Group::new(1);
    let other = Group::new(1);
    let (s, pin) = relay_server(&other);
    let a = g.node(0);
    let away = away_of(&g, &a, 0);
    away.meet_at(&a.node, &relay_header(&s.addr().to_string(), &pin, true)).unwrap();
    let runner = {
        let (aw, n) = (away.clone(), a.node.clone());
        std::thread::spawn(move || aw.run(n))
    };
    assert!(
        wait_for(Duration::from_secs(30), || away
            .status(&a.node)
            .and_then(|s| s.relay)
            .is_some_and(|r| !r.error.is_empty() && !r.detail.is_empty())),
        "{:?}",
        away.status(&a.node)
    );
    a.node.close();
    let _ = runner.join();
}

/// Two hubs: the root and a device that only passes copies on. Meeting
/// at home, the root shares its offer and clients with the other hub,
/// which keeps them and, being below the root, gives way while the root
/// serves. A member's tunnel is dropped once the records remove it, and
/// when the root stops being a hub the other forgets its offer.
#[test]
fn several_hubs_share_and_prune() {
    let mut g = Group::new(1);
    let fi = g.add_forwarder();
    let mi = g.add();
    let (a, f, m) = (g.node(0), g.node(fi), g.node(mi));
    let (away_a, away_f, away_m) = (away_of(&g, &a, 0), away_of(&g, &f, fi), away_of(&g, &m, mi));
    let keys = away_a.make_hub(&hub_header(free_udp_port())).unwrap();
    a.node.set_tunnel_key(Some(keys));
    away_a.serve_if_first(&a.node);
    let keys = away_f.make_hub(&hub_header(free_udp_port())).unwrap();
    f.node.set_tunnel_key(Some(keys));
    // The forwarder serves too: no hub above it is known yet.
    away_f.serve_if_first(&f.node);
    assert!(away_f.serving.lock().unwrap().is_some());
    m.node.set_tunnel_key(Some(away_m.turn_on().unwrap()));
    // The member meets the root: its tunnel key is admitted.
    let mh = meet_at_home(&m, &a, &g.devs[0].id);
    assert!(wait_for(Duration::from_secs(20), || away_a.st.lock().unwrap().as_ref().unwrap().members.len() == 1));
    // The forwarder meets the root: it learns the root's offer and clients
    // and gives way, the root being above it.
    let fh = meet_at_home(&f, &a, &g.devs[0].id);
    assert!(
        wait_for(Duration::from_secs(20), || away_f.st.lock().unwrap().as_ref().is_some_and(|s| s
            .hubs
            .iter()
            .any(|h| h.device == g.id(0))
            && s.members.iter().any(|c| c.device == g.id(mi)))),
        "{:?}",
        f.logs.lock().unwrap()
    );
    assert!(
        wait_for(Duration::from_secs(20), || away_f.standby.lock().unwrap().is_some()),
        "{:?}",
        f.logs.lock().unwrap()
    );
    assert!(f.logged("a hub above this one"), "{:?}", f.logs.lock().unwrap());
    let st = away_f.status(&f.node).unwrap();
    assert!(st.error.is_empty(), "{st:?}");

    // The records remove the member: the root drops its tunnel.
    let r = g.revoke(mi);
    a.node.records().lock().unwrap().add(&r).unwrap();
    away_a.prune(&a.node);
    assert!(a.logged("was removed from the group"), "{:?}", a.logs.lock().unwrap());
    assert!(away_a.st.lock().unwrap().as_ref().unwrap().members.iter().all(|c| c.device != g.id(mi)));

    // The root stops being a hub: the forwarder, still connected, forgets
    // its offer.
    away_a.stop_hub(&a.node, true).unwrap();
    assert!(wait_for(Duration::from_secs(10), || f.logged("its offer is forgotten")), "{:?}", f.logs.lock().unwrap());
    for n in [&a, &f, &m] {
        n.node.close();
    }
    let _ = (mh.join(), fh.join());
}

/// What a device that is no hub of the group shares is ignored, as is a
/// share that does not decode.
#[test]
fn shares_ignored() {
    let g = Group::new(2);
    let b = g.node(1);
    let away_b = away_of(&g, &b, 1);
    away_b.turn_on().unwrap();
    let chain: Vec<Cert> = g.chain(0).iter().map(|d| Cert::parse(d).unwrap()).collect();
    let other: Vec<Cert> = g.chain(1).iter().map(|d| Cert::parse(d).unwrap()).collect();
    away_b.hubs_shared(&b.node, &g.devs[1].id, &other, &serde_json::json!({}));
    assert!(b.logged("only the group's root"));
    away_b.hubs_shared(&b.node, &g.devs[0].id, &chain, &serde_json::json!({"clients": 3}));
    assert!(b.logged("does not decode"));
    // A stopped share of a hub it never kept changes nothing.
    away_b.hubs_shared(&b.node, &g.devs[0].id, &chain, &serde_json::json!({"stopped": true}));
    assert!(!b.logged("forgotten"));
}

/// Wires the node's hub commands as the service carries them out
/// (service.rs hub_command): checked against the records, then a stop
/// order stops the hub after the result went back, and any other makes
/// this device the hub.
fn take_hub_commands(n: &NodeAt, away: &Arc<Away>) {
    let (a, w) = (away.clone(), Arc::downgrade(&n.node));
    n.node.on_command(Arc::new(move |_peer, c| {
        let node = w.upgrade().unwrap();
        let me = node.identity().id.to_string();
        let body = node.records().lock().unwrap().verify_command(c, &me, crate::uptime::wall_ms());
        let mut res = crate::wire::CommandResult { status: "done".into(), ..Default::default() };
        let body = match body {
            Ok(b) => b,
            Err(e) => {
                (res.status, res.reason) = ("refused".into(), e.message().to_string());
                return res;
            }
        };
        res.id = body.id.clone();
        let order = body.hub.clone().unwrap_or_default();
        if super::is_stop(&order) {
            let (a, node) = (a.clone(), node.clone());
            std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(300));
                a.stop_hub(&node, true).unwrap();
            });
            return res;
        }
        match a.take_hub(&node, &body.by, &order) {
            Ok(o) => res.tunnel = serde_json::to_value(&o).ok(),
            Err(e) => (res.status, res.reason) = ("refused".into(), e.message().to_string()),
        }
        res
    }));
}

/// The root makes another computer a hub that only passes copies on, with
/// a hub command, and keeps its offer; then stops it; then moves the hub
/// there, becoming that hub's client. What a hub command may not name is
/// refused before it goes.
#[test]
fn the_root_makes_stops_and_moves_hubs() {
    let mut g = Group::new(1);
    let bi = g.add_with(|b| b.caps = vec![cbb_core::authority::CAP_HUB.into()]);
    let ci = g.add();
    let (a, b) = (g.node(0), g.node(bi));
    let (away_a, away_b) = (away_of(&g, &a, 0), away_of(&g, &b, bi));
    take_hub_commands(&b, &away_b);
    let admin = crate::admin::Admin { node: &a.node, dir: &a.dir.0 };
    let addrs = |p: u16| vec![format!("127.0.0.1:{p}")];
    // Refused before any command: this device, a device that cannot be a
    // hub, no address.
    assert!(away_a.make_hub_on(&admin, &g.id(0), &addrs(1), ("", ""), true).is_err());
    let e = away_a.make_hub_on(&admin, &g.id(ci), &addrs(1), ("", ""), true).unwrap_err();
    assert!(e.to_string().contains("cannot be a hub"), "{e}");
    assert!(away_a.make_hub_on(&admin, &g.id(bi), &addrs(1), ("", ""), false).is_err(), "no admin");
    assert!(away_a.make_hub_on(&admin, &g.id(bi), &[], ("", ""), true).is_err());
    assert!(away_a.move_hub(&admin, &g.id(bi), &addrs(1), ("", "")).is_err(), "not the hub");
    assert!(away_a.stop_hub_on(&admin, &g.id(bi), false).is_err(), "no hub known");

    let keys = away_a.make_hub(&hub_header(free_udp_port())).unwrap();
    a.node.set_tunnel_key(Some(keys));
    away_a.serve_if_first(&a.node);
    b.node.set_tunnel_key(Some(away_b.turn_on().unwrap()));
    let home = meet_at_home(&b, &a, &g.devs[0].id);
    assert!(wait_for(Duration::from_secs(20), || away_a.st.lock().unwrap().as_ref().unwrap().members.len() == 1));

    // B becomes a hub that passes copies on.
    away_a.make_hub_on(&admin, &g.id(bi), &addrs(free_udp_port()), ("", ""), true).unwrap();
    assert!(away_b.is_hub());
    assert!(b.logged("in place of"), "{:?}", b.logs.lock().unwrap());
    let order = a.node.hub_order();
    let known = away_a.known_hubs(&order);
    assert!(known.contains(&g.id(bi)) && known.contains(&g.id(0)), "{known:?} {order:?}");

    // And stops: A forgets its offer.
    away_a.stop_hub_on(&admin, &g.id(bi), false).unwrap();
    assert!(wait_for(Duration::from_secs(10), || !away_b.is_hub()));
    assert!(!away_a.known_hubs(&a.node.hub_order()).contains(&g.id(bi)));

    // The hub moves to B: A becomes its client.
    away_a.move_hub(&admin, &g.id(bi), &addrs(free_udp_port()), ("", "")).unwrap();
    assert!(away_b.is_hub());
    assert!(!away_a.is_hub());
    assert!(away_a.st.lock().unwrap().as_ref().unwrap().hubs.iter().any(|h| h.device == g.id(bi)));
    for n in [&a, &b] {
        n.node.close();
    }
    let _ = home.join();
}

/// A hub with a forwarder and VLESS registers there while it serves:
/// its status shows the forwarder registered and where it saw the hub,
/// it keeps the VLESS settings the forwarder gave and its update way names
/// them; a forwarder that refuses shows why in short.
#[test]
fn a_hub_registers_with_its_forwarder() {
    use base64::Engine;
    let g = Group::new(1);
    let f =
        crate::nettest::forwarder::Forwarder::start(crate::nettest::forwarder::welcome(), Some("203.0.113.9:51820"));
    let a = g.node(0);
    let away = away_of(&g, &a, 0);
    let pin = base64::engine::general_purpose::STANDARD.encode(f.pin);
    let h = Header {
        forwarder: f.addr.to_string(),
        forwarder_key: pin.clone(),
        vless: true,
        port: i64::from(free_udp_port()),
        ..hub_header(0)
    };
    let h = Header { addrs: Vec::new(), ..h };
    let keys = away.make_hub(&h).unwrap();
    a.node.set_tunnel_key(Some(keys));
    away.serve_if_first(&a.node);
    assert!(
        wait_for(Duration::from_secs(20), || away
            .status(&a.node)
            .and_then(|s| s.forwarder)
            .is_some_and(|fw| fw.registered && fw.seen == "203.0.113.9:51820")),
        "{:?} {:?}",
        away.status(&a.node),
        a.logs.lock().unwrap()
    );
    let claim = &f.claims()[0];
    assert!(claim["vless"].is_string() && claim["obfuscation"].is_object(), "VLESS comes with AmneziaWG");
    away.vless_learned(&a.node);
    assert!(a.logged("come over VLESS to the forwarder"), "{:?}", a.logs.lock().unwrap());
    let way = away.update_way(&a.node).unwrap();
    assert_eq!(way["id"], claim["vless"]);
    // Set again keeping its settings: the same VLESS user ID.
    let again = Header { keep: true, forwarder: String::new(), forwarder_key: String::new(), port: 0, ..h.clone() };
    away.make_hub(&again).unwrap();
    let st = away.st.lock().unwrap().clone().unwrap();
    assert_eq!(st.forwarder.as_ref().unwrap().vless_id, claim["vless"].as_str().unwrap());
    drop(st);
    away.stop_serving();

    // A forwarder that refuses.
    let no = crate::nettest::forwarder::Forwarder::start(
        Arc::new(|_: &serde_json::Value| serde_json::json!({"error": "full"})),
        None,
    );
    let h = Header {
        forwarder: no.addr.to_string(),
        forwarder_key: base64::engine::general_purpose::STANDARD.encode(no.pin),
        vless: false,
        ..h
    };
    away.make_hub(&h).unwrap();
    away.serve_if_first(&a.node);
    assert!(
        wait_for(Duration::from_secs(20), || away
            .status(&a.node)
            .and_then(|s| s.forwarder)
            .is_some_and(|fw| fw.error.contains("refused the registration: full"))),
        "{:?}",
        away.status(&a.node)
    );
    a.node.close();
}

/// What a hub request must give, and turning on and off.
#[test]
fn hub_requests_refused() {
    let g = Group::new(1);
    let a = g.node(0);
    let away = away_of(&g, &a, 0);
    let refused = |h: Header, want: &str| {
        let e = away.make_hub(&h).unwrap_err().to_string();
        assert!(e.contains(want), "{want}: {e}");
    };
    refused(Header { port: 70000, ..hub_header(1) }, "a bad port");
    refused(Header { consent: false, ..hub_header(1) }, "turn it on first");
    refused(Header { keep: true, ..hub_header(1) }, "not a hub yet");
    refused(Header { addrs: Vec::new(), ..hub_header(1) }, "an address away from home or a forwarder");
    refused(Header { vless: true, ..hub_header(1) }, "VLESS goes to a forwarder");
    refused(Header { addrs: vec!["nowhere".into()], ..hub_header(1) }, "");
    refused(Header { forwarder: "nowhere".into(), forwarder_key: "x".into(), ..hub_header(1) }, "");
    assert!(away.stop_hub(&a.node, false).is_err(), "no hub");
    // A hub alone refuses to stop without anyway.
    away.make_hub(&hub_header(free_udp_port())).unwrap();
    let e = away.stop_hub(&a.node, false).unwrap_err().to_string();
    assert!(e.contains("no other hub"), "{e}");
    // Obfuscated, and set again keeping its address and port.
    let o = away.make_hub(&Header { obfuscate: true, ..hub_header(free_udp_port()) }).unwrap();
    let again =
        away.make_hub(&Header { keep: true, addrs: Vec::new(), port: 0, obfuscate: true, ..hub_header(0) }).unwrap();
    assert_eq!(o, again, "the same keys");
    let st = away.st.lock().unwrap().clone().unwrap();
    assert!(st.obfuscation.is_some() && !st.endpoints.is_empty() && st.listen_port != 0);
    drop(st);
    away.turn_off().unwrap();
    assert!(!away.is_hub() && away.key().is_none());
    assert!(a.logged("sync away from home is off"));
}

/// The tunnel state the service starts with: none, one of another group,
/// which is dropped, one of no group, which takes this one, and one that
/// does not read, which keeps it off and says why.
#[test]
fn the_state_it_starts_with() {
    let g = Group::new(1);
    let a = g.node(0);
    let tag = certs::tag(&g.root);
    let me = g.devs[0].id.clone();
    let off = Away::new(a.dir.0.clone(), tag.clone(), me.clone(), a.log());
    assert!(off.key().is_none() && off.status(&a.node).is_none());
    let mut st = State::new("0123456789abcdef").unwrap();
    st.save(&a.dir.0).unwrap();
    let other = Away::new(a.dir.0.clone(), tag.clone(), me.clone(), a.log());
    assert!(other.key().is_none());
    assert!(a.logged("in another group now"));
    st.group = String::new();
    st.save(&a.dir.0).unwrap();
    let none = Away::new(a.dir.0.clone(), tag.clone(), me.clone(), a.log());
    assert!(none.key().is_some());
    assert_eq!(State::load(&a.dir.0).unwrap().unwrap().group, tag);
    std::fs::write(a.dir.0.join("tunnel.json"), b"{not json").unwrap();
    let bad = Away::new(a.dir.0.clone(), tag, me, a.log());
    let s = bad.status(&a.node).unwrap();
    assert!(!s.error.is_empty(), "{s:?}");
}
