// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The tunnel toward a hub on the records of 0.6: this device's own key
//! toward that hub, and the pre-shared keys of its member connections with
//! it tried one at a time.

use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use cbb_core::records::DeviceId;

use crate::hub::{Hub as Server, Peer};
use crate::nettest::{Group, wait_for};
use crate::tunnel::{self, Hub, Link};

/// A link with a pre-shared key the hub does not hold gets no answer; one
/// with the key it holds does, under this device's key toward that hub and
/// the hub's key on the way.
#[test]
fn a_link_answers_only_with_the_key_the_hub_holds() {
    let g = Group::new(2);
    let hub_key: [u8; 32] = tunnel::new_key().unwrap().try_into().unwrap();
    let secret = [9u8; 32];
    let id = g.id(1);
    let me = DeviceId(std::array::from_fn(|i| u8::from_str_radix(&id[i * 2..i * 2 + 2], 16).unwrap()));
    let toward = cbb_core::hubkey::key_for(&secret, &cbb_core::format::DeviceId(me.0));
    let (held, other) = ([3u8; 32], [4u8; 32]);
    let peer = Peer {
        key: toward.1,
        psk: held,
        older_psks: Vec::new(),
        addr: tunnel::addr(&g.id(1)).unwrap(),
        until: None,
        source: None,
    };
    let server = Server::start(
        &hub_key,
        &g.id(0),
        None,
        vec![peer],
        SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0),
        Arc::new(|_| Some(1)),
        Arc::new(|_| {}),
    )
    .unwrap();
    let hub = Hub {
        device: g.id(0),
        key: tunnel::public_key_of(&hub_key),
        endpoints: vec![SocketAddr::new(Ipv4Addr::LOCALHOST.into(), server.udp_port())],
        ..Hub::default()
    };
    let way = &hub.ways()[0];
    let wrong = Link::start_toward(toward.0, other, way, &me, Arc::new(|_| {})).unwrap();
    assert!(!wait_for(Duration::from_secs(3), || wrong.answered()), "a key the hub does not hold");
    drop(wrong);
    let right = Link::start_toward(toward.0, held, way, &me, Arc::new(|_| {})).unwrap();
    assert!(wait_for(Duration::from_secs(10), || right.answered()), "the key the hub holds");
}

/// A hub that holds several pre-shared keys of a client answers a link
/// under any of them, the newest or an older one, and none under a key it
/// does not hold.
#[test]
fn a_hub_answers_under_each_key_it_holds() {
    let (echo_port, _) = super::races::echo();
    let g = Group::new(2);
    let hub_key: [u8; 32] = tunnel::new_key().unwrap().try_into().unwrap();
    let id = g.id(1);
    let me = DeviceId(std::array::from_fn(|i| u8::from_str_radix(&id[i * 2..i * 2 + 2], 16).unwrap()));
    let toward = cbb_core::hubkey::key_for(&[9u8; 32], &cbb_core::format::DeviceId(me.0));
    let peer = Peer {
        key: toward.1,
        psk: [3; 32],
        older_psks: vec![[4; 32], [5; 32]],
        addr: tunnel::addr(&g.id(1)).unwrap(),
        until: None,
        source: None,
    };
    let server = Server::start(
        &hub_key,
        &g.id(0),
        None,
        vec![peer],
        SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0),
        Arc::new(move |_| Some(echo_port)),
        Arc::new(|_| {}),
    )
    .unwrap();
    let hub = Hub {
        device: g.id(0),
        key: tunnel::public_key_of(&hub_key),
        endpoints: vec![SocketAddr::new(Ipv4Addr::LOCALHOST.into(), server.udp_port())],
        ..Hub::default()
    };
    let way = &hub.ways()[0];
    for psk in [[5u8; 32], [3; 32], [4; 32]] {
        let l = Link::start_toward(toward.0, psk, way, &me, Arc::new(|_| {})).unwrap();
        assert!(wait_for(Duration::from_secs(10), || l.answered()), "key {}", psk[0]);
        // Data goes both ways under that key: an echo through the hub.
        let mut c = std::net::TcpStream::connect_timeout(&l.local(), Duration::from_secs(5)).unwrap();
        c.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        c.write_all(b"ping").unwrap();
        let mut back = [0u8; 4];
        c.read_exact(&mut back).unwrap();
        assert_eq!(&back, b"ping", "key {}", psk[0]);
    }
    let l = Link::start_toward(toward.0, [6; 32], way, &me, Arc::new(|_| {})).unwrap();
    assert!(!wait_for(Duration::from_secs(3), || l.answered()), "a key the hub does not hold");
}

/// The ways to a hub: its own key on the endpoints no face names, each
/// face's key on its endpoint, and VLESS with the first face's key.
#[test]
fn a_hub_has_a_way_per_key() {
    let (direct, fw1, fw2): (SocketAddr, SocketAddr, SocketAddr) =
        ("192.0.2.1:51820".parse().unwrap(), "203.0.113.5:8443".parse().unwrap(), "198.51.100.7:8443".parse().unwrap());
    let hub = Hub {
        device: "0".repeat(32),
        key: vec![1; 32],
        endpoints: vec![direct, fw1, fw2],
        vless: Some(serde_json::json!({"endpoint": "203.0.113.5:443"})),
        faces: vec![tunnel::Face { endpoint: fw1, key: vec![2; 32] }, tunnel::Face { endpoint: fw2, key: vec![3; 32] }],
        ..Hub::default()
    };
    let ways = hub.ways();
    let keys: Vec<(u8, Vec<SocketAddr>, bool)> =
        ways.iter().map(|w| (w.key[0], w.endpoints.clone(), w.vless.is_some())).collect();
    assert_eq!(keys, vec![(1, vec![direct], false), (2, vec![fw1], true), (3, vec![fw2], false)]);
    assert!(ways.iter().all(|w| w.faces.is_empty()));
    // No faces: one way, VLESS on the hub's own key.
    let plain = Hub { faces: Vec::new(), ..hub };
    assert_eq!(plain.ways().len(), 1);
    assert!(plain.ways()[0].vless.is_some());
}
