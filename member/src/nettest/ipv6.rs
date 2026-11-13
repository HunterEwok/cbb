// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The tunnel and the relay over IPv6: a hub and a relay that listen on
//! the IPv6 loopback, reached there. Where the system has no IPv6 the tests
//! say so and pass, unless CBB_TEST_IPV6=1 asks for them, as on the bench.

use std::io::{Read, Write};
use std::net::{Ipv6Addr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use super::races::{echo, hub_and_link_at, round_trip};
use crate::nettest::{Group, wait_for};

/// Whether the IPv6 loopback takes TCP and UDP; without it a test that
/// CBB_TEST_IPV6=1 does not ask for is skipped, and says so.
fn ipv6(test: &str) -> bool {
    let up = TcpListener::bind((Ipv6Addr::LOCALHOST, 0)).is_ok() && UdpSocket::bind((Ipv6Addr::LOCALHOST, 0)).is_ok();
    if !up {
        assert!(std::env::var("CBB_TEST_IPV6").as_deref() != Ok("1"), "{test}: no IPv6 loopback here");
        eprintln!("{test}: skipped, no IPv6 loopback here (CBB_TEST_IPV6=1 asks for it)");
    }
    up
}

#[test]
fn a_tunnel_over_ipv6() {
    if !ipv6("a_tunnel_over_ipv6") {
        return;
    }
    let (port, _) = echo();
    let (_server, link, _, _) = hub_and_link_at(Ipv6Addr::LOCALHOST.into(), port);
    let at = link.local();
    assert!(wait_for(Duration::from_secs(20), || round_trip(at, 10, false)), "the tunnel does not pass over IPv6");
    for n in [1, 1500, 70_000] {
        assert!(round_trip(at, n, false), "{n} bytes");
    }
}

#[derive(Default)]
struct Seen {
    want: AtomicBool,
    dials: Mutex<Vec<u16>>,
    last: Mutex<Option<crate::relay::Report>>,
}

impl crate::relay::Events for Seen {
    fn wanted(&self, _: &str) -> bool {
        self.want.load(Ordering::SeqCst)
    }
    fn dial(&self, _: &str, port: u16) {
        self.dials.lock().unwrap().push(port);
    }
    fn calling(&self, _: &str, _: u16) {}
    fn changed(&self, r: &crate::relay::Report) {
        *self.last.lock().unwrap() = Some(r.clone());
    }
    fn log(&self, _: &str) {}
}

/// Two devices register with a relay on the IPv6 loopback, and one dials
/// the other through it.
#[test]
fn the_relay_over_ipv6() {
    use crate::relay::{Config, Relay};
    use crate::relayd::keys::Keys;
    use crate::relayd::limits::Limits;
    use crate::relayd::server::{self, Relay as Server};

    if !ipv6("the_relay_over_ipv6") {
        return;
    }
    let mut g = Group::new(2);
    if g.id(0) > g.id(1) {
        g.devs.swap(0, 1);
    }
    let keys = Keys::new().unwrap();
    let pin = cbb_core::certs::Cert::parse(&keys.cert).unwrap().key_hash();
    let s = Server::start(server::Config {
        listen: SocketAddr::from((Ipv6Addr::LOCALHOST, 0)),
        keys,
        groups: Vec::new(),
        open: true,
        limits: Limits::default(),
        log: Arc::new(|_| {}),
        verbose: false,
    })
    .unwrap();
    assert!(s.addr().is_ipv6());
    let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).unwrap();
    let config = |i: usize, member_port: u16| Config {
        endpoint: s.addr(),
        pins: vec![pin],
        chain: g.chain(i),
        key: g.key(i),
        device: g.id(i),
        wg_key: crate::tunnel::new_key().unwrap().try_into().unwrap(),
        records: Arc::new(Mutex::new(g.records_json())),
        member_port,
        credentials: Arc::new(Mutex::new(None)),
    };
    let (a, b) = (Arc::new(Seen::default()), Arc::new(Seen::default()));
    let _ra = Relay::start(config(0, 1), a.clone());
    let _rb = Relay::start(config(1, listener.local_addr().unwrap().port()), b.clone());
    let on = |x: &Seen| x.last.lock().unwrap().as_ref().is_some_and(|r| r.connected && r.online.len() == 1);
    assert!(wait_for(Duration::from_secs(20), || on(&a) && on(&b)), "{:?} {:?}", a.last.lock(), b.last.lock());
    a.want.store(true, Ordering::SeqCst);
    assert!(wait_for(Duration::from_secs(20), || !a.dials.lock().unwrap().is_empty()), "no dial");
    let port = a.dials.lock().unwrap()[0];
    let mut c = TcpStream::connect(("127.0.0.1", port)).unwrap();
    let (mut k, _) = listener.accept().unwrap();
    c.write_all(b"over six").unwrap();
    let mut got = [0u8; 8];
    k.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    k.read_exact(&mut got).unwrap();
    assert_eq!(&got, b"over six");
}
