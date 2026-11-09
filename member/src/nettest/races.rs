// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! Races: many connections through one tunnel while the hub's clients
//! change and the link ends, many registrations with the relay at once while
//! it stops, and one engine taking copies from many threads.

use std::io::{Read, Write};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicUsize, Ordering};
use std::sync::{Arc, Barrier};
use std::time::{Duration, Instant};

use cbb_core::clip::{Engine, Event, Kind, Via};
use cbb_core::hlc::{Clock, Timestamp};

use crate::hub::{Hub as Server, Peer};
use crate::nettest::{Group, now_ms, wait_for};
use crate::tunnel::{self, Hub, Link, State};

fn key() -> [u8; 32] {
    tunnel::new_key().unwrap().try_into().unwrap()
}

/// An echo server; it counts the connections it served to their end.
pub(super) fn echo() -> (u16, Arc<AtomicUsize>) {
    let ln = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let port = ln.local_addr().unwrap().port();
    let done = Arc::new(AtomicUsize::new(0));
    let d = done.clone();
    std::thread::spawn(move || {
        for c in ln.incoming() {
            let Ok(mut c) = c else { continue };
            let d = d.clone();
            std::thread::spawn(move || {
                let mut r = c.try_clone().unwrap();
                let _ = std::io::copy(&mut r, &mut c);
                let _ = c.shutdown(std::net::Shutdown::Both);
                d.fetch_add(1, Ordering::SeqCst);
            });
        }
    });
    (port, done)
}

/// A hub and one client's link to it, the hub passing every connection to
/// port.
fn hub_and_link(port: u16) -> (Server, Link, Peer, Ipv6Addr) {
    hub_and_link_at(Ipv4Addr::LOCALHOST.into(), port)
}

/// A hub listening on ip, and one client's link to it.
pub(super) fn hub_and_link_at(ip: std::net::IpAddr, port: u16) -> (Server, Link, Peer, Ipv6Addr) {
    let g = Group::new(2);
    let (hub_key, client_key, psk) = (key(), key(), key());
    let own = tunnel::addr(&g.id(0)).unwrap();
    let client = tunnel::addr(&g.id(1)).unwrap();
    let peer = Peer { key: tunnel::public_key_of(&client_key).try_into().unwrap(), psk, addr: client, until: None };
    let server = Server::start(
        &hub_key,
        &g.id(0),
        None,
        vec![peer.clone()],
        SocketAddr::new(ip, 0),
        Arc::new(move |_| Some(port)),
        Arc::new(|_| {}),
    )
    .unwrap();
    let hub = Hub {
        device: g.id(0),
        key: tunnel::public_key_of(&hub_key),
        psk: psk.to_vec(),
        endpoints: vec![SocketAddr::new(ip, server.udp_port())],
        next: Vec::new(),
        obfuscation: None,
        vless: None,
    };
    let me = cbb_core::certs::DeviceId::parse(&g.id(1)).unwrap();
    let link = Link::start(&State::with_key(&client_key).unwrap(), &hub, &me, Arc::new(|_| {})).unwrap();
    (server, link, peer, own)
}

/// One connection through the link: it sends n bytes and reads them back,
/// or leaves halfway when cut.
pub(super) fn round_trip(at: SocketAddr, n: usize, cut: bool) -> bool {
    let Ok(mut c) = TcpStream::connect_timeout(&at, Duration::from_secs(5)) else { return false };
    c.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
    let data: Vec<u8> = (0..n).map(|i| (i * 7 + n) as u8).collect();
    let w = {
        let mut c = c.try_clone().unwrap();
        let data = data.clone();
        std::thread::spawn(move || c.write_all(&data).is_ok())
    };
    if cut {
        let mut half = vec![0u8; n / 2];
        let r = c.read_exact(&mut half);
        drop(c);
        let _ = w.join();
        return r.is_ok() && half == data[..n / 2];
    }
    let mut back = vec![0u8; n];
    let r = c.read_exact(&mut back);
    let wr = w.join().unwrap_or(false);
    r.is_ok() && wr && back == data
}

/// Connections at once through one tunnel, some cut halfway, while
/// the hub's clients are set again and again; then the link ends with
/// connections open, and none of them hangs.
#[test]
fn many_connections_through_a_tunnel_at_once() {
    let (port, served) = echo();
    let (server, link, peer, own) = hub_and_link(port);
    let at = link.local();
    assert!(wait_for(Duration::from_secs(20), || round_trip(at, 10, false)), "the tunnel does not pass");
    let stop = Arc::new(AtomicBool::new(false));
    let server = Arc::new(server);
    let churn = {
        let (stop, server, peer) = (stop.clone(), server.clone(), peer.clone());
        std::thread::spawn(move || {
            let mut n = 0;
            while !stop.load(Ordering::SeqCst) {
                server.set_peers_at(vec![peer.clone()], own).unwrap();
                n += 1;
                std::thread::sleep(Duration::from_millis(2));
            }
            n
        })
    };
    // More connections at once than the hub keeps sockets listening, and
    // fewer than a link passes with the ones still closing (tunnel.rs,
    // MAX_BRIDGES).
    let threads = 16;
    let start = Arc::new(Barrier::new(threads));
    let ts: Vec<_> = (0..threads)
        .map(|i| {
            let start = start.clone();
            std::thread::spawn(move || {
                start.wait();
                (0..4).all(|k| round_trip(at, 1 + (i * 3001 + k * 977) % 40_000, (i + k) % 5 == 0))
            })
        })
        .collect();
    let ok = ts.into_iter().map(|t| t.join().unwrap()).filter(|x| *x).count();
    stop.store(true, Ordering::SeqCst);
    assert!(churn.join().unwrap() > 0);
    assert_eq!(ok, threads, "every connection passed its bytes");
    let closed = wait_for(Duration::from_secs(10), || served.load(Ordering::SeqCst) >= threads * 4);
    assert!(closed, "the far ends close: {} of {}", served.load(Ordering::SeqCst), threads * 4);

    // The link ends with connections open: their reads end, none hangs.
    let open: Vec<TcpStream> = (0..8)
        .map(|_| {
            let c = TcpStream::connect(at).unwrap();
            c.set_read_timeout(Some(Duration::from_secs(30))).unwrap();
            c
        })
        .collect();
    std::thread::sleep(Duration::from_millis(200));
    let began = Instant::now();
    drop(link);
    for mut c in open {
        let mut b = [0u8; 16];
        let _ = c.read(&mut b);
    }
    assert!(began.elapsed() < Duration::from_secs(15), "connections outlived their link: {:?}", began.elapsed());
    drop(server);
}

/// Devices of one group register with the relay at once, each with the
/// group's records, one of them removed: the others all register, and
/// all keep their watches. Then
/// they register again at once while the relay stops, and the stop ends.
#[test]
fn registrations_at_once_and_a_stop() {
    use crate::relay::{Config, Events, Relay, Report};
    use crate::relayd::keys::Keys;
    use crate::relayd::limits::Limits;
    use crate::relayd::server::{self, Relay as RelayServer};

    #[derive(Default)]
    struct Count(AtomicUsize, std::sync::Mutex<Option<Report>>);
    impl Events for Count {
        fn wanted(&self, _: &str) -> bool {
            false
        }
        fn dial(&self, _: &str, _: u16) {}
        fn calling(&self, _: &str, _: u16) {}
        fn changed(&self, r: &Report) {
            if r.connected {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
            *self.1.lock().unwrap() = Some(r.clone());
        }
        fn log(&self, _: &str) {}
    }

    // More devices than a hub passes connections (tunnel.rs, MAX_BRIDGES):
    // each keeps its watch open through the relay.
    let n = 40;
    let mut g = Group::new(n);
    g.revoke(n - 1);
    let keys = Keys::new().unwrap();
    let pin = cbb_core::certs::Cert::parse(&keys.cert).unwrap().key_hash();
    let s = RelayServer::start(server::Config {
        listen: SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
        keys,
        groups: Vec::new(),
        open: true,
        // Every device registers from the loopback address.
        limits: Limits {
            per_address: 4096,
            per_network: 4096,
            per_wide: 4096,
            per_provider: 4096,
            ..Limits::default()
        },
        log: Arc::new(|_| {}),
        verbose: false,
    })
    .unwrap();
    let seen: Vec<Arc<Count>> = (0..n).map(|_| Arc::new(Count::default())).collect();
    let links: Vec<Relay> = (0..n)
        .map(|i| {
            Relay::start(
                Config {
                    endpoint: s.addr(),
                    pins: vec![pin],
                    chain: g.chain(i),
                    key: g.key(i),
                    device: g.id(i),
                    wg_key: key(),
                    records: Arc::new(std::sync::Mutex::new(g.records_json())),
                    member_port: 1,
                    credentials: Arc::new(std::sync::Mutex::new(None)),
                },
                seen[i].clone(),
            )
        })
        .collect();
    let online = |i: usize| seen[i].1.lock().unwrap().as_ref().is_some_and(|r| r.connected && r.online.len() == n - 2);
    assert!(
        wait_for(Duration::from_secs(40), || (0..n - 1).all(online)),
        "{:?}",
        seen.iter().map(|c| c.1.lock().unwrap().clone()).collect::<Vec<_>>()
    );
    assert_eq!(s.stats().1, n - 1, "the removed device stays out");
    assert!(seen[n - 1].1.lock().unwrap().as_ref().is_none_or(|r| !r.connected));

    // They end and register again at once, and the relay stops meanwhile.
    drop(links);
    let again: Vec<Relay> = (0..n - 1)
        .map(|i| {
            Relay::start(
                Config {
                    endpoint: s.addr(),
                    pins: vec![pin],
                    chain: g.chain(i),
                    key: g.key(i),
                    device: g.id(i),
                    wg_key: key(),
                    records: Arc::new(std::sync::Mutex::new(g.records_json())),
                    member_port: 1,
                    credentials: Arc::new(std::sync::Mutex::new(None)),
                },
                Arc::new(Count::default()),
            )
        })
        .collect();
    std::thread::sleep(Duration::from_millis(150));
    let began = Instant::now();
    drop(s);
    assert!(began.elapsed() < Duration::from_secs(20), "the stop took {:?}", began.elapsed());
    let began = Instant::now();
    drop(again);
    assert!(began.elapsed() < Duration::from_secs(20), "the links' end took {:?}", began.elapsed());
}

/// One engine takes local copies and the events of another member from
/// many threads at once: it ends with the latest of them all, and its
/// clock never issued one timestamp twice.
#[test]
fn one_engine_from_many_threads() {
    let base = now_ms();
    let engine = |id: &str| {
        let wall = Arc::new(AtomicI64::new(base));
        let w = wall.clone();
        let clock = Clock::new(Box::new(move || w.load(Ordering::SeqCst)), Timestamp::default(), None);
        let w = wall.clone();
        (
            Arc::new(Engine::new(
                id,
                clock,
                Box::new(move || w.load(Ordering::SeqCst)),
                Box::new(|| Duration::from_secs(1000)),
            )),
            wall,
        )
    };
    let (a, wall_a) = engine("00000000000000000000000000000001");
    let (b, wall_b) = engine("00000000000000000000000000000002");
    // b's copies, made ahead, reach a from several threads while a's own
    // threads copy.
    let theirs: Vec<Event> = (0..200)
        .map(|i| {
            wall_b.fetch_add(if i % 3 == 0 { -50 } else { 30 }, Ordering::SeqCst);
            b.copied(&format!("theirs {i}"), Kind::Text, Via::Copy).unwrap().unwrap()
        })
        .collect();
    let theirs = Arc::new(theirs);
    let mine = Arc::new(std::sync::Mutex::new(Vec::new()));
    let start = Arc::new(Barrier::new(8));
    let ts: Vec<_> = (0..8)
        .map(|t| {
            let (a, theirs, mine, start, wall) =
                (a.clone(), theirs.clone(), mine.clone(), start.clone(), wall_a.clone());
            std::thread::spawn(move || {
                start.wait();
                for k in 0..100 {
                    if t % 2 == 0 {
                        wall.fetch_add(if k % 4 == 0 { -40 } else { 20 }, Ordering::SeqCst);
                        if let Some(ev) = a.copied(&format!("mine {t} {k}"), Kind::Text, Via::Copy).unwrap() {
                            mine.lock().unwrap().push(ev);
                        }
                    } else {
                        let ev = theirs[(k * 7 + t * 13) % theirs.len()].clone();
                        let _ = a.received(ev).unwrap();
                    }
                }
            })
        })
        .collect();
    for t in ts {
        t.join().unwrap();
    }
    for ev in theirs.iter() {
        let _ = a.received(ev.clone()).unwrap();
    }
    let mine = mine.lock().unwrap();
    assert_eq!(mine.len(), 400);
    let mut times: Vec<Timestamp> = mine.iter().map(|e| e.time).collect();
    times.sort();
    times.dedup();
    assert_eq!(times.len(), 400, "a timestamp issued twice");
    let all: Vec<&Event> = mine.iter().chain(theirs.iter()).collect();
    let latest = all.iter().copied().reduce(|x, y| if y.later(x) { y } else { x }).unwrap();
    assert_eq!(a.current().unwrap().id, latest.id);
}
