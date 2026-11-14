// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The relay's link against the Rust relay server in the same process: the
//! registration, the watch, a dial and its answer through the tunnel, the
//! refusals and the credentials' change.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use cbb_core::certs::{self, Cert};

use super::*;
use crate::nettest::{Group, wait_for};
use crate::relayd::keys::Keys;
use crate::relayd::limits::Limits;
use crate::relayd::server::{self, Relay as Server};

/// What a link told the app.
#[derive(Default)]
struct Seen {
    want: Mutex<bool>,
    dials: Mutex<Vec<(String, u16)>>,
    calls: Mutex<Vec<(String, u16)>>,
    reports: Mutex<Vec<Report>>,
    logs: Mutex<Vec<String>>,
}

impl Seen {
    fn last(&self) -> Option<Report> {
        self.reports.lock().unwrap().last().cloned()
    }
    fn logged(&self, s: &str) -> bool {
        self.logs.lock().unwrap().iter().any(|l| l.contains(s))
    }
}

impl Events for Seen {
    fn wanted(&self, _peer: &str) -> bool {
        *self.want.lock().unwrap()
    }
    fn dial(&self, peer: &str, port: u16) {
        self.dials.lock().unwrap().push((peer.into(), port));
    }
    fn calling(&self, peer: &str, port: u16) {
        self.calls.lock().unwrap().push((peer.into(), port));
    }
    fn changed(&self, report: &Report) {
        self.reports.lock().unwrap().push(report.clone());
    }
    fn log(&self, line: &str) {
        self.logs.lock().unwrap().push(line.into());
    }
}

fn server(open: bool, groups: Vec<String>) -> (Server, Vec<certs::KeyHash>) {
    let keys = Keys::new().unwrap();
    let pin = Cert::parse(&keys.cert).unwrap().key_hash();
    let s = Server::start(server::Config {
        listen: SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
        keys,
        groups,
        open,
        limits: Limits::default(),
        log: Arc::new(|_| {}),
        verbose: true,
        refused: None,
    })
    .unwrap();
    (s, vec![pin])
}

fn config(g: &Group, i: usize, s: &Server, pins: &[certs::KeyHash], member_port: u16) -> Config {
    Config {
        endpoint: s.addr(),
        pins: pins.to_vec(),
        chain: g.chain(i),
        key: g.key(i),
        device: g.id(i),
        wg_key: crate::tunnel::new_key().unwrap().try_into().unwrap(),
        records: Arc::new(Mutex::new(g.records_json())),
        member_port,
        credentials: Arc::new(Mutex::new(None)),
    }
}

fn connected(seen: &Seen, others: usize) -> bool {
    seen.last().is_some_and(|r| r.connected && r.online.len() == others)
}

/// Two devices of a group register; the one with the lower ID dials the
/// other through the relay when the app wants it, and the bytes pass both
/// ways between the port the app dials and the other's member listener.
#[test]
fn dials_and_answers_through_the_relay() {
    let mut g = Group::new(2);
    let (s, pins) = server(true, Vec::new());
    // The lower ID dials.
    if g.id(0) > g.id(1) {
        g.devs.swap(0, 1);
    }
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let member_port = listener.local_addr().unwrap().port();
    let (a, b) = (Arc::new(Seen::default()), Arc::new(Seen::default()));
    let ra = Relay::start(config(&g, 0, &s, &pins, 1), a.clone());
    let rb = Relay::start(config(&g, 1, &s, &pins, member_port), b.clone());
    assert!(
        wait_for(Duration::from_secs(20), || connected(&a, 1) && connected(&b, 1)),
        "{:?} {:?}",
        a.last(),
        b.last()
    );
    assert!(a.last().unwrap().online.contains(&g.id(1)));
    assert_eq!(s.stats().1, 2);

    *a.want.lock().unwrap() = true;
    assert!(wait_for(Duration::from_secs(20), || !a.dials.lock().unwrap().is_empty()), "no dial");
    let (peer, port) = a.dials.lock().unwrap()[0].clone();
    assert_eq!(peer, g.id(1));
    let mut c = TcpStream::connect(("127.0.0.1", port)).unwrap();
    c.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    let (mut k, _) = listener.accept().unwrap();
    k.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    assert!(wait_for(Duration::from_secs(5), || !b.calls.lock().unwrap().is_empty()));
    assert_eq!(b.calls.lock().unwrap()[0].0, g.id(0));
    c.write_all(b"hello").unwrap();
    let mut buf = [0u8; 5];
    k.read_exact(&mut buf).unwrap();
    assert_eq!(&buf, b"hello");
    k.write_all(b"world").unwrap();
    c.read_exact(&mut buf).unwrap();
    assert_eq!(&buf, b"world");
    assert!(wait_for(Duration::from_secs(5), || a.last().is_some_and(|r| r.through == 1)));
    drop(k);
    drop(c);
    // Both ends see it closed at once: a bridge that ends sends its FIN
    // before smoltcp's socket goes.
    assert!(
        wait_for(Duration::from_secs(5), || a.last().is_some_and(|r| r.through == 0)
            && b.last().is_some_and(|r| r.through == 0)),
        "{:?} {:?}",
        a.last(),
        b.last()
    );

    // The other goes: the list the relay sends drops it.
    drop(rb);
    assert!(wait_for(Duration::from_secs(20), || connected(&a, 0)), "{:?}", a.last());
    drop(ra);
    assert!(wait_for(Duration::from_secs(10), || s.stats().1 == 0));
}

/// A dial the app does not take ends after its wait, and the link says so
/// in its log, then dials again.
#[test]
fn a_dial_the_app_does_not_take() {
    let mut g = Group::new(2);
    let (s, pins) = server(true, Vec::new());
    if g.id(0) > g.id(1) {
        g.devs.swap(0, 1);
    }
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let (a, b) = (Arc::new(Seen::default()), Arc::new(Seen::default()));
    *a.want.lock().unwrap() = true;
    let _ra = Relay::start(config(&g, 0, &s, &pins, 1), a.clone());
    let _rb = Relay::start(config(&g, 1, &s, &pins, listener.local_addr().unwrap().port()), b.clone());
    assert!(
        wait_for(Duration::from_secs(40), || a.logged("did not take the connection")),
        "{:?}",
        a.logs.lock().unwrap()
    );
}

/// A relay that serves other groups refuses the registration, and the
/// link reports why and keeps trying.
#[test]
fn refused_by_a_relay_of_other_groups() {
    let g = Group::new(1);
    let (s, pins) = server(false, vec!["0123456789abcdef".into()]);
    let a = Arc::new(Seen::default());
    let _r = Relay::start(config(&g, 0, &s, &pins, 1), a.clone());
    assert!(wait_for(Duration::from_secs(20), || a.last().is_some_and(|r| r.error.is_some())), "no error");
    let r = a.last().unwrap();
    assert!(!r.connected);
    assert!(a.logged("the relay"));
}

/// A relay whose key is not pinned is not one to register with.
#[test]
fn refuses_a_relay_of_another_key() {
    let g = Group::new(1);
    let (s, _) = server(true, Vec::new());
    let a = Arc::new(Seen::default());
    let _r = Relay::start(config(&g, 0, &s, &[[7u8; 32]], 1), a.clone());
    assert!(wait_for(Duration::from_secs(20), || a.last().is_some_and(|r| r.error.is_some())), "no error");
}

/// The relay serves the device's group by its tag.
#[test]
fn a_relay_of_the_group() {
    let g = Group::new(1);
    let (s, pins) = server(false, vec![certs::tag(&g.root)]);
    let a = Arc::new(Seen::default());
    let _r = Relay::start(config(&g, 0, &s, &pins, 1), a.clone());
    assert!(wait_for(Duration::from_secs(20), || connected(&a, 0)), "{:?}", a.last());
}

/// Nobody listens at the relay's address: an error each try, and stopping
/// ends the link at once.
#[test]
fn no_relay_there() {
    let g = Group::new(1);
    let ln = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let addr = ln.local_addr().unwrap();
    drop(ln);
    let a = Arc::new(Seen::default());
    let cfg = Config {
        endpoint: addr,
        pins: vec![[0; 32]],
        chain: g.chain(0),
        key: g.key(0),
        device: g.id(0),
        wg_key: [1; 32],
        records: Arc::new(Mutex::new(Vec::new())),
        member_port: 1,
        credentials: Arc::new(Mutex::new(None)),
    };
    cfg.records.lock().unwrap().push(serde_json::json!({}));
    let r = Relay::start(cfg, a.clone());
    assert!(wait_for(Duration::from_secs(10), || a.last().is_some_and(|r| r.error.is_some())));
    let t = std::time::Instant::now();
    drop(r);
    assert!(t.elapsed() < Duration::from_secs(3));
}

/// The notes of a watch: a list of devices that is not valid ends the
/// registration; a call with a bad name or ticket is not taken; at most
/// MAX_CALLS calls at once; the pseudonyms the app named stand for their
/// devices.
#[test]
fn notes_of_the_watch() {
    let g = Group::new(1);
    let seen = Arc::new(Seen::default());
    let events: Arc<dyn Events> = seen.clone();
    let cfg = Arc::new(config_without_server(&g));
    let pseudonym = "A".repeat(43) + "=";
    let s = Arc::new(Session {
        cfg,
        name: "f".repeat(32),
        names: HashMap::from([(pseudonym.clone(), g.id(0))]),
        was: None,
        events,
        at: SocketAddr::from((Ipv4Addr::LOCALHOST, 1)),
        stop: AtomicBool::new(false),
        state: Mutex::new(SessionState::default()),
        conns: Mutex::new(HashMap::new()),
        threads: Mutex::new(Vec::new()),
    });
    assert!(s.note(Note { online: Some(vec!["relay".into()]), ..Note::default() }).is_err());
    assert!(s.note(Note { online: Some(vec!["0".repeat(32); MAX_MEMBERS + 1]), ..Note::default() }).is_err());
    // A device with a lower name than this one's is not dialed.
    s.note(Note { online: Some(vec![pseudonym.clone(), "0".repeat(32)]), ..Note::default() }).unwrap();
    assert!(s.state.lock().unwrap().dialers.is_empty());
    assert_eq!(seen.last().unwrap().online, vec![g.id(0), "0".repeat(32)]);
    assert_eq!(s.device(&pseudonym), g.id(0));
    assert_eq!(s.device("x"), "x");
    // Calls not valid are dropped without a thread.
    s.note(Note { call: "bad".into(), ticket: "AAAAAAAAAAAAAAAAAAAAAA==".into(), ..Note::default() }).unwrap();
    s.note(Note { call: "0".repeat(32), ticket: "bad".into(), ..Note::default() }).unwrap();
    s.note(Note::default()).unwrap();
    assert!(s.threads.lock().unwrap().is_empty());
    for _ in 0..MAX_CALLS {
        assert!(s.take_call());
    }
    assert!(!s.take_call());
    s.note(Note { call: "0".repeat(32), ticket: "AAAAAAAAAAAAAAAAAAAAAA==".into(), ..Note::default() }).unwrap();
    assert!(s.threads.lock().unwrap().is_empty());
    s.state.lock().unwrap().calls = 0;
    // A call taken goes nowhere here: the relay's port is closed, and the
    // log says so.
    s.note(Note { call: "0".repeat(32), ticket: "AAAAAAAAAAAAAAAAAAAAAA==".into(), ..Note::default() }).unwrap();
    assert!(wait_for(Duration::from_secs(10), || seen.logged("answering")), "{:?}", seen.logs.lock().unwrap());
    assert!(wait_for(Duration::from_secs(5), || s.state.lock().unwrap().calls == 0));
    // Once the session ended nothing more is held.
    s.end();
    let c = TcpStream::connect(("127.0.0.1", member_listener().1)).unwrap();
    assert!(s.hold(&c).is_err());
    assert!(!s.credentials_changed());
    *s.cfg.credentials.lock().unwrap() = None;
}

fn member_listener() -> (TcpListener, u16) {
    static L: std::sync::OnceLock<(TcpListener, u16)> = std::sync::OnceLock::new();
    let (l, p) = L.get_or_init(|| {
        let l = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let p = l.local_addr().unwrap().port();
        (l, p)
    });
    (l.try_clone().unwrap(), *p)
}

fn config_without_server(g: &Group) -> Config {
    Config {
        endpoint: SocketAddr::from((Ipv4Addr::LOCALHOST, 1)),
        pins: Vec::new(),
        chain: g.chain(0),
        key: g.key(0),
        device: g.id(0),
        wg_key: [1; 32],
        records: Arc::new(Mutex::new(Vec::new())),
        member_port: 1,
        credentials: Arc::new(Mutex::new(None)),
    }
}

/// Frames: a frame too long is an error, a partial one waits.
#[test]
fn frames_of_the_watch() {
    let mut inbox = vec![0xff, 0xff, 0xff, 0xff];
    assert!(take_frame(&mut inbox).is_err());
    let mut inbox = vec![0, 0, 0, 3, b'{'];
    assert_eq!(take_frame(&mut inbox).unwrap(), None);
    let mut inbox = vec![0, 0];
    assert_eq!(take_frame(&mut inbox).unwrap(), None);
    assert!(!valid_name(&"g".repeat(32)));
    assert!(!valid_name(&("A".repeat(42) + "==")));
    assert!(io_err(std::io::Error::other("x")).to_string().contains("through the relay"));
}

/// Pause returns at once when stopped, and after its time otherwise.
#[test]
fn pause_stops() {
    let stop = AtomicBool::new(true);
    let t = std::time::Instant::now();
    pause(Duration::from_secs(5), &[&stop]);
    assert!(t.elapsed() < Duration::from_secs(1));
    let go = AtomicBool::new(false);
    pause(Duration::from_millis(50), &[&go]);
    assert!(t.elapsed() >= Duration::from_millis(50));
}

/// Two devices register with the group's credentials in place of their
/// member certificates: on an open relay and on one that serves the group,
/// which asks for the roots; each knows the other by its pseudonym. A
/// change of the credentials makes the link register again.
#[test]
fn registers_with_credentials() {
    let mut g = Group::new(2);
    let servers = [crate::nettest::new_key(), crate::nettest::new_key()];
    // The lower pseudonym dials.
    let pseudo = |k: &Arc<cbb_core::identity::FileKey>| {
        cbb_core::credential::pseudonym(&certs::sha256(&certs::p256_spki_of(&crate::identity::ExternalKey::public(
            &**k,
        ))))
    };
    let mut servers = servers.to_vec();
    if pseudo(&servers[0]) > pseudo(&servers[1]) {
        servers.swap(0, 1);
    }
    let creds = g.period(&servers, 1);
    let names = |i: usize| HashMap::from([(pseudo(&servers[1 - i]), g.id(1 - i))]);
    let cred = |i: usize, creds: &[cbb_core::credential::Credential]| {
        Arc::new(
            Credentialed::new(
                servers[i].clone(),
                creds.to_vec(),
                vec![g.root.der.clone()],
                names(i),
                crate::nettest::now_ms(),
            )
            .unwrap(),
        )
    };
    for open in [true, false] {
        let groups = if open { Vec::new() } else { vec![certs::tag(&g.root)] };
        let (s, pins) = server(open, groups);
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let (a, b) = (Arc::new(Seen::default()), Arc::new(Seen::default()));
        let ca = config(&g, 0, &s, &pins, 1);
        *ca.credentials.lock().unwrap() = Some(cred(0, &creds));
        let creds_a = ca.credentials.clone();
        let cb = config(&g, 1, &s, &pins, listener.local_addr().unwrap().port());
        *cb.credentials.lock().unwrap() = Some(cred(1, &creds));
        let _ra = Relay::start(ca, a.clone());
        let _rb = Relay::start(cb, b.clone());
        assert!(
            wait_for(Duration::from_secs(20), || connected(&a, 1) && connected(&b, 1)),
            "open {open}: {:?} {:?} {:?}",
            a.last(),
            b.last(),
            a.logs.lock().unwrap()
        );
        assert_eq!(a.last().unwrap().online, vec![g.id(1)], "the pseudonym stands for its device");
        *a.want.lock().unwrap() = true;
        assert!(wait_for(Duration::from_secs(20), || !a.dials.lock().unwrap().is_empty()), "no dial");
        let (_, port) = a.dials.lock().unwrap()[0].clone();
        let _c = TcpStream::connect(("127.0.0.1", port)).unwrap();
        let _k = listener.accept().unwrap();
        assert!(wait_for(Duration::from_secs(5), || b.calls.lock().unwrap().first().is_some_and(|c| c.0 == g.id(0))));
        // A new period: the link registers again with it.
        let newer = g.period(&servers, 2);
        *creds_a.lock().unwrap() = Some(cred(0, &newer));
        assert!(wait_for(Duration::from_secs(20), || a.logged("credentials changed")), "{:?}", a.logs.lock().unwrap());
    }
    // Credentials that do not list the server key, a key that is not
    // P-256's, too many roots, a pseudonym that is not one.
    let other = crate::nettest::new_key();
    assert!(Credentialed::new(other, creds.to_vec(), Vec::new(), HashMap::new(), crate::nettest::now_ms()).is_err());
    assert!(
        Credentialed::new(
            servers[0].clone(),
            creds.to_vec(),
            vec![Vec::new(); MAX_ROOTS + 1],
            HashMap::new(),
            crate::nettest::now_ms()
        )
        .is_err()
    );
    assert!(
        Credentialed::new(
            servers[0].clone(),
            creds.to_vec(),
            Vec::new(),
            HashMap::from([("x".to_string(), g.id(0))]),
            crate::nettest::now_ms()
        )
        .is_err()
    );
    g.add();
}
