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
use crate::nettest::blind::Blind;
use crate::nettest::wait_for;
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

fn config(s: &Server, pins: &[certs::KeyHash], member_port: u16, cred: Option<Arc<Credentialed>>) -> Config {
    Config { endpoint: s.addr(), pins: pins.to_vec(), member_port, credentials: Arc::new(Mutex::new(cred)) }
}

fn connected(seen: &Seen, others: usize) -> bool {
    seen.last().is_some_and(|r| r.connected && r.online.len() == others)
}

/// Two devices of a group register with their credentials; the one with
/// the lower pseudonym dials the other through the relay when the app
/// wants it, and the bytes pass both ways between the port the app dials
/// and the other's member listener. The relay names them by pseudonym, the
/// link by the device IDs they stand for.
#[test]
fn dials_and_answers_through_the_relay() {
    let g = Blind::new(2);
    let (s, pins) = server(true, Vec::new());
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let member_port = listener.local_addr().unwrap().port();
    let (a, b) = (Arc::new(Seen::default()), Arc::new(Seen::default()));
    let ra = Relay::start(config(&s, &pins, 1, Some(g.credentialed(0, 1))), a.clone());
    let rb = Relay::start(config(&s, &pins, member_port, Some(g.credentialed(1, 1))), b.clone());
    assert!(
        wait_for(Duration::from_secs(20), || connected(&a, 1) && connected(&b, 1)),
        "{:?} {:?}",
        a.last(),
        b.last()
    );
    assert_eq!(a.last().unwrap().online, vec![g.ids[1].clone()]);
    assert_eq!(s.stats().1, 2);

    *a.want.lock().unwrap() = true;
    assert!(wait_for(Duration::from_secs(20), || !a.dials.lock().unwrap().is_empty()), "no dial");
    let (peer, port) = a.dials.lock().unwrap()[0].clone();
    assert_eq!(peer, g.ids[1]);
    let mut c = TcpStream::connect(("127.0.0.1", port)).unwrap();
    c.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    let (mut k, _) = listener.accept().unwrap();
    k.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    assert!(wait_for(Duration::from_secs(5), || !b.calls.lock().unwrap().is_empty()));
    assert_eq!(b.calls.lock().unwrap()[0].0, g.ids[0]);
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
    let g = Blind::new(2);
    let (s, pins) = server(true, Vec::new());
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let (a, b) = (Arc::new(Seen::default()), Arc::new(Seen::default()));
    *a.want.lock().unwrap() = true;
    let _ra = Relay::start(config(&s, &pins, 1, Some(g.credentialed(0, 1))), a.clone());
    let port = listener.local_addr().unwrap().port();
    let _rb = Relay::start(config(&s, &pins, port, Some(g.credentialed(1, 1))), b.clone());
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
    let g = Blind::new(1);
    let (s, pins) = server(false, vec![Blind::new(1).listed()]);
    let a = Arc::new(Seen::default());
    let _r = Relay::start(config(&s, &pins, 1, Some(g.credentialed(0, 1))), a.clone());
    assert!(wait_for(Duration::from_secs(20), || a.last().is_some_and(|r| r.error.is_some())), "no error");
    let r = a.last().unwrap();
    assert!(!r.connected);
    assert!(r.error.unwrap().contains("not of a group this relay serves"));
    assert!(a.logged("the relay"));
}

/// A relay whose key is not pinned is not one to register with.
#[test]
fn refuses_a_relay_of_another_key() {
    let g = Blind::new(1);
    let (s, _) = server(true, Vec::new());
    let a = Arc::new(Seen::default());
    let _r = Relay::start(config(&s, &[[7u8; 32]], 1, Some(g.credentialed(0, 1))), a.clone());
    assert!(wait_for(Duration::from_secs(20), || a.last().is_some_and(|r| r.error.is_some())), "no error");
}

/// A relay with a list serves the device's group, named by its root and
/// recovery key: it asks for the period credential and the root.
#[test]
fn a_relay_of_the_group() {
    let g = Blind::new(1);
    let (s, pins) = server(false, vec![g.listed()]);
    let a = Arc::new(Seen::default());
    let _r = Relay::start(config(&s, &pins, 1, Some(g.credentialed(0, 1))), a.clone());
    assert!(wait_for(Duration::from_secs(20), || connected(&a, 0)), "{:?}", a.last());
}

/// Before the members' credential lists the device the link does not
/// reach the relay: it waits and says why, once; it registers as soon as
/// the credentials come.
#[test]
fn waits_for_its_credentials() {
    let g = Blind::new(1);
    let (s, pins) = server(true, Vec::new());
    let a = Arc::new(Seen::default());
    let cfg = config(&s, &pins, 1, None);
    let creds = cfg.credentials.clone();
    let _r = Relay::start(cfg, a.clone());
    assert!(wait_for(Duration::from_secs(5), || a.last().is_some_and(|r| r.error.as_deref() == Some(NOT_LISTED))));
    std::thread::sleep(CREDENTIAL_CHECK * 3);
    assert_eq!(a.reports.lock().unwrap().len(), 1, "said once");
    assert_eq!(s.stats().1, 0);
    *creds.lock().unwrap() = Some(g.credentialed(0, 1));
    assert!(wait_for(Duration::from_secs(20), || connected(&a, 0)), "{:?}", a.last());
}

/// Nobody listens at the relay's address: an error each try, and stopping
/// ends the link at once.
#[test]
fn no_relay_there() {
    let g = Blind::new(1);
    let ln = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let addr = ln.local_addr().unwrap();
    drop(ln);
    let a = Arc::new(Seen::default());
    let cfg = Config {
        endpoint: addr,
        pins: vec![[0; 32]],
        member_port: 1,
        credentials: Arc::new(Mutex::new(Some(g.credentialed(0, 1)))),
    };
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
    let g = Blind::new(1);
    let seen = Arc::new(Seen::default());
    let events: Arc<dyn Events> = seen.clone();
    let cfg = Arc::new(Config {
        endpoint: SocketAddr::from((Ipv4Addr::LOCALHOST, 1)),
        pins: Vec::new(),
        member_port: 1,
        credentials: Arc::new(Mutex::new(None)),
    });
    let (low, high) = ("A".repeat(43) + "=", "/".repeat(43) + "w");
    let s = Arc::new(Session {
        cfg,
        name: "Q".repeat(43) + "=",
        names: HashMap::from([(high.clone(), g.ids[0].clone())]),
        was: String::new(),
        events,
        at: SocketAddr::from((Ipv4Addr::LOCALHOST, 1)),
        stop: AtomicBool::new(false),
        state: Mutex::new(SessionState::default()),
        conns: Mutex::new(HashMap::new()),
        threads: Mutex::new(Vec::new()),
    });
    assert!(s.note(Note { online: Some(vec!["relay".into()]), ..Note::default() }).is_err());
    assert!(s.note(Note { online: Some(vec!["0".repeat(32)]), ..Note::default() }).is_err(), "a device ID");
    assert!(s.note(Note { online: Some(vec![low.clone(); MAX_MEMBERS + 1]), ..Note::default() }).is_err());
    // A device with a lower name than this one's is not dialed.
    s.note(Note { online: Some(vec![low.clone()]), ..Note::default() }).unwrap();
    assert!(s.state.lock().unwrap().dialers.is_empty());
    assert_eq!(seen.last().unwrap().online, vec![low.clone()]);
    assert_eq!(s.device(&high), g.ids[0]);
    assert_eq!(s.device("x"), "x");
    // Calls not valid are dropped without a thread.
    s.note(Note { call: "bad".into(), ticket: "AAAAAAAAAAAAAAAAAAAAAA==".into(), ..Note::default() }).unwrap();
    s.note(Note { call: low.clone(), ticket: "bad".into(), ..Note::default() }).unwrap();
    s.note(Note::default()).unwrap();
    assert!(s.threads.lock().unwrap().is_empty());
    for _ in 0..MAX_CALLS {
        assert!(s.take_call());
    }
    assert!(!s.take_call());
    s.note(Note { call: low.clone(), ticket: "AAAAAAAAAAAAAAAAAAAAAA==".into(), ..Note::default() }).unwrap();
    assert!(s.threads.lock().unwrap().is_empty());
    s.state.lock().unwrap().calls = 0;
    // A call taken goes nowhere here: the relay's port is closed, and the
    // log says so.
    s.note(Note { call: low.clone(), ticket: "AAAAAAAAAAAAAAAAAAAAAA==".into(), ..Note::default() }).unwrap();
    assert!(wait_for(Duration::from_secs(10), || seen.logged("answering")), "{:?}", seen.logs.lock().unwrap());
    assert!(wait_for(Duration::from_secs(5), || s.state.lock().unwrap().calls == 0));
    // Once the session ended nothing more is held.
    s.end();
    let c = TcpStream::connect(("127.0.0.1", member_listener().1)).unwrap();
    assert!(s.hold(&c).is_err());
    assert!(s.credentials_changed(), "none now, a registration before");
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

/// Frames: a frame off the format's grid is an error, a partial one waits.
#[test]
fn frames_of_the_watch() {
    let mut inbox = vec![0xff, 0xff, 0xff, 0xff];
    assert!(take_frame(&mut inbox).is_err());
    let mut inbox = vec![0, 0, 0, 3, b'{'];
    assert!(take_frame(&mut inbox).is_err(), "off the grid");
    let mut inbox = vec![0, 0, 0, 64, 0xa1];
    assert_eq!(take_frame(&mut inbox).unwrap(), None);
    let mut inbox = vec![0, 0];
    assert_eq!(take_frame(&mut inbox).unwrap(), None);
    assert!(!valid_name(&"g".repeat(32)));
    assert!(!valid_name(&"0".repeat(32)));
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

/// A new period makes the link register again with it, on an open relay
/// and on one that serves the group; what does not verify is refused
/// before it reaches a relay.
#[test]
fn registers_again_for_a_new_period() {
    let g = Blind::new(2);
    for open in [true, false] {
        let groups = if open { Vec::new() } else { vec![g.listed()] };
        let (s, pins) = server(open, groups);
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let (a, b) = (Arc::new(Seen::default()), Arc::new(Seen::default()));
        let ca = config(&s, &pins, 1, Some(g.credentialed(0, 1)));
        let creds_a = ca.credentials.clone();
        let port = listener.local_addr().unwrap().port();
        let _ra = Relay::start(ca, a.clone());
        let _rb = Relay::start(config(&s, &pins, port, Some(g.credentialed(1, 1))), b.clone());
        assert!(
            wait_for(Duration::from_secs(20), || connected(&a, 1) && connected(&b, 1)),
            "open {open}: {:?} {:?} {:?}",
            a.last(),
            b.last(),
            a.logs.lock().unwrap()
        );
        *creds_a.lock().unwrap() = Some(g.credentialed(0, 2));
        assert!(wait_for(Duration::from_secs(20), || a.logged("credentials changed")), "{:?}", a.logs.lock().unwrap());
        assert!(wait_for(Duration::from_secs(20), || connected(&a, 1)), "{:?}", a.last());
    }
    // A members' credential that does not list the server key, a period
    // of another group, a pseudonym that is not one, too many.
    let now = u64::try_from(crate::nettest::now_ms()).unwrap();
    let [period, hubs, members] = g.credentials(1, &[1]);
    let creds = vec![hubs.clone(), members.clone()];
    let key = |i: usize| -> Arc<dyn crate::identity::ExternalKey> { g.servers[i].clone() };
    let make = |k, c: Vec<Vec<u8>>, p: Vec<u8>, root: Vec<u8>, names| Credentialed::new(k, c, p, root, names, now);
    assert!(make(key(0), creds.clone(), period.clone(), g.root(), HashMap::new()).is_err());
    assert!(make(key(1), creds.clone(), period.clone(), g.root(), HashMap::new()).is_ok());
    let other = Blind::new(1);
    let [other_period, ..] = other.credentials(1, &[0]);
    assert!(make(key(1), creds.clone(), other_period, g.root(), HashMap::new()).is_err());
    let bad = HashMap::from([("x".to_string(), g.ids[0].clone())]);
    assert!(make(key(1), creds.clone(), period.clone(), g.root(), bad).is_err());
    let many: HashMap<String, String> = (0..=MAX_NAMES as u64)
        .map(|i| {
            let mut n = [0u8; 32];
            n[..8].copy_from_slice(&i.to_be_bytes());
            (base64::Engine::encode(&base64::engine::general_purpose::STANDARD, n), g.ids[0].clone())
        })
        .collect();
    assert!(make(key(1), creds, period, g.root(), many).is_err());
}
