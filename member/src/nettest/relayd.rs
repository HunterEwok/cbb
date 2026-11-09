// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The relay server against registrations made by hand: the settings it
//! refuses to start with, the certificates, claims, records and credentials
//! it refuses, and the requests in the tunnel it turns down.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream};
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use cbb_core::authority::Record;
use cbb_core::certs::{self, Cert, b64};
use cbb_core::credential::Credential;
use cbb_core::identity::{ExternalKey, FileKey};

use super::keys::Keys;
use super::limits::Limits;
use super::server::{self, Relay};
use super::wire::Note;
use crate::forward::{Registrar, prove};
use crate::nettest::{Group, new_key, now_ms, wait_for};
use crate::relay::{PROTOCOL, RELAY_ADDR};
use crate::tunnel::{self, Link, State};

const PROOF_LABEL: &[u8] = b"cbb relay key";

// The device's side of the messages, as member/src/relay.rs writes them,
// with every field open to the test.

#[derive(Deserialize)]
struct Challenge {
    #[serde(with = "b64")]
    e: Vec<u8>,
    #[serde(default)]
    roots: bool,
}

#[derive(Serialize, Clone)]
struct Claim {
    #[serde(with = "b64")]
    key: Vec<u8>,
    #[serde(with = "b64")]
    proof: Vec<u8>,
    records: Vec<Record>,
    credentials: Vec<Credential>,
    #[serde(with = "b64::list")]
    roots: Vec<Vec<u8>>,
}

#[derive(Deserialize, Debug, Default)]
struct Welcome {
    #[serde(default)]
    error: String,
    #[serde(with = "b64::opt", default)]
    key: Option<Vec<u8>>,
    #[serde(with = "b64::opt", default)]
    psk: Option<Vec<u8>>,
    #[serde(default)]
    addr: String,
}

#[derive(Serialize, Default)]
struct Request {
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    watch: bool,
    #[serde(skip_serializing_if = "String::is_empty")]
    dial: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    answer: String,
}

fn config(open: bool, groups: Vec<String>) -> server::Config {
    server::Config {
        listen: SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
        keys: Keys::new().unwrap(),
        groups,
        open,
        limits: Limits::default(),
        log: Arc::new(|_| {}),
        verbose: true,
    }
}

fn start(open: bool, groups: Vec<String>) -> (Relay, Vec<certs::KeyHash>) {
    let cfg = config(open, groups);
    let pin = Cert::parse(&cfg.keys.cert).unwrap().key_hash();
    (Relay::start(cfg).unwrap(), vec![pin])
}

/// A registration up to the relay's challenge.
struct Reg {
    reg: Registrar,
    ch: Challenge,
    proof_key: [u8; 32],
}

fn connect(s: &Relay, pins: &[certs::KeyHash], chain: &[Vec<u8>], key: &Arc<dyn ExternalKey>) -> crate::Result<Reg> {
    let mut reg = Registrar::connect(s.addr(), pins, chain, key, PROTOCOL, "relay")?;
    let proof_key = reg.export(PROOF_LABEL)?;
    let ch: Challenge = reg.read(&AtomicBool::new(false))?;
    Ok(Reg { reg, ch, proof_key })
}

impl Reg {
    /// A claim that proves wg.
    fn claim(&self, wg: &[u8; 32]) -> Claim {
        let (public, proof) = prove(wg, &self.ch.e, &self.proof_key).unwrap();
        Claim { key: public.to_vec(), proof, records: Vec::new(), credentials: Vec::new(), roots: Vec::new() }
    }

    fn send(mut self, c: &Claim) -> (Registrar, Welcome) {
        self.reg.write(c).unwrap();
        let w: Welcome = self.reg.read(&AtomicBool::new(false)).unwrap();
        (self.reg, w)
    }
}

fn wg() -> [u8; 32] {
    tunnel::new_key().unwrap().try_into().unwrap()
}

/// The device i of g registers with claim, made from a claim that proves a
/// fresh key; the relay's answer.
fn register(g: &Group, i: usize, s: &Relay, pins: &[certs::KeyHash], f: impl FnOnce(&mut Claim)) -> Welcome {
    let r = connect(s, pins, &g.chain(i), &g.key(i)).unwrap();
    let mut c = r.claim(&wg());
    f(&mut c);
    r.send(&c).1
}

#[track_caller]
fn refused(w: &Welcome, what: &str) {
    assert!(!w.error.is_empty() && w.error.contains(what), "{what:?}: {w:?}");
}

#[test]
fn settings_it_does_not_start_with() {
    let err = |open, groups: Vec<&str>| {
        Relay::start(config(open, groups.into_iter().map(String::from).collect())).err().unwrap().to_string()
    };
    assert!(err(true, vec!["0011223344556677"]).contains("serves every group"));
    assert!(err(false, vec![]).contains("no group to serve"));
    assert!(err(false, vec!["not a tag"]).contains("not a group's tag"));
    // A port taken.
    let (s, _) = start(true, Vec::new());
    let mut cfg = config(true, Vec::new());
    cfg.listen = s.addr();
    assert!(Relay::start(cfg).err().unwrap().to_string().contains("cannot listen"));
    assert!(!s.stopped());
}

/// What a claim may not be: a key of another length or of low order, a
/// proof of another key, too many records.
#[test]
fn claims_it_refuses() {
    let g = Group::new(1);
    let (s, pins) = start(true, Vec::new());
    refused(&register(&g, 0, &s, &pins, |c| c.key.truncate(31)), "not 32 bytes");
    refused(&register(&g, 0, &s, &pins, |c| c.key = vec![0; 32]), "not an X25519 key");
    let other = x25519_public(&wg());
    refused(&register(&g, 0, &s, &pins, |c| c.key = other.to_vec()), "does not hold that WireGuard key");
    let rec = g.records.all()[0].clone();
    refused(&register(&g, 0, &s, &pins, |c| c.records = vec![rec; 1025]), "too many records");
    // A claim that does not decode: the relay closes the connection.
    let mut r = connect(&s, &pins, &g.chain(0), &g.key(0)).unwrap();
    r.reg.write(&serde_json::json!({"key": 5})).unwrap();
    assert!(r.reg.read::<Welcome>(&AtomicBool::new(false)).is_err());
    // After all of them, the device registers.
    let w = register(&g, 0, &s, &pins, |_| {});
    assert!(w.error.is_empty(), "{w:?}");
    assert_eq!(w.key.map(|k| k.len()), Some(32));
}

fn x25519_public(k: &[u8; 32]) -> [u8; 32] {
    *gotatun::x25519::PublicKey::from(&gotatun::x25519::StaticSecret::from(*k)).as_bytes()
}

/// Two devices may not register the same WireGuard key; the relay of a
/// fixed list refuses a group it does not serve.
#[test]
fn a_key_taken_and_a_group_not_served() {
    let g = Group::new(2);
    let (s, pins) = start(true, Vec::new());
    let key = wg();
    let r = connect(&s, &pins, &g.chain(0), &g.key(0)).unwrap();
    let c = r.claim(&key);
    let (_keep, w) = r.send(&c);
    assert!(w.error.is_empty(), "{w:?}");
    let r = connect(&s, &pins, &g.chain(1), &g.key(1)).unwrap();
    let c = r.claim(&key);
    refused(&r.send(&c).1, "another device registered that WireGuard key");

    let other = Group::new(1);
    let (closed, pins) = start(false, vec![certs::tag(&other.root)]);
    let err = connect(&closed, &pins, &g.chain(0), &g.key(0)).err().unwrap().to_string();
    assert!(err.contains("closed") || err.contains("broke") || err.contains("answer"), "{err}");
}

/// Certificates that name no device of a group: a group CA as the device's
/// certificate, and a chain longer than any device has.
#[test]
fn certificates_it_refuses() {
    let g = Group::new(1);
    let (s, pins) = start(true, Vec::new());
    let root: Arc<dyn ExternalKey> = g.root_key.clone();
    assert!(connect(&s, &pins, &[g.root.der.clone()], &root).is_err());
    let mut long = g.chain(0);
    for _ in 0..9 {
        long.push(g.root.der.clone());
    }
    assert!(connect(&s, &pins, &long, &g.key(0)).is_err());
    // The relay still takes the device's own chain.
    assert!(register(&g, 0, &s, &pins, |_| {}).error.is_empty());
}

/// A device the group's records remove is refused, and so are records
/// that are not the group's.
#[test]
fn records_that_refuse() {
    let mut g = Group::new(3);
    let (s, pins) = start(true, Vec::new());
    let before = g.records.all().to_vec();
    // Device 2 registers while the records still hold it.
    let r = connect(&s, &pins, &g.chain(2), &g.key(2)).unwrap();
    let mut c = r.claim(&wg());
    c.records = before.clone();
    let (_two, w) = r.send(&c);
    assert!(w.error.is_empty(), "{w:?}");
    assert!(wait_for(Duration::from_secs(5), || s.stats().1 == 1));
    g.revoke(2);
    let records = g.records.all().to_vec();
    // Its own claim with the record that removes it is refused, and the
    // relay forgets the records a refused registration brought.
    refused(&register(&g, 2, &s, &pins, |c| c.records = records.clone()), "");
    // Device 1 brings them: the relay keeps them and drops device 2.
    let r = connect(&s, &pins, &g.chain(1), &g.key(1)).unwrap();
    let mut c = r.claim(&wg());
    c.records = records.clone();
    let (_one, w) = r.send(&c);
    assert!(w.error.is_empty(), "{w:?}");
    assert!(wait_for(Duration::from_secs(5), || s.stats().1 == 1), "{:?}", s.stats());
    // Device 2 is refused now without records of its own.
    refused(&register(&g, 2, &s, &pins, |_| {}), "");
    // Records of another group do not verify and change nothing.
    let other = Group::new(1);
    let theirs = other.records.all().to_vec();
    let w = register(&g, 0, &s, &pins, |c| c.records = theirs.clone());
    assert!(w.error.is_empty(), "{w:?}");
    refused(&register(&g, 2, &s, &pins, |_| {}), "");
}

/// A device that registers with the group's credentials: the server key's
/// certificate alone, and the credentials that must list it.
#[test]
fn credentials_it_refuses() {
    let g = Group::new(1);
    let server = new_key();
    let other = new_key();
    let creds = g.period(&[server.clone()], 1);
    let not_listed = g.period(&[other.clone()], 1);
    let cert = |k: &Arc<FileKey>| {
        certs::server_cert_by(&k.public(), &mut |tbs| crate::identity::sign_external(&**k, tbs)).unwrap()
    };
    let key: Arc<dyn ExternalKey> = server.clone();
    let with = |s: &Relay, pins: &[certs::KeyHash], f: &dyn Fn(&mut Claim)| {
        let r = connect(s, pins, &[cert(&server)], &key).unwrap();
        let mut c = r.claim(&wg());
        f(&mut c);
        r.send(&c).1
    };
    let (open, pins) = start(true, Vec::new());
    let pins_open = pins.clone();
    let listed: Vec<Credential> = creds[1..].to_vec();
    assert!(with(&open, &pins, &|c| c.credentials = listed.clone()).error.is_empty());
    refused(&with(&open, &pins, &|_| {}), "do not verify");
    refused(&with(&open, &pins, &|c| c.credentials = vec![creds[1].clone()]), "no members' credential");
    refused(&with(&open, &pins, &|c| c.credentials = not_listed[1..].to_vec()), "does not list this device");
    let mut bad = listed.clone();
    bad[1].body.push(b' ');
    refused(&with(&open, &pins, &|c| c.credentials = bad.clone()), "do not verify");

    // A relay of a fixed list wants the period credential and a root of a
    // group it serves.
    let (closed, pins) = start(false, vec![certs::tag(&g.root)]);
    let r = connect(&closed, &pins, &[cert(&server)], &key).unwrap();
    assert!(r.ch.roots, "a relay of a fixed list asks for the roots");
    assert!(!connect(&open, &pins_open, &[cert(&server)], &key).unwrap().ch.roots);
    refused(&with(&closed, &pins, &|c| c.credentials = listed.clone()), "no root of its group");
    let full = creds.to_vec();
    refused(&with(&closed, &pins, &|c| c.credentials = full.clone()), "not of a group this relay serves");
    let roots = vec![g.root.der.clone(); 9];
    refused(
        &with(&closed, &pins, &|c| {
            c.credentials = full.clone();
            c.roots = roots.clone();
        }),
        "no root of its group",
    );
    let stranger = Group::new(1);
    refused(
        &with(&closed, &pins, &|c| {
            c.credentials = full.clone();
            c.roots = vec![b"junk".to_vec(), stranger.root.der.clone()];
        }),
        "not of a group this relay serves",
    );
    let w = with(&closed, &pins, &|c| {
        c.credentials = full.clone();
        c.roots = vec![g.root.der.clone()];
    });
    assert!(w.error.is_empty(), "{w:?}");
}

/// A registered device's tunnel to the relay.
struct Tunneled {
    _reg: Registrar,
    link: Link,
}

fn tunneled(g: &Group, i: usize, s: &Relay, pins: &[certs::KeyHash]) -> Tunneled {
    let key = wg();
    let r = connect(s, pins, &g.chain(i), &g.key(i)).unwrap();
    let c = r.claim(&key);
    let (reg, w) = r.send(&c);
    assert!(w.error.is_empty(), "{w:?}");
    let hub = tunnel::Hub {
        device: "relay".into(),
        key: w.key.unwrap(),
        psk: w.psk.unwrap(),
        endpoints: vec![s.addr()],
        next: Vec::new(),
        obfuscation: None,
        vless: None,
    };
    let own: Ipv6Addr = w.addr.parse().unwrap();
    let link = Link::start_at(&State::with_key(&key).unwrap(), &hub, own, RELAY_ADDR, Arc::new(|_| {})).unwrap();
    Tunneled { _reg: reg, link }
}

impl Tunneled {
    /// Sends a request on a new connection through the tunnel, and the
    /// relay's first note on it.
    fn ask(&self, r: &Request) -> (TcpStream, Note) {
        let mut c = TcpStream::connect(self.link.local()).unwrap();
        c.set_read_timeout(Some(Duration::from_secs(15))).unwrap();
        super::wire::write_frame(&mut c, r, super::wire::MAX_LINE).unwrap();
        let f = super::wire::read_frame(&mut c, super::wire::MAX_LINE).unwrap();
        (c, note(&f))
    }
}

fn note(f: &[u8]) -> Note {
    let v: serde_json::Value = serde_json::from_slice(f).unwrap();
    let s = |k: &str| v.get(k).and_then(|x| x.as_str()).unwrap_or_default().to_string();
    Note {
        online: v.get("online").map(|o| serde_json::from_value(o.clone()).unwrap()),
        call: s("call"),
        ticket: s("ticket"),
        ok: v.get("ok").and_then(|x| x.as_bool()).unwrap_or(false),
        error: s("error"),
    }
}

/// The requests the relay turns down: none it knows, a dial to itself, to
/// a device not there or not listening, an answer to no call, and a call
/// left unanswered.
#[test]
fn requests_it_turns_down() {
    let mut g = Group::new(2);
    if g.id(0) > g.id(1) {
        g.devs.swap(0, 1);
    }
    let (s, pins) = start(true, Vec::new());
    let a = tunneled(&g, 0, &s, &pins);
    let b = tunneled(&g, 1, &s, &pins);
    assert_eq!(a.ask(&Request::default()).1.error, "an unknown request");
    let dial = |to: &str| Request { dial: to.into(), ..Request::default() };
    assert_eq!(a.ask(&dial(&g.id(0))).1.error, "that device is not on the relay");
    assert_eq!(a.ask(&dial("00112233445566778899aabbccddeeff")).1.error, "that device is not on the relay");
    assert_eq!(a.ask(&dial(&g.id(1))).1.error, "that device is not listening yet");
    let answer = Request { answer: "AAAAAAAAAAAAAAAAAAAAAA==".into(), ..Request::default() };
    assert_eq!(a.ask(&answer).1.error, "no such call");

    // b watches: it hears of a, and of a's call, which it leaves.
    let (mut w, first) = b.ask(&Request { watch: true, ..Request::default() });
    assert_eq!(first.online, Some(vec![g.id(0)]));
    let started = std::time::Instant::now();
    let caller = std::thread::spawn({
        let a = a.link.local();
        let to = g.id(1);
        move || {
            let mut c = TcpStream::connect(a).unwrap();
            c.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
            super::wire::write_frame(&mut c, &dial(&to), super::wire::MAX_LINE).unwrap();
            note(&super::wire::read_frame(&mut c, super::wire::MAX_LINE).unwrap())
        }
    });
    let call = note(&super::wire::read_frame(&mut w, super::wire::MAX_LINE).unwrap());
    assert_eq!(call.call, g.id(0));
    assert!(!call.ticket.is_empty());
    assert_eq!(caller.join().unwrap().error, "that device did not answer");
    assert!(started.elapsed() >= server::CALL_TIMEOUT - Duration::from_secs(1));
    // An answer too late finds no call.
    let late = Request { answer: call.ticket, ..Request::default() };
    assert_eq!(b.ask(&late).1.error, "no such call");
    drop(w);
    assert!(wait_for(Duration::from_secs(5), || s.stats().1 == 2));
    let _ = now_ms();
}
