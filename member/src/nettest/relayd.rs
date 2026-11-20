// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The relay server against registrations of `cbb-relay/3` made by hand:
//! the settings it refuses to start with, the certificates, claims and
//! credentials it refuses, the requests in the tunnel it turns down, the
//! groups it keeps apart, the devices a newer members' credential drops,
//! what a refused registration leaves, and its log, which names no device
//! and no address.

use std::io::Write;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream};
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use cbb_core::certs::{self, Cert};
use cbb_core::format::cbor::Value;
use cbb_core::format::frame;
use cbb_core::identity::ExternalKey;
use cbb_core::msg::tables as t;

use super::keys::Keys;
use super::limits::Limits;
use super::server::{self, Relay};
use super::wire::Note;
use super::wire3::{self, PROTOCOL, Register};
use crate::forward::{Registrar, prove};
use crate::nettest::blind::Blind;
use crate::nettest::{Group, wait_for};
use crate::relay::RELAY_ADDR;
use crate::tunnel::{self, Link, State};

const PROOF_LABEL: &[u8] = b"cbb relay key";

fn config(open: bool, groups: Vec<String>) -> server::Config {
    server::Config {
        listen: SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
        keys: Keys::new().unwrap(),
        groups,
        open,
        limits: Limits::default(),
        log: Arc::new(|_| {}),
        verbose: true,
        refused: None,
    }
}

fn start_with(cfg: server::Config) -> (Relay, Vec<certs::KeyHash>) {
    let pin = Cert::parse(&cfg.keys.cert).unwrap().key_hash();
    (Relay::start(cfg).unwrap(), vec![pin])
}

fn start(open: bool, groups: Vec<String>) -> (Relay, Vec<certs::KeyHash>) {
    start_with(config(open, groups))
}

fn msg(ty: u64, mut fields: Vec<(u16, Value<'_>)>) -> Vec<u8> {
    fields.insert(0, (frame::FIELD_T, Value::Uint(ty)));
    frame::write(&Value::Map(fields))
}

/// A registration up to the relay's challenge: its ephemeral key and
/// whether it asks for the period and the root.
struct Reg {
    reg: Registrar,
    e: Vec<u8>,
    root: bool,
    proof_key: [u8; 32],
}

/// The relay's last message: its keys and the tunnel address, or why it
/// refused.
type Welcome = Result<([u8; 32], [u8; 32], String), String>;

fn connect(s: &Relay, pins: &[certs::KeyHash], chain: &[Vec<u8>], key: &Arc<dyn ExternalKey>) -> crate::Result<Reg> {
    let mut reg = Registrar::connect(s.addr(), pins, chain, key, PROTOCOL, "relay")?.on_grid();
    let proof_key = reg.export(PROOF_LABEL)?;
    let body = reg.next_frame(&AtomicBool::new(false))?.unwrap();
    let (ty, v, _) = cbb_core::msg::read_noted(&body).unwrap();
    if ty == t::T_RELAY_ERROR {
        return Err(crate::Error::msg(v.get(2).and_then(Value::as_text).unwrap_or_default().to_string()));
    }
    assert_eq!(ty, t::T_RELAY_CHALLENGE);
    let e = v.get(2).and_then(Value::as_bytes).unwrap().to_vec();
    Ok(Reg { reg, e, root: v.get(3).and_then(Value::as_uint) == Some(1), proof_key })
}

/// Device i of g, by its server key's certificate.
fn connect_as(g: &Blind, i: usize, s: &Relay, pins: &[certs::KeyHash]) -> Reg {
    let key: Arc<dyn ExternalKey> = g.servers[i].clone();
    connect(s, pins, &[g.servers[i].cert().unwrap()], &key).unwrap()
}

impl Reg {
    /// A claim that proves wg, with the credentials creds.
    fn claim(&self, wg: &[u8; 32], creds: &[Vec<u8>], root: Option<Vec<u8>>) -> Register {
        let (public, proof) = prove(wg, &self.e, &self.proof_key).unwrap();
        Register { key: public, proof: proof.try_into().unwrap(), credentials: creds.to_vec(), root }
    }

    fn send_raw(mut self, frame: &[u8]) -> (Registrar, Welcome) {
        self.reg.send(frame).unwrap();
        let w = match self.reg.next_frame(&AtomicBool::new(false)) {
            Ok(Some(body)) => {
                let (ty, v, _) = cbb_core::msg::read_noted(&body).unwrap();
                if ty == t::T_RELAY_ERROR {
                    Err(v.get(2).and_then(Value::as_text).unwrap_or_default().to_string())
                } else {
                    let key = cbb_core::format::Key::from_value(v.get(2).unwrap()).unwrap();
                    Ok((
                        key.public.try_into().unwrap(),
                        v.get(3).and_then(Value::as_bytes).unwrap().try_into().unwrap(),
                        v.get(4).and_then(Value::as_text).unwrap().to_string(),
                    ))
                }
            }
            Ok(None) => Err("no answer".into()),
            Err(e) => Err(format!("closed: {e}")),
        };
        (self.reg, w)
    }

    fn send(self, c: &Register) -> (Registrar, Welcome) {
        self.send_raw(&c.write())
    }
}

fn wg() -> [u8; 32] {
    tunnel::new_key().unwrap().try_into().unwrap()
}

/// The hubs' and members' credentials of g at version 1, every device
/// listed, and the period credential.
fn creds(g: &Blind) -> (Vec<Vec<u8>>, Vec<u8>) {
    let [period, hubs, members] = g.credentials(1, &(0..g.servers.len()).collect::<Vec<_>>());
    (vec![hubs, members], period)
}

/// Device i of g registers with credentials on an open relay, with a
/// fresh key; the relay's answer.
fn register(g: &Blind, i: usize, s: &Relay, pins: &[certs::KeyHash], f: impl FnOnce(&mut Register)) -> Welcome {
    let r = connect_as(g, i, s, pins);
    let mut c = r.claim(&wg(), &creds(g).0, None);
    f(&mut c);
    r.send(&c).1
}

#[track_caller]
fn refused(w: &Welcome, what: &str) {
    assert!(w.as_ref().is_err_and(|e| e.contains(what)), "{what:?}: {w:?}");
}

#[test]
fn settings_it_does_not_start_with() {
    let err = |open, groups: Vec<String>| Relay::start(config(open, groups)).err().unwrap().to_string();
    assert!(err(true, vec![Blind::new(1).listed()]).contains("serves every group"));
    assert!(err(false, vec![]).contains("no group to serve"));
    assert!(err(false, vec!["0011223344556677".into()]).contains("is not a group of 0.6"), "a tag of 0.5");
    // A port taken.
    let (s, _) = start(true, Vec::new());
    let mut cfg = config(true, Vec::new());
    cfg.listen = s.addr();
    assert!(Relay::start(cfg).err().unwrap().to_string().contains("cannot listen"));
    assert!(!s.stopped());
}

/// What a claim may not be: a key of low order, a proof of another key,
/// no credentials, a message that is not a claim.
#[test]
fn claims_it_refuses() {
    let g = Blind::new(1);
    let (s, pins) = start(true, Vec::new());
    refused(&register(&g, 0, &s, &pins, |c| c.key = [0; 32]), "not an X25519 key");
    let other = x25519_public(&wg());
    refused(&register(&g, 0, &s, &pins, |c| c.key = other), "does not hold that WireGuard key");
    refused(&register(&g, 0, &s, &pins, |c| c.credentials.clear()), "breaks");
    let r = connect_as(&g, 0, &s, &pins);
    refused(&r.send_raw(&msg(t::T_RELAY_WATCH, vec![])).1, "not a claim");
    // After all of them, the device registers.
    let w = register(&g, 0, &s, &pins, |_| {});
    assert!(w.is_ok(), "{w:?}");
}

fn x25519_public(k: &[u8; 32]) -> [u8; 32] {
    *gotatun::x25519::PublicKey::from(&gotatun::x25519::StaticSecret::from(*k)).as_bytes()
}

/// Two devices may not register the same WireGuard key; the relay of a
/// list refuses a group it does not serve.
#[test]
fn a_key_taken_and_a_group_not_served() {
    let g = Blind::new(2);
    let (s, pins) = start(true, Vec::new());
    let key = wg();
    let (cs, _) = creds(&g);
    let r = connect_as(&g, 0, &s, &pins);
    let c = r.claim(&key, &cs, None);
    let (_keep, w) = r.send(&c);
    assert!(w.is_ok(), "{w:?}");
    let r = connect_as(&g, 1, &s, &pins);
    let c = r.claim(&key, &cs, None);
    refused(&r.send(&c).1, "another device registered that WireGuard key");

    let (closed, pins) = start(false, vec![Blind::new(1).listed()]);
    let r = connect_as(&g, 0, &closed, &pins);
    assert!(r.root);
    let (cs, period) = creds(&g);
    let mut all = cs.clone();
    all.push(period);
    let c = r.claim(&wg(), &all, Some(g.root()));
    refused(&r.send(&c).1, "not of a group this relay serves");
}

/// What the device shows in its TLS: the certificate of its server key
/// alone, which is no CA's.
#[test]
fn certificates_it_refuses() {
    let g = Blind::new(1);
    let (s, pins) = start(true, Vec::new());
    let old = Group::new(1);
    let root: Arc<dyn ExternalKey> = old.root_key.clone();
    let alone = "show the certificate of your server key alone";
    let e = connect(&s, &pins, std::slice::from_ref(&old.root.der), &root).err().unwrap().to_string();
    assert!(e.contains(alone), "a CA: {e}");
    let key: Arc<dyn ExternalKey> = g.servers[0].clone();
    let two = vec![g.servers[0].cert().unwrap(), old.root.der.clone()];
    let e = connect(&s, &pins, &two, &key).err().unwrap().to_string();
    assert!(e.contains(alone), "a chain: {e}");
    // The relay still takes the server key's own certificate.
    assert!(register(&g, 0, &s, &pins, |_| {}).is_ok());
}

/// The credentials must list the device and be the group's; a relay of a
/// list wants the period credential and the root that signed it; a group
/// takes no credentials older than ones the relay saw.
#[test]
fn credentials_it_refuses() {
    let g = Blind::new(2);
    let (open, pins_open) = start(true, Vec::new());
    let [_, hubs, only_one] = g.credentials(1, &[1]);
    refused(&register(&g, 0, &open, &pins_open, |c| c.credentials = vec![hubs.clone()]), "no members' credential");
    refused(
        &register(&g, 0, &open, &pins_open, |c| c.credentials = vec![hubs.clone(), only_one.clone()]),
        "does not list this device",
    );
    let other = Blind::new(1);
    let [_, their_hubs, _] = other.credentials(1, &[0]);
    let (cs, period) = creds(&g);
    refused(&register(&g, 0, &open, &pins_open, |c| c.credentials[0] = their_hubs.clone()), "do not verify");
    let mut bad = cs[1].clone();
    let n = bad.len();
    bad[n - 1] ^= 1;
    refused(&register(&g, 0, &open, &pins_open, |c| c.credentials[1] = bad.clone()), "do not verify");
    // Version 2 seen, version 1 is older.
    let [_, h2, m2] = g.credentials(2, &[0, 1]);
    let (_two, w) = {
        let r = connect_as(&g, 1, &open, &pins_open);
        let c = r.claim(&wg(), &[h2, m2], None);
        r.send(&c)
    };
    assert!(w.is_ok(), "{w:?}");
    refused(&register(&g, 0, &open, &pins_open, |_| {}), "older than ones this relay saw");

    // A relay of a list asks for the period credential and the root.
    let (closed, pins) = start(false, vec![g.listed()]);
    assert!(connect_as(&g, 0, &closed, &pins).root, "a relay of a list asks for the root");
    assert!(!connect_as(&g, 0, &open, &pins_open).root);
    let send = |cs: &[Vec<u8>], root: Option<Vec<u8>>| {
        let r = connect_as(&g, 0, &closed, &pins);
        let c = r.claim(&wg(), cs, root);
        r.send(&c).1
    };
    refused(&send(&cs, Some(g.root())), "no root of its group");
    let mut all = cs.clone();
    all.push(period.clone());
    refused(&send(&all, None), "not of a group this relay serves");
    refused(&send(&all, Some(other.root())), "not of a group this relay serves");
    let w = send(&all, Some(g.root()));
    assert!(w.is_ok(), "{w:?}");
}

/// A registered device's tunnel to the relay.
struct Tunneled {
    _reg: Registrar,
    link: Link,
}

fn tunneled_by(g: &Blind, i: usize, s: &Relay, pins: &[certs::KeyHash], cs: &[Vec<u8>]) -> Tunneled {
    let key = wg();
    let r = connect_as(g, i, s, pins);
    let c = r.claim(&key, cs, None);
    let (reg, w) = r.send(&c);
    let (relay_key, psk, addr) = w.unwrap();
    let hub = tunnel::Hub {
        device: "relay".into(),
        key: relay_key.to_vec(),
        psk: psk.to_vec(),
        endpoints: vec![s.addr()],
        next: Vec::new(),
        obfuscation: None,
        vless: None,
        next_obfuscation: None,
        next_vless: None,
    };
    let own: Ipv6Addr = addr.parse().unwrap();
    let link = Link::start_at(&State::with_key(&key).unwrap(), &hub, own, RELAY_ADDR, Arc::new(|_| {})).unwrap();
    Tunneled { _reg: reg, link }
}

fn tunneled(g: &Blind, i: usize, s: &Relay, pins: &[certs::KeyHash]) -> Tunneled {
    tunneled_by(g, i, s, pins, &creds(g).0)
}

fn read_note(c: &mut TcpStream) -> Note {
    let (_, body) = wire3::read(c, super::wire::MAX_LINE).unwrap();
    let (ty, v, _) = cbb_core::msg::read_noted(&body).unwrap();
    let b64 = |b: &[u8]| base64::Engine::encode(&base64::engine::general_purpose::STANDARD, b);
    let bytes = |n| v.get(n).and_then(Value::as_bytes).map(b64).unwrap_or_default();
    match ty {
        t::T_RELAY_ONLINE => Note {
            online: Some(
                v.get(2).and_then(Value::as_array).unwrap_or(&[]).iter().filter_map(Value::as_bytes).map(b64).collect(),
            ),
            ..Note::default()
        },
        t::T_RELAY_CALL => Note { call: bytes(2), ticket: bytes(3), ..Note::default() },
        t::T_RELAY_OK => Note { ok: true, ..Note::default() },
        t::T_RELAY_ERROR => Note::error(v.get(2).and_then(Value::as_text).unwrap_or_default()),
        _ => panic!("a note of type {ty}"),
    }
}

fn unb64(s: &str) -> Vec<u8> {
    base64::Engine::decode(&base64::engine::general_purpose::STANDARD, s).unwrap()
}

fn dial(to: &str) -> Vec<u8> {
    msg(t::T_RELAY_DIAL, vec![(2, Value::Bytes(&unb64(to)))])
}

fn answer(ticket: &str) -> Vec<u8> {
    msg(t::T_RELAY_ANSWER, vec![(2, Value::Bytes(&unb64(ticket)))])
}

fn watch() -> Vec<u8> {
    msg(t::T_RELAY_WATCH, vec![])
}

impl Tunneled {
    /// Sends a request on a new connection through the tunnel, and the
    /// relay's first note on it.
    fn ask(&self, r: &[u8]) -> (TcpStream, Note) {
        let mut c = TcpStream::connect(self.link.local()).unwrap();
        c.set_read_timeout(Some(Duration::from_secs(15))).unwrap();
        c.write_all(r).unwrap();
        let n = read_note(&mut c);
        (c, n)
    }
}

/// The requests the relay turns down: none it knows, a dial to itself, to
/// a device not there or not listening, an answer to no call, and a call
/// left unanswered.
#[test]
fn requests_it_turns_down() {
    let g = Blind::new(2);
    let (s, pins) = start(true, Vec::new());
    let a = tunneled(&g, 0, &s, &pins);
    let b = tunneled(&g, 1, &s, &pins);
    assert_eq!(a.ask(&msg(t::T_RELAY_OK, vec![])).1.error, "an unknown request");
    assert_eq!(a.ask(&dial(&g.name(0))).1.error, "that device is not on the relay");
    assert_eq!(a.ask(&dial(&("A".repeat(43) + "="))).1.error, "that device is not on the relay");
    assert_eq!(a.ask(&dial(&g.name(1))).1.error, "that device is not listening yet");
    assert_eq!(a.ask(&answer("AAAAAAAAAAAAAAAAAAAAAA==")).1.error, "no such call");

    // b watches: it hears of a, and of a's call, which it leaves.
    let (mut w, first) = b.ask(&watch());
    assert_eq!(first.online, Some(vec![g.name(0)]));
    let started = std::time::Instant::now();
    let caller = std::thread::spawn({
        let a = a.link.local();
        let to = dial(&g.name(1));
        move || {
            let mut c = TcpStream::connect(a).unwrap();
            c.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
            c.write_all(&to).unwrap();
            read_note(&mut c)
        }
    });
    let call = read_note(&mut w);
    assert_eq!(call.call, g.name(0));
    assert!(!call.ticket.is_empty());
    assert_eq!(caller.join().unwrap().error, "that device did not answer");
    assert!(started.elapsed() >= server::CALL_TIMEOUT - Duration::from_secs(1));
    // An answer too late finds no call.
    assert_eq!(b.ask(&answer(&call.ticket)).1.error, "no such call");
    drop(w);
    assert!(wait_for(Duration::from_secs(5), || s.stats().1 == 2));
}

/// A device that asks the relay to join it to an address, not to a device
/// of its group, reaches nothing: a dial names a pseudonym of 32 bytes,
/// and the relay only joins two of a group's registered devices, never
/// dialing anywhere.
#[test]
fn a_dial_reaches_no_address() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let hits = Arc::new(AtomicUsize::new(0));
    let ln = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let addr = ln.local_addr().unwrap().to_string();
    std::thread::spawn({
        let hits = hits.clone();
        move || {
            for c in ln.incoming() {
                if c.is_err() {
                    return;
                }
                hits.fetch_add(1, Ordering::SeqCst);
            }
        }
    });
    let g = Blind::new(1);
    let (s, pins) = start(true, Vec::new());
    let a = tunneled(&g, 0, &s, &pins);
    for to in [addr.as_str(), "1.1.1.1:443", "example.com:443", "[::1]:22"] {
        let as_text = msg(t::T_RELAY_DIAL, vec![(2, Value::Text(to))]);
        let as_bytes = msg(t::T_RELAY_DIAL, vec![(2, Value::Bytes(to.as_bytes()))]);
        for r in [as_text, as_bytes] {
            // The relay turns it down, or closes a request the format
            // does not take.
            let mut c = TcpStream::connect(a.link.local()).unwrap();
            c.set_read_timeout(Some(Duration::from_secs(15))).unwrap();
            c.write_all(&r).unwrap();
            if let Ok((_, body)) = wire3::read(&mut c, super::wire::MAX_LINE) {
                let (ty, v, _) = cbb_core::msg::read_noted(&body).unwrap();
                assert_eq!(ty, t::T_RELAY_ERROR, "a dial to {to}");
                assert!(v.get(2).and_then(Value::as_text).is_some_and(|w| !w.is_empty()), "a dial to {to}");
            }
        }
    }
    assert_eq!(hits.load(Ordering::SeqCst), 0, "a connection reached an address a device asked for");
}

/// Two groups on one open relay: a device of one hears only of its own
/// group and cannot dial a device of the other.
#[test]
fn groups_apart() {
    let (one, two) = (Blind::new(1), Blind::new(1));
    let (s, pins) = start(true, Vec::new());
    let a = tunneled(&one, 0, &s, &pins);
    let b = tunneled(&two, 0, &s, &pins);
    assert_eq!(s.stats(), (2, 2));
    let (_w, first) = a.ask(&watch());
    assert_eq!(first.online, Some(vec![]), "nobody else of its group");
    assert_eq!(a.ask(&dial(&two.name(0))).1.error, "that device is not on the relay");
    assert_eq!(b.ask(&dial(&one.name(0))).1.error, "that device is not on the relay");
}

/// A newer members' credential that leaves a device out drops it from the
/// relay, and the device cannot come back with the older one.
#[test]
fn a_device_left_out_goes() {
    let g = Blind::new(3);
    let (s, pins) = start(true, Vec::new());
    let _a = tunneled(&g, 0, &s, &pins);
    let _c = tunneled(&g, 2, &s, &pins);
    assert!(wait_for(Duration::from_secs(5), || s.stats().1 == 2));
    let [_, h2, m2] = g.credentials(2, &[0, 1]);
    let _b = tunneled_by(&g, 1, &s, &pins, &[h2, m2]);
    assert!(wait_for(Duration::from_secs(5), || s.stats().1 == 2), "{:?}", s.stats());
    refused(&register(&g, 2, &s, &pins, |_| {}), "older than ones this relay saw");
}

/// A refused registration leaves the relay as it was: no group, device or
/// period of it.
#[test]
fn a_refused_registration_leaves_nothing() {
    let g = Blind::new(2);
    let (s, pins) = start(true, Vec::new());
    let [_, hubs, only_one] = g.credentials(1, &[1]);
    refused(&register(&g, 0, &s, &pins, |c| c.credentials = vec![hubs, only_one]), "does not list this device");
    let st = s.inner().lock();
    assert!(st.groups.is_empty() && st.by_addr.is_empty() && st.periods.is_empty() && st.members.is_empty());
}

/// The relay's log, verbose included, names no device and no address of
/// one, through registrations, refusals and a call.
#[test]
fn its_log_names_no_device() {
    let lines = Arc::new(Mutex::new(Vec::<String>::new()));
    let mut cfg = config(true, Vec::new());
    cfg.log = {
        let lines = lines.clone();
        Arc::new(move |l: &str| lines.lock().unwrap().push(l.to_string()))
    };
    let (s, pins) = start_with(cfg);
    let g = Blind::new(2);
    let a = tunneled(&g, 0, &s, &pins);
    let b = tunneled(&g, 1, &s, &pins);
    let (_w, _) = b.ask(&watch());
    let _ = a.ask(&dial(&g.name(1)));
    let [_, hubs, only_one] = g.credentials(1, &[1]);
    refused(&register(&g, 0, &s, &pins, |c| c.credentials = vec![hubs, only_one]), "");
    drop((a, b));
    drop(s);
    let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
    for l in lines.lock().unwrap().iter() {
        assert!(!l.contains("127.0.0.1"), "an address: {l}");
        for i in 0..2 {
            let name = g.name(i);
            let h = hex(&unb64(&name));
            assert!(!l.contains(&name) && !l.contains(&h) && !l.contains(&g.ids[i]), "a device: {l}");
        }
    }
}
