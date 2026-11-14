// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! Members by their keys, both ends in memory over the sans-I/O session.

use std::sync::{Arc, Mutex};

use rustls::NamedGroup;
use rustls::pki_types::UnixTime;
use rustls::time_provider::TimeProvider;

use super::*;
use crate::alpn;
use crate::identity::new_key;
use crate::records::Key as RKey;
use crate::records::State;
use crate::records::eval::DeviceState;
use crate::tls::Session;

#[derive(Debug)]
struct SystemClock;

impl TimeProvider for SystemClock {
    fn current_time(&self) -> Option<UnixTime> {
        Some(UnixTime::now())
    }
}

fn clock() -> Clock {
    Arc::new(SystemClock)
}

fn own() -> OwnKey {
    OwnKey::pkcs8(&new_key().unwrap()).unwrap()
}

/// Moves the bytes between two sessions until neither has any to send, and
/// returns everything that went over the wire, each way.
fn shuttle(a: &mut Session, b: &mut Session) -> (Vec<u8>, Vec<u8>) {
    let (mut ab, mut ba) = (Vec::new(), Vec::new());
    loop {
        let (x, y) = (a.take_outgoing(), b.take_outgoing());
        if x.is_empty() && y.is_empty() {
            return (ab, ba);
        }
        ab.extend_from_slice(&x);
        ba.extend_from_slice(&y);
        if b.feed(&x).is_err() || a.feed(&y).is_err() {
            return (ab, ba);
        }
    }
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

fn device(key: &OwnKey) -> DeviceState {
    let k = RKey::es256(key.point().to_vec());
    DeviceState {
        id: k.device_id(),
        key: k,
        name: "laptop".into(),
        role: crate::records::body::ROLE_MEMBER,
        rights: 3,
        skip: 0,
        caps: 0,
        os: 1,
        store: 1,
        proof: 0,
        admin: None,
        powers: 0,
        commands: 0,
        frozen: false,
        replaces: None,
        guarded: false,
        by_root: true,
    }
}

fn pair(a: &OwnKey, b: &OwnKey, expect: Option<DeviceId>, ja: Judge, jb: Judge) -> (Session, Session) {
    let c = client(a, expect, ja, alpn::MEMBER, &clock()).unwrap();
    let s = server(b, jb, alpn::MEMBER, &clock()).unwrap();
    (Session::client(Arc::new(c), unsent_name()).unwrap(), Session::server(Arc::new(s)).unwrap())
}

#[test]
fn members_by_their_keys() {
    let (a, b) = (own(), own());
    let want = Key::new(Alg::Es256, b.point()).device_id();
    let (mut c, mut s) = pair(&a, &b, Some(want), any_key(), any_key());
    let (up, down) = shuttle(&mut c, &mut s);
    assert!(!c.is_handshaking() && !s.is_handshaking());
    assert_eq!(c.alpn_protocol(), Some(alpn::MEMBER));
    assert_eq!(c.kx_group(), Some(NamedGroup::X25519MLKEM768));
    assert_eq!(s.kx_group(), Some(NamedGroup::X25519MLKEM768));
    assert_eq!(peer_key(c.peer_certificates()), Some(*b.point()));
    assert_eq!(peer_key(s.peer_certificates()), Some(*a.point()));

    // What a relay sees: no server name, no key, no device ID, no name.
    for wire in [&up, &down] {
        for k in [&a, &b] {
            let key = Key::new(Alg::Es256, k.point());
            assert!(!contains(wire, k.point()), "a key in the clear");
            assert!(!contains(wire, &key.device_id().0), "a device ID in the clear");
            assert!(!contains(wire, &key.hash().0), "a key hash in the clear");
        }
        assert!(!contains(wire, b"cbb.invalid"), "a server name");
        assert!(!contains(wire, b"\x06\x03\x55\x04\x03"), "a certificate name in the clear");
    }
    assert!(!has_sni(&up), "the client hello has a server name extension");

    c.write(b"hello").unwrap();
    shuttle(&mut c, &mut s);
    let mut buf = [0u8; 16];
    assert_eq!(s.read(&mut buf), 5);
}

/// Reports whether a TLS client hello (the first record of `wire`) carries
/// the server_name extension.
fn has_sni(wire: &[u8]) -> bool {
    // record header 5, handshake header 4, version 2, random 32
    let mut i = 5 + 4 + 2 + 32;
    let sid = usize::from(wire[i]);
    i += 1 + sid;
    let suites = usize::from(u16::from_be_bytes([wire[i], wire[i + 1]]));
    i += 2 + suites;
    let comp = usize::from(wire[i]);
    i += 1 + comp;
    let end = i + 2 + usize::from(u16::from_be_bytes([wire[i], wire[i + 1]]));
    i += 2;
    while i + 4 <= end {
        let t = u16::from_be_bytes([wire[i], wire[i + 1]]);
        let n = usize::from(u16::from_be_bytes([wire[i + 2], wire[i + 3]]));
        if t == 0 {
            return true;
        }
        i += 4 + n;
    }
    false
}

#[test]
fn falls_back_to_x25519_without_a_retry() {
    let (a, b) = (own(), own());
    // A server whose provider has X25519 alone, as a peer of today.
    let mut p = provider();
    p.kx_groups.retain(|g| g.name() == NamedGroup::X25519);
    let mut scfg = rustls::ServerConfig::builder_with_details(Arc::new(p), clock())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_client_cert_verifier(Arc::new(DialerVerifier { judge: any_key() }))
        .with_cert_resolver(Arc::new(OneCert(b.certified())));
    scfg.alpn_protocols = vec![alpn::MEMBER.to_vec()];
    let c = client(&a, None, any_key(), alpn::MEMBER, &clock()).unwrap();
    let mut c = Session::client(Arc::new(c), unsent_name()).unwrap();
    let mut s = Session::server(Arc::new(scfg)).unwrap();
    let first = c.take_outgoing();
    s.feed(&first).unwrap();
    let answer = s.take_outgoing();
    // A HelloRetryRequest is a ServerHello with this fixed random.
    let hrr = [
        0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91, 0xc2, 0xa2,
        0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
    ];
    assert!(!contains(&answer, &hrr), "the server asked again");
    c.feed(&answer).unwrap();
    shuttle(&mut c, &mut s);
    assert!(!c.is_handshaking() && !s.is_handshaking());
    assert_eq!(c.kx_group(), Some(NamedGroup::X25519));
}

#[test]
fn another_device_than_dialed_is_refused() {
    let (a, b, other) = (own(), own(), own());
    let want = Key::new(Alg::Es256, other.point()).device_id();
    let (mut c, mut s) = pair(&a, &b, Some(want), any_key(), any_key());
    shuttle(&mut c, &mut s);
    assert!(c.is_handshaking() || s.is_handshaking(), "the handshake must not finish");
}

#[test]
fn an_ordinary_certificate_is_refused() {
    let b = own();
    let key = new_key().unwrap();
    let cert =
        crate::certs::self_signed(&crate::certs::DeviceId::random(), &crate::identity::signing_key(&key).unwrap())
            .unwrap();
    let (ccfg, _) = crate::tls::pair_client(&cert, &key, &clock()).unwrap();
    let mut ccfg = ccfg;
    ccfg.alpn_protocols = vec![alpn::MEMBER.to_vec()];
    let mut c = Session::client(Arc::new(ccfg), unsent_name()).unwrap();
    let mut s = Session::server(Arc::new(server(&b, any_key(), alpn::MEMBER, &clock()).unwrap())).unwrap();
    shuttle(&mut c, &mut s);
    assert!(s.is_handshaking(), "the server must refuse an ordinary certificate");
}

#[test]
fn the_records_judge() {
    let (me, laptop, gone, cold, stranger) = (own(), own(), own(), own(), own());
    let mut state = State::default();
    let mut frozen = device(&cold);
    frozen.frozen = true;
    let mut devices = vec![device(&me), device(&laptop), frozen];
    devices.sort_by_key(|x| x.id);
    state.devices = devices;
    let gone_key = RKey::es256(gone.point().to_vec());
    state.revoked.push(gone_key.hash());
    state.named.insert(gone_key.device_id());
    for d in &state.devices {
        state.named.insert(d.id);
    }
    let mine = me.hash();
    assert_eq!(
        standing(&state, &mine, laptop.point()),
        Standing::Member(Key::new(Alg::Es256, laptop.point()).device_id())
    );
    assert_eq!(standing(&state, &mine, me.point()), Standing::Refused("connected to itself"));
    assert_eq!(standing(&state, &mine, gone.point()), Standing::Refused("removed from the group"));
    assert_eq!(standing(&state, &mine, cold.point()), Standing::Refused("frozen"));
    assert_eq!(standing(&state, &mine, stranger.point()), Standing::Unknown);

    // Over TLS: a removed device does not get through; a member does.
    let shared = Arc::new(Mutex::new(state));
    let judge = |unknown_ok| {
        let st = shared.clone();
        by_standing(move |p| standing(&st.lock().unwrap(), &mine, p), unknown_ok)
    };
    for (peer, ok) in [(&laptop, true), (&gone, false), (&cold, false), (&stranger, false)] {
        let (mut c, mut s) = pair(peer, &me, None, any_key(), judge(false));
        shuttle(&mut c, &mut s);
        assert_eq!(!s.is_handshaking() && !c.is_handshaking(), ok);
    }
    let (mut c, mut s) = pair(&stranger, &me, None, any_key(), judge(true));
    shuttle(&mut c, &mut s);
    assert!(!s.is_handshaking(), "an unknown key gets through to send its intro");
}

#[test]
fn the_tunnel_key_comes_from_the_connection_with_each_hub() {
    use crate::hubkey;
    let (dev, hub, hub2) = (own(), own(), own());
    let id = |k: &OwnKey| Key::new(Alg::Es256, k.point()).device_id();
    let psk_with = |h: &OwnKey| {
        let (c, cx) = exporting_client(client(&dev, None, any_key(), alpn::MEMBER, &clock()).unwrap());
        let (s, sx) = exporting_server(server(h, any_key(), alpn::MEMBER, &clock()).unwrap());
        let mut c = Session::client(Arc::new(c), unsent_name()).unwrap();
        let mut s = Session::server(Arc::new(s)).unwrap();
        shuttle(&mut c, &mut s);
        let ctx = hubkey::context(&id(h), &id(&dev));
        let (mut a, mut b) = ([0u8; 32], [0u8; 32]);
        cx.export(hubkey::EXPORTER_LABEL, &ctx, &mut a).unwrap();
        sx.export(hubkey::EXPORTER_LABEL, &ctx, &mut b).unwrap();
        assert_eq!(a, b, "both ends export one secret");
        assert!(hubkey::hybrid(c.kx_group()), "the connection's key exchange is the hybrid one");
        hubkey::psk(&a, hubkey::hybrid(c.kx_group())).unwrap().key
    };
    let (p1, p1_again, p2) = (psk_with(&hub), psk_with(&hub), psk_with(&hub2));
    assert_ne!(p1, p1_again, "a new connection, a new key");
    assert_ne!(p1, p2, "each hub its own");
}

/// A pairing session of 0.6 takes the exporter labelled
/// `EXPERIMENTAL-cbb-pair-v3`, both ends the same; it differs from 0.5's
/// label of the same session, and a member session gives none.
#[test]
fn a_pairing_session_takes_the_v3_exporter() {
    let (a, b) = (own(), own());
    let session = |name: &[u8]| {
        let (c, cx) = exporting_client(client(&a, None, any_key(), name, &clock()).unwrap());
        let (s, sx) = exporting_server(server(&b, any_key(), name, &clock()).unwrap());
        let mut c = Session::client(Arc::new(c), unsent_name()).unwrap();
        let mut s = Session::server(Arc::new(s)).unwrap();
        assert!(pairing_exporter(&c, &cx).is_err(), "none before the handshake ends");
        shuttle(&mut c, &mut s);
        (c, cx, s, sx)
    };
    let (c, cx, s, sx) = session(alpn::PAIR);
    assert_eq!(c.alpn_protocol(), Some(alpn::PAIR));
    let ours = pairing_exporter(&c, &cx).unwrap();
    assert_eq!(pairing_exporter(&s, &sx).unwrap(), ours, "both ends export one value");
    let mut by_hand = [0u8; 32];
    cx.export(b"EXPERIMENTAL-cbb-pair-v3", &[], &mut by_hand).unwrap();
    assert_eq!(by_hand, ours);
    let mut v2 = [0u8; 32];
    cx.export(crate::pair::EXPORTER_LABEL, &[], &mut v2).unwrap();
    assert_ne!(v2, ours, "0.5's label gives another value of the same session");
    let (c, cx, _, _) = session(alpn::MEMBER);
    assert!(pairing_exporter(&c, &cx).is_err(), "a member session is no pairing session");
}
