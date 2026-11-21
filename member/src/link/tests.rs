// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

use std::collections::VecDeque;

use cbb_core::identity::ExternalKey;
use cbb_core::records::body::{self, Device};
use cbb_core::records::{Key, Kind, Recovery, key::ALG_SLH_DSA, pq};
use p256::ecdsa::SigningKey;
use p256::ecdsa::signature::hazmat::PrehashSigner as _;

use super::*;

/// A P-256 key made from fixed bytes, signing as a device's key does.
struct K(SigningKey);

impl K {
    fn new(n: u8) -> K {
        K(SigningKey::from_slice(&[n; 32]).unwrap())
    }
    fn point(&self) -> [u8; 65] {
        self.0.verifying_key().to_sec1_point(false).as_bytes().try_into().unwrap()
    }
    fn key(&self) -> Key {
        Key::es256(self.point().to_vec())
    }
}

impl ExternalKey for K {
    fn public(&self) -> Vec<u8> {
        self.point().to_vec()
    }
    fn sign_digest(&self, digest: &[u8; 32]) -> cbb_core::error::Result<Vec<u8>> {
        let sig: p256::ecdsa::Signature = self.0.sign_prehash(digest).unwrap();
        Ok(sig.to_der().as_bytes().to_vec())
    }
}

fn empty(root: &K) -> RecordSet {
    let (k1, k2) = pq::recovery_keys(&[1; 32]).unwrap();
    let k1 = SigningKey::from(&k1).verifying_key().to_sec1_point(false).as_bytes().to_vec();
    RecordSet::new(root.key(), Recovery::new(Key::es256(k1), Key::new(ALG_SLH_DSA, k2.public())).unwrap())
}

/// The root writes a device record for key.
fn admit(set: &mut RecordSet, root: &K, key: &K, name: &str, time_ms: u64) {
    let mut d = Device::new(key.key(), name, body::ROLE_MEMBER);
    d.rights = body::RIGHT_READ | body::RIGHT_SEND | body::RIGHT_SECRETS;
    let state = set.state();
    set.write_record(&state, root, Kind::device(d), time_ms).unwrap();
}

/// Runs both sides until nothing is in flight: each opens with its hello
/// and sends one again after every change. Returns how many messages went.
fn settle(a: (&mut RecordSet, &mut Exchange), b: (&mut RecordSet, &mut Exchange)) -> usize {
    let opening = vec![(true, hello(a.0)), (false, hello(b.0))];
    flow(a, b, opening)
}

/// Runs both sides from the frames in flight (to b?, frame) until
/// nothing is: each sends its hello again after every change.
fn flow(
    a: (&mut RecordSet, &mut Exchange),
    b: (&mut RecordSet, &mut Exchange),
    opening: Vec<(bool, Vec<u8>)>,
) -> usize {
    let (sa, xa) = a;
    let (sb, xb) = b;
    let mut q: VecDeque<(bool, Vec<u8>)> = opening.into();
    let mut n = 0;
    while let Some((to_b, f)) = q.pop_front() {
        n += 1;
        assert!(n < 10_000, "the exchange does not settle");
        frame::read(&f, frame::LIMIT_MEMBER).unwrap();
        let (set, x) = if to_b { (&mut *sb, &mut *xb) } else { (&mut *sa, &mut *xa) };
        let out = x.take(set, &f[4..]).unwrap();
        assert!(out.stuck.is_none());
        for s in out.send {
            q.push_back((!to_b, s));
        }
        if out.changed {
            q.push_back((!to_b, hello(set)));
        }
    }
    n
}

#[test]
fn two_members_end_with_the_same_set() {
    let (root, a, b, c) = (K::new(1), K::new(2), K::new(3), K::new(4));
    let mut full = empty(&root);
    admit(&mut full, &root, &a, "a", 1);
    admit(&mut full, &root, &b, "b", 2);
    // b holds what the root wrote up to its own admission.
    let mut sb = empty(&root);
    let recs: Vec<Record> = full.in_dependency_order().into_iter().cloned().collect();
    sb.take_part(&recs, &[]);
    admit(&mut full, &root, &c, "c", 3);
    assert_ne!(full.digest(), sb.digest());

    let mut xa = Exchange::new(a.key().hash(), b.point());
    let mut xb = Exchange::new(b.key().hash(), a.point());
    settle((&mut full, &mut xa), (&mut sb, &mut xb));
    assert_eq!(full.digest(), sb.digest());
    assert_eq!(sb.state().devices.len(), full.state().devices.len());

    // Equal sets: hellos only, and a want for nothing is never sent.
    let n = settle((&mut full, &mut xa), (&mut sb, &mut xb));
    assert_eq!(n, 2);
}

#[test]
fn a_record_written_while_connected_reaches_the_peer() {
    let (root, a, b, c) = (K::new(1), K::new(2), K::new(3), K::new(4));
    let mut sa = empty(&root);
    admit(&mut sa, &root, &a, "a", 1);
    admit(&mut sa, &root, &b, "b", 2);
    let mut sb = empty(&root);
    let recs: Vec<Record> = sa.in_dependency_order().into_iter().cloned().collect();
    sb.take_part(&recs, &[]);
    let mut xa = Exchange::new(a.key().hash(), b.point());
    let mut xb = Exchange::new(b.key().hash(), a.point());
    assert_eq!(settle((&mut sa, &mut xa), (&mut sb, &mut xb)), 2);
    // The root writes on a; a's next hello carries the new digest.
    admit(&mut sa, &root, &c, "c", 3);
    let out = xb.take(&mut sb, &hello(&sa)[4..]).unwrap();
    assert_eq!(out.send.len(), 1, "b answers with its have");
    // Only a's hello goes: b says nothing new of itself, and a answers b's
    // have with its own.
    let opening = out.send.into_iter().map(|f| (false, f)).collect();
    flow((&mut sa, &mut xa), (&mut sb, &mut xb), opening);
    assert_eq!(sa.digest(), sb.digest());
}

#[test]
fn a_stranger_gets_no_records() {
    let (root, a, b, stranger) = (K::new(1), K::new(2), K::new(3), K::new(9));
    let mut sa = empty(&root);
    admit(&mut sa, &root, &a, "a", 1);
    admit(&mut sa, &root, &b, "b", 2);
    let mut xa = Exchange::new(a.key().hash(), stranger.point());
    // A stranger asks for every record a holds by ID.
    let ids: Vec<RecordId> = sa.ids().copied().collect();
    let mut out = Out::default();
    want(&ids, None, &mut out);
    let asked = xa.take(&mut sa, &out.send[0][4..]).unwrap();
    for f in &asked.send {
        let (_, v, _) = cbb_core::msg::read_noted(&f[4..]).unwrap();
        let (records, _) = welcome::read_part(&v).unwrap();
        assert!(records.is_empty(), "a stranger was given {} records", records.len());
    }
}

#[test]
fn the_rounds_are_bounded() {
    let (root, a, b) = (K::new(1), K::new(2), K::new(3));
    let mut sa = empty(&root);
    admit(&mut sa, &root, &a, "a", 1);
    let mut xa = Exchange::new(a.key().hash(), b.point());
    // A peer that keeps saying it holds another set.
    let other = empty(&root);
    let mut stuck = 0;
    for _ in 0..MAX_ROUNDS + 3 {
        let out = xa.take(&mut sa, &hello(&other)[4..]).unwrap();
        stuck += usize::from(out.stuck.is_some());
    }
    assert_eq!(stuck, 1);
}

#[test]
fn a_bad_message_is_an_error() {
    let (root, a, b) = (K::new(1), K::new(2), K::new(3));
    let mut sa = empty(&root);
    let mut xa = Exchange::new(a.key().hash(), b.point());
    assert!(xa.take(&mut sa, b"not cbor").is_err());
    // A want of nothing breaks its table.
    assert!(xa.take(&mut sa, &write(m::T_WANT, Vec::new())[4..]).is_err());
    // A message this exchange does not read goes to the caller.
    assert_eq!(xa.take(&mut sa, &write(m::T_PING, Vec::new())[4..]).unwrap().other, Some(m::T_PING));
}

/// Two members over TCP with TLS by key: each judges the other by its
/// standing in its own set, and the exchange runs on the TLS stream until
/// both sets are equal.
#[test]
fn two_members_sync_over_tls_by_key() {
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use cbb_core::alpn;
    use cbb_core::tls::Session;
    use cbb_core::tls::bykey;

    let (root, a, b, c) = (K::new(1), K::new(2), K::new(3), K::new(4));
    let mut sa = empty(&root);
    admit(&mut sa, &root, &a, "a", 1);
    admit(&mut sa, &root, &b, "b", 2);
    let mut sb = empty(&root);
    let recs: Vec<Record> = sa.in_dependency_order().into_iter().cloned().collect();
    sb.take_part(&recs, &[]);
    admit(&mut sa, &root, &c, "c", 3);
    let want = sa.digest();

    let pkcs8 = |n: u8| {
        use p256::pkcs8::EncodePrivateKey as _;
        SigningKey::from_slice(&[n; 32]).unwrap().to_pkcs8_der().unwrap().as_bytes().to_vec()
    };
    let judge = |set: Arc<Mutex<RecordSet>>, own: KeyHash| {
        bykey::by_standing(move |p| standing(&set.lock().unwrap().state(), &own, p), false)
    };
    let sa = Arc::new(Mutex::new(sa));
    let sb = Arc::new(Mutex::new(sb));
    let clock = crate::tls::clock();
    let scfg = bykey::server(
        &bykey::OwnKey::pkcs8(&pkcs8(2)).unwrap(),
        judge(sa.clone(), a.key().hash()),
        alpn::MEMBER,
        &clock,
    )
    .unwrap();
    let ccfg = bykey::client(
        &bykey::OwnKey::pkcs8(&pkcs8(3)).unwrap(),
        Some(cbb_core::format::Key::new(cbb_core::format::Alg::Es256, &a.point()).hash().id()),
        judge(sb.clone(), b.key().hash()),
        alpn::MEMBER,
        &clock,
    )
    .unwrap();

    let ln = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = ln.local_addr().unwrap();
    let (a_hash, a_point) = (a.key().hash(), a.point());
    let server = {
        let sa = sa.clone();
        std::thread::spawn(move || {
            let (sock, _) = ln.accept().unwrap();
            sock.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
            let mut s = Session::server(Arc::new(scfg)).unwrap();
            crate::tls::handshake(&mut s, &sock, "the handshake").unwrap();
            let peer = bykey::peer_key(s.peer_certificates()).unwrap();
            let mut x = Exchange::new(a_hash, peer);
            let mut stream = crate::tls::Stream::new(s, sock);
            run(&mut stream, &mut x, &sa, &mut |_| {}, &mut |_, _| {}, &mut |l| panic!("{l}"));
        })
    };
    let sock = std::net::TcpStream::connect(addr).unwrap();
    sock.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    let mut s = Session::client(Arc::new(ccfg), bykey::unsent_name()).unwrap();
    crate::tls::handshake(&mut s, &sock, "the handshake").unwrap();
    let peer = bykey::peer_key(s.peer_certificates()).unwrap();
    assert_eq!(peer, a_point);
    let mut x = Exchange::new(b.key().hash(), peer);
    let mut stream = crate::tls::Stream::new(s, sock);
    let mut saved = 0;
    // The connection ends when the reads time out, the sets settled.
    run(&mut stream, &mut x, &sb, &mut |_| saved += 1, &mut |_, _| {}, &mut |l| panic!("{l}"));
    drop(stream);
    server.join().unwrap();
    assert!(saved >= 1);
    assert_eq!(sb.lock().unwrap().digest(), want);
}

/// A key the set does not know is refused in the handshake.
#[test]
fn a_stranger_is_refused_in_the_handshake() {
    use std::sync::{Arc, Mutex};

    use cbb_core::alpn;
    use cbb_core::tls::Session;
    use cbb_core::tls::bykey;

    let (root, a) = (K::new(1), K::new(2));
    let mut sa = empty(&root);
    admit(&mut sa, &root, &a, "a", 1);
    let sa = Arc::new(Mutex::new(sa));
    let pkcs8 = |n: u8| {
        use p256::pkcs8::EncodePrivateKey as _;
        SigningKey::from_slice(&[n; 32]).unwrap().to_pkcs8_der().unwrap().as_bytes().to_vec()
    };
    let own = a.key().hash();
    let set = sa.clone();
    let judge = bykey::by_standing(move |p| standing(&set.lock().unwrap().state(), &own, p), false);
    let clock = crate::tls::clock();
    let scfg = bykey::server(&bykey::OwnKey::pkcs8(&pkcs8(2)).unwrap(), judge, alpn::MEMBER, &clock).unwrap();
    let ccfg =
        bykey::client(&bykey::OwnKey::pkcs8(&pkcs8(9)).unwrap(), None, bykey::any_key(), alpn::MEMBER, &clock).unwrap();
    let ln = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = ln.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        let (sock, _) = ln.accept().unwrap();
        let mut s = Session::server(Arc::new(scfg)).unwrap();
        crate::tls::handshake(&mut s, &sock, "the handshake").is_err()
    });
    let sock = std::net::TcpStream::connect(addr).unwrap();
    let mut s = Session::client(Arc::new(ccfg), bykey::unsent_name()).unwrap();
    let _ = crate::tls::handshake(&mut s, &sock, "the handshake");
    assert!(server.join().unwrap(), "the server took a stranger");
}

/// An admin's record reaches the root while they stay connected, after an
/// earlier round in which the admin had sent its have already: the root
/// answers the admin's new hello with its have, and the admin, holding
/// more than that hello's sender, sends its own again.
#[test]
fn an_admins_record_reaches_the_root_on_a_kept_connection() {
    let (root, kr, kd, ad, kp) = (K::new(1), K::new(2), K::new(3), K::new(4), K::new(5));
    let mut sr = empty(&root);
    let mut d = Device::new(kr.key(), "r", body::ROLE_MEMBER);
    d.rights = body::RIGHT_READ | body::RIGHT_SEND | body::RIGHT_SECRETS;
    d.holds_root = true;
    let st = sr.state();
    sr.write_record(&st, &root, Kind::device(d), 1).unwrap();
    admit(&mut sr, &root, &kd, "d", 2);
    let mut sd = empty(&root);
    let recs: Vec<Record> = sr.in_dependency_order().into_iter().cloned().collect();
    sd.take_part(&recs, &[]);
    let mut xr = Exchange::new(kr.key().hash(), kd.point());
    let mut xd = Exchange::new(kd.key().hash(), kr.point());
    assert_eq!(settle((&mut sr, &mut xr), (&mut sd, &mut xd)), 2);
    // The root makes d an admin; its hello brings d the record.
    let st = sr.state();
    let mut rec = Device::new(kd.key(), "d", body::ROLE_MEMBER);
    rec.rights = body::RIGHT_READ | body::RIGHT_SEND | body::RIGHT_SECRETS;
    rec.admin = Some(ad.key());
    (rec.powers, rec.commands) = body::AdminKind::Computer.grants();
    sr.write_record(&st, &root, Kind::device(rec), 3).unwrap();
    let h = hello(&sr);
    flow((&mut sr, &mut xr), (&mut sd, &mut xd), vec![(true, h)]);
    assert_eq!(sr.digest(), sd.digest());
    // d writes as an admin, twice; only its hello goes each time.
    let st = sd.state();
    sd.write_record(&st, &ad, Kind::Copies { incoming_ms: 30_000, seen: Vec::new() }, 4).unwrap();
    let h = hello(&sd);
    flow((&mut sr, &mut xr), (&mut sd, &mut xd), vec![(false, h)]);
    assert_eq!(sr.digest(), sd.digest(), "the root takes the admin's first record");
    let mut dp = Device::new(kp.key(), "p", body::ROLE_MEMBER);
    dp.rights = body::RIGHT_READ | body::RIGHT_SEND;
    let st = sd.state();
    sd.write_record(&st, &ad, Kind::device(dp), 5).unwrap();
    let h = hello(&sd);
    flow((&mut sr, &mut xr), (&mut sd, &mut xd), vec![(false, h)]);
    assert_eq!(sr.digest(), sd.digest(), "the root takes the admin's second record");
    assert!(sr.state().device(&kp.key().device_id()).is_some());
}

/// A change of root by the recovery key reaches a member on a kept
/// connection: the recovery record, its list and the new root's first
/// records, which wait for the list.
#[test]
fn a_change_of_root_reaches_a_member() {
    let (root, kd, kl, new_root) = (K::new(1), K::new(3), K::new(4), K::new(6));
    let mut sd = empty(&root);
    admit(&mut sd, &root, &kd, "d", 1);
    admit(&mut sd, &root, &kl, "l", 2);
    let mut sl = empty(&root);
    let recs: Vec<Record> = sd.in_dependency_order().into_iter().cloned().collect();
    sl.take_part(&recs, &[]);
    let mut xd = Exchange::new(kd.key().hash(), kl.point());
    let mut xl = Exchange::new(kl.key().hash(), kd.point());
    assert_eq!(settle((&mut sd, &mut xd), (&mut sl, &mut xl)), 2);
    let (k1, k2) = pq::recovery_keys(&[1; 32]).unwrap();
    let k1 = K(SigningKey::from(&k1));
    let st = sd.state();
    let mut me = Device::new(kd.key(), "d", body::ROLE_MEMBER);
    me.rights = body::RIGHT_READ | body::RIGHT_SEND | body::RIGHT_SECRETS;
    me.holds_root = true;
    sd.write_change(&st, &k1, &k2, &new_root, me, &[], false, 3).unwrap();
    let h = hello(&sd);
    flow((&mut sd, &mut xd), (&mut sl, &mut xl), vec![(true, h)]);
    assert_eq!(sd.digest(), sl.digest());
    assert_eq!(sl.state().roots.last(), Some(&new_root.key().hash()));
}
