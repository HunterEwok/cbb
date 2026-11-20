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
fn run(a: (&mut RecordSet, &mut Exchange), b: (&mut RecordSet, &mut Exchange)) -> usize {
    let (sa, xa) = a;
    let (sb, xb) = b;
    // In flight: (to b?, frame).
    let mut q: VecDeque<(bool, Vec<u8>)> = VecDeque::new();
    q.push_back((true, hello(sa)));
    q.push_back((false, hello(sb)));
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
    run((&mut full, &mut xa), (&mut sb, &mut xb));
    assert_eq!(full.digest(), sb.digest());
    assert_eq!(sb.state().devices.len(), full.state().devices.len());

    // Equal sets: hellos only, and a want for nothing is never sent.
    let n = run((&mut full, &mut xa), (&mut sb, &mut xb));
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
    assert_eq!(run((&mut sa, &mut xa), (&mut sb, &mut xb)), 2);
    // The root writes on a; a's next hello carries the new digest.
    admit(&mut sa, &root, &c, "c", 3);
    let out = xb.take(&mut sb, &hello(&sa)[4..]).unwrap();
    assert_eq!(out.send.len(), 1, "b answers with its have");
    run((&mut sa, &mut xa), (&mut sb, &mut xb));
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
