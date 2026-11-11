// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The scenarios of the model of the record rules (docs/model/records-v3.qnt)
//! run against the core: the same devices, records and waits, so that the
//! model and the code are seen to agree on them. The model's names: R the
//! first root, A a phone admin, C a computer admin, K the recovery key, D a
//! device, NA and NK the new roots A and K would name; m is a member that
//! only syncs.

use std::collections::BTreeMap;

use cbb_core::certs::sha256;
use cbb_core::identity::ExternalKey;
use cbb_core::records::body::{
    AdminKind, DEFAULT_DELAY_MS, Device, RIGHT_READ, RIGHT_SEND, ROLE_MEMBER, ROLE_PHONE, Removal, Seen,
};
use cbb_core::records::eval::{ClaimState, Stop};
use cbb_core::records::{Body, Key, KeyHash, Kind, Record, RecordId, RecordSet, State};
use p256::ecdsa::SigningKey;
use p256::ecdsa::signature::hazmat::PrehashSigner as _;

/// A key made from a name, so that a scenario replays exactly.
struct K {
    sk: SigningKey,
    key: Key,
    hash: KeyHash,
}

impl ExternalKey for K {
    fn public(&self) -> Vec<u8> {
        self.key.public.clone()
    }
    fn sign_digest(&self, digest: &[u8; 32]) -> cbb_core::error::Result<Vec<u8>> {
        let sig: p256::ecdsa::Signature = self.sk.sign_prehash(digest).unwrap();
        Ok(sig.to_der().as_bytes().to_vec())
    }
}

fn k(name: &str) -> K {
    let sk = SigningKey::from_slice(&sha256(format!("model {name}").as_bytes())).unwrap();
    let key = Key::es256(sk.verifying_key().to_sec1_point(false).as_bytes().to_vec());
    let hash = key.hash();
    K { sk, key, hash }
}

/// The model's group: R made A a phone admin, C a computer admin and K the
/// recovery key. Each key's records follow on by seq and prev.
struct Group {
    root: K,
    heads: BTreeMap<KeyHash, (u64, RecordId)>,
    recs: Vec<Record>,
}

impl Group {
    fn new() -> Group {
        let mut g = Group { root: k("R"), heads: BTreeMap::new(), recs: Vec::new() };
        for (member, admin, kind) in [("A phone", "A", AdminKind::Phone), ("C computer", "C", AdminKind::Computer)] {
            let mut d = Device::new(k(member).key, member, ROLE_PHONE);
            d.rights = RIGHT_READ | RIGHT_SEND;
            d.admin = Some(k(admin).key);
            (d.powers, d.commands) = kind.grants();
            g.sign("R", Kind::Device(d));
        }
        g.sign("R", Kind::Recovery { admin: k("K").key });
        g
    }

    /// What the signer's device holds: here, every record so far.
    fn seen(&self) -> Vec<Seen> {
        self.heads.iter().map(|(k, (s, _))| Seen { key: *k, seq: *s }).collect()
    }

    fn sign(&mut self, by: &str, kind: Kind) -> Record {
        let by = k(by);
        let (seq, prev) = match self.heads.get(&by.hash) {
            Some((s, id)) => (s + 1, Some(*id)),
            None => (1, None),
        };
        let body = Body { group: self.root.key.device_id(), signer: by.hash, seq, prev, time_ms: 0, kind, held: false };
        let r = Record::sign(body, &by).unwrap();
        self.heads.insert(by.hash, (seq, r.id()));
        self.recs.push(r.clone());
        r
    }

    fn claim(&mut self, by: &str, root: &str) -> Record {
        let seen = self.seen();
        self.sign(by, Kind::Claim { root: k(root).key, seen })
    }

    fn revoke(&mut self, by: &str, key: &str) -> Record {
        let seen = self.seen();
        self.sign(by, Kind::Revoke(Removal { keys: vec![k(key).hash], seen }))
    }

    fn device(&mut self, by: &str) -> Record {
        let mut d = Device::new(k("D").key, "D", ROLE_MEMBER);
        d.rights = RIGHT_READ | RIGHT_SEND;
        self.sign(by, Kind::Device(d))
    }

    /// Member m: a set that took these records one by one, in this order.
    fn member(&self, recs: &[&Record]) -> RecordSet {
        let mut set = RecordSet::new(self.root.key.clone());
        set.insert_all(recs.iter().map(|r| (*r).clone()));
        set
    }
}

fn claim_state(s: &State, r: &Record) -> Option<ClaimState> {
    s.claims.iter().find(|c| c.record == r.id()).map(|c| c.state)
}

/// The member has held each of these claims for ms.
fn held(claims: &[&Record], ms: u64) -> BTreeMap<RecordId, u64> {
    claims.iter().map(|c| (c.id(), ms)).collect()
}

/// recoveryKeyTakesOverTest: the claim waits out the delay as the member
/// itself held it, then the new root takes over.
#[test]
fn recovery_key_takes_over() {
    let mut g = Group::new();
    let c = g.claim("K", "NK");
    let m = g.member(&g.recs.iter().collect::<Vec<_>>());
    let s = m.state(&held(&[&c], DEFAULT_DELAY_MS - 1));
    assert_eq!(claim_state(&s, &c), Some(ClaimState::Pending));
    assert_eq!(s.roots, vec![g.root.hash]);
    let s = m.state(&held(&[&c], DEFAULT_DELAY_MS));
    assert_eq!(claim_state(&s, &c), Some(ClaimState::Effective));
    assert_eq!(s.roots, vec![g.root.hash, k("NK").hash]);
}

/// computerCannotTakeOverTest: a computer admin's claim never counts.
#[test]
fn a_computer_cannot_take_over() {
    let mut g = Group::new();
    let c = g.claim("C", "NK");
    let m = g.member(&g.recs.iter().collect::<Vec<_>>());
    let s = m.state(&held(&[&c], u64::MAX));
    assert_eq!(claim_state(&s, &c), Some(ClaimState::Void));
    assert_eq!(s.roots, vec![g.root.hash]);
    assert_eq!(s.stop, Stop::None);
}

/// competingClaimsStopTest: two claims stop the group; the root's records
/// still count, and its resolve ends the stop.
#[test]
fn competing_claims_stop_and_the_root_resolves() {
    let mut g = Group::new();
    // Neither claimant holds the other's claim.
    let seen = g.seen();
    let ca = g.sign("A", Kind::Claim { root: k("NA").key, seen: seen.clone() });
    let ck = g.sign("K", Kind::Claim { root: k("NK").key, seen });
    let h = held(&[&ca, &ck], DEFAULT_DELAY_MS);
    let s = g.member(&g.recs.iter().collect::<Vec<_>>()).state(&h);
    assert_eq!(s.stop, Stop::Full);
    assert_eq!(
        (claim_state(&s, &ca), claim_state(&s, &ck)),
        (Some(ClaimState::Competing), Some(ClaimState::Competing))
    );
    g.device("R");
    g.revoke("R", "D");
    let s = g.member(&g.recs.iter().collect::<Vec<_>>()).state(&h);
    assert_eq!(s.stop, Stop::Full);
    assert!(s.revoked.contains(&k("D").hash));
    g.sign("R", Kind::Resolve(vec![ca.id()]));
    let s = g.member(&g.recs.iter().collect::<Vec<_>>()).state(&h);
    assert_eq!(s.stop, Stop::None);
    assert_eq!(
        (claim_state(&s, &ca), claim_state(&s, &ck)),
        (Some(ClaimState::Cancelled), Some(ClaimState::Effective))
    );
    assert_eq!(s.roots, vec![g.root.hash, k("NK").hash]);
}

/// objectionDisputesTest: a phone admin that had not seen a claim removes
/// the claimant; the claim is disputed and the group stops.
#[test]
fn an_objection_disputes_a_claim() {
    let mut g = Group::new();
    // A signs before it gets the claim: its seen leaves the claim out.
    let seen = g.seen();
    let c = g.claim("K", "NK");
    let objection = g.sign("A", Kind::Revoke(Removal { keys: vec![k("K").hash], seen }));
    let m = g.member(&g.recs.iter().collect::<Vec<_>>());
    let s = m.state(&held(&[&c], DEFAULT_DELAY_MS));
    assert!(s.counting.contains(&objection.id()));
    assert_eq!(claim_state(&s, &c), Some(ClaimState::Disputed));
    assert_eq!(s.stop, Stop::Full);
    assert_eq!(s.roots, vec![g.root.hash]);
}

/// removedDeviceStaysOutTest: a new record for a removed device's key does
/// not bring it back.
#[test]
fn a_removed_device_stays_out() {
    let mut g = Group::new();
    g.device("R");
    g.revoke("R", "D");
    g.device("R");
    let s = g.member(&g.recs.iter().collect::<Vec<_>>()).state(&BTreeMap::new());
    assert!(s.revoked.contains(&k("D").hash));
    assert!(s.device_by_key(&k("D").hash).is_none());
    assert!(s.id_taken(&k("D").key.device_id()));
}

/// claimedRootRoomTest: a claimed root keeps only what its claim paid ahead
/// until the claim counts and the member gives it a root's room.
#[test]
fn a_claimed_root_keeps_what_its_claim_paid() {
    let mut g = Group::new();
    let c = g.claim("K", "NK");
    // More than the 16 units paid ahead.
    let news: Vec<Record> = (0..20).map(|_| g.device_by_new_root()).collect();
    let mut m = g.member(&g.recs.iter().collect::<Vec<_>>());
    let kept = news.iter().filter(|r| m.contains(&r.id())).count();
    assert!(kept > 0 && kept <= 16, "{kept}");
    let h = held(&[&c], DEFAULT_DELAY_MS);
    let s = m.state(&h);
    assert_eq!(s.roots, vec![g.root.hash, k("NK").hash]);
    m.compact(&s);
    m.insert_all(news.iter().cloned());
    assert!(news.iter().all(|r| m.contains(&r.id())));
}

impl Group {
    /// NK, the root K's claim names, admits a device of its own.
    fn device_by_new_root(&mut self) -> Record {
        let n = self.recs.len();
        let mut d = Device::new(k(&format!("NK device {n}")).key, "NK device", ROLE_MEMBER);
        d.rights = RIGHT_READ | RIGHT_SEND;
        self.sign("NK", Kind::Device(d))
    }
}

/// The model's first promise on one case: the members that got the same
/// records in other orders keep the same set and have the same state.
#[test]
fn any_order_gives_one_state() {
    let mut g = Group::new();
    let ca = g.claim("A", "NA");
    g.device("C");
    g.revoke("R", "D");
    g.sign("NA", Kind::Copies { incoming_ms: 5_000 });
    let ck = g.claim("K", "NK");
    g.sign("R", Kind::Resolve(vec![ca.id()]));
    let h = held(&[&ca, &ck], DEFAULT_DELAY_MS);
    let all: Vec<&Record> = g.recs.iter().collect();
    let mut rev = all.clone();
    rev.reverse();
    let mut odd: Vec<&Record> = all.iter().copied().skip(1).step_by(2).collect();
    odd.extend(all.iter().copied().step_by(2));
    let sets: Vec<RecordSet> = [all, rev, odd].iter().map(|order| g.member(order)).collect();
    for s in &sets[1..] {
        assert_eq!(s.digest(), sets[0].digest());
        assert_eq!(s.state(&h), sets[0].state(&h));
    }
}
