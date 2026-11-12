// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The scenarios of the model of the record rules (docs/model/records-v3.qnt)
//! run against the core: the same devices, records and waits, so that the
//! model and the code are seen to agree on them. The model's names: R the
//! first root, A a phone admin, C a computer admin, W a watch admin (the
//! member keys of their devices "A phone", "C computer", "W watch"), K the
//! recovery key, D a device, NA and NK the new roots A and K would name, X a
//! key a claimed root names; m is a member that only syncs.

use std::collections::{BTreeMap, BTreeSet};

use cbb_core::certs::sha256;
use cbb_core::identity::ExternalKey;
use cbb_core::records::body::{
    AdminKind, DEFAULT_DELAY_MS, Device, Head, RIGHT_READ, RIGHT_SEND, ROLE_MEMBER, ROLE_PHONE, Removal, Seen,
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

/// The model's group: R made A a phone admin, C a computer admin, W a watch
/// admin and K the recovery key. Each key's records follow on by seq and
/// prev.
struct Group {
    root: K,
    heads: BTreeMap<KeyHash, (u64, RecordId)>,
    recs: Vec<Record>,
}

impl Group {
    fn new() -> Group {
        let mut g = Group { root: k("R"), heads: BTreeMap::new(), recs: Vec::new() };
        for (member, admin, kind) in [
            ("A phone", "A", AdminKind::Phone),
            ("C computer", "C", AdminKind::Computer),
            ("W watch", "W", AdminKind::Watch),
        ] {
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
        self.heads.iter().map(|(k, (s, id))| Seen { key: *k, seq: *s, id: *id }).collect()
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
    g.sign("NA", Kind::Copies { incoming_ms: 5_000, seen: vec![] });
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

/// removalsByAdminAndRootTest: the root's resolve voids an admin's removal,
/// and the device counts again under its old key and ID; a root's removal is
/// final, and its resolve changes nothing.
#[test]
fn an_admins_removal_is_not_final_a_roots_is() {
    let mut g = Group::new();
    g.device("C");
    let rm = g.revoke("C", "D");
    let s = g.member(&g.recs.iter().collect::<Vec<_>>()).state(&BTreeMap::new());
    assert!(s.device_by_key(&k("D").hash).is_none() && s.revoked.contains(&k("D").hash));
    g.sign("R", Kind::Resolve(vec![rm.id()]));
    let s = g.member(&g.recs.iter().collect::<Vec<_>>()).state(&BTreeMap::new());
    let d = s.device_by_key(&k("D").hash).expect("the device counts again");
    assert_eq!(d.id, k("D").key.device_id());
    assert!(!s.revoked.contains(&k("D").hash) && !s.counting.contains(&rm.id()));
    let root_rm = g.revoke("R", "D");
    g.sign("R", Kind::Resolve(vec![root_rm.id()]));
    let s = g.member(&g.recs.iter().collect::<Vec<_>>()).state(&BTreeMap::new());
    assert!(s.device_by_key(&k("D").hash).is_none() && s.revoked.contains(&k("D").hash));
}

impl Group {
    /// The signer signs a second record at the seq of its newest one.
    fn sign_twin(&mut self, by: &str, kind: Kind) -> Record {
        let by = k(by);
        let (seq, head) = self.heads[&by.hash];
        let prev = self.recs.iter().find(|r| r.id() == head).and_then(|r| r.body().prev);
        let body = Body { group: self.root.key.device_id(), signer: by.hash, seq, prev, time_ms: 0, kind, held: false };
        let r = Record::sign(body, &by).unwrap();
        self.recs.push(r.clone());
        r
    }

    fn freeze(&mut self, by: &str, key: &str, seen: Vec<Seen>) -> Record {
        self.sign(by, Kind::Freeze(Removal { keys: vec![k(key).hash], seen }))
    }

    /// A checkpoint of the signer: every key's head so far, keeping every
    /// record that counts in state.
    fn checkpoint(&mut self, by: &str, state: &State) -> Record {
        let heads = self.heads.iter().map(|(k, (s, id))| Head { key: *k, seq: *s, id: *id }).collect();
        let keep = state.counting.iter().copied().collect();
        self.sign(by, Kind::Checkpoint { heads, keep })
    }

    fn all(&self) -> Vec<&Record> {
        self.recs.iter().collect()
    }
}

/// A member that took every record so far and counted these claims.
fn counting_member(g: &Group, counted: &[&Record]) -> RecordSet {
    let mut m = g.member(&g.all());
    m.remember_counted(counted.iter().map(|c| c.id())).unwrap();
    m
}

/// countedTakeoverStaysTest: a takeover the member counted stays; neither
/// the old root's late resolve of the claim nor a later claim of another
/// admin undoes it.
#[test]
fn a_counted_takeover_stays() {
    let mut g = Group::new();
    let c = g.claim("K", "NK");
    let s = g.member(&g.all()).state(&held(&[&c], DEFAULT_DELAY_MS));
    assert_eq!(claim_state(&s, &c), Some(ClaimState::Effective));
    g.sign("R", Kind::Resolve(vec![c.id()]));
    let later = g.claim("A", "NA");
    let m = counting_member(&g, &[&c]);
    let s = m.state(&held(&[&c, &later], DEFAULT_DELAY_MS));
    assert_eq!(s.roots, vec![g.root.hash, k("NK").hash]);
    assert_eq!(claim_state(&s, &c), Some(ClaimState::Effective));
}

/// recoveryFreezeTest: a watch admin may not freeze the recovery key; its
/// freeze does not count and the recovery key's claim takes effect.
#[test]
fn a_watch_admin_cannot_freeze_the_recovery_key() {
    let mut g = Group::new();
    let seen = g.seen();
    let f = g.freeze("W", "K", seen);
    let c = g.claim("K", "NK");
    let s = g.member(&g.all()).state(&held(&[&c], DEFAULT_DELAY_MS));
    assert!(!s.counting.contains(&f.id()));
    assert_eq!(s.roots, vec![g.root.hash, k("NK").hash]);
}

/// ownKeyFreezesTest: two freezes a watch admin signs of its own key do not
/// stop the group.
#[test]
fn freezes_of_ones_own_key_do_not_stop_the_group() {
    let mut g = Group::new();
    g.freeze("W", "W", Vec::new());
    g.freeze("W", "W", Vec::new());
    let s = g.member(&g.all()).state(&BTreeMap::new());
    assert_eq!(s.stop, Stop::None);
    assert!(s.may_command(&k("A").hash));
    assert!(!s.may_command(&k("W").hash));
}

/// bothKeysRemovedTest: a removal of an admin's member key removes its
/// admin key; its later claim does not count.
#[test]
fn a_removal_of_the_member_key_removes_the_admin_key() {
    let mut g = Group::new();
    g.revoke("R", "A phone");
    let c = g.claim("A", "NA");
    let s = g.member(&g.all()).state(&held(&[&c], DEFAULT_DELAY_MS));
    assert!(s.revoked.contains(&k("A").hash));
    assert!(!s.may_command(&k("A").hash));
    // The removal did not see the claim (it came first): void.
    assert_eq!(claim_state(&s, &c), Some(ClaimState::Void));
    assert_eq!(s.roots, vec![g.root.hash]);
}

/// oldRootResolveStaysTest: what the old root resolved stays resolved after
/// a takeover.
#[test]
fn an_old_roots_resolve_stays_after_a_takeover() {
    let mut g = Group::new();
    g.device("C");
    let rm = g.revoke("C", "D");
    g.sign("R", Kind::Resolve(vec![rm.id()]));
    let c = g.claim("K", "NK");
    let s = g.member(&g.all()).state(&held(&[&c], DEFAULT_DELAY_MS));
    assert_eq!(s.roots, vec![g.root.hash, k("NK").hash]);
    assert!(s.device_by_key(&k("D").hash).is_some());
}

/// oldRootAboveCutTest: after a takeover the old root's key counts only on
/// the chain the claim saw; neither a new removal nor a second record at
/// the seq of its newest counts, and a member that compacted keeps neither.
#[test]
fn an_old_root_counts_only_within_the_cut() {
    let mut g = Group::new();
    g.device("R");
    let c = g.claim("K", "NK");
    let h = held(&[&c], DEFAULT_DELAY_MS);
    let mut m = g.member(&g.all());
    let s = m.state(&h);
    assert_eq!(s.roots, vec![g.root.hash, k("NK").hash]);
    m.compact(&s);
    let rm = g.revoke("R", "D");
    let twin = g.sign_twin("R", Kind::Revoke(Removal { keys: vec![k("D").hash], seen: g.seen() }));
    m.insert_all([rm.clone(), twin.clone()]);
    assert!(!m.contains(&rm.id()) && !m.contains(&twin.id()));
    let s = m.state(&h);
    assert_eq!(s.roots, vec![g.root.hash, k("NK").hash]);
    assert!(s.device_by_key(&k("D").hash).is_some());
    let s = counting_member(&g, &[&c]).state(&h);
    assert!(s.device_by_key(&k("D").hash).is_some());
}

/// mintedKeyTest: a key a claimed root names teaches nothing until the
/// claim counts: its records are not kept.
#[test]
fn a_key_a_claimed_root_names_teaches_nothing() {
    let mut g = Group::new();
    g.claim("A", "NA");
    let mut d = Device::new(k("X phone").key, "X phone", ROLE_PHONE);
    d.rights = RIGHT_READ | RIGHT_SEND;
    d.admin = Some(k("X").key);
    (d.powers, d.commands) = AdminKind::Computer.grants();
    g.sign("NA", Kind::Device(d));
    let x = g.device("X");
    let m = g.member(&g.all());
    assert!(!m.contains(&x.id()));
    let s = m.state(&BTreeMap::new());
    assert!(s.device_by_key(&k("D").hash).is_none());
    assert!(!s.may_command(&k("X").hash));
}

/// checkpointTest: the root's checkpoint gives the state on a member that
/// compacted on it; a claimed root's checkpoint is not tried.
#[test]
fn only_a_path_roots_checkpoint_gives_the_state() {
    let mut g = Group::new();
    g.device("R");
    let s = g.member(&g.all()).state(&BTreeMap::new());
    let cp = g.checkpoint("R", &s);
    let mut m = g.member(&g.all());
    let s = m.state(&BTreeMap::new());
    assert_eq!(s.checkpoint, Some(cp.id()));
    assert!(s.device_by_key(&k("D").hash).is_some());
    m.compact(&s);
    g.claim("A", "NA");
    let s2 = g.member(&g.all()).state(&BTreeMap::new());
    let other = g.checkpoint("NA", &s2);
    m.insert_all(g.recs.iter().cloned());
    let s = m.state(&BTreeMap::new());
    assert_eq!(s.checkpoint, Some(cp.id()));
    assert!(!s.counting.contains(&other.id()));
    assert!(s.device_by_key(&k("D").hash).is_some() && s.may_command(&k("A").hash));
}

/// The first promise with counted claims: members that got the same records
/// in other orders and counted the same claims keep one set and one state.
#[test]
fn counted_claims_and_records_in_any_order_give_one_state() {
    let mut g = Group::new();
    g.device("C");
    let c = g.claim("K", "NK");
    g.sign("R", Kind::Resolve(vec![c.id()]));
    g.sign("NK", Kind::Copies { incoming_ms: 5_000, seen: vec![] });
    g.freeze("W", "C", Vec::new());
    let h = held(&[&c], DEFAULT_DELAY_MS);
    let all = g.all();
    let mut rev = all.clone();
    rev.reverse();
    let counted: BTreeSet<RecordId> = [c.id()].into();
    let sets: Vec<RecordSet> = [all, rev]
        .iter()
        .map(|order| {
            let mut m = g.member(order);
            m.remember_counted(counted.iter().copied()).unwrap();
            m
        })
        .collect();
    assert_eq!(sets[0].digest(), sets[1].digest());
    assert_eq!(sets[0].state(&h), sets[1].state(&h));
    assert_eq!(sets[0].state(&h).roots, vec![g.root.hash, k("NK").hash]);
}

impl Group {
    /// The root's record of an admin's device again: with another admin key,
    /// or none, and the heads it saw of the old one.
    fn admin_again(&mut self, member: &str, admin: Option<(&str, AdminKind)>) -> Record {
        let mut d = Device::new(k(member).key, member, ROLE_PHONE);
        d.rights = RIGHT_READ | RIGHT_SEND;
        if let Some((a, kind)) = admin {
            d.admin = Some(k(a).key);
            (d.powers, d.commands) = kind.grants();
        }
        d.seen = self.seen();
        self.sign("R", Kind::Device(d))
    }
}

/// demotedAdminTest: the root takes the admin key off A's device; what A
/// signs after, unseen by that record, does not count.
#[test]
fn an_admin_key_the_root_took_off_signs_nothing() {
    let mut g = Group::new();
    g.admin_again("A phone", None);
    let c = g.claim("A", "NA");
    let s = g.member(&g.all()).state(&held(&[&c], DEFAULT_DELAY_MS));
    assert_ne!(claim_state(&s, &c), Some(ClaimState::Effective));
    assert_eq!(s.roots, vec![g.root.hash]);
    assert!(!s.may_command(&k("A").hash));
}

/// countedClaimKeptTest: a counted claim is kept outside the rooms:
/// records the claimant signs beside it at its seq never push it out,
/// before or after compaction.
#[test]
fn a_counted_claim_is_never_pushed_out() {
    let mut g = Group::new();
    let c = g.claim("K", "NK");
    for _ in 0..40 {
        g.sign_twin("K", Kind::Copies { incoming_ms: 5_000, seen: vec![] });
    }
    let h = held(&[&c], DEFAULT_DELAY_MS);
    let mut m = counting_member(&g, &[&c]);
    assert!(m.contains(&c.id()));
    let s = m.state(&h);
    m.compact(&s);
    assert!(m.contains(&c.id()));
    assert_eq!(m.state(&h).roots, vec![g.root.hash, k("NK").hash]);
}

/// thawTest and thawSeenTest: a thaw revives only what it saw of the
/// frozen key; the rest stays cut off.
#[test]
fn a_thaw_revives_only_what_it_saw() {
    for saw in [false, true] {
        let mut g = Group::new();
        let seen = g.seen();
        let f = g.freeze("A", "C", seen);
        let before = g.seen();
        g.device("C");
        let seen = if saw { g.seen() } else { before };
        g.sign("R", Kind::Thaw { ids: vec![f.id()], seen });
        let s = g.member(&g.all()).state(&BTreeMap::new());
        assert!(s.may_command(&k("C").hash), "saw {saw}");
        assert_eq!(s.device_by_key(&k("D").hash).is_some(), saw, "saw {saw}");
    }
}

/// claimantRemovedTest: the live old root removes the claimant after
/// seeing its claim. A member that was off during the delay and gets both
/// sees the claim cancelled; one that counted first keeps the takeover.
#[test]
fn a_claimant_removed_after_its_claim_is_cancelled_where_not_counted() {
    let mut g = Group::new();
    let c = g.claim("K", "NK");
    let h = held(&[&c], DEFAULT_DELAY_MS);
    let counted = counting_member(&g, &[&c]);
    g.revoke("R", "K");
    let s = g.member(&g.all()).state(&h);
    assert_eq!(claim_state(&s, &c), Some(ClaimState::Cancelled));
    assert_eq!(s.roots, vec![g.root.hash]);
    let mut counted = counted;
    counted.insert_all(g.recs.iter().cloned());
    assert_eq!(counted.state(&h).roots, vec![g.root.hash, k("NK").hash]);
}

/// claimantRemovedAfterNewRootTest: a removal of the claimant that saw the
/// new root's records disputes nothing.
#[test]
fn a_removal_that_saw_the_new_root_changes_nothing() {
    let mut g = Group::new();
    let c = g.claim("K", "NK");
    g.device_by_new_root();
    g.revoke("R", "K");
    let s = g.member(&g.all()).state(&held(&[&c], DEFAULT_DELAY_MS));
    assert_eq!(claim_state(&s, &c), Some(ClaimState::Effective));
    assert_eq!(s.roots, vec![g.root.hash, k("NK").hash]);
}

/// fullRoomAfterTakeoverTest: after a takeover counts, other keys fill the
/// room; the old root keeps its records from the head the claim saw
/// downward, and the takeover stays.
#[test]
fn a_full_room_after_a_takeover_keeps_it() {
    let mut g = Group::new();
    let c = g.claim("K", "NK");
    for by in ["A", "C", "W", "NK"] {
        for _ in 0..300 {
            g.sign(by, Kind::Copies { incoming_ms: 5_000, seen: vec![] });
        }
    }
    let h = held(&[&c], DEFAULT_DELAY_MS);
    let m = counting_member(&g, &[&c]);
    let s = m.state(&h);
    assert_eq!(s.roots, vec![g.root.hash, k("NK").hash]);
    assert_eq!(claim_state(&s, &c), Some(ClaimState::Effective));
}
