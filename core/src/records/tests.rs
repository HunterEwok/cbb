// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The rules of records v3 as tests: who signs what, one place per record,
//! the limits, claims and the stop, held records, the keys statement, and
//! one state for one set in any order.

use std::collections::BTreeMap;
use std::time::Instant;

use p256::ecdsa::SigningKey;
use p256::ecdsa::signature::hazmat::PrehashSigner as _;

use super::body::*;
use super::eval::{ClaimState, ConflictKind, Stop, Why};
use super::key::{ALG_XWING, XWING_PUBLIC, tests_hook};
use super::set::{Added, Refused};
use super::statement::{self, Statement};
use super::*;
use crate::certs::sha256;
use crate::identity::ExternalKey;

/// A key made from a name, so that a test replays exactly.
struct K {
    sk: SigningKey,
    key: Key,
    hash: KeyHash,
}

impl ExternalKey for K {
    fn public(&self) -> Vec<u8> {
        self.key.public.clone()
    }
    fn sign_digest(&self, digest: &[u8; 32]) -> crate::error::Result<Vec<u8>> {
        let sig: p256::ecdsa::Signature = self.sk.sign_prehash(digest).unwrap();
        Ok(sig.to_der().as_bytes().to_vec())
    }
}

fn k(name: &str) -> K {
    let sk = SigningKey::from_slice(&sha256(name.as_bytes())).unwrap();
    let key = Key::es256(sk.verifying_key().to_sec1_point(false).as_bytes().to_vec());
    let hash = key.hash();
    K { sk, key, hash }
}

/// Builds a group's records: each signer's next seq and prev.
struct G {
    root: K,
    gid: GroupId,
    heads: BTreeMap<KeyHash, (u64, RecordId)>,
    recs: Vec<Record>,
}

impl G {
    fn new() -> G {
        let root = k("root");
        let gid = root.key.device_id();
        G { root, gid, heads: BTreeMap::new(), recs: Vec::new() }
    }

    fn body(&self, by: &K, kind: Kind) -> Body {
        let (seq, prev) = match self.heads.get(&by.hash) {
            Some((s, id)) => (s + 1, Some(*id)),
            None => (1, None),
        };
        Body { group: self.gid, signer: by.hash, seq, prev, time_ms: 0, kind, held: false }
    }

    fn push(&mut self, r: Record) -> Record {
        self.heads.insert(r.body().signer, (r.body().seq, r.id()));
        self.recs.push(r.clone());
        r
    }

    fn rec(&mut self, by: &K, kind: Kind) -> Record {
        let r = Record::sign(self.body(by, kind), by).unwrap();
        self.push(r)
    }

    /// A record of the root's own key.
    fn root_rec(&mut self, kind: Kind) -> Record {
        let root = k("root");
        self.rec(&root, kind)
    }

    fn device(&mut self, by: &K, member: &K, name: &str, f: impl FnOnce(&mut Device)) -> Record {
        let mut d = Device::new(member.key.clone(), name, ROLE_MEMBER);
        d.rights = RIGHT_READ | RIGHT_SEND;
        f(&mut d);
        self.rec(by, Kind::Device(d))
    }

    /// The root records the device of member as an admin with powers.
    fn admin(&mut self, member: &K, admin: &K, powers: u64) -> Record {
        let root = k("root");
        self.device(&root, member, "admin", |d| {
            d.admin = Some(admin.key.clone());
            d.powers = powers;
        })
    }

    fn seen(&self) -> Vec<Seen> {
        self.heads.iter().map(|(k, (s, id))| Seen { key: *k, seq: *s, id: *id }).collect()
    }

    /// The entry of a seen list for key's record at seq.
    fn seen_at(&self, key: &KeyHash, seq: u64) -> Seen {
        let r = self.recs.iter().find(|r| r.body().signer == *key && r.body().seq == seq).unwrap();
        Seen { key: *key, seq, id: r.id() }
    }

    fn state(&self) -> State {
        state_of(&self.root.key, &self.recs, &BTreeMap::new())
    }
}

fn state_of(root: &Key, recs: &[Record], held: &BTreeMap<RecordId, u64>) -> State {
    evaluate(&Input { root, records: recs, held_ms: held, counted: &[] })
}

fn removal(keys: &[KeyHash], seen: Vec<Seen>) -> Removal {
    let mut keys = keys.to_vec();
    keys.sort();
    Removal { keys, seen }
}

/// The same body with another signature: s replaced by n − s.
fn high_s(r: &Record) -> Record {
    let sig = p256::ecdsa::Signature::from_slice(r.sig()).unwrap();
    let (rr, s) = sig.split_scalars();
    let flipped = p256::ecdsa::Signature::from_scalars(rr, -*s).unwrap();
    Record::from_parts(r.body_bytes().to_vec(), flipped.to_bytes().to_vec(), None, r.body().clone()).unwrap()
}

#[test]
fn signatures_have_one_form() {
    let mut g = G::new();
    let laptop = k("laptop");
    let r = g.device(&k("root"), &laptop, "laptop", |_| {});
    let root = g.root.key.clone();
    assert_eq!(r.verify(&root), Ok(false));
    let twin = high_s(&r);
    assert_eq!(twin.id(), r.id());
    assert!(twin.verify(&root).unwrap_err().is("sig/low-s"));
    let short = Record::from_parts(r.body_bytes().to_vec(), r.sig()[..63].to_vec(), None, r.body().clone()).unwrap();
    assert!(short.verify(&root).unwrap_err().is("sig/size"));
    let mut zero = r.sig().to_vec();
    zero[..32].fill(0);
    let zero = Record::from_parts(r.body_bytes().to_vec(), zero, None, r.body().clone()).unwrap();
    assert!(zero.verify(&root).unwrap_err().is("sig/range"));
    let other = Record::sign(r.body().clone(), &k("root")).unwrap();
    let mut wrong = r.body_bytes().to_vec();
    wrong.push(0);
    assert!(Record::from_parts(wrong, other.sig().to_vec(), None, r.body().clone()).is_err());
    // A body signed under another label does not verify as a record.
    let sig = key::sign_es256(&k("root"), "cbb command v3", r.body_bytes()).unwrap();
    let as_command = Record::from_parts(r.body_bytes().to_vec(), sig.to_vec(), None, r.body().clone()).unwrap();
    assert!(as_command.verify(&root).unwrap_err().is("sig/verify"));
}

#[test]
fn a_record_has_one_place() {
    let mut g = G::new();
    let laptop = k("laptop");
    let r = g.device(&k("root"), &laptop, "laptop", |_| {});
    let mut set = RecordSet::new(g.root.key.clone());
    // A copy that does not verify is refused and takes no place.
    assert!(matches!(set.insert(high_s(&r)), Err(Refused::Broken(rule)) if rule.is("sig/low-s")));
    assert!(set.is_empty());
    assert_eq!(set.insert(r.clone()), Ok(Added::Stored));
    // The key holder signing the same body again gives the same record.
    let again = Record::sign(r.body().clone(), &k("root")).unwrap();
    assert_eq!(again.id(), r.id());
    assert_eq!(set.insert(again), Ok(Added::Known));
    assert_eq!(set.len(), 1);
    let digest = set.digest();
    assert_eq!(digest, super::digest([r.id()].iter()));
}

#[test]
fn records_wait_for_their_signer() {
    let mut g = G::new();
    let (phone, admin, tablet) = (k("phone"), k("phone admin"), k("tablet"));
    let a = g.admin(&phone, &admin, POWER_ADMIT);
    let t = g.device(&admin, &tablet, "tablet", |_| {});
    let mut set = RecordSet::new(g.root.key.clone());
    assert_eq!(set.insert(t.clone()), Err(Refused::UnknownSigner));
    assert!(set.is_empty());
    let (stored, refused) = set.insert_all([t.clone(), a.clone()]);
    assert_eq!((stored, refused.len()), (2, 0));
    let order: Vec<RecordId> = set.in_dependency_order().iter().map(|r| r.id()).collect();
    assert_eq!(order, [a.id(), t.id()]);
    let other =
        G { root: k("another root"), gid: k("another root").key.device_id(), heads: BTreeMap::new(), recs: Vec::new() };
    let mut other = other;
    let o = other.device(&k("another root"), &tablet, "tablet", |_| {});
    assert_eq!(set.insert(o), Err(Refused::Group));
}

#[test]
fn an_admin_signs_only_a_new_devices_first_record() {
    let mut g = G::new();
    let root = k("root");
    let (pa, a, pb, b) = (k("phone a"), k("admin a"), k("phone b"), k("admin b"));
    let (laptop, tablet) = (k("laptop"), k("tablet"));
    g.admin(&pa, &a, POWER_ADMIT | POWER_REMOVE);
    g.admin(&pb, &b, POWER_ADMIT);
    let l = g.device(&root, &laptop, "laptop", |d| d.rights |= RIGHT_HUB);
    let t = g.device(&a, &tablet, "tablet", |_| {});
    // Admin b writes records for a device the root recorded and for one
    // admin a admitted.
    let bl = g.device(&b, &laptop, "mine", |_| {});
    let bt = g.device(&b, &tablet, "mine", |_| {});
    // Admin a writes a second record for its own device without manage.
    let at = g.device(&a, &tablet, "renamed", |_| {});
    let s = g.state();
    let dl = s.device(&laptop.key.device_id()).unwrap();
    assert_eq!((dl.name.as_str(), dl.rights), ("laptop", RIGHT_READ | RIGHT_SEND | RIGHT_HUB));
    // Two admins admitting one device differently: neither counts.
    assert!(s.device(&tablet.key.device_id()).is_none());
    assert!(s.conflicts.iter().any(|c| c.kind == ConflictKind::Admits && c.records.contains(&bt.id())));
    for r in [&bl, &at] {
        assert!(!s.counting.contains(&r.id()));
        assert!(s.ignored.iter().any(|i| i.record == r.id() && i.why == Why::Power));
    }
    assert!(!s.counting.contains(&t.id()) && !s.counting.contains(&bt.id()));
    assert!(s.counting.contains(&l.id()));
    // Without admin b's record, admin a's first record admits the tablet,
    // and its second, without manage, changes nothing.
    let recs: Vec<Record> = g.recs.iter().filter(|r| r.id() != bt.id()).cloned().collect();
    let s = state_of(&g.root.key, &recs, &BTreeMap::new());
    let dt = s.device(&tablet.key.device_id()).unwrap();
    assert_eq!(dt.name, "tablet");
    assert!(!dt.by_root);
    assert!(s.counting.contains(&t.id()) && !s.counting.contains(&at.id()));
    // Each device keeps its one key: an admin's record never adds one.
    assert_eq!(dl.key, laptop.key);
}

/// An admin admits an ordinary leaf like any device, never a guarded one;
/// only a root sets the guard, and an admin cannot clear it (owner, 11.11).
#[test]
fn ordinary_and_guarded_leaves() {
    let mut g = G::new();
    let (pa, a, pm, m) = (k("phone a"), k("admin a"), k("phone m"), k("admin m"));
    let (lamp, lock, kettle) = (k("lamp"), k("lock"), k("kettle"));
    g.admin(&pa, &a, POWER_ADMIT | POWER_MANAGE);
    g.admin(&pm, &m, POWER_MANAGE);
    let leaf = |d: &mut Device| {
        d.role = ROLE_LEAF;
        d.rights = 0;
    };
    // An ordinary leaf from an admin counts.
    let lamp_rec = g.device(&a, &lamp, "lamp", leaf);
    // An admin's record with the guard does not.
    let lock_rec = g.device(&a, &lock, "lock", |d| {
        leaf(d);
        d.guarded = true;
    });
    let s = g.state();
    assert!(s.counting.contains(&lamp_rec.id()));
    let d = s.device(&lamp.key.device_id()).unwrap();
    assert!(d.role == ROLE_LEAF && !d.guarded && !d.by_root);
    assert!(!s.counting.contains(&lock_rec.id()));
    assert!(s.device(&lock.key.device_id()).is_none());
    // A manage record cannot set the guard on the leaf, nor make it
    // another role.
    let set = g.device(&m, &lamp, "lamp", |d| {
        leaf(d);
        d.guarded = true;
    });
    let member = g.device(&m, &lamp, "lamp", |_| {});
    let s = g.state();
    assert!(!s.counting.contains(&set.id()) && !s.counting.contains(&member.id()));
    assert_eq!(s.device(&lamp.key.device_id()).unwrap().role, ROLE_LEAF);
    // The root marks an admin-admitted leaf guarded: it counts, and the
    // leaf is the root's alone.
    g.device(&a, &kettle, "kettle", leaf);
    let guard = g.device(&k("root"), &kettle, "kettle", |d| {
        leaf(d);
        d.guarded = true;
    });
    let s = g.state();
    assert!(s.counting.contains(&guard.id()));
    let d = s.device(&kettle.key.device_id()).unwrap();
    assert!(d.guarded && d.by_root);
    // An admin's later record without the guard does not clear it.
    let clear = g.device(&a, &kettle, "kettle", leaf);
    let cleared = g.device(&m, &kettle, "kettle", leaf);
    let s = g.state();
    assert!(!s.counting.contains(&clear.id()) && !s.counting.contains(&cleared.id()));
    assert!(s.device(&kettle.key.device_id()).unwrap().guarded);
    // The root's later record without the guard counts, and the leaf stays
    // guarded: a reset leaf has a new key, so it is a new device.
    let renamed = g.device(&k("root"), &kettle, "kettle 2", leaf);
    let s = g.state();
    assert!(s.counting.contains(&renamed.id()));
    let d = s.device(&kettle.key.device_id()).unwrap();
    assert!(d.guarded && d.name == "kettle 2");
    // The guard is a leaf's only.
    let mut d = Device::new(k("pc").key.clone(), "pc", ROLE_MEMBER);
    d.guarded = true;
    let body = g.body(&k("root"), Kind::Device(d));
    assert!(body.check().unwrap_err().is("records/device/guarded"));
}

/// A root's later record never makes a leaf of another device, nor another
/// device of a leaf: it does not count.
#[test]
fn a_root_keeps_a_devices_kind() {
    let mut g = G::new();
    let root = k("root");
    let (pc, lamp) = (k("pc"), k("lamp"));
    g.device(&root, &pc, "pc", |_| {});
    let lamp_first = g.device(&root, &lamp, "lamp", |d| d.role = ROLE_LEAF);
    let pc_leaf = g.device(&root, &pc, "pc", |d| d.role = ROLE_LEAF);
    let lamp_pc = g.device(&root, &lamp, "lamp", |_| {});
    let phone = g.device(&root, &pc, "pc 2", |d| d.role = ROLE_PHONE);
    for order in 0..2 {
        let mut recs = g.recs.clone();
        if order == 1 {
            recs.reverse();
        }
        let s = state_of(&g.root.key, &recs, &BTreeMap::new());
        for r in [&pc_leaf, &lamp_pc] {
            assert!(!s.counting.contains(&r.id()));
            assert!(s.ignored.iter().any(|x| x.record == r.id() && x.why == Why::Role));
        }
        assert!(s.counting.contains(&lamp_first.id()) && s.counting.contains(&phone.id()));
        let d = s.device(&pc.key.device_id()).unwrap();
        assert_eq!((d.name.as_str(), d.role), ("pc 2", ROLE_PHONE));
        assert_eq!(s.device(&lamp.key.device_id()).unwrap().role, ROLE_LEAF);
    }
    // An admin's earlier record does not bind the root: the root's first
    // record for a device an admin admitted fixes its kind.
    let (pa, a, board) = (k("phone a"), k("admin a"), k("board"));
    g.admin(&pa, &a, POWER_ADMIT);
    g.device(&a, &board, "board", |_| {});
    let as_leaf = g.device(&root, &board, "board", |d| d.role = ROLE_LEAF);
    let s = g.state();
    assert!(s.counting.contains(&as_leaf.id()));
    let d = s.device(&board.key.device_id()).unwrap();
    assert!(d.role == ROLE_LEAF && d.by_root);
}

#[test]
fn an_admin_never_widens_a_device() {
    let mut g = G::new();
    let (pa, a, pm, m) = (k("phone a"), k("admin a"), k("phone m"), k("admin m"));
    let (w, x, y, z) = (k("w"), k("x"), k("y"), k("z"));
    g.admin(&pa, &a, POWER_ADMIT);
    g.admin(&pm, &m, POWER_MANAGE);
    // Past base rights: a hub, an admin key, a watch.
    let hub = g.device(&a, &w, "w", |d| d.rights |= RIGHT_HUB);
    let admin_key = g.device(&a, &x, "x", |d| d.admin = Some(k("x admin").key.clone()));
    let watch = g.device(&a, &y, "y", |d| d.role = ROLE_WATCH);
    // Secrets only when the admin's own device has them; a's has not.
    let wider = g.device(&a, &z, "z", |d| d.rights |= RIGHT_SECRETS);
    let s = g.state();
    for (n, r) in [&hub, &admin_key, &watch, &wider].into_iter().enumerate() {
        assert!(!s.counting.contains(&r.id()), "record {n}");
    }
    assert!(s.devices.iter().all(|d| d.name == "admin"));
    // Manage narrows a device an admin admitted, and cannot widen it again.
    let ok = g.device(&a, &w, "w", |_| {});
    let narrow = g.device(&m, &w, "w2", |d| d.rights = RIGHT_READ);
    let s = g.state();
    assert!(s.counting.contains(&ok.id()) && s.counting.contains(&narrow.id()));
    let d = s.device(&w.key.device_id()).unwrap();
    assert_eq!((d.name.as_str(), d.rights), ("w2", RIGHT_READ));
    let wide = g.device(&m, &w, "w3", |d| d.rights = RIGHT_READ | RIGHT_SEND | RIGHT_HUB);
    let s = g.state();
    assert!(!s.counting.contains(&wide.id()));
    assert_eq!(s.device(&w.key.device_id()).unwrap().rights, RIGHT_READ);
    // An admin whose own device reads secrets may give them.
    let (ps, sa, v) = (k("phone s"), k("admin s"), k("v"));
    g.device(&k("root"), &ps, "admin", |d| {
        d.rights |= RIGHT_SECRETS;
        d.admin = Some(sa.key.clone());
        d.powers = POWER_ADMIT;
    });
    let given = g.device(&sa, &v, "v", |d| d.rights |= RIGHT_SECRETS);
    assert!(g.state().counting.contains(&given.id()));
}

#[test]
fn two_admins_admitting_one_device() {
    let mut g = G::new();
    let (pa, a, pb, b, t) = (k("phone a"), k("admin a"), k("phone b"), k("admin b"), k("t"));
    g.admin(&pa, &a, POWER_ADMIT);
    g.admin(&pb, &b, POWER_ADMIT);
    let ra = g.device(&a, &t, "from a", |_| {});
    let rb = g.device(&b, &t, "from b", |_| {});
    // Different records: neither counts. The same record from both: it
    // counts once.
    let s = g.state();
    assert!(s.device(&t.key.device_id()).is_none());
    assert!(!s.counting.contains(&ra.id()) && !s.counting.contains(&rb.id()));
    let mut g = G::new();
    g.admin(&pa, &a, POWER_ADMIT);
    g.admin(&pb, &b, POWER_ADMIT);
    let ra = g.device(&a, &t, "t", |_| {});
    let rb = g.device(&b, &t, "t", |_| {});
    let first = ra.id().min(rb.id());
    let mut recs = g.recs.clone();
    for _ in 0..2 {
        let s = state_of(&g.root.key, &recs, &BTreeMap::new());
        assert_eq!(s.device(&t.key.device_id()).unwrap().name, "t");
        assert_eq!(s.counting.contains(&ra.id()), first == ra.id());
        recs.reverse();
    }
}

/// A device another admin already admitted, and works, meets a second
/// admin's different first record for it: neither counts, so the device
/// is out of the state until the root records it, and then it is the
/// root's alone.
#[test]
fn a_second_admins_first_record_for_a_working_device() {
    let mut g = G::new();
    let (pa, a, pb, b, t) = (k("phone a"), k("admin a"), k("phone b"), k("admin b"), k("t"));
    g.admin(&pa, &a, POWER_ADMIT);
    g.admin(&pb, &b, POWER_ADMIT);
    let ra = g.device(&a, &t, "from a", |_| {});
    let works = g.state();
    assert_eq!(works.device(&t.key.device_id()).unwrap().name, "from a");
    let rb = g.device(&b, &t, "from b", |_| {});
    let s = g.state();
    assert!(s.device(&t.key.device_id()).is_none());
    assert!(!s.counting.contains(&ra.id()) && !s.counting.contains(&rb.id()));
    assert!(s.conflicts.iter().any(|c| c.kind == ConflictKind::Admits));
    let rr = g.device(&k("root"), &t, "from root", |_| {});
    let s = g.state();
    assert_eq!(s.device(&t.key.device_id()).unwrap().name, "from root");
    assert!(s.counting.contains(&rr.id()));
}

/// No key, the first root's included (after a takeover, the old root's),
/// pushes another key's counting records out of the set by making many of
/// its own, whatever order they come in.
#[test]
fn a_flood_from_one_key_keeps_the_others() {
    let mut g = G::new();
    let root = k("root");
    let (pa, a, pb, b) = (k("phone a"), k("admin a"), k("phone b"), k("admin b"));
    g.admin(&pa, &a, POWER_ADMIT);
    g.admin(&pb, &b, POWER_ADMIT);
    let admitted: Vec<Record> = (0..40).map(|i| g.device(&a, &k(&format!("t{i}")), "t", |_| {})).collect();
    let quiet = g.recs.clone();
    for flooder in [&root, &b] {
        let mut g = G { root: k("root"), gid: g.gid, heads: g.heads.clone(), recs: quiet.clone() };
        for i in 0..1500 {
            g.device(flooder, &k(&format!("f{i}")), "flood", |_| {});
        }
        for order in 0..2 {
            let mut recs = g.recs.clone();
            if order == 1 {
                recs.reverse();
            }
            let mut set = RecordSet::new(g.root.key.clone());
            set.insert_all(recs);
            assert!(set.len() < g.recs.len());
            for r in &admitted {
                assert!(set.contains(&r.id()));
            }
            let s = set.state(&BTreeMap::new());
            for r in &admitted {
                assert!(s.counting.contains(&r.id()));
            }
        }
    }
}

#[test]
fn removals_follow_the_powers() {
    let mut g = G::new();
    let root = k("root");
    let (pa, a, pb, b, laptop) = (k("phone a"), k("admin a"), k("phone b"), k("admin b"), k("laptop"));
    g.admin(&pa, &a, POWER_REMOVE);
    g.admin(&pb, &b, POWER_ADMIT);
    g.device(&root, &laptop, "laptop", |_| {});
    // Removing an admin needs remove-admins; removing a device, remove.
    let seen = g.seen();
    let of_admin = g.rec(&a, Kind::Revoke(removal(&[pb.hash], seen.clone())));
    let of_root = g.rec(&a, Kind::Revoke(removal(&[root.hash], seen.clone())));
    let of_laptop = g.rec(&a, Kind::Revoke(removal(&[laptop.hash], seen)));
    let s = g.state();
    assert!(!s.counting.contains(&of_admin.id()) && !s.counting.contains(&of_root.id()));
    assert!(s.counting.contains(&of_laptop.id()));
    assert_eq!(s.revoked, vec![laptop.hash]);
    assert!(s.device(&laptop.key.device_id()).is_none());
}

#[test]
fn a_device_s_two_keys_are_removed_together() {
    let mut g = G::new();
    let (pt, t) = (k("phone t"), k("admin t"));
    g.admin(&pt, &t, POWER_ADMIT | POWER_TAKEOVER);
    g.device(&k("root"), &k("laptop"), "laptop", |_| {});
    let seen = g.seen();
    g.root_rec(Kind::Revoke(removal(&[pt.hash], seen)));
    let s = g.state();
    assert!(s.revoked.contains(&pt.hash) && s.revoked.contains(&t.hash));
    let admitted = g.device(&t, &k("other laptop"), "other laptop", |_| {});
    let seen = g.seen();
    let claim = g.rec(&t, Kind::Claim { root: k("other root").key.clone(), seen });
    let s = state_of(&g.root.key, &g.recs, &BTreeMap::from([(claim.id(), DEFAULT_DELAY_MS)]));
    assert!(!s.counting.contains(&admitted.id()) && !s.counting.contains(&claim.id()));
    assert!(s.device(&k("other laptop").key.device_id()).is_none());
    assert_eq!(s.roots, vec![g.root.hash]);
    // And the reverse: a removal by admin key removes the member key too.
    let mut g = G::new();
    g.admin(&pt, &t, POWER_ADMIT);
    let seen = g.seen();
    g.root_rec(Kind::Freeze(removal(&[t.hash], seen)));
    let s = g.state();
    assert!(s.device(&pt.key.device_id()).is_some_and(|d| d.frozen));
    let mut g = G::new();
    g.admin(&pt, &t, POWER_ADMIT);
    let seen = g.seen();
    g.root_rec(Kind::Revoke(removal(&[t.hash], seen)));
    let s = g.state();
    assert!(s.revoked.contains(&pt.hash) && s.device(&pt.key.device_id()).is_none());
}

#[test]
fn only_who_may_remove_the_recovery_key_freezes_it() {
    let (rk, pw, w, pp, p, n) = (k("recovery"), k("watch"), k("admin w"), k("phone p"), k("admin p"), k("new root"));
    let watch = POWER_REMOVE | POWER_FREEZE;
    // Before the recovery key is used.
    let mut g = G::new();
    g.root_rec(Kind::Recovery { admin: rk.key.clone() });
    g.admin(&pw, &w, watch);
    g.admin(&pp, &p, POWER_REMOVE_ADMINS | POWER_FREEZE);
    let seen = g.seen();
    let by_watch = g.rec(&w, Kind::Freeze(removal(&[rk.hash], seen.clone())));
    let revoke_by_watch = g.rec(&w, Kind::Revoke(removal(&[rk.hash], seen)));
    let seen = g.seen();
    let claim = g.rec(&rk, Kind::Claim { root: n.key.clone(), seen });
    let s = state_of(&g.root.key, &g.recs, &BTreeMap::from([(claim.id(), DEFAULT_DELAY_MS)]));
    assert!(!s.counting.contains(&by_watch.id()) && !s.counting.contains(&revoke_by_watch.id()));
    assert_eq!(s.claims[0].state, ClaimState::Effective);
    assert_eq!(s.roots.len(), 2);
    // After it was used.
    let mut g = G::new();
    g.root_rec(Kind::Recovery { admin: rk.key.clone() });
    g.admin(&pw, &w, watch);
    let seen = g.seen();
    let claim = g.rec(&rk, Kind::Claim { root: n.key.clone(), seen });
    g.device(&n, &k("new phone"), "new phone", |d| d.holds_root = true);
    let held = BTreeMap::from([(claim.id(), DEFAULT_DELAY_MS)]);
    let seen = g.seen();
    g.rec(&w, Kind::Freeze(removal(&[rk.hash], seen)));
    let s = state_of(&g.root.key, &g.recs, &held);
    assert_eq!(s.roots.len(), 2);
    assert_eq!(s.stop, Stop::None);
    // A phone admin may freeze it.
    let mut g = G::new();
    g.root_rec(Kind::Recovery { admin: rk.key.clone() });
    g.admin(&pp, &p, POWER_REMOVE_ADMINS | POWER_FREEZE);
    let seen = g.seen();
    let by_phone = g.rec(&p, Kind::Freeze(removal(&[rk.hash], seen)));
    let seen = g.seen();
    let claim = g.rec(&rk, Kind::Claim { root: n.key.clone(), seen });
    let s = state_of(&g.root.key, &g.recs, &BTreeMap::from([(claim.id(), DEFAULT_DELAY_MS)]));
    assert!(s.counting.contains(&by_phone.id()));
    assert_eq!(s.roots.len(), 1);
}

#[test]
fn what_a_root_resolved_stays_resolved_after_a_takeover() {
    let mut g = G::new();
    let all = POWER_ADMIT | POWER_REMOVE | POWER_REMOVE_ADMINS | POWER_TAKEOVER;
    let (pa, a, pb, b, n, laptop) =
        (k("phone a"), k("admin a"), k("phone b"), k("admin b"), k("new root"), k("laptop"));
    g.admin(&pa, &a, all);
    g.admin(&pb, &b, all);
    g.device(&k("root"), &laptop, "laptop", |_| {});
    let seen = g.seen();
    let removal_by_b = g.rec(&b, Kind::Revoke(removal(&[laptop.hash], seen)));
    let undo = g.root_rec(Kind::Resolve(vec![removal_by_b.id()]));
    let s = g.state();
    assert!(!s.revoked.contains(&laptop.hash) && s.counting.contains(&undo.id()));
    let seen = g.seen();
    let claim = g.rec(&a, Kind::Claim { root: n.key.clone(), seen });
    let s = state_of(&g.root.key, &g.recs, &BTreeMap::from([(claim.id(), DEFAULT_DELAY_MS)]));
    assert_eq!(s.roots.len(), 2);
    assert!(!s.counting.contains(&removal_by_b.id()));
    assert!(!s.revoked.contains(&laptop.hash));
    assert!(s.device(&laptop.key.device_id()).is_some());
}

#[test]
fn a_claim_takes_effect_after_the_device_held_it() {
    let mut g = G::new();
    let (pa, a, laptop, n) = (k("phone a"), k("admin a"), k("laptop"), k("new root"));
    g.admin(&pa, &a, POWER_TAKEOVER);
    g.device(&k("root"), &laptop, "laptop", |_| {});
    let seen = g.seen();
    let c = g.rec(&a, Kind::Claim { root: n.key.clone(), seen });
    // The future root's records count only once the claim does.
    let nd = g.device(&n, &k("new phone"), "new phone", |d| d.holds_root = true);
    let s = g.state();
    assert_eq!(s.roots, vec![g.root.hash]);
    assert_eq!(s.claims[0].state, ClaimState::Pending);
    assert_eq!(s.claims[0].left_ms, DEFAULT_DELAY_MS);
    assert!(!s.counting.contains(&nd.id()));
    // No clock: only the time the device held the claim counts.
    let mut held = BTreeMap::from([(c.id(), DEFAULT_DELAY_MS - 1)]);
    let s = state_of(&g.root.key, &g.recs, &held);
    assert_eq!((s.claims[0].state, s.claims[0].left_ms), (ClaimState::Pending, 1));
    held.insert(c.id(), DEFAULT_DELAY_MS);
    let s = state_of(&g.root.key, &g.recs, &held);
    assert_eq!(s.roots, vec![g.root.hash, n.hash]);
    assert_eq!(s.root_device, Some(k("new phone").key.device_id()));
    assert!(s.counting.contains(&nd.id()) && s.counting.contains(&c.id()));
    // A handover takes effect at once.
    let mut g2 = G::new();
    g2.admin(&pa, &a, POWER_TAKEOVER);
    g2.root_rec(Kind::Handover { admin: a.hash });
    let seen = g2.seen();
    g2.rec(&a, Kind::Claim { root: n.key.clone(), seen });
    assert_eq!(g2.state().roots.len(), 2);
}

#[test]
fn one_claim_for_each_admin_and_its_own_room() {
    let mut g = G::new();
    let (pa, a) = (k("phone a"), k("admin a"));
    g.admin(&pa, &a, POWER_TAKEOVER);
    let seen = g.seen();
    let c1 = g.rec(&a, Kind::Claim { root: k("n1").key.clone(), seen: seen.clone() });
    let c2 = g.rec(&a, Kind::Claim { root: k("n2").key.clone(), seen });
    let s = g.state();
    let st = |id: RecordId| s.claims.iter().find(|c| c.record == id).unwrap().state;
    assert_eq!((st(c1.id()), st(c2.id())), (ClaimState::Pending, ClaimState::Void));
    assert_eq!(s.stop, Stop::None);
    // A future root gets 16 records before its claim counts, in its
    // claimant's room.
    let n1 = k("n1");
    let mut future = Vec::new();
    for i in 0..20 {
        future.push(g.device(&n1, &k(&format!("f{i}")), "f", |_| {}));
    }
    let s = g.state();
    let limited = future.iter().filter(|r| s.ignored.iter().any(|i| i.record == r.id() && i.why == Why::Limit)).count();
    assert_eq!(limited, 4);
    // A claim whose new root is the claimant's own key is void.
    let mut g = G::new();
    g.admin(&pa, &a, POWER_TAKEOVER);
    let seen = g.seen();
    let c = g.rec(&a, Kind::Claim { root: a.key.clone(), seen });
    assert_eq!(g.state().claims.iter().find(|x| x.record == c.id()).unwrap().state, ClaimState::Void);
}

#[test]
fn competing_claims_stop_the_group_and_the_root_still_acts() {
    let mut g = G::new();
    let (pa, a, pb, b, laptop) = (k("phone a"), k("admin a"), k("phone b"), k("admin b"), k("laptop"));
    g.admin(&pa, &a, POWER_TAKEOVER);
    g.admin(&pb, &b, POWER_TAKEOVER);
    g.device(&k("root"), &laptop, "laptop", |_| {});
    let seen = g.seen();
    let ca = g.rec(&a, Kind::Claim { root: k("na").key.clone(), seen: seen.clone() });
    let cb = g.rec(&b, Kind::Claim { root: k("nb").key.clone(), seen });
    let s = g.state();
    assert_eq!(s.stop, Stop::Full);
    assert!(s.conflicts.iter().any(|c| c.kind == ConflictKind::Claims));
    // During the stop the root's removal counts.
    let seen = g.seen();
    g.root_rec(Kind::Revoke(removal(&[laptop.hash], seen)));
    let s = g.state();
    assert_eq!(s.stop, Stop::Full);
    assert_eq!(s.revoked, vec![laptop.hash]);
    // The root resolves: it cancels one claim, the other goes on.
    let mut ids = vec![ca.id()];
    ids.sort();
    g.root_rec(Kind::Resolve(ids));
    let s = g.state();
    assert_eq!(s.stop, Stop::None);
    let st = |id: RecordId| s.claims.iter().find(|c| c.record == id).unwrap().state;
    assert_eq!((st(ca.id()), st(cb.id())), (ClaimState::Cancelled, ClaimState::Pending));
}

#[test]
fn held_records_are_kept_not_applied() {
    let mut g = G::new();
    let laptop = k("laptop");
    let mut body = g.body(&k("root"), Kind::Device(Device::new(laptop.key.clone(), "laptop", ROLE_MEMBER)));
    body.held = true;
    // The writer refuses a body it does not understand; a reader that got
    // one signed by a later version keeps it.
    assert!(Record::sign(body.clone(), &k("root")).is_err());
    let bytes = body.encode();
    let sig = key::sign_es256(&k("root"), LABEL_RECORD, &bytes).unwrap();
    let held = g.push(Record::from_parts(bytes, sig.to_vec(), None, body).unwrap());
    let unknown = {
        let body = g.body(&k("root"), Kind::Unknown(99));
        let bytes = body.encode();
        let sig = key::sign_es256(&k("root"), LABEL_RECORD, &bytes).unwrap();
        g.push(Record::from_parts(bytes, sig.to_vec(), None, body).unwrap())
    };
    // The next record of the root hangs on them and counts.
    let next = g.device(&k("root"), &k("tablet"), "tablet", |_| {});
    let mut set = RecordSet::new(g.root.key.clone());
    assert_eq!(set.insert_all(g.recs.clone()).0, 3);
    let s = set.state(&BTreeMap::new());
    assert!(s.device(&laptop.key.device_id()).is_none());
    let mut want = vec![held.id(), unknown.id()];
    want.sort();
    assert_eq!(s.newer, want);
    assert!(s.counting.contains(&next.id()));
    assert!(set.for_peer(&s, &k("tablet").hash).len() == 3);
}

#[test]
fn newer_rules_stop_secrets_here() {
    let mut g = G::new();
    g.root_rec(Kind::Settings(Settings { min_rules: 2, ..Settings::default() }));
    let s = g.state();
    assert!(s.too_old);
    assert_eq!(s.settings.rules(), 2);
    let mut g = G::new();
    g.root_rec(Kind::Settings(Settings { takeover_delay_ms: Some(0), ..Settings::default() }));
    let s = g.state();
    assert!(!s.too_old);
    assert_eq!(s.settings.delay_ms(), 0);
    // A field at its default is never written.
    let bad = Settings { min_rules: 1, ..Settings::default() };
    assert!(
        Body { kind: Kind::Settings(bad), ..g.body(&k("root"), Kind::Unknown(1)) }
            .check()
            .unwrap_err()
            .is("records/settings/min_rules")
    );
}

/// An admin key keeps at most 256 records: the hard ceiling, with no
/// working limit under it.
#[test]
fn the_admin_ceiling() {
    let mut g = G::new();
    let (pa, a) = (k("phone a"), k("admin a"));
    g.admin(&pa, &a, POWER_ADMIT);
    let rs: Vec<Record> = (0..MAX_ADMIN_RECORDS as u64 + 4)
        .map(|i| g.rec(&a, Kind::Copies { incoming_ms: 5_000 + i, seen: vec![] }))
        .collect();
    let s = g.state();
    let counted = rs.iter().filter(|r| s.counting.contains(&r.id())).count();
    assert_eq!(counted, MAX_ADMIN_RECORDS);
    let last = rs.last().unwrap().id();
    assert!(s.ignored.iter().any(|i| i.record == last && i.why == Why::Limit));
}

#[test]
fn two_keys_with_one_id_count_for_nothing() {
    let _short = tests_hook::keep(1);
    // Find two member keys whose IDs agree in the one byte kept.
    let names: Vec<String> = (0..64).map(|i| format!("m{i}")).collect();
    let mut by_id: BTreeMap<DeviceId, String> = BTreeMap::new();
    let mut pair = None;
    for n in &names {
        let id = k(n).key.device_id();
        if let Some(o) = by_id.get(&id) {
            pair = Some((o.clone(), n.clone()));
            break;
        }
        by_id.insert(id, n.clone());
    }
    let (x, y) = pair.expect("a collision in one byte among 64 keys");
    let mut g = G::new();
    let root = k("root");
    let rx = g.device(&root, &k(&x), "x", |_| {});
    let ry = g.device(&root, &k(&y), "y", |_| {});
    let s = g.state();
    let id = k(&x).key.device_id();
    assert!(s.device(&id).is_none());
    assert!(s.conflicts.iter().any(|c| c.kind == ConflictKind::Ids && c.records.contains(&rx.id())));
    for r in [&rx, &ry] {
        assert!(s.ignored.iter().any(|i| i.record == r.id() && i.why == Why::IdConflict));
    }
}

#[test]
fn a_removed_device_gets_only_its_removal() {
    let mut g = G::new();
    let (laptop, tablet, stranger) = (k("laptop"), k("tablet"), k("stranger"));
    g.device(&k("root"), &laptop, "laptop", |_| {});
    g.device(&k("root"), &tablet, "tablet", |_| {});
    let seen = g.seen();
    let rv = g.root_rec(Kind::Revoke(removal(&[laptop.hash], seen)));
    let mut set = RecordSet::new(g.root.key.clone());
    set.insert_all(g.recs.clone());
    let s = set.state(&BTreeMap::new());
    let got: Vec<RecordId> = set.for_peer(&s, &laptop.hash).iter().map(|r| r.id()).collect();
    assert_eq!(got, [rv.id()]);
    assert!(set.for_peer(&s, &stranger.hash).is_empty());
    assert_eq!(set.for_peer(&s, &tablet.hash).len(), 3);
}

fn xwing(n: u8) -> Key {
    Key { alg: ALG_XWING, public: vec![n; XWING_PUBLIC] }
}

#[test]
fn the_sealing_key_is_the_devices_own() {
    let mut g = G::new();
    let laptop = k("laptop");
    g.device(&k("root"), &laptop, "laptop", |_| {});
    let s = g.state();
    let st = |epoch, seal, by: &K| {
        Statement::sign(statement::Body { group: g.gid, signer: by.hash, epoch, time_ms: 0, seal, held: false }, by)
    };
    let e1 = st(1, xwing(1), &laptop).unwrap();
    let e2 = st(2, xwing(2), &laptop).unwrap();
    let e2b = st(2, xwing(3), &laptop).unwrap();
    // Nobody else signs a device's statement.
    assert!(st(3, xwing(4), &laptop).is_ok());
    let forged = Statement::from_parts(
        statement::Body { group: g.gid, signer: laptop.hash, epoch: 9, time_ms: 0, seal: xwing(9), held: false }
            .encode(),
        key::sign_es256(
            &k("root"),
            statement::LABEL_KEYS,
            &statement::Body { group: g.gid, signer: laptop.hash, epoch: 9, time_ms: 0, seal: xwing(9), held: false }
                .encode(),
        )
        .unwrap()
        .to_vec(),
        statement::Body { group: g.gid, signer: laptop.hash, epoch: 9, time_ms: 0, seal: xwing(9), held: false },
    )
    .unwrap();
    let chosen = statement::choose(&s, [&e1, &forged, &e2]);
    let c = &chosen[&laptop.key.device_id()];
    assert_eq!((c.statement.body().epoch, c.conflict), (2, false));
    let chosen = statement::choose(&s, [&e2b, &e1, &e2]);
    let c = &chosen[&laptop.key.device_id()];
    assert_eq!(c.statement.id(), e2.id().min(e2b.id()));
    assert!(c.conflict);
    // A removed device's statement counts no more.
    let seen = g.seen();
    g.root_rec(Kind::Revoke(removal(&[laptop.hash], seen)));
    assert!(statement::choose(&g.state(), [&e2]).is_empty());
}

#[test]
fn a_checkpoint_frees_room() {
    let mut g = G::new();
    let root = k("root");
    let mut ds = Vec::new();
    for i in 0..6 {
        ds.push(g.device(&root, &k(&format!("d{i}")), &format!("d{i}"), |_| {}));
    }
    let seen = g.seen();
    let rv = g.root_rec(Kind::Revoke(removal(&[k("d0").hash], seen)));
    let (s, id) = g.heads[&root.hash];
    let mut keep: Vec<RecordId> = ds[1..].iter().map(|r| r.id()).collect();
    keep.sort();
    let cp = g.root_rec(Kind::Checkpoint { heads: vec![Head { key: root.hash, seq: s, id }], keep });
    let mut set = RecordSet::new(g.root.key.clone());
    set.insert_all(g.recs.clone());
    let before = set.state(&BTreeMap::new());
    assert_eq!(before.checkpoint, Some(cp.id()));
    assert_eq!(set.compact(&before), 1);
    assert!(!set.contains(&ds[0].id()) && set.contains(&rv.id()));
    let after = set.state(&BTreeMap::new());
    assert_eq!(after.devices, before.devices);
    assert_eq!(after.revoked, before.revoked);
}

/// A root at its ceiling still checkpoints; the checkpoint frees room
/// and the root records again, so a long-lived group never fills up.
#[test]
fn a_full_root_checkpoints_and_goes_on() {
    let mut g = G::new();
    let root = k("root");
    let laptop = g.device(&root, &k("laptop"), "laptop", |_| {});
    for i in 1..MAX_ROOT_RECORDS as u64 {
        g.root_rec(Kind::Copies { incoming_ms: 5_000 + i, seen: vec![] });
    }
    let mut set = RecordSet::new(g.root.key.clone());
    set.insert_all(g.recs.clone());
    assert_eq!(set.len(), MAX_ROOT_RECORDS);
    // Full: the root's next ordinary record finds no room.
    let late = Record::sign(g.body(&root, Kind::Copies { incoming_ms: 9_999, seen: vec![] }), &root).unwrap();
    assert_eq!(set.insert(late), Ok(Added::NoRoom));
    let (seq, id) = g.heads[&root.hash];
    let cp = g.root_rec(Kind::Checkpoint { heads: vec![Head { key: root.hash, seq, id }], keep: vec![laptop.id()] });
    assert_eq!(set.insert(cp.clone()), Ok(Added::Stored));
    let state = set.state(&BTreeMap::new());
    assert_eq!(state.checkpoint, Some(cp.id()));
    assert!(set.compact(&state) > 1000);
    let next = g.device(&root, &k("phone"), "phone", |_| {});
    assert_eq!(set.insert(next.clone()), Ok(Added::Stored));
    let s = set.state(&BTreeMap::new());
    assert!(s.counting.contains(&next.id()) && s.device(&k("laptop").key.device_id()).is_some());
}

#[test]
fn the_set_stays_within_its_bytes_whatever_the_order() {
    // Root checkpoints of nearly 64 KiB each fill 2 MiB quickly.
    let mut g = G::new();
    let root = k("root");
    let first = g.device(&root, &k("laptop"), "laptop", |_| {});
    let fill: Vec<RecordId> = (0..1900u32).map(|i| RecordId(sha256(&i.to_be_bytes()))).collect();
    let mut fill = fill;
    fill.sort();
    for _ in 0..36 {
        let head = Head { key: root.hash, seq: g.heads[&root.hash].0, id: g.heads[&root.hash].1 };
        g.root_rec(Kind::Checkpoint { heads: vec![head], keep: fill.clone() });
    }
    let mut a = RecordSet::new(g.root.key.clone());
    a.insert_all(g.recs.clone());
    let mut b = RecordSet::new(g.root.key.clone());
    let mut rev = g.recs.clone();
    rev.reverse();
    b.insert_all(rev);
    assert!(a.bytes() <= MAX_SET_BYTES && a.len() < g.recs.len());
    assert_eq!(a.digest(), b.digest());
    // The root's checkpoints come first, the newest first; the newest
    // prunes the first device anyway.
    assert!(a.contains(&g.recs.last().unwrap().id()));
    assert!(!a.contains(&first.id()));
}

#[test]
fn many_claims_evaluate_quickly() {
    // A claim takes 80 units of the set's 4096, so about 50 claims fit
    // beside their admins' records: 48 here, all kept.
    let mut g = G::new();
    let n = 48;
    let mut admins = Vec::new();
    for i in 0..n {
        let (p, a) = (k(&format!("p{i}")), k(&format!("a{i}")));
        g.admin(&p, &a, POWER_TAKEOVER);
        admins.push(a);
    }
    let (seq, id) = g.heads[&g.root.hash];
    let seen = vec![Seen { key: g.root.hash, seq, id }];
    for (i, a) in admins.iter().enumerate() {
        g.rec(a, Kind::Claim { root: k(&format!("n{i}")).key.clone(), seen: seen.clone() });
    }
    let mut set = RecordSet::new(g.root.key.clone());
    set.insert_all(g.recs.clone());
    let t = Instant::now();
    let s = set.state(&BTreeMap::new());
    let took = t.elapsed();
    assert_eq!(set.len(), g.recs.len());
    assert_eq!(s.stop, Stop::Full);
    assert_eq!(s.claims.len(), n);
    assert!(took.as_secs() < 10, "{took:?}");
}

/// A removed admin signs as much as it can, through claims of its own that
/// never count and the roots they name: the group's removals hold, the
/// devices admins admitted stay, admins still record, and a takeover
/// still takes effect.
#[test]
fn limits_hold_for_any_signer() {
    let mut g = G::new();
    let (pa, a, px, x, pt, t) = (k("phone a"), k("admin a"), k("phone x"), k("admin x"), k("phone t"), k("admin t"));
    g.admin(&pa, &a, POWER_ADMIT | POWER_REMOVE_ADMINS);
    g.admin(&px, &x, POWER_TAKEOVER);
    g.admin(&pt, &t, POWER_TAKEOVER);
    let admitted: Vec<Record> = (0..20).map(|i| g.device(&a, &k(&format!("d{i}")), "d", |_| {})).collect();
    let seen = g.seen();
    let removal_of_x = g.rec(&a, Kind::Revoke(removal(&[x.hash], seen)));
    // X, removed, claims four roots of its own and floods with each and
    // with its own key.
    let quiet = g.recs.clone();
    for i in 0..4 {
        let seen = g.seen();
        let r = k(&format!("x root {i}"));
        g.rec(&x, Kind::Claim { root: r.key.clone(), seen });
        for j in 0..400 {
            g.device(&r, &k(&format!("x{i} {j}")), "flood", |_| {});
        }
    }
    for j in 0..400 {
        g.device(&x, &k(&format!("x {j}")), "flood", |_| {});
    }
    let flood: Vec<Record> = g.recs[quiet.len()..].to_vec();
    // An honest takeover goes on beside it.
    let seen = g.seen();
    let claim = g.rec(&t, Kind::Claim { root: k("t root").key.clone(), seen });
    let held = BTreeMap::from([(claim.id(), DEFAULT_DELAY_MS)]);
    for order in 0..2 {
        let mut recs = g.recs.clone();
        if order == 1 {
            recs.reverse();
        }
        let mut set = RecordSet::new(g.root.key.clone());
        set.insert_all(recs);
        assert!(set.len() < g.recs.len() && set.bytes() <= MAX_SET_BYTES);
        let s = set.state(&held);
        assert!(s.revoked.contains(&x.hash) && s.counting.contains(&removal_of_x.id()));
        for r in &admitted {
            assert!(s.counting.contains(&r.id()));
        }
        assert!(flood.iter().all(|r| !s.counting.contains(&r.id())));
        // X holds no more than its own 256 units whatever it signs: its
        // claims' roots keep only what the claims paid ahead.
        let units_of = |f: &dyn Fn(&KeyHash) -> bool| -> u64 {
            set.ids()
                .filter_map(|id| set.get(id))
                .filter(|r| f(&r.body().signer))
                .map(|r| super::eval::item(r, super::eval::Role::Admin).units)
                .sum()
        };
        let roots: Vec<KeyHash> = (0..4).map(|i| k(&format!("x root {i}")).hash).collect();
        let claims_kept = set
            .ids()
            .filter_map(|id| set.get(id))
            .filter(|r| r.body().signer == x.hash && matches!(r.body().kind, Kind::Claim { .. }))
            .count() as u64;
        assert!(units_of(&|h| *h == x.hash) <= 256);
        assert!(units_of(&|h| roots.contains(h)) <= 16 * claims_kept);
        assert_eq!(s.roots, vec![g.root.hash, k("t root").hash]);
        assert!(s.counting.contains(&claim.id()));
        // An admin still records.
        let mut g2 = G { root: k("root"), gid: g.gid, heads: g.heads.clone(), recs: Vec::new() };
        let more = g2.device(&a, &k("one more"), "one more", |_| {});
        assert_eq!(set.insert(more.clone()), Ok(Added::Stored));
        assert!(set.state(&held).counting.contains(&more.id()));
    }
}

/// Two members converge once both count a takeover: one where it does not
/// count yet keeps only 16 units of the new root's records, and takes the
/// rest by sync once it counts there too.
#[test]
fn members_converge_once_both_count_the_takeover() {
    let mut g = G::new();
    let (pt, t, n) = (k("phone t"), k("admin t"), k("new root"));
    g.admin(&pt, &t, POWER_TAKEOVER);
    let seen = g.seen();
    let claim = g.rec(&t, Kind::Claim { root: n.key.clone(), seen });
    let news: Vec<Record> = (0..60).map(|i| g.device(&n, &k(&format!("n{i}")), "n", |_| {})).collect();
    let held = BTreeMap::from([(claim.id(), DEFAULT_DELAY_MS)]);
    let sync = |set: &mut RecordSet, recs: &[Record], held: &BTreeMap<RecordId, u64>| {
        for _ in 0..3 {
            set.insert_all(recs.iter().cloned());
            let st = set.state(held);
            set.compact(&st);
        }
    };
    let mut a = RecordSet::new(g.root.key.clone());
    sync(&mut a, &g.recs, &held);
    let mut b = RecordSet::new(g.root.key.clone());
    let mut rev = g.recs.clone();
    rev.reverse();
    sync(&mut b, &rev, &BTreeMap::new());
    // On b the claim does not count yet: 16 units of the new root.
    let kept_b = news.iter().filter(|r| b.contains(&r.id())).count();
    assert!(kept_b <= 16 && kept_b > 0);
    assert!(news.iter().all(|r| a.contains(&r.id())));
    assert_ne!(a.digest(), b.digest());
    sync(&mut b, &rev, &held);
    assert_eq!(a.digest(), b.digest());
    assert_eq!(a.state(&held), b.state(&held));
    assert_eq!(a.state(&held).roots, vec![g.root.hash, n.hash]);
}

/// A claim that is dropped takes its root's records and its key with it,
/// whatever order the records came in.
#[test]
fn a_dropped_claim_takes_its_root_along() {
    let mut g = G::new();
    let (px, x, r) = (k("phone x"), k("admin x"), k("x root"));
    g.admin(&px, &x, POWER_TAKEOVER);
    // X's own records at seq 1, more than its 256 units.
    let forks: Vec<Record> = (0..300)
        .map(|i| {
            let b = Body { seq: 1, prev: None, ..g.body(&x, Kind::Copies { incoming_ms: 5_000 + i, seen: vec![] }) };
            Record::sign(b, &x).unwrap()
        })
        .collect();
    let head = forks.iter().map(|f| f.id()).min().unwrap();
    let seen = g.seen();
    let claim_body = Body { seq: 2, prev: Some(head), ..g.body(&x, Kind::Claim { root: r.key.clone(), seen }) };
    let claim = Record::sign(claim_body, &x).unwrap();
    let root_recs: Vec<Record> = (0..5).map(|i| g.device(&r, &k(&format!("r{i}")), "r", |_| {})).collect();
    let base: Vec<Record> = g.recs[..g.recs.len() - root_recs.len()].to_vec();
    for order in 0..2 {
        let mut set = RecordSet::new(g.root.key.clone());
        set.insert_all(base.clone());
        let mut later: Vec<Record> = forks.clone();
        if order == 0 {
            // The claim and its root first: kept until X's own records
            // push the claim out.
            assert_eq!(set.insert(claim.clone()), Ok(Added::Stored));
            set.insert_all(root_recs.clone());
            assert!(root_recs.iter().all(|r| set.contains(&r.id())));
        } else {
            later.push(claim.clone());
            later.extend(root_recs.iter().cloned());
            later.reverse();
        }
        set.insert_all(later);
        assert!(!set.contains(&claim.id()));
        assert!(root_recs.iter().all(|r| !set.contains(&r.id())));
        let next = g.device(&r, &k("r late"), "r", |_| {});
        assert_eq!(set.insert(next), Err(Refused::UnknownSigner));
    }
}

/// A claim the device has held for no known time stays pending: the
/// caller passes the held time, and nothing reads a clock.
#[test]
fn an_unknown_held_time_keeps_a_claim_pending() {
    let mut g = G::new();
    let (pa, a) = (k("phone a"), k("admin a"));
    g.admin(&pa, &a, POWER_TAKEOVER);
    let seen = g.seen();
    let c = g.rec(&a, Kind::Claim { root: k("n").key.clone(), seen });
    for held in [BTreeMap::new(), BTreeMap::from([(RecordId([7; 32]), u64::MAX)])] {
        let s = state_of(&g.root.key, &g.recs, &held);
        assert_eq!((s.claims[0].state, s.claims[0].left_ms), (ClaimState::Pending, DEFAULT_DELAY_MS));
    }
    let s = state_of(&g.root.key, &g.recs, &BTreeMap::from([(c.id(), u64::MAX)]));
    assert_eq!(s.claims[0].state, ClaimState::Effective);
}

/// A removal signed again after a root voided its signer's two histories
/// keeps what the first saw of the removed key: nothing that key signed
/// in between counts.
#[test]
fn a_removal_signed_again_keeps_what_it_saw() {
    let mut g = G::new();
    let (ps, s_, pt, t) = (k("phone s"), k("admin s"), k("phone t"), k("admin t"));
    g.admin(&ps, &s_, POWER_REMOVE_ADMINS);
    g.admin(&pt, &t, POWER_ADMIT);
    g.device(&t, &k("d1"), "d1", |_| {});
    let rm = removal(&[t.hash], g.seen());
    let first = g.rec(&s_, Kind::Revoke(rm.clone()));
    // S's key signs seq 1 twice: none of its records counts, T goes on.
    let twin_body = Body { seq: 1, prev: None, ..g.body(&s_, Kind::Copies { incoming_ms: 6_000, seen: vec![] }) };
    let twin = g.push(Record::sign(twin_body, &s_).unwrap());
    let later: Vec<Record> = (2..5).map(|i| g.device(&t, &k(&format!("d{i}")), "d", |_| {})).collect();
    let s = g.state();
    assert!(s.two_histories(&s_.hash) && !s.revoked.contains(&t.hash));
    let mut ids = vec![first.id(), twin.id()];
    ids.sort();
    g.root_rec(Kind::Resolve(ids));
    let current = g.seen();
    let sign_at_one = |g: &mut G, rm: Removal| {
        let b = Body { seq: 1, prev: None, ..g.body(&s_, Kind::Revoke(rm)) };
        Record::sign(b, &s_).unwrap()
    };
    // Signed again with the current seen, T's later records would stay.
    let mut naive = G { root: k("root"), gid: g.gid, heads: g.heads.clone(), recs: g.recs.clone() };
    let r = sign_at_one(&mut naive, Removal { keys: rm.keys.clone(), seen: current.clone() });
    naive.push(r);
    let s = naive.state();
    assert!(s.revoked.contains(&t.hash) && later.iter().all(|r| s.counting.contains(&r.id())));
    let r = sign_at_one(&mut g, rm.signed_again(&current));
    g.push(r);
    let s = g.state();
    assert!(s.revoked.contains(&t.hash) && !s.two_histories(&s_.hash));
    assert!(later.iter().all(|r| !s.counting.contains(&r.id())));
}

/// An admin that removes its own key: nothing that key signs after the
/// removal counts.
#[test]
fn an_admin_removing_its_own_key_signs_nothing_after() {
    let mut g = G::new();
    let (pa, a) = (k("phone a"), k("admin a"));
    g.admin(&pa, &a, POWER_ADMIT | POWER_REMOVE | POWER_REMOVE_ADMINS);
    let d = g.device(&a, &k("d"), "d", |_| {});
    let before = g.state();
    assert!(before.counting.contains(&d.id()));
    let own = g.rec(&a, Kind::Revoke(removal(&[a.hash], g.seen())));
    let late = g.device(&a, &k("late"), "late", |_| {});
    let rv = g.rec(&a, Kind::Revoke(removal(&[k("d").hash], g.seen())));
    let s = g.state();
    assert!(s.revoked.contains(&a.hash) && s.counting.contains(&own.id()));
    assert!(s.counting.contains(&d.id()) && !s.revoked.contains(&k("d").hash));
    assert!(!s.counting.contains(&late.id()) && !s.counting.contains(&rv.id()));
    assert!(s.device(&k("late").key.device_id()).is_none());
}

/// A root's removal is final: its resolve does not bring the device back.
#[test]
fn a_roots_removal_is_final() {
    let mut g = G::new();
    g.device(&k("root"), &k("d"), "d", |_| {});
    let rv = g.root_rec(Kind::Revoke(removal(&[k("d").hash], g.seen())));
    assert!(g.state().revoked.contains(&k("d").hash));
    g.root_rec(Kind::Resolve(vec![rv.id()]));
    let s = g.state();
    assert!(s.revoked.contains(&k("d").hash) && s.counting.contains(&rv.id()));
    assert!(s.id_taken(&k("d").key.device_id()) && s.device(&k("d").key.device_id()).is_none());
}

/// The root voids an admin's removal: the device counts again, with its
/// key and ID.
#[test]
fn the_root_voids_an_admins_removal() {
    let mut g = G::new();
    let (pa, a) = (k("phone a"), k("admin a"));
    g.admin(&pa, &a, POWER_ADMIT | POWER_REMOVE);
    let d = g.device(&k("root"), &k("d"), "d", |_| {});
    let rv = g.rec(&a, Kind::Revoke(removal(&[k("d").hash], g.seen())));
    assert!(g.state().revoked.contains(&k("d").hash));
    g.root_rec(Kind::Resolve(vec![rv.id()]));
    let s = g.state();
    assert!(!s.revoked.contains(&k("d").hash) && !s.counting.contains(&rv.id()));
    assert!(s.counting.contains(&d.id()) && s.device(&k("d").key.device_id()).is_some());
}

/// An old root's removal after a claim's seen does not survive the
/// takeover: a root that does not cancel the claim within the delay loses
/// what it signed after the seen, and the device counts again under the
/// new root.
#[test]
fn an_old_roots_late_removal_ends_with_the_takeover() {
    let mut g = G::new();
    let (pa, a, laptop, n) = (k("phone a"), k("admin a"), k("laptop"), k("new root"));
    g.admin(&pa, &a, POWER_TAKEOVER);
    let ld = g.device(&k("root"), &laptop, "laptop", |_| {});
    let seen = g.seen();
    let c = g.rec(&a, Kind::Claim { root: n.key.clone(), seen });
    let rv = g.root_rec(Kind::Revoke(removal(&[laptop.hash], g.seen())));
    let s = g.state();
    assert_eq!(s.claims[0].state, ClaimState::Pending);
    assert!(s.revoked.contains(&laptop.hash));
    let held = BTreeMap::from([(c.id(), DEFAULT_DELAY_MS)]);
    let s = state_of(&g.root.key, &g.recs, &held);
    assert_eq!(s.roots, vec![g.root.hash, n.hash]);
    assert!(!s.counting.contains(&rv.id()) && !s.revoked.contains(&laptop.hash));
    assert!(s.counting.contains(&ld.id()) && s.device(&laptop.key.device_id()).is_some());
}

/// Any os number is taken: 11 (harmonyos) and a later version's 12 are
/// kept and count, never refused or held.
#[test]
fn any_os_number_is_taken() {
    let mut g = G::new();
    for (i, os) in [11u64, 12, 9_999].into_iter().enumerate() {
        let r = g.device(&k("root"), &k(&format!("o{i}")), "o", |d| d.os = os);
        let s = g.state();
        assert!(s.counting.contains(&r.id()), "os {os}");
    }
}

/// What a command's receiver asks of the state: a key with two histories,
/// a removed or frozen admin, and every admin during a full stop sign no
/// command; the root does.
#[test]
fn who_may_command() {
    let mut g = G::new();
    let (pa, a, pb, b, pc, c) = (k("phone a"), k("admin a"), k("phone b"), k("admin b"), k("phone c"), k("admin c"));
    let (pd, d) = (k("phone d"), k("admin d"));
    g.admin(&pa, &a, POWER_TAKEOVER);
    g.admin(&pb, &b, POWER_TAKEOVER | POWER_FREEZE);
    g.admin(&pc, &c, 0);
    g.admin(&pd, &d, POWER_TAKEOVER);
    let s = g.state();
    assert!(s.may_command(&g.root.hash) && s.may_command(&a.hash) && s.may_command(&c.hash));
    assert!(!s.may_command(&k("stranger").hash));
    // Two histories of c.
    g.rec(&c, Kind::Copies { incoming_ms: 6_000, seen: vec![] });
    let twin = Body { seq: 1, prev: None, ..g.body(&c, Kind::Copies { incoming_ms: 7_000, seen: vec![] }) };
    g.push(Record::sign(twin, &c).unwrap());
    let s = g.state();
    assert!(s.two_histories(&c.hash) && !s.may_command(&c.hash) && s.may_command(&a.hash));
    // A freeze of a.
    let seen = g.seen();
    g.rec(&b, Kind::Freeze(removal(&[a.hash], seen)));
    assert!(!g.state().may_command(&a.hash));
    // Competing claims: a full stop; only the root commands.
    let seen = g.seen();
    g.rec(&b, Kind::Claim { root: k("nb").key.clone(), seen: seen.clone() });
    g.rec(&d, Kind::Claim { root: k("nd").key.clone(), seen });
    let s = g.state();
    assert_eq!(s.stop, Stop::Full);
    assert!(s.may_command(&g.root.hash) && !s.may_command(&b.hash));
}

/// A huge time field changes no order and no result: time is for display.
/// (b's records see a's, so the ID, which the time changes, decides
/// nothing either.)
#[test]
fn a_huge_time_changes_nothing() {
    let build = |time: u64| {
        let mut g = G::new();
        let (pa, a, pb, b) = (k("phone a"), k("admin a"), k("phone b"), k("admin b"));
        g.admin(&pa, &a, POWER_HUB | POWER_ADMIT);
        g.admin(&pb, &b, POWER_HUB | POWER_ADMIT);
        g.device(&k("root"), &k("hub"), "hub", |d| d.rights |= RIGHT_HUB);
        g.device(&k("root"), &k("hub2"), "hub2", |d| d.rights |= RIGHT_HUB);
        let (h1, h2) = (k("hub").key.device_id(), k("hub2").key.device_id());
        for (by, kind) in [
            (&a, Kind::Hubs { hubs: vec![h1.min(h2), h1.max(h2)], seen: vec![] }),
            (&b, Kind::Hubs { hubs: vec![h1.min(h2)], seen: vec![] }),
            (&a, Kind::Copies { incoming_ms: 5_000, seen: vec![] }),
            (&b, Kind::Copies { incoming_ms: 3_600_000, seen: vec![] }),
        ] {
            let saw = g.seen();
            let kind = match kind {
                Kind::Hubs { hubs, .. } if by.hash == b.hash => Kind::Hubs { hubs, seen: saw },
                Kind::Copies { incoming_ms, .. } if by.hash == b.hash => Kind::Copies { incoming_ms, seen: saw },
                kind => kind,
            };
            let mut body = g.body(by, kind);
            if by.hash == b.hash {
                body.time_ms = time;
            }
            let r = Record::sign(body, by).unwrap();
            g.push(r);
        }
        g.state()
    };
    let (plain, huge) = (build(0), build(crate::format::cbor::MAX_INT));
    assert_eq!(plain.hubs, huge.hubs);
    assert_eq!(plain.incoming_ms, huge.incoming_ms);
    assert_eq!(plain.devices, huge.devices);
    assert_eq!(plain.counting.len(), huge.counting.len());
}

/// The recovery key signs a claim and nothing else.
#[test]
fn the_recovery_key_only_claims() {
    let mut g = G::new();
    let rk = k("recovery");
    g.root_rec(Kind::Recovery { admin: rk.key.clone() });
    let copies = g.rec(&rk, Kind::Copies { incoming_ms: 3_600_000, seen: vec![] });
    let s = g.state();
    assert!(!s.counting.contains(&copies.id()) && s.incoming_ms.is_none());
    let seen = g.seen();
    let claim = g.rec(&rk, Kind::Claim { root: k("n").key.clone(), seen });
    assert!(g.state().counting.contains(&claim.id()));
}

/// A device ID any kept device record names is taken, a removed device's
/// included, even after a checkpoint pruned its record.
#[test]
fn a_removed_devices_id_stays_taken() {
    let mut g = G::new();
    let root = k("root");
    let (old, other) = (k("old"), k("other"));
    let rec = g.device(&root, &old, "old", |_| {});
    g.device(&root, &other, "other", |_| {});
    let seen = g.seen();
    g.root_rec(Kind::Revoke(removal(&[old.hash], seen)));
    let s = g.state();
    assert!(s.device(&old.key.device_id()).is_none());
    assert!(s.id_taken(&old.key.device_id()) && s.id_taken(&other.key.device_id()));
    assert!(!s.id_taken(&k("new").key.device_id()));
    let (seq, id) = g.heads[&root.hash];
    g.root_rec(Kind::Checkpoint { heads: vec![Head { key: root.hash, seq, id }], keep: vec![] });
    let mut set = RecordSet::new(g.root.key.clone());
    set.insert_all(g.recs.clone());
    let st = set.state(&BTreeMap::new());
    assert!(set.compact(&st) > 0 && !set.contains(&rec.id()));
    assert!(set.state(&BTreeMap::new()).id_taken(&old.key.device_id()));
}

/// The three kinds of admin give fixed powers and commands, and the rules
/// hold each to them.
#[test]
fn the_three_kinds_of_admin() {
    use AdminKind::*;
    let bits = |ts: &[u64]| ts.iter().fold(0, |b, &t| b | command_bit(t));
    let all = bits(&(COMMAND_MODE..=COMMAND_DEVICE).collect::<Vec<_>>());
    assert_eq!(
        Watch.grants(),
        (
            POWER_REMOVE | POWER_FREEZE,
            bits(&[COMMAND_PASTE_OFF, COMMAND_ACTIONS_OFF, COMMAND_AWAY_OFF, COMMAND_ACTION])
        )
    );
    assert_eq!(Computer.grants(), (POWER_ADMIT | POWER_MANAGE | POWER_REMOVE | POWER_FREEZE | POWER_HUB, all));
    assert_eq!(Phone.grants().0, Computer.grants().0 | POWER_REMOVE_ADMINS | POWER_THAW | POWER_TAKEOVER);
    assert_eq!(Phone.grants().1, all);
    assert_eq!(all, 0x3ff);
    for kind in [Watch, Computer, Phone] {
        assert_eq!(kind.grants().0 & POWER_PERIODS, 0);
    }
    let mut g = G::new();
    let root = k("root");
    let admin = |g: &mut G, who: &str, kind: AdminKind| {
        let (p, a) = (k(&format!("phone {who}")), k(&format!("admin {who}")));
        g.device(&root, &p, who, |d| {
            d.admin = Some(a.key.clone());
            (d.powers, d.commands) = kind.grants();
            if kind == Watch {
                d.role = ROLE_WATCH;
            }
        });
        a
    };
    let (h, a, s_) = (admin(&mut g, "h", Watch), admin(&mut g, "a", Computer), admin(&mut g, "s", Phone));
    let laptop = k("laptop");
    g.device(&root, &laptop, "laptop", |_| {});
    let by_helper = g.device(&h, &k("w1"), "w1", |_| {});
    let by_admin = g.device(&a, &k("w2"), "w2", |_| {});
    let seen = g.seen();
    let removal = g.rec(&h, Kind::Revoke(removal(&[laptop.hash], seen.clone())));
    let claim_a = g.rec(&a, Kind::Claim { root: k("na").key.clone(), seen: seen.clone() });
    let claim_s = g.rec(&s_, Kind::Claim { root: k("ns").key.clone(), seen });
    let st = g.state();
    assert!(!st.counting.contains(&by_helper.id()) && st.counting.contains(&by_admin.id()));
    assert!(st.counting.contains(&removal.id()));
    assert!(!st.counting.contains(&claim_a.id()) && st.claims.iter().any(|c| c.record == claim_s.id()));
}

/// A computer admin never takes the group over, whatever the root is: a
/// group with no phone is taken over with its recovery key alone.
#[test]
fn only_a_phone_admin_or_the_recovery_key_takes_over() {
    let mut g = G::new();
    let (pc, c, rk) = (k("computer"), k("computer admin"), k("recovery"));
    g.device(&k("root"), &pc, "computer", |d| {
        d.admin = Some(c.key.clone());
        (d.powers, d.commands) = AdminKind::Computer.grants();
    });
    g.root_rec(Kind::Recovery { admin: rk.key.clone() });
    let seen = g.seen();
    let by_computer = g.rec(&c, Kind::Claim { root: k("nc").key.clone(), seen: seen.clone() });
    let s = g.state();
    assert!(!s.counting.contains(&by_computer.id()));
    assert!(s.claims.iter().all(|cl| cl.record != by_computer.id() || cl.state == ClaimState::Void));
    assert_eq!(s.stop, Stop::None);
    let by_recovery = g.rec(&rk, Kind::Claim { root: k("nr").key.clone(), seen });
    let held = BTreeMap::from([(by_recovery.id(), DEFAULT_DELAY_MS)]);
    let s = state_of(&g.root.key, &g.recs, &held);
    assert_eq!(s.roots, vec![g.root.hash, k("nr").hash]);
}

/// A pool of records that touches every rule: admins, devices, removals,
/// a freeze and a thaw, two histories, claims, held records, settings.
/// A full set never drops a root's removal or resolve: 16 admin keys fill
/// their 256 units each, the root signs some 300 records after them, and
/// its removal and its resolve at the end still count.
#[test]
fn a_full_set_keeps_the_roots_removals() {
    let mut g = G::new();
    let root = k("root");
    let d = k("d");
    g.device(&root, &d, "d", |_| {});
    let admins: Vec<K> = (0..16).map(|i| k(&format!("a{i}"))).collect();
    for (i, a) in admins.iter().enumerate() {
        g.admin(&k(&format!("p{i}")), a, POWER_ADMIT | POWER_REMOVE);
    }
    let e = g.device(&admins[0], &k("e"), "e", |_| {});
    let rv_e = g.rec(&admins[0], Kind::Revoke(removal(&[k("e").hash], g.seen())));
    for a in &admins {
        for i in g.heads.get(&a.hash).map_or(0, |h| h.0)..300 {
            g.rec(a, Kind::Copies { incoming_ms: 5_000 + i, seen: vec![] });
        }
    }
    let below: Vec<Record> =
        (0..300).map(|i| g.root_rec(Kind::Copies { incoming_ms: 5_000 + i, seen: vec![] })).collect();
    let rv_d = g.root_rec(Kind::Revoke(removal(&[d.hash], g.seen())));
    let resolve = g.root_rec(Kind::Resolve(vec![rv_e.id()]));
    let mut set = RecordSet::new(g.root.key.clone());
    set.insert_all(g.recs.clone());
    assert!(set.len() < g.recs.len());
    assert!(set.contains(&rv_d.id()) && set.contains(&resolve.id()));
    // The root's records right under them are dropped: the removal stands
    // for its chain.
    assert!(!set.contains(&below[299].id()));
    for s in [set.state(&BTreeMap::new()), g.state()] {
        assert!(s.revoked.contains(&d.hash), "the root's removal counts");
        assert!(s.counting.contains(&rv_d.id()) && s.counting.contains(&resolve.id()));
        assert!(!s.revoked.contains(&k("e").hash) && s.counting.contains(&e.id()), "the root's resolve counts");
    }
}

/// A root's removal counts without the records under it, but an ordinary
/// root record above a gap waits for the gap to fill.
#[test]
fn a_roots_removal_counts_by_itself_and_nothing_above_it() {
    let mut g = G::new();
    let root = k("root");
    g.device(&root, &k("d"), "d", |_| {});
    g.device(&root, &k("x"), "x", |_| {});
    let third = g.device(&root, &k("y"), "y", |_| {});
    g.root_rec(Kind::Copies { incoming_ms: 6_000, seen: vec![] });
    let rv = g.root_rec(Kind::Revoke(removal(&[k("d").hash], g.seen())));
    let sixth = g.device(&root, &k("z"), "z", |_| {});
    let held = BTreeMap::new();
    let without: Vec<Record> = g.recs.iter().filter(|r| r.id() != third.id()).cloned().collect();
    let s = state_of(&g.root.key, &without, &held);
    assert!(s.revoked.contains(&k("d").hash) && s.counting.contains(&rv.id()));
    assert!(!s.counting.contains(&sixth.id()) && s.device(&k("z").key.device_id()).is_none());
    let want = g.state();
    assert!(want.counting.contains(&sixth.id()) && want.revoked.contains(&k("d").hash));
    for seed in 1..6 {
        let mut set = RecordSet::new(g.root.key.clone());
        set.insert_all(shuffled(&g.recs, seed));
        assert_eq!(set.state(&held), want, "order {seed}");
    }
}

/// The same records in an order of seed.
fn shuffled(recs: &[Record], seed: u64) -> Vec<Record> {
    let mut out = recs.to_vec();
    let mut s = seed;
    for i in (1..out.len()).rev() {
        s = s.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        out.swap(i, (s >> 33) as usize % (i + 1));
    }
    out
}

/// More keys than the set has room for, each up to its ceiling: what the
/// set keeps is the same whatever order the records come in, also while
/// the units it stores fit.
#[test]
fn a_full_set_keeps_the_same_records_in_any_order() {
    let mut g = G::new();
    let admins: Vec<K> = (0..18).map(|i| k(&format!("a{i}"))).collect();
    for (i, a) in admins.iter().enumerate() {
        g.admin(&k(&format!("p{i}")), a, POWER_ADMIT);
    }
    for (i, a) in admins.iter().enumerate() {
        for j in 0..(200 + 10 * i) {
            g.rec(a, Kind::Copies { incoming_ms: 5_000 + j as u64, seen: vec![] });
        }
    }
    let mut want = RecordSet::new(g.root.key.clone());
    want.insert_all(g.recs.clone());
    assert!(want.len() < g.recs.len());
    for seed in 1..3 {
        let mut set = RecordSet::new(g.root.key.clone());
        set.insert_all(shuffled(&g.recs, seed));
        assert_eq!(set.digest(), want.digest(), "order {seed}");
    }
    // And it is what the evaluation of all the records keeps.
    let strip = |s: &State| State { ignored: Vec::new(), ..s.clone() };
    assert_eq!(strip(&want.state(&BTreeMap::new())), strip(&g.state()));
}

fn pool() -> (Key, Vec<Record>) {
    let mut g = G::new();
    let root = k("root");
    let (pa, a, pb, b, pc, c) = (k("pa"), k("a"), k("pb"), k("b"), k("pc"), k("c"));
    g.admin(&pa, &a, POWER_ADMIT | POWER_REMOVE | POWER_TAKEOVER);
    g.admin(&pb, &b, POWER_ADMIT | POWER_MANAGE | POWER_FREEZE | POWER_REMOVE_ADMINS);
    g.admin(&pc, &c, POWER_TAKEOVER | POWER_THAW | POWER_REMOVE_ADMINS);
    for i in 0..3 {
        g.device(&root, &k(&format!("r{i}")), "r", |_| {});
    }
    for i in 0..5 {
        g.device(&a, &k(&format!("x{i}")), "x", |_| {});
    }
    g.device(&b, &k("x0"), "x0 by b", |d| d.rights = RIGHT_READ);
    let seen = g.seen();
    g.rec(&a, Kind::Revoke(removal(&[k("r1").hash], seen.clone())));
    let f = g.rec(&b, Kind::Freeze(removal(&[a.hash], seen.clone())));
    g.rec(&c, Kind::Thaw { ids: vec![f.id()], seen: vec![] });
    g.rec(&a, Kind::Claim { root: k("na").key.clone(), seen: seen.clone() });
    g.rec(&c, Kind::Claim { root: k("nc").key.clone(), seen });
    // A second history of b at its last seq.
    let mut twin = g.body(&b, Kind::Copies { incoming_ms: 9_000, seen: vec![] });
    twin.seq -= 1;
    twin.prev = g.recs.iter().find(|r| r.body().signer == b.hash && r.body().seq == twin.seq - 1).map(|r| r.id());
    g.push(Record::sign(twin, &b).unwrap());
    g.rec(&b, Kind::Hubs { hubs: vec![k("r0").key.device_id()], seen: vec![] });
    let mut held = g.body(&root, Kind::Unknown(77));
    held.held = true;
    let bytes = held.encode();
    let sig = key::sign_es256(&root, LABEL_RECORD, &bytes).unwrap();
    g.push(Record::from_parts(bytes, sig.to_vec(), None, held).unwrap());
    g.device(&k("na"), &k("na phone"), "na phone", |_| {});
    (g.root.key.clone(), g.recs)
}

mod props {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #![proptest_config(ProptestConfig { cases: 32, failure_persistence: None, ..ProptestConfig::default() })]

        /// Any order of one set, and any order of putting it into a set,
        /// gives one kept set and one state.
        #[test]
        fn any_order_one_state(seed in any::<u64>(), drop in 0usize..40, held_ms in prop::sample::select(vec![0u64, DEFAULT_DELAY_MS])) {
            let (root, recs) = pool();
            let held = recs.iter().filter(|r| matches!(r.body().kind, Kind::Claim { .. })).map(|r| (r.id(), held_ms)).collect();
            // A subset, the same for both orders.
            let sub: Vec<Record> = recs.iter().enumerate().filter(|(i, _)| *i != drop).map(|(_, r)| r.clone()).collect();
            let want = state_of(&root, &sub, &held);
            let mut shuffled = sub.clone();
            let mut s = seed;
            for i in (1..shuffled.len()).rev() {
                s = s.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
                shuffled.swap(i, (s >> 33) as usize % (i + 1));
            }
            prop_assert_eq!(&state_of(&root, &shuffled, &held), &want);
            let mut a = RecordSet::new(root.clone());
            a.insert_all(sub);
            let mut b = RecordSet::new(root.clone());
            b.insert_all(shuffled);
            prop_assert_eq!(a.digest(), b.digest());
            // evaluate acts as a member that has compacted: one that keeps
            // nothing of an old root off its takeover's cut.
            let st = a.state(&held);
            a.compact(&st);
            let st = b.state(&held);
            b.compact(&st);
            prop_assert_eq!(a.digest(), b.digest());
            // The set refuses what it cannot verify; its state is that of
            // the records it kept.
            let kept: Vec<Record> = a.ids().map(|id| a.get(id).unwrap().clone()).collect();
            prop_assert_eq!(a.counted(), b.counted());
            let stored = evaluate(&Input { root: &root, records: &kept, held_ms: &held, counted: a.counted_claims() });
            prop_assert_eq!(&a.state(&held), &stored);
            prop_assert_eq!(&b.state(&held), &stored);
            let strip = |s: &State| State { ignored: Vec::new(), ..s.clone() };
            // The claims the set counted are final for it, on its whole
            // set too.
            let sub: Vec<Record> = recs.iter().enumerate().filter(|(i, _)| *i != drop).map(|(_, r)| r.clone()).collect();
            let whole = evaluate(&Input { root: &root, records: &sub, held_ms: &held, counted: a.counted_claims() });
            prop_assert_eq!(strip(&stored), strip(&whole));
            prop_assert_eq!(strip(&stored).roots, want.roots);
        }
    }
}

mod vectors {
    use std::path::PathBuf;

    use serde_json::Value as Json;

    use super::*;

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    fn records() -> Json {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../testdata/format/records.json");
        serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
    }

    /// Every record the format's vectors take reads, held where they say
    /// so, and writes back to the same bytes; every one they refuse is
    /// refused by the rule they name, all but the signature and the group,
    /// which the set checks.
    #[test]
    fn records_read_as_the_vectors_say() {
        let v = records();
        for t in v["take"].as_array().unwrap() {
            let name = t["name"].as_str().unwrap();
            let env = unhex(t["envelope"].as_str().unwrap());
            let r = Record::decode(&env).unwrap_or_else(|e| panic!("{name}: {e}"));
            assert_eq!(r.id().0.to_vec(), unhex(t["id"].as_str().unwrap()), "{name}");
            assert_eq!(r.envelope(), env, "{name}");
            let held = r.body().check().unwrap();
            assert_eq!(held, t["verdict"] == "hold", "{name}");
            // A body writes back to its bytes, but for the optional fields
            // a reader skips.
            let optional =
                crate::format::cbor::decode(r.body_bytes()).unwrap().as_map().unwrap().iter().any(|(k, _)| *k >= 256);
            if !held && !optional {
                assert_eq!(r.body().encode(), r.body_bytes(), "{name}");
            }
            if let Some(os) = t["os"].as_u64() {
                assert!(matches!(&r.body().kind, Kind::Device(d) if d.os == os), "{name}");
            }
        }
        let mut refused = 0;
        for t in v["refuse"].as_array().unwrap() {
            let (name, rule) = (t["name"].as_str().unwrap(), t["rule"].as_str().unwrap());
            if rule == "sig/verify" || rule == "records/group" {
                continue;
            }
            let env = unhex(t["envelope"].as_str().unwrap());
            let got = Record::decode(&env).map(|_| ()).unwrap_err();
            assert_eq!(got.to_string(), rule, "{name}");
            refused += 1;
        }
        assert!(refused > 20);
    }

    /// Settings' field 13 (the working limit, gone) is refused on reading.
    #[test]
    fn settings_field_13_is_refused() {
        let v = records();
        let t = v["refuse"]
            .as_array()
            .unwrap()
            .iter()
            .find(|t| t["rule"] == "form/critical" && t["name"].as_str().unwrap().starts_with("settings"))
            .unwrap();
        let got = Record::decode(&unhex(t["envelope"].as_str().unwrap())).map(|_| ()).unwrap_err();
        assert!(got.is("form/critical"));
    }
}

/// A `seen` list names each key once, whatever the seqs.
#[test]
fn seen_names_each_key_once() {
    let g = G::new();
    let a = k("a").hash;
    let twice = vec![Seen { key: a, seq: 2, id: RecordId([2; 32]) }, Seen { key: a, seq: 3, id: RecordId([3; 32]) }];
    let body = g.body(&k("root"), Kind::Revoke(removal(&[a], twice.clone())));
    assert!(body.check().unwrap_err().is("records/revoke/seen"));
    let body = g.body(&k("root"), Kind::Claim { root: k("n").key.clone(), seen: twice });
    assert!(body.check().unwrap_err().is("records/claim/seen"));
}

/// Two removals of an admin's own key, whatever they saw: the first
/// counts, the second is cut off by it, and the group goes on.
#[test]
fn two_removals_of_ones_own_key() {
    let mut g = G::new();
    let (pw, w, pa, a) = (k("watch"), k("admin w"), k("phone a"), k("admin a"));
    let (watch, _) = AdminKind::Watch.grants();
    let (phone, _) = AdminKind::Phone.grants();
    g.admin(&pw, &w, watch);
    g.admin(&pa, &a, phone);
    let f1 = g.rec(&w, Kind::Freeze(removal(&[w.hash], vec![])));
    let f2 = g.rec(&w, Kind::Freeze(removal(&[w.hash], vec![])));
    let s = g.state();
    assert_eq!(s.stop, Stop::None);
    assert!(s.conflicts.is_empty());
    assert!(s.counting.contains(&f1.id()) && !s.counting.contains(&f2.id()));
    assert!(s.may_command(&a.hash) && !s.may_command(&w.hash));
}

/// A record of by with kind, its body's map edited before it is signed.
fn raw(
    g: &G,
    by: &K,
    kind: Kind,
    edit: impl FnOnce(&mut Vec<(u16, crate::format::cbor::Value<'static>)>),
) -> Result<Record, Rule> {
    let plain: &'static [u8] = Box::leak(g.body(by, kind).encode().into_boxed_slice());
    let map = crate::format::decode(plain).unwrap();
    let mut entries = map.as_map().unwrap().to_vec();
    edit(&mut entries);
    entries.sort_by_key(|(k, _)| *k);
    let bytes = crate::format::cbor::Value::Map(entries).encode();
    let sig = key::sign_es256(by, LABEL_RECORD, &bytes).unwrap();
    Record::decode(&crate::format::envelope::write(&bytes, &sig, None))
}

/// Settings take each value of their rows only: a level or a rules
/// version of 0 is refused, the default written out too.
#[test]
fn settings_take_only_the_values_of_their_rows() {
    let g = G::new();
    let root = k("root");
    let plain = Settings::default();
    for (field, value, rule) in [
        (11u16, 0u64, "records/settings/key_level"),
        (12, 0, "records/settings/min_rules"),
        (11, 2, "form/default"),
        (12, 1, "form/default"),
    ] {
        let r =
            raw(&g, &root, Kind::Settings(plain.clone()), |m| m.push((field, crate::format::cbor::Value::Uint(value))));
        assert_eq!(r.map(|_| ()).unwrap_err().to_string(), rule, "{field} = {value}");
    }
    let ok = raw(&g, &root, Kind::Settings(plain), |m| m.push((11, crate::format::cbor::Value::Uint(3)))).unwrap();
    assert_eq!(ok.body().encode(), ok.body_bytes());
}

/// Every record the rules' tests make reads back from its envelope as the
/// same record.
#[test]
fn records_read_back_from_their_envelopes() {
    let (_, recs) = pool();
    for r in &recs {
        let back = Record::decode(&r.envelope()).unwrap();
        assert_eq!(&back, r);
    }
    // Not a record: a broken envelope, a body that is not a map.
    assert!(Record::decode(&[0x80]).unwrap_err().is("env/shape"));
}

/// One body with `signer2` in two envelopes whose second signatures differ
/// in length: both count the same, so two members keep the same set.
#[test]
fn a_record_counts_the_same_in_every_envelope() {
    let mut g = G::new();
    let (pa, a) = (k("phone a"), k("admin a"));
    g.admin(&pa, &a, POWER_ADMIT | POWER_REMOVE);
    g.device(&k("root"), &k("laptop"), "laptop", |_| {});
    let base = g.recs.clone();
    let second = [7u8; 32];
    let plain: &'static [u8] =
        Box::leak(g.body(&a, Kind::Copies { incoming_ms: 60_000, seen: vec![] }).encode().into_boxed_slice());
    let mut entries = crate::format::decode(plain).unwrap().as_map().unwrap().to_vec();
    entries.push((8, crate::format::cbor::Value::Bytes(&second)));
    let bytes = crate::format::cbor::Value::Map(entries).encode();
    let sig = key::sign_es256(&a, LABEL_RECORD, &bytes).unwrap();
    let two = |n: usize| Record::decode(&crate::format::envelope::write(&bytes, &sig, Some(&vec![0x55u8; n]))).unwrap();
    let max = crate::format::envelope::MAX_SIG2;
    let (short, long) = (two(1), two(max));
    assert!(
        Record::decode(&crate::format::envelope::write(&bytes, &sig, Some(&vec![0x55u8; max + 1])))
            .unwrap_err()
            .is("env/sig2")
    );
    assert_eq!(short.id(), long.id());
    assert_eq!(short.size(), long.size());
    assert_eq!(short.size(), bytes.len() + ENVELOPE_ALLOWANCE + SIG2_ALLOWANCE);
    g.push(short.clone());
    let mut later = Vec::new();
    for i in 0..200 {
        later.push(g.device(&a, &k(&format!("x{i}")), "x", |_| {}));
    }
    let seen = g.seen();
    later.push(g.rec(&a, Kind::Revoke(removal(&[k("laptop").hash], seen))));
    let mut m1 = RecordSet::new(g.root.key.clone());
    let mut m2 = RecordSet::new(g.root.key.clone());
    m1.insert_all(base.iter().cloned().chain([short]).chain(later.iter().cloned()));
    m2.insert_all(base.iter().cloned().chain([long]).chain(later.iter().cloned()));
    assert_eq!(m1.len(), m2.len());
    assert_eq!(m1.digest(), m2.digest());
    assert_eq!(m1.state(&BTreeMap::new()), m2.state(&BTreeMap::new()));
}

/// A group whose admin A took it over to the new root N, which then
/// recorded its phone and removed the device "gone".
fn taken_over_group() -> (G, BTreeMap<RecordId, u64>, Record) {
    let mut g = G::new();
    let all = POWER_ADMIT | POWER_MANAGE | POWER_REMOVE | POWER_REMOVE_ADMINS | POWER_FREEZE | POWER_TAKEOVER;
    let (pa, a, pt, t, n) = (k("phone a"), k("admin a"), k("phone t"), k("admin t"), k("new root"));
    g.admin(&pa, &a, all);
    g.admin(&pt, &t, all);
    g.device(&k("root"), &k("laptop"), "laptop", |_| {});
    g.device(&k("root"), &k("gone"), "gone", |_| {});
    let seen = g.seen();
    let claim = g.rec(&a, Kind::Claim { root: n.key.clone(), seen });
    g.device(&n, &k("new phone"), "new phone", |d| d.holds_root = true);
    let seen = g.seen();
    g.rec(&n, Kind::Revoke(removal(&[k("gone").hash], seen)));
    let held = BTreeMap::from([(claim.id(), DEFAULT_DELAY_MS)]);
    let s = state_of(&g.root.key, &g.recs, &held);
    assert_eq!(s.roots, vec![g.root.hash, n.hash]);
    assert!(s.revoked.contains(&k("gone").hash));
    (g, held, claim)
}

fn counted_state(g: &G, held: &BTreeMap<RecordId, u64>, counted: &[RecordId]) -> State {
    let counted = Counted::chain(&g.root.hash, counted, |id| g.recs.iter().find(|r| r.id() == *id));
    evaluate(&Input { root: &g.root.key, records: &g.recs, held_ms: held, counted: &counted })
}

/// A takeover the device counted stays: the old root's later resolve of
/// the claim does not count there. A device that had not counted it yet
/// takes the resolve as a cancel, as before.
#[test]
fn a_counted_takeover_is_final_on_the_device() {
    let (mut g, held, claim) = taken_over_group();
    let n = k("new root");
    let late = g.root_rec(Kind::Resolve(vec![claim.id()]));
    let s = counted_state(&g, &held, &[claim.id()]);
    assert_eq!(s.roots, vec![g.root.hash, n.hash]);
    assert!(!s.counting.contains(&late.id()));
    assert!(s.revoked.contains(&k("gone").hash));
    assert_eq!(s.claims.iter().find(|c| c.record == claim.id()).map(|c| c.state), Some(ClaimState::Effective));
    // A peer that has not counted it does not disagree; one that counted
    // another owner does.
    assert!(!s.disagrees(&[g.root.hash]) && s.disagrees(&[g.root.hash, k("other root").hash]));
    // Not counted yet: the resolve cancels it.
    let s = counted_state(&g, &held, &[]);
    assert_eq!(s.roots, vec![g.root.hash]);
    assert_eq!(s.claims.iter().find(|c| c.record == claim.id()).map(|c| c.state), Some(ClaimState::Cancelled));
    // A set remembers what it counted when it compacts, and keeps it.
    let mut set = RecordSet::new(g.root.key.clone());
    set.insert_all(g.recs[..g.recs.len() - 1].iter().cloned());
    let st = set.state(&held);
    set.compact(&st);
    assert!(set.counted().contains(&claim.id()));
    // It keeps nothing of the old root above the cut.
    assert_eq!(set.insert(late.clone()), Ok(Added::NoRoom));
    assert!(!set.contains(&late.id()));
    let st = set.state(&held);
    assert_eq!(st.roots, vec![g.root.hash, n.hash]);
    assert!(!st.disagrees(&[g.root.hash]) && st.disagrees(&[g.root.hash, k("other root").hash]));
    set.compact(&st);
    assert_eq!(set.state(&held).roots.len(), 2);
    // A set that got the resolve before it counted takes the cancel.
    let mut first = RecordSet::new(g.root.key.clone());
    first.insert_all(g.recs.iter().cloned());
    let st = first.state(&held);
    first.compact(&st);
    assert!(first.counted().is_empty());
    assert_eq!(first.state(&held).roots, vec![g.root.hash]);
}

/// Under a counted takeover, a later claim of the old root's epoch is left
/// out: no competing claims, no stop, and the new root's removal of its
/// signer still counts.
#[test]
fn a_later_claim_does_not_rival_a_counted_takeover() {
    let (mut g, held, claim) = taken_over_group();
    let (t, n) = (k("admin t"), k("new root"));
    let seen = g.seen();
    let t_removed = g.rec(&n, Kind::Revoke(removal(&[t.hash, k("phone t").hash], seen)));
    let seen = vec![g.seen_at(&g.root.hash, 1)];
    let rival = g.rec(&t, Kind::Claim { root: k("other root").key.clone(), seen });
    let mut held2 = held.clone();
    held2.insert(rival.id(), DEFAULT_DELAY_MS);
    let s = counted_state(&g, &held2, &[claim.id()]);
    assert_eq!(s.roots, vec![g.root.hash, n.hash]);
    assert_eq!(s.stop, Stop::None);
    assert!(s.claims.iter().all(|c| c.state != ClaimState::Competing));
    assert!(s.counting.contains(&t_removed.id()) && s.revoked.contains(&t.hash));
    assert!(s.device(&k("gone").key.device_id()).is_none());
    // A peer that has not counted it does not disagree; one that counted
    // another owner does.
    assert!(!s.disagrees(&[g.root.hash]) && s.disagrees(&[g.root.hash, k("other root").hash]));
    // Not counted: the two claims compete, as before.
    let s = counted_state(&g, &held2, &[]);
    assert_eq!(s.stop, Stop::Full);
    assert_eq!(s.roots, vec![g.root.hash]);
}

/// The same records and the same counted claims give one state in any
/// order of arrival.
#[test]
fn counted_claims_give_one_state_in_any_order() {
    let (mut g, held, claim) = taken_over_group();
    let late = g.root_rec(Kind::Resolve(vec![claim.id()]));
    let seen = vec![g.seen_at(&g.root.hash, 1)];
    g.rec(&k("admin t"), Kind::Claim { root: k("other root").key.clone(), seen });
    let mut want = None;
    for turn in 0..6u64 {
        let mut recs = g.recs.clone();
        // A fixed shuffle per turn.
        recs.sort_by_key(|r| sha256(&[r.id().0.as_slice(), &turn.to_be_bytes()].concat()));
        let mut set = RecordSet::new(g.root.key.clone());
        assert_eq!(set.remember_counted([claim.id()]), Ok(()));
        set.insert_all(recs);
        let st = set.state(&held);
        assert!(!st.counting.contains(&late.id()));
        match &want {
            None => want = Some(st),
            Some(w) => assert_eq!(&st, w),
        }
    }
}

/// Checkpoints signed by a key a claim names, which is not on the path,
/// are not tried: the root's checkpoint still counts on a member that
/// compacted on it and on one that did not.
#[test]
fn only_the_path_roots_checkpoints_are_tried() {
    let mut g = G::new();
    let root = k("root");
    let (pw, w) = (k("watch"), k("admin w"));
    g.admin(&pw, &w, POWER_REMOVE | POWER_FREEZE | POWER_TAKEOVER);
    let mut ds = Vec::new();
    for i in 0..6 {
        ds.push(g.device(&root, &k(&format!("d{i}")), &format!("d{i}"), |_| {}));
    }
    let seen = g.seen();
    let rv = g.root_rec(Kind::Revoke(removal(&[w.hash, pw.hash], seen)));
    let (s, id) = g.heads[&root.hash];
    let mut keep: Vec<RecordId> = ds.iter().map(|r| r.id()).chain([rv.id()]).collect();
    keep.sort();
    let cp = g.root_rec(Kind::Checkpoint { heads: vec![Head { key: root.hash, seq: s, id }], keep });
    let late = g.device(&root, &k("late"), "late", |_| {});
    let mut a = RecordSet::new(g.root.key.clone());
    a.insert_all(g.recs.clone());
    let st = a.state(&BTreeMap::new());
    assert_eq!(st.checkpoint, Some(cp.id()));
    assert!(a.compact(&st) > 0);
    let mut b = RecordSet::new(g.root.key.clone());
    b.insert_all(g.recs.clone());
    let x = k("named root");
    let mut more = vec![
        Record::sign(Body { seq: 1, prev: None, ..g.body(&w, Kind::Claim { root: x.key.clone(), seen: vec![] }) }, &w)
            .unwrap(),
    ];
    for i in 0..8u64 {
        let body = Body {
            seq: MAX_SEQ - i,
            prev: Some(RecordId([9; 32])),
            ..g.body(
                &x,
                Kind::Checkpoint { heads: vec![Head { key: x.hash, seq: 1, id: RecordId([8; 32]) }], keep: vec![] },
            )
        };
        more.push(Record::sign(body, &x).unwrap());
    }
    a.insert_all(more.clone());
    b.insert_all(more);
    let (sa, sb) = (a.state(&BTreeMap::new()), b.state(&BTreeMap::new()));
    assert_eq!(sa.checkpoint, Some(cp.id()));
    assert_eq!(sb.checkpoint, Some(cp.id()));
    assert_eq!(sa.devices.len(), 7);
    assert!(sa.counting.contains(&late.id()));
    assert_eq!(sa.devices, sb.devices);
}

/// A takeover's cut names the old root's record: on a device that counted
/// the claim, a record the old root signs later at a seq the claim saw is
/// off that chain and does not count, nor does a resolve that hangs on it.
#[test]
fn a_takeover_s_cut_holds_the_old_root_to_the_chain_it_saw() {
    let (mut g, held, claim) = taken_over_group();
    let root = k("root");
    let n = k("new root");
    let before = counted_state(&g, &held, &[claim.id()]);
    let true_first = g.seen_at(&root.hash, 1).id;
    let other = k("other phone");
    let mut d = Device::new(other.key.clone(), "other", ROLE_PHONE);
    d.rights = RIGHT_READ | RIGHT_SEND | RIGHT_SECRETS;
    d.holds_root = true;
    let twin = Record::sign(Body { seq: 1, prev: None, ..g.body(&root, Kind::Device(d)) }, &root).unwrap();
    let resolve =
        Record::sign(Body { seq: 2, prev: Some(twin.id()), ..g.body(&root, Kind::Resolve(vec![true_first])) }, &root)
            .unwrap();
    g.recs.push(twin.clone());
    g.recs.push(resolve.clone());
    let s = counted_state(&g, &held, &[claim.id()]);
    assert_eq!(s.roots, vec![root.hash, n.hash]);
    assert!(!s.counting.contains(&twin.id()) && !s.counting.contains(&resolve.id()));
    assert!(s.device(&other.key.device_id()).is_none());
    assert_eq!(s.devices, before.devices);
}

/// A removal's seen names the head it saw: a record its key signs later
/// at a seq at or below it, off that chain, is cut off.
#[test]
fn a_record_off_the_chain_a_removal_saw_is_cut_off() {
    let mut g = G::new();
    let (pt, t) = (k("phone t"), k("admin t"));
    g.admin(&pt, &t, POWER_ADMIT | POWER_REMOVE);
    for name in ["d1", "d2"] {
        g.device(&k("root"), &k(name), name, |_| {});
    }
    let first = g.rec(&t, Kind::Revoke(removal(&[k("d1").hash], g.seen())));
    g.root_rec(Kind::Resolve(vec![first.id()]));
    let seen = g.seen();
    g.root_rec(Kind::Revoke(removal(&[t.hash, pt.hash], seen)));
    let s = g.state();
    assert!(s.revoked.contains(&t.hash) && s.device(&k("d1").key.device_id()).is_some());
    let again =
        Record::sign(Body { seq: 1, prev: None, ..g.body(&t, Kind::Revoke(removal(&[k("d2").hash], vec![]))) }, &t)
            .unwrap();
    g.recs.push(again.clone());
    let s = g.state();
    assert!(!s.counting.contains(&again.id()));
    assert!(s.device(&k("d2").key.device_id()).is_some());
}

/// Once a takeover counts, the old root keeps nothing above the claim's
/// cut and its checkpoints do not come first: large checkpoints it signs
/// later take none of its room, and its history stays.
#[test]
fn an_old_root_keeps_nothing_above_its_cut() {
    let (mut g, held, claim) = taken_over_group();
    let root = k("root");
    let mut m = RecordSet::new(g.root.key.clone());
    m.insert_all(g.recs.iter().cloned());
    let st = m.state(&held);
    m.compact(&st);
    assert_eq!(st.cuts.len(), 1);
    let before = m.state(&held);
    let history: Vec<RecordId> = g.recs.iter().filter(|r| r.body().signer == root.hash).map(Record::id).collect();
    let mut more = Vec::new();
    for i in 0..9u8 {
        let keep: Vec<RecordId> = (0..1900u32)
            .map(|j| {
                let mut id = [i; 32];
                id[..4].copy_from_slice(&j.to_be_bytes());
                RecordId(id)
            })
            .collect();
        let body = Body {
            seq: 1000 + u64::from(i),
            prev: Some(RecordId([7; 32])),
            ..g.body(
                &root,
                Kind::Checkpoint { heads: vec![Head { key: root.hash, seq: 1, id: RecordId([8; 32]) }], keep },
            )
        };
        more.push(Record::sign(body, &root).unwrap());
    }
    let (stored, _) = m.insert_all(more.clone());
    assert_eq!(stored, 0);
    assert!(history.iter().all(|id| m.contains(id)));
    let after = m.state(&held);
    assert_eq!(after.roots, before.roots);
    assert_eq!(after.devices, before.devices);
    // The same from evaluate, for a device that counted the claim.
    g.recs.extend(more);
    let s = counted_state(&g, &held, &[claim.id()]);
    assert_eq!(s.roots, before.roots);
    assert_eq!(s.devices, before.devices);
}

/// A root that only a claim names teaches no admin key: the keys its
/// device records name sign nothing a member keeps, so the root's own
/// records keep their room.
#[test]
fn a_named_root_teaches_no_admin_key() {
    let mut g = G::new();
    let (pw, w) = (k("watch"), k("admin w"));
    for i in 0..40 {
        g.device(&k("root"), &k(&format!("device {i}")), "device", |_| {});
    }
    g.admin(&pw, &w, POWER_REMOVE | POWER_FREEZE | POWER_TAKEOVER);
    let seen = g.seen();
    g.root_rec(Kind::Revoke(removal(&[w.hash, pw.hash], seen)));
    let honest = g.recs.clone();
    let n = k("named root");
    g.rec(&w, Kind::Claim { root: n.key.clone(), seen: Vec::new() });
    let mut named = Vec::new();
    for i in 0..16 {
        let x = k(&format!("named x {i}"));
        g.device(&n, &k("no device"), "x", |d| {
            d.admin = Some(x.key.clone());
            d.powers = POWER_ADMIT | POWER_TAKEOVER;
        });
        named.push(x);
    }
    for (i, x) in named.iter().enumerate() {
        let keys: Vec<KeyHash> = (0..200u32)
            .map(|j| {
                let mut h = [0u8; 32];
                h[..4].copy_from_slice(&j.to_be_bytes());
                h[4] = i as u8;
                KeyHash(h)
            })
            .collect();
        g.rec(x, Kind::Freeze(Removal { keys, seen: Vec::new() }));
        g.rec(x, Kind::Claim { root: k(&format!("named root {i}")).key.clone(), seen: Vec::new() });
    }
    let s = g.state();
    assert_eq!(s.devices.len(), 40);
    assert!(honest.iter().all(|r| s.counting.contains(&r.id())));
    let mut m1 = RecordSet::new(g.root.key.clone());
    m1.insert_all(g.recs.iter().cloned());
    let mut m2 = RecordSet::new(g.root.key.clone());
    m2.insert_all(g.recs.iter().rev().cloned());
    for m in [&m1, &m2] {
        assert!(honest.iter().all(|r| m.contains(&r.id())));
        assert!(m.ids().all(|id| named.iter().all(|x| m.get(id).unwrap().body().signer != x.hash)));
        assert_eq!(m.state(&BTreeMap::new()).devices.len(), 40);
    }
    assert_eq!(m1.digest(), m2.digest());
}

/// A key that is an admin key and a claim's root teaches nothing as a
/// root, whichever record a member saw first: two members keep one set.
#[test]
fn an_admin_key_named_by_a_claim_teaches_nothing_in_any_order() {
    let mut g = G::new();
    let (pa, a, pn, n, x) = (k("phone a"), k("admin a"), k("phone n"), k("admin n"), k("other x"));
    let watch = POWER_REMOVE | POWER_FREEZE | POWER_TAKEOVER;
    let ra = g.admin(&pa, &a, watch);
    let rn = g.admin(&pn, &n, watch);
    let c = g.rec(&a, Kind::Claim { root: n.key.clone(), seen: Vec::new() });
    let d = g.device(&n, &k("no device"), "x", |d| {
        d.admin = Some(x.key.clone());
        d.powers = POWER_ADMIT;
    });
    let xr = g.rec(&x, Kind::Copies { incoming_ms: 60_000, seen: vec![] });
    let mut m1 = RecordSet::new(g.root.key.clone());
    for r in [&ra, &c, &d, &xr, &rn] {
        let _ = m1.insert(r.clone());
    }
    let mut m2 = RecordSet::new(g.root.key.clone());
    for r in [&ra, &rn, &c, &d, &xr] {
        let _ = m2.insert(r.clone());
    }
    for _ in 0..3 {
        let from1: Vec<Record> = m1.in_dependency_order().into_iter().cloned().collect();
        let from2: Vec<Record> = m2.in_dependency_order().into_iter().cloned().collect();
        m2.insert_all(from1);
        m1.insert_all(from2);
    }
    assert_eq!(m1.digest(), m2.digest());
    assert!(!m1.contains(&xr.id()) && !m2.contains(&xr.id()));
    let s1 = state_of(&g.root.key, &[ra.clone(), c.clone(), d.clone(), xr.clone(), rn.clone()], &BTreeMap::new());
    let s2 = state_of(&g.root.key, &[ra, rn, c, d, xr], &BTreeMap::new());
    assert_eq!(s1, s2);
}

mod differential {
    use super::*;
    use proptest::prelude::*;

    /// Builds records from a list of steps: devices, removals, freezes,
    /// thaws, resolves, claims and checkpoints by the root, two admins and
    /// a claim's new root.
    fn build(steps: &[(u8, u8, u8)]) -> (G, Vec<Record>) {
        let mut g = G::new();
        let all = POWER_ADMIT
            | POWER_MANAGE
            | POWER_REMOVE
            | POWER_REMOVE_ADMINS
            | POWER_FREEZE
            | POWER_THAW
            | POWER_TAKEOVER;
        let (pa, a, pb, b) = (k("phone a"), k("admin a"), k("phone b"), k("admin b"));
        g.admin(&pa, &a, all);
        g.admin(&pb, &b, POWER_ADMIT | POWER_REMOVE | POWER_FREEZE | POWER_TAKEOVER);
        let signers = [k("root"), a, b, k("new root a"), k("new root b")];
        let devices: Vec<K> = (0..6).map(|i| k(&format!("dev {i}"))).collect();
        for &(who, op, arg) in steps {
            let by = &signers[usize::from(who) % signers.len()];
            let target = &devices[usize::from(arg) % devices.len()];
            let kind = match op % 9 {
                0 => {
                    let mut d = Device::new(target.key.clone(), "dev", ROLE_MEMBER);
                    d.rights = RIGHT_READ | RIGHT_SEND;
                    Kind::Device(d)
                }
                1 => Kind::Revoke(removal(&[target.hash], g.seen())),
                2 => Kind::Freeze(removal(&[signers[1 + usize::from(arg) % 2].hash], g.seen())),
                3 => match g.recs.iter().rev().find(|r| matches!(r.body().kind, Kind::Freeze(_))) {
                    Some(f) if arg % 2 == 0 => Kind::Thaw { ids: vec![f.id()], seen: g.seen() },
                    Some(f) => Kind::Thaw { ids: vec![f.id()], seen: vec![] },
                    None => continue,
                },
                4 => match g.recs.get(usize::from(arg) % g.recs.len().max(1)) {
                    Some(r) => Kind::Resolve(vec![r.id()]),
                    None => continue,
                },
                5 => Kind::Claim { root: signers[3 + usize::from(arg) % 2].key.clone(), seen: g.seen() },
                6 => Kind::Hubs {
                    hubs: vec![target.key.device_id()],
                    seen: if arg % 2 == 0 { g.seen() } else { vec![] },
                },
                7 => Kind::Copies { incoming_ms: MIN_INCOMING_MS + u64::from(arg), seen: g.seen() },
                _ => {
                    let Some(&(seq, id)) = g.heads.get(&by.hash) else { continue };
                    let counting = g.state().counting;
                    let mut keep: Vec<RecordId> = g
                        .recs
                        .iter()
                        // A checkpoint keeps what counts, as a real one
                        // does, and of the rest some.
                        .filter(|r| {
                            r.body().signer == by.hash
                                && r.body().seq < seq
                                && (counting.contains(&r.id()) || r.id().0[0] % 2 == arg % 2)
                        })
                        .map(Record::id)
                        .collect();
                    keep.sort();
                    Kind::Checkpoint { heads: vec![Head { key: by.hash, seq, id }], keep }
                }
            };
            if let Ok(r) = Record::sign(g.body(by, kind), by) {
                g.push(r);
            }
        }
        let recs = g.recs.clone();
        (g, recs)
    }

    fn shuffle(recs: &[Record], seed: u64) -> Vec<Record> {
        let mut out = recs.to_vec();
        let mut s = seed;
        for i in (1..out.len()).rev() {
            s = s.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            out.swap(i, (s >> 33) as usize % (i + 1));
        }
        out
    }

    /// Fills a set in order, compacting now and then, as a member does,
    /// in three rounds of sync: a record whose signer it did not know yet
    /// comes again.
    fn fill(root: &Key, recs: &[Record], held: &BTreeMap<RecordId, u64>, every: usize) -> RecordSet {
        let mut m = RecordSet::new(root.clone());
        for _ in 0..3 {
            for (i, r) in recs.iter().enumerate() {
                let _ = m.insert(r.clone());
                if (i + 1) % every == 0 {
                    let st = m.state(held);
                    m.compact(&st);
                }
            }
        }
        for _ in 0..2 {
            let st = m.state(held);
            m.compact(&st);
        }
        m
    }

    proptest! {
        #![proptest_config(ProptestConfig { cases: 48, failure_persistence: None, ..ProptestConfig::default() })]

        /// A set's state is evaluate's state of the records it keeps and
        /// the claims it counted, and of all the records with those claims,
        /// whatever the order and the compactions; two sets that counted
        /// the same claims keep the same records.
        #[test]
        fn a_set_agrees_with_evaluate(
            steps in prop::collection::vec((0u8..5, 0u8..9, any::<u8>()), 4..40),
            seed in any::<u64>(),
            every in 1usize..8,
            held_ms in prop::sample::select(vec![0u64, DEFAULT_DELAY_MS]),
        ) {
            let (g, recs) = build(&steps);
            let held: BTreeMap<RecordId, u64> =
                recs.iter().filter(|r| matches!(r.body().kind, Kind::Claim { .. })).map(|r| (r.id(), held_ms)).collect();
            let m1 = fill(&g.root.key, &recs, &held, every);
            let m2 = fill(&g.root.key, &shuffle(&recs, seed), &held, every.saturating_add(2));
            for m in [&m1, &m2] {
                let kept: Vec<Record> = m.ids().map(|id| m.get(id).unwrap().clone()).collect();
                let want = evaluate(&Input { root: &g.root.key, records: &kept, held_ms: &held, counted: m.counted_claims() });
                let got = m.state(&held);
                prop_assert_eq!(&got, &want);
                let whole = evaluate(&Input { root: &g.root.key, records: &recs, held_ms: &held, counted: m.counted_claims() });
                prop_assert_eq!(&got.roots, &whole.roots);
                prop_assert_eq!(&got.devices, &whole.devices);
                prop_assert_eq!(&got.revoked, &whole.revoked);
                prop_assert_eq!(&got.stop, &whole.stop);
                prop_assert_eq!(&got.claims, &whole.claims);
            }
            if m1.counted() == m2.counted() {
                prop_assert_eq!(m1.digest(), m2.digest());
                prop_assert_eq!(m1.state(&held), m2.state(&held));
            }
        }
    }
}

/// A key a member first took for a claim's root, and then learned as an
/// admin key, has an admin's room from then on: its later records are
/// kept as on a member that saw them in the order they were made.
#[test]
fn an_admin_key_first_named_by_a_claim_gets_its_room() {
    let mut g = G::new();
    let (pw, w, pb, b) = (k("watch"), k("admin w"), k("phone b"), k("admin b"));
    let w_rec = g.admin(&pw, &w, POWER_REMOVE | POWER_FREEZE | POWER_TAKEOVER);
    let b_rec = g.admin(&pb, &b, POWER_ADMIT | POWER_REMOVE | POWER_REMOVE_ADMINS | POWER_TAKEOVER);
    let mut b_recs = Vec::new();
    for i in 0..20 {
        b_recs.push(g.device(&b, &k(&format!("d{i}")), "d", |_| {}));
    }
    let seen = g.seen();
    let rm = g.rec(&b, Kind::Revoke(removal(&[w.hash, pw.hash], seen)));
    b_recs.push(rm.clone());
    let claim =
        g.rec(&w, Kind::Claim { root: b.key.clone(), seen: vec![Seen { key: g.root.hash, seq: 1, id: w_rec.id() }] });
    let mut m1 = RecordSet::new(g.root.key.clone());
    m1.insert_all(g.recs.iter().cloned());
    let mut m2 = RecordSet::new(g.root.key.clone());
    let mut first: Vec<Record> = vec![w_rec.clone(), claim.clone()];
    first.extend(b_recs.iter().cloned());
    for r in first {
        let _ = m2.insert(r);
    }
    let _ = m2.insert(b_rec.clone());
    for _ in 0..3 {
        for r in &g.recs {
            let _ = m2.insert(r.clone());
        }
        let st = m2.state(&BTreeMap::new());
        m2.compact(&st);
    }
    assert!(m2.contains(&rm.id()));
    assert_eq!(m1.digest(), m2.digest());
    let (s1, s2) = (m1.state(&BTreeMap::new()), m2.state(&BTreeMap::new()));
    assert!(s1.revoked.contains(&w.hash) && s2.revoked.contains(&w.hash));
}

/// Two records at one seq stop the secrets only for a live admin of the
/// epoch: not for a removed admin, nor for a key that only a void claim
/// names.
#[test]
fn only_a_live_admin_s_two_histories_stop_the_secrets() {
    let twins = |g: &G, by: &K| -> Vec<Record> {
        (0..2)
            .map(|i| {
                Record::sign(
                    Body {
                        seq: 1,
                        prev: None,
                        ..g.body(by, Kind::Copies { incoming_ms: MIN_INCOMING_MS + i, seen: vec![] })
                    },
                    by,
                )
                .unwrap()
            })
            .collect()
    };
    let (pw, w) = (k("watch"), k("admin w"));
    let watch = POWER_REMOVE | POWER_FREEZE;
    let mut g = G::new();
    g.admin(&pw, &w, watch);
    let seen = g.seen();
    g.root_rec(Kind::Revoke(removal(&[w.hash, pw.hash], seen)));
    let two = twins(&g, &w);
    g.recs.extend(two);
    let s = g.state();
    assert!(s.revoked.contains(&w.hash));
    assert_eq!(s.stop, Stop::None);
    let mut g = G::new();
    g.admin(&pw, &w, watch);
    let x = k("nobody");
    let seen = g.seen();
    g.rec(&w, Kind::Claim { root: x.key.clone(), seen });
    let two = twins(&g, &x);
    g.recs.extend(two);
    assert_eq!(g.state().stop, Stop::None);
    // A live admin's two histories still do.
    let mut g = G::new();
    g.admin(&pw, &w, watch);
    let two = twins(&g, &w);
    g.recs.extend(two);
    assert_eq!(g.state().stop, Stop::Secrets);
}

/// Removals that list one key's head walk its chain once: a set of about
/// a thousand records within the ceilings evaluates quickly.
#[test]
fn many_removals_of_one_key_evaluate_quickly() {
    let mut g = G::new();
    let all = POWER_ADMIT | POWER_REMOVE | POWER_REMOVE_ADMINS | POWER_TAKEOVER;
    let (pv, v) = (k("phone v"), k("admin v"));
    g.admin(&pv, &v, all);
    let admins: Vec<(K, K)> = (0..3).map(|i| (k(&format!("phone {i}")), k(&format!("admin {i}")))).collect();
    for (p, a) in &admins {
        g.admin(p, a, all);
    }
    for i in 0..250 {
        g.rec(&v, Kind::Copies { incoming_ms: MIN_INCOMING_MS + i, seen: vec![] });
    }
    let (seq, id) = g.heads[&v.hash];
    for (_, a) in &admins {
        for _ in 0..250 {
            let seen = vec![Seen { key: v.hash, seq, id }];
            g.rec(a, Kind::Revoke(removal(&[k("nobody").hash, v.hash], seen)));
        }
    }
    let t = Instant::now();
    let s = g.state();
    let took = t.elapsed();
    assert!(s.revoked.contains(&v.hash));
    eprintln!("evaluate took {took:?}");
    assert!(took.as_secs_f64() < 4.0, "evaluate took {took:?}");
}

/// A record whose body names a second signer is counted for the largest
/// second signature: nine units more than without it.
#[test]
fn a_second_signer_costs_nine_units() {
    let g = G::new();
    let a = k("admin a");
    let second = [7u8; 32];
    let plain: &'static [u8] =
        Box::leak(g.body(&a, Kind::Copies { incoming_ms: 60_000, seen: vec![] }).encode().into_boxed_slice());
    let mut entries = crate::format::decode(plain).unwrap().as_map().unwrap().to_vec();
    entries.push((8, crate::format::cbor::Value::Bytes(&second)));
    let bytes = crate::format::cbor::Value::Map(entries).encode();
    let sig = key::sign_es256(&a, LABEL_RECORD, &bytes).unwrap();
    let max = crate::format::envelope::MAX_SIG2;
    let r = Record::decode(&crate::format::envelope::write(&bytes, &sig, Some(&vec![0x55u8; max]))).unwrap();
    let plain = Record::sign(g.body(&a, Kind::Copies { incoming_ms: 60_000, seen: vec![] }), &a).unwrap();
    let units = |r: &Record| keep::units(r.size(), false);
    assert_eq!(units(&r), units(&plain) + 9);
    assert!(r.size() >= r.envelope().len());
}

/// The device record's fields here are the format's list.
#[test]
fn device_fields_are_the_format_s() {
    let mine: Vec<u16> = body::COMMON_FIELDS.iter().chain(body::DEVICE_OWN).copied().collect();
    assert_eq!(mine, crate::format::DEVICE_FIELDS);
}

/// A removed admin's hubs and copies window are left out: another
/// admin's later records take their place.
#[test]
fn a_removed_admin_s_hubs_and_copies_are_left_out() {
    let mut g = G::new();
    let (x, y) = (k("admin x"), k("admin y"));
    let (lo, hi, plo, phi) = if x.hash < y.hash { (x, y, k("pc x"), k("pc y")) } else { (y, x, k("pc y"), k("pc x")) };
    let computer = POWER_ADMIT | POWER_MANAGE | POWER_REMOVE | POWER_FREEZE | POWER_HUB;
    let (pp, p) = (k("phone p"), k("admin p"));
    g.admin(&plo, &lo, computer);
    g.admin(&phi, &hi, computer);
    g.admin(&pp, &p, POWER_ADMIT | POWER_REMOVE | POWER_REMOVE_ADMINS);
    let (h1, h2) = (k("hub 1"), k("hub 2"));
    g.device(&k("root"), &h1, "hub 1", |d| d.rights |= RIGHT_HUB);
    g.device(&k("root"), &h2, "hub 2", |d| d.rights |= RIGHT_HUB);
    g.rec(&lo, Kind::Hubs { hubs: vec![h1.key.device_id()], seen: vec![] });
    g.rec(&lo, Kind::Copies { incoming_ms: MIN_INCOMING_MS, seen: vec![] });
    let seen = g.seen();
    g.rec(&p, Kind::Revoke(removal(&[lo.hash, plo.hash], seen)));
    g.rec(&hi, Kind::Hubs { hubs: vec![h2.key.device_id()], seen: vec![] });
    g.rec(&hi, Kind::Copies { incoming_ms: 600_000, seen: vec![] });
    let s = g.state();
    assert!(s.revoked.contains(&lo.hash));
    assert_eq!(s.hubs, vec![h2.key.device_id()]);
    assert_eq!(s.incoming_ms, Some(600_000));
}

/// Counted claims are taken in the order they were counted, each under
/// the root it follows: a second claim with a small ID and a short seen
/// never skips the root between.
#[test]
fn counted_claims_follow_the_path_in_order() {
    let (mut g, mut held, claim) = taken_over_group();
    let (t, n) = (k("admin t"), k("new root"));
    let first = g.seen_at(&g.root.hash, 1);
    let (n_seq, n_id) = g.heads[&n.hash];
    let mut seen = vec![first, Seen { key: n.hash, seq: n_seq, id: n_id }];
    seen.sort_by_key(|s| s.key);
    let mut second = None;
    for i in 0..10_000 {
        let n2 = k(&format!("next root {i}"));
        let r = Record::sign(g.body(&t, Kind::Claim { root: n2.key.clone(), seen: seen.clone() }), &t).unwrap();
        if r.id() < claim.id() {
            second = Some((r, n2));
            break;
        }
    }
    let (c2, n2) = second.unwrap();
    g.push(c2.clone());
    held.insert(c2.id(), DEFAULT_DELAY_MS);
    let s1 = counted_state(&g, &held, &[claim.id()]);
    assert_eq!(s1.roots, vec![g.root.hash, n.hash, n2.hash]);
    let s2 = counted_state(&g, &held, &[claim.id(), c2.id()]);
    assert_eq!(s2.roots, vec![g.root.hash, n.hash, n2.hash]);
    assert!(s2.revoked.contains(&k("gone").hash));
    // A set that compacts as it goes keeps the root between.
    let mut m = RecordSet::new(g.root.key.clone());
    m.insert_all(g.recs[..g.recs.len() - 1].iter().cloned());
    for _ in 0..2 {
        let st = m.state(&held);
        m.compact(&st);
    }
    let _ = m.insert(c2.clone());
    for _ in 0..3 {
        let st = m.state(&held);
        assert!(st.roots.contains(&n.hash));
        m.compact(&st);
    }
    assert_eq!(m.counted(), &[claim.id(), c2.id()]);
    let st = m.state(&held);
    assert_eq!(st.roots, vec![g.root.hash, n.hash, n2.hash]);
    assert!(st.revoked.contains(&k("gone").hash));
}

/// A counted claim needs no record: when its signer's later records push
/// the claim out of its room, the takeover stays, before and after the
/// set compacts.
#[test]
fn a_counted_takeover_outlives_its_record() {
    let mut g = G::new();
    let (rk, n) = (k("recovery"), k("new root"));
    g.root_rec(Kind::Recovery { admin: rk.key.clone() });
    g.device(&k("root"), &k("laptop"), "laptop", |_| {});
    g.device(&k("root"), &k("gone"), "gone", |_| {});
    let seen = g.seen();
    let claim = g.rec(&rk, Kind::Claim { root: n.key.clone(), seen });
    g.device(&n, &k("new phone"), "new phone", |d| d.holds_root = true);
    let seen = g.seen();
    g.rec(&n, Kind::Revoke(removal(&[k("gone").hash], seen)));
    let held = BTreeMap::from([(claim.id(), DEFAULT_DELAY_MS)]);
    let mut m = RecordSet::new(g.root.key.clone());
    m.insert_all(g.recs.iter().cloned());
    for _ in 0..2 {
        let st = m.state(&held);
        m.compact(&st);
    }
    assert_eq!(m.counted(), vec![claim.id()]);
    let more: Vec<Record> = (0..4000u64)
        .map(|i| {
            Record::sign(
                Body {
                    seq: 1,
                    prev: None,
                    ..g.body(&rk, Kind::Copies { incoming_ms: MIN_INCOMING_MS + i, seen: vec![] })
                },
                &rk,
            )
            .unwrap()
        })
        .filter(|r| r.id() < claim.id())
        .collect();
    m.insert_all(more.iter().cloned());
    assert!(!m.contains(&claim.id()));
    let after = m.state(&held);
    assert_eq!(after.roots, vec![g.root.hash, n.hash]);
    assert!(after.revoked.contains(&k("gone").hash));
    for _ in 0..2 {
        let st = m.state(&held);
        m.compact(&st);
    }
    let last = m.state(&held);
    assert_eq!(last.roots, vec![g.root.hash, n.hash]);
    assert!(g.recs.iter().filter(|r| r.body().signer == n.hash).all(|r| m.contains(&r.id())));
    // The same for evaluate, from what the device kept of the claim.
    let kept: Vec<Record> = m.ids().map(|id| m.get(id).unwrap().clone()).collect();
    let s = evaluate(&Input { root: &g.root.key, records: &kept, held_ms: &held, counted: m.counted_claims() });
    assert_eq!(s.roots, vec![g.root.hash, n.hash]);
}

/// A counted claim is checked once, when a member takes it as counted:
/// the records must show a claimant with the takeover power under its
/// root, not removed in what the claim saw. Once taken, nothing later
/// asks again.
#[test]
fn a_counted_claim_is_checked_once() {
    let (pw, w, pa, a) = (k("watch"), k("admin w"), k("phone a"), k("admin a"));
    let take = |g: &G, claim: &Record| {
        let mut set = RecordSet::new(g.root.key.clone());
        set.insert_all(g.recs.iter().cloned());
        set.remember_counted([claim.id()]).map(|()| set)
    };
    // No takeover power.
    let mut g = G::new();
    g.admin(&pw, &w, POWER_REMOVE | POWER_FREEZE);
    let seen = g.seen();
    let claim = g.rec(&w, Kind::Claim { root: k("other root").key.clone(), seen });
    assert_eq!(take(&g, &claim).err(), Some(claim.id()));
    // Removed before the claim.
    let mut g = G::new();
    g.admin(&pa, &a, POWER_ADMIT | POWER_TAKEOVER);
    let seen = g.seen();
    g.root_rec(Kind::Revoke(removal(&[a.hash, pa.hash], seen)));
    let seen = g.seen();
    let claim = g.rec(&a, Kind::Claim { root: k("other root").key.clone(), seen });
    assert_eq!(take(&g, &claim).err(), Some(claim.id()));
    // Proved: it stays counted, whatever the old root signs after.
    let (mut g, held, claim) = taken_over_group();
    let mut set = take(&g, &claim).unwrap();
    let seen = g.seen();
    let late = g.root_rec(Kind::Revoke(removal(&[k("admin a").hash, k("phone a").hash], seen)));
    let _ = set.insert(late);
    let st = set.state(&held);
    assert_eq!(st.roots, vec![g.root.hash, k("new root").hash]);
}

/// A thaw brings back what it lists of the frozen key: a record the
/// key signed that the thaw saw counts again; one it did not see, signed
/// before the thaw or after it, stays cut. The same for a root's thaw.
#[test]
fn a_thaw_brings_back_only_what_it_lists() {
    let both = |by_root: bool| {
        let mut g = G::new();
        let (pw, w, pp, p) = (k("watch"), k("admin w"), k("phone p"), k("admin p"));
        g.admin(&pw, &w, POWER_REMOVE | POWER_FREEZE);
        g.admin(&pp, &p, POWER_REMOVE_ADMINS | POWER_FREEZE | POWER_THAW);
        g.device(&k("root"), &k("laptop"), "laptop", |_| {});
        g.device(&k("root"), &k("tablet"), "tablet", |_| {});
        let seen = g.seen();
        let fr = if by_root {
            g.root_rec(Kind::Freeze(removal(&[w.hash], seen)))
        } else {
            g.rec(&p, Kind::Freeze(removal(&[w.hash], seen)))
        };
        let seen = g.seen();
        let listed = g.rec(&w, Kind::Revoke(removal(&[k("laptop").hash], seen)));
        let at = g.seen_at(&w.hash, listed.body().seq);
        let seen = g.seen();
        let unlisted = g.rec(&w, Kind::Revoke(removal(&[k("tablet").hash], seen)));
        let thaw = Kind::Thaw { ids: vec![fr.id()], seen: vec![at] };
        if by_root {
            g.root_rec(thaw);
        } else {
            g.rec(&p, thaw);
        }
        let seen = g.seen();
        let after = g.rec(&w, Kind::Revoke(removal(&[k("laptop").hash], seen)));
        let s = g.state();
        assert!(s.counting.contains(&listed.id()) && s.revoked.contains(&k("laptop").hash), "root {by_root}");
        assert!(!s.counting.contains(&unlisted.id()) && !s.revoked.contains(&k("tablet").hash), "root {by_root}");
        assert!(!s.counting.contains(&after.id()), "root {by_root}");
        assert!(s.device(&pw.key.device_id()).is_some_and(|d| !d.frozen), "root {by_root}");
    };
    both(false);
    both(true);
}

/// Of two admins' hubs or copies records, the one that saw the other
/// counts; when neither saw the other, the smaller ID.
#[test]
fn of_two_admins_settings_the_one_that_saw_the_other_counts() {
    let (pa, a, pb, b) = (k("phone a"), k("admin a"), k("phone b"), k("admin b"));
    // The later author is the one with the larger key hash, so the
    // signer's order would pick the other.
    let (first, later) = if a.hash < b.hash { (&a, &b) } else { (&b, &a) };
    let build = |later_saw: bool| {
        let mut g = G::new();
        g.admin(&pa, &a, POWER_HUB);
        g.admin(&pb, &b, POWER_HUB);
        g.device(&k("root"), &k("hub"), "hub", |d| d.rights |= RIGHT_HUB);
        g.device(&k("root"), &k("hub2"), "hub2", |d| d.rights |= RIGHT_HUB);
        let (h1, h2) = (k("hub").key.device_id(), k("hub2").key.device_id());
        let before = g.seen();
        let r1 = g.rec(first, Kind::Hubs { hubs: vec![h1], seen: before.clone() });
        let c1 = g.rec(first, Kind::Copies { incoming_ms: 5_000, seen: before.clone() });
        let saw = if later_saw { g.seen() } else { before };
        let r2 = g.rec(later, Kind::Hubs { hubs: vec![h2], seen: saw.clone() });
        let c2 = g.rec(later, Kind::Copies { incoming_ms: 7_000, seen: saw });
        (g.state(), [(r1, h1, c1), (r2, h2, c2)])
    };
    let (s, [_, (_, h2, _)]) = build(true);
    assert_eq!(s.hubs, vec![h2]);
    assert_eq!(s.incoming_ms, Some(7_000));
    let (s, [(r1, h1, c1), (r2, h2, c2)]) = build(false);
    assert_eq!(s.hubs, vec![if r1.id() < r2.id() { h1 } else { h2 }]);
    assert_eq!(s.incoming_ms, Some(if c1.id() < c2.id() { 5_000 } else { 7_000 }));
}

/// An admin key counts only from the newest root record of its device.
/// A newer one that names no admin key, or another, works as a removal
/// of the old key: what the key signed that the record's field 26 saw
/// still counts, the rest does not.
#[test]
fn an_admin_key_counts_from_its_device_s_newest_root_record() {
    let all = POWER_ADMIT | POWER_REMOVE | POWER_TAKEOVER;
    // Named no more.
    let mut g = G::new();
    let (pt, t) = (k("phone t"), k("admin t"));
    g.admin(&pt, &t, all);
    g.device(&k("root"), &k("laptop"), "laptop", |_| {});
    let before = g.device(&t, &k("kept"), "kept", |_| {});
    let at = g.seen_at(&t.hash, before.body().seq);
    g.device(&k("root"), &pt, "phone t", |d| d.seen = vec![at]);
    let admitted = g.device(&t, &k("late"), "late", |_| {});
    let seen = g.seen();
    let rm = g.rec(&t, Kind::Revoke(removal(&[k("laptop").hash], seen)));
    let seen = g.seen();
    let claim = g.rec(&t, Kind::Claim { root: k("other root").key.clone(), seen });
    let s = state_of(&g.root.key, &g.recs, &BTreeMap::from([(claim.id(), DEFAULT_DELAY_MS)]));
    assert!(s.counting.contains(&before.id()));
    assert!(!s.counting.contains(&admitted.id()) && !s.counting.contains(&rm.id()));
    assert!(!s.revoked.contains(&k("laptop").hash));
    assert_eq!(s.roots.len(), 1);
    assert!(s.device(&pt.key.device_id()).is_some_and(|d| d.admin.is_none()));
    assert!(!s.may_command(&t.hash));
    // Another key named.
    let mut g = G::new();
    let t2 = k("admin t2");
    g.admin(&pt, &t, all);
    g.admin(&pt, &t2, POWER_REMOVE);
    let late = g.device(&t, &k("x"), "x", |_| {});
    let s = g.state();
    assert!(!s.counting.contains(&late.id()));
    assert_eq!(s.device(&pt.key.device_id()).and_then(|d| d.admin), Some(t2.hash));
}

/// A removal of a claimant that saw records of the claim's new root came
/// after the takeover and disputes nothing, also on a member that had not
/// counted the claim; one that saw none of them disputes it, as before.
/// Whether a peer counts another owner comes from its path alone.
#[test]
fn a_removal_after_the_new_root_s_records_disputes_nothing() {
    let (mut g, held, claim) = taken_over_group();
    let (a, pa, t) = (k("admin a"), k("phone a"), k("admin t"));
    let seen = g.seen();
    assert!(seen.iter().any(|s| s.key == k("new root").hash));
    g.rec(&t, Kind::Revoke(removal(&[a.hash, pa.hash], seen)));
    for counted in [&[][..], &[claim.id()][..]] {
        let s = counted_state(&g, &held, counted);
        assert_eq!(s.roots, vec![g.root.hash, k("new root").hash], "counted {}", counted.len());
        assert_eq!(s.stop, Stop::None);
        assert_eq!(s.claims.iter().find(|c| c.record == claim.id()).map(|c| c.state), Some(ClaimState::Effective));
        assert!(!s.disagrees(&[g.root.hash]) && !s.disagrees(&s.roots));
    }
    // Without the new root's records in its seen, it disputes the claim.
    let (mut g, held, claim) = taken_over_group();
    let seen: Vec<Seen> = g.seen().into_iter().filter(|s| s.key != k("new root").hash).collect();
    g.rec(&t, Kind::Revoke(removal(&[a.hash, pa.hash], seen)));
    let s = counted_state(&g, &held, &[]);
    assert_eq!(s.claims.iter().find(|c| c.record == claim.id()).map(|c| c.state), Some(ClaimState::Disputed));
}

/// Of a root a takeover cut, below the chain the records show, a member
/// keeps only what the newest checkpoint on that chain names; and it does
/// not take again what the counting checkpoint left out.
#[test]
fn below_a_cut_root_s_checkpoint_only_what_it_names_stays() {
    let mut g = G::new();
    let root = k("root");
    let all = POWER_ADMIT | POWER_MANAGE | POWER_REMOVE | POWER_REMOVE_ADMINS | POWER_FREEZE | POWER_TAKEOVER;
    let (pa, a, pt, t, n) = (k("phone a"), k("admin a"), k("phone t"), k("admin t"), k("new root"));
    let r1 = g.admin(&pa, &a, all);
    let r2 = g.admin(&pt, &t, all);
    let r3 = g.device(&root, &k("laptop"), "laptop", |_| {});
    let left_out = g.root_rec(Kind::Copies { incoming_ms: 60_000, seen: vec![] });
    let r5 = g.device(&root, &k("tablet"), "tablet", |_| {});
    let mut keep = vec![r1.id(), r2.id(), r3.id()];
    keep.sort();
    g.root_rec(Kind::Checkpoint { heads: vec![Head { key: root.hash, seq: 5, id: r5.id() }], keep });
    let seen = g.seen();
    let claim = g.rec(&a, Kind::Claim { root: n.key.clone(), seen });
    g.device(&n, &k("new phone"), "new phone", |d| d.holds_root = true);
    let held = BTreeMap::from([(claim.id(), DEFAULT_DELAY_MS)]);
    let mut m = RecordSet::new(g.root.key.clone());
    m.insert_all(g.recs.iter().cloned());
    for _ in 0..2 {
        let st = m.state(&held);
        m.compact(&st);
    }
    let before = m.state(&held);
    assert_eq!(before.roots.len(), 2);
    assert!(before.checkpoint.is_some() && !m.contains(&left_out.id()));
    // What the checkpoint left out is not taken again.
    assert_eq!(m.insert(left_out.clone()), Ok(Added::NoRoom));
    let low: Vec<Record> = (0..1300u64)
        .map(|i| {
            let kind = Kind::Copies { incoming_ms: MIN_INCOMING_MS + i, seen: vec![] };
            Record::sign(Body { seq: 1, prev: None, ..g.body(&root, kind) }, &root).unwrap()
        })
        .collect();
    let (stored, _) = m.insert_all(low.iter().cloned());
    assert_eq!(stored, 0);
    for _ in 0..2 {
        let st = m.state(&held);
        m.compact(&st);
    }
    let after = m.state(&held);
    assert_eq!(after.roots, before.roots);
    assert_eq!(after.devices, before.devices);
    assert!(after.devices.iter().any(|d| d.admin == Some(t.hash)));
    // The same from evaluate, for a device that counted the claim.
    g.recs.extend(low);
    let s = counted_state(&g, &held, &[claim.id()]);
    assert_eq!(s.roots, before.roots);
    assert_eq!(s.devices, before.devices);
}

/// A root's removal is final: when the root key signs a twin at its seq,
/// the removal still counts; the two histories are a conflict of their
/// own, and the twin counts for nothing.
#[test]
fn a_root_s_removal_outlasts_a_twin_at_its_seq() {
    let mut g = G::new();
    let root = k("root");
    g.device(&root, &k("laptop"), "laptop", |_| {});
    g.device(&root, &k("tablet"), "tablet", |_| {});
    let seen = g.seen();
    let rm = g.root_rec(Kind::Revoke(removal(&[k("laptop").hash], seen)));
    let b = rm.body();
    let twin = Record::sign(
        Body { seq: b.seq, prev: b.prev, ..g.body(&root, Kind::Copies { incoming_ms: 60_000, seen: vec![] }) },
        &root,
    )
    .unwrap();
    g.recs.push(twin.clone());
    let s = g.state();
    assert!(s.counting.contains(&rm.id()) && s.revoked.contains(&k("laptop").hash));
    assert!(!s.counting.contains(&twin.id()));
    assert!(s.conflicts.iter().any(|c| c.kind == ConflictKind::TwoHistories && c.signers == vec![root.hash]));
    assert!(s.device(&k("tablet").key.device_id()).is_some());
}

/// A root's removals never fall out of its room: its own checkpoints,
/// however large, come after them in its order.
#[test]
fn a_root_s_checkpoints_never_push_out_its_removals() {
    let mut g = G::new();
    let root = k("root");
    let mut removed = Vec::new();
    for i in 0..20 {
        let d = k(&format!("device {i}"));
        g.device(&root, &d, "device", |_| {});
        let seen = g.seen();
        removed.push((d.hash, g.root_rec(Kind::Revoke(removal(&[d.hash], seen)))));
    }
    let mut set = RecordSet::new(g.root.key.clone());
    set.insert_all(g.recs.iter().cloned());
    for i in 0..9u8 {
        let keep: Vec<RecordId> = (0..1900u32)
            .map(|j| {
                let mut id = [i; 32];
                id[..4].copy_from_slice(&j.to_be_bytes());
                RecordId(id)
            })
            .collect();
        let body = Body {
            seq: 1000 + u64::from(i),
            prev: Some(RecordId([7; 32])),
            ..g.body(
                &root,
                Kind::Checkpoint { heads: vec![Head { key: root.hash, seq: 1, id: RecordId([8; 32]) }], keep },
            )
        };
        let r = Record::sign(body, &root).unwrap();
        set.insert(r.clone()).ok();
        g.recs.push(r);
    }
    assert!(removed.iter().all(|(_, r)| set.contains(&r.id())));
    let s = g.state();
    assert!(removed.iter().all(|(d, r)| s.counting.contains(&r.id()) && s.revoked.contains(d)));
}

/// A root's removal of a claimant, by its admin key or its device's
/// member key: one that saw the claim cancels it; one that did not came
/// before and voids it; one that saw records of the claim's new root came
/// after the takeover and cancels nothing.
#[test]
fn a_root_s_removal_of_a_claimant_cancels_or_voids() {
    let all = POWER_ADMIT | POWER_REMOVE | POWER_TAKEOVER;
    let (pa, a, n) = (k("phone a"), k("admin a"), k("new root"));
    let case = |key: &K, saw_claim: bool, saw_new_root: bool| {
        let mut g = G::new();
        g.admin(&pa, &a, all);
        g.device(&k("root"), &k("laptop"), "laptop", |_| {});
        let before = g.seen();
        let claim = g.rec(&a, Kind::Claim { root: n.key.clone(), seen: before.clone() });
        g.device(&n, &k("new phone"), "new phone", |d| d.holds_root = true);
        let mut seen = if saw_claim { g.seen() } else { before };
        if !saw_new_root {
            seen.retain(|s| s.key != n.hash);
        }
        g.root_rec(Kind::Revoke(removal(&[key.hash], seen)));
        let s = state_of(&g.root.key, &g.recs, &BTreeMap::from([(claim.id(), DEFAULT_DELAY_MS)]));
        s.claims.iter().find(|c| c.record == claim.id()).map(|c| c.state)
    };
    for key in [&a, &pa] {
        assert_eq!(case(key, true, false), Some(ClaimState::Cancelled));
        assert_eq!(case(key, false, false), Some(ClaimState::Void));
        assert_eq!(case(key, true, true), Some(ClaimState::Effective));
    }
}
