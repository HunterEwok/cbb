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
        self.heads.iter().map(|(k, (s, _))| Seen { key: *k, seq: *s }).collect()
    }

    fn state(&self) -> State {
        state_of(&self.root.key, &self.recs, &BTreeMap::new())
    }
}

fn state_of(root: &Key, recs: &[Record], held: &BTreeMap<RecordId, u64>) -> State {
    evaluate(&Input { root, records: recs, held_ms: held })
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
    let rs: Vec<Record> =
        (0..MAX_ADMIN_RECORDS as u64 + 4).map(|i| g.rec(&a, Kind::Copies { incoming_ms: 5_000 + i })).collect();
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
        g.root_rec(Kind::Copies { incoming_ms: 5_000 + i });
    }
    let mut set = RecordSet::new(g.root.key.clone());
    set.insert_all(g.recs.clone());
    assert_eq!(set.len(), MAX_ROOT_RECORDS);
    // Full: the root's next ordinary record finds no room.
    let late = Record::sign(g.body(&root, Kind::Copies { incoming_ms: 9_999 }), &root).unwrap();
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
    let seen = vec![Seen { key: g.root.hash, seq: g.heads[&g.root.hash].0 }];
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
                .map(|r| super::eval::item(r).units)
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
            let b = Body { seq: 1, prev: None, ..g.body(&x, Kind::Copies { incoming_ms: 5_000 + i }) };
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
    let twin_body = Body { seq: 1, prev: None, ..g.body(&s_, Kind::Copies { incoming_ms: 6_000 }) };
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
    g.rec(&c, Kind::Copies { incoming_ms: 6_000 });
    let twin = Body { seq: 1, prev: None, ..g.body(&c, Kind::Copies { incoming_ms: 7_000 }) };
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
            (&a, Kind::Hubs(vec![h1.min(h2), h1.max(h2)])),
            (&b, Kind::Hubs(vec![h1.min(h2)])),
            (&a, Kind::Copies { incoming_ms: 5_000 }),
            (&b, Kind::Copies { incoming_ms: 3_600_000 }),
        ] {
            let mut body = g.body(by, kind);
            if by.hash == b.hash {
                body.time_ms = time;
            }
            let r = Record::sign(body, by).unwrap();
            g.push(r);
        }
        g.state()
    };
    let (plain, huge) = (build(0), build(u64::MAX));
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
    let copies = g.rec(&rk, Kind::Copies { incoming_ms: 3_600_000 });
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

/// A pool of records that touches every rule: admins, devices, removals,
/// a freeze and a thaw, two histories, claims, held records, settings.
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
    g.rec(&c, Kind::Thaw(vec![f.id()]));
    g.rec(&a, Kind::Claim { root: k("na").key.clone(), seen: seen.clone() });
    g.rec(&c, Kind::Claim { root: k("nc").key.clone(), seen });
    // A second history of b at its last seq.
    let mut twin = g.body(&b, Kind::Copies { incoming_ms: 9_000 });
    twin.seq -= 1;
    twin.prev = g.recs.iter().find(|r| r.body().signer == b.hash && r.body().seq == twin.seq - 1).map(|r| r.id());
    g.push(Record::sign(twin, &b).unwrap());
    g.rec(&b, Kind::Hubs(vec![k("r0").key.device_id()]));
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
            // The set refuses what it cannot verify; its state is that of
            // the records it kept.
            let kept: Vec<Record> = a.ids().map(|id| a.get(id).unwrap().clone()).collect();
            let stored = state_of(&root, &kept, &held);
            prop_assert_eq!(&a.state(&held), &stored);
            prop_assert_eq!(&b.state(&held), &stored);
            let strip = |s: &State| State { ignored: Vec::new(), ..s.clone() };
            prop_assert_eq!(strip(&stored), strip(&want));
        }
    }
}
