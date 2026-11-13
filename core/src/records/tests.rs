// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The rules of records v3 as tests: who signs what, one place per record,
//! the limits, the change of root by the recovery key and the stop, held
//! records, the keys statement, and one state for one set in any order.

use std::collections::BTreeMap;
use std::time::Instant;

use p256::ecdsa::SigningKey;
use p256::ecdsa::signature::hazmat::PrehashSigner as _;

use super::body::*;
use super::eval::{ChangeState, ConflictKind, Stop, Why};
use super::key::{ALG_XWING, XWING_PUBLIC, tests_hook};
use super::set::{Added, Refused};
use super::statement::{self, Statement};
use super::*;
use crate::certs::sha256;
use crate::identity::ExternalKey;

/// A key made from a name, so that a test replays exactly.
#[derive(Clone)]
struct K {
    sk: SigningKey,
    key: Key,
    hash: KeyHash,
}

impl ExternalKey for K {
    fn public(&self) -> Vec<u8> {
        self.key.public().to_vec()
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

/// The group's recovery key in the tests.
fn rk() -> Recovery {
    crate::testkit::recovery()
}

/// An empty set of the tests' group whose first root is root.
fn set_of(root: &Key) -> RecordSet {
    RecordSet::new(root.clone(), rk())
}

/// Builds a group's records: each signer's next seq and prev, and the
/// recovery records' lists.
#[derive(Clone)]
struct G {
    root: K,
    gid: GroupId,
    heads: BTreeMap<KeyHash, (u64, RecordId)>,
    recs: Vec<Record>,
    lists: Vec<Vec<u8>>,
}

impl G {
    fn new() -> G {
        let root = k("root");
        let gid = group_id(&root.key, &rk());
        G { root, gid, heads: BTreeMap::new(), recs: Vec::new(), lists: Vec::new() }
    }

    /// A change of root to new_root by the recovery key, with list.
    fn change(&mut self, new_root: &K, list: &[RecordId]) -> Record {
        self.change_from(new_root, list, 0)
    }

    /// The same, the new root's records starting at seq from. The new
    /// root signs its first checkpoint first, which the head names: it
    /// keeps the whole list and names a head of a key that is no new root
    /// (the first root's, else the recovery key's), so it narrows nothing.
    fn change_from(&mut self, new_root: &K, list: &[RecordId], from: u64) -> Record {
        let mut ids = list.to_vec();
        ids.sort();
        ids.dedup();
        let list = List(ids);
        self.lists.push(list.encode());
        let first = self.first_checkpoint(new_root, &list.0);
        self.rec(
            &k("recovery"),
            Kind::Recovery {
                root: new_root.key.clone(),
                list: list.hash(),
                from,
                first,
                signer2: crate::testkit::rk2().key().hash(),
            },
        )
    }

    /// The first checkpoint of new_root a head names (`change_from`).
    fn first_checkpoint(&mut self, new_root: &K, keep: &[RecordId]) -> RecordId {
        let other = [self.root.hash, k("recovery").hash]
            .into_iter()
            .chain(self.heads.keys().copied())
            .find(|key| *key != new_root.hash && self.heads.contains_key(key))
            .expect("a key with a record");
        let (seq, id) = self.heads[&other];
        self.rec(new_root, Kind::Checkpoint { heads: vec![Head { key: other, seq, id }], keep: keep.to_vec() }).id()
    }

    /// The IDs of the records of the roots on the path that count now,
    /// with every root's removal: what a writer that holds them all lists.
    fn listing(&self) -> Vec<RecordId> {
        let mut set = set_of(&self.root.key);
        set.insert_all(self.recs.clone());
        for l in &self.lists {
            let _ = set.insert_list(l);
        }
        set.change_list(&set.state()).0
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
        let r = crate::testkit::sign_by(self.body(by, kind), by);
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
        self.rec(by, Kind::device(d))
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
        evaluate(&Input { root: &self.root.key, recovery: &rk(), records: &self.recs, lists: &self.lists })
    }
}

fn state_of(root: &Key, recs: &[Record]) -> State {
    evaluate(&Input { root, recovery: &rk(), records: recs, lists: &[] })
}

/// A group whose root was changed by the recovery key: the first root
/// admitted a laptop and an admin with a device, then the recovery key
/// made "new root" the root, listing all that counts; the new root then
/// admitted a tablet.
fn changed_group() -> G {
    let mut g = G::new();
    let root = k("root");
    g.device(&root, &k("laptop"), "laptop", |_| {});
    g.admin(&k("phone a"), &k("admin a"), POWER_ADMIT | POWER_REMOVE);
    g.device(&k("admin a"), &k("tv"), "tv", |_| {});
    let list = g.listing();
    g.change(&k("new root"), &list);
    g.device(&k("new root"), &k("tablet"), "tablet", |_| {});
    g
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
    let mut set = set_of(&g.root.key.clone());
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
    let mut set = set_of(&g.root.key.clone());
    assert_eq!(set.insert(t.clone()), Err(Refused::UnknownSigner));
    assert!(set.is_empty());
    let (stored, refused) = set.insert_all([t.clone(), a.clone()]);
    assert_eq!((stored, refused.len()), (2, 0));
    let order: Vec<RecordId> = set.in_dependency_order().iter().map(|r| r.id()).collect();
    assert_eq!(order, [a.id(), t.id()]);
    let other = G {
        root: k("another root"),
        gid: group_id(&k("another root").key, &rk()),
        heads: BTreeMap::new(),
        recs: Vec::new(),
        lists: Vec::new(),
    };
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
    let s = state_of(&g.root.key, &recs);
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
    let body = g.body(&k("root"), Kind::device(d));
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
        let s = state_of(&g.root.key, &recs);
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
        let s = state_of(&g.root.key, &recs);
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
        let mut g = G { root: k("root"), gid: g.gid, heads: g.heads.clone(), recs: quiet.clone(), lists: Vec::new() };
        for i in 0..2000 {
            g.device(flooder, &k(&format!("f{i}")), "flood", |_| {});
        }
        for order in 0..2 {
            let mut recs = g.recs.clone();
            if order == 1 {
                recs.reverse();
            }
            let mut set = set_of(&g.root.key.clone());
            set.insert_all(recs);
            assert!(set.len() < g.recs.len());
            for r in &admitted {
                assert!(set.contains(&r.id()));
            }
            let s = set.state();
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
    g.admin(&pt, &t, POWER_ADMIT);
    g.device(&k("root"), &k("laptop"), "laptop", |_| {});
    let seen = g.seen();
    g.root_rec(Kind::Revoke(removal(&[pt.hash], seen)));
    let s = g.state();
    assert!(s.revoked.contains(&pt.hash) && s.revoked.contains(&t.hash));
    let admitted = g.device(&t, &k("other laptop"), "other laptop", |_| {});
    let s = g.state();
    assert!(!s.counting.contains(&admitted.id()));
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
fn held_records_are_kept_not_applied() {
    let mut g = G::new();
    let laptop = k("laptop");
    let mut body = g.body(&k("root"), Kind::device(Device::new(laptop.key.clone(), "laptop", ROLE_MEMBER)));
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
    let mut set = set_of(&g.root.key.clone());
    assert_eq!(set.insert_all(g.recs.clone()).0, 3);
    let s = set.state();
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
    g.root_rec(Kind::settings(Settings { min_rules: 2, ..Settings::default() }));
    let s = g.state();
    assert!(s.too_old);
    assert_eq!(s.settings.rules(), 2);
    let mut g = G::new();
    g.root_rec(Kind::settings(Settings { shared: true, ..Settings::default() }));
    let s = g.state();
    assert!(!s.too_old);
    // A field at its default is never written.
    let bad = Settings { min_rules: 1, ..Settings::default() };
    assert!(
        Body { kind: Kind::settings(bad), ..g.body(&k("root"), Kind::Unknown(1)) }
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
    let mut set = set_of(&g.root.key.clone());
    set.insert_all(g.recs.clone());
    let s = set.state();
    let got: Vec<RecordId> = set.for_peer(&s, &laptop.hash).iter().map(|r| r.id()).collect();
    assert_eq!(got, [rv.id()]);
    assert!(set.for_peer(&s, &stranger.hash).is_empty());
    assert_eq!(set.for_peer(&s, &tablet.hash).len(), 3);
}

/// A removed device that does not know its removal's signer gets what
/// proves it, and nothing else: an admin's root record, or the change of
/// root with its first checkpoint and list; it then knows it is removed.
#[test]
fn a_removed_device_learns_it_is_removed_whoever_signed() {
    // An admin the device never heard of removes it.
    let mut g = G::new();
    let laptop = k("laptop");
    g.device(&k("root"), &laptop, "laptop", |_| {});
    let at_join = g.recs.clone();
    let tablet = g.device(&k("root"), &k("tablet"), "tablet", |_| {});
    let grant = g.admin(&k("pa"), &k("a"), POWER_ADMIT | POWER_REMOVE);
    let rv = g.rec(&k("a"), Kind::Revoke(removal(&[laptop.hash], g.seen())));
    let set = set_with(&g.root.key, &g.recs, &g.lists);
    let st = set.state();
    assert!(st.revoked.contains(&laptop.hash));
    // The admin's root record with its chain to what the device holds.
    let given: Vec<RecordId> = set.for_peer(&st, &laptop.hash).iter().map(|r| r.id()).collect();
    let mut chain: Vec<RecordId> = at_join.iter().map(Record::id).collect();
    chain.extend([tablet.id(), grant.id(), rv.id()]);
    assert_eq!(given, chain);
    let mut mine = set_with(&g.root.key, &at_join, &g.lists);
    mine.insert_all(set.for_peer(&st, &laptop.hash).into_iter().cloned());
    assert!(mine.state().revoked.contains(&laptop.hash));

    // A new root, whose change the device never got, removes it.
    let mut g = G::new();
    g.device(&k("root"), &laptop, "laptop", |_| {});
    g.device(&k("root"), &k("tablet"), "tablet", |_| {});
    let at_join = g.recs.clone();
    let list = g.listing();
    let head = g.change(&k("root2"), &list);
    let rv = g.rec(&k("root2"), Kind::Revoke(removal(&[laptop.hash], g.seen())));
    let set = set_with(&g.root.key, &g.recs, &g.lists);
    let st = set.state();
    assert!(st.revoked.contains(&laptop.hash));
    let given: Vec<&Record> = set.for_peer(&st, &laptop.hash);
    let first = match &head.body().kind {
        Kind::Recovery { first, .. } => *first,
        _ => unreachable!(),
    };
    let ids: Vec<RecordId> = given.iter().map(|r| r.id()).collect();
    assert!(ids.contains(&head.id()) && ids.contains(&first) && ids.contains(&rv.id()));
    assert_eq!(ids.len(), 3, "nothing but the change, its first checkpoint and the removal");
    let mut mine = set_with(&g.root.key, &at_join, &g.lists);
    for _ in 0..2 {
        mine.insert_all(given.iter().map(|r| (*r).clone()));
        for l in set.lists() {
            let _ = mine.insert_list(l);
        }
    }
    assert!(mine.state().revoked.contains(&laptop.hash));
}

fn xwing(n: u8) -> Key {
    Key::new(ALG_XWING, vec![n; XWING_PUBLIC])
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
    let mut set = set_of(&g.root.key.clone());
    set.insert_all(g.recs.clone());
    let before = set.state();
    assert_eq!(before.checkpoint, Some(cp.id()));
    // The checkpoint compacted the set as it came.
    assert_eq!(set.compact(&before), 0);
    assert!(!set.contains(&ds[0].id()) && set.contains(&rv.id()));
    let after = set.state();
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
    let mut set = set_of(&g.root.key.clone());
    set.insert_all(g.recs.clone());
    assert_eq!(set.len(), MAX_ROOT_RECORDS);
    // Full: the root's next ordinary record finds no room.
    let late = Record::sign(g.body(&root, Kind::Copies { incoming_ms: 9_999, seen: vec![] }), &root).unwrap();
    assert_eq!(set.insert(late), Ok(Added::NoRoom));
    let (seq, id) = g.heads[&root.hash];
    let cp = g.root_rec(Kind::Checkpoint { heads: vec![Head { key: root.hash, seq, id }], keep: vec![laptop.id()] });
    let held = set.len();
    assert_eq!(set.insert(cp.clone()), Ok(Added::Stored));
    let state = set.state();
    assert_eq!(state.checkpoint, Some(cp.id()));
    // It compacted the set as it came.
    assert!(held - set.len() > 1000);
    assert_eq!(set.compact(&state), 0);
    let next = g.device(&root, &k("phone"), "phone", |_| {});
    assert_eq!(set.insert(next.clone()), Ok(Added::Stored));
    let s = set.state();
    assert!(s.counting.contains(&next.id()) && s.device(&k("laptop").key.device_id()).is_some());
}

/// A root whose room is full writes the checkpoint that frees it even
/// when that checkpoint is large (here it keeps the records of twelve
/// admins, about 200 units): a checkpoint is kept before the root's other
/// records, so it takes room from them, counts, and prunes them.
#[test]
fn a_full_root_writes_a_large_checkpoint_that_frees_it() {
    let mut g = G::new();
    let root = k("root");
    let admins: Vec<K> = (0..12).map(|i| k(&format!("admin {i}"))).collect();
    let grants: Vec<Record> = admins
        .iter()
        .enumerate()
        .map(|(i, a)| g.admin(&k(&format!("admin device {i}")), a, POWER_ADMIT | POWER_MANAGE))
        .collect();
    for a in &admins {
        for _ in 0..240 {
            g.rec(a, Kind::Copies { incoming_ms: MIN_INCOMING_MS, seen: vec![] });
        }
    }
    while g.heads[&root.hash].0 < MAX_ROOT_RECORDS as u64 {
        g.root_rec(Kind::Copies { incoming_ms: MIN_INCOMING_MS, seen: vec![] });
    }
    let mut set = set_of(&g.root.key.clone());
    set.insert_all(g.recs.clone());
    let late = Record::sign(g.body(&root, Kind::Copies { incoming_ms: 9_999, seen: vec![] }), &root).unwrap();
    assert_eq!(set.insert(late), Ok(Added::NoRoom), "the root's room is full");
    // The admins' records, and the root's records that make them admins.
    let mut keep: Vec<RecordId> =
        set.ids().filter(|id| set.get(id).is_some_and(|r| r.body().signer != root.hash)).copied().collect();
    keep.extend(grants.iter().map(Record::id));
    keep.sort();
    let mut heads: Vec<Head> = admins
        .iter()
        .chain([&root])
        .map(|a| Head { key: a.hash, seq: g.heads[&a.hash].0, id: g.heads[&a.hash].1 })
        .collect();
    heads.sort_by_key(|h| h.key);
    let cp = g.root_rec(Kind::Checkpoint { heads, keep });
    let units = super::keep::units(cp.size());
    assert!(units > 150, "{units} units");
    assert_eq!(set.insert(cp.clone()), Ok(Added::Stored));
    let s = set.state();
    assert_eq!(s.checkpoint, Some(cp.id()));
    let next = g.device(&root, &k("phone"), "phone", |_| {});
    assert_eq!(set.insert(next.clone()), Ok(Added::Stored));
    assert!(set.state().counting.contains(&next.id()));
    let mut fresh = set_of(&g.root.key.clone());
    fresh.insert_all(g.recs.clone());
    assert_eq!(fresh.digest(), set.digest());
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
    let mut a = set_of(&g.root.key.clone());
    a.insert_all(g.recs.clone());
    let mut b = set_of(&g.root.key.clone());
    let mut rev = g.recs.clone();
    rev.reverse();
    b.insert_all(rev);
    assert!(a.bytes() <= MAX_SET_BYTES && a.len() < g.recs.len());
    assert_eq!(a.digest(), b.digest());
    // The root's checkpoints come first, the newest first; none counts,
    // and the first device is out of the rooms: at most aside, as the
    // record the oldest waiting checkpoint waits for.
    assert!(a.contains(&g.recs.last().unwrap().id()));
    assert!(!a.contains(&first.id()) || a.waits_aside(&first.id()));
    assert!(!a.state().counting.contains(&first.id()));
}

/// A removed admin signs as much as it can, through recovery records of
/// its own that never count and the roots they name: the group's removals
/// hold, the devices admins admitted stay, admins still record, and a
/// change of root by the recovery key still takes effect.
#[test]
fn limits_hold_for_any_signer() {
    let mut g = G::new();
    let (pa, a, px, x) = (k("phone a"), k("admin a"), k("phone x"), k("admin x"));
    g.admin(&pa, &a, POWER_ADMIT | POWER_REMOVE_ADMINS);
    g.admin(&px, &x, POWER_ADMIT);
    let admitted: Vec<Record> = (0..20).map(|i| g.device(&a, &k(&format!("d{i}")), "d", |_| {})).collect();
    let seen = g.seen();
    let removal_of_x = g.rec(&a, Kind::Revoke(removal(&[x.hash], seen)));
    // X, removed, names four roots of its own and floods with each and
    // with its own key.
    let quiet = g.recs.clone();
    for i in 0..4 {
        let r = k(&format!("x root {i}"));
        g.rec(
            &x,
            Kind::Recovery {
                root: r.key.clone(),
                list: [0; 32],
                from: 0,
                first: RecordId([0xf1; 32]),
                signer2: crate::testkit::rk2().key().hash(),
            },
        );
        for j in 0..400 {
            g.device(&r, &k(&format!("x{i} {j}")), "flood", |_| {});
        }
    }
    for j in 0..400 {
        g.device(&x, &k(&format!("x {j}")), "flood", |_| {});
    }
    let flood: Vec<Record> = g.recs[quiet.len()..].to_vec();
    // An honest change of root goes on beside it.
    let list = g.listing();
    let change = g.change(&k("t root"), &list);
    for order in 0..2 {
        let mut recs = g.recs.clone();
        if order == 1 {
            recs.reverse();
        }
        let mut set = set_of(&g.root.key.clone());
        set.insert_all(recs);
        for l in &g.lists {
            set.insert_list(l).unwrap();
        }
        assert!(set.len() < g.recs.len() && set.bytes() <= MAX_SET_BYTES);
        let s = set.state();
        assert!(s.revoked.contains(&x.hash) && s.counting.contains(&removal_of_x.id()));
        for r in &admitted {
            assert!(s.counting.contains(&r.id()));
        }
        assert!(flood.iter().all(|r| !s.counting.contains(&r.id())));
        // X holds no more than its own 256 units whatever it signs, and
        // the roots it names are no keys at all.
        let units_of = |f: &dyn Fn(&KeyHash) -> bool| -> u64 {
            set.ids()
                .filter_map(|id| set.get(id))
                .filter(|r| f(&r.body().signer))
                .map(|r| super::eval::item(r, super::eval::Role::Admin).units)
                .sum()
        };
        let roots: Vec<KeyHash> = (0..4).map(|i| k(&format!("x root {i}")).hash).collect();
        assert!(units_of(&|h| *h == x.hash) <= 256);
        assert_eq!(units_of(&|h| roots.contains(h)), 0);
        assert_eq!(s.roots, vec![g.root.hash, k("t root").hash]);
        assert!(s.counting.contains(&change.id()));
        // An admin still records.
        let mut g2 = G { root: k("root"), gid: g.gid, heads: g.heads.clone(), recs: Vec::new(), lists: Vec::new() };
        let more = g2.device(&a, &k("one more"), "one more", |_| {});
        assert_eq!(set.insert(more.clone()), Ok(Added::Stored));
        assert!(set.state().counting.contains(&more.id()));
    }
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
    // S's key signs seq 1 twice: of its records only the removal, on a
    // whole chain, still counts (F-7 for every key); T stays out.
    let twin_body = Body { seq: 1, prev: None, ..g.body(&s_, Kind::Copies { incoming_ms: 6_000, seen: vec![] }) };
    let twin = g.push(Record::sign(twin_body, &s_).unwrap());
    let later: Vec<Record> = (2..5).map(|i| g.device(&t, &k(&format!("d{i}")), "d", |_| {})).collect();
    let s = g.state();
    assert!(s.two_histories(&s_.hash) && s.revoked.contains(&t.hash));
    assert!(later.iter().all(|r| !s.counting.contains(&r.id())));
    // The root voids both: until the removal is signed again, T is back.
    let mut ids = vec![first.id(), twin.id()];
    ids.sort();
    g.root_rec(Kind::Resolve(ids));
    let current = g.seen();
    let sign_at_one = |g: &mut G, rm: Removal| {
        let b = Body { seq: 1, prev: None, ..g.body(&s_, Kind::Revoke(rm)) };
        Record::sign(b, &s_).unwrap()
    };
    // Signed again with the current seen, T's later records would stay.
    let mut naive = G { root: k("root"), gid: g.gid, heads: g.heads.clone(), recs: g.recs.clone(), lists: Vec::new() };
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

/// Two histories of the root stop the group in full, and its own resolve
/// does not end them: a root's record is never voided.
#[test]
fn the_roots_resolve_leaves_its_two_histories() {
    let mut g = G::new();
    let root = k("root");
    let first = g.device(&root, &k("d"), "d", |_| {});
    let x = g.device(&root, &k("x"), "x", |_| {});
    let mut d = Device::new(k("y").key.clone(), "y", ROLE_MEMBER);
    d.rights = RIGHT_READ;
    let y = Record::sign(Body { seq: 2, prev: Some(first.id()), ..g.body(&root, Kind::device(d)) }, &root).unwrap();
    g.recs.push(y.clone());
    assert_eq!(g.state().stop, Stop::Full);
    g.root_rec(Kind::Resolve(vec![y.id()]));
    let s = g.state();
    assert_eq!(s.stop, Stop::Full);
    assert!(!s.counting.contains(&x.id()) && !s.counting.contains(&y.id()));
    let mut set = set_of(&g.root.key);
    set.insert_all(g.recs.clone());
    assert_eq!(set.state(), s);
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
/// command; the root does, but for a fork, where nobody does.
#[test]
fn who_may_command() {
    let mut g = G::new();
    let (pa, a, pb, b, pc, c) = (k("phone a"), k("admin a"), k("phone b"), k("admin b"), k("phone c"), k("admin c"));
    let (pd, d) = (k("phone d"), k("admin d"));
    g.admin(&pa, &a, POWER_HUB);
    g.admin(&pb, &b, POWER_HUB | POWER_FREEZE);
    g.admin(&pc, &c, 0);
    g.admin(&pd, &d, POWER_HUB);
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
    // Two recovery records at one seq: a full stop for good; nobody
    // commands, the root neither.
    let r = k("recovery");
    let one = g.body(
        &r,
        Kind::Recovery {
            root: k("nb").key.clone(),
            list: [1; 32],
            from: 0,
            first: RecordId([0xf1; 32]),
            signer2: crate::testkit::rk2().key().hash(),
        },
    );
    let two = Body {
        kind: Kind::Recovery {
            root: k("nd").key.clone(),
            list: [2; 32],
            from: 0,
            first: RecordId([0xf1; 32]),
            signer2: crate::testkit::rk2().key().hash(),
        },
        ..one.clone()
    };
    g.push(crate::testkit::sign_by(one, &r));
    g.push(crate::testkit::sign_by(two, &r));
    let s = g.state();
    assert_eq!(s.stop, Stop::Full);
    assert!(s.conflicts.iter().any(|c| c.kind == ConflictKind::Fork));
    assert!(s.halted() && !s.may_command(&g.root.hash) && !s.may_command(&b.hash));
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
    let mut set = set_of(&g.root.key.clone());
    set.insert_all(g.recs.clone());
    assert!(!set.contains(&rec.id()));
    assert!(set.state().id_taken(&old.key.device_id()));
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
    assert_eq!(Phone.grants().0, Computer.grants().0 | POWER_REMOVE_ADMINS | POWER_THAW);
    assert_eq!(Phone.grants().1, all);
    assert_eq!(all, 0x3ff);
    for kind in [Watch, Computer, Phone] {
        assert_eq!(kind.grants().0 & (POWER_PERIODS | POWER_RETIRED), 0);
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
    let removal = g.rec(&h, Kind::Revoke(removal(&[laptop.hash], seen)));
    // No admin takes the group over, a phone's included (rule 33).
    let by_a = g.rec(
        &a,
        Kind::Recovery {
            root: k("na").key.clone(),
            list: [0; 32],
            from: 0,
            first: RecordId([0xf1; 32]),
            signer2: crate::testkit::rk2().key().hash(),
        },
    );
    let by_s = g.rec(
        &s_,
        Kind::Recovery {
            root: k("ns").key.clone(),
            list: [0; 32],
            from: 0,
            first: RecordId([0xf1; 32]),
            signer2: crate::testkit::rk2().key().hash(),
        },
    );
    let st = g.state();
    assert!(!st.counting.contains(&by_helper.id()) && st.counting.contains(&by_admin.id()));
    assert!(st.counting.contains(&removal.id()));
    assert!(!st.counting.contains(&by_a.id()) && !st.counting.contains(&by_s.id()));
    assert!(st.changes.is_empty() && st.roots == vec![g.root.hash]);
}

/// A pool of records that touches every rule: admins, devices, removals,
/// a freeze and a thaw, two histories, claims, held records, settings.
/// A full set never drops a root's removal or resolve: 16 admin keys fill
/// their 256 units each, the root signs more records than its ceiling
/// after them, and its removal and its resolve at the end still count.
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
    let below: Vec<Record> = (0..MAX_ROOT_RECORDS as u64 + 64)
        .map(|i| g.root_rec(Kind::Copies { incoming_ms: 5_000 + i, seen: vec![] }))
        .collect();
    let rv_d = g.root_rec(Kind::Revoke(removal(&[d.hash], g.seen())));
    let resolve = g.root_rec(Kind::Resolve(vec![rv_e.id()]));
    let mut set = set_of(&g.root.key.clone());
    set.insert_all(g.recs.clone());
    assert!(set.len() < g.recs.len());
    assert!(set.contains(&rv_d.id()) && set.contains(&resolve.id()));
    // The root's records right under them are dropped: the removal stands
    // for its chain.
    assert!(!set.contains(&below.last().unwrap().id()));
    for s in [set.state(), g.state()] {
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
    let without: Vec<Record> = g.recs.iter().filter(|r| r.id() != third.id()).cloned().collect();
    let s = state_of(&g.root.key, &without);
    assert!(s.revoked.contains(&k("d").hash) && s.counting.contains(&rv.id()));
    assert!(!s.counting.contains(&sixth.id()) && s.device(&k("z").key.device_id()).is_none());
    let want = g.state();
    assert!(want.counting.contains(&sixth.id()) && want.revoked.contains(&k("d").hash));
    for seed in 1..6 {
        let mut set = set_of(&g.root.key.clone());
        set.insert_all(shuffled(&g.recs, seed));
        assert_eq!(set.state(), want, "order {seed}");
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
    let mut want = set_of(&g.root.key.clone());
    want.insert_all(g.recs.clone());
    assert!(want.len() < g.recs.len());
    for seed in 1..3 {
        let mut set = set_of(&g.root.key.clone());
        set.insert_all(shuffled(&g.recs, seed));
        assert_eq!(set.digest(), want.digest(), "order {seed}");
    }
    // And it is what the evaluation of all the records keeps.
    let strip = |s: &State| State { ignored: Vec::new(), ..s.clone() };
    assert_eq!(strip(&want.state()), strip(&g.state()));
}

/// A set of records of every kind, with a change of root: the first root,
/// the new root and the lists.
fn pool() -> (Key, Vec<Record>, Vec<Vec<u8>>) {
    let mut g = G::new();
    let root = k("root");
    let (pa, a, pb, b, pc, c) = (k("pa"), k("a"), k("pb"), k("b"), k("pc"), k("c"));
    g.admin(&pa, &a, POWER_ADMIT | POWER_REMOVE);
    g.admin(&pb, &b, POWER_ADMIT | POWER_MANAGE | POWER_FREEZE | POWER_REMOVE_ADMINS);
    g.admin(&pc, &c, POWER_THAW | POWER_REMOVE_ADMINS);
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
    g.root_rec(Kind::Revoke(removal(&[k("r2").hash], seen)));
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
    let list = g.listing();
    g.change(&k("na"), &list);
    g.device(&k("na"), &k("na phone"), "na phone", |_| {});
    g.rec(&k("na"), Kind::Revoke(removal(&[k("x3").hash], g.seen())));
    (g.root.key.clone(), g.recs, g.lists)
}

/// A set of root's group given recs and the lists their heads name, in
/// two rounds of sync: what it could not take before a list came, it takes
/// in the second.
fn set_with(root: &Key, recs: &[Record], lists: &[Vec<u8>]) -> RecordSet {
    let mut set = set_of(root);
    for _ in 0..2 {
        set.insert_all(recs.to_vec());
        for l in lists {
            let _ = set.insert_list(l);
        }
    }
    set
}

/// The records a set holds that count, without those kept aside for a
/// root whose change waits.
fn counting(set: &RecordSet) -> Vec<Record> {
    let aside: Vec<&RecordId> = set.aside().collect();
    set.ids().filter(|id| !aside.contains(id)).map(|id| set.get(id).unwrap().clone()).collect()
}

fn state_with(root: &Key, recs: &[Record], lists: &[Vec<u8>]) -> State {
    evaluate(&Input { root, recovery: &rk(), records: recs, lists })
}

mod props {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #![proptest_config(ProptestConfig { cases: 32, failure_persistence: None, ..ProptestConfig::default() })]

        /// Any order of one set, and any order of putting it into a set,
        /// gives one kept set and one state.
        #[test]
        fn any_order_one_state(seed in any::<u64>(), drop in 0usize..40) {
            let (root, recs, lists) = pool();
            // A subset, the same for both orders.
            let sub: Vec<Record> = recs.iter().enumerate().filter(|(i, _)| *i != drop).map(|(_, r)| r.clone()).collect();
            let want = state_with(&root, &sub, &lists);
            let shuffled = super::shuffled(&sub, seed);
            prop_assert_eq!(&state_with(&root, &shuffled, &lists), &want);
            let mut a = set_with(&root, &sub, &lists);
            let mut b = set_with(&root, &shuffled, &lists);
            prop_assert_eq!(a.digest(), b.digest());
            let strip = |s: &State| State { ignored: Vec::new(), ..s.clone() };
            prop_assert_eq!(strip(&a.state()), strip(&want));
            let st = a.state();
            a.compact(&st);
            let st = b.state();
            b.compact(&st);
            prop_assert_eq!(a.digest(), b.digest());
            // The set refuses what it cannot verify; its state is that of
            // the records it kept.
            let kept = counting(&a);
            let stored = state_with(&root, &kept, &lists);
            prop_assert_eq!(&a.state(), &stored);
            prop_assert_eq!(&b.state(), &stored);
            prop_assert_eq!(strip(&stored), strip(&want));
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

    /// Every list of the vectors is taken by its hash and reads as the
    /// IDs it says, bytes that are no list as the empty list.
    #[test]
    fn lists_read_as_the_vectors_say() {
        let v = records();
        let lists = v["lists"].as_array().unwrap();
        assert!(lists.iter().any(|l| l["name"].as_str().unwrap().contains("no list")));
        for l in lists {
            let name = l["name"].as_str().unwrap();
            let bytes = unhex(l["bytes"].as_str().unwrap());
            let hash: [u8; 32] = unhex(l["hash"].as_str().unwrap()).try_into().unwrap();
            assert_eq!(list_hash(&bytes), hash, "{name}");
            let list = List::of(&bytes, &hash).unwrap_or_else(|| panic!("{name}: taken by its hash"));
            assert_eq!(list.0.len() as u64, l["ids"].as_u64().unwrap(), "{name}");
        }
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
            if rule == "sig/verify" || rule == "records/group" || rule == "env/damaged" {
                continue;
            }
            let env = unhex(t["envelope"].as_str().unwrap());
            let got = Record::decode(&env).map(|r| r.body().check().map(|_| ())).and_then(|c| c);
            assert_eq!(got.map_err(|e| e.to_string()), Err(rule.to_string()), "{name}");
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
    let body = g.body(&k("root"), Kind::Freeze(removal(&[a], twice)));
    assert!(body.check().unwrap_err().is("records/freeze/seen"));
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
    Record::decode(&envelope_of(by, &bytes))
}

/// The envelope of body bytes signed by by: a body naming `signer2` (a
/// recovery head) gets K2's signature first and K1's over the body and its
/// hash, as `Record::sign_head` makes them.
fn envelope_of(by: &K, bytes: &[u8]) -> Vec<u8> {
    let named = crate::format::decode(bytes).unwrap().get(8).is_some();
    if named {
        let sig2 = crate::testkit::rk2().sign(bytes, pq::CONTEXT_RECORD).unwrap();
        let sig = key::sign_es256(by, LABEL_RECORD, &with_sig2(bytes, &sig2)).unwrap();
        return crate::format::envelope::write(bytes, &sig, Some(&sig2));
    }
    let sig = key::sign_es256(by, LABEL_RECORD, bytes).unwrap();
    crate::format::envelope::write(bytes, &sig, None)
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
            raw(&g, &root, Kind::settings(plain.clone()), |m| m.push((field, crate::format::cbor::Value::Uint(value))));
        assert_eq!(r.map(|_| ()).unwrap_err().to_string(), rule, "{field} = {value}");
    }
    let ok = raw(&g, &root, Kind::settings(plain), |m| m.push((11, crate::format::cbor::Value::Uint(3)))).unwrap();
    assert_eq!(ok.body().encode(), ok.body_bytes());
}

/// Every record the rules' tests make reads back from its envelope as the
/// same record.
#[test]
fn records_read_back_from_their_envelopes() {
    let (_, recs, _) = pool();
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
    let max = crate::format::envelope::MAX_SIG2_RECORD;
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
    let mut m1 = set_of(&g.root.key.clone());
    let mut m2 = set_of(&g.root.key.clone());
    m1.insert_all(base.iter().cloned().chain([short]).chain(later.iter().cloned()));
    m2.insert_all(base.iter().cloned().chain([long]).chain(later.iter().cloned()));
    assert_eq!(m1.len(), m2.len());
    assert_eq!(m1.digest(), m2.digest());
    assert_eq!(m1.state(), m2.state());
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

mod differential {
    use super::*;
    use proptest::prelude::*;

    /// Builds records from a list of steps: devices, removals, freezes,
    /// thaws, resolves, changes of root (now and then a second head at one
    /// seq) and checkpoints by the root, two admins and two new roots.
    fn build(steps: &[(u8, u8, u8)]) -> (G, Vec<Record>) {
        let mut g = G::new();
        let all = POWER_ADMIT | POWER_MANAGE | POWER_REMOVE | POWER_REMOVE_ADMINS | POWER_FREEZE | POWER_THAW;
        let (pa, a, pb, b) = (k("phone a"), k("admin a"), k("phone b"), k("admin b"));
        g.admin(&pa, &a, all);
        g.admin(&pb, &b, POWER_ADMIT | POWER_REMOVE | POWER_FREEZE);
        let signers = [k("root"), a, b, k("new root a"), k("new root b")];
        let devices: Vec<K> = (0..6).map(|i| k(&format!("dev {i}"))).collect();
        for &(who, op, arg) in steps {
            let by = &signers[usize::from(who) % signers.len()];
            let target = &devices[usize::from(arg) % devices.len()];
            let kind = match op % 9 {
                0 => {
                    let mut d = Device::new(target.key.clone(), "dev", ROLE_MEMBER);
                    d.rights = RIGHT_READ | RIGHT_SEND;
                    Kind::device(d)
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
                5 => {
                    let new_root = &signers[3 + usize::from(arg) % 2];
                    let list = g.listing();
                    if arg % 7 == 6 && g.heads.contains_key(&k("recovery").hash) {
                        // A second head at the recovery key's last seq.
                        let rec = k("recovery");
                        let mut twin = g.body(
                            &rec,
                            Kind::Recovery {
                                root: new_root.key.clone(),
                                list: [arg; 32],
                                from: 0,
                                first: RecordId([0xf1; 32]),
                                signer2: crate::testkit::rk2().key().hash(),
                            },
                        );
                        twin.seq -= 1;
                        twin.prev = g
                            .recs
                            .iter()
                            .find(|r| r.body().signer == rec.hash && r.body().seq + 1 == twin.seq)
                            .map(|r| r.id());
                        if let Ok(r) = Record::sign(twin, &rec) {
                            g.recs.push(r);
                        }
                    } else {
                        g.change(new_root, &list);
                    }
                    continue;
                }
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

    /// Fills a set in order, compacting now and then, as a member does,
    /// in rounds of sync until one changes nothing: a record it could not
    /// take yet comes again.
    fn fill(root: &Key, recs: &[Record], lists: &[Vec<u8>], every: usize) -> RecordSet {
        let mut m = set_of(&root.clone());
        let mut last = None;
        for _ in 0..12 {
            let now = m.digest();
            if last.as_ref() == Some(&now) {
                break;
            }
            last = Some(now);
            for (i, r) in recs.iter().enumerate() {
                let _ = m.insert(r.clone());
                for l in lists {
                    let _ = m.insert_list(l);
                }
                if (i + 1) % every == 0 {
                    let st = m.state();
                    m.compact(&st);
                }
            }
            for _ in 0..2 {
                let st = m.state();
                m.compact(&st);
            }
        }
        m
    }

    /// Compacting the set by its own state changes neither what it holds
    /// nor its state.
    fn compacted_as_it_came(set: &RecordSet) {
        let mut again = set.clone();
        let st = again.state();
        again.compact(&st);
        assert_eq!(again.digest(), set.digest(), "compacting dropped records");
        assert_eq!(again.state(), st, "compacting changed the state");
    }

    /// What a member saves (its records as it sends them, then its lists)
    /// restores to the same set, in that order or any other: the same IDs,
    /// those kept aside included, the same digest, the same state.
    fn restores(set: &RecordSet, seed: u64) {
        let saved: Vec<Record> = set.in_dependency_order().into_iter().cloned().collect();
        let lists: Vec<Vec<u8>> = set.lists().map(<[u8]>::to_vec).collect();
        let st = set.state();
        for records in [saved.clone(), shuffled(&saved, seed.wrapping_add(1))] {
            let back = RecordSet::restore(set.root().clone(), set.recovery().clone(), &records, &lists);
            assert_eq!(back.ids().collect::<Vec<_>>(), set.ids().collect::<Vec<_>>(), "restored IDs");
            assert_eq!(back.digest(), set.digest());
            assert_eq!(back.state(), st, "restored state");
        }
    }

    /// A set filled in the order of seed (0: as made), compacting every
    /// so many records, agrees with evaluate: its state is that of the
    /// records it keeps, and the roots, devices, removals and stop are
    /// those of all the records.
    fn agree(g: &G, recs: &[Record], every: usize, seed: u64) -> RecordSet {
        let order = if seed == 0 { recs.to_vec() } else { shuffled(recs, seed) };
        let m = fill(&g.root.key, &order, &g.lists, every);
        let kept = counting(&m);
        let st = m.state();
        assert_eq!(st, state_with(&g.root.key, &kept, &g.lists));
        let whole = state_with(&g.root.key, recs, &g.lists);
        assert_eq!(
            (&st.roots, &st.devices, &st.revoked, &st.stop),
            (&whole.roots, &whole.devices, &whole.revoked, &whole.stop)
        );
        assert_eq!(st.changes, whole.changes);
        // A member that never asks to compact is in the same state: a
        // counting checkpoint compacts as it comes.
        // After any insert, compacting changes nothing: no caller needs
        // to ask for it.
        let mut plain = set_of(&g.root.key);
        for _ in 0..12 {
            let before = plain.digest();
            for r in &order {
                let _ = plain.insert(r.clone());
                compacted_as_it_came(&plain);
            }
            for l in &g.lists {
                let _ = plain.insert_list(l);
                compacted_as_it_came(&plain);
            }
            if plain.digest() == before {
                break;
            }
        }
        assert_eq!(plain.digest(), m.digest());
        assert_eq!(plain.state(), st);
        restores(&m, seed);
        restores(&plain, seed);
        // One round with every list last: the records of a root whose
        // recovery record waited for its list were kept aside and taken
        // when it came, so the set ends the same.
        let mut late = set_of(&g.root.key);
        late.insert_all(order.iter().cloned());
        // Saved while a head waits for its list: what is kept aside comes
        // back.
        compacted_as_it_came(&late);
        restores(&late, seed);
        for l in &g.lists {
            let _ = late.insert_list(l);
        }
        // A halted set took nothing but the recovery records before the
        // lists came, and a head waits for its first checkpoint: the set
        // asks again for what it misses, round by round, as a member does.
        for _ in 0..4 {
            let before = late.digest();
            late.insert_all(order.iter().cloned());
            if late.digest() == before {
                break;
            }
        }
        for _ in 0..2 {
            let s = late.state();
            late.compact(&s);
        }
        restores(&late, seed);
        let ls = late.state();
        assert_eq!((ls.halted(), ls.fork), (st.halted(), st.fork));
        assert_eq!(
            (&ls.roots, &ls.devices, &ls.revoked, &ls.stop, &ls.changes),
            (&st.roots, &st.devices, &st.revoked, &st.stop, &st.changes)
        );
        m
    }

    /// A sequence once found by the property below: the set agrees with
    /// evaluate in both orders.
    #[test]
    fn agrees_after_a_newer_checkpoint_of_the_old_root() {
        let steps = [
            (0, 5, 0),
            (0, 0, 0),
            (0, 0, 0),
            (1, 0, 0),
            (0, 0, 0),
            (0, 0, 0),
            (0, 0, 0),
            (0, 0, 0),
            (0, 0, 0),
            (1, 0, 0),
            (0, 4, 2),
            (3, 0, 0),
            (0, 2, 90),
            (0, 0, 0),
            (0, 0, 0),
            (0, 0, 0),
            (1, 0, 0),
            (2, 0, 0),
            (0, 0, 0),
            (2, 5, 0),
            (4, 0, 0),
            (0, 0, 0),
            (0, 3, 0),
            (0, 0, 0),
            (0, 0, 0),
            (0, 0, 0),
            (0, 0, 0),
            (0, 0, 0),
            (0, 0, 0),
            (0, 4, 155),
            (0, 8, 163),
        ];
        let (g, recs) = build(&steps);
        agree(&g, &recs, 5, 0);
        agree(&g, &recs, 7, 17_255_029_705_063_971_860);
    }

    /// A sequence once found by the property below: a resolve of the root
    /// after the set compacted by its checkpoint.
    #[test]
    fn agrees_when_a_resolve_takes_a_checkpoint_out() {
        let steps = [
            (0, 0, 0),
            (0, 0, 0),
            (0, 0, 0),
            (4, 0, 0),
            (4, 0, 0),
            (1, 0, 0),
            (0, 6, 0),
            (0, 0, 0),
            (0, 0, 0),
            (2, 0, 0),
            (0, 0, 0),
            (0, 0, 0),
            (0, 0, 0),
            (0, 0, 0),
            (0, 0, 0),
            (0, 6, 0),
            (0, 6, 0),
            (0, 0, 0),
            (0, 0, 0),
            (4, 4, 162),
            (0, 0, 0),
            (0, 0, 0),
            (0, 0, 0),
            (0, 0, 0),
            (0, 5, 7),
            (0, 8, 66),
            (0, 0, 0),
            (0, 6, 0),
            (0, 0, 0),
            (0, 4, 124),
            (0, 0, 0),
            (0, 0, 0),
            (0, 0, 0),
        ];
        let (g, recs) = build(&steps);
        agree(&g, &recs, 1, 0);
        agree(&g, &recs, 3, 65241865646381);
    }

    /// Another such sequence, the resolve after two root records arriving
    /// one by one.
    #[test]
    fn agrees_when_a_resolve_comes_after_the_checkpoint() {
        let steps = [
            (0, 0, 0),
            (0, 0, 0),
            (1, 0, 0),
            (0, 0, 0),
            (0, 0, 0),
            (0, 0, 0),
            (0, 0, 0),
            (0, 0, 0),
            (0, 6, 0),
            (0, 0, 0),
            (0, 5, 125),
            (0, 6, 0),
            (4, 0, 0),
            (0, 0, 0),
            (0, 5, 43),
            (4, 0, 0),
            (0, 0, 0),
            (0, 0, 0),
            (0, 6, 0),
            (4, 8, 0),
            (4, 4, 71),
            (0, 2, 0),
            (0, 0, 0),
            (0, 0, 0),
            (0, 0, 0),
            (0, 0, 0),
            (0, 0, 0),
            (0, 0, 0),
            (0, 0, 0),
            (0, 0, 0),
            (0, 0, 0),
            (0, 0, 0),
            (0, 0, 0),
            (0, 0, 0),
            (0, 0, 0),
            (0, 0, 0),
            (0, 0, 0),
            (0, 0, 0),
        ];
        let (g, recs) = build(&steps);
        agree(&g, &recs, 1, 0);
        agree(&g, &recs, 3, 17222876326135848401);
    }

    /// A sequence once found by the property below: the set agrees with
    /// evaluate in both orders.
    #[test]
    fn agrees_with_a_checkpoint_above_a_head() {
        let steps = [
            (3, 6, 132),
            (3, 0, 84),
            (0, 0, 25),
            (1, 3, 0),
            (1, 5, 20),
            (1, 4, 10),
            (0, 3, 0),
            (0, 0, 0),
            (1, 4, 168),
            (0, 0, 2),
            (2, 1, 104),
            (0, 0, 0),
            (0, 0, 0),
            (1, 5, 31),
            (3, 0, 0),
            (0, 0, 0),
            (0, 0, 0),
            (0, 0, 0),
            (0, 0, 0),
            (0, 0, 0),
            (3, 8, 49),
            (0, 0, 0),
            (0, 0, 0),
            (0, 0, 0),
            (0, 0, 0),
            (0, 0, 0),
        ];
        let (g, recs) = build(&steps);
        agree(&g, &recs, 1, 0);
        agree(&g, &recs, 3, 15_461_929_454);
    }

    /// A sequence once found by the property below: the set agrees with
    /// evaluate in both orders.
    #[test]
    fn agrees_with_a_checkpoint_it_pruned_by_early() {
        let steps = [(1, 5, 44), (2, 2, 223), (1, 3, 0), (3, 2, 1), (2, 5, 125), (3, 0, 0), (3, 8, 68), (0, 0, 0)];
        let (g, recs) = build(&steps);
        agree(&g, &recs, 1, 0);
        agree(&g, &recs, 3, 0);
    }

    /// Every order of recs, never compacted or compacting every 1, 2 or 3
    /// records, ends as evaluate of them all, with stop.
    fn every_order(g: &G, recs: &[Record], stop: Stop) {
        fn perms(items: &[Record]) -> Vec<Vec<Record>> {
            if items.len() <= 1 {
                return vec![items.to_vec()];
            }
            let mut out = Vec::new();
            for i in 0..items.len() {
                let mut rest = items.to_vec();
                let first = rest.remove(i);
                for mut p in perms(&rest) {
                    p.insert(0, first.clone());
                    out.push(p);
                }
            }
            out
        }
        let whole = state_with(&g.root.key, recs, &g.lists);
        assert_eq!(whole.stop, stop);
        for order in perms(recs) {
            let s = set_with(&g.root.key, &order, &g.lists).state();
            assert_eq!(
                (&s.devices, &s.stop, &s.counting),
                (&whole.devices, &whole.stop, &whole.counting),
                "never compacted"
            );
            for every in [1, 2, 3] {
                let s = fill(&g.root.key, &order, &g.lists, every).state();
                assert_eq!(
                    (&s.roots, &s.devices, &s.revoked, &s.stop, &s.counting),
                    (&whole.roots, &whole.devices, &whole.revoked, &whole.stop, &whole.counting),
                    "every {every}"
                );
            }
        }
    }

    /// Found by the fuzzer: the root signs two records at seq 1; its later
    /// checkpoints chain from one and keep the other. The pair is a fork
    /// at any depth: the group stops and no checkpoint above it counts, in
    /// every order (the checkpoints and the kept twin before the other
    /// included).
    #[test]
    fn agrees_on_two_records_of_the_root_at_one_seq_under_its_checkpoints() {
        let mut g = G::new();
        let root = k("root");
        let dev = g.device(&root, &k("dev 5"), "dev", |_| {});
        let twin = Record::sign(
            Body { seq: 1, prev: None, ..g.body(&root, Kind::Copies { incoming_ms: MIN_INCOMING_MS, seen: vec![] }) },
            &root,
        )
        .unwrap();
        g.recs.push(twin.clone());
        let head = |g: &G| {
            let (seq, id) = g.heads[&root.hash];
            vec![Head { key: root.hash, seq, id }]
        };
        let h = head(&g);
        let c2 = g.root_rec(Kind::Checkpoint { heads: h, keep: vec![] });
        let mut later = Vec::new();
        for _ in 0..2 {
            let h = head(&g);
            later.push(g.root_rec(Kind::Checkpoint { heads: h, keep: vec![twin.id()] }));
        }
        let recs = g.recs.clone();
        every_order(&g, &recs, Stop::Full);
        let order = vec![later[0].clone(), twin.clone(), c2, dev.clone(), later[1].clone()];
        let s = fill(&g.root.key, &order, &g.lists, 1).state();
        assert_eq!(s.stop, Stop::Full);
        assert!(s.checkpoint.is_none() && !s.counting.contains(&twin.id()) && !s.counting.contains(&dev.id()));
    }

    /// Found by the fuzzer: two records of the root at seq 1, a device on
    /// one of them, and a checkpoint above that keeps nothing below its
    /// head: the pair stops the group and the checkpoint does not count,
    /// in every order.
    #[test]
    fn agrees_on_twins_under_a_checkpoint() {
        let mut g = G::new();
        let root = k("root");
        let copies = |g: &G, i: u64| {
            Record::sign(
                Body {
                    seq: 1,
                    prev: None,
                    ..g.body(&root, Kind::Copies { incoming_ms: MIN_INCOMING_MS + i, seen: vec![] })
                },
                &root,
            )
            .unwrap()
        };
        let (a, b) = (copies(&g, 0), copies(&g, 1));
        g.push(a.clone());
        g.recs.push(b);
        let dev = g.device(&root, &k("dev 2"), "dev", |_| {});
        assert_eq!(dev.body().prev, Some(a.id()));
        let (seq, id) = g.heads[&root.hash];
        g.root_rec(Kind::Checkpoint { heads: vec![Head { key: root.hash, seq, id }], keep: vec![] });
        let recs = g.recs.clone();
        every_order(&g, &recs, Stop::Full);
        let s = g.state();
        assert!(s.checkpoint.is_none() && s.device_by_key(&k("dev 2").hash).is_none());
    }

    /// Found by the fuzzer: a second head's list names a checkpoint of the
    /// root between (with its removal, the first head and an ID nobody
    /// holds). That checkpoint is an anchor only: it prunes nothing and is
    /// not the state's checkpoint, in the set and in evaluate alike.
    #[test]
    fn agrees_on_a_listed_checkpoint_of_an_earlier_root() {
        let mut g = G::new();
        let root = k("root");
        let (na, nb) = (k("new root a"), k("new root b"));
        let d0 = g.device(&root, &k("dev 0"), "dev", |_| {});
        let phone = g.device(&nb, &k("phone a"), "phone", |d| {
            d.role = ROLE_PHONE;
            d.holds_root = true;
        });
        let rm = g.rec(&nb, Kind::Revoke(removal(&[k("dev 7").hash], vec![])));
        let mut keep = vec![phone.id(), d0.id()];
        keep.sort();
        let cp = g.rec(&nb, Kind::Checkpoint { heads: vec![Head { key: nb.hash, seq: 2, id: rm.id() }], keep });
        let h1 = g.change(&nb, &[d0.id()]);
        g.change(&na, &[RecordId([0x5d; 32]), cp.id(), rm.id(), h1.id()]);
        let recs = g.recs.clone();
        for seed in 0..12u64 {
            for every in [1, 2, 3] {
                let m = agree(&g, &recs, every, seed.wrapping_mul(0x9e37_79b9_7f4a_7c15));
                assert_eq!(m.state().checkpoint, None, "seed {seed}, every {every}");
            }
        }
    }

    /// A sequence once found by the property below: the set agrees with
    /// evaluate in both orders.
    #[test]
    fn agrees_with_a_head_after_a_pruning_checkpoint() {
        let steps = [
            (1, 5, 92),
            (0, 0, 30),
            (1, 4, 28),
            (0, 1, 31),
            (0, 2, 47),
            (0, 0, 0),
            (1, 2, 151),
            (3, 2, 32),
            (1, 5, 83),
            (3, 0, 0),
            (3, 8, 19),
        ];
        let (g, recs) = build(&steps);
        agree(&g, &recs, 1, 0);
        agree(&g, &recs, 3, 0);
    }

    /// A new root's checkpoint signed before it took the group, whole
    /// with an empty keep, never counts in its place: in any order the
    /// set holds what its first checkpoint keeps, as evaluate does.
    #[test]
    fn a_checkpoint_from_before_the_change_never_counts() {
        let steps: Vec<(u8, u8, u8)> = vec![
            (0, 6, 0),
            (0, 0, 0),
            (0, 6, 0),
            (0, 6, 0),
            (0, 6, 0),
            (0, 6, 0),
            (3, 6, 0),
            (3, 8, 0),
            (0, 0, 0),
            (0, 0, 0),
            (0, 0, 0),
            (0, 0, 0),
            (0, 0, 0),
            (0, 0, 0),
            (0, 0, 0),
            (0, 5, 0),
            (0, 2, 0),
            (0, 0, 0),
            (0, 0, 0),
            (0, 5, 72),
            (0, 0, 0),
            (0, 0, 0),
            (0, 0, 0),
            (0, 5, 63),
            (0, 0, 0),
            (0, 0, 0),
            (0, 0, 0),
        ];
        let (g, recs) = build(&steps);
        let m1 = agree(&g, &recs, 4, 0);
        let m2 = agree(&g, &recs, 6, 1_319_781_888_007_025_613);
        assert_eq!(m1.digest(), m2.digest());
        assert_eq!(m1.state(), m2.state());
        assert!(!m1.state().devices.is_empty());
    }

    proptest! {
        #![proptest_config(ProptestConfig { cases: 96, failure_persistence: None, ..ProptestConfig::default() })]

        /// A set's state is evaluate's state of the records it keeps, and
        /// of all the records, whatever the order and the compactions; two
        /// sets of the same records keep the same records.
        #[test]
        fn a_set_agrees_with_evaluate(
            steps in prop::collection::vec((0u8..5, 0u8..9, any::<u8>()), 4..40),
            seed in 1u64..,
            every in 1usize..8,
        ) {
            let (g, recs) = build(&steps);
            let m1 = agree(&g, &recs, every, 0);
            let m2 = agree(&g, &recs, every.saturating_add(2), seed);
            prop_assert_eq!(m1.digest(), m2.digest());
            prop_assert_eq!(m1.state(), m2.state());
        }
    }
}

/// Two records at one seq stop the secrets only for a live admin of the
/// epoch: not for a removed admin, nor for a key nothing names.
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
    let all = POWER_ADMIT | POWER_REMOVE | POWER_REMOVE_ADMINS;
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
    let max = crate::format::envelope::MAX_SIG2_RECORD;
    let r = Record::decode(&crate::format::envelope::write(&bytes, &sig, Some(&vec![0x55u8; max]))).unwrap();
    let plain = Record::sign(g.body(&a, Kind::Copies { incoming_ms: 60_000, seen: vec![] }), &a).unwrap();
    let units = |r: &Record| keep::units(r.size());
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

/// A thaw brings back what it lists of the frozen key: a record the
/// key signed that the thaw saw counts again; one from the frozen time it
/// did not see stays cut. What the key signs after, listing the thaw in
/// its own seen, counts; one that does not list it stays cut. The same
/// for a root's thaw, and the state agrees: the key may command.
#[test]
fn a_thaw_brings_back_what_it_lists_and_what_lists_it() {
    let both = |by_root: bool| {
        let mut g = G::new();
        let (pw, w, pp, p) = (k("watch"), k("admin w"), k("phone p"), k("admin p"));
        g.admin(&pw, &w, POWER_REMOVE | POWER_FREEZE);
        g.admin(&pp, &p, POWER_REMOVE_ADMINS | POWER_FREEZE | POWER_THAW);
        g.device(&k("root"), &k("laptop"), "laptop", |_| {});
        g.device(&k("root"), &k("tablet"), "tablet", |_| {});
        g.device(&k("root"), &k("phone"), "phone", |_| {});
        g.device(&k("root"), &k("tv"), "tv", |_| {});
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
        let thawer = if by_root { k("root").hash } else { p.hash };
        let blind: Vec<Seen> = g.seen().into_iter().filter(|x| x.key != thawer).collect();
        let unseeing = g.rec(&w, Kind::Revoke(removal(&[k("phone").hash], blind)));
        let seen = g.seen();
        let after = g.rec(&w, Kind::Revoke(removal(&[k("tv").hash], seen)));
        let s = g.state();
        assert!(s.counting.contains(&listed.id()) && s.revoked.contains(&k("laptop").hash), "root {by_root}");
        assert!(!s.counting.contains(&unlisted.id()) && !s.revoked.contains(&k("tablet").hash), "root {by_root}");
        assert!(!s.counting.contains(&unseeing.id()) && !s.revoked.contains(&k("phone").hash), "root {by_root}");
        assert!(s.counting.contains(&after.id()) && s.revoked.contains(&k("tv").hash), "root {by_root}");
        assert!(s.device(&pw.key.device_id()).is_some_and(|d| !d.frozen), "root {by_root}");
        assert!(s.may_command(&w.hash), "root {by_root}");
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
    let all = POWER_ADMIT | POWER_REMOVE;
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
    let s = g.state();
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

/// When the root key signs a twin at a removal's seq, the group stops and
/// the removal still counts, so what either history removed stays out;
/// the twin counts for nothing.
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
    let mut set = set_of(&g.root.key.clone());
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

/// The signatures this thread verifies while f runs.
fn verified_by<T>(f: impl FnOnce() -> T) -> (T, usize) {
    let before = super::VERIFIED.with(|n| n.get());
    let out = f();
    (out, super::VERIFIED.with(|n| n.get()) - before)
}

/// A record's signature is verified once: by evaluate however many
/// passes its path takes, and by a set when the record enters it, never
/// again by its state, its compaction or a record offered again.
#[test]
fn each_signature_is_verified_once() {
    let g = changed_group();
    let (s, n) = verified_by(|| g.state());
    assert_eq!(s.roots.len(), 2);
    assert_eq!(n, g.recs.len());
    // A set: each record once, when it enters.
    let mut set = set_of(&g.root.key.clone());
    let (_, n) = verified_by(|| {
        // As members pass them: the heads with their lists, then the rest.
        set.insert_all(g.recs.iter().filter(|r| matches!(r.body().kind, Kind::Recovery { .. })).cloned());
        for l in &g.lists {
            set.insert_list(l).unwrap();
        }
        set.insert_all(g.recs.iter().cloned());
    });
    assert_eq!(n, g.recs.len());
    let (_, n) = verified_by(|| {
        for _ in 0..3 {
            let st = set.state();
            set.compact(&st);
            set.insert_all(g.recs.iter().cloned());
        }
    });
    assert_eq!(n, 0);
}

/// A set whose key is at its ceiling takes one more record for far less
/// than an evaluation of all it holds: its signature, and a cut.
#[test]
fn one_more_record_costs_one_verification_at_most() {
    let mut g = G::new();
    let (p, a) = (k("phone a"), k("admin a"));
    g.admin(&p, &a, POWER_ADMIT);
    let mut set = set_of(&g.root.key.clone());
    set.insert_all(g.recs.iter().cloned());
    // Past the admin key's ceiling: each record more makes the set cut.
    for i in 0..keep::ceiling(false) + 40 {
        let r = g.device(&a, &k(&format!("d{i}")), "d", |_| {});
        set.insert(r).ok();
    }
    assert!(set.len() < g.recs.len());
    // A record the set keeps: its signature, once.
    let r = g.device(&k("root"), &k("one more"), "d", |_| {});
    let (added, n) = verified_by(|| set.insert(r.clone()));
    assert_eq!(added, Ok(Added::Stored));
    assert_eq!(n, 1);
    let (added, n) = verified_by(|| set.insert(r));
    assert_eq!((added, n), (Ok(Added::Known), 0));
    // One past where its key stopped: turned away before verifying.
    let late = g.device(&a, &k("late"), "d", |_| {});
    let (added, n) = verified_by(|| set.insert(late));
    assert_eq!((added, n), (Ok(Added::NoRoom), 0));
}

/// A first record that does not count stands in the way of none that
/// does: once the root named another admin key for a device, the old
/// key's record for a new device does not count, and the new key's for
/// that device admits it, in the evaluation and in a set.
#[test]
fn a_replaced_admin_key_does_not_block_the_new_one() {
    let mut g = G::new();
    let (pc, c, c2, d) = (k("computer c"), k("admin c"), k("admin c2"), k("device d"));
    g.admin(&pc, &c, POWER_ADMIT | POWER_MANAGE);
    let seen = g.seen();
    g.device(&k("root"), &pc, "admin", |dv| {
        dv.admin = Some(c2.key.clone());
        dv.powers = POWER_ADMIT | POWER_MANAGE;
        dv.seen = seen;
    });
    let old = g.device(&c, &d, "d", |_| {});
    assert!(g.state().device_by_key(&d.hash).is_none());
    let new = g.device(&c2, &d, "d", |_| {});
    let s = g.state();
    assert!(s.device_by_key(&d.hash).is_some());
    assert!(s.counting.contains(&new.id()) && !s.counting.contains(&old.id()));
    assert!(s.conflicts.is_empty());
    let mut set = set_of(&g.root.key.clone());
    set.insert_all(g.recs.iter().cloned());
    assert!(set.state().device_by_key(&d.hash).is_some());
}

/// Gives the set the records and the lists, in two rounds, then compacts
/// until it settles.
fn sync_all(m: &mut RecordSet, recs: &[Record], lists: &[Vec<u8>]) {
    // Two rounds: what the set could not take before a list came, it takes
    // in the second.
    for _ in 0..2 {
        m.insert_all(recs.iter().cloned());
        for l in lists {
            let _ = m.insert_list(l);
        }
    }
    for _ in 0..4 {
        let st = m.state();
        m.compact(&st);
    }
}

/// A checkpoint names its own key's head below itself.
#[test]
fn a_checkpoints_own_head_is_below_it() {
    let mut g = G::new();
    let root = k("root");
    g.device(&root, &k("laptop"), "laptop", |_| {});
    let (seq, id) = g.heads[&root.hash];
    let body = g.body(&root, Kind::Checkpoint { heads: vec![Head { key: root.hash, seq: seq + 1, id }], keep: vec![] });
    assert!(Record::sign(body, &root).is_err());
    let ok = g.body(&root, Kind::Checkpoint { heads: vec![Head { key: root.hash, seq, id }], keep: vec![] });
    assert!(Record::sign(ok, &root).is_ok());
}

/// A set with an admin key at its ceiling, and the records it keeps.
fn set_at_a_ceiling() -> (G, RecordSet) {
    let mut g = G::new();
    let (p, a) = (k("phone a"), k("admin a"));
    g.admin(&p, &a, POWER_ADMIT);
    for i in 0..keep::ceiling(false) + 8 {
        g.device(&a, &k(&format!("d{i}")), "d", |_| {});
    }
    let mut set = set_of(&g.root.key.clone());
    set.insert_all(g.recs.iter().cloned());
    (g, set)
}

/// The records a device saves in its own store, as it reads them back.
fn saved(set: &RecordSet, local: &[u8; 32]) -> Vec<(Record, Option<Mark>)> {
    set.marked(local).into_iter().map(|(r, m)| (Record::decode(&r.envelope()).unwrap(), Some(m))).collect()
}

/// Records loaded from the device's own store with their marks are taken
/// without verifying a signature, into the same set.
#[test]
fn marked_records_load_without_their_signatures() {
    let local = [7u8; 32];
    let (_, set) = set_at_a_ceiling();
    let store = saved(&set, &local);
    let mut loaded = set_of(set.root());
    let ((stored, refused), n) = verified_by(|| loaded.load_marked(&local, store.clone()));
    assert_eq!((stored, refused.len(), n), (set.len(), 0, 0));
    assert_eq!(loaded.digest(), set.digest());
    assert_eq!(loaded.state(), set.state());
    // Without marks, each record is verified as if new.
    let mut plain = set_of(set.root());
    let bare: Vec<(Record, Option<Mark>)> = store.into_iter().map(|(r, _)| (r, None)).collect();
    let (_, n) = verified_by(|| plain.load_marked(&local, bare));
    assert_eq!(n, set.len());
}

/// A record whose mark is wrong goes through its signature: a good one
/// is taken, a bad one refused. Under another local key every record is
/// verified.
#[test]
fn a_wrong_mark_falls_back_to_the_signature() {
    let local = [7u8; 32];
    let (_, set) = set_at_a_ceiling();
    let store = saved(&set, &local);
    let last = store.len() - 1;
    let mut flipped = store.clone();
    if let Some((_, Some(m))) = flipped.get_mut(last) {
        m[5] ^= 1;
    }
    let mut loaded = set_of(set.root());
    let ((stored, refused), n) = verified_by(|| loaded.load_marked(&local, flipped));
    assert_eq!((stored, refused.len(), n), (set.len(), 0, 1));
    assert_eq!(loaded.digest(), set.digest());
    // One flipped byte in a record's signature: its mark no longer holds,
    // and its signature does not verify.
    let mut env = store[last].0.envelope();
    let at = env.len() - 1;
    env[at] ^= 1;
    let mut broken = store.clone();
    broken[last].0 = Record::decode(&env).unwrap();
    let mut loaded = set_of(set.root());
    let ((stored, refused), n) = verified_by(|| loaded.load_marked(&local, broken));
    assert_eq!((stored, n), (set.len() - 1, 1));
    assert!(matches!(refused.as_slice(), [(_, Refused::Broken(_))]));
    // Another local key: no mark holds.
    let mut other = set_of(set.root());
    let ((stored, _), n) = verified_by(|| other.load_marked(&[8u8; 32], store));
    assert_eq!((stored, n), (set.len(), set.len()));
    assert_eq!(other.digest(), set.digest());
}

/// A thawed admin admits again: its device record that lists the thaw
/// counts, as the state's may_command says.
#[test]
fn a_thawed_admin_admits_again() {
    let mut g = G::new();
    let (pw, w, pp, p) = (k("computer"), k("admin w"), k("phone p"), k("admin p"));
    g.admin(&pw, &w, POWER_ADMIT | POWER_MANAGE);
    g.admin(&pp, &p, POWER_REMOVE_ADMINS | POWER_FREEZE | POWER_THAW);
    let seen = g.seen();
    let fr = g.rec(&p, Kind::Freeze(removal(&[w.hash], seen)));
    let seen = g.seen();
    g.rec(&p, Kind::Thaw { ids: vec![fr.id()], seen });
    let seen = g.seen();
    let admit = g.device(&w, &k("tv"), "tv", |d| d.seen = seen);
    let s = g.state();
    assert!(s.may_command(&w.hash));
    assert!(s.counting.contains(&admit.id()));
    assert!(s.device(&k("tv").key.device_id()).is_some());
}

/// A checkpoint of the root that names the records it keeps, and so
/// prunes the rest at or below its head.
fn checkpoint_keeping(g: &mut G, keep: &[&Record]) -> Record {
    let root = k("root");
    let (seq, id) = g.heads[&root.hash];
    let mut keep: Vec<RecordId> = keep.iter().map(|r| r.id()).collect();
    keep.sort();
    g.root_rec(Kind::Checkpoint { heads: vec![Head { key: root.hash, seq, id }], keep })
}

/// The state of each member: evaluate over all records, and sets filled
/// in both orders and compacted.
fn members_agree(g: &G) -> State {
    let s = g.state();
    for order in 0..2 {
        let mut recs = g.recs.clone();
        if order == 1 {
            recs.reverse();
        }
        let mut m = set_of(&g.root.key.clone());
        sync_all(&mut m, &recs, &g.lists);
        let from_set = m.state();
        assert_eq!(
            (&from_set.roots, &from_set.devices, &from_set.revoked, &from_set.changes),
            (&s.roots, &s.devices, &s.revoked, &s.changes),
            "order {order}"
        );
    }
    s
}

mod cap;
mod insert_cost;
mod recovery;
mod sync;
mod traces;

/// A checkpoint and the head below it that fills its key's room: the
/// checkpoint prunes before the room is judged, so a member that took the
/// head first and one that took the checkpoint first hold the same.
#[test]
fn a_checkpoint_prunes_before_the_room_is_judged() {
    let mut g = G::new();
    let root = k("root");
    let laptop = g.device(&root, &k("laptop"), "laptop", |_| {});
    for i in 1..(MAX_ROOT_RECORDS as u64 - 1) {
        g.root_rec(Kind::Copies { incoming_ms: 5_000 + i, seen: vec![] });
    }
    let head = g.root_rec(Kind::Copies { incoming_ms: 9_999, seen: vec![] });
    let (seq, id) = g.heads[&root.hash];
    let cp = g.root_rec(Kind::Checkpoint { heads: vec![Head { key: root.hash, seq, id }], keep: vec![laptop.id()] });
    let before: Vec<Record> = g.recs[..g.recs.len() - 2].to_vec();
    let mut sets = Vec::new();
    for order in [[head.clone(), cp.clone()], [cp.clone(), head.clone()]] {
        let mut set = set_of(&g.root.key.clone());
        set.insert_all(before.clone());
        assert_eq!(set.len(), MAX_ROOT_RECORDS - 1);
        for r in order {
            assert_eq!(set.insert(r), Ok(Added::Stored));
        }
        let s = set.state();
        assert_eq!(s.checkpoint, Some(cp.id()));
        assert!(set.contains(&head.id()) && s.counting.contains(&head.id()));
        sets.push((set.digest(), s));
    }
    assert_eq!(sets[0], sets[1]);
}

/// A newer checkpoint that cannot count (it keeps an ID nobody holds)
/// waits: the one below it keeps counting with everything it names, and
/// what the newer one keeps that the rooms turn away waits in the place
/// aside without counting, in any order.
#[test]
fn a_checkpoint_naming_an_unheld_id_leaves_the_counting_one_counting() {
    let mut g = G::new();
    let root = k("root");
    g.device(&root, &k("laptop"), "laptop", |_| {});
    for i in 0..5 {
        g.root_rec(Kind::Copies { incoming_ms: 5_000 + i, seen: vec![] });
    }
    let (seq, id) = g.heads[&root.hash];
    let below: Vec<RecordId> = g.recs.iter().filter(|r| r.id() != id).map(Record::id).collect();
    let mut keep = below.clone();
    keep.sort();
    let counting = g.root_rec(Kind::Checkpoint { heads: vec![Head { key: root.hash, seq, id }], keep });
    let late: Vec<Record> = (0..2).map(|i| g.root_rec(Kind::Copies { incoming_ms: 9_000 + i, seen: vec![] })).collect();
    let (seq, id) = g.heads[&root.hash];
    let mut keep: Vec<RecordId> = below.iter().copied().chain([late[0].id(), RecordId([0x5a; 32])]).collect();
    keep.sort();
    let waits = g.root_rec(Kind::Checkpoint { heads: vec![Head { key: root.hash, seq, id }], keep });
    let small = crate::records::keep::small::Small::new(14, 8, 5);
    for r in &g.recs {
        small.units(r.id(), 1);
    }
    let mut sets = Vec::new();
    for seed in [0, 1, 2, 3, 4] {
        let order = if seed == 0 { g.recs.clone() } else { shuffled(&g.recs, seed) };
        let set = set_with(&g.root.key, &order, &g.lists);
        let st = set.state();
        assert_eq!(st.checkpoint, Some(counting.id()), "order {seed}");
        assert!(below.iter().all(|id| set.contains(id) && st.counting.contains(id)), "order {seed}");
        // The newer one is kept first; what it keeps that the rooms turn
        // away waits aside, counting for nothing and outside the digest.
        assert!(set.contains(&waits.id()) && set.waits_aside(&late[0].id()), "order {seed}");
        assert!(set.ids().all(|id| *id != late[0].id()), "order {seed}");
        let held: Vec<Record> = set.ids().map(|id| set.get(id).unwrap().clone()).collect();
        assert_eq!(st, state_with(&g.root.key, &held, &g.lists), "order {seed}");
        sets.push((set.digest(), st));
    }
    assert!(sets.windows(2).all(|w| w[0] == w[1]));
}

/// A record a counting checkpoint pruned, which the root's newer
/// checkpoint keeps again, is taken back by a member that pruned it, which
/// then counts the newer one: it ends as a member handed everything at
/// once.
#[test]
fn a_record_a_newer_checkpoint_keeps_again_comes_back() {
    let mut g = G::new();
    let root = k("root");
    let laptop = g.device(&root, &k("laptop"), "laptop", |_| {});
    let x = g.device(&root, &k("x"), "x", |_| {});
    let phone = g.device(&root, &k("phone"), "phone", |_| {});
    let (seq, id) = g.heads[&root.hash];
    let older = g.root_rec(Kind::Checkpoint { heads: vec![Head { key: root.hash, seq, id }], keep: vec![laptop.id()] });
    let tv = g.device(&root, &k("tv"), "tv", |_| {});
    let (seq, id) = g.heads[&root.hash];
    let mut keep = vec![laptop.id(), x.id(), phone.id(), older.id()];
    keep.sort();
    let newer = g.root_rec(Kind::Checkpoint { heads: vec![Head { key: root.hash, seq, id }], keep });
    let at_once = set_with(&g.root.key, &g.recs, &g.lists);
    assert_eq!(at_once.state().checkpoint, Some(newer.id()));
    for late_first in [false, true] {
        let mut m = set_with(&g.root.key, &g.recs[..4], &g.lists);
        let st = m.state();
        m.compact(&st);
        assert_eq!(m.state().checkpoint, Some(older.id()));
        assert!(!m.contains(&x.id()), "the older checkpoint pruned it");
        let mut rest = vec![tv.clone(), newer.clone(), x.clone()];
        if late_first {
            rest.reverse();
        }
        sync_all(&mut m, &rest, &g.lists);
        sync_all(&mut m, &g.recs, &g.lists);
        assert_eq!(m.state().checkpoint, Some(newer.id()), "late first {late_first}");
        assert_eq!(m.digest(), at_once.digest(), "late first {late_first}");
        assert_eq!(m.state(), at_once.state(), "late first {late_first}");
    }
}

/// A checkpoint that waits below a newer one that waits too counts once
/// it is whole, the newer one still waiting; once the member is synced
/// with one that holds everything, both count the newer.
#[test]
fn only_the_newest_checkpoint_waits() {
    let mut g = G::new();
    let root = k("root");
    g.device(&root, &k("laptop"), "laptop", |_| {});
    for i in 0..4 {
        g.root_rec(Kind::Copies { incoming_ms: 5_000 + i, seen: vec![] });
    }
    let (seq, id) = g.heads[&root.hash];
    let mut keep: Vec<RecordId> = g.recs.iter().filter(|r| r.id() != id).map(Record::id).collect();
    keep.sort();
    let counting = g.root_rec(Kind::Checkpoint { heads: vec![Head { key: root.hash, seq, id }], keep: keep.clone() });
    let y = g.root_rec(Kind::Copies { incoming_ms: 7_000, seen: vec![] });
    let z = g.root_rec(Kind::Copies { incoming_ms: 7_001, seen: vec![] });
    let (seq, id) = g.heads[&root.hash];
    let mut k18 = keep.clone();
    k18.push(y.id());
    k18.sort();
    let c18 = g.root_rec(Kind::Checkpoint { heads: vec![Head { key: root.hash, seq, id }], keep: k18 });
    let w = g.root_rec(Kind::Copies { incoming_ms: 7_002, seen: vec![] });
    let (seq, id) = g.heads[&root.hash];
    let mut k19 = keep.clone();
    k19.extend([z.id(), c18.id()]);
    k19.sort();
    let c19 = g.root_rec(Kind::Checkpoint { heads: vec![Head { key: root.hash, seq, id }], keep: k19 });
    let small = crate::records::keep::small::Small::new(14, 9, 5);
    for r in &g.recs {
        small.units(r.id(), 1);
    }
    let base: Vec<Record> =
        g.recs.iter().filter(|r| ![&y, &z, &w, &c18, &c19].iter().any(|o| o.id() == r.id())).cloned().collect();
    let mut m = set_with(&g.root.key, &base, &g.lists);
    assert_eq!(m.state().checkpoint, Some(counting.id()));
    // 18 waits for y; 19 comes, waiting for z, w and 18's being held;
    // y comes after: 18, whole now, counts below 19, which still waits.
    sync_all(&mut m, &[c18.clone(), c19.clone()], &g.lists);
    assert_eq!(m.state().checkpoint, Some(counting.id()));
    sync_all(&mut m, core::slice::from_ref(&y), &g.lists);
    assert_eq!(m.state().checkpoint, Some(c18.id()));
    assert!(m.contains(&c19.id()));
    let peer = set_with(&g.root.key, &g.recs, &g.lists);
    assert_eq!(peer.state().checkpoint, Some(c19.id()));
    let theirs: Vec<Record> = peer.ids().map(|id| peer.get(id).unwrap().clone()).collect();
    sync_all(&mut m, &theirs, &g.lists);
    assert_eq!(m.state().checkpoint, Some(c19.id()));
    assert_eq!(m.digest(), peer.digest());
    assert_eq!(m.state(), peer.state());
}

/// A second record of the root at r's seq, on r's prev: not pushed.
fn root_twin(g: &G, r: &Record, kind: Kind) -> Record {
    let b = r.body();
    let body = Body { group: g.gid, signer: b.signer, seq: b.seq, prev: b.prev, time_ms: 0, kind, held: false };
    Record::sign(body, &k("root")).unwrap()
}

/// The root's checkpoint at its head now, keeping keep.
fn root_cp(g: &mut G, mut keep: Vec<RecordId>) -> Record {
    let root = k("root");
    let (seq, id) = g.heads[&root.hash];
    keep.sort();
    g.root_rec(Kind::Checkpoint { heads: vec![Head { key: root.hash, seq, id }], keep })
}

/// Checkpoints 7, 8 and 9 of the root: 7 prunes x's admission, 8 keeps it
/// again, 9 keeps an ID nobody holds and is never whole. A member that
/// counted 8 before 9 came and one that counted 7 and was handed 9 first
/// end alike after a sync: every checkpoint above the counting one may
/// count, and what any of them keeps comes back.
#[test]
fn a_checkpoint_that_is_never_whole_holds_back_nobody() {
    let mut g = G::new();
    let laptop = g.device(&k("root"), &k("laptop"), "laptop", |_| {});
    let x = g.device(&k("root"), &k("x"), "x", |_| {});
    g.root_rec(Kind::Copies { incoming_ms: 5_000, seen: vec![] });
    let c7 = root_cp(&mut g, vec![laptop.id()]);
    let c8 = root_cp(&mut g, vec![laptop.id(), x.id(), c7.id()]);
    let c9 = root_cp(&mut g, vec![laptop.id(), c8.id(), RecordId([0x59; 32])]);
    let upto = |r: &Record| g.recs.iter().position(|o| o.id() == r.id()).unwrap() + 1;
    let mut m1 = set_with(&g.root.key, &g.recs[..upto(&c8)], &g.lists);
    assert_eq!(m1.state().checkpoint, Some(c8.id()));
    sync_all(&mut m1, core::slice::from_ref(&c9), &g.lists);
    let mut m2 = set_with(&g.root.key, &g.recs[..upto(&c7)], &g.lists);
    sync_all(&mut m2, &[], &g.lists);
    assert_eq!(m2.state().checkpoint, Some(c7.id()));
    assert!(!m2.contains(&x.id()));
    sync_all(&mut m2, core::slice::from_ref(&c9), &g.lists);
    for _ in 0..2 {
        let theirs: Vec<Record> = m1.ids().map(|id| m1.get(id).unwrap().clone()).collect();
        sync_all(&mut m2, &theirs, &g.lists);
        sync_all(&mut m2, &[c8.clone(), x.clone()], &g.lists);
        let mine: Vec<Record> = m2.ids().map(|id| m2.get(id).unwrap().clone()).collect();
        sync_all(&mut m1, &mine, &g.lists);
    }
    for m in [&m1, &m2] {
        let st = m.state();
        assert_eq!(st.checkpoint, Some(c8.id()));
        assert!(st.device_by_key(&k("x").hash).is_some());
    }
    assert_eq!(m1.digest(), m2.digest());
    assert_eq!(m1.state(), m2.state());
}

/// A record the counting checkpoint pruned that a newer one keeps waits
/// aside while that one is not whole: it counts for nothing, takes no
/// place in the digest, stays when the set compacts, and goes in the step
/// a checkpoint that counts prunes the one that kept it.
#[test]
fn what_waits_aside_counts_for_nothing_and_goes_with_its_checkpoint() {
    let mut g = G::new();
    let laptop = g.device(&k("root"), &k("laptop"), "laptop", |_| {});
    let x = g.device(&k("root"), &k("x"), "x", |_| {});
    g.root_rec(Kind::Copies { incoming_ms: 5_000, seen: vec![] });
    let c7 = root_cp(&mut g, vec![laptop.id()]);
    let w = root_cp(&mut g, vec![laptop.id(), x.id(), c7.id(), RecordId([0x5a; 32])]);
    let others: Vec<Record> = g.recs.iter().filter(|r| r.id() != x.id()).cloned().collect();
    let mut m = set_with(&g.root.key, &others, &g.lists);
    sync_all(&mut m, &[], &g.lists);
    assert_eq!(m.state().checkpoint, Some(c7.id()));
    let without = m.digest();
    assert_eq!(m.insert(x.clone()), Ok(Added::Waiting));
    sync_all(&mut m, &[], &g.lists);
    assert!(m.waits_aside(&x.id()) && m.get(&x.id()).is_some());
    assert!(m.ids().all(|id| *id != x.id()));
    assert_eq!(m.digest(), without);
    assert!(m.state().device_by_key(&k("x").hash).is_none());
    let n = root_cp(&mut g, vec![laptop.id(), c7.id(), w.id()]);
    assert_eq!(m.insert(n.clone()), Ok(Added::Stored));
    sync_all(&mut m, &[], &g.lists);
    assert_eq!(m.state().checkpoint, Some(n.id()));
    assert!(!m.contains(&x.id()), "nothing above the counting one keeps it");
    assert_eq!(m.insert(x.clone()), Ok(Added::Settled { head: w.body().seq }));
}

/// A record taken for a waiting checkpoint is judged first as any settled
/// root record: with the other record of its seq it makes the pair in
/// either order, after which nothing at or above the fork waits; and one
/// that left the place aside is remembered, so the other one waits for it.
#[test]
fn what_waits_aside_still_makes_the_pair() {
    let mut g = G::new();
    let laptop = g.device(&k("root"), &k("laptop"), "laptop", |_| {});
    let x = g.device(&k("root"), &k("x"), "x", |_| {});
    let x2 = root_twin(&g, &x, Kind::device(Device::new(k("y").key.clone(), "y", ROLE_MEMBER)));
    g.root_rec(Kind::Copies { incoming_ms: 5_000, seen: vec![] });
    let c7 = root_cp(&mut g, vec![laptop.id()]);
    let w = root_cp(&mut g, vec![laptop.id(), x.id(), c7.id(), RecordId([0x5a; 32])]);
    let base = || {
        let mut m = set_with(&g.root.key, &g.recs, &g.lists);
        sync_all(&mut m, &[], &g.lists);
        assert_eq!(m.state().checkpoint, Some(c7.id()));
        m
    };
    let mut states = Vec::new();
    for order in [[&x, &x2], [&x2, &x]] {
        let mut m = base();
        for r in order {
            m.insert((*r).clone()).unwrap();
        }
        let st = m.state();
        let root = k("root").hash;
        assert!(st.conflicts.iter().any(|c| c.kind == ConflictKind::TwoHistories && c.signers == vec![root]));
        assert!(!m.waits_aside(&x.id()) && !m.waits_aside(&x2.id()));
        states.push((m.digest(), st));
    }
    assert_eq!(states[0], states[1]);
    // x waits, then a counting checkpoint takes its place: x is
    // remembered, and its twin waits for it.
    let mut m = base();
    m.insert(x.clone()).unwrap();
    let n = root_cp(&mut g, vec![laptop.id(), c7.id(), w.id()]);
    m.insert(n).unwrap();
    assert!(!m.contains(&x.id()));
    let _ = m.insert(x2.clone());
    assert!(m.missing(&m.state()).contains(&x.id()));
    m.insert(x.clone()).unwrap();
    let root = k("root").hash;
    assert!(m.state().conflicts.iter().any(|c| c.kind == ConflictKind::TwoHistories && c.signers == vec![root]));
}

/// The place aside holds at most one ROOM: what the newest waiting
/// checkpoint names first, then the next newest, each by the lowest
/// (seq, ID), whatever order the records came in.
#[test]
fn the_place_aside_keeps_one_room_by_seq() {
    let mut g = G::new();
    let laptop = g.device(&k("root"), &k("laptop"), "laptop", |_| {});
    let c7 = root_cp(&mut g, vec![laptop.id()]);
    let old: Vec<Record> = (0..20).map(|i| g.root_rec(Kind::Copies { incoming_ms: 5_000 + i, seen: vec![] })).collect();
    // Five checkpoints that never become whole (each keeps a record never
    // released), each naming itself, its prev and five records: seven
    // units, within the root's ceiling of eight.
    let mut waiting = Vec::new();
    for w in 0..5u8 {
        let mut keep: Vec<RecordId> = old[usize::from(w) * 4..usize::from(w) * 4 + 4].iter().map(Record::id).collect();
        keep.extend([laptop.id(), RecordId([0x50 + w; 32])]);
        waiting.push(root_cp(&mut g, keep));
    }
    let small = crate::records::keep::small::Small::new(14, 8, 5);
    for r in &g.recs {
        small.units(r.id(), 1);
    }
    let base: Vec<Record> = g.recs.iter().filter(|r| !old.iter().any(|o| o.id() == r.id())).cloned().collect();
    // The rooms keep c7, the laptop and the five checkpoints (seven of the
    // root's eight units) and the lowest old record; aside, by the newest
    // checkpoint first: what the fifth, fourth and third keep (old 16..19,
    // 12..15, 8..11), then the second's lowest two (old 4 and 5).
    let mut want: Vec<RecordId> =
        [16, 17, 18, 19, 12, 13, 14, 15, 8, 9, 10, 11, 4, 5].iter().map(|i: &usize| old[*i].id()).collect();
    want.sort();
    let mut seen = Vec::new();
    for seed in [0, 1, 2] {
        let mut m = set_with(&g.root.key, &base, &g.lists);
        sync_all(&mut m, &[], &g.lists);
        assert_eq!(m.state().checkpoint, Some(c7.id()));
        assert!(waiting.iter().all(|w| m.contains(&w.id()) && !m.waits_aside(&w.id())));
        let order = if seed == 0 { old.clone() } else { shuffled(&old, seed) };
        sync_all(&mut m, &order, &g.lists);
        let mut aside: Vec<RecordId> = old.iter().map(Record::id).filter(|id| m.waits_aside(id)).collect();
        aside.sort();
        assert_eq!(aside.len(), 14, "order {seed}");
        assert_eq!(aside, want, "order {seed}");
        assert!(m.contains(&old[0].id()) && !m.waits_aside(&old[0].id()), "order {seed}: old 0 in the rooms");
        seen.push((m.digest(), m.state()));
    }
    assert!(seen.windows(2).all(|w| w[0] == w[1]));
}

/// What waits aside for the current root goes when a change of root
/// applies: a root the path left has nothing aside.
#[test]
fn a_change_of_root_empties_the_place_aside() {
    let mut g = G::new();
    let laptop = g.device(&k("root"), &k("laptop"), "laptop", |_| {});
    let x = g.device(&k("root"), &k("x"), "x", |_| {});
    g.root_rec(Kind::Copies { incoming_ms: 5_000, seen: vec![] });
    let c7 = root_cp(&mut g, vec![laptop.id()]);
    root_cp(&mut g, vec![laptop.id(), x.id(), c7.id(), RecordId([0x5c; 32])]);
    let mut m = set_with(&g.root.key, &g.recs, &g.lists);
    sync_all(&mut m, &[], &g.lists);
    m.insert(x.clone()).unwrap();
    assert!(m.waits_aside(&x.id()));
    let list = g.listing();
    let before = g.recs.len();
    g.change(&k("root2"), &list);
    let rest: Vec<Record> = g.recs[before..].to_vec();
    sync_all(&mut m, &rest, &g.lists);
    assert_eq!(m.state().roots.last(), Some(&k("root2").hash));
    assert!(!m.waits_aside(&x.id()));
}

/// The root's checkpoint, written by the set that holds recs.
fn root_checkpoint(g: &mut G, recs: &[Record]) -> Record {
    let set = set_with(&g.root.key, recs, &g.lists);
    let cp = set.write_checkpoint(&set.state(), &k("root"), 0).unwrap();
    g.push(cp)
}

/// A root's removal of a device whose admission the root holds goes with
/// that admission at its next checkpoint: the room is freed, the old
/// records are refused as settled, and a new record admits the device
/// again.
#[test]
fn a_checkpoint_prunes_a_settled_removal() {
    let mut g = G::new();
    let root = k("root");
    g.device(&root, &k("laptop"), "laptop", |_| {});
    let d = g.device(&root, &k("d"), "d", |_| {});
    let rv = g.root_rec(Kind::Revoke(removal(&[k("d").hash], g.seen())));
    g.device(&root, &k("tv"), "tv", |_| {});
    let recs = g.recs.clone();
    let cp = root_checkpoint(&mut g, &recs);
    let mut set = set_with(&g.root.key, &g.recs, &g.lists);
    let s = set.state();
    assert!(s.checkpoints.contains(&cp.id()));
    assert!(!set.contains(&rv.id()) && !set.contains(&d.id()));
    assert!(!s.revoked.contains(&k("d").hash) && s.device_by_key(&k("d").hash).is_none());
    assert!(s.device_by_key(&k("laptop").hash).is_some());
    // Refused as settled, with the head the root's next record goes above.
    let Kind::Checkpoint { heads, .. } = &cp.body().kind else { panic!() };
    let head = heads.iter().find(|h| h.key == root.hash).unwrap().seq;
    assert_eq!(set.insert(d.clone()), Ok(Added::Settled { head }));
    assert_eq!(set.insert(rv), Ok(Added::Settled { head }));
    let again = g.device(&root, &k("d"), "d", |_| {});
    assert_eq!(set.insert(again.clone()), Ok(Added::Stored));
    assert!(set.state().counting.contains(&again.id()));
}

/// A removal written with nothing seen of the admission is kept: an
/// admin's admission that comes after the checkpoint still does not
/// count.
#[test]
fn a_checkpoint_keeps_a_removal_without_its_admission() {
    let mut g = G::new();
    let (pa, a) = (k("phone a"), k("admin a"));
    g.admin(&pa, &a, POWER_ADMIT | POWER_REMOVE);
    g.device(&a, &k("x"), "x", |_| {});
    let late = g.device(&a, &k("d"), "d", |_| {});
    let rv = Record::sign(g.body(&k("root"), Kind::Revoke(removal(&[k("d").hash], Vec::new()))), &k("root")).unwrap();
    g.push(rv.clone());
    g.device(&k("root"), &k("tv"), "tv", |_| {});
    let mine: Vec<Record> = g.recs.iter().filter(|r| r.id() != late.id()).cloned().collect();
    let cp = root_checkpoint(&mut g, &mine);
    let Kind::Checkpoint { keep, .. } = &cp.body().kind else { panic!() };
    assert!(keep.contains(&rv.id()));
    let s = g.state();
    assert!(s.checkpoints.contains(&cp.id()));
    assert!(s.revoked.contains(&k("d").hash) && s.device_by_key(&k("d").hash).is_none());
    let mut set = set_with(&g.root.key, &mine, &g.lists);
    set.insert(cp).unwrap();
    assert_eq!(set.insert(late), Ok(Added::Stored));
    let st = set.state();
    assert!(st.revoked.contains(&k("d").hash) && st.device_by_key(&k("d").hash).is_none());
}

/// The removal of an admin whose admissions still count is kept: what it
/// admitted before stays, and so does the removal.
#[test]
fn a_checkpoint_keeps_a_removal_while_what_the_key_signed_counts() {
    let mut g = G::new();
    let (pa, a) = (k("phone a"), k("admin a"));
    g.admin(&pa, &a, POWER_ADMIT | POWER_REMOVE);
    let tv = g.device(&a, &k("tv"), "tv", |_| {});
    let rv = g.root_rec(Kind::Revoke(removal(&[a.hash], g.seen())));
    g.device(&k("root"), &k("laptop"), "laptop", |_| {});
    let recs = g.recs.clone();
    let cp = root_checkpoint(&mut g, &recs);
    let Kind::Checkpoint { heads, keep } = &cp.body().kind else { panic!() };
    assert!(keep.contains(&rv.id()) && heads.iter().any(|h| h.id == tv.id()));
    let s = set_with(&g.root.key, &g.recs, &g.lists).state();
    assert_eq!(s, g.state());
    assert!(s.revoked.contains(&a.hash) && s.device_by_key(&k("tv").hash).is_some());
}

/// The root's checkpoint that comes after the set dropped some of the
/// root's removals past its ceiling (16 full admins beside it) is still
/// taken: it counts on the set it prunes, as in evaluate, and frees
/// the room it was turned away from.
#[test]
fn a_checkpoint_after_the_roots_drops_is_taken() {
    let mut g = G::new();
    let root = k("root");
    let admins: Vec<(K, K)> = (0..16).map(|i| (k(&format!("phone {i}")), k(&format!("admin {i}")))).collect();
    for (p, a) in &admins {
        g.admin(p, a, POWER_ADMIT);
    }
    for (_, a) in &admins {
        for i in 0..MAX_ADMIN_RECORDS as u64 {
            g.rec(a, Kind::Copies { incoming_ms: 5_000 + i, seen: vec![] });
        }
    }
    // Past the root's own ceiling: the admins cannot push it lower.
    for n in 0..100u8 {
        let keys: Vec<KeyHash> = (0..256u16)
            .map(|i| {
                let mut h = [n; 32];
                h[..2].copy_from_slice(&i.to_be_bytes());
                KeyHash(h)
            })
            .collect();
        g.root_rec(Kind::Revoke(removal(&keys, Vec::new())));
    }
    let mut set = set_of(&g.root.key);
    set.insert_all(g.recs.clone());
    let roots_held = g.recs.iter().filter(|r| r.body().signer == root.hash && set.contains(&r.id())).count();
    assert!(roots_held < 16 + 100, "the root dropped some of its removals");
    let mut heads: Vec<Head> = admins
        .iter()
        .map(|(_, a)| {
            let (seq, id) = g.heads[&a.hash];
            Head { key: a.hash, seq, id }
        })
        .collect();
    let (seq, id) = g.heads[&root.hash];
    heads.push(Head { key: root.hash, seq, id });
    heads.sort_by_key(|h| h.key);
    let cp = g.root_rec(Kind::Checkpoint { heads, keep: Vec::new() });
    set.insert(cp.clone()).unwrap();
    // The peers offer again what it names.
    set.insert_all(g.recs.clone());
    let want = g.state();
    assert_eq!(want.checkpoint, Some(cp.id()));
    assert_eq!(set.state(), want);
}

/// The removal of an admin key is kept for good, even when nothing it
/// signed counts: a key that may sign could bring back what it signed
/// while removed.
#[test]
fn a_checkpoint_keeps_an_admins_removal() {
    let mut g = G::new();
    let (pa, a) = (k("phone a"), k("admin a"));
    g.admin(&pa, &a, POWER_ADMIT | POWER_REMOVE);
    let rv = g.root_rec(Kind::Revoke(removal(&[a.hash], g.seen())));
    g.device(&k("root"), &k("laptop"), "laptop", |_| {});
    let recs = g.recs.clone();
    let cp = root_checkpoint(&mut g, &recs);
    let Kind::Checkpoint { keep, .. } = &cp.body().kind else { panic!() };
    assert!(keep.contains(&rv.id()));
    let s = set_with(&g.root.key, &g.recs, &g.lists).state();
    assert!(s.revoked.contains(&a.hash) && s.revoked.contains(&pa.hash));
}

/// Two records of the root at one seq are a fork at any depth: a member
/// that counted a checkpoint above them, and pruned one, halts when it is
/// handed both, as one that held the pair before the checkpoint does; the
/// checkpoint counts on neither.
#[test]
fn the_roots_pair_halts_below_a_checkpoint() {
    let mut g = G::new();
    let root = k("root");
    g.device(&root, &k("laptop"), "laptop", |_| {});
    let below = g.device(&root, &k("d"), "d", |_| {});
    let x = g.root_rec(Kind::Revoke(removal(&[k("d").hash], g.seen())));
    let mut d = Device::new(k("thief").key.clone(), "thief", ROLE_MEMBER);
    d.rights = RIGHT_READ;
    let twin =
        Record::sign(Body { seq: x.body().seq, prev: Some(below.id()), ..g.body(&root, Kind::device(d)) }, &root)
            .unwrap();
    g.device(&root, &k("phone"), "phone", |_| {});
    let line: Vec<Record> = g.recs.clone();
    let cp = root_checkpoint(&mut g, &line);
    assert!(!matches!(&cp.body().kind, Kind::Checkpoint { keep, .. } if keep.contains(&x.id())));
    // B counted the checkpoint first and holds no x any more: the twin
    // alone is settled.
    let without: Vec<Record> = g.recs.iter().filter(|r| r.id() != x.id()).cloned().collect();
    let mut b = set_with(&g.root.key, &without, &g.lists);
    assert!(b.state().checkpoints.contains(&cp.id()) && !b.contains(&x.id()));
    assert!(matches!(b.insert(twin.clone()), Ok(Added::Settled { .. })));
    assert_eq!(b.state().stop, Stop::None);
    // Handed the pair, it halts.
    b.insert(x.clone()).unwrap();
    let sb = b.state();
    assert_eq!(sb.stop, Stop::Full);
    assert!(!sb.checkpoints.contains(&cp.id()) && b.contains(&twin.id()) && b.contains(&x.id()));
    // A held the pair before the checkpoint came.
    let mut a = set_with(&g.root.key, &line, &g.lists);
    a.insert(twin.clone()).unwrap();
    assert_eq!(a.state().stop, Stop::Full);
    a.insert(cp.clone()).unwrap();
    let sa = a.state();
    assert_eq!(sa.stop, Stop::Full);
    assert!(sa.checkpoint.is_none());
    let mut all = g.recs.clone();
    all.push(twin);
    let want = state_of(&g.root.key, &all);
    assert_eq!(want.stop, Stop::Full);
    assert!(want.checkpoint.is_none());
}

/// Many settled root records offered while one waits for its pair push
/// it out of memory, not out of mind: the set remembers its ID, keeps the
/// other when it comes, asks for the first and halts when it comes again.
#[test]
fn older_settled_records_leave_a_waiting_one() {
    let mut g = G::new();
    let root = k("root");
    g.device(&root, &k("laptop"), "laptop", |_| {});
    let mut old = vec![];
    for i in 0..9 {
        let name = format!("old {i}");
        old.push(g.device(&root, &k(&name), &name, |_| {}));
        old.push(g.root_rec(Kind::Revoke(removal(&[k(&name).hash], g.seen()))));
    }
    let below = g.device(&root, &k("d"), "d", |_| {});
    let x = g.root_rec(Kind::Revoke(removal(&[k("d").hash], g.seen())));
    let mut d = Device::new(k("thief").key.clone(), "thief", ROLE_MEMBER);
    d.rights = RIGHT_READ;
    let twin =
        Record::sign(Body { seq: x.body().seq, prev: Some(below.id()), ..g.body(&root, Kind::device(d)) }, &root)
            .unwrap();
    g.device(&root, &k("phone"), "phone", |_| {});
    let line: Vec<Record> = g.recs.clone();
    let cp = root_checkpoint(&mut g, &line);
    // B counted the checkpoint first and holds none of them any more.
    let gone: Vec<RecordId> = old.iter().chain([&x]).map(Record::id).collect();
    let without: Vec<Record> = g.recs.iter().filter(|r| !gone.contains(&r.id())).cloned().collect();
    let mut b = set_with(&g.root.key, &without, &g.lists);
    assert!(b.state().checkpoints.contains(&cp.id()) && !b.contains(&x.id()));
    assert!(old.iter().all(|r| !b.contains(&r.id())));
    assert!(matches!(b.insert(twin.clone()), Ok(Added::Settled { .. })));
    for r in &old {
        assert!(matches!(b.insert(r.clone()), Ok(Added::Settled { .. })));
    }
    b.insert(x.clone()).unwrap();
    let st = b.state();
    assert_eq!(st.stop, Stop::None);
    assert!(b.missing(&st).contains(&twin.id()));
    b.insert(twin.clone()).unwrap();
    assert_eq!(b.state().stop, Stop::Full);
    assert!(b.contains(&twin.id()) && b.contains(&x.id()));
}

/// Root records waiting for a partner the set remembers by ID are kept
/// within their bound, the oldest going first: the newest still wait, the
/// set asks for their partners, and one that comes halts it.
#[test]
fn records_waiting_for_their_pair_keep_within_their_bound() {
    let mut g = G::new();
    let root = k("root");
    g.device(&root, &k("laptop"), "laptop", |_| {});
    let (mut xs, mut twins, mut gone) = (vec![], vec![], vec![]);
    for i in 0..18 {
        let name = format!("d {i}");
        let below = g.device(&root, &k(&name), &name, |_| {});
        let x = g.root_rec(Kind::Revoke(removal(&[k(&name).hash], g.seen())));
        let mut d = Device::new(k(&format!("other {i}")).key.clone(), "other", ROLE_MEMBER);
        d.rights = RIGHT_READ;
        let twin =
            Record::sign(Body { seq: x.body().seq, prev: Some(below.id()), ..g.body(&root, Kind::device(d)) }, &root)
                .unwrap();
        gone.extend([below.id(), x.id()]);
        xs.push(x);
        twins.push(twin);
    }
    let mut old = vec![];
    for i in 0..9 {
        let name = format!("old {i}");
        old.push(g.device(&root, &k(&name), &name, |_| {}));
        old.push(g.root_rec(Kind::Revoke(removal(&[k(&name).hash], g.seen()))));
    }
    gone.extend(old.iter().map(Record::id));
    g.device(&root, &k("phone"), "phone", |_| {});
    let line: Vec<Record> = g.recs.clone();
    let cp = root_checkpoint(&mut g, &line);
    let without: Vec<Record> = g.recs.iter().filter(|r| !gone.contains(&r.id())).cloned().collect();
    let mut b = set_with(&g.root.key, &without, &g.lists);
    assert!(b.state().checkpoints.contains(&cp.id()));
    for r in twins.iter().chain(&old) {
        assert!(matches!(b.insert(r.clone()), Ok(Added::Settled { .. })));
    }
    for x in &xs {
        assert!(matches!(b.insert(x.clone()), Ok(Added::Settled { .. })));
    }
    let st = b.state();
    assert_eq!(st.stop, Stop::None);
    let asked = b.missing(&st);
    assert!(twins[..2].iter().all(|t| !asked.contains(&t.id())));
    assert!(twins[2..].iter().all(|t| asked.contains(&t.id())));
    b.insert(twins[17].clone()).unwrap();
    assert_eq!(b.state().stop, Stop::Full);
}

/// A second admission of a key the root removed, which the root never
/// saw, brings the device back after the prune; the member that dropped
/// the removal tells it, and a new admission by the root is not told.
#[test]
fn an_unseen_admission_after_a_prune_is_a_notice() {
    let mut g = G::new();
    let root = k("root");
    let (pa, a) = (k("phone a"), k("admin a"));
    g.admin(&pa, &a, POWER_ADMIT);
    g.rec(&a, Kind::Copies { incoming_ms: MIN_INCOMING_MS, seen: vec![] });
    g.device(&root, &k("d"), "d", |_| {});
    let unseen = g.device(&a, &k("d"), "d", |_| {});
    g.root_rec(Kind::Revoke(removal(&[k("d").hash], Vec::new())));
    g.device(&root, &k("tv"), "tv", |_| {});
    let rootside: Vec<Record> = g.recs.iter().filter(|r| r.id() != unseen.id()).cloned().collect();
    let cp = root_checkpoint(&mut g, &rootside);
    let mut m = set_with(&g.root.key, &rootside, &g.lists);
    m.insert(cp.clone()).unwrap();
    let s = m.state();
    assert!(s.checkpoints.contains(&cp.id()) && !has_key(&s, &k("d")) && m.notices(&s).is_empty());
    m.insert(unseen.clone()).unwrap();
    let s = m.state();
    assert!(has_key(&s, &k("d")));
    assert_eq!(m.notices(&s), vec![(unseen.id(), vec![k("d").hash])]);
    m.dismiss(&unseen.id());
    assert!(m.notices(&m.state()).is_empty());
    // On a member that never gets the unseen admission, the root's new
    // admission is not told.
    let mut n = set_with(&g.root.key, &rootside, &g.lists);
    n.insert(cp).unwrap();
    let again = g.device(&root, &k("d"), "d", |_| {});
    n.insert(again).unwrap();
    let s = n.state();
    assert!(has_key(&s, &k("d")) && n.notices(&s).is_empty());
}

/// An old admission a newer checkpoint of the root keeps again, while it
/// prunes the removal: the key counts again, and a member that dropped the
/// removal tells it. While a removal naming the key is kept, the key stays
/// out whatever the keep says.
#[test]
fn an_admission_kept_again_counts_only_past_every_removal() {
    for keep_removal in [false, true] {
        let mut g = G::new();
        let root = k("root");
        let laptop = g.device(&root, &k("laptop"), "laptop", |_| {});
        let x = g.device(&root, &k("d"), "d", |_| {});
        let rm = g.root_rec(Kind::Revoke(removal(&[k("d").hash], Vec::new())));
        g.device(&root, &k("tv"), "tv", |_| {});
        let line = g.recs.clone();
        let older = root_checkpoint(&mut g, &line);
        let Kind::Checkpoint { keep, .. } = &older.body().kind else { unreachable!() };
        assert!(!keep.contains(&x.id()) && !keep.contains(&rm.id()), "the writer prunes both");
        let phone = g.device(&root, &k("phone"), "phone", |_| {});
        let (seq, id) = g.heads[&root.hash];
        let mut keep: Vec<RecordId> = keep.iter().copied().chain([x.id(), older.id()]).collect();
        if keep_removal {
            keep.push(rm.id());
        }
        keep.sort();
        let newer = g.root_rec(Kind::Checkpoint { heads: vec![Head { key: root.hash, seq, id }], keep });
        let mut m = set_with(&g.root.key, &line, &g.lists);
        m.insert(older.clone()).unwrap();
        let st = m.state();
        m.compact(&st);
        assert!(!m.contains(&x.id()) && !has_key(&m.state(), &k("d")));
        sync_all(&mut m, &[phone.clone(), newer.clone()], &g.lists);
        sync_all(&mut m, &g.recs, &g.lists);
        let s = m.state();
        assert_eq!(s.checkpoint, Some(newer.id()), "removal kept {keep_removal}");
        assert_eq!(has_key(&s, &k("d")), !keep_removal, "removal kept {keep_removal}");
        let told = m.notices(&s);
        assert_eq!(told.is_empty(), keep_removal, "{told:?}");
        let at_once = set_with(&g.root.key, &g.recs, &g.lists);
        assert_eq!(m.digest(), at_once.digest());
        assert_eq!(s, at_once.state());
        let _ = laptop;
    }
}

/// The writer's check: a checkpoint that keeps an admission while it
/// prunes the root's removal of that key is one the writer refuses; the
/// one the writer writes passes it.
#[test]
fn keeping_an_admission_while_pruning_its_removal_is_refused() {
    let mut g = G::new();
    let root = k("root");
    g.device(&root, &k("laptop"), "laptop", |_| {});
    let x = g.device(&root, &k("d"), "d", |_| {});
    let rm = g.root_rec(Kind::Revoke(removal(&[k("d").hash], Vec::new())));
    g.device(&root, &k("tv"), "tv", |_| {});
    let set = set_with(&g.root.key, &g.recs, &g.lists);
    let recs: Vec<(&Record, crate::records::eval::Role)> =
        set.ids().map(|id| (set.get(id).unwrap(), crate::records::eval::Role::Root)).collect();
    let held = || recs.iter().copied();
    let cp = set.write_checkpoint(&set.state(), &root, 0).unwrap();
    let Kind::Checkpoint { heads, keep } = &cp.body().kind else { unreachable!() };
    assert!(!crate::records::eval::revives(heads, keep, held()));
    let mut with_x = keep.clone();
    with_x.push(x.id());
    with_x.sort();
    assert!(crate::records::eval::revives(heads, &with_x, held()));
    let mut both = with_x.clone();
    both.push(rm.id());
    both.sort();
    assert!(!crate::records::eval::revives(heads, &both, held()), "the removal kept too");
}

fn has_key(s: &State, member: &K) -> bool {
    s.device_by_key(&member.hash).is_some()
}

/// A root's checkpoint that waits for a record it keeps asks the peers
/// for it, and counts once it comes.
#[test]
fn a_waiting_checkpoint_asks_for_what_it_keeps() {
    let mut g = G::new();
    let root = k("root");
    let laptop = g.device(&root, &k("laptop"), "laptop", |_| {});
    g.device(&root, &k("tv"), "tv", |_| {});
    let recs = g.recs.clone();
    let cp = root_checkpoint(&mut g, &recs);
    let mut set = set_with(&g.root.key, &[g.recs[1].clone()], &g.lists);
    let _ = set.insert(cp.clone());
    let st = set.state();
    assert!(st.checkpoint.is_none());
    assert!(set.missing(&st).contains(&laptop.id()));
    set.insert(laptop).unwrap();
    assert_eq!(set.state().checkpoint, Some(cp.id()));
}

/// A head's first that names a record which is no checkpoint of its new
/// root keeps nothing outside the rooms: a checkpoint that leaves the
/// record out prunes it, whatever order the records came in.
#[test]
fn a_first_that_is_no_checkpoint_keeps_nothing() {
    let mut g = G::new();
    let root = k("root");
    let d = g.device(&root, &k("dev 1"), "dev", |_| {});
    let list = List(vec![d.id()]);
    g.lists.push(list.encode());
    let head = g.rec(
        &k("recovery"),
        Kind::Recovery {
            root: k("new root a").key.clone(),
            list: list.hash(),
            from: 0,
            first: d.id(),
            signer2: crate::testkit::rk2().key().hash(),
        },
    );
    let (s1, i1) = g.heads[&root.hash];
    let c2 = g.root_rec(Kind::Checkpoint { heads: vec![Head { key: root.hash, seq: s1, id: i1 }], keep: vec![] });
    let (s2, i2) = g.heads[&root.hash];
    let c3 = g.root_rec(Kind::Checkpoint { heads: vec![Head { key: root.hash, seq: s2, id: i2 }], keep: vec![] });
    let orders: [[&Record; 4]; 3] = [[&d, &head, &c2, &c3], [&head, &c3, &d, &c2], [&c3, &c2, &d, &head]];
    let mut digests = alloc::collections::BTreeSet::new();
    for o in orders {
        let recs: Vec<Record> = o.iter().map(|r| (*r).clone()).collect();
        let s = set_with(&root.key, &recs, &g.lists);
        assert!(!s.contains(&d.id()) && s.contains(&c3.id()));
        let saved: Vec<Record> = s.ids().map(|id| s.get(id).unwrap().clone()).collect();
        let back = RecordSet::restore(root.key.clone(), rk(), &saved, &g.lists);
        assert_eq!(back.digest(), s.digest());
        digests.insert(s.digest());
    }
    assert_eq!(digests.len(), 1);
}

/// The root's two records at one seq leave its room: what the room
/// turned away before the second came is taken when offered again, as by
/// a member that got all at once.
#[test]
fn a_pair_out_of_the_room_lets_back_what_it_turned_away() {
    let mut g = G::new();
    let root = k("root");
    let mut own = vec![];
    for i in 0..9 {
        own.push(g.root_rec(Kind::Copies { incoming_ms: MIN_INCOMING_MS + i, seen: vec![] }));
    }
    let twin = Record::sign(
        Body { kind: Kind::Copies { incoming_ms: MIN_INCOMING_MS + 99, seen: vec![] }, ..own[2].body().clone() },
        &root,
    )
    .unwrap();
    let small = crate::records::keep::small::Small::new(14, 8, 5);
    for r in g.recs.iter().chain([&twin]) {
        small.units(r.id(), 1);
    }
    let mut member = set_with(&g.root.key, &g.recs, &g.lists);
    assert!(!member.contains(&own[8].id()));
    member.insert(twin.clone()).unwrap();
    let _ = member.insert(own[8].clone());
    let mut all = vec![twin];
    all.extend(g.recs.iter().cloned());
    let fresh = set_with(&g.root.key, &all, &g.lists);
    assert!(fresh.contains(&own[8].id()));
    assert_eq!(member.digest(), fresh.digest());
    assert_eq!(member.state(), fresh.state());
}

/// The root's newest checkpoint, kept first, takes its part of the room
/// and of its key's ceiling: the root keeps no more than its ceiling, the
/// set no more than its room, and an admin its fair share of the rest.
/// What waits aside for it takes no unit.
#[test]
fn a_checkpoint_kept_first_takes_its_part_of_the_room() {
    let mut g = G::new();
    let root = k("root");
    let (pa, a) = (k("phone a"), k("admin a"));
    g.admin(&pa, &a, POWER_ADMIT);
    for i in 0..8 {
        g.root_rec(Kind::Copies { incoming_ms: MIN_INCOMING_MS + i, seen: vec![] });
    }
    for i in 0..8 {
        g.rec(&a, Kind::Copies { incoming_ms: MIN_INCOMING_MS + i, seen: vec![] });
    }
    let (seq, id) = g.heads[&root.hash];
    let mut keep: Vec<RecordId> = g.recs.iter().filter(|r| r.body().signer == root.hash).map(Record::id).collect();
    keep.retain(|k| *k != id);
    keep.sort();
    let cp = g.root_rec(Kind::Checkpoint { heads: vec![Head { key: root.hash, seq, id }], keep });
    let small = crate::records::keep::small::Small::new(14, 8, 5);
    for r in &g.recs {
        small.units(r.id(), if r.id() == cp.id() { 2 } else { 1 });
    }
    let units = |s: &RecordSet, key: &KeyHash| -> u64 {
        g.recs
            .iter()
            .filter(|r| r.body().signer == *key && s.ids().any(|id| *id == r.id()))
            .map(|r| if r.id() == cp.id() { 2 } else { 1 })
            .sum()
    };
    for seed in [0, 1, 2] {
        let order = if seed == 0 { g.recs.clone() } else { shuffled(&g.recs, seed) };
        let s = set_with(&g.root.key, &order, &g.lists);
        assert!(s.contains(&cp.id()));
        let (r, ad) = (units(&s, &root.hash), units(&s, &a.hash));
        assert!(r <= 8, "the root keeps {r} units");
        assert!(r + ad <= 14, "the set keeps {} units", r + ad);
        assert_eq!(ad, 5, "the admin keeps {ad} units");
    }
}

/// A checkpoint that names more of a key's records than the key's
/// ceiling counts for no member, in any order, and the same in evaluate;
/// one that names as many as the ceiling counts.
#[test]
fn a_checkpoint_naming_more_than_a_key_holds_counts_nowhere() {
    for named in [5usize, 6] {
        let mut g = G::new();
        let root = k("root");
        let (pa, a) = (k("phone a"), k("admin a"));
        let grant = g.admin(&pa, &a, POWER_ADMIT);
        let mine: Vec<Record> =
            (0..7).map(|i| g.rec(&a, Kind::Copies { incoming_ms: MIN_INCOMING_MS + i, seen: vec![] })).collect();
        let (seq, id) = g.heads[&a.hash];
        let mut keep: Vec<RecordId> = mine[..named].iter().map(Record::id).chain([grant.id()]).collect();
        keep.sort();
        let cp = g.root_rec(Kind::Checkpoint { heads: vec![Head { key: a.hash, seq, id }], keep });
        let small = crate::records::keep::small::Small::new(14, 8, 5);
        for r in &g.recs {
            small.units(r.id(), 1);
        }
        let want = (named <= 5).then(|| cp.id());
        assert_eq!(state_with(&g.root.key, &g.recs, &g.lists).checkpoint, want, "{named} named");
        for seed in [0, 1, 2, 3] {
            let order = if seed == 0 { g.recs.clone() } else { shuffled(&g.recs, seed) };
            let s = set_with(&g.root.key, &order, &g.lists);
            assert_eq!(s.state().checkpoint, want, "{named} named, order {seed}");
        }
        let _ = root;
    }
}

/// A checkpoint that names an admin key's records but not the root's
/// record that makes the key an admin counts for no member: the key has
/// no ceiling among what it names.
#[test]
fn a_checkpoint_naming_an_admins_records_without_its_grant_counts_nowhere() {
    for with_grant in [true, false] {
        let mut g = G::new();
        let (pa, a) = (k("phone a"), k("admin a"));
        let grant = g.admin(&pa, &a, POWER_ADMIT);
        g.device(&k("root"), &k("laptop"), "laptop", |_| {});
        let mine: Vec<Record> =
            (0..3).map(|i| g.rec(&a, Kind::Copies { incoming_ms: MIN_INCOMING_MS + i, seen: vec![] })).collect();
        let (seq, id) = g.heads[&a.hash];
        let mut keep: Vec<RecordId> = mine[..2].iter().map(Record::id).collect();
        if with_grant {
            keep.push(grant.id());
        }
        keep.sort();
        let cp = g.root_rec(Kind::Checkpoint { heads: vec![Head { key: a.hash, seq, id }], keep });
        let want = with_grant.then(|| cp.id());
        assert_eq!(state_with(&g.root.key, &g.recs, &g.lists).checkpoint, want);
        for seed in [0, 1, 2] {
            let order = if seed == 0 { g.recs.clone() } else { shuffled(&g.recs, seed) };
            assert_eq!(set_with(&g.root.key, &order, &g.lists).state().checkpoint, want, "order {seed}");
        }
    }
}

/// The records a counting checkpoint names are kept ahead of the rooms:
/// the root's removals that come after it, which go first among the rest,
/// take only what is left, and the checkpoint keeps counting, in any order.
#[test]
fn what_a_checkpoint_names_is_kept_ahead_of_later_records() {
    let mut g = G::new();
    let root = k("root");
    g.device(&root, &k("laptop"), "laptop", |_| {});
    let older = g.root_rec(Kind::Copies { incoming_ms: MIN_INCOMING_MS, seen: vec![] });
    let waited = g.root_rec(Kind::Copies { incoming_ms: MIN_INCOMING_MS + 1, seen: vec![] });
    let laptop = g.recs[0].id();
    let mut keep = vec![laptop, older.id()];
    keep.sort();
    let (seq, id) = g.heads[&root.hash];
    let cp = g.root_rec(Kind::Checkpoint { heads: vec![Head { key: root.hash, seq, id }], keep });
    for i in 0..3 {
        g.root_rec(Kind::Revoke(removal(&[k(&format!("gone {i}")).hash], g.seen())));
    }
    let small = crate::records::keep::small::Small::new(14, 6, 5);
    for r in &g.recs {
        small.units(r.id(), 1);
    }
    let named = [laptop, older.id(), waited.id(), cp.id()];
    let want = state_with(&g.root.key, &g.recs, &g.lists);
    assert_eq!(want.checkpoint, Some(cp.id()));
    for seed in [0, 1, 2, 3, 4] {
        let order = if seed == 0 { g.recs.clone() } else { shuffled(&g.recs, seed) };
        let s = set_with(&g.root.key, &order, &g.lists);
        assert!(named.iter().all(|id| s.contains(id)), "order {seed}");
        assert_eq!(s.state().checkpoint, Some(cp.id()), "order {seed}");
        let held = g.recs.iter().filter(|r| s.contains(&r.id())).count();
        assert!(held <= 6, "the root holds {held} units, order {seed}");
    }
}

/// The root's two records at one seq below a checkpoint, at a member that
/// pruned by it, with many other settled records of the root around them:
/// two that come together halt it, in one sync or one after the other, and
/// after a restart the same; two that come apart halt it once it asks for
/// the one it remembers by ID.
#[test]
fn the_roots_pair_halts_whatever_came_between() {
    let mut g = G::new();
    let root = k("root");
    g.device(&root, &k("laptop"), "laptop", |_| {});
    let below = g.device(&root, &k("d"), "d", |_| {});
    let x = g.root_rec(Kind::Revoke(removal(&[k("d").hash], g.seen())));
    let mut d = Device::new(k("thief").key.clone(), "thief", ROLE_MEMBER);
    d.rights = RIGHT_READ;
    let twin =
        Record::sign(Body { seq: x.body().seq, prev: Some(below.id()), ..g.body(&root, Kind::device(d)) }, &root)
            .unwrap();
    let mut late = vec![];
    for i in 0..12 {
        let name = format!("late {i}");
        late.push(g.device(&root, &k(&name), &name, |_| {}));
        late.push(g.root_rec(Kind::Revoke(removal(&[k(&name).hash], g.seen()))));
    }
    g.device(&root, &k("phone"), "phone", |_| {});
    let line: Vec<Record> = g.recs.clone();
    let cp = root_checkpoint(&mut g, &line);
    // A member that counted the checkpoint first and never held x nor
    // the later ones.
    let gone: Vec<RecordId> = late.iter().chain([&x]).map(Record::id).collect();
    let without: Vec<Record> = g.recs.iter().filter(|r| !gone.contains(&r.id())).cloned().collect();
    let pruned = || {
        let m = set_with(&g.root.key, &without, &g.lists);
        assert!(m.state().checkpoints.contains(&cp.id()) && !m.contains(&x.id()));
        assert!(late.iter().all(|r| !m.contains(&r.id())));
        m
    };
    let halted = |m: &RecordSet| m.state().stop == Stop::Full && m.contains(&x.id()) && m.contains(&twin.id());
    // The later ones first, then the two one after the other.
    let mut m = pruned();
    for r in &late {
        assert!(matches!(m.insert(r.clone()), Ok(Added::Settled { .. })));
    }
    let _ = m.insert(x.clone());
    let _ = m.insert(twin.clone());
    assert!(halted(&m));
    // What a holder of the pair sends, in one sync, and again after a
    // restart of a member that took the later ones before.
    let mut holder = set_with(&g.root.key, &line, &g.lists);
    holder.insert(twin.clone()).unwrap();
    let st = holder.state();
    let sends: Vec<Record> = holder.for_peer(&st, &k("laptop").hash).into_iter().cloned().collect();
    let mut shuffled_sends = sends.clone();
    shuffled_sends.reverse();
    for batch in [sends.clone(), shuffled_sends] {
        let mut m = pruned();
        for r in &late {
            let _ = m.insert(r.clone());
        }
        m.insert_all(batch.clone());
        assert!(halted(&m));
        let mut back = pruned();
        back.insert_all(batch);
        assert!(halted(&back));
    }
    // Apart: the twin, many others, then x; the member asks for the twin.
    let mut m = pruned();
    assert!(matches!(m.insert(twin.clone()), Ok(Added::Settled { .. })));
    for r in &late {
        let _ = m.insert(r.clone());
    }
    assert!(matches!(m.insert(x.clone()), Ok(Added::Settled { .. })));
    assert_eq!(m.state().stop, Stop::None);
    let st = m.state();
    assert!(m.missing(&st).contains(&twin.id()));
    let _ = m.insert(twin.clone());
    assert!(halted(&m));
}

/// One sync between two members as the protocol runs it: each offers the
/// IDs it holds, then each asks for what it misses and gets it by ID.
fn sync_pair(a: &mut RecordSet, b: &mut RecordSet, lists: &[Vec<u8>]) {
    for _ in 0..2 {
        let from_b: Vec<Record> = b.ids().map(|id| b.get(id).unwrap().clone()).collect();
        sync_all(a, &from_b, lists);
        let from_a: Vec<Record> = a.ids().map(|id| a.get(id).unwrap().clone()).collect();
        sync_all(b, &from_a, lists);
        let asked: Vec<Record> = a.missing(&a.state()).iter().filter_map(|id| b.get(id).cloned()).collect();
        sync_all(a, &asked, lists);
        let asked: Vec<Record> = b.missing(&b.state()).iter().filter_map(|id| a.get(id).cloned()).collect();
        sync_all(b, &asked, lists);
    }
}

/// The formal model's three scenarios of a root record pruned and named
/// again: records 1 to 6 of the root (4 admits x, 5 removes it), 7 prunes
/// 4 and 5, 8 keeps 4 again, and in the third 5 too. Members that held
/// different parts end alike: x counts by 8 alone, and stays out when 8
/// keeps the removal as well.
#[test]
fn the_models_pruned_and_named_again_scenarios_end_alike() {
    for (case, keeps_removal, given_only_to_m) in [(1, false, false), (2, false, true), (3, true, false)] {
        let mut g = G::new();
        let r1 = g.device(&k("root"), &k("laptop"), "laptop", |_| {});
        let r2 = g.root_rec(Kind::Copies { incoming_ms: 5_000, seen: vec![] });
        let r3 = g.root_rec(Kind::Copies { incoming_ms: 5_001, seen: vec![] });
        let r4 = g.device(&k("root"), &k("x"), "x", |_| {});
        let r5 = g.root_rec(Kind::Revoke(removal(&[k("x").hash], g.seen())));
        let r6 = g.root_rec(Kind::Copies { incoming_ms: 5_002, seen: vec![] });
        let c7 = root_cp(&mut g, vec![r1.id(), r2.id(), r3.id()]);
        let mut keep8 = vec![r1.id(), r2.id(), r3.id(), r4.id(), r6.id()];
        if keeps_removal {
            keep8.push(r5.id());
        }
        let c8 = root_cp(&mut g, keep8);
        let upto7: Vec<Record> = g.recs.iter().take_while(|r| r.id() != c8.id()).cloned().collect();
        let no4: Vec<Record> = upto7.iter().filter(|r| r.id() != r4.id()).cloned().collect();
        let (mut a, mut c, mut m) = if given_only_to_m {
            (set_with(&g.root.key, &no4, &g.lists), set_with(&g.root.key, &no4, &g.lists), {
                set_with(&g.root.key, &no4, &g.lists)
            })
        } else {
            let s = || set_with(&g.root.key, &upto7, &g.lists);
            (s(), s(), s())
        };
        let mut kk = set_with(&g.root.key, &upto7[..upto7.len() - 1], &g.lists);
        for s in [&mut a, &mut c, &mut m] {
            sync_all(s, &[], &g.lists);
            assert_eq!(s.state().checkpoint, Some(c7.id()), "case {case}");
        }
        sync_all(&mut a, core::slice::from_ref(&c8), &g.lists);
        if given_only_to_m {
            sync_all(&mut m, &[c8.clone(), r4.clone()], &g.lists);
        }
        for _ in 0..2 {
            sync_pair(&mut a, &mut c, &g.lists);
            sync_pair(&mut c, &mut m, &g.lists);
            sync_pair(&mut m, &mut kk, &g.lists);
            sync_pair(&mut kk, &mut a, &g.lists);
            sync_pair(&mut a, &mut m, &g.lists);
            sync_pair(&mut c, &mut kk, &g.lists);
        }
        let once = set_with(&g.root.key, &g.recs, &g.lists);
        for (name, s) in [("a", &a), ("c", &c), ("m", &m), ("k", &kk)] {
            let st = s.state();
            assert_eq!(st.checkpoint, Some(c8.id()), "case {case} member {name}");
            assert_eq!(st.device_by_key(&k("x").hash).is_some(), !keeps_removal, "case {case} member {name}");
            assert_eq!(s.digest(), once.digest(), "case {case} member {name}");
            assert_eq!(st, once.state(), "case {case} member {name}");
        }
    }
}

/// The writer never names a head below the one its counting checkpoint
/// names for that key, also when it does not hold that head's record:
/// what was settled stays settled.
#[test]
fn a_new_checkpoint_names_no_lower_head() {
    let mut g = G::new();
    let (pa, a) = (k("phone a"), k("admin a"));
    let grant = g.admin(&pa, &a, POWER_ADMIT);
    let a1 = g.rec(&a, Kind::Copies { incoming_ms: MIN_INCOMING_MS, seen: vec![] });
    let a2 = g.rec(&a, Kind::Copies { incoming_ms: MIN_INCOMING_MS + 1, seen: vec![] });
    let a3 = g.rec(&a, Kind::Copies { incoming_ms: MIN_INCOMING_MS + 2, seen: vec![] });
    let root = k("root");
    let (seq, id) = g.heads[&root.hash];
    let mut keep = vec![grant.id(), a1.id()];
    keep.sort();
    let mut heads = vec![Head { key: root.hash, seq, id }, Head { key: a.hash, seq: a3.body().seq, id: a3.id() }];
    heads.sort_by_key(|h| h.key);
    let c7 = g.root_rec(Kind::Checkpoint { heads, keep });
    // The writer holds the checkpoint and what it keeps, not the head's
    // record, nor what is between.
    let held: Vec<Record> = g.recs.iter().filter(|r| ![a2.id(), a3.id()].contains(&r.id())).cloned().collect();
    let set = set_with(&g.root.key, &held, &g.lists);
    let st = set.state();
    assert_eq!(st.checkpoint, Some(c7.id()));
    let cp = set.write_checkpoint(&st, &root, 0).unwrap();
    let Kind::Checkpoint { heads, .. } = &cp.body().kind else { unreachable!() };
    let h = heads.iter().find(|h| h.key == a.hash).expect("a head for the admin");
    assert!(h.seq >= a3.body().seq);
}

/// A checkpoint the core's writer never writes, which names a lower head
/// for a key than the counting one: a member follows it as any member
/// handed the same records does, and a record between the two heads that
/// a peer still holds is taken and counts when its chain reaches the
/// lower head.
#[test]
fn a_checkpoint_with_a_lower_head_is_followed_as_written() {
    let mut g = G::new();
    let (pa, a) = (k("phone a"), k("admin a"));
    let grant = g.admin(&pa, &a, POWER_ADMIT);
    let a1 = g.rec(&a, Kind::Copies { incoming_ms: MIN_INCOMING_MS, seen: vec![] });
    let a2 = g.rec(&a, Kind::Copies { incoming_ms: MIN_INCOMING_MS + 1, seen: vec![] });
    let a3 = g.rec(&a, Kind::Copies { incoming_ms: MIN_INCOMING_MS + 2, seen: vec![] });
    let root = k("root");
    let with_heads = |g: &mut G, admin: Head, keep: Vec<RecordId>| {
        let (seq, id) = g.heads[&root.hash];
        let mut heads = vec![Head { key: root.hash, seq, id }, admin];
        heads.sort_by_key(|h| h.key);
        let mut keep = keep;
        keep.sort();
        g.root_rec(Kind::Checkpoint { heads, keep })
    };
    let c7 = with_heads(&mut g, Head { key: a.hash, seq: a3.body().seq, id: a3.id() }, vec![grant.id()]);
    let c8 = with_heads(&mut g, Head { key: a.hash, seq: a1.body().seq, id: a1.id() }, vec![grant.id(), c7.id()]);
    let upto7: Vec<Record> = g.recs.iter().filter(|r| r.id() != c8.id()).cloned().collect();
    let mut m = set_with(&g.root.key, &upto7, &g.lists);
    sync_all(&mut m, &[], &g.lists);
    assert_eq!(m.state().checkpoint, Some(c7.id()));
    assert!(!m.contains(&a2.id()), "settled under the counting checkpoint");
    sync_all(&mut m, core::slice::from_ref(&c8), &g.lists);
    assert_eq!(m.state().checkpoint, Some(c8.id()));
    sync_all(&mut m, core::slice::from_ref(&a2), &g.lists);
    let st = m.state();
    assert!(m.contains(&a2.id()) && st.counting.contains(&a2.id()));
    let held: Vec<Record> = m.ids().map(|id| m.get(id).unwrap().clone()).collect();
    assert_eq!(st, state_with(&g.root.key, &held, &g.lists));
}

/// The peer's key as its 65 bytes.
fn point_of(x: &K) -> [u8; 65] {
    x.key.public().to_vec().try_into().unwrap()
}

/// Two histories of the current root: a key one line admits, which the
/// state lists nowhere, gets the proof (the lowest pair) and nothing else,
/// the same after a restart; from it the member takes only what makes or
/// completes a pair of the current root.
#[test]
fn a_key_one_line_admits_gets_the_pair_alone() {
    let mut g = G::new();
    g.device(&k("root"), &k("m0"), "m0", |_| {});
    let low = g.root_rec(Kind::Copies { incoming_ms: 5_000, seen: vec![] });
    let low2 = root_twin(&g, &low, Kind::Copies { incoming_ms: 5_001, seen: vec![] });
    let a = g.device(&k("root"), &k("m5"), "m5", |_| {});
    let a2 = root_twin(&g, &a, Kind::device(Device::new(k("m6").key.clone(), "m6", ROLE_MEMBER)));
    let mut m0 = set_with(&g.root.key, &g.recs, &g.lists);
    m0.insert(a2.clone()).unwrap();
    let mut pair = vec![a.id(), a2.id()];
    pair.sort();
    let me = k("m0").hash;
    for (when, set) in [
        ("live", m0.clone()),
        ("restarted", {
            let held: Vec<Record> = m0.in_dependency_order().into_iter().cloned().collect();
            RecordSet::restore(g.root.key.clone(), rk(), &held, &g.lists)
        }),
    ] {
        let st = set.state();
        assert!(st.stopped() && !st.halted(), "{when}");
        assert!(st.device_by_key(&k("m5").hash).is_none() && !st.revoked.contains(&k("m5").hash), "{when}");
        let mut keys = vec![k("m5").hash, k("m6").hash];
        keys.sort();
        assert_eq!(st.proof_to, keys, "{when}");
        assert_eq!(st.root_pair, Some((a.body().seq, pair[0], pair[1])), "{when}");
        assert_eq!(crate::peer::standing(&st, &me, &point_of(&k("m5"))), crate::peer::Standing::ForkProof, "{when}");
        let given: Vec<RecordId> = set.for_peer(&st, &k("m5").hash).iter().map(|r| r.id()).collect();
        assert_eq!(given, pair, "{when}: the pair and nothing else");
        assert_eq!(crate::peer::standing(&st, &me, &point_of(&k("stranger"))), crate::peer::Standing::Unknown);
        assert!(set.for_peer(&st, &k("stranger").hash).is_empty());
    }
    // m5, which holds one half, takes the other from m0 and halts alike.
    let upto: Vec<Record> = g.recs.clone();
    let mut m5 = set_with(&g.root.key, &upto, &g.lists);
    let st0 = m0.state();
    m5.insert_all(m0.for_peer(&st0, &k("m5").hash).into_iter().cloned());
    assert_eq!(m5.state().root_pair, st0.root_pair);
    // From such a peer: a record the root signed goes through the
    // ordinary insert (a pair at a lower seq moves the fork seq down);
    // what another key signed is not read.
    let other = g.root_rec(Kind::Copies { incoming_ms: 6_000, seen: vec![] });
    assert_ne!(m0.insert_proof(other.clone()), Ok(Added::Halted));
    let theirs = g.device(&k("a admin"), &k("m9"), "m9", |_| {});
    assert_eq!(m0.insert_proof(theirs), Ok(Added::Halted));
    assert_eq!(m0.insert_proof(low2.clone()), Ok(Added::Stored));
    let st = m0.state();
    let mut low_pair = [low.id(), low2.id()];
    low_pair.sort();
    assert_eq!(st.root_pair, Some((low.body().seq, low_pair[0], low_pair[1])));
}

/// A member that took the pair before the records that admit anyone can
/// place no peer: from a key one line admits it takes the root's records
/// by the ordinary insert, and ends as a member that held them all.
#[test]
fn a_member_that_holds_only_the_pair_takes_the_root_records() {
    let mut g = G::new();
    g.device(&k("root"), &k("m0"), "m0", |_| {});
    g.root_rec(Kind::Copies { incoming_ms: 5_000, seen: vec![] });
    let a = g.device(&k("root"), &k("m5"), "m5", |_| {});
    let a2 = root_twin(&g, &a, Kind::device(Device::new(k("m6").key.clone(), "m6", ROLE_MEMBER)));
    g.device(&k("root"), &k("m7"), "m7", |_| {});
    let mut full = set_with(&g.root.key, &g.recs, &g.lists);
    full.insert(a2.clone()).unwrap();
    let mut m = RecordSet::new(g.root.key.clone(), rk());
    m.insert(a.clone()).unwrap();
    m.insert(a2.clone()).unwrap();
    let st = m.state();
    assert!(st.stopped() && st.devices.is_empty());
    assert_eq!(crate::peer::standing(&st, &k("m6").hash, &point_of(&k("m5"))), crate::peer::Standing::ForkProof);
    for r in full.in_dependency_order() {
        m.insert_proof(r.clone()).unwrap();
    }
    assert_eq!(m.digest(), full.digest());
    assert_eq!(m.state(), full.state());
}

/// A removed key is told its removal also when that removal is half of the
/// pair, but never the pair as such: not the other half, and of two
/// removals that both name it, one.
#[test]
fn a_removed_key_gets_its_removal_but_never_the_pair() {
    let mut g = G::new();
    g.device(&k("root"), &k("m0"), "m0", |_| {});
    let a = g.device(&k("root"), &k("m5"), "m5", |_| {});
    let rm = root_twin(&g, &a, Kind::Revoke(removal(&[k("m5").hash], g.seen())));
    let mut m0 = set_with(&g.root.key, &g.recs, &g.lists);
    m0.insert(rm.clone()).unwrap();
    let st = m0.state();
    assert!(st.stopped() && st.revoked.contains(&k("m5").hash));
    assert!(st.proof_to.is_empty());
    assert_ne!(crate::peer::standing(&st, &k("m0").hash, &point_of(&k("m5"))), crate::peer::Standing::ForkProof);
    let got: Vec<RecordId> = m0.for_peer(&st, &k("m5").hash).iter().map(|r| r.id()).collect();
    assert_eq!(got, [rm.id()]);

    // Both halves name it: it gets one of them.
    let mut g = G::new();
    g.device(&k("root"), &k("m0"), "m0", |_| {});
    g.device(&k("root"), &k("m5"), "m5", |_| {});
    g.device(&k("root"), &k("m6"), "m6", |_| {});
    let one = g.root_rec(Kind::Revoke(removal(&[k("m5").hash], g.seen())));
    let mut both = [k("m5").hash, k("m6").hash];
    both.sort();
    let two = root_twin(&g, &one, Kind::Revoke(removal(&both, g.seen())));
    let mut m0 = set_with(&g.root.key, &g.recs, &g.lists);
    m0.insert(two.clone()).unwrap();
    let st = m0.state();
    assert!(st.stopped() && st.revoked.contains(&k("m5").hash));
    let got: Vec<RecordId> = m0.for_peer(&st, &k("m5").hash).iter().map(|r| r.id()).collect();
    assert_eq!(got, [one.id().min(two.id())]);
}

/// A device the root removes above the fork learns it is removed: the
/// removal counts on its line, and it is no part of the pair.
#[test]
fn a_device_removed_above_the_fork_learns_it_is_removed() {
    let mut g = G::new();
    g.device(&k("root"), &k("m0"), "m0", |_| {});
    g.device(&k("root"), &k("m5"), "m5", |_| {});
    let x = g.device(&k("root"), &k("m6"), "m6", |_| {});
    let twin = root_twin(&g, &x, Kind::Copies { incoming_ms: 5_000, seen: vec![] });
    let rm = g.root_rec(Kind::Revoke(removal(&[k("m5").hash], g.seen())));
    let mut m0 = set_with(&g.root.key, &g.recs, &g.lists);
    m0.insert(twin.clone()).unwrap();
    let st = m0.state();
    assert!(st.stopped() && st.revoked.contains(&k("m5").hash));
    assert!(st.root_pair.is_some_and(|(seq, _, _)| seq < rm.body().seq));
    let got: Vec<RecordId> = m0.for_peer(&st, &k("m5").hash).iter().map(|r| r.id()).collect();
    assert!(got.contains(&rm.id()));
    assert!(!got.contains(&x.id()) && !got.contains(&twin.id()));
}

/// A key an admin admits while the root has two histories: the admin's
/// record counts as before (its power comes from a root record below the
/// fork, and an admin's seq says nothing of the root's), so the key is a
/// device; it gets the records, and the stop gates every action.
#[test]
fn a_key_an_admin_admits_in_a_root_fork_is_a_device_that_does_nothing() {
    let mut g = G::new();
    g.device(&k("root"), &k("m0"), "m0", |_| {});
    g.admin(&k("pa"), &k("a"), POWER_ADMIT);
    let a = g.device(&k("root"), &k("m5"), "m5", |_| {});
    let a2 = root_twin(&g, &a, Kind::Copies { incoming_ms: 5_000, seen: vec![] });
    let m8 = g.device(&k("a"), &k("m8"), "m8", |_| {});
    let mut m0 = set_with(&g.root.key, &g.recs, &g.lists);
    m0.insert(a2).unwrap();
    let st = m0.state();
    assert!(st.stopped() && st.counting.contains(&m8.id()));
    let id = st.device_by_key(&k("m8").hash).unwrap().id;
    assert_eq!(
        crate::peer::standing(&st, &k("m0").hash, &point_of(&k("m8"))),
        crate::peer::Standing::Member(crate::format::DeviceId(id.0))
    );
    assert!(!st.proof_to.contains(&k("m8").hash));
}

/// An admin's removal naming the recovery key counts for nothing (no
/// admin outranks it), and no removal puts the recovery key among the
/// removed; the state names the group's recovery key.
#[test]
fn the_recovery_key_is_never_removed() {
    let mut g = G::new();
    g.device(&k("root"), &k("m0"), "m0", |_| {});
    g.admin(&k("pa"), &k("a"), POWER_ADMIT | POWER_REMOVE | POWER_REMOVE_ADMINS);
    let by_admin = g.rec(&k("a"), Kind::Revoke(removal(&[rk().hash()], g.seen())));
    g.root_rec(Kind::Revoke(removal(&[rk().hash()], g.seen())));
    let set = set_with(&g.root.key, &g.recs, &g.lists);
    let st = set.state();
    assert!(!st.revoked.contains(&rk().hash()));
    assert!(!st.counting.contains(&by_admin.id()));
    assert!(st.ignored.iter().any(|i| i.record == by_admin.id() && i.why == Why::Power));
    assert_eq!(st.recovery, rk().hash());
    assert_eq!(st, state_with(&g.root.key, &g.recs, &g.lists));
}

/// A set whose root key is its recovery key takes nothing, and a device's
/// store that pinned such keys is not taken.
#[test]
fn a_set_whose_root_is_its_recovery_key_takes_nothing() {
    let root = k("root");
    let own = Recovery { k1: root.key.clone(), ..rk() };
    let gid = group_id(&root.key, &own);
    let body = Body {
        group: gid,
        signer: root.hash,
        seq: 1,
        prev: None,
        time_ms: 0,
        kind: Kind::device(Device::new(k("m0").key.clone(), "m0", ROLE_MEMBER)),
        held: false,
    };
    let r = Record::sign(body, &root).unwrap();
    let mut set = RecordSet::new(root.key.clone(), own.clone());
    assert_eq!(set.insert(r), Err(Refused::Group));
    assert!(set.is_empty());
    let local = [7u8; 32];
    let mark = pin_mark(&local, &root.key, &own);
    assert!(RecordSet::pinned(root.key.clone(), own, &local, &mark).is_none());
}

/// Records 1 to 20 of the root that checkpoint 7 pruned; 8 keeps the
/// first eight, 9 the next eight: more than the place aside holds
/// together (small rooms 14/12/5), each fitting on its own.
fn eight_and_nine(nine_unheld: bool) -> (G, Vec<Record>, Record, Record, Record) {
    let mut g = G::new();
    let laptop = g.device(&k("root"), &k("laptop"), "laptop", |_| {});
    let old: Vec<Record> = (0..20).map(|i| g.root_rec(Kind::Copies { incoming_ms: 5_000 + i, seen: vec![] })).collect();
    g.root_rec(Kind::Copies { incoming_ms: 6_000, seen: vec![] });
    let c7 = root_cp(&mut g, vec![laptop.id()]);
    let mut k8: Vec<RecordId> = old[..8].iter().map(Record::id).collect();
    k8.extend([laptop.id(), c7.id()]);
    let c8 = root_cp(&mut g, k8);
    let mut k9: Vec<RecordId> = old[8..16].iter().map(Record::id).collect();
    k9.extend([laptop.id(), c8.id()]);
    if nine_unheld {
        k9.push(RecordId([0x59; 32]));
    }
    let c9 = root_cp(&mut g, k9);
    (g, old, c7, c8, c9)
}

/// What the newest waiting checkpoint keeps stays aside first: an honest
/// 8 and 9 whose records together pass the place aside end at 9 on a
/// member that counted 7, as on one handed everything at once.
#[test]
fn the_newest_waiting_checkpoint_keeps_its_records_aside_first() {
    let small = crate::records::keep::small::Small::new(14, 12, 5);
    let (g, old, c7, _c8, c9) = eight_and_nine(false);
    for r in &g.recs {
        small.units(r.id(), 1);
    }
    let base: Vec<Record> = g.recs.iter().filter(|r| !old.iter().any(|o| o.id() == r.id())).cloned().collect();
    let without9: Vec<Record> = base.iter().filter(|r| r.id() != c9.id()).cloned().collect();
    let mut m = set_with(&g.root.key, &without9[..without9.len() - 1], &g.lists);
    sync_all(&mut m, &[], &g.lists);
    assert_eq!(m.state().checkpoint, Some(c7.id()));
    sync_all(&mut m, &base, &g.lists);
    for seed in [0, 1, 2] {
        let mut m = m.clone();
        let order = if seed == 0 { old.clone() } else { shuffled(&old, seed) };
        sync_all(&mut m, &order, &g.lists);
        assert_eq!(m.state().checkpoint, Some(c9.id()), "order {seed}");
        let once = set_with(&g.root.key, &g.recs, &g.lists);
        assert_eq!(m.digest(), once.digest(), "order {seed}");
        assert_eq!(m.state(), once.state(), "order {seed}");
    }
}

/// The limit, as written: a checkpoint of the root that is never whole,
/// whose records with an older waiting one's pass the place aside, keeps a
/// member at an older checkpoint, and once the member gave up asking each
/// is told with its reason.
#[test]
fn a_checkpoint_never_whole_that_fills_the_place_aside_is_told() {
    let small = crate::records::keep::small::Small::new(14, 12, 5);
    let (g, old, c7, c8, c9) = eight_and_nine(true);
    for r in &g.recs {
        small.units(r.id(), 1);
    }
    let base: Vec<Record> = g.recs.iter().filter(|r| !old.iter().any(|o| o.id() == r.id())).cloned().collect();
    let without: Vec<Record> = base.iter().filter(|r| r.body().seq < c7.body().seq + 1).cloned().collect();
    let mut m = set_with(&g.root.key, &without, &g.lists);
    sync_all(&mut m, &[], &g.lists);
    sync_all(&mut m, &base, &g.lists);
    // 9's records first, then 8's: 9 keeps its place, 8 is never whole.
    sync_all(&mut m, &old[8..16], &g.lists);
    sync_all(&mut m, &old[..8], &g.lists);
    assert_eq!(m.state().checkpoint, Some(c7.id()));
    assert!(m.stuck_checkpoints().is_empty());
    for _ in 0..crate::records::set::MISSING_ROUNDS {
        let st = m.state();
        let asked = m.missing(&st);
        let given: Vec<Record> = asked.iter().filter_map(|id| g.recs.iter().find(|r| r.id() == *id).cloned()).collect();
        sync_all(&mut m, &given, &g.lists);
    }
    assert_eq!(m.state().checkpoint, Some(c7.id()));
    // 9 waits for a record nobody has; 8's records were offered every
    // round and had no room beside 9's.
    let mut told = m.stuck_checkpoints();
    told.sort();
    let mut want = vec![(c9.id(), Stuck::NeverOffered), (c8.id(), Stuck::NoRoom)];
    want.sort();
    assert_eq!(told, want);
}

/// A record a later checkpoint keeps, of which the member remembers only
/// another record at its seq, waits aside as a half: the checkpoint counts
/// once it is whole, and the member still asks for the other record.
#[test]
fn a_half_a_later_checkpoint_keeps_waits_aside() {
    let mut g = G::new();
    let laptop = g.device(&k("root"), &k("laptop"), "laptop", |_| {});
    let x = g.device(&k("root"), &k("x"), "x", |_| {});
    let x2 = root_twin(&g, &x, Kind::device(Device::new(k("y").key.clone(), "y", ROLE_MEMBER)));
    let fill: Vec<Record> =
        (0..20).map(|i| g.root_rec(Kind::Copies { incoming_ms: 5_000 + i, seen: vec![] })).collect();
    g.root_rec(Kind::Copies { incoming_ms: 6_000, seen: vec![] });
    let c7 = root_cp(&mut g, vec![laptop.id()]);
    let c8 = root_cp(&mut g, vec![laptop.id(), x.id(), c7.id()]);
    let others: Vec<Record> =
        g.recs.iter().filter(|r| r.id() != x.id() && !fill.iter().any(|f| f.id() == r.id())).cloned().collect();
    let mut m = set_with(&g.root.key, &others, &g.lists);
    sync_all(&mut m, &[], &g.lists);
    assert_eq!(m.state().checkpoint, Some(c7.id()));
    // x2 comes and goes; only its (seq, key, ID) stays.
    assert!(matches!(m.insert(x2.clone()), Ok(Added::Settled { .. })));
    for r in &fill {
        let _ = m.insert(r.clone());
    }
    let _ = m.insert(x.clone());
    sync_all(&mut m, &[], &g.lists);
    assert_eq!(m.state().checkpoint, Some(c8.id()));
    assert!(m.missing(&m.state()).contains(&x2.id()));
}

/// The member asks for what every checkpoint above the counting one
/// keeps, not only the newest one.
#[test]
fn the_member_asks_for_what_every_waiting_checkpoint_keeps() {
    let mut g = G::new();
    let laptop = g.device(&k("root"), &k("laptop"), "laptop", |_| {});
    let x = g.device(&k("root"), &k("x"), "x", |_| {});
    g.root_rec(Kind::Copies { incoming_ms: 5_000, seen: vec![] });
    let c7 = root_cp(&mut g, vec![laptop.id()]);
    let c8 = root_cp(&mut g, vec![laptop.id(), x.id(), c7.id()]);
    root_cp(&mut g, vec![laptop.id(), c8.id(), RecordId([0x59; 32])]);
    let others: Vec<Record> = g.recs.iter().filter(|r| r.id() != x.id()).cloned().collect();
    let mut m = set_with(&g.root.key, &others, &g.lists);
    sync_all(&mut m, &[], &g.lists);
    assert_eq!(m.state().checkpoint, Some(c7.id()));
    let st = m.state();
    assert!(m.missing(&st).contains(&x.id()));
}

/// A record of the place aside goes by its ID to a device of the group,
/// not to a removed key.
#[test]
fn what_waits_aside_goes_by_id_as_the_peers_standing_says() {
    let mut g = G::new();
    let laptop = g.device(&k("root"), &k("laptop"), "laptop", |_| {});
    let x = g.device(&k("root"), &k("x"), "x", |_| {});
    g.device(&k("root"), &k("gone"), "gone", |_| {});
    g.root_rec(Kind::Revoke(removal(&[k("gone").hash], g.seen())));
    let c7 = root_cp(&mut g, vec![laptop.id()]);
    root_cp(&mut g, vec![laptop.id(), x.id(), c7.id(), RecordId([0x5d; 32])]);
    let others: Vec<Record> = g.recs.iter().filter(|r| r.id() != x.id()).cloned().collect();
    let mut m = set_with(&g.root.key, &others, &g.lists);
    sync_all(&mut m, &[], &g.lists);
    m.insert(x.clone()).unwrap();
    assert!(m.waits_aside(&x.id()));
    let st = m.state();
    assert!(st.revoked.contains(&k("gone").hash));
    assert!(m.for_peer_by_id(&st, &k("laptop").hash, &x.id()).is_some());
    assert!(m.for_peer_by_id(&st, &k("gone").hash, &x.id()).is_none());
    assert!(m.for_peer_by_id(&st, &k("stranger").hash, &x.id()).is_none());
}

/// The writer of ordinary records: it follows the key's head, the set
/// takes what it writes, and it refuses what its own set would not keep
/// or count, leaving the set as it was and using no seq.
#[test]
fn the_writer_writes_only_what_its_own_set_keeps_and_counts() {
    let _small = crate::records::keep::small::Small::new(64, 16, 4);
    let mut g = G::new();
    let (pa, a) = (k("phone a"), k("admin a"));
    g.admin(&pa, &a, POWER_ADMIT);
    let mut set = set_with(&g.root.key, &g.recs, &g.lists);
    let mut seqs = Vec::new();
    for i in 0..4 {
        let st = set.state();
        let d = Device::new(k(&format!("laptop {i}")).key.clone(), "laptop", ROLE_MEMBER);
        let r = set.write_record(&st, &a, Kind::device(d), 0).unwrap();
        assert!(set.contains(&r.id()) && set.state().counting.contains(&r.id()), "record {i}");
        seqs.push(r.body().seq);
    }
    assert_eq!(seqs, vec![1, 2, 3, 4], "each follows the key's head");
    // The admin key's room (four units) is full: the next is refused and
    // the set is as it was.
    let (before, st) = (set.digest(), set.state());
    let d = Device::new(k("laptop 4").key.clone(), "laptop", ROLE_MEMBER);
    assert!(set.write_record(&st, &a, Kind::device(d), 0).is_err());
    assert_eq!(set.digest(), before);
    // A key with no room, the recovery key, a checkpoint: refused.
    let d = Device::new(k("laptop 5").key.clone(), "laptop", ROLE_MEMBER);
    assert!(set.write_record(&st, &k("stranger"), Kind::device(d.clone()), 0).is_err());
    assert!(set.write_record(&st, &k("recovery"), Kind::device(d.clone()), 0).is_err());
    let cp = Kind::Checkpoint { heads: Vec::new(), keep: Vec::new() };
    assert!(set.write_record(&st, &g.root, cp, 0).is_err());
    assert_eq!(set.digest(), before);
    // The root still writes, at its own next seq.
    let r = set.write_record(&st, &g.root, Kind::device(d), 0).unwrap();
    assert_eq!(r.body().seq, 2);
    assert!(set.state().counting.contains(&r.id()));
}

/// A frozen admin's next record would not count: the writer refuses it.
#[test]
fn the_writer_refuses_a_record_that_would_not_count() {
    let mut g = G::new();
    let (pa, a) = (k("phone a"), k("admin a"));
    g.admin(&pa, &a, POWER_ADMIT);
    let seen = g.seen();
    g.root_rec(Kind::Freeze(removal(&[a.hash], seen)));
    let mut set = set_with(&g.root.key, &g.recs, &g.lists);
    let (before, st) = (set.digest(), set.state());
    let d = Device::new(k("laptop").key.clone(), "laptop", ROLE_MEMBER);
    assert!(set.write_record(&st, &a, Kind::device(d), 0).is_err());
    assert_eq!(set.digest(), before);
}

/// An admin's removal reaches a device that lacks the admin's records
/// below it (here its own admission): it is handed the removal's chain,
/// the removal counts there, and nothing above the removal nor another
/// line of the admin's key is handed (simulator seed 766).
#[test]
fn a_removed_device_gets_its_removals_chain() {
    let mut g = G::new();
    let (pa, a) = (k("pa"), k("a"));
    g.admin(&pa, &a, POWER_ADMIT | POWER_REMOVE);
    let at_root = g.recs.clone();
    let (laptop, tablet) = (k("laptop"), k("tablet"));
    let admitted = g.device(&a, &laptop, "laptop", |_| {});
    let other = g.device(&a, &tablet, "tablet", |_| {});
    let rv = g.rec(&a, Kind::Revoke(removal(&[laptop.hash], g.seen())));
    let after = g.device(&a, &k("phone"), "phone", |_| {});
    let set = set_with(&g.root.key, &g.recs, &g.lists);
    let st = set.state();
    assert!(st.revoked.contains(&laptop.hash));
    let given: Vec<RecordId> = set.for_peer(&st, &laptop.hash).iter().map(|r| r.id()).collect();
    for r in [&admitted, &other, &rv] {
        assert!(given.contains(&r.id()), "the removal and its chain");
    }
    assert!(!given.contains(&after.id()), "nothing above the removal");
    // The device holds the root's records and the removal, not its own
    // admission: with what it is handed, it knows it is removed.
    let mut mine = set_with(&g.root.key, &at_root, &g.lists);
    mine.insert(rv.clone()).unwrap();
    assert!(!mine.state().revoked.contains(&laptop.hash));
    mine.insert_all(set.for_peer(&st, &laptop.hash).into_iter().cloned());
    assert!(mine.state().revoked.contains(&laptop.hash));
    // By ID too, as `missing()` asks.
    assert_eq!(set.for_peer_by_id(&st, &laptop.hash, &admitted.id()).map(Record::id), Some(admitted.id()));
    assert!(set.for_peer_by_id(&st, &laptop.hash, &after.id()).is_none());
    // What is handed of the admin's key is one line, within its ceiling.
    let units: u64 = set
        .for_peer(&st, &laptop.hash)
        .iter()
        .filter(|r| r.body().signer == a.hash)
        .map(|r| crate::records::keep::units(r.envelope().len()))
        .sum();
    assert!(units <= crate::records::keep::ceiling(false));
    // A twin of the chain (a second record of the admin's key at the
    // tablet's seq) is on no prev chain of the removal: never handed.
    let twin = Body {
        group: g.gid,
        signer: a.hash,
        seq: other.body().seq,
        prev: other.body().prev,
        time_ms: 1,
        kind: Kind::device(Device::new(k("tv").key.clone(), "tv", ROLE_MEMBER)),
        held: false,
    };
    let twin = Record::sign(twin, &a).unwrap();
    let mut both = set.clone();
    let _ = both.insert(twin.clone());
    let st2 = both.state();
    // Two histories of the admin's key: its removal on a whole chain still
    // bars the device (F-7 for every key), and what is handed is the one
    // line the removal's prev chain walks.
    assert!(st2.two_histories(&a.hash) && st2.revoked.contains(&laptop.hash));
    let handed = both.for_peer(&st2, &laptop.hash);
    assert!(handed.iter().any(|r| r.id() == rv.id()));
    assert!(!handed.iter().any(|r| r.id() == twin.id()), "the twin is not handed");
    let mut seqs: Vec<u64> = handed.iter().filter(|r| r.body().signer == a.hash).map(|r| r.body().seq).collect();
    let n = seqs.len();
    seqs.dedup();
    assert_eq!(seqs.len(), n, "one record of the admin's key per seq");
}

/// A root checkpoint that pruned before its twin came (fuzz
/// min-dev-twin-cp): the pair stops the group and the checkpoint below
/// counts again, naming records the member dropped. It asks for them, takes
/// them from a peer that holds them, and ends as one that took every
/// record at once. When no peer holds them every member ends alike and is
/// told; the recovery key's change of root, written from what the writer
/// holds, is taken by every member and the group goes on.
#[test]
fn a_checkpoint_that_pruned_before_its_twin_gets_back_what_it_dropped() {
    let mut g = G::new();
    let d0 = g.device(&k("root"), &k("dev0"), "dev0", |_| {});
    let d3 = g.device(&k("root"), &k("dev3"), "dev3", |_| {});
    let d1 = g.device(&k("root"), &k("dev1"), "dev1", |_| {});
    let c6 = root_cp(&mut g, vec![d0.id(), d3.id()]);
    let c7 = root_cp(&mut g, vec![]);
    let t7 = root_twin(&g, &c7, Kind::device(Device::new(k("dev9").key.clone(), "dev9", ROLE_MEMBER)));
    let base: Vec<Record> = vec![d0.clone(), d3.clone(), d1.clone(), c6.clone()];
    let pruned_first = || {
        let mut a = set_with(&g.root.key, &base, &g.lists);
        a.insert(c7.clone()).unwrap();
        let _ = a.insert(t7.clone());
        a
    };
    let mut a = pruned_first();
    let mut b = set_with(&g.root.key, &base, &g.lists);
    let _ = b.insert(t7.clone());
    let _ = b.insert(c7.clone());
    let mut all = base.clone();
    all.extend([c7.clone(), t7.clone()]);
    let whole = state_with(&g.root.key, &all, &g.lists);
    assert!(whole.stopped() && whole.devices.len() == 3);
    assert_eq!(b.state().devices, whole.devices);
    assert!(!a.contains(&d0.id()) && !a.contains(&d3.id()));
    // It asks for them, and the peer gives them by ID.
    let st = a.state();
    let asked = a.missing(&st);
    assert!(asked.contains(&d0.id()) && asked.contains(&d3.id()));
    let sb = b.state();
    let given: Vec<Record> =
        asked.iter().filter_map(|id| b.for_peer_by_id(&sb, &k("dev1").hash, id)).cloned().collect();
    a.insert_all(given);
    assert_eq!(a.digest(), b.digest());
    assert_eq!(a.state().devices, whole.devices);

    // Nobody holds them: the members end alike, and are told.
    let (mut a1, mut a2) = (pruned_first(), pruned_first());
    assert_eq!(a1.digest(), a2.digest());
    assert_eq!(a1.state(), a2.state());
    assert!(a1.state().stopped());
    for _ in 0..=crate::records::set::MISSING_ROUNDS {
        let st = a1.state();
        a1.missing(&st);
    }
    assert!(a1.stuck_checkpoints().contains(&(c6.id(), Stuck::NeverOffered)));
    // The recovery key changes the root from what a1 holds; a2 takes it and
    // the group goes on, the same at both.
    let st = a1.state();
    let phone = Device::new(k("root2 phone").key.clone(), "root2 phone", ROLE_PHONE);
    let w = a1.write_change(&st, &k("recovery"), crate::testkit::rk2(), &k("root2"), phone, &[], false, 0).unwrap();
    a2.insert(w.record.clone()).unwrap();
    a2.insert_list(&w.list.encode()).unwrap();
    a2.insert_all(w.first.iter().cloned());
    let (s1, s2) = (a1.state(), a2.state());
    assert_eq!(s1.roots.last(), Some(&k("root2").hash));
    assert!(!s1.stopped());
    assert_eq!(s1, s2);
    assert_eq!(a1.digest(), a2.digest());
}

/// Fuzz min-dev-twin-cp: a whole checkpoint of the root at the seq where
/// it has two histories never counts, so it does not hold back the one
/// below it: what that one keeps again (a record an older one pruned) is
/// taken, and the member ends as one that took every record at once.
#[test]
fn a_checkpoint_at_the_fork_seq_counts_for_nothing() {
    let mut g = G::new();
    let d0 = g.device(&k("root"), &k("dev0"), "dev0", |_| {});
    let d3 = g.device(&k("root"), &k("dev3"), "dev3", |_| {});
    let s3 = g.root_rec(Kind::settings(Settings { shared: true, ..Settings::default() }));
    let c4 = root_cp(&mut g, vec![d3.id()]);
    let d1 = g.device(&k("root"), &k("dev1"), "dev1", |_| {});
    let c6 = root_cp(&mut g, vec![s3.id(), d0.id()]);
    let c7 = root_cp(&mut g, vec![c4.id(), d3.id()]);
    let t7 = root_twin(&g, &c7, Kind::device(Device::new(k("dev9").key.clone(), "dev9", ROLE_MEMBER)));
    let all = vec![d0.clone(), d3.clone(), s3.clone(), c4.clone(), d1.clone(), c6.clone(), c7.clone(), t7.clone()];
    let whole = state_with(&g.root.key, &all, &g.lists);
    assert!(whole.stopped());
    let mut m = set_with(&g.root.key, &all[..4], &g.lists);
    for r in [&d1, &c6, &c7, &t7] {
        let _ = m.insert(r.clone());
    }
    // What the checkpoint below the fork keeps again, asked for.
    for _ in 0..4 {
        let st = m.state();
        let asked = m.missing(&st);
        m.insert_all(all.iter().filter(|r| asked.contains(&r.id())).cloned());
    }
    let st = m.state();
    assert!(m.contains(&d0.id()) && m.contains(&s3.id()));
    assert_eq!(st.checkpoint, whole.checkpoint);
    assert_eq!(st.devices, whole.devices);
    assert_eq!(st.counting, whole.counting);
}

/// F-7 for every key: an admin key in two histories brings back nothing it
/// removed. A twin at seq 1, or just below its oldest removal, leaves every
/// removal on a whole chain barring; the removals of both histories count;
/// one whose chain is not whole counts on neither.
#[test]
fn a_key_in_two_histories_brings_back_nothing_it_removed() {
    let (pa, a) = (k("pa"), k("a"));
    let (d1, d2, d3) = (k("d1"), k("d2"), k("d3"));
    let base = |g: &mut G| -> (Record, Record, Record) {
        g.admin(&pa, &a, POWER_ADMIT | POWER_REMOVE);
        let x1 = g.device(&a, &d1, "d1", |_| {});
        let x2 = g.device(&a, &d2, "d2", |_| {});
        let rv = g.rec(&a, Kind::Revoke(removal(&[d1.hash], g.seen())));
        (x1, x2, rv)
    };
    let twin_at = |g: &G, seq: u64, prev: Option<RecordId>, kind: Kind| {
        let b = Body { group: g.gid, signer: a.hash, seq, prev, time_ms: 7, kind, held: false };
        Record::sign(b, &a).unwrap()
    };
    let copies = || Kind::Copies { incoming_ms: 6_000, seen: vec![] };
    // A twin at seq 1, and one just below the removal (at seq 2).
    for at in [1u64, 2] {
        let mut g = G::new();
        let (x1, _, _) = base(&mut g);
        let prev = if at == 1 { None } else { Some(x1.id()) };
        let t = twin_at(&g, at, prev, copies());
        g.push(t);
        let s = g.state();
        assert!(s.two_histories(&a.hash), "twin at {at}");
        assert!(s.revoked.contains(&d1.hash), "twin at {at}: the removal still bars");
        assert!(s.device_by_key(&d1.hash).is_none(), "twin at {at}");
    }
    // Each history removes a device: both stay out.
    let mut g = G::new();
    let (_, x2, _) = base(&mut g);
    let t = twin_at(&g, 3, Some(x2.id()), Kind::Revoke(removal(&[d2.hash], g.seen())));
    g.push(t);
    let s = g.state();
    assert!(s.two_histories(&a.hash));
    assert!(s.revoked.contains(&d1.hash) && s.revoked.contains(&d2.hash), "both histories' removals count");
    // A removal whose chain is not whole counts on neither history.
    let mut g = G::new();
    let (_, x2, rv) = base(&mut g);
    let rv3 = g.rec(&a, Kind::Revoke(removal(&[d3.hash], g.seen())));
    assert_eq!(rv3.body().prev, Some(rv.id()));
    let t = twin_at(&g, 1, None, copies());
    g.push(t);
    let held: Vec<Record> = g.recs.iter().filter(|r| r.id() != x2.id()).cloned().collect();
    let s = state_with(&g.root.key, &held, &g.lists);
    assert!(s.two_histories(&a.hash));
    assert!(!s.counting.contains(&rv3.id()) && !s.revoked.contains(&d3.hash), "a removal above a gap");
}

/// The root removes an admin key in two histories: its own removals of
/// what that key's removals bar come first, so nothing the key barred on
/// either line comes back in any order of arrival, and nothing the key
/// signs after its removal counts. A removal that skips the writer is told.
#[test]
fn removing_a_key_in_two_histories_keeps_out_what_it_barred() {
    let mut g = G::new();
    let (pa, a) = (k("pa"), k("a"));
    g.admin(&pa, &a, POWER_ADMIT | POWER_REMOVE);
    let (d1, d2, d3) = (k("d1"), k("d2"), k("d3"));
    let x1 = g.device(&a, &d1, "d1", |_| {});
    let x2 = g.device(&a, &d2, "d2", |_| {});
    g.device(&a, &d3, "d3", |_| {});
    let seen = g.seen();
    let rv1 = g.rec(&a, Kind::Revoke(removal(&[d1.hash], seen.clone())));
    // The other line: at rv1's seq, after x2... no: after the record below rv1.
    let below = g.recs.iter().find(|r| r.id() == rv1.body().prev.unwrap()).unwrap().clone();
    let tb = Body {
        group: g.gid,
        signer: a.hash,
        seq: rv1.body().seq,
        prev: Some(below.id()),
        time_ms: 9,
        kind: Kind::Revoke(removal(&[d2.hash], seen)),
        held: false,
    };
    let rv2 = g.push(Record::sign(tb, &a).unwrap());
    let _ = (x1, x2);
    let mut set = set_with(&g.root.key, &g.recs, &g.lists);
    let st = set.state();
    assert!(st.two_histories(&a.hash));
    assert!(st.revoked.contains(&d1.hash) && st.revoked.contains(&d2.hash));
    // write_record refuses, untouched.
    let before = set.digest();
    assert!(set.write_record(&st, &g.root, Kind::Revoke(removal(&[a.hash], Vec::new())), 0).is_err());
    assert_eq!(set.digest(), before);
    let written = set.write_removal(&st, &g.root, &[a.hash], 0).unwrap();
    assert!(written.len() >= 2);
    let s = set.state();
    for key in [&a.hash, &d1.hash, &d2.hash] {
        assert!(s.revoked.contains(key));
    }
    assert!(s.forked_removed.is_empty());
    // In every order of arrival of both lines and the removal at a member
    // that holds the rest, whichever line arrives first.
    let rest: Vec<Record> = g.recs.iter().filter(|r| r.id() != rv1.id() && r.id() != rv2.id()).cloned().collect();
    let mut late: Vec<Record> = vec![rv1.clone(), rv2.clone()];
    late.extend(written.iter().cloned());
    let mut idx: Vec<usize> = (0..late.len()).collect();
    let mut orders = 0;
    loop {
        let mut m = set_with(&g.root.key, &rest, &g.lists);
        for &i in &idx {
            let _ = m.insert(late[i].clone());
        }
        let sm = m.state();
        assert!(sm.revoked.contains(&d1.hash) && sm.revoked.contains(&d2.hash) && sm.revoked.contains(&a.hash));
        assert!(sm.forked_removed.is_empty());
        orders += 1;
        // Next permutation.
        let Some(i) = (0..idx.len().saturating_sub(1)).rev().find(|&i| idx[i] < idx[i + 1]) else { break };
        let j = (i + 1..idx.len()).rev().find(|&j| idx[j] > idx[i]).unwrap();
        idx.swap(i, j);
        idx[i + 1..].reverse();
    }
    assert!(orders >= 24);
    // Nothing A signs after its removal counts.
    let head = g.heads[&a.hash];
    let late = Body {
        group: g.gid,
        signer: a.hash,
        seq: head.0 + 1,
        prev: Some(head.1),
        time_ms: 10,
        kind: Kind::Revoke(removal(&[d3.hash], g.seen())),
        held: false,
    };
    let late = Record::sign(late, &a).unwrap();
    let _ = set.insert(late.clone());
    let s = set.state();
    assert!(!s.counting.contains(&late.id()) && !s.revoked.contains(&d3.hash));
    // A removal of A that skips the writer, seeing one line: the other
    // line's removal no longer counts, and the state tells it.
    for (line, other) in [(&rv1, &d2), (&rv2, &d1)] {
        let mut seen = g.seen();
        seen.retain(|e| e.key != a.hash);
        seen.push(Seen { key: a.hash, seq: line.body().seq, id: line.id() });
        seen.sort_by_key(|e| e.key);
        let mut h = G { root: k("root"), gid: g.gid, heads: g.heads.clone(), recs: g.recs.clone(), lists: Vec::new() };
        h.root_rec(Kind::Revoke(removal(&[a.hash], seen)));
        let s = h.state();
        assert!(!s.revoked.contains(&other.hash));
        assert_eq!(s.forked_removed, vec![(a.hash, vec![other.hash])]);
    }
}

/// At most ADMIN_KEYS_MAX admin keys count: the writer refuses another
/// admission of an admin key, and a reader handed one more (a root that
/// deviates) counts the first sixteen admitted; the seventeenth device is
/// a device without an admin key, and what its key signs counts for
/// nothing.
#[test]
fn at_most_sixteen_admin_keys_count() {
    use crate::records::ADMIN_KEYS_MAX;
    let mut g = G::new();
    for i in 0..ADMIN_KEYS_MAX {
        g.admin(&k(&format!("admin device {i}")), &k(&format!("admin {i}")), POWER_ADMIT);
    }
    let mut set = set_with(&g.root.key, &g.recs, &g.lists);
    let st = set.state();
    assert_eq!(st.devices.iter().filter(|d| d.admin.is_some()).count(), ADMIN_KEYS_MAX);
    let extra = k("admin 16");
    let mut d = Device::new(k("admin device 16").key.clone(), "admin", ROLE_MEMBER);
    d.rights = RIGHT_READ | RIGHT_SEND;
    d.admin = Some(extra.key.clone());
    d.powers = POWER_ADMIT;
    let before = set.digest();
    let err = set.write_record(&st, &g.root, Kind::device(d.clone()), 0).unwrap_err();
    assert!(alloc::format!("{err}").contains("admin keys already"), "{err}");
    assert_eq!(set.digest(), before);
    // A plain device still goes in.
    set.write_record(&st, &g.root, Kind::device(Device::new(k("laptop").key.clone(), "laptop", ROLE_MEMBER)), 0)
        .unwrap();
    // A reader handed a seventeenth admission.
    g.rec(&k("root"), Kind::device(d));
    let admitted = g.rec(&extra, Kind::device(Device::new(k("tv").key.clone(), "tv", ROLE_MEMBER)));
    let s = state_with(&g.root.key, &g.recs, &g.lists);
    assert_eq!(s.devices.iter().filter(|d| d.admin.is_some()).count(), ADMIN_KEYS_MAX);
    let dev = s.devices.iter().find(|d| d.key.hash() == k("admin device 16").hash).unwrap();
    assert_eq!(dev.admin, None);
    assert!(!s.counting.contains(&admitted.id()));
    assert!(s.device_by_key(&k("tv").hash).is_none());
    // Removing one admin frees a place: the next admitted counts.
    g.root_rec(Kind::Revoke(removal(&[k("admin 3").hash], g.seen())));
    let s = state_with(&g.root.key, &g.recs, &g.lists);
    assert_eq!(s.devices.iter().filter(|d| d.admin.is_some()).count(), ADMIN_KEYS_MAX);
    assert!(s.devices.iter().any(|d| d.admin == Some(extra.hash)));
}

/// The roots before the current one keep, together, at most the cut
/// roots' reserve, however many changes the path holds: two changes
/// whose lists name every record of the roots before keep the first
/// units of their removals and records within one reserve, the same in
/// every order, and the set agrees with evaluate.
#[test]
fn the_cut_roots_share_one_reserve() {
    let mut g = G::new();
    let root = k("root");
    for i in 0..4 {
        g.device(&root, &k(&format!("d{i}")), "d", |_| {});
    }
    let list = g.listing();
    g.change(&k("n1"), &list);
    let n1 = k("n1");
    for i in 0..4 {
        g.device(&n1, &k(&format!("e{i}")), "e", |_| {});
    }
    // The second change lists everything the first two roots signed.
    let all: Vec<RecordId> =
        g.recs.iter().filter(|r| r.body().signer == root.hash || r.body().signer == n1.hash).map(Record::id).collect();
    g.change(&k("n2"), &all);
    let small = crate::records::keep::small::Small::new(30, 6, 4);
    for r in &g.recs {
        small.units(r.id(), 1);
    }
    let cut_units = |set: &RecordSet| {
        set.ids()
            .filter_map(|id| set.get(id))
            .filter(|r| r.body().signer == root.hash || r.body().signer == n1.hash)
            .count()
    };
    let mut seen = Vec::new();
    for seed in [0, 1, 2, 3] {
        let order = if seed == 0 { g.recs.clone() } else { shuffled(&g.recs, seed) };
        let set = set_with(&g.root.key, &order, &g.lists);
        let st = set.state();
        assert_eq!(st.roots.last(), Some(&k("n2").hash), "order {seed}");
        assert!(cut_units(&set) <= 6, "order {seed}: {} units of cut roots", cut_units(&set));
        let held: Vec<Record> = set.ids().map(|id| set.get(id).unwrap().clone()).collect();
        assert_eq!(st, state_with(&g.root.key, &held, &g.lists), "order {seed}");
        seen.push(set.digest());
    }
    assert!(seen.windows(2).all(|w| w[0] == w[1]));
}

/// The fold: a root removal that a newer one covers (every key it names,
/// the same seen of them) is left out of the next checkpoint and of a
/// change's list, by subset for many keys; the state is the same, and the
/// removal offered again counts for nothing new. One whose keys signed
/// more by the newer one does not fold.
#[test]
fn a_removal_a_newer_one_covers_folds() {
    let mut g = G::new();
    let s: Vec<K> = (0..10).map(|i| k(&format!("stranger {i}"))).collect();
    let singles: Vec<Record> = s.iter().map(|x| g.root_rec(Kind::Revoke(removal(&[x.hash], Vec::new())))).collect();
    let mut all: Vec<KeyHash> = s.iter().map(|x| x.hash).collect();
    all.sort();
    let cover = g.root_rec(Kind::Revoke(removal(&all, Vec::new())));
    // An admin removed, then signing on, then removed again with a device.
    let (pa, a) = (k("phone a"), k("admin a"));
    g.admin(&pa, &a, POWER_ADMIT);
    g.device(&a, &k("t1"), "t1", |_| {});
    let first = g.root_rec(Kind::Revoke(removal(&[a.hash], g.seen())));
    g.rec(&a, Kind::Copies { incoming_ms: 6_000, seen: vec![] });
    let mut both = vec![a.hash, k("t9").hash];
    both.sort();
    let again = g.root_rec(Kind::Revoke(removal(&both, g.seen())));
    g.device(&k("root"), &k("laptop"), "laptop", |_| {});
    let before = state_with(&g.root.key, &g.recs, &g.lists);
    let recs = g.recs.clone();
    let cp = root_checkpoint(&mut g, &recs);
    let Kind::Checkpoint { keep, .. } = &cp.body().kind else { panic!() };
    for r in &singles {
        assert!(!keep.contains(&r.id()), "a single removal the cover names is folded");
    }
    assert!(keep.contains(&cover.id()));
    assert!(keep.contains(&first.id()) && keep.contains(&again.id()), "seen differ: no fold");
    let after = state_with(&g.root.key, &g.recs, &g.lists);
    assert_eq!(after.checkpoint, Some(cp.id()));
    assert_eq!(before.revoked, after.revoked);
    let mut set = set_with(&g.root.key, &g.recs, &g.lists);
    for r in &singles {
        assert!(!set.contains(&r.id()));
        let _ = set.insert(r.clone());
    }
    assert_eq!(set.state().revoked, before.revoked);
    // A change's list carries none of the singles.
    let list = set.change_list(&set.state());
    assert!(singles.iter().all(|r| !list.0.contains(&r.id())));
}

/// The fold in a change's list: the root's removals of devices an admin
/// admitted (named, so listed), the older ones covered by a newer one,
/// are carried as the newer one alone, and the new root keeps them out.
#[test]
fn a_change_carries_the_newer_removal_alone() {
    let mut g = G::new();
    let (pa, a) = (k("phone a"), k("admin a"));
    g.admin(&pa, &a, POWER_ADMIT);
    let ts: Vec<K> = (0..4).map(|i| k(&format!("t{i}"))).collect();
    for t in &ts {
        g.device(&a, t, "t", |_| {});
    }
    let one = g.root_rec(Kind::Revoke(removal(&[ts[0].hash], g.seen())));
    let mut keys: Vec<KeyHash> = ts.iter().map(|t| t.hash).collect();
    keys.sort();
    let mut rm = removal(&keys, Vec::new());
    rm.seen = match &one.body().kind {
        Kind::Revoke(r) => r.seen.clone(),
        _ => unreachable!(),
    };
    let cover = g.root_rec(Kind::Revoke(rm));
    let set = set_with(&g.root.key, &g.recs, &g.lists);
    let st = set.state();
    let list = set.change_list(&st);
    assert!(list.0.contains(&cover.id()));
    assert!(!list.0.contains(&one.id()));
    let mut set = set;
    let w = set
        .write_change(
            &st,
            &k("recovery"),
            crate::testkit::rk2(),
            &k("n1"),
            {
                let mut d = Device::new(k("new phone").key.clone(), "new phone", ROLE_PHONE);
                d.rights = RIGHT_READ | RIGHT_SEND;
                d
            },
            &[],
            false,
            0,
        )
        .unwrap();
    let mut all = g.recs.clone();
    all.extend(w.first.iter().cloned());
    all.push(w.record.clone());
    let mut lists = g.lists.clone();
    lists.push(w.list.encode());
    let s = state_with(&g.root.key, &all, &lists);
    for t in &ts {
        assert!(s.revoked.contains(&t.hash) && s.device_by_key(&t.hash).is_none());
    }
}
