// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The scenarios of the model of the record rules (docs/model/records-v3.qnt)
//! run against the core: the same devices, records and changes of root, so
//! that the model and the code are seen to agree on them. The model's
//! names: R the first root, A a phone admin, C a computer admin, W a watch
//! admin (the member keys of their devices "A phone", "C computer",
//! "W watch"), K the group's recovery key, D a device, NK and NA the new
//! roots K's heads name, X a key a root not yet on the path names; m is a
//! member that only syncs.

use std::collections::BTreeMap;

use cbb_core::certs::sha256;
use cbb_core::identity::ExternalKey;
use cbb_core::records::body::{
    AdminKind, Device, Head, RIGHT_READ, RIGHT_SEND, ROLE_MEMBER, ROLE_PHONE, Removal, Seen,
};
use cbb_core::records::eval::{ChangeState, ConflictKind, Stop};
use cbb_core::records::set::Written;
use cbb_core::records::{Body, GroupId, Key, KeyHash, Kind, List, Record, RecordId, RecordSet, State, group_id};
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

/// The model's group: R made A a phone admin, C a computer admin and W a
/// watch admin; K is the group's recovery key. Each key's records follow
/// on by seq and prev; the lists of K's heads ride beside them.
struct Group {
    root: K,
    heads: BTreeMap<KeyHash, (u64, RecordId)>,
    recs: Vec<Record>,
    lists: Vec<Vec<u8>>,
}

impl Group {
    fn new() -> Group {
        let mut g = Group { root: k("R"), heads: BTreeMap::new(), recs: Vec::new(), lists: Vec::new() };
        for (member, admin, kind) in [
            ("A phone", "A", AdminKind::Phone),
            ("C computer", "C", AdminKind::Computer),
            ("W watch", "W", AdminKind::Watch),
        ] {
            let mut d = Device::new(k(member).key, member, ROLE_PHONE);
            d.rights = RIGHT_READ | RIGHT_SEND;
            d.admin = Some(k(admin).key);
            (d.powers, d.commands) = kind.grants();
            g.sign("R", Kind::device(d));
        }
        g
    }

    fn group(&self) -> GroupId {
        group_id(&self.root.key, &k("K").key)
    }

    /// What the signer's device holds: here, every record so far.
    fn seen(&self) -> Vec<Seen> {
        self.heads.iter().map(|(k, (s, id))| Seen { key: *k, seq: *s, id: *id }).collect()
    }

    fn push(&mut self, r: Record) -> Record {
        let b = r.body();
        let newer = self.heads.get(&b.signer).is_none_or(|(s, _)| b.seq > *s);
        if newer {
            self.heads.insert(b.signer, (b.seq, r.id()));
        }
        self.recs.push(r.clone());
        r
    }

    fn sign(&mut self, by: &str, kind: Kind) -> Record {
        let by = k(by);
        let (seq, prev) = match self.heads.get(&by.hash) {
            Some((s, id)) => (s + 1, Some(*id)),
            None => (1, None),
        };
        let body = Body { group: self.group(), signer: by.hash, seq, prev, time_ms: 0, kind, held: false };
        self.push(Record::sign(body, &by).unwrap())
    }

    /// The signer signs a second record at the seq of its newest one.
    fn sign_twin(&mut self, by: &str, kind: Kind) -> Record {
        let by = k(by);
        let (seq, head) = self.heads[&by.hash];
        let prev = self.recs.iter().find(|r| r.id() == head).and_then(|r| r.body().prev);
        let body = Body { group: self.group(), signer: by.hash, seq, prev, time_ms: 0, kind, held: false };
        let r = Record::sign(body, &by).unwrap();
        self.recs.push(r.clone());
        r
    }

    fn revoke(&mut self, by: &str, key: &str) -> Record {
        let seen = self.seen();
        self.sign(by, Kind::Revoke(Removal { keys: vec![k(key).hash], seen }))
    }

    fn freeze(&mut self, by: &str, key: &str, seen: Vec<Seen>) -> Record {
        self.sign(by, Kind::Freeze(Removal { keys: vec![k(key).hash], seen }))
    }

    fn device(&mut self, by: &str) -> Record {
        let mut d = Device::new(k("D").key, "D", ROLE_MEMBER);
        d.rights = RIGHT_READ | RIGHT_SEND;
        self.sign(by, Kind::device(d))
    }

    /// A checkpoint of the signer: every key's head so far, keeping every
    /// record that counts in state but checkpoints (as the model's).
    fn checkpoint(&mut self, by: &str, state: &State) -> Record {
        let heads = self.heads.iter().map(|(k, (s, id))| Head { key: *k, seq: *s, id: *id }).collect();
        let checkpoints: Vec<RecordId> =
            self.recs.iter().filter(|r| matches!(r.body().kind, Kind::Checkpoint { .. })).map(|r| r.id()).collect();
        let keep = state.counting.iter().copied().filter(|id| !checkpoints.contains(id)).collect();
        self.sign(by, Kind::Checkpoint { heads, keep })
    }

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
        self.sign("R", Kind::device(d))
    }

    fn all(&self) -> Vec<&Record> {
        self.recs.iter().collect()
    }

    /// Member m: a set that took these records in this order, and the
    /// lists beside them, as a sync round does: the records, the lists
    /// their heads name, then the records again (a new root's records wait
    /// for the head's list).
    fn member(&self, recs: &[&Record]) -> RecordSet {
        let mut set = RecordSet::new(self.root.key.clone(), k("K").key);
        take(&mut set, recs, &self.lists);
        set
    }

    /// The recovery key's member changes the root to new_root, holding
    /// only `from`: the writer's first records of the new root, its head
    /// and its list join the group. It unticks `remove`.
    fn change_from(&mut self, from: &[&Record], new_root: &str, remove: &[&str]) -> Written {
        let set = self.member(from);
        let st = set.state();
        let mut d = Device::new(k(&format!("{new_root} phone")).key, "new phone", ROLE_PHONE);
        d.rights = RIGHT_READ | RIGHT_SEND;
        let remove: Vec<KeyHash> = remove.iter().map(|r| k(r).hash).collect();
        let w = set.write_change(&st, &k("K"), &k(new_root), d, &remove, false, 0).unwrap();
        for r in &w.first {
            self.push(r.clone());
        }
        self.push(w.record.clone());
        self.lists.push(w.list.encode());
        w
    }

    /// The change by a writer that holds every record so far.
    fn change(&mut self, new_root: &str) -> Written {
        let all: Vec<Record> = self.recs.clone();
        self.change_from(&all.iter().collect::<Vec<_>>(), new_root, &[])
    }

    /// A head the recovery key signs at seq naming root, with prev the
    /// chain's record before it (or none) and the given list, whatever
    /// the chain holds: for twins, old roots and edited lists. It names a
    /// first checkpoint nobody signed, so it never applies by itself.
    fn head_at(&mut self, seq: u64, root: &str, list: &List) -> Record {
        self.head_naming(seq, root, list, RecordId([0xf1; 32]))
    }

    /// The same, after root signs its first checkpoint (keeping the whole
    /// list, naming the first root's head), which the head names: one
    /// that applies. Returns the head and the checkpoint.
    fn head_applying(&mut self, seq: u64, root: &str, list: &List) -> (Record, Record) {
        let (rs, rid) = self.heads[&k("R").hash];
        let first = self.sign(
            root,
            Kind::Checkpoint { heads: vec![Head { key: k("R").hash, seq: rs, id: rid }], keep: list.0.clone() },
        );
        (self.head_naming(seq, root, list, first.id()), first)
    }

    fn head_naming(&mut self, seq: u64, root: &str, list: &List, first: RecordId) -> Record {
        let prev = self.recs.iter().find(|r| r.body().signer == k("K").hash && r.body().seq + 1 == seq).map(|r| r.id());
        let kind = Kind::Recovery { root: k(root).key, list: list.hash(), from: 0, first };
        let body = Body { group: self.group(), signer: k("K").hash, seq, prev, time_ms: 0, kind, held: false };
        let r = Record::sign(body, &k("K")).unwrap();
        self.lists.push(list.encode());
        self.push(r)
    }
}

/// One sync round of a set: records, lists, records.
fn take(set: &mut RecordSet, recs: &[&Record], lists: &[Vec<u8>]) {
    set.insert_all(recs.iter().map(|r| (*r).clone()));
    for l in lists {
        let _ = set.insert_list(l);
    }
    set.insert_all(recs.iter().map(|r| (*r).clone()));
}

fn roots(names: &[&str]) -> Vec<KeyHash> {
    names.iter().map(|n| k(n).hash).collect()
}

fn has(s: &State, member: &str) -> bool {
    s.device_by_key(&k(member).hash).is_some()
}

/// Stopped for good: two heads at one seq, and no admin's commands run.
fn stopped_for_good(s: &State) -> bool {
    s.stop == Stop::Full
        && s.conflicts.iter().any(|c| c.kind == ConflictKind::Fork)
        && ["A", "C", "W"].iter().all(|n| !s.may_command(&k(n).hash))
}

/// recoveryChangesRootTest: the recovery key changes the root; a member
/// that holds the head and its list follows it at once, and the admins
/// the first root named stay.
#[test]
fn the_recovery_key_changes_the_root() {
    let mut g = Group::new();
    let w = g.change("NK");
    assert_eq!(w.list.0.len(), 3);
    let s = g.member(&g.all()).state();
    assert_eq!(s.roots, roots(&["R", "NK"]));
    assert_eq!(s.changes.len(), 1);
    assert_eq!(s.changes[0].state, ChangeState::Effective);
    assert!(["A", "C", "W", "NK"].iter().all(|n| s.may_command(&k(n).hash)));
    assert!(!s.may_command(&k("R").hash));
}

/// recoveryUntouchableTest: neither the root's removal nor the phone
/// admin's freeze of the recovery key touches it.
#[test]
fn nothing_touches_the_recovery_key() {
    let mut g = Group::new();
    g.revoke("R", "K");
    let seen = g.seen();
    g.freeze("A", "K", seen);
    g.change("NK");
    let s = g.member(&g.all()).state();
    assert_eq!(s.roots, roots(&["R", "NK"]));
}

/// oldKeyNotValidTest: a head naming a key that was a root before
/// changes nothing and does not stop the group.
#[test]
fn a_head_naming_an_earlier_root_changes_nothing() {
    let mut g = Group::new();
    let all: Vec<RecordId> = g.recs.iter().map(|r| r.id()).collect();
    let mut all = all;
    all.sort();
    g.head_at(1, "R", &List(all));
    let s = g.member(&g.all()).state();
    assert_eq!(s.roots, roots(&["R"]));
    assert_eq!(s.stop, Stop::None);
}

/// removedDeviceStaysOutTest: a new record for a removed device's key does
/// not bring it back.
#[test]
fn a_removed_device_stays_out() {
    let mut g = Group::new();
    g.device("R");
    g.revoke("R", "D");
    g.device("R");
    let s = g.member(&g.all()).state();
    assert!(s.revoked.contains(&k("D").hash));
    assert!(!has(&s, "D"));
    assert!(s.id_taken(&k("D").key.device_id()));
}

/// removalsByAdminAndRootTest: the root's resolve voids an admin's removal,
/// and the device counts again under its old key and ID; a root's removal is
/// final, and its resolve changes nothing.
#[test]
fn an_admins_removal_is_not_final_a_roots_is() {
    let mut g = Group::new();
    g.device("C");
    let rm = g.revoke("C", "D");
    let s = g.member(&g.all()).state();
    assert!(!has(&s, "D") && s.revoked.contains(&k("D").hash));
    g.sign("R", Kind::Resolve(vec![rm.id()]));
    let s = g.member(&g.all()).state();
    let d = s.device_by_key(&k("D").hash).expect("the device counts again");
    assert_eq!(d.id, k("D").key.device_id());
    assert!(!s.revoked.contains(&k("D").hash) && !s.counting.contains(&rm.id()));
    let root_rm = g.revoke("R", "D");
    g.sign("R", Kind::Resolve(vec![root_rm.id()]));
    let s = g.member(&g.all()).state();
    assert!(!has(&s, "D") && s.revoked.contains(&k("D").hash));
}

/// ownKeyFreezesTest: two freezes a watch admin signs of its own key do not
/// stop the group.
#[test]
fn freezes_of_ones_own_key_do_not_stop_the_group() {
    let mut g = Group::new();
    g.freeze("W", "W", Vec::new());
    g.freeze("W", "W", Vec::new());
    let s = g.member(&g.all()).state();
    assert_eq!(s.stop, Stop::None);
    assert!(s.may_command(&k("A").hash));
    assert!(!s.may_command(&k("W").hash));
}

/// bothKeysRemovedTest: a removal of an admin's member key removes its
/// admin key; its later removal, unseen by the root's, does not count.
#[test]
fn a_removal_of_the_member_key_removes_the_admin_key() {
    let mut g = Group::new();
    g.revoke("R", "A phone");
    g.revoke("A", "C");
    let s = g.member(&g.all()).state();
    assert!(s.revoked.contains(&k("A").hash));
    assert!(!s.may_command(&k("A").hash));
    assert!(!s.revoked.contains(&k("C").hash));
}

/// removedAdminThiefTest: a thief with the removed phone admin's key gains
/// nothing, before or after a change of root.
#[test]
fn a_removed_admins_thief_gains_nothing() {
    let mut g = Group::new();
    g.revoke("R", "A");
    g.revoke("A", "C");
    g.freeze("A", "W", Vec::new());
    g.device("A");
    let check = |s: &State| {
        assert!(!s.may_command(&k("A").hash) && s.may_command(&k("C").hash) && s.may_command(&k("W").hash));
        assert!(!has(s, "D"));
        assert!(!s.devices.iter().any(|d| d.frozen));
    };
    check(&g.member(&g.all()).state());
    g.change("NK");
    let s = g.member(&g.all()).state();
    assert_eq!(s.roots, roots(&["R", "NK"]));
    assert!(s.revoked.contains(&k("A").hash));
    check(&s);
}

/// oldRootResolveStaysTest: what the old root resolved stays resolved after
/// a change of root, when the writer held it.
#[test]
fn an_old_roots_resolve_stays_after_a_change() {
    let mut g = Group::new();
    g.device("C");
    let rm = g.revoke("C", "D");
    g.sign("R", Kind::Resolve(vec![rm.id()]));
    g.change("NK");
    let s = g.member(&g.all()).state();
    assert_eq!(s.roots, roots(&["R", "NK"]));
    assert!(has(&s, "D"));
}

/// oldRootThiefTest: a thief with the old root key after the change
/// removes a device, names an admin and forks a record: none is on the
/// list, so none counts, and a member keeps none.
#[test]
fn an_old_roots_thief_counts_nowhere() {
    let mut g = Group::new();
    g.device("R");
    g.change("NK");
    let mut m = g.member(&g.all());
    let s = m.state();
    assert_eq!(s.roots, roots(&["R", "NK"]));
    assert!(has(&s, "D"));
    let rm = g.revoke("R", "D");
    let mut d = Device::new(k("X phone").key, "X phone", ROLE_PHONE);
    d.rights = RIGHT_READ | RIGHT_SEND;
    d.admin = Some(k("X").key);
    (d.powers, d.commands) = AdminKind::Phone.grants();
    let admin = g.sign("R", Kind::device(d));
    let twin = g.sign_twin("R", Kind::Revoke(Removal { keys: vec![k("D").hash], seen: g.seen() }));
    take(&mut m, &[&rm, &admin, &twin], &g.lists);
    for r in [&rm, &admin, &twin] {
        assert!(!m.contains(&r.id()));
    }
    let s = m.state();
    assert!(has(&s, "D") && !s.may_command(&k("X").hash));
    let s = g.member(&g.all()).state();
    assert!(has(&s, "D") && !s.may_command(&k("X").hash));
}

/// unlistedRootRemovalTest: a removal by the old root the writer did not
/// hold is not on the list: after the change it counts no more and the
/// device returns, on a member that had applied it too.
#[test]
fn a_removal_the_writer_lacked_is_gone() {
    let mut g = Group::new();
    g.device("R");
    let held: Vec<Record> = g.recs.clone();
    g.revoke("R", "D");
    let mut c = g.member(&g.all());
    assert!(!has(&c.state(), "D"));
    g.change_from(&held.iter().collect::<Vec<_>>(), "NK", &[]);
    take(&mut c, &g.all(), &g.lists);
    let s = c.state();
    assert_eq!(s.roots, roots(&["R", "NK"]));
    assert!(has(&s, "D"));
}

/// mintedKeyTest: a key a root not yet on the path names teaches nothing:
/// its records are not kept until a head makes that root the root.
#[test]
fn a_key_a_root_off_the_path_names_teaches_nothing() {
    let mut g = Group::new();
    let mut d = Device::new(k("X computer").key, "X computer", ROLE_PHONE);
    d.rights = RIGHT_READ | RIGHT_SEND;
    d.admin = Some(k("X").key);
    (d.powers, d.commands) = AdminKind::Computer.grants();
    let named = g.sign("NA", Kind::device(d));
    let x = g.device("X");
    let mut m = g.member(&g.all());
    assert!(!m.contains(&x.id()));
    let s = m.state();
    assert!(!has(&s, "D") && !s.may_command(&k("X").hash));
    let list = List({
        let mut ids: Vec<RecordId> = g.recs.iter().filter(|r| r.body().signer == k("R").hash).map(|r| r.id()).collect();
        ids.sort();
        ids
    });
    let (head, first) = g.head_applying(1, "NA", &list);
    take(&mut m, &[&head, &first, &named, &x], &g.lists);
    let s = m.state();
    assert_eq!(s.roots, roots(&["R", "NA"]));
    assert!(s.may_command(&k("X").hash) && has(&s, "D"));
}

/// checkpointTest: the root's checkpoint gives the state on a member that
/// compacted on it.
#[test]
fn the_roots_checkpoint_gives_the_state() {
    let mut g = Group::new();
    g.device("R");
    let s = g.member(&g.all()).state();
    let cp = g.checkpoint("R", &s);
    let mut m = g.member(&g.all());
    let s = m.state();
    assert_eq!(s.checkpoint, Some(cp.id()));
    assert!(has(&s, "D"));
    m.compact(&s);
    let s = m.state();
    assert_eq!(s.checkpoint, Some(cp.id()));
    assert!(has(&s, "D") && s.may_command(&k("A").hash));
}

/// demotedAdminTest: the root takes the admin key off A's device; what A
/// signs after, unseen by that record, does not count.
#[test]
fn an_admin_key_the_root_took_off_signs_nothing() {
    let mut g = Group::new();
    g.admin_again("A phone", None);
    g.revoke("A", "C");
    let s = g.member(&g.all()).state();
    assert!(!s.revoked.contains(&k("C").hash));
    assert!(!s.may_command(&k("A").hash));
}

/// replacedAdminKeyTest: the root names another admin key for C's device:
/// C's later record does not count, the new key's does.
#[test]
fn an_admin_key_the_root_replaced_signs_nothing() {
    let mut g = Group::new();
    g.admin_again("C computer", Some(("C2", AdminKind::Computer)));
    g.device("C");
    let s = g.member(&g.all()).state();
    assert!(!has(&s, "D"));
    assert!(s.may_command(&k("C2").hash) && !s.may_command(&k("C").hash));
    g.device("C2");
    let s = g.member(&g.all()).state();
    assert!(has(&s, "D"));
}

/// secondChangeTest: a second change of root under NK. A member that holds
/// the second head alone follows nothing yet; with the first it follows
/// both, and what NK signed counts.
#[test]
fn a_second_change_of_root() {
    let mut g = Group::new();
    let first = g.change("NK");
    g.device("NK");
    let w = g.change("NA");
    let second: Vec<&Record> = w.first.iter().chain([&w.record]).collect();
    let s = g.member(&second).state();
    assert_eq!(s.roots, roots(&["R"]));
    let s = g.member(&g.all()).state();
    assert_eq!(s.roots, roots(&["R", "NK", "NA"]));
    assert!(has(&s, "D") && s.may_command(&k("A").hash));
    assert!(w.list.0.len() > first.list.0.len());
}

/// recoveryTwinStopsTest: two heads at one seq stop every member that
/// holds both for good, the root's commands included.
#[test]
fn two_heads_at_one_seq_stop_the_group_for_good() {
    let mut g = Group::new();
    let w = g.change("NK");
    let s = g.member(&g.all()).state();
    assert_eq!(s.roots, roots(&["R", "NK"]));
    g.head_at(1, "NA", &w.list);
    let s = g.member(&g.all()).state();
    assert!(stopped_for_good(&s));
    assert_eq!(s.changes.iter().filter(|c| c.state == ChangeState::Competing).count(), 2);
}

/// After a fork nothing commands and nothing acts, at seq 1 (where the
/// path before the fork ends at the first root) and at depth: no root, no
/// admin, no admission; a record the old root signs after does not make
/// it command. The state shows the chain below the fork and what the list
/// applied there names: at depth the first root's listed devices, at seq 1
/// the first root alone.
#[test]
fn after_a_fork_nobody_commands() {
    use cbb_core::join::decide::{Signer, may_admit};
    for depth in [1u64, 2] {
        let mut g = Group::new();
        let w = g.change("NK");
        let list = if depth == 2 { g.change("NA").list } else { w.list };
        g.head_at(depth, "X", &list);
        let last = if depth == 2 { "NK" } else { "R" };
        g.device(last);
        let s = g.member(&g.all()).state();
        assert!(stopped_for_good(&s) && s.halted(), "depth {depth}");
        for n in ["R", "NK", "NA", "X", "A", "C", "W"] {
            assert!(!s.may_command(&k(n).hash), "depth {depth}: {n} commands");
        }
        assert!(!may_admit(&s, &k(last).hash, Signer::Root, &k(last).hash), "depth {depth}");
        assert!(!may_admit(&s, &k("A phone").hash, Signer::Admin, &k(last).hash), "depth {depth}");
        let shown = has(&s, "A phone") && has(&s, "C computer") && has(&s, "W watch");
        assert_eq!(shown, depth == 2, "depth {depth}");
        assert!(!has(&s, "D"), "depth {depth}");
    }
}

/// deepTwinStopsTest: after two changes, a head at seq 1 naming another
/// root stops every member for good.
#[test]
fn a_twin_deep_in_the_chain_stops_the_group_for_good() {
    let mut g = Group::new();
    let w = g.change("NK");
    g.change("NA");
    assert_eq!(g.member(&g.all()).state().roots, roots(&["R", "NK", "NA"]));
    g.head_at(1, "NA", &w.list);
    assert!(stopped_for_good(&g.member(&g.all()).state()));
}

/// invalidForkStopsTest: a fork may be two heads of which one is not
/// valid (it names an earlier root): any two heads at one seq stop the
/// group for good.
#[test]
fn a_fork_with_an_invalid_head_stops_the_group_for_good() {
    let mut g = Group::new();
    let w = g.change("NK");
    g.head_at(1, "R", &w.list);
    assert!(stopped_for_good(&g.member(&g.all()).state()));
}

/// removedDeviceFollowsTest: a thief with the old root key removes D after
/// the change; m gets that removal before the head. It still takes the
/// head and follows the new root, and D counts again there.
#[test]
fn a_member_that_took_the_thiefs_removal_follows_the_head() {
    let mut g = Group::new();
    g.device("R");
    let w = g.change("NK");
    let rm = g.revoke("R", "D");
    let before: Vec<&Record> = g.recs.iter().filter(|r| !w.first.contains(r) && r.id() != w.record.id()).collect();
    let mut m = g.member(&before);
    assert!(m.contains(&rm.id()) && !has(&m.state(), "D"));
    take(&mut m, &g.all(), &g.lists);
    let s = m.state();
    assert_eq!(s.roots, roots(&["R", "NK"]));
    assert!(has(&s, "D"));
}

/// untickTest: the owner unticks the computer admin: the new root signs
/// its removal in the same act. The root's earlier removal of the watch
/// admin is on the list and stays.
#[test]
fn the_owner_unticks_an_admin() {
    let mut g = Group::new();
    g.revoke("R", "W");
    let all: Vec<Record> = g.recs.clone();
    g.change_from(&all.iter().collect::<Vec<_>>(), "NK", &["C"]);
    let s = g.member(&g.all()).state();
    assert_eq!(s.roots, roots(&["R", "NK"]));
    assert!(s.may_command(&k("A").hash));
    assert!(!s.may_command(&k("C").hash) && !s.may_command(&k("W").hash));
    assert!(s.revoked.contains(&k("W").hash));
}

/// literalListTest: why the list holds what the writer counts of every
/// earlier root: a second head whose list names only what NK signed
/// leaves the first root's admins off the newest list, so they are gone.
#[test]
fn a_list_of_the_replaced_root_alone_drops_the_first_roots_admins() {
    let mut g = Group::new();
    g.change("NK");
    let mut nk: Vec<RecordId> = g.recs.iter().filter(|r| r.body().signer == k("NK").hash).map(|r| r.id()).collect();
    nk.sort();
    g.head_applying(2, "NA", &List(nk));
    let s = g.member(&g.all()).state();
    assert_eq!(s.roots, roots(&["R", "NK", "NA"]));
    assert!(["A", "C", "W"].iter().all(|n| !s.may_command(&k(n).hash)));
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
        let s = g.member(&g.all()).state();
        assert!(s.may_command(&k("C").hash), "saw {saw}");
        assert_eq!(has(&s, "D"), saw, "saw {saw}");
    }
}

/// thawedAdminWorksTest: what the thawed key signs after the thaw, listing
/// it in seen, counts.
#[test]
fn a_thawed_admin_works() {
    let mut g = Group::new();
    let seen = g.seen();
    let f = g.freeze("A", "C", seen);
    let seen = g.seen();
    g.sign("R", Kind::Thaw { ids: vec![f.id()], seen });
    let mut d = Device::new(k("D").key, "D", ROLE_MEMBER);
    d.rights = RIGHT_READ | RIGHT_SEND;
    d.seen = g.seen();
    g.sign("C", Kind::device(d));
    let s = g.member(&g.all()).state();
    assert!(s.may_command(&k("C").hash) && has(&s, "D"));
}

/// fullRoomAfterChangeTest: after a change of root other keys fill the
/// room; the change stays, since the head is outside the rooms.
#[test]
fn a_full_room_after_a_change_keeps_it() {
    let mut g = Group::new();
    let w = g.change("NK");
    for by in ["A", "C", "W", "NK"] {
        for _ in 0..300 {
            g.sign(by, Kind::Copies { incoming_ms: 5_000, seen: vec![] });
        }
    }
    let m = g.member(&g.all());
    assert!(m.contains(&w.record.id()));
    assert_eq!(m.state().roots, roots(&["R", "NK"]));
}

/// The model's first promise on one case: members that got the same
/// records in other orders keep the same set and have the same state,
/// across two changes of root.
#[test]
fn any_order_gives_one_state() {
    let mut g = Group::new();
    g.device("C");
    g.revoke("R", "D");
    g.change("NK");
    g.sign("NK", Kind::Copies { incoming_ms: 5_000, seen: vec![] });
    g.freeze("W", "C", Vec::new());
    g.change("NA");
    let all = g.all();
    let mut rev = all.clone();
    rev.reverse();
    let mut odd: Vec<&Record> = all.iter().copied().skip(1).step_by(2).collect();
    odd.extend(all.iter().copied().step_by(2));
    let sets: Vec<RecordSet> = [all, rev, odd].iter().map(|order| g.member(order)).collect();
    assert_eq!(sets[0].state().roots, roots(&["R", "NK", "NA"]));
    for s in &sets[1..] {
        assert_eq!(s.digest(), sets[0].digest());
        assert_eq!(s.state(), sets[0].state());
    }
}

/// compactedAgree's trace, by the room: two members take the same records,
/// one compacts on the new root's newest checkpoint and one does not; the
/// newest checkpoint prunes an older one of the same root, and a counting
/// checkpoint compacts as it comes. As the new root fills its room, both
/// keep the same records and have the same state.
#[test]
fn compacting_on_the_roots_checkpoint_changes_nothing() {
    let mut g = Group::new();
    g.change("NK");
    let s = g.member(&g.all()).state();
    let older = g.checkpoint("NK", &s);
    for _ in 0..900 {
        g.sign("NK", Kind::Copies { incoming_ms: 5_000, seen: vec![] });
    }
    let s = g.member(&g.all()).state();
    let newest = g.checkpoint("NK", &s);
    let mut a = g.member(&g.all());
    let mut b = g.member(&g.all());
    let st = a.state();
    assert_eq!(st.checkpoint, Some(newest.id()));
    a.compact(&st);
    // The newest checkpoint compacted both when it came: compacting again
    // changes nothing.
    assert!(!a.contains(&older.id()) && !b.contains(&older.id()), "the checkpoint compacts as it counts");
    assert_eq!(a.digest(), b.digest());
    let mut dropped = 0;
    for i in 0..400 {
        let r = g.sign("NK", Kind::Copies { incoming_ms: 5_000, seen: vec![] });
        a.insert(r.clone()).unwrap();
        b.insert(r.clone()).unwrap();
        assert_eq!(a.contains(&r.id()), b.contains(&r.id()), "record {i} after the checkpoint");
        assert_eq!(a.state(), b.state(), "state after record {i}");
        dropped += usize::from(!a.contains(&r.id()));
    }
    assert!(dropped > 0, "the room filled");
}
