// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The epoch of device records (section 10): a root's checkpoint that
//! leaves a removal out moves `drops`; a device record of an older epoch
//! counts only where the counting checkpoint or the change's list keeps
//! it, so a record signed without knowing of the removal never brings the
//! removed device back.

use super::*;
use alloc::collections::BTreeSet;

fn has(s: &State, member: &K) -> bool {
    s.device_by_key(&member.hash).is_some()
}

/// The root admits d and removes it, and an admin admits x; when
/// `admin_first`, the admin also signs a record of its own before. The
/// admin's record for d is signed (at the epoch before the removal goes)
/// but reaches the root's writer only after the root's checkpoint left the
/// removal out. Returns the group, the admin's late record, and the
/// records the writer held.
fn late_record(admin_first: bool) -> (G, Record, Vec<Record>) {
    let mut g = G::new();
    let root = k("root");
    let (pa, a) = (k("phone a"), k("admin a"));
    g.admin(&pa, &a, POWER_ADMIT | POWER_MANAGE | POWER_REMOVE);
    if admin_first {
        g.device(&a, &k("x"), "x", |_| {});
    }
    g.device(&root, &k("d"), "d", |_| {});
    let late = g.device(&a, &k("d"), "d renamed", |_| {});
    let mut mine: Vec<Record> = g.recs.iter().filter(|r| r.id() != late.id()).cloned().collect();
    let mut set = set_with(&g.root.key, &mine, &g.lists);
    let st = set.state();
    for r in set.write_removal(&st, &root, &[k("d").hash], 0).unwrap() {
        mine.push(g.push(r));
    }
    mine.push(g.device(&root, &k("tv"), "tv", |_| {}));
    mine.push(root_checkpoint(&mut g, &mine));
    (g, late, mine)
}

/// The checkpoint leaves the removal out and moves the epoch; the admin's
/// late record, of the older epoch and kept by nothing, counts neither
/// at the writer nor in the evaluation of all records, and the state
/// names it for the admin's app.
fn a_late_record_brings_no_removed_device_back(admin_first: bool) {
    let (g, late, mine) = late_record(admin_first);
    let mut set = set_with(&g.root.key, &mine, &g.lists);
    let st = set.state();
    assert!(st.checkpoint.is_some_and(|c| mine.last().is_some_and(|r| r.id() == c)));
    assert_eq!(st.drops, 1, "the checkpoint left a removal out");
    assert!(!has(&st, &k("d")));
    let _ = set.insert(late.clone());
    let st = set.state();
    assert!(!has(&st, &k("d")), "the removed device stays removed at the writer");
    let whole = g.state();
    assert!(!has(&whole, &k("d")), "and in the evaluation of every record");
    assert!(whole.stale.contains(&late.id()), "the notice names the record");
    if set.contains(&late.id()) {
        assert!(st.stale.contains(&late.id()), "the notice names the record");
    }
}

#[test]
fn a_late_record_without_a_head_brings_no_removed_device_back() {
    let _drop = crate::records::set::drop_settled();
    a_late_record_brings_no_removed_device_back(false);
}

#[test]
fn a_late_record_above_its_signers_head_brings_no_removed_device_back() {
    let _drop = crate::records::set::drop_settled();
    a_late_record_brings_no_removed_device_back(true);
}

/// The same across a change of root: the writer of the change held the
/// removal, which its list leaves out, and the new root's first
/// checkpoint moves the epoch; the admin's late record counts nowhere.
#[test]
fn a_late_record_brings_no_removed_device_back_across_a_change_of_root() {
    let _drop = crate::records::set::drop_settled();
    let mut g = G::new();
    let root = k("root");
    let (pa, a) = (k("phone a"), k("admin a"));
    g.admin(&pa, &a, POWER_ADMIT | POWER_MANAGE | POWER_REMOVE);
    g.device(&root, &k("d"), "d", |_| {});
    let late = g.device(&a, &k("d"), "d renamed", |_| {});
    let mine: Vec<Record> = g.recs.iter().filter(|r| r.id() != late.id()).cloned().collect();
    let mut set = set_with(&g.root.key, &mine, &g.lists);
    let st = set.state();
    let mut mine = mine;
    for r in set.write_removal(&st, &root, &[k("d").hash], 0).unwrap() {
        mine.push(g.push(r));
    }
    mine.push(g.device(&root, &k("tv"), "tv", |_| {}));
    let mut writer = set_with(&g.root.key, &mine, &g.lists);
    let st = writer.state();
    let mut phone = Device::new(k("phone 1").key.clone(), "new phone", ROLE_PHONE);
    phone.rights = RIGHT_READ | RIGHT_SEND | RIGHT_SECRETS;
    let w = writer.write_change(&st, &k("recovery"), crate::testkit::rk2(), &k("n1"), phone, &[], false, 0).unwrap();
    for r in &w.first {
        g.push(r.clone());
    }
    g.push(w.record.clone());
    g.lists.push(w.list.encode());
    let mut m = set_of(&g.root.key);
    let without: Vec<Record> = g.recs.iter().filter(|r| r.id() != late.id()).cloned().collect();
    sync_all(&mut m, &without, &g.lists);
    assert_eq!(m.state().roots.last(), Some(&k("n1").hash));
    assert!(!has(&m.state(), &k("d")));
    let _ = m.insert(late.clone());
    assert!(!has(&m.state(), &k("d")), "the removed device stays removed");
    assert!(!has(&set_with(&g.root.key, &g.recs, &g.lists).state(), &k("d")));
    assert!(!has(&g.state(), &k("d")), "and in the evaluation of every record");
}

/// An admin's admission signed at the current epoch, after the checkpoint
/// that moved it, counts as any other: the epoch bars only what was
/// signed before.
#[test]
fn an_admission_at_the_current_epoch_counts() {
    let _drop = crate::records::set::drop_settled();
    let (mut g, late, mine) = late_record(false);
    let set = set_with(&g.root.key, &mine, &g.lists);
    assert_eq!(set.state().drops, 1);
    let a = k("admin a");
    let fresh = g.device(&a, &k("d"), "d again", |_| {});
    assert!(matches!(&fresh.body().kind, Kind::Device(d) if d.epoch == 1));
    // The admin's chain runs through its late record, which stays held
    // and is named in the notice; the new admission counts.
    let st = set_with(&g.root.key, &g.recs, &g.lists).state();
    assert!(has(&st, &k("d")), "a user admitted it again");
    assert_eq!(st.stale, vec![late.id()]);
    assert_eq!(g.state(), st);
}

/// The set's own writer signs device records at the epoch it holds.
#[test]
fn the_writer_signs_at_the_epoch_it_holds() {
    let _drop = crate::records::set::drop_settled();
    let (g, _, mine) = late_record(false);
    let mut set = set_with(&g.root.key, &mine, &g.lists);
    let st = set.state();
    let mut d = Device::new(k("lamp").key.clone(), "lamp", ROLE_MEMBER);
    d.rights = RIGHT_READ;
    let r = set.write_record(&st, &k("root"), Kind::device(d), 0).unwrap();
    assert!(matches!(&r.body().kind, Kind::Device(d) if d.epoch == st.drops && d.epoch == 1));
    assert!(has(&set.state(), &k("lamp")));
}

/// An admin's admission of the older epoch that the root's checkpoint
/// keeps still counts: the checkpoint is what an older record needs.
#[test]
fn an_older_admission_the_checkpoint_keeps_counts() {
    let _drop = crate::records::set::drop_settled();
    let (g, _, mine) = late_record(true);
    let st = set_with(&g.root.key, &mine, &g.lists).state();
    assert_eq!(st.drops, 1);
    assert!(has(&st, &k("x")), "the admin's admission before the epoch moved");
    assert!(st.stale.is_empty());
}

/// Two members, one that took the late record before the checkpoint and
/// one after it, end alike, in both orders.
#[test]
fn both_orders_end_alike_with_a_late_record() {
    let _drop = crate::records::set::drop_settled();
    for admin_first in [false, true] {
        let (g, late, mine) = late_record(admin_first);
        let mut early = set_of(&g.root.key);
        let mut before: Vec<Record> = mine[..mine.len() - 1].to_vec();
        before.push(late.clone());
        sync_all(&mut early, &before, &g.lists);
        sync_all(&mut early, &mine, &g.lists);
        let mut after = set_of(&g.root.key);
        sync_all(&mut after, &mine, &g.lists);
        let _ = after.insert(late.clone());
        sync_all(&mut after, &early.in_dependency_order().into_iter().cloned().collect::<Vec<_>>(), &g.lists);
        sync_all(&mut early, &after.in_dependency_order().into_iter().cloned().collect::<Vec<_>>(), &g.lists);
        assert_eq!(early.state(), after.state(), "admin_first {admin_first}");
        assert_eq!(early.digest(), after.digest(), "admin_first {admin_first}");
        assert!(!has(&early.state(), &k("d")));
        let held: BTreeSet<RecordId> = early.in_dependency_order().into_iter().map(Record::id).collect();
        assert!(held.iter().all(|id| after.contains(id)));
    }
}

/// A checkpoint that leaves no removal out keeps the epoch.
#[test]
fn a_checkpoint_that_drops_no_removal_keeps_the_epoch() {
    let mut g = G::new();
    let root = k("root");
    g.device(&root, &k("laptop"), "laptop", |_| {});
    let recs = g.recs.clone();
    let cp = root_checkpoint(&mut g, &recs);
    assert!(matches!(&cp.body().kind, Kind::Checkpoint { drops: 0, .. }));
    assert_eq!(g.state().drops, 0);
}

/// `drops` and `epoch` at their default are left out of the encoding, and
/// a written 0 breaks `form/default`; other values round-trip.
#[test]
fn drops_and_epoch_round_trip() {
    let mut g = G::new();
    let root = k("root");
    let mut d = Device::new(k("lamp").key.clone(), "lamp", ROLE_MEMBER);
    d.epoch = 3;
    let r = g.rec(&root, Kind::device(d));
    let back = Record::decode(&r.envelope()).unwrap();
    assert!(matches!(&back.body().kind, Kind::Device(d) if d.epoch == 3));
    let (seq, id) = g.heads[&root.hash];
    let cp = g.root_rec(Kind::Checkpoint { heads: vec![Head { key: root.hash, seq, id }], keep: vec![], drops: 2 });
    let back = Record::decode(&cp.envelope()).unwrap();
    assert!(matches!(&back.body().kind, Kind::Checkpoint { drops: 2, .. }));
}

/// A writer's change of root by a set of `from`, making `new_root` the
/// root on a new phone `member`; g takes its first records, head and list.
fn change(g: &mut G, from: &[Record], new_root: &K, member: &str) {
    let mut writer = set_with(&g.root.key, from, &g.lists);
    let st = writer.state();
    let mut phone = Device::new(k(member).key.clone(), member, ROLE_PHONE);
    phone.rights = RIGHT_READ | RIGHT_SEND | RIGHT_SECRETS;
    let w = writer.write_change(&st, &k("recovery"), crate::testkit::rk2(), new_root, phone, &[], false, 0).unwrap();
    for r in &w.first {
        g.push(r.clone());
    }
    g.push(w.record.clone());
    g.lists.push(w.list.encode());
}

/// Two admissions and two changes: the root admits d, and an admin's
/// record for d reaches one member only; the root removes d; a change
/// makes nk the root, whose checkpoint leaves the removal out; a second
/// change, written on a device that holds nk's checkpoint and the admin's
/// record, makes na the root. The admin's record is of the epoch before
/// nk's checkpoint and nothing keeps it: the second writer neither lists
/// it nor keeps it, and d stays out at every member.
#[test]
fn an_old_admission_stays_out_across_two_changes() {
    let _drop = crate::records::set::drop_settled();
    let mut g = G::new();
    let root = k("root");
    let (pa, a) = (k("phone a"), k("admin a"));
    g.admin(&pa, &a, POWER_ADMIT | POWER_MANAGE | POWER_REMOVE);
    g.device(&root, &k("d"), "d", |_| {});
    let late = g.device(&a, &k("d"), "d renamed", |_| {});
    let without = |g: &G| -> Vec<Record> { g.recs.iter().filter(|r| r.id() != late.id()).cloned().collect() };
    let mut set = set_with(&g.root.key, &without(&g), &g.lists);
    let st = set.state();
    for r in set.write_removal(&st, &root, &[k("d").hash], 0).unwrap() {
        g.push(r);
    }
    g.device(&root, &k("tv"), "tv", |_| {});
    let nk = k("nk");
    let from = without(&g);
    change(&mut g, &from, &nk, "phone nk");
    let held = set_with(&g.root.key, &without(&g), &g.lists);
    let cp = held.write_checkpoint(&held.state(), &nk, 0).unwrap();
    assert!(matches!(&cp.body().kind, Kind::Checkpoint { drops, .. } if *drops >= 1));
    g.push(cp);
    // The second writer holds nk's checkpoint and the admin's record.
    let all = g.recs.clone();
    let st = set_with(&g.root.key, &all, &g.lists).state();
    assert!(st.stale.contains(&late.id()) && !has(&st, &k("d")));
    change(&mut g, &all, &k("na"), "phone na");
    let list = List::decode(g.lists.last().unwrap()).unwrap();
    assert!(!list.0.contains(&late.id()), "the writer lists no old record that does not count");
    for keep_late in [true, false] {
        let recs: Vec<Record> = if keep_late { g.recs.clone() } else { without(&g) };
        let mut m = set_of(&g.root.key);
        sync_all(&mut m, &recs, &g.lists);
        let st = m.state();
        assert_eq!(st.roots.last(), Some(&k("na").hash), "keep_late {keep_late}");
        assert!(!has(&st, &k("d")), "keep_late {keep_late}: d stays out");
        let _ = m.insert(late.clone());
        assert!(!has(&m.state(), &k("d")), "keep_late {keep_late}: d stays out after the record comes");
    }
    assert!(!has(&g.state(), &k("d")), "and in the evaluation of every record");
}

/// A checkpoint that keeps a device record of an older epoch that does not
/// count would bring it back: the check the writer runs refuses it.
#[test]
fn keeping_an_old_record_that_does_not_count_is_refused() {
    let _drop = crate::records::set::drop_settled();
    let (g, late, mine) = late_record(false);
    let mut recs = mine.clone();
    recs.push(late.clone());
    let set = set_with(&g.root.key, &recs, &g.lists);
    let st = set.state();
    assert!(st.stale.contains(&late.id()));
    let held: Vec<(&Record, crate::records::eval::Role)> = set
        .ids()
        .filter_map(|id| set.get(id))
        .map(|r| {
            let role = if r.body().signer == k("root").hash {
                crate::records::eval::Role::Root
            } else {
                crate::records::eval::Role::Admin
            };
            (r, role)
        })
        .collect();
    let cp = set.write_checkpoint(&st, &k("root"), 0).unwrap();
    let Kind::Checkpoint { heads, keep, .. } = &cp.body().kind else { unreachable!() };
    assert!(!keep.contains(&late.id()), "the writer keeps no old record that does not count");
    let counts = |id: &RecordId| st.counting.contains(id);
    assert!(!crate::records::eval::revives(heads, keep, st.drops, held.iter().copied(), counts));
    let mut with = keep.clone();
    with.push(late.id());
    with.sort();
    assert!(crate::records::eval::revives(heads, &with, st.drops, held.iter().copied(), counts));
}

/// The writer leaves a settled removal in while the root's room has space:
/// the epoch stays, and an admin's admission signed before counts on.
#[test]
fn a_settled_removal_stays_while_the_room_has_space() {
    let mut g = G::new();
    let root = k("root");
    let (pa, a) = (k("phone a"), k("admin a"));
    g.admin(&pa, &a, POWER_ADMIT);
    g.device(&root, &k("d"), "d", |_| {});
    let rv = g.root_rec(Kind::Revoke(removal(&[k("d").hash], g.seen())));
    g.device(&root, &k("tv"), "tv", |_| {});
    let recs = g.recs.clone();
    let cp = root_checkpoint(&mut g, &recs);
    let Kind::Checkpoint { keep, drops, .. } = &cp.body().kind else { unreachable!() };
    assert_eq!(*drops, 0);
    assert!(keep.contains(&rv.id()), "the removal stays");
    let x = g.device(&a, &k("x"), "x", |_| {});
    assert!(matches!(&x.body().kind, Kind::Device(d) if d.epoch == 0));
    let st = set_with(&g.root.key, &g.recs, &g.lists).state();
    assert!(has(&st, &k("x")) && !has(&st, &k("d")) && st.stale.is_empty());
}

/// In small rooms the root's room asks: past three quarters of its cap the
/// writer leaves out its settled removals, the oldest first, until the
/// room is at most half full, and the epoch moves once.
#[test]
fn a_full_room_leaves_out_its_oldest_settled_removals() {
    let small = crate::records::keep::small::Small::new(32, 14, 5);
    let mut g = G::new();
    let root = k("root");
    let mut removals = Vec::new();
    for i in 0..5 {
        let name = alloc::format!("d{i}");
        g.device(&root, &k(&name), &name, |_| {});
        removals.push(g.root_rec(Kind::Revoke(removal(&[k(&name).hash], g.seen()))));
    }
    g.device(&root, &k("tv"), "tv", |_| {});
    for r in &g.recs {
        small.units(r.id(), 1);
    }
    let recs = g.recs.clone();
    let set = set_with(&g.root.key, &recs, &g.lists);
    let cp = set.write_checkpoint(&set.state(), &root, 0).unwrap();
    let Kind::Checkpoint { keep, drops, .. } = &cp.body().kind else { unreachable!() };
    assert_eq!(*drops, 1);
    let gone: Vec<bool> = removals.iter().map(|r| !keep.contains(&r.id())).collect();
    assert!(gone[0], "the oldest goes first: {gone:?}");
    assert!(!gone.iter().all(|g| *g), "only as many as the room asks for: {gone:?}");
    assert!(gone.windows(2).all(|w| w[0] || !w[1]), "oldest first: {gone:?}");
}

/// The trial of a take-back where the root's checkpoint can be written:
/// the checkpoint keeps what the admin key signed that counts, so no
/// device stops counting, and the record written then agrees.
#[test]
fn a_removal_outcome_with_the_checkpoint_first_names_nobody() {
    let mut g = G::new();
    let root = k("root");
    let (pa, a) = (k("phone a"), k("admin a"));
    g.admin(&pa, &a, POWER_ADMIT);
    let x = g.device(&a, &k("x"), "x", |_| {});
    g.device(&root, &k("tv"), "tv", |_| {});
    let at = g.seen_at(&a.hash, x.body().seq);
    let mut set = set_with(&g.root.key, &g.recs, &g.lists);
    let st = set.state();
    let mut back = Device::new(pa.key.clone(), "admin", ROLE_MEMBER);
    back.rights = RIGHT_READ | RIGHT_SEND;
    back.seen = vec![at];
    let kind = Kind::device(back);
    let outcome = set.removal_outcome(&st, &root.hash, &kind, 0);
    assert!(outcome.checkpoint_first);
    set.write_record(&st, &root, kind, 0).unwrap();
    let after = set.state();
    assert!(outcome.out.is_empty(), "{:?}", outcome.out);
    assert!(st.devices.iter().all(|d| after.device(&d.id).is_some()));
    assert!(after.device_by_key(&pa.hash).is_some_and(|d| d.admin.is_none()));
}

/// The trial where no checkpoint of the root counts before the record (its
/// room has no place for one): the record goes alone, and the devices
/// the admin key admitted are named.
#[test]
fn a_removal_outcome_without_a_checkpoint_names_the_devices() {
    let small = crate::records::keep::small::Small::new(32, 3, 4);
    let mut g = G::new();
    let root = k("root");
    let (pa, a) = (k("phone a"), k("admin a"));
    g.admin(&pa, &a, POWER_ADMIT);
    g.device(&a, &k("x"), "x", |_| {});
    g.device(&root, &k("tv"), "tv", |_| {});
    g.device(&root, &k("lamp"), "lamp", |_| {});
    for r in &g.recs {
        small.units(r.id(), 1);
    }
    let set = set_with(&g.root.key, &g.recs, &g.lists);
    let st = set.state();
    assert!(st.device_by_key(&k("x").hash).is_some());
    let kind = Kind::Revoke(removal(&[a.hash], Vec::new()));
    let outcome = set.removal_outcome(&st, &root.hash, &kind, 0);
    assert!(!outcome.checkpoint_first);
    let x = st.device_by_key(&k("x").hash).unwrap().id;
    assert!(outcome.out.contains(&x), "{:?}", outcome.out);
}

/// The root's twin at the seq of its checkpoint that left a removal out:
/// the checkpoint no longer counts for a member holding both, the group
/// halts, and the admin's late record must still not bring the removed
/// device back, whether the member pruned by the checkpoint before the
/// twin came or got the twin first.
#[test]
fn a_twin_of_the_pruning_checkpoint_brings_no_removed_device_back() {
    let _drop = crate::records::set::drop_settled();
    let (mut g, late, mine) = late_record(false);
    let root = k("root");
    let x = mine.last().unwrap().clone();
    let b = x.body();
    let twin = Record::sign(
        Body { seq: b.seq, prev: b.prev, ..g.body(&root, Kind::Copies { incoming_ms: 60_000, seen: vec![] }) },
        &root,
    )
    .unwrap();
    g.recs.push(twin.clone());
    // Pruned by the checkpoint first, then the twin, then the late record.
    let mut pruned = set_with(&g.root.key, &mine, &g.lists);
    assert_eq!(pruned.state().drops, 1);
    let _ = pruned.insert(twin.clone());
    let _ = pruned.insert(late.clone());
    let a = pruned.state();
    assert_eq!(a.drops, 1, "the epoch stays where the checkpoint put it");
    // The twin first, then the checkpoint, then the late record.
    let before: Vec<Record> = mine.iter().filter(|r| r.id() != x.id()).cloned().chain([twin.clone()]).collect();
    let mut first = set_with(&g.root.key, &before, &g.lists);
    let _ = first.insert(x.clone());
    let _ = first.insert(late.clone());
    let f = first.state();
    let whole = g.state();
    assert!(!has(&a, &k("d")), "pruned first");
    assert!(!has(&f, &k("d")), "twin first");
    assert!(!has(&whole, &k("d")));
}

/// A root's resolve that names its own checkpoint voids nothing: a
/// root's record is never voided, so the checkpoint that left a removal
/// out still counts, the epoch stays, and the late record stays out.
#[test]
fn a_resolve_naming_the_root_s_checkpoint_changes_no_epoch() {
    let _drop = crate::records::set::drop_settled();
    let (mut g, late, mut mine) = late_record(false);
    let x = mine.last().unwrap().id();
    mine.push(g.root_rec(Kind::Resolve(vec![x])));
    let mut set = set_with(&g.root.key, &mine, &g.lists);
    let st = set.state();
    assert_eq!(st.checkpoint, Some(x));
    assert_eq!(st.drops, 1);
    let _ = set.insert(late.clone());
    assert!(!has(&set.state(), &k("d")));
    assert!(!has(&g.state(), &k("d")));
}

/// A stale record held aside on its signer's chain: the admin signs on
/// after it, the root's writer checkpoints, and neither keeps nor names
/// the stale record, while what the admin signed after it counts at the
/// writer, at a member that gets only what the checkpoint keeps, and in
/// the evaluation of every record alike.
#[test]
fn a_record_held_aside_is_never_kept_and_what_follows_it_counts() {
    let _drop = crate::records::set::drop_settled();
    let (mut g, late, _) = late_record(false);
    let a = k("admin a");
    let y = g.device(&a, &k("y"), "y", |_| {});
    let st = g.state();
    assert!(st.stale.contains(&late.id()) && has(&st, &k("y")) && !has(&st, &k("d")));
    let recs = g.recs.clone();
    let cp = root_checkpoint(&mut g, &recs);
    let Kind::Checkpoint { heads, keep, drops } = &cp.body().kind else { unreachable!() };
    assert!(!keep.contains(&late.id()), "the stale record is not kept");
    assert!(heads.iter().all(|h| h.id != late.id()), "nor named as a head");
    assert_eq!(*drops, 1, "nothing more left out");
    let writer = set_with(&g.root.key, &g.recs, &g.lists).state();
    assert_eq!(writer.checkpoint, Some(cp.id()));
    assert!(has(&writer, &k("y")) && !has(&writer, &k("d")));
    let kept: Vec<Record> =
        g.recs.iter().filter(|r| r.id() == cp.id() || keep.contains(&r.id()) || r.id() == y.id()).cloned().collect();
    let fresh = set_with(&g.root.key, &kept, &g.lists).state();
    assert!(has(&fresh, &k("y")) && !has(&fresh, &k("d")));
    let whole = g.state();
    assert!(has(&whole, &k("y")) && !has(&whole, &k("d")));
}
