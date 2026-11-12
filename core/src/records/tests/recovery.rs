// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! Rule 33 as tests: the recovery key changes the root at once, by a head
//! and its list; two heads at one seq stop the group for good; a head the
//! device cannot read stops that device until it is updated; the writer's
//! list carries what it counts of every earlier root, unedited, and the
//! owner's choice is made of removals.

use super::*;
use crate::records::set::Written;
use alloc::collections::BTreeSet;

/// The device record of a new phone of the root.
fn phone(member: &K) -> Device {
    let mut d = Device::new(member.key.clone(), "new phone", ROLE_PHONE);
    d.rights = RIGHT_READ | RIGHT_SEND | RIGHT_SECRETS;
    d
}

/// The writer's change: a set of `from` (what the writer holds) writes
/// it, making `new_root` the root on the device of `member`, removing
/// `remove`; g takes its first records, its head and its list.
fn write(g: &mut G, from: &[Record], new_root: &K, member: &K, remove: &[KeyHash]) -> Written {
    let set = set_with(&g.root.key, from, &g.lists);
    let st = set.state();
    let w = set.write_change(&st, &k("recovery"), new_root, phone(member), remove, false, 0).unwrap();
    for r in &w.first {
        g.push(r.clone());
    }
    g.push(w.record.clone());
    g.lists.push(w.list.encode());
    w
}

/// A head at seq of the recovery key naming root, with prev and list as
/// given, whatever the chain holds.
fn head_at(g: &G, seq: u64, prev: Option<RecordId>, root: &K, list: [u8; 32]) -> Record {
    let body = Body {
        seq,
        prev,
        ..g.body(&k("recovery"), Kind::Recovery { root: root.key.clone(), list, from: 0, first: RecordId([0xf1; 32]) })
    };
    Record::sign(body, &k("recovery")).unwrap()
}

/// The first root's group: its own phone (holds_root), a laptop and a TV.
fn base() -> G {
    let mut g = G::new();
    let root = k("root");
    g.device(&root, &k("old phone"), "old phone", |d| {
        d.role = ROLE_PHONE;
        d.holds_root = true;
    });
    g.device(&root, &k("laptop"), "laptop", |_| {});
    g.device(&root, &k("tv"), "tv", |_| {});
    g
}

fn has(s: &State, member: &K) -> bool {
    s.device_by_key(&member.hash).is_some()
}

fn forked(s: &State) -> bool {
    s.stop == Stop::Full && s.conflicts.iter().any(|c| c.kind == ConflictKind::Fork)
}

/// Two different heads at one seq stop the group for good, in any order
/// the records come: at seq 1, and at depth, also when the second head is
/// otherwise not valid (its prev is not the tip). The two are the proof.
#[test]
fn two_heads_at_one_seq_stop_the_group_for_good() {
    for depth in [1u64, 2] {
        let mut g = base();
        let list = g.listing();
        g.change(&k("n1"), &list);
        if depth == 2 {
            let list = g.listing();
            g.change(&k("n2"), &list);
        }
        let prev = (depth > 1).then_some(RecordId([7; 32]));
        g.push(head_at(&g, depth, prev, &k("n9"), [9; 32]));
        let want = g.state();
        assert!(forked(&want), "depth {depth}");
        let competing = want.changes.iter().filter(|c| c.state == ChangeState::Competing).count();
        assert_eq!(competing, 2, "depth {depth}");
        assert!(!want.may_command(&k("n1").hash) || depth == 2);
        let mut digests = Vec::new();
        for seed in 0..6 {
            let order = if seed == 0 { g.recs.iter().rev().cloned().collect() } else { shuffled(&g.recs, seed) };
            let set = set_with(&g.root.key, &order, &g.lists);
            let s = set.state();
            assert!(forked(&s), "depth {depth}, order {seed}");
            digests.push(set.digest());
        }
        assert!(digests.windows(2).all(|w| w[0] == w[1]));
        // A writer refuses to write on a group stopped for good.
        let set = set_with(&g.root.key, &g.recs, &g.lists);
        let st = set.state();
        assert!(set.write_change(&st, &k("recovery"), &k("n5"), phone(&k("p5")), &[], false, 0).is_err());
    }
}

/// A head whose signature holds but whose form the device does not know
/// (a critical field of a later version) stops that device by itself, as
/// "update needed": no fork, and the chain stays where it was.
#[test]
fn a_head_the_device_cannot_read_stops_it_until_it_is_updated() {
    let mut g = base();
    let list = g.listing();
    g.change(&k("n1"), &list);
    let later = raw(
        &g,
        &k("recovery"),
        Kind::Recovery { root: k("n2").key.clone(), list: [5; 32], from: 0, first: RecordId([0xf1; 32]) },
        |m| m.push((99, crate::format::cbor::Value::Uint(1))),
    )
    .unwrap();
    assert!(later.body().held);
    g.push(later);
    let s = g.state();
    assert!(s.update_needed);
    assert_eq!(s.stop, Stop::Full);
    assert!(!s.conflicts.iter().any(|c| c.kind == ConflictKind::Fork));
    assert_eq!(s.roots, vec![k("root").hash, k("n1").hash]);
    let set = set_with(&g.root.key, &g.recs, &g.lists);
    assert!(set.state().update_needed);
}

/// A member that applied the old root's removals and checkpoints before
/// the head takes the head over them: what the writer counted stays, its
/// removals with it, and the new root's device is the root's.
#[test]
fn a_member_takes_the_head_over_the_old_roots_work() {
    let mut g = base();
    g.device(&k("root"), &k("printer"), "printer", |_| {});
    let seen = g.seen();
    g.root_rec(Kind::Revoke(removal(&[k("tv").hash], seen)));
    let old: Vec<Record> = g.recs.clone();
    checkpoint_keeping(&mut g, &old.iter().collect::<Vec<_>>());
    let from = g.recs.clone();
    write(&mut g, &from, &k("n1"), &k("new phone"), &[k("old phone").hash]);
    let s = members_agree(&g);
    assert_eq!(s.roots, vec![k("root").hash, k("n1").hash]);
    assert!(s.revoked.contains(&k("tv").hash), "the old root's removal stays a removal");
    assert!(s.revoked.contains(&k("old phone").hash), "the old root's device was unticked");
    assert!(has(&s, &k("laptop")) && has(&s, &k("printer")));
    assert_eq!(s.root_device, Some(k("new phone").key.device_id()));
}

/// A writer that had not seen a removal of the old root lists it not; a
/// member that held it drops it at the change, and keeps a notice of it
/// for its app ("removed before, back now"). The member it named is a
/// member again: its record still counts and no removal that counts
/// names it.
#[test]
fn a_removal_the_writer_lacks_becomes_a_notice() {
    let mut g = base();
    let seen = g.seen();
    let rv = g.root_rec(Kind::Revoke(removal(&[k("tv").hash], seen)));
    let from: Vec<Record> = g.recs.iter().filter(|r| r.id() != rv.id()).cloned().collect();
    write(&mut g, &from, &k("n1"), &k("new phone"), &[]);
    let s = members_agree(&g);
    assert!(!s.revoked.contains(&k("tv").hash) && has(&s, &k("tv")));
    let mut m = set_of(&g.root.key);
    sync_all(&mut m, &g.recs, &g.lists);
    assert!(m.notices().contains(&k("tv").hash));
    assert!(m.get(&rv.id()).is_none(), "the dropped removal is not kept");
}

/// A thief with the old root's unlocked phone removed a device and
/// admitted its own: the writer saw both, so the list carries both, and
/// the owner's unticks remove the thief's device. The price written down:
/// the device the thief removed stays removed.
#[test]
fn a_thiefs_removals_and_devices_on_a_member() {
    let mut g = base();
    let seen = g.seen();
    g.root_rec(Kind::Revoke(removal(&[k("laptop").hash], seen)));
    g.device(&k("root"), &k("thief"), "thief", |_| {});
    let from = g.recs.clone();
    let w = write(&mut g, &from, &k("n1"), &k("new phone"), &[k("thief").hash, k("old phone").hash]);
    assert!(w.list.0.iter().any(|id| g.recs.iter().any(|r| r.id() == *id && matches!(r.body().kind, Kind::Revoke(_)))));
    let s = members_agree(&g);
    assert!(s.revoked.contains(&k("thief").hash) && !has(&s, &k("thief")));
    assert!(s.revoked.contains(&k("laptop").hash));
    assert!(has(&s, &k("tv")) && has(&s, &k("new phone")));
}

/// A device the old root removed writes the change: it comes in as a new
/// device under the new root, and its old key stays removed.
#[test]
fn a_removed_device_writes_the_change() {
    let mut g = base();
    let seen = g.seen();
    g.root_rec(Kind::Revoke(removal(&[k("old phone").hash], seen)));
    let from = g.recs.clone();
    write(&mut g, &from, &k("n1"), &k("phone again"), &[]);
    let s = members_agree(&g);
    assert!(s.revoked.contains(&k("old phone").hash));
    assert_eq!(s.root_device, Some(k("phone again").key.device_id()));
    assert!(s.may_command(&k("n1").hash) && !s.may_command(&k("root").hash));
}

/// A writer behind by an admin's removal: an admin's records are not
/// listed, they count by themselves while the admin counts, so the
/// removal counts on every member once it arrives, before or after the
/// head.
#[test]
fn a_writer_behind_by_an_admin_removal() {
    let mut g = base();
    g.admin(&k("phone a"), &k("admin a"), POWER_ADMIT | POWER_REMOVE);
    let seen = g.seen();
    let rv = g.rec(&k("admin a"), Kind::Revoke(removal(&[k("tv").hash], seen)));
    let from: Vec<Record> = g.recs.iter().filter(|r| r.id() != rv.id()).cloned().collect();
    write(&mut g, &from, &k("n1"), &k("new phone"), &[]);
    let s = members_agree(&g);
    assert!(s.revoked.contains(&k("tv").hash) && s.counting.contains(&rv.id()));
    assert!(s.may_command(&k("admin a").hash));
}

/// A listed record only the writer holds: a member asks its peers for it
/// and takes it from anyone, and it counts once it arrives and verifies.
#[test]
fn a_listed_record_only_the_writer_holds() {
    let mut g = base();
    let only = g.device(&k("root"), &k("watch"), "watch", |_| {});
    let from = g.recs.clone();
    write(&mut g, &from, &k("n1"), &k("new phone"), &[]);
    let without: Vec<Record> = g.recs.iter().filter(|r| r.id() != only.id()).cloned().collect();
    let mut m = set_with(&g.root.key, &without, &g.lists);
    assert!(!has(&m.state(), &k("watch")));
    assert!(m.missing(&m.state()).contains(&only.id()));
    m.insert(only.clone()).unwrap();
    let s = m.state();
    assert!(has(&s, &k("watch")) && s.counting.contains(&only.id()));
    assert!(!m.missing(&m.state()).contains(&only.id()));
}

/// The newest list is the whole truth: one that names nothing drops every
/// record of the earlier roots, and the devices only they named; one that
/// names IDs nobody holds is asked for some rounds, then given up; bytes
/// that hash right and do not read are the empty list.
#[test]
fn lists_naming_nothing_everything_or_ids_nobody_holds() {
    // Nothing.
    let mut g = base();
    g.change(&k("n1"), &[]);
    let s = members_agree(&g);
    assert!(!has(&s, &k("laptop")) && !has(&s, &k("old phone")));
    assert_eq!(s.roots.len(), 2);
    // Everything.
    let mut g = base();
    let list = g.listing();
    g.change(&k("n1"), &list);
    let s = members_agree(&g);
    assert!(has(&s, &k("laptop")) && has(&s, &k("tv")) && has(&s, &k("old phone")));
    // IDs nobody holds.
    let mut g = base();
    let mut list = g.listing();
    let ghost = RecordId([0xee; 32]);
    list.push(ghost);
    g.change(&k("n1"), &list);
    let s = members_agree(&g);
    assert!(has(&s, &k("laptop")));
    let mut m = set_with(&g.root.key, &g.recs, &g.lists);
    let mut asked = 0;
    while m.missing(&m.state()).contains(&ghost) {
        asked += 1;
        assert!(asked <= 64, "asked for ever");
    }
    assert!(asked > 0);
    // Bytes that do not read.
    let mut g = base();
    let junk = vec![0xff, 0x00, 0x01];
    let h = list_hash(&junk);
    let first = g.first_checkpoint(&k("n1"), &[]);
    g.rec(&k("recovery"), Kind::Recovery { root: k("n1").key.clone(), list: h, from: 0, first });
    g.lists.push(junk.clone());
    let s = g.state();
    assert_eq!(s.roots.len(), 2);
    assert!(!has(&s, &k("laptop")), "the empty list");
    let mut m = set_of(&g.root.key);
    m.insert_all(g.recs.clone());
    assert_eq!(m.insert_list(&junk), Ok(true));
    assert_eq!(m.state().roots.len(), 2);
    // A list no held head names is not taken.
    assert!(m.insert_list(&[0x80]).is_err());
}

/// The recovery key is no admin: a freeze or a removal naming its hash
/// does nothing, and its head still changes the root.
#[test]
fn a_freeze_or_removal_of_the_recovery_key_does_nothing() {
    let mut g = base();
    let seen = g.seen();
    g.root_rec(Kind::Freeze(removal(&[rk().hash()], seen.clone())));
    g.root_rec(Kind::Revoke(removal(&[rk().hash()], seen)));
    let from = g.recs.clone();
    write(&mut g, &from, &k("n1"), &k("new phone"), &[]);
    let s = members_agree(&g);
    assert_eq!(s.roots, vec![k("root").hash, k("n1").hash]);
    assert_eq!(s.root_device, Some(k("new phone").key.device_id()));
}

/// The recovery key signs heads only: any other record of it is refused.
#[test]
fn the_recovery_key_signs_heads_only() {
    let mut g = base();
    let d = g.device(&k("recovery"), &k("sneaky"), "sneaky", |_| {});
    let mut set = set_of(&g.root.key);
    assert_eq!(set.insert(d.clone()), Err(Refused::Broken(Rule::new("records/recovery"))));
    let s = g.state();
    assert!(!has(&s, &k("sneaky")));
}

/// At most 16 heads for the group's life: a 17th is not signed, not
/// stored, and a writer at 16 refuses.
#[test]
fn at_most_sixteen_heads() {
    let mut g = base();
    for i in 1..=16 {
        let list = g.listing();
        g.change(&k(&format!("n{i}")), &list);
    }
    let s = g.state();
    assert_eq!(s.roots.len(), 17);
    let (_, tip) = g.heads[&rk().hash()];
    let body = Body {
        seq: 17,
        prev: Some(tip),
        ..g.body(
            &k("recovery"),
            Kind::Recovery { root: k("n17").key, list: [1; 32], from: 0, first: RecordId([0xf1; 32]) },
        )
    };
    assert!(Record::sign(body.clone(), &k("recovery")).is_err());
    let set = set_with(&g.root.key, &g.recs, &g.lists);
    let st = set.state();
    assert!(set.write_change(&st, &k("recovery"), &k("n17"), phone(&k("p17")), &[], false, 0).is_err());
}

/// A head naming an admin's key as the root: the chain wins, and what that
/// key signed as an admin counts only if listed. The core's writer
/// refuses a key its state knows.
#[test]
fn an_admin_key_named_as_the_root() {
    let mut g = base();
    g.admin(&k("phone a"), &k("admin a"), POWER_ADMIT);
    let by_admin = g.device(&k("admin a"), &k("lamp"), "lamp", |_| {});
    let set = set_with(&g.root.key, &g.recs, &g.lists);
    let st = set.state();
    assert!(set.write_change(&st, &k("recovery"), &k("admin a"), phone(&k("p")), &[], false, 0).is_err());
    assert!(set.write_change(&st, &k("recovery"), &k("laptop"), phone(&k("p")), &[], false, 0).is_err());
    // A head that names it anyway is valid, and the key is the root.
    let mut with = g.listing();
    with.push(by_admin.id());
    g.change(&k("admin a"), &with);
    let s = members_agree(&g);
    assert_eq!(s.roots.last(), Some(&k("admin a").hash));
    assert!(has(&s, &k("lamp")), "listed");
    assert!(s.may_command(&k("admin a").hash));
}

/// A head that names a key that signed before carries `from`, the seq its
/// records as the root start at: its records below it count only if the
/// list names them, those from it on count as the root's.
#[test]
fn a_head_names_where_the_new_roots_records_start() {
    let mut g = base();
    g.admin(&k("phone a"), &k("admin a"), POWER_ADMIT);
    g.device(&k("admin a"), &k("lamp"), "lamp", |_| {});
    let kept = g.device(&k("admin a"), &k("bulb"), "bulb", |_| {});
    let (seq, _) = g.heads[&k("admin a").hash];
    let mut list = g.listing();
    list.push(kept.id());
    g.change_from(&k("admin a"), &list, seq + 1);
    let after = g.device(&k("admin a"), &k("kettle"), "kettle", |_| {});
    // From on: its first checkpoint at from, then its own records.
    assert_eq!(after.body().seq, seq + 2);
    let s = members_agree(&g);
    assert_eq!(s.roots.last(), Some(&k("admin a").hash));
    assert!(!has(&s, &k("lamp")), "below from, not listed");
    assert!(has(&s, &k("bulb")), "below from, listed");
    assert!(has(&s, &k("kettle")), "from on, the root's own");
    // Written as 0 it is the default, and refused; above a seq, refused.
    let r = raw(
        &g,
        &k("recovery"),
        Kind::Recovery { root: k("n9").key.clone(), list: [1; 32], from: 0, first: RecordId([0xf1; 32]) },
        |m| m.push((12, crate::format::cbor::Value::Uint(0))),
    );
    assert_eq!(r.map(|_| ()).unwrap_err(), Rule::new("form/default"));
    let body = g.body(
        &k("recovery"),
        Kind::Recovery { root: k("n9").key.clone(), list: [1; 32], from: MAX_SEQ + 1, first: RecordId([0xf1; 32]) },
    );
    assert!(body.check().unwrap_err().is("records/recovery/from"));
}

/// The writer signs the new root's first checkpoint with the head, so the
/// old root's checkpoint's pruning never lapses: a member that compacted
/// under the old checkpoint and one that did not end equal, in both
/// orders the records come.
#[test]
fn members_that_did_and_did_not_compact_end_equal() {
    let mut g = base();
    g.admin(&k("phone a"), &k("admin a"), POWER_ADMIT);
    let pruned = g.device(&k("admin a"), &k("lamp"), "lamp", |_| {});
    let stays = g.device(&k("admin a"), &k("bulb"), "bulb", |_| {});
    let a = k("admin a");
    let (aseq, aid) = g.heads[&a.hash];
    let root = k("root");
    let (rseq, rid) = g.heads[&root.hash];
    let mut keep: Vec<RecordId> =
        g.recs.iter().filter(|r| r.body().signer == root.hash && r.id() != rid).map(Record::id).collect();
    keep.retain(|id| *id != stays.id());
    keep.push(stays.id());
    keep.sort();
    let mut heads = vec![Head { key: a.hash, seq: aseq, id: aid }, Head { key: root.hash, seq: rseq, id: rid }];
    heads.sort();
    g.root_rec(Kind::Checkpoint { heads, keep });
    let before = g.state();
    assert!(!has(&before, &k("lamp")) && has(&before, &k("bulb")));
    let old = g.recs.clone();
    let w = write(&mut g, &old, &k("n1"), &k("new phone"), &[]);
    assert!(
        matches!(&w.first.last().unwrap().body().kind, Kind::Checkpoint { heads, .. } if heads.iter().any(|h| h.key == a.hash))
    );
    let want = g.state();
    assert!(!has(&want, &k("lamp")) && has(&want, &k("bulb")));
    let new: Vec<Record> = g.recs[old.len()..].to_vec();
    for order in 0..2 {
        // One member compacted under the old checkpoint, one did not
        // ask: the checkpoint compacted both as it came.
        let mut compacted = set_of(&g.root.key);
        sync_all(&mut compacted, &old, &[]);
        assert!(compacted.get(&pruned.id()).is_none());
        let mut plain = set_of(&g.root.key);
        plain.insert_all(old.clone());
        assert!(plain.get(&pruned.id()).is_none());
        let mut rest = new.clone();
        if order == 1 {
            rest.reverse();
        }
        for m in [&mut compacted, &mut plain] {
            sync_all(m, &rest, &g.lists);
        }
        let strip = |s: &State| State { ignored: Vec::new(), ..s.clone() };
        assert_eq!(strip(&compacted.state()), strip(&want), "order {order}");
        assert_eq!(strip(&plain.state()), strip(&want), "order {order}");
        assert_eq!(compacted.digest(), plain.digest(), "order {order}");
    }
}

/// A checkpoint of the new root closes the list: a listed record that
/// arrives after it does not count, and nobody asks for it.
#[test]
fn the_new_roots_first_checkpoint_closes_the_list() {
    let mut g = base();
    let late = g.device(&k("root"), &k("watch"), "watch", |_| {});
    let from = g.recs.clone();
    write(&mut g, &from, &k("n1"), &k("new phone"), &[]);
    let n1 = k("n1");
    let (seq, id) = g.heads[&n1.hash];
    let mut keep: Vec<RecordId> = g.listing().into_iter().filter(|x| *x != late.id()).collect();
    keep.sort();
    keep.retain(|x| g.recs.iter().any(|r| r.id() == *x && r.body().signer != n1.hash));
    g.rec(&n1, Kind::Checkpoint { heads: vec![Head { key: n1.hash, seq, id }], keep });
    let without: Vec<Record> = g.recs.iter().filter(|r| r.id() != late.id()).cloned().collect();
    let mut m = set_with(&g.root.key, &without, &g.lists);
    assert!(!m.missing(&m.state()).contains(&late.id()));
    let _ = m.insert(late.clone());
    assert!(!has(&m.state(), &k("watch")));
}

/// The writer signs the new root's first records before the head: its
/// device record (holds_root), a copy of the settings, a copy of the hubs
/// unless dropped, and the removals the owner chose; the head names the
/// list's hash. It refuses a key other than the group's recovery key.
#[test]
fn the_writer_signs_the_new_roots_first_records() {
    let mut g = base();
    g.root_rec(Kind::settings(Settings { min_rules: 2, ..Settings::default() }));
    g.root_rec(Kind::Hubs { hubs: vec![k("laptop").key.device_id()], seen: g.seen() });
    let set = set_with(&g.root.key, &g.recs, &g.lists);
    let st = set.state();
    let w = set
        .write_change(&st, &k("recovery"), &k("n1"), phone(&k("new phone")), &[k("old phone").hash], false, 7)
        .unwrap();
    let kinds: Vec<&Kind> = w.first.iter().map(|r| &r.body().kind).collect();
    assert!(matches!(kinds[0], Kind::Device(d) if d.holds_root && d.key == k("new phone").key));
    assert!(kinds.iter().any(|k| matches!(k, Kind::Settings(s) if s.min_rules == 2)));
    assert!(kinds.iter().any(|k| matches!(k, Kind::Hubs { .. })));
    assert!(kinds.iter().any(|kd| matches!(kd, Kind::Revoke(r) if r.keys == vec![k("old phone").hash])));
    assert!(w.first.iter().all(|r| r.body().signer == k("n1").hash));
    assert!(matches!(&w.record.body().kind, Kind::Recovery { list, .. } if *list == w.list.hash()));
    assert_eq!((w.record.body().seq, w.record.body().prev), (1, None));
    let dropped = set.write_change(&st, &k("recovery"), &k("n1"), phone(&k("new phone")), &[], true, 7).unwrap();
    assert!(!dropped.first.iter().any(|r| matches!(r.body().kind, Kind::Hubs { .. })));
    assert!(set.write_change(&st, &k("not the key"), &k("n1"), phone(&k("new phone")), &[], false, 7).is_err());
}

/// One state for one set in any order, over a group holding every kind of
/// record: devices, removals, freezes, thaws, resolves, settings, copies,
/// checkpoints, hubs, a held record, heads of the recovery key and lists.
#[test]
fn every_kind_of_record_in_any_order() {
    let mut g = base();
    g.admin(&k("phone a"), &k("admin a"), POWER_ADMIT | POWER_REMOVE | POWER_FREEZE | POWER_THAW);
    g.admin(&k("phone b"), &k("admin b"), POWER_ADMIT | POWER_REMOVE);
    g.device(&k("admin a"), &k("lamp"), "lamp", |_| {});
    let seen = g.seen();
    g.rec(&k("admin a"), Kind::Revoke(removal(&[k("lamp").hash], seen.clone())));
    let f = g.rec(&k("admin a"), Kind::Freeze(removal(&[k("admin b").hash], seen)));
    g.rec(&k("admin a"), Kind::Thaw { ids: vec![f.id()], seen: g.seen() });
    let conflict = g.rec(&k("admin b"), Kind::Copies { incoming_ms: 9_000, seen: g.seen() });
    g.root_rec(Kind::Resolve(vec![conflict.id()]));
    g.root_rec(Kind::settings(Settings { min_rules: 3, ..Settings::default() }));
    g.root_rec(Kind::Hubs { hubs: vec![k("laptop").key.device_id()], seen: g.seen() });
    let mut held = g.body(&k("root"), Kind::Unknown(77));
    held.held = true;
    let bytes = held.encode();
    let sig = key::sign_es256(&k("root"), LABEL_RECORD, &bytes).unwrap();
    g.push(Record::from_parts(bytes, sig.to_vec(), None, held).unwrap());
    let root = k("root").hash;
    let old: Vec<Record> = g.recs.iter().filter(|r| r.body().signer == root && !r.body().held).cloned().collect();
    checkpoint_keeping(&mut g, &old.iter().collect::<Vec<_>>());
    let from = g.recs.clone();
    write(&mut g, &from, &k("n1"), &k("new phone"), &[k("old phone").hash]);
    g.device(&k("n1"), &k("speaker"), "speaker", |_| {});
    let list = g.listing();
    g.change(&k("n2"), &list);
    g.device(&k("n2"), &k("clock"), "clock", |_| {});
    let want = g.state();
    assert_eq!(want.roots.len(), 3);
    let strip = |s: &State| State { ignored: Vec::new(), ..s.clone() };
    let mut digest = None;
    for seed in 0..12 {
        let order: Vec<Record> =
            if seed == 0 { g.recs.iter().rev().cloned().collect() } else { shuffled(&g.recs, seed) };
        assert_eq!(strip(&state_with(&g.root.key, &order, &g.lists)), strip(&want), "evaluate, order {seed}");
        let mut m = set_of(&g.root.key);
        sync_all(&mut m, &order, &g.lists);
        assert_eq!(strip(&m.state()), strip(&want), "set, order {seed}");
        let d = m.digest();
        assert!(digest.is_none_or(|x| x == d), "order {seed}");
        digest = Some(d);
    }
}

/// A device pins the root key and the recovery key together: a set loads
/// from its store only under the mark of both.
#[test]
fn a_device_pins_the_root_and_the_recovery_key() {
    let local = [3u8; 32];
    let root = k("root").key;
    let mark = pin_mark(&local, &root, &rk());
    assert!(RecordSet::pinned(root.clone(), rk(), &local, &mark).is_some());
    assert!(RecordSet::pinned(root.clone(), k("other").key, &local, &mark).is_none());
    assert!(RecordSet::pinned(k("root 2").key, rk(), &local, &mark).is_none());
    assert!(RecordSet::pinned(root, rk(), &[4u8; 32], &mark).is_none());
}

/// The Group ID commits to both keys.
#[test]
fn the_group_id_commits_to_both_keys() {
    let root = k("root").key;
    assert_ne!(group_id(&root, &rk()), group_id(&root, &k("other").key));
    assert_ne!(group_id(&root, &rk()), group_id(&k("root 2").key, &rk()));
    assert_ne!(group_id(&root, &rk()), root.device_id());
}

/// A head that names a root already on the path is void: the chain stops
/// there, and nothing after it applies.
#[test]
fn a_head_naming_an_earlier_root_is_void() {
    let mut g = base();
    let list = g.listing();
    g.change(&k("n1"), &list);
    let list = g.listing();
    g.change(&k("root"), &list);
    let s = members_agree(&g);
    assert_eq!(s.roots, vec![k("root").hash, k("n1").hash]);
    assert!(s.changes.iter().any(|c| c.state == ChangeState::Void));
}

/// Retired types refuse on reading: the claim, the root's recovery record
/// and the handover; and the takeover power bit.
#[test]
fn the_retired_types_and_power_refuse() {
    let g = base();
    for t in RETIRED_TYPES {
        let r = raw(&g, &k("root"), Kind::Copies { incoming_ms: 5_000, seen: vec![] }, |m| {
            for (key, v) in m.iter_mut() {
                if *key == 1 {
                    *v = crate::format::cbor::Value::Uint(*t);
                }
            }
        });
        assert_eq!(r.map(|_| ()).unwrap_err(), Rule::new("records/retired"), "type {t}");
    }
    let body = g.body(&k("root"), {
        let mut d = Device::new(k("x").key.clone(), "x", ROLE_PHONE);
        d.admin = Some(k("x admin").key.clone());
        d.powers = POWER_RETIRED;
        Kind::device(d)
    });
    assert!(body.check().unwrap_err().is("records/device/powers"));
}

/// A fetch proof has its own label: the recovery key's signature for a
/// fetch does not make a head, nor a head's signature a fetch proof.
#[test]
fn a_fetch_proof_and_a_head_are_not_one_signature() {
    let g = base();
    let head = head_at(&g, 1, None, &k("root 2"), List(g.listing()).hash());
    let body = head.body_bytes().to_vec();
    let fetch = crate::records::sign_fetch(&k("recovery"), &body).unwrap();
    assert_eq!(crate::records::verify_fetch(&rk(), &body, &fetch), Ok(()));
    // The fetch signature on the head's body is not the head.
    let forged = Record::decode(&crate::format::envelope::write(&body, &fetch, None)).unwrap();
    assert!(forged.verify(&rk()).is_err());
    let mut set = set_of(&g.root.key);
    assert!(set.insert(forged).is_err());
    // The head's signature is no fetch proof.
    assert!(crate::records::verify_fetch(&rk(), &body, head.sig()).is_err());
    assert!(head.verify(&rk()).is_ok());
}

/// Two changes of root: the phone the first new root holds is not
/// removed by the second, so it stays a device, listed and counting.
#[test]
fn the_first_new_roots_phone_stays_after_a_second_change() {
    let mut g = base();
    let all = g.recs.clone();
    let w1 = write(&mut g, &all, &k("n1"), &k("p1"), &[]);
    assert!(has(&g.state(), &k("p1")));
    let all = g.recs.clone();
    let w2 = write(&mut g, &all, &k("n2"), &k("p2"), &[]);
    let p1 = w1.first.iter().find(|r| matches!(&r.body().kind, Kind::Device(d) if d.key == k("p1").key)).unwrap();
    assert!(w2.list.0.contains(&p1.id()), "the second list names it");
    let s = g.state();
    assert_eq!(s.roots.len(), 3);
    assert!(has(&s, &k("p1")) && has(&s, &k("p2")) && has(&s, &k("laptop")));
}

/// A writer whose set took the first new root's records before that
/// root's head had its list keeps them aside and takes them when the list
/// comes: its list names them, and after its change they still count. No
/// second round is needed. Before the list they count for nothing, and a
/// writer refuses to write a change while a list is missing.
#[test]
fn a_writer_that_took_one_round_keeps_what_came_early() {
    let mut g = base();
    let all = g.recs.clone();
    let w1 = write(&mut g, &all, &k("n1"), &k("p1"), &[]);
    // The head first, as a sender sends (`in_dependency_order`), then
    // every record in the order the group holds them.
    let mut set = set_of(&g.root.key);
    assert_eq!(set.insert(w1.record.clone()), Ok(Added::Stored));
    for r in &g.recs {
        let added = set.insert(r.clone()).unwrap();
        let first = w1.first.iter().any(|f| f.id() == r.id());
        assert_eq!(added == Added::Waiting, first, "{:?}", r.body().kind);
    }
    let st = set.state();
    assert!(!has(&st, &k("p1")) && st.roots.len() == 1);
    let err = set.write_change(&st, &k("recovery"), &k("n2"), phone(&k("p2")), &[], false, 0).unwrap_err();
    assert_eq!(err.to_string(), crate::records::set::CHANGE_WAITING);
    for l in &g.lists {
        set.insert_list(l).unwrap();
    }
    let st = set.state();
    assert!(has(&st, &k("p1")) && st.roots.len() == 2);
    assert!(w1.first.iter().all(|r| set.contains(&r.id())));
    let w2 = set.write_change(&st, &k("recovery"), &k("n2"), phone(&k("p2")), &[], false, 0).unwrap();
    let p1 = w1.first.iter().find(|r| matches!(&r.body().kind, Kind::Device(d) if d.key == k("p1").key)).unwrap();
    assert!(w2.list.0.contains(&p1.id()));
    for r in w2.first.iter().chain([&w2.record]) {
        g.push(r.clone());
    }
    g.lists.push(w2.list.encode());
    let s = g.state();
    assert!(has(&s, &k("p1")) && has(&s, &k("p2")));
}

/// What waits for a root's list is bounded by that root's room, and goes
/// when the record naming the root turns out to be one side of a fork.
#[test]
fn what_waits_is_bounded_and_goes_with_a_fork() {
    let mut g = base();
    let list = g.listing();
    let head = g.change(&k("n1"), &list);
    let n1 = k("n1");
    let mut early = Vec::new();
    for _ in 0..(crate::records::keep::ceiling(true) + 8) {
        early.push(g.rec(&n1, Kind::Copies { incoming_ms: MIN_INCOMING_MS, seen: vec![] }));
    }
    let mut set = set_of(&g.root.key);
    set.insert_all(g.recs.iter().filter(|r| r.body().signer != n1.hash).cloned());
    // Newest first: the lowest seqs stay, whatever the order.
    for r in early.iter().rev() {
        assert_eq!(set.insert(r.clone()), Ok(Added::Waiting));
    }
    assert_eq!(set.insert(early.last().unwrap().clone()), Ok(Added::NoRoom));
    let units: u64 = set
        .in_dependency_order()
        .iter()
        .filter(|r| r.body().signer == n1.hash)
        .map(|r| crate::records::eval::item(r, crate::records::eval::Role::Root).units)
        .sum();
    assert_eq!(units, crate::records::keep::ceiling(true));
    // A second record at the head's seq: the group stops, and what waited
    // for n1 goes.
    let twin = head_at(&g, head.body().seq, head.body().prev, &k("n9"), [7; 32]);
    set.insert(twin).unwrap();
    assert!(!set.in_dependency_order().iter().any(|r| r.body().signer == n1.hash));
    for l in &g.lists {
        let _ = set.insert_list(l);
    }
    assert!(set.state().halted());
}

/// What waits for several roots shares one root's room: the root of the
/// lower recovery seq first, whatever the order the records came in.
#[test]
fn what_waits_for_two_roots_shares_one_room() {
    let mut g = base();
    let list = g.listing();
    g.change(&k("n1"), &list);
    let list = g.listing();
    g.change(&k("n2"), &list);
    let (n1, n2) = (k("n1"), k("n2"));
    let ceiling = crate::records::keep::ceiling(true);
    let many = |g: &mut G, by: &K, n: u64| -> Vec<Record> {
        (0..n).map(|_| g.rec(by, Kind::Copies { incoming_ms: MIN_INCOMING_MS, seen: vec![] })).collect()
    };
    let second = many(&mut g, &n2, ceiling);
    let first = many(&mut g, &n1, ceiling / 2);
    let units = |set: &RecordSet, by: &K| -> u64 {
        set.in_dependency_order()
            .iter()
            .filter(|r| r.body().signer == by.hash)
            .map(|r| crate::records::eval::item(r, crate::records::eval::Role::Root).units)
            .sum()
    };
    let base: Vec<Record> =
        g.recs.iter().filter(|r| r.body().signer != n1.hash && r.body().signer != n2.hash).cloned().collect();
    let mut digests = Vec::new();
    for order in [[&second, &first], [&first, &second]] {
        let mut set = set_of(&g.root.key);
        set.insert_all(base.iter().cloned());
        for rs in order {
            for r in rs.iter() {
                let _ = set.insert(r.clone());
            }
        }
        let (u1, u2) = (units(&set, &n1), units(&set, &n2));
        assert_eq!(
            u1,
            first.iter().map(|r| crate::records::eval::item(r, crate::records::eval::Role::Root).units).sum::<u64>()
        );
        assert_eq!(u1 + u2, ceiling);
        digests.push(set.in_dependency_order().iter().map(|r| r.id()).collect::<Vec<_>>());
    }
    assert_eq!(digests[0], digests[1]);
}

/// The writer writes no change while the set holds a recovery record it
/// has not applied: one waiting for its list, one it cannot read, a void
/// one. Writing then would sign a second record at that seq.
#[test]
fn the_writer_waits_for_every_change_it_holds() {
    use crate::records::set::CHANGE_WAITING;
    let refused = |g: &G, lists: &[Vec<u8>]| {
        let set = set_with(&g.root.key, &g.recs, lists);
        let st = set.state();
        set.write_change(&st, &k("recovery"), &k("n9"), phone(&k("p9")), &[], false, 0).err().map(|e| e.to_string())
    };
    // A head waiting for its list.
    let mut g = base();
    let list = g.listing();
    g.change(&k("n1"), &list);
    assert_eq!(refused(&g, &[]).as_deref(), Some(CHANGE_WAITING));
    assert_eq!(refused(&g, &g.lists), None);
    // A head this device cannot read.
    let mut g = base();
    let held = raw(
        &g,
        &k("recovery"),
        Kind::Recovery { root: k("n1").key.clone(), list: [5; 32], from: 0, first: RecordId([0xf1; 32]) },
        |m| m.push((99, crate::format::cbor::Value::Uint(1))),
    )
    .unwrap();
    assert!(held.body().held);
    g.push(held);
    assert_eq!(refused(&g, &[]).as_deref(), Some(CHANGE_WAITING));
    // A void head (it names a root already on the path).
    let mut g = base();
    let list = g.listing();
    g.change(&k("n1"), &list);
    let list = g.listing();
    g.change(&k("root"), &list);
    assert_eq!(refused(&g, &g.lists).as_deref(), Some(CHANGE_WAITING));
}

/// The owner's unticks carry what the writer saw: an unticked admin's
/// work up to then stays (the device it admitted stays, the device it
/// removed stays removed), and the admin commands no more.
#[test]
fn an_untick_keeps_what_the_admin_did() {
    let mut g = base();
    let (pb, b) = (k("phone b"), k("admin b"));
    g.admin(&pb, &b, POWER_ADMIT | POWER_REMOVE);
    g.device(&b, &k("speaker"), "speaker", |_| {});
    let seen = g.seen();
    g.rec(&b, Kind::Revoke(removal(&[k("tv").hash], seen)));
    for remove in [vec![pb.hash, b.hash], vec![pb.hash], vec![b.hash]] {
        let mut g = g.clone();
        let all = g.recs.clone();
        let w = write(&mut g, &all, &k("n1"), &k("p1"), &remove);
        let rm = w.first.iter().find_map(|r| match &r.body().kind {
            Kind::Revoke(rm) => Some(rm.clone()),
            _ => None,
        });
        assert!(rm.is_some_and(|rm| !rm.seen.is_empty()));
        let s = g.state();
        assert!(has(&s, &k("speaker")), "{remove:?}");
        assert!(!has(&s, &k("tv")) && s.revoked.contains(&k("tv").hash), "{remove:?}");
        assert!(!s.may_command(&b.hash), "{remove:?}");
    }
}

/// The writer refuses what would leave the new root unable to act: a
/// removal of the new root, its device, the recovery key or a root on the
/// path, and a device key the group removed.
#[test]
fn the_writer_refuses_what_it_cannot_mean() {
    let mut g = base();
    let seen = g.seen();
    g.rec(&k("root"), Kind::Revoke(removal(&[k("laptop").hash], seen)));
    let set = set_with(&g.root.key, &g.recs, &g.lists);
    let st = set.state();
    let w = |dev: &K, remove: &[KeyHash]| set.write_change(&st, &k("recovery"), &k("n1"), phone(dev), remove, false, 0);
    for bad in [k("n1").hash, k("p1").hash, rk().hash(), k("root").hash] {
        assert!(w(&k("p1"), &[bad]).is_err());
    }
    assert!(w(&k("laptop"), &[]).is_err());
    assert!(w(&k("p1"), &[k("tv").hash]).is_ok());
}

/// A change's list names no checkpoint record, not even one a later
/// checkpoint names as its key's head; members that took the records in
/// any order count the same.
#[test]
fn a_change_lists_no_checkpoint() {
    let mut g = base();
    let all = g.recs.clone();
    let refs: Vec<&Record> = all.iter().collect();
    let first = checkpoint_keeping(&mut g, &refs);
    let second = checkpoint_keeping(&mut g, &refs);
    let before = g.recs.clone();
    let list = g.listing();
    assert!(!list.contains(&first.id()) && !list.contains(&second.id()));
    g.change(&k("n1"), &list);
    let mut a = set_of(&g.root.key);
    sync_all(&mut a, &before, &[]);
    sync_all(&mut a, &g.recs, &g.lists);
    let mut b = set_of(&g.root.key);
    sync_all(&mut b, &g.recs, &g.lists);
    let c = set_with(&g.root.key, &g.recs, &g.lists);
    assert_eq!(a.state(), b.state());
    assert_eq!(a.state().checkpoints, c.state().checkpoints);
}

/// A change's list carries the earlier roots' removals that name a key
/// some record names, at most their share, the newest first.
#[test]
fn a_change_lists_removals_that_name_someone_within_their_share() {
    use crate::records::set::EARLIER_REMOVALS;
    let mut g = base();
    let ghosts: Vec<RecordId> = (0..40u32)
        .map(|i| g.root_rec(Kind::Revoke(removal(&[KeyHash(sha256(&i.to_be_bytes()))], vec![]))).id())
        .collect();
    let tv = k("tv");
    let of_tv: Vec<RecordId> =
        (0..EARLIER_REMOVALS + 40).map(|_| g.root_rec(Kind::Revoke(removal(&[tv.hash], vec![]))).id()).collect();
    let list = g.listing();
    assert!(of_tv.iter().all(|id| list.contains(id)));
    g.change(&k("n1"), &list);
    // The new root admits the tv again; a second change follows.
    g.device(&k("n1"), &tv, "tv", |_| {});
    let list = g.listing();
    assert!(ghosts.iter().all(|id| !list.contains(id)));
    let listed: Vec<&RecordId> = of_tv.iter().filter(|id| list.contains(id)).collect();
    assert_eq!(listed, of_tv[of_tv.len() - EARLIER_REMOVALS..].iter().collect::<Vec<_>>());
}

/// While halted a set takes the recovery key's records and what the list
/// applied below the fork names, and shows only that: a member that held
/// everything before the proof came and one that took it all at once hold
/// and show the same. After a fork at seq 1 that is the first root alone.
#[test]
fn a_halted_member_shows_the_chain_below_the_fork() {
    let mut g = base();
    let from = g.recs.clone();
    write(&mut g, &from, &k("n1"), &k("new phone"), &[k("old phone").hash]);
    g.device(&k("n1"), &k("tablet"), "tablet", |_| {});
    let twin = head_at(&g, 1, None, &k("n9"), [9; 32]);
    let mut old = set_of(&g.root.key);
    sync_all(&mut old, &g.recs, &g.lists);
    assert_eq!(old.insert(twin.clone()), Ok(Added::Stored));
    // The first root's key signs after the fork: not taken.
    let thief = g.device(&k("root"), &k("thief"), "thief", |_| {});
    assert_eq!(old.insert(thief), Ok(Added::Halted));
    let s = old.state();
    let head = s.changes.iter().map(|c| c.record).find(|id| *id != twin.id()).unwrap();
    let (a, b) = if head < twin.id() { (head, twin.id()) } else { (twin.id(), head) };
    assert_eq!(s.fork, Some((1, a, b)));
    assert_eq!(s.roots, vec![k("root").hash]);
    assert!(s.devices.is_empty());
    let mut all = g.recs.clone();
    all.push(twin);
    let fresh = set_with(&g.root.key, &all, &g.lists);
    assert_eq!(fresh.digest(), old.digest());
    assert_eq!(fresh.state(), s);
    // Every peer gets the two heads and nothing else.
    let me = crate::format::KeyHash(k("laptop").hash.0);
    for peer in ["thief", "tablet", "laptop", "old phone", "stranger"] {
        let p: [u8; 65] = k(peer).key.public.clone().try_into().unwrap();
        if peer != "laptop" {
            assert_eq!(crate::peer::standing(&s, &me, &p), crate::peer::Standing::Halted);
        }
        let ids: Vec<RecordId> = old.for_peer(&s, &k(peer).hash).iter().map(|r| r.id()).collect();
        assert_eq!(ids.iter().copied().collect::<BTreeSet<_>>(), BTreeSet::from([a, b]));
    }
}

/// After a fork at depth the state shows the roots below it and the
/// devices and removals of the list applied there; the last root's own
/// records do not show, its first records (its phone, the owner's
/// unticks) among them.
#[test]
fn a_fork_at_depth_shows_the_list_below_it() {
    let mut g = base();
    let from = g.recs.clone();
    write(&mut g, &from, &k("n1"), &k("new phone"), &[k("old phone").hash]);
    let from = g.recs.clone();
    write(&mut g, &from, &k("n2"), &k("phone 2"), &[k("new phone").hash]);
    let mut old = set_of(&g.root.key);
    sync_all(&mut old, &g.recs, &g.lists);
    let prev = old.state().chain().first().copied();
    let twin = head_at(&g, 2, prev, &k("n9"), [9; 32]);
    old.insert(twin.clone()).unwrap();
    let late = g.device(&k("n1"), &k("thief"), "thief", |_| {});
    assert_eq!(old.insert(late), Ok(Added::Halted));
    let s = old.state();
    assert!(s.halted());
    assert_eq!(s.fork.map(|f| f.0), Some(2));
    assert_eq!(s.roots, vec![k("root").hash, k("n1").hash]);
    let devices: BTreeSet<KeyHash> = s.devices.iter().map(|d| d.key.hash()).collect();
    assert_eq!(devices, BTreeSet::from([k("laptop").hash, k("tv").hash, k("old phone").hash]));
    let mut all = g.recs.clone();
    all.push(twin);
    let fresh = set_with(&g.root.key, &all, &g.lists);
    assert_eq!(fresh.digest(), old.digest());
    assert_eq!(fresh.state(), s);
}

/// A removal the list drops because no record the writer holds names its
/// key does not bring the key back, of the current root or of an earlier
/// one: the root's admission a peer offers after the change is off the
/// cut.
#[test]
fn a_dropped_removal_brings_no_root_admission_back() {
    for earlier in [false, true] {
        let mut g = base();
        let x = k("x");
        let admitted = g.device(&k("root"), &x, "x", |_| {});
        g.root_rec(Kind::Revoke(removal(&[x.hash], g.seen())));
        if earlier {
            let from = g.recs.clone();
            write(&mut g, &from, &k("n1"), &k("phone 1"), &[]);
        } else {
            // Something after the removal, so that the checkpoint's head
            // (listed as an anchor) is not the removal.
            g.device(&k("root"), &k("y"), "y", |_| {});
            let keep: Vec<Record> = g.recs.iter().filter(|r| r.id() != admitted.id()).cloned().collect();
            checkpoint_keeping(&mut g, &keep.iter().collect::<Vec<_>>());
        }
        // The writer holds no record naming x: its checkpoint pruned it,
        // or (an earlier root's) the writer never got it.
        let mut writer = set_of(&g.root.key);
        sync_all(&mut writer, &g.recs, &g.lists);
        assert_eq!(writer.contains(&admitted.id()), earlier);
        let from: Vec<Record> =
            writer.in_dependency_order().into_iter().filter(|r| r.id() != admitted.id()).cloned().collect();
        let writer = set_with(&g.root.key, &from, &g.lists);
        let w = write(&mut g, &from, &k("n2"), &k("phone 2"), &[]);
        assert!(!w.list.0.iter().any(|id| writer.get(id).is_some_and(|r| matches!(r.body().kind, Kind::Revoke(_)))));
        // A peer that kept the admission offers it after the change.
        let mut m = set_of(&g.root.key);
        sync_all(&mut m, &g.recs, &g.lists);
        let _ = m.insert(admitted.clone());
        let s = m.state();
        assert!(!has(&s, &x), "earlier {earlier}");
        let mut all = g.recs.clone();
        all.push(admitted.clone());
        assert!(!has(&set_with(&g.root.key, &all, &g.lists).state(), &x), "earlier {earlier}");
    }
}

/// The same for a key an admin that stays admitted, whose admission the
/// writer had pruned: the new root's first checkpoint turns the admission
/// away when a peer offers it after the change.
#[test]
fn a_dropped_removal_brings_no_admin_admission_back() {
    let mut g = base();
    let (pa, a, x) = (k("phone a"), k("admin a"), k("x"));
    g.admin(&pa, &a, POWER_ADMIT | POWER_REMOVE);
    let admitted = g.device(&a, &x, "x", |_| {});
    g.device(&a, &k("z"), "z", |_| {});
    g.root_rec(Kind::Revoke(removal(&[x.hash], g.seen())));
    g.device(&k("root"), &k("y"), "y", |_| {});
    let st = g.state();
    let (rs, rid) = g.heads[&k("root").hash];
    let (as_, aid) = g.heads[&a.hash];
    let mut heads = vec![Head { key: k("root").hash, seq: rs, id: rid }, Head { key: a.hash, seq: as_, id: aid }];
    heads.sort_by_key(|h| h.key);
    let mut keep: Vec<RecordId> =
        st.counting.iter().copied().filter(|id| *id != admitted.id() && *id != aid && *id != rid).collect();
    keep.sort();
    g.root_rec(Kind::Checkpoint { heads, keep });
    let mut writer = set_of(&g.root.key);
    sync_all(&mut writer, &g.recs, &g.lists);
    assert!(!writer.contains(&admitted.id()));
    let from: Vec<Record> = writer.in_dependency_order().into_iter().cloned().collect();
    let w = write(&mut g, &from, &k("n1"), &k("phone 1"), &[]);
    assert!(!w.list.0.iter().any(|id| writer.get(id).is_some_and(|r| matches!(r.body().kind, Kind::Revoke(_)))));
    assert!(has(&set_with(&g.root.key, &g.recs, &g.lists).state(), &pa));
    let mut m = set_of(&g.root.key);
    sync_all(&mut m, &g.recs, &g.lists);
    let _ = m.insert(admitted.clone());
    assert!(!has(&m.state(), &x));
    let mut all = g.recs.clone();
    all.push(admitted);
    assert!(!has(&set_with(&g.root.key, &all, &g.lists).state(), &x));
}

/// A head applies only once the member holds its list and the new root's
/// first checkpoint it names: with the head and the list alone the old
/// root stays, the old phone with it, and the member asks for the
/// checkpoint; when the first records come, the change applies at once.
#[test]
fn a_head_waits_for_the_new_roots_first_checkpoint() {
    let mut g = base();
    let from = g.recs.clone();
    let w = write(&mut g, &from, &k("n1"), &k("new phone"), &[k("old phone").hash]);
    let cp = w.first.last().unwrap().clone();
    assert!(matches!(&w.record.body().kind, Kind::Recovery { first, .. } if *first == cp.id()));
    let mut m = set_of(&g.root.key);
    sync_all(&mut m, &from, &[]);
    m.insert(w.record.clone()).unwrap();
    m.insert_list(&w.list.encode()).unwrap();
    let s = m.state();
    assert_eq!(s.roots, vec![k("root").hash]);
    assert_eq!(s.first_missing, Some(cp.id()));
    assert!(m.missing(&s).contains(&cp.id()));
    assert!(has(&s, &k("old phone")) && !has(&s, &k("new phone")));
    for r in &w.first {
        let _ = m.insert(r.clone());
    }
    let s = m.state();
    assert_eq!(s.roots, vec![k("root").hash, k("n1").hash]);
    assert_eq!(s.first_missing, None);
    assert!(has(&s, &k("new phone")) && !has(&s, &k("old phone")));
}

/// What a member keeps aside for a root whose change waits is part of the
/// set for sync: its IDs, its digest, what it holds when asked, and what
/// a device of the group gets, after the head that names the root. It
/// counts for nothing in the state until the change applies.
#[test]
fn what_waits_syncs_with_the_rest() {
    let mut g = base();
    let from = g.recs.clone();
    let w = write(&mut g, &from, &k("n1"), &k("new phone"), &[]);
    let mut head_only = set_of(&g.root.key);
    sync_all(&mut head_only, &from, &[]);
    head_only.insert(w.record.clone()).unwrap();
    let mut a = head_only.clone();
    for r in &w.first {
        assert_eq!(a.insert(r.clone()), Ok(Added::Waiting));
    }
    let st = a.state();
    assert_eq!(st.roots, vec![k("root").hash]);
    assert!(!has(&st, &k("new phone")));
    for r in &w.first {
        assert!(a.contains(&r.id()));
        assert_eq!(a.get(&r.id()), Some(r));
        assert!(a.ids().any(|id| *id == r.id()));
    }
    assert_ne!(a.digest(), head_only.digest());
    // Another member that took them in the other order holds the same.
    let mut b = set_of(&g.root.key);
    for r in w.first.iter().rev() {
        let _ = b.insert(r.clone());
    }
    sync_all(&mut b, &from, &[]);
    b.insert(w.record.clone()).unwrap();
    for r in w.first.iter().rev() {
        let _ = b.insert(r.clone());
    }
    assert_eq!(b.digest(), a.digest());
    assert_eq!(b.ids().collect::<Vec<_>>(), a.ids().collect::<Vec<_>>());
    // A device of the group gets them, each after the head.
    let sent = a.for_peer(&st, &k("laptop").hash);
    let at = |id: RecordId| sent.iter().position(|r| r.id() == id);
    let head = at(w.record.id()).unwrap();
    for r in &w.first {
        assert!(at(r.id()).is_some_and(|i| i > head));
    }
    // A member fed in that order takes them all, and the change applies
    // once the list comes.
    let mut c = set_of(&g.root.key);
    for r in sent {
        let _ = c.insert(r.clone());
    }
    assert_eq!(c.digest(), a.digest());
    c.insert_list(&w.list.encode()).unwrap();
    assert!(has(&c.state(), &k("new phone")));
}

/// A halted member restarted from what it saved (its records as it sends
/// them, then its lists) holds and shows what it did before, in that
/// order or reversed: after a fork at depth the list below it names the
/// records of the root before, its device record at seq 1 among them.
#[test]
fn a_halted_set_restores_from_what_it_saved() {
    let mut g = base();
    let from = g.recs.clone();
    write(&mut g, &from, &k("n1"), &k("new phone"), &[k("old phone").hash]);
    let from = g.recs.clone();
    write(&mut g, &from, &k("n2"), &k("phone 2"), &[]);
    let from = g.recs.clone();
    write(&mut g, &from, &k("n3"), &k("phone 3"), &[]);
    let mut old = set_of(&g.root.key);
    sync_all(&mut old, &g.recs, &g.lists);
    let prev = old.state().chain().get(1).copied();
    let twin = head_at(&g, 3, prev, &k("n9"), [9; 32]);
    old.insert(twin).unwrap();
    let s = old.state();
    assert!(s.halted());
    assert!(has(&s, &k("new phone")));
    let saved: Vec<Record> = old.in_dependency_order().into_iter().cloned().collect();
    let lists: Vec<Vec<u8>> = old.lists().map(<[u8]>::to_vec).collect();
    let mut reversed = saved.clone();
    reversed.reverse();
    for records in [saved, reversed] {
        let back = RecordSet::restore(g.root.key.clone(), k("recovery").key, &records, &lists);
        assert_eq!(back.ids().collect::<Vec<_>>(), old.ids().collect::<Vec<_>>());
        assert_eq!(back.digest(), old.digest());
        assert_eq!(back.state(), s);
    }
}

/// A recovery record off the chain (here one past a gap) has nothing kept
/// aside: its root's records are not taken. The
/// chain's next record, waiting for its list, has its root's records kept
/// aside.
#[test]
fn a_head_off_the_chain_keeps_nothing_aside() {
    let mut g = base();
    let from = g.recs.clone();
    let w1 = write(&mut g, &from, &k("n1"), &k("new phone"), &[]);
    let mut m = set_of(&g.root.key);
    sync_all(&mut m, &from, &[]);
    // Seq 2 with no seq 1 held: off the chain.
    let gap = head_at(&g, 2, Some(w1.record.id()), &k("n9"), [9; 32]);
    m.insert(gap).unwrap();
    let of_n9 = g.device(&k("n9"), &k("n9 phone"), "n9 phone", |_| {});
    assert!(matches!(m.insert(of_n9.clone()), Ok(Added::NoRoom) | Err(Refused::UnknownSigner)));
    assert!(!m.contains(&of_n9.id()));
    assert_eq!(m.aside().count(), 0);
    // The chain's first record, without its list: what its root signed
    // waits aside.
    m.insert(w1.record.clone()).unwrap();
    for r in &w1.first {
        assert_eq!(m.insert(r.clone()), Ok(Added::Waiting));
    }
    assert_eq!(m.aside().count(), w1.first.len());
}

/// When a later change applies, the earlier root's first checkpoint is
/// not kept any more: the set keeps the newest applied record's first.
#[test]
fn an_earlier_first_goes_when_a_later_change_applies() {
    let mut g = base();
    let from = g.recs.clone();
    let w1 = write(&mut g, &from, &k("n1"), &k("new phone"), &[]);
    let from = g.recs.clone();
    let w2 = write(&mut g, &from, &k("n2"), &k("phone 2"), &[]);
    let (cp1, cp2) = (w1.first.last().unwrap().id(), w2.first.last().unwrap().id());
    let mut m = set_of(&g.root.key);
    sync_all(&mut m, &g.recs, &g.lists);
    let s = m.state();
    assert_eq!(s.roots, vec![k("root").hash, k("n1").hash, k("n2").hash]);
    assert!(!m.contains(&cp1));
    assert!(m.contains(&cp2));
    let fresh = set_with(&g.root.key, &g.recs, &g.lists);
    assert_eq!(fresh.digest(), m.digest());
}

/// The records of a root whose recovery record came before the record it
/// follows are not taken at first, and taken once it is on the chain: a
/// member that got them in that order ends as one that got them in order.
#[test]
fn records_of_a_late_chain_record_are_taken_when_it_joins() {
    let mut g = base();
    let from = g.recs.clone();
    let w1 = write(&mut g, &from, &k("n1"), &k("new phone"), &[]);
    let from = g.recs.clone();
    let w2 = write(&mut g, &from, &k("n2"), &k("phone 2"), &[]);
    let mut early = set_of(&g.root.key);
    early.insert(w2.record.clone()).unwrap();
    for r in &w2.first {
        assert!(matches!(early.insert(r.clone()), Ok(Added::NoRoom) | Err(Refused::UnknownSigner)));
        assert!(!early.contains(&r.id()));
    }
    sync_all(&mut early, &g.recs, &g.lists);
    let fresh = set_with(&g.root.key, &g.recs, &g.lists);
    assert_eq!(early.digest(), fresh.digest());
    assert_eq!(early.state(), fresh.state());
    assert!(has(&early.state(), &k("phone 2")));
    let _ = w1;
}

/// A new root's first checkpoint over the 64 KiB a checkpoint once had
/// (the whole list and what the old root's checkpoint kept of 256 devices'
/// admins) is signed and taken, and the change applies.
#[test]
fn a_large_first_checkpoint_applies() {
    let mut g = base();
    let admins: Vec<K> = (0..6).map(|i| k(&format!("admin {i}"))).collect();
    for (i, a) in admins.iter().enumerate() {
        g.admin(&k(&format!("admin device {i}")), a, POWER_ADMIT | POWER_MANAGE);
    }
    for a in &admins {
        for _ in 0..240 {
            g.rec(a, Kind::Copies { incoming_ms: MIN_INCOMING_MS, seen: vec![] });
        }
    }
    for _ in 0..560 {
        g.root_rec(Kind::Copies { incoming_ms: MIN_INCOMING_MS, seen: vec![] });
    }
    let set = set_with(&g.root.key, &g.recs, &g.lists);
    let mut keep: Vec<RecordId> = set
        .ids()
        .filter(|id| set.get(id).is_some_and(|r| admins.iter().any(|a| a.hash == r.body().signer)))
        .copied()
        .collect();
    keep.sort();
    let mut heads: Vec<Head> =
        admins.iter().map(|a| Head { key: a.hash, seq: g.heads[&a.hash].0, id: g.heads[&a.hash].1 }).collect();
    heads.sort_by_key(|h| h.key);
    let cp = g.root_rec(Kind::Checkpoint { heads, keep });
    let from = g.recs.clone();
    assert_eq!(set_with(&g.root.key, &from, &g.lists).state().checkpoint, Some(cp.id()));
    let w = write(&mut g, &from, &k("n1"), &k("new phone"), &[]);
    let first = w.first.last().unwrap();
    assert!(first.body_bytes().len() > 64 << 10, "{}", first.body_bytes().len());
    let m = set_with(&g.root.key, &g.recs, &g.lists);
    assert!(m.contains(&first.id()));
    assert!(has(&m.state(), &k("new phone")));
}

/// A checkpoint over its ceiling is not signed.
#[test]
fn a_checkpoint_over_its_ceiling_is_not_signed() {
    let g = base();
    let mut keep: Vec<RecordId> = (0..5000u32).map(|i| RecordId(crate::certs::sha256(&i.to_be_bytes()))).collect();
    keep.sort();
    let root = k("root");
    let head = Head { key: root.hash, seq: g.heads[&root.hash].0, id: g.heads[&root.hash].1 };
    let body = g.body(&root, Kind::Checkpoint { heads: vec![head], keep });
    assert!(body.encode().len() > crate::records::MAX_CHECKPOINT_BODY);
    assert!(Record::sign(body, &root).is_err());
}

/// A halted state is for display only: it shows the devices of the list
/// below the stop, and nothing acts on them. No key commands, nobody
/// admits, the holder sends no request to anyone and an admin takes none,
/// every other peer stands as halted, and the writer writes no change.
#[test]
fn a_halted_state_is_for_display_only() {
    use crate::join::decide::{Signer, may_admit};
    use crate::join::waiting::{admin_may_take, holder_may_send};
    let mut g = base();
    g.device(&k("root"), &k("hub"), "hub", |d| d.rights |= RIGHT_HUB);
    let from = g.recs.clone();
    write(&mut g, &from, &k("n1"), &k("new phone"), &[]);
    let from = g.recs.clone();
    write(&mut g, &from, &k("n2"), &k("phone 2"), &[]);
    let mut m = set_of(&g.root.key);
    sync_all(&mut m, &g.recs, &g.lists);
    let live = m.state();
    let hub = live.device_by_key(&k("hub").hash).unwrap().id;
    assert!(admin_may_take(&live, &hub));
    let prev = live.chain().first().copied();
    m.insert(head_at(&g, 2, prev, &k("n9"), [9; 32])).unwrap();
    let s = m.state();
    assert!(s.halted());
    assert!(s.device(&hub).is_some(), "the halted state still shows the devices");
    for key in ["root", "n1", "n2"] {
        assert!(!s.may_command(&k(key).hash), "{key}");
    }
    let f = |h: KeyHash| crate::format::KeyHash(h.0);
    let n1 = f(k("n1").hash);
    assert!(!may_admit(&s, &n1, Signer::Root, &n1));
    for d in &s.devices {
        assert!(!holder_may_send(&s, &d.id));
        assert!(!admin_may_take(&s, &d.id));
        let p: [u8; 65] = d.key.public.clone().try_into().unwrap();
        if d.key.hash() != k("laptop").hash {
            assert_eq!(crate::peer::standing(&s, &f(k("laptop").hash), &p), crate::peer::Standing::Halted);
        }
    }
    let err = m.write_change(&s, &k("recovery"), &k("n3"), phone(&k("p3")), &[], false, 0).unwrap_err();
    assert_eq!(err.to_string(), crate::records::set::CHANGE_WAITING);
}

/// Nothing computed while halted is carried over: a member that halted
/// and restarts from what it saved, without the record that halted it (as
/// a version that reads it would apply it), and takes again from a peer
/// what the halt dropped, ends as a member that never saw it.
#[test]
fn leaving_a_halt_carries_nothing_over() {
    let mut g = base();
    let from = g.recs.clone();
    write(&mut g, &from, &k("n1"), &k("new phone"), &[k("old phone").hash]);
    let from = g.recs.clone();
    write(&mut g, &from, &k("n2"), &k("phone 2"), &[]);
    let mut m = set_of(&g.root.key);
    sync_all(&mut m, &g.recs, &g.lists);
    let prev = m.state().chain().first().copied();
    let twin = head_at(&g, 2, prev, &k("n9"), [9; 32]);
    m.insert(twin.clone()).unwrap();
    assert!(m.state().halted());
    assert!(m.len() < g.recs.len(), "the halt dropped records");
    let mut saved: Vec<Record> = m.in_dependency_order().into_iter().filter(|r| r.id() != twin.id()).cloned().collect();
    saved.extend(g.recs.iter().cloned());
    let lists: Vec<Vec<u8>> = m.lists().map(<[u8]>::to_vec).collect();
    let back = RecordSet::restore(g.root.key.clone(), k("recovery").key, &saved, &lists);
    let never = set_with(&g.root.key, &g.recs, &g.lists);
    assert_eq!(back.digest(), never.digest());
    assert_eq!(back.state(), never.state());
    assert!(has(&back.state(), &k("phone 2")));
}

/// A full set names more IDs than its rooms hold: besides 4096 records in
/// the rooms it holds the recovery chain and what a waiting root signed,
/// kept aside. A message that names every ID the set holds (`have`,
/// `records`) must allow for them.
#[test]
fn a_full_set_names_more_ids_than_its_rooms_hold() {
    let mut g = base();
    let root = k("root");
    let admins: Vec<K> = (0..12).map(|i| k(&format!("admin {i}"))).collect();
    for (i, a) in admins.iter().enumerate() {
        g.admin(&k(&format!("admin device {i}")), a, POWER_ADMIT | POWER_MANAGE);
    }
    for a in &admins {
        for _ in 0..MAX_ADMIN_RECORDS {
            g.rec(a, Kind::Copies { incoming_ms: MIN_INCOMING_MS, seen: vec![] });
        }
    }
    while g.heads[&root.hash].0 < MAX_ROOT_RECORDS as u64 {
        g.root_rec(Kind::Copies { incoming_ms: MIN_INCOMING_MS, seen: vec![] });
    }
    let from = g.recs.clone();
    let mut m = set_of(&g.root.key);
    m.insert_all(from.iter().cloned());
    assert_eq!(m.len(), crate::records::MAX_RECORDS);
    let w = write(&mut g, &from, &k("n1"), &k("new phone"), &[]);
    m.insert(w.record.clone()).unwrap();
    let n1 = k("n1");
    for r in &w.first {
        assert_eq!(m.insert(r.clone()), Ok(Added::Waiting));
    }
    for _ in 0..64 {
        let r = g.rec(&n1, Kind::Copies { incoming_ms: MIN_INCOMING_MS, seen: vec![] });
        assert_eq!(m.insert(r), Ok(Added::Waiting));
    }
    let n = m.ids().count();
    assert!(n > crate::format::cbor::MAX_COUNT, "{n}");
}
