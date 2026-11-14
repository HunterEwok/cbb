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
    let mut set = set_with(&g.root.key, from, &g.lists);
    let st = set.state();
    let w = set
        .write_change(&st, &k("recovery"), crate::testkit::rk2(), new_root, phone(member), remove, false, 0)
        .unwrap();
    for r in &w.first {
        g.push(r.clone());
    }
    g.push(w.record.clone());
    g.lists.push(w.list.encode());
    w
}

/// Whether a change carries the removal rm: in its list, or re-issued
/// by the new root among its first records (keys and seen alike).
fn carried(w: &Written, rm: &Record) -> bool {
    let Kind::Revoke(x) = &rm.body().kind else { return false };
    w.list.0.contains(&rm.id())
        || w.first.iter().any(|z| {
            matches!(&z.body().kind, Kind::Revoke(z) if x.keys.iter().all(|k| z.keys.contains(k))
                && x.seen.iter().all(|s| z.seen.contains(s)))
        })
}

/// A head at seq of the recovery key naming root, with prev and list as
/// given, whatever the chain holds.
fn head_at(g: &G, seq: u64, prev: Option<RecordId>, root: &K, list: [u8; 32]) -> Record {
    let body = Body {
        seq,
        prev,
        ..g.body(
            &k("recovery"),
            Kind::Recovery {
                root: root.key.clone(),
                list,
                from: 0,
                first: RecordId([0xf1; 32]),
                signer2: crate::testkit::rk2().key().hash(),
            },
        )
    };
    crate::testkit::sign_by(body, &k("recovery"))
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

/// The state without what it ignored: a member that holds a record the
/// change cut lists it there, one that never had it does not.
fn unignored(mut s: State) -> State {
    s.ignored.clear();
    s
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
        let mut set = set_with(&g.root.key, &g.recs, &g.lists);
        let st = set.state();
        assert!(
            set.write_change(&st, &k("recovery"), crate::testkit::rk2(), &k("n5"), phone(&k("p5")), &[], false, 0)
                .is_err()
        );
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
        Kind::Recovery {
            root: k("n2").key.clone(),
            list: [5; 32],
            from: 0,
            first: RecordId([0xf1; 32]),
            signer2: crate::testkit::rk2().key().hash(),
        },
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
    let st = m.state();
    assert_eq!(m.notices(&st), vec![(rv.id(), vec![k("tv").hash])]);
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
    let rm = g.recs.iter().find(|r| matches!(&r.body().kind, Kind::Revoke(x) if x.keys == [k("laptop").hash])).unwrap();
    assert!(carried(&w, rm), "the thief's removal is neither listed nor re-issued");
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
    g.rec(
        &k("recovery"),
        Kind::Recovery {
            root: k("n1").key.clone(),
            list: h,
            from: 0,
            first,
            signer2: crate::testkit::rk2().key().hash(),
        },
    );
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

/// At most MAX_RECOVERY (64) heads for the group's life: the next is not
/// signed, not stored, and a writer at the cap refuses.
#[test]
fn at_most_max_recovery_heads() {
    let mut g = base();
    let max = crate::records::body::MAX_RECOVERY;
    for i in 1..=max {
        let list = g.listing();
        g.change(&k(&format!("n{i}")), &list);
    }
    let s = g.state();
    assert_eq!(s.roots.len() as u64, max + 1);
    let (_, tip) = g.heads[&rk().hash()];
    let body = Body {
        seq: max + 1,
        prev: Some(tip),
        ..g.body(
            &k("recovery"),
            Kind::Recovery {
                root: k(&format!("n{}", max + 1)).key,
                list: [1; 32],
                from: 0,
                first: RecordId([0xf1; 32]),
                signer2: crate::testkit::rk2().key().hash(),
            },
        )
    };
    assert!(Record::sign(body.clone(), &k("recovery")).is_err());
    let mut set = set_with(&g.root.key, &g.recs, &g.lists);
    let st = set.state();
    assert!(
        set.write_change(
            &st,
            &k("recovery"),
            crate::testkit::rk2(),
            &k(&format!("n{}", max + 1)),
            phone(&k(&format!("p{}", max + 1))),
            &[],
            false,
            0
        )
        .is_err()
    );
}

/// A head naming an admin's key as the root: the chain wins, and what that
/// key signed as an admin counts only if listed. The core's writer
/// refuses a key its state knows.
#[test]
fn an_admin_key_named_as_the_root() {
    let mut g = base();
    g.admin(&k("phone a"), &k("admin a"), POWER_ADMIT);
    let by_admin = g.device(&k("admin a"), &k("lamp"), "lamp", |_| {});
    let mut set = set_with(&g.root.key, &g.recs, &g.lists);
    let st = set.state();
    assert!(
        set.write_change(&st, &k("recovery"), crate::testkit::rk2(), &k("admin a"), phone(&k("p")), &[], false, 0)
            .is_err()
    );
    assert!(
        set.write_change(&st, &k("recovery"), crate::testkit::rk2(), &k("laptop"), phone(&k("p")), &[], false, 0)
            .is_err()
    );
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
        Kind::Recovery {
            root: k("n9").key.clone(),
            list: [1; 32],
            from: 0,
            first: RecordId([0xf1; 32]),
            signer2: crate::testkit::rk2().key().hash(),
        },
        |m| m.push((12, crate::format::cbor::Value::Uint(0))),
    );
    assert_eq!(r.map(|_| ()).unwrap_err(), Rule::new("form/default"));
    let body = g.body(
        &k("recovery"),
        Kind::Recovery {
            root: k("n9").key.clone(),
            list: [1; 32],
            from: MAX_SEQ + 1,
            first: RecordId([0xf1; 32]),
            signer2: crate::testkit::rk2().key().hash(),
        },
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
    let held = set_with(&g.root.key, &g.recs, &g.lists);
    let mut set = held.clone();
    let st = set.state();
    let w = set
        .write_change(
            &st,
            &k("recovery"),
            crate::testkit::rk2(),
            &k("n1"),
            phone(&k("new phone")),
            &[k("old phone").hash],
            false,
            7,
        )
        .unwrap();
    assert!(!w.again && set.contains(&w.record.id()));
    let kinds: Vec<&Kind> = w.first.iter().map(|r| &r.body().kind).collect();
    assert!(matches!(kinds[0], Kind::Device(d) if d.holds_root && d.key == k("new phone").key));
    assert!(kinds.iter().any(|k| matches!(k, Kind::Settings(s) if s.min_rules == 2)));
    assert!(kinds.iter().any(|k| matches!(k, Kind::Hubs { .. })));
    assert!(kinds.iter().any(|kd| matches!(kd, Kind::Revoke(r) if r.keys == vec![k("old phone").hash])));
    assert!(w.first.iter().all(|r| r.body().signer == k("n1").hash));
    assert!(matches!(&w.record.body().kind, Kind::Recovery { list, .. } if *list == w.list.hash()));
    assert_eq!((w.record.body().seq, w.record.body().prev), (1, None));
    // Asked again, with other ticks: the change it holds, signed once.
    let again = set
        .write_change(&st, &k("recovery"), crate::testkit::rk2(), &k("n1"), phone(&k("new phone")), &[], true, 7)
        .unwrap();
    assert!(again.again && again.record.id() == w.record.id());
    // A writer that never wrote one drops the hubs record when asked.
    let mut other = held.clone();
    let dropped = other
        .write_change(&st, &k("recovery"), crate::testkit::rk2(), &k("n1"), phone(&k("new phone")), &[], true, 7)
        .unwrap();
    assert!(!dropped.first.iter().any(|r| matches!(r.body().kind, Kind::Hubs { .. })));
    let mut other = held.clone();
    assert!(
        other
            .write_change(
                &st,
                &k("not the key"),
                crate::testkit::rk2(),
                &k("n1"),
                phone(&k("new phone")),
                &[],
                false,
                7
            )
            .is_err()
    );
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
    let other = Recovery { k1: k("other").key, ..rk() };
    assert!(RecordSet::pinned(root.clone(), other, &local, &mark).is_none());
    let other2 = Recovery { k2: crate::records::pq::PqKey::from_seeds(&[9; 16], &[9; 16], &[9; 16]).key(), ..rk() };
    assert!(RecordSet::pinned(root.clone(), other2, &local, &mark).is_none());
    assert!(RecordSet::pinned(k("root 2").key, rk(), &local, &mark).is_none());
    assert!(RecordSet::pinned(root, rk(), &[4u8; 32], &mark).is_none());
}

/// The Group ID commits to the root and both halves of the recovery key.
#[test]
fn the_group_id_commits_to_both_keys() {
    let root = k("root").key;
    assert_ne!(group_id(&root, &rk()), group_id(&root, &Recovery { k1: k("other").key, ..rk() }));
    let k2 = crate::records::pq::PqKey::from_seeds(&[9; 16], &[9; 16], &[9; 16]).key();
    assert_ne!(group_id(&root, &rk()), group_id(&root, &Recovery { k2, ..rk() }));
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
    let (fetch, fetch2) = crate::records::sign_fetch(&k("recovery"), crate::testkit::rk2(), &body).unwrap();
    assert_eq!(crate::records::verify_fetch(&rk(), &body, &fetch, &fetch2), Ok(()));
    // The fetch signatures on the head's body are not the head.
    let forged = Record::decode(&crate::format::envelope::write(&body, &fetch, Some(&fetch2))).unwrap();
    assert!(forged.verify_head(&rk()).is_err());
    let mut set = set_of(&g.root.key);
    assert!(set.insert(forged).is_err());
    // The head's signatures are no fetch proof, nor half of one.
    let head2 = head.sig2().unwrap();
    assert!(crate::records::verify_fetch(&rk(), &body, head.sig(), head2).is_err());
    assert!(crate::records::verify_fetch(&rk(), &body, &fetch, head2).is_err());
    assert!(crate::records::verify_fetch(&rk(), &body, head.sig(), &fetch2).is_err());
    assert_eq!(head.verify_head(&rk()), Ok(false));
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
    let err = set
        .write_change(&st, &k("recovery"), crate::testkit::rk2(), &k("n2"), phone(&k("p2")), &[], false, 0)
        .unwrap_err();
    assert_eq!(err.to_string(), crate::records::set::CHANGE_WAITING);
    for l in &g.lists {
        set.insert_list(l).unwrap();
    }
    let st = set.state();
    assert!(has(&st, &k("p1")) && st.roots.len() == 2);
    assert!(w1.first.iter().all(|r| set.contains(&r.id())));
    let w2 =
        set.write_change(&st, &k("recovery"), crate::testkit::rk2(), &k("n2"), phone(&k("p2")), &[], false, 0).unwrap();
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
        let mut set = set_with(&g.root.key, &g.recs, lists);
        let st = set.state();
        set.write_change(&st, &k("recovery"), crate::testkit::rk2(), &k("n9"), phone(&k("p9")), &[], false, 0)
            .err()
            .map(|e| e.to_string())
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
        Kind::Recovery {
            root: k("n1").key.clone(),
            list: [5; 32],
            from: 0,
            first: RecordId([0xf1; 32]),
            signer2: crate::testkit::rk2().key().hash(),
        },
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
    let mut set = set_with(&g.root.key, &g.recs, &g.lists);
    let st = set.state();
    let mut w = |dev: &K, remove: &[KeyHash]| {
        set.write_change(&st, &k("recovery"), crate::testkit::rk2(), &k("n1"), phone(dev), remove, false, 0)
    };
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

/// A change's list carries every counting removal of the earlier roots,
/// also of a key no record the writer holds names (the writer may lack its
/// admission); of removals that name the same keys and saw the same, the
/// newest alone (the fold).
#[test]
fn a_change_lists_every_removal_that_counts() {
    let mut g = base();
    let ghosts: Vec<RecordId> = (0..40u32)
        .map(|i| g.root_rec(Kind::Revoke(removal(&[KeyHash(sha256(&i.to_be_bytes()))], vec![]))).id())
        .collect();
    let tv = k("tv");
    let of_tv: Vec<RecordId> = (0..300).map(|_| g.root_rec(Kind::Revoke(removal(&[tv.hash], vec![]))).id()).collect();
    let list = g.listing();
    let newest = *of_tv.last().unwrap();
    assert!(of_tv.iter().all(|id| list.contains(id) == (*id == newest)));
    assert!(ghosts.iter().all(|id| list.contains(id)));
    g.change(&k("n1"), &list);
    // The new root admits the tv again; a second change follows.
    g.device(&k("n1"), &tv, "tv", |_| {});
    let list = g.listing();
    assert!(ghosts.iter().all(|id| list.contains(id)));
    let listed: Vec<&RecordId> = of_tv.iter().filter(|id| list.contains(id)).collect();
    assert_eq!(listed, vec![&newest]);
    // Removals of different keys each keep their place, however many.
    let mut g = base();
    let devs: Vec<K> = (0..300).map(|i| k(&format!("dev {i}"))).collect();
    let rms: Vec<RecordId> = devs
        .iter()
        .map(|d| {
            g.device(&k("root"), d, "d", |_| {});
            g.root_rec(Kind::Revoke(removal(&[d.hash], vec![]))).id()
        })
        .collect();
    let list = g.listing();
    g.change(&k("n1"), &list);
    g.device(&k("n1"), &k("tv 2"), "tv", |_| {});
    let list = g.listing();
    assert!(rms.iter().all(|id| list.contains(id)));
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
        let p: [u8; 65] = k(peer).key.public().to_vec().try_into().unwrap();
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
        let back = RecordSet::restore(g.root.key.clone(), rk(), &records, &lists);
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
    for _ in 0..560 {
        g.root_rec(Kind::Copies { incoming_ms: MIN_INCOMING_MS, seen: vec![] });
    }
    let set = set_with(&g.root.key, &g.recs, &g.lists);
    let mut keep: Vec<RecordId> = set
        .ids()
        .filter(|id| set.get(id).is_some_and(|r| admins.iter().any(|a| a.hash == r.body().signer)))
        .copied()
        .chain(grants.iter().map(Record::id))
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
    let mut keep: Vec<RecordId> = (0..9000u32).map(|i| RecordId(crate::certs::sha256(&i.to_be_bytes()))).collect();
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
        let p: [u8; 65] = d.key.public().to_vec().try_into().unwrap();
        if d.key.hash() != k("laptop").hash {
            assert_eq!(crate::peer::standing(&s, &f(k("laptop").hash), &p), crate::peer::Standing::Halted);
        }
    }
    // Two changes at one seq: the writer says the group stopped for good,
    // not that a change waits for a sync.
    let err = m
        .write_change(&s, &k("recovery"), crate::testkit::rk2(), &k("n3"), phone(&k("p3")), &[], false, 0)
        .unwrap_err();
    assert_eq!(err.to_string(), crate::records::set::CHANGE_STOPPED);
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
    let back = RecordSet::restore(g.root.key.clone(), rk(), &saved, &lists);
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
    let admins: Vec<K> = (0..crate::records::ADMIN_KEYS_MAX).map(|i| k(&format!("admin {i}"))).collect();
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
    // The current root and every admin key full: the cut roots' reserve
    // is the rest of the room.
    assert_eq!(m.len(), crate::records::MAX_RECORDS - crate::records::CUT_ROOTS_RESERVE);
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
    // More IDs than the old profile's 4096 items, and they go as one
    // array: the profile's count holds them.
    let ids: Vec<crate::format::Value> = m.ids().map(|id| crate::format::Value::Bytes(&id.0[..])).collect();
    assert!(ids.len() > 4096, "{}", ids.len());
    let one = crate::format::Value::Array(ids).encode();
    assert_eq!(
        crate::format::cbor::decode(&one).ok().and_then(|v| v.as_array().map(<[_]>::len)),
        Some(m.ids().count())
    );
}

/// A group of 250 admin keys, each of which has signed.
fn many_admins() -> (G, Vec<K>) {
    let mut g = base();
    let admins: Vec<K> = (0..250).map(|i| k(&format!("admin {i}"))).collect();
    for (i, a) in admins.iter().enumerate() {
        g.admin(&k(&format!("admin device {i}")), a, POWER_ADMIT | POWER_MANAGE);
        g.rec(a, Kind::Copies { incoming_ms: MIN_INCOMING_MS, seen: vec![] });
    }
    (g, admins)
}

/// The removals of a writer's change name in `seen` only the keys they
/// concern, the removed keys and their admin or member key: removing a
/// plain device names none and weighs one unit, removing an admin's
/// device names its admin key, and removing 256 keys of a group of 250
/// devices made admins (of which 16, the cap, count) fits, in as many
/// records as their bodies need.
#[test]
fn removals_name_only_the_keys_they_concern() {
    let (g, admins) = many_admins();
    let set = set_with(&g.root.key, &g.recs, &g.lists);
    let st = set.state();
    // Each from a writer that holds no change yet.
    let removals = |remove: &[KeyHash]| -> Vec<Removal> {
        let w = set
            .clone()
            .write_change(
                &st,
                &k("recovery"),
                crate::testkit::rk2(),
                &k("n1"),
                phone(&k("new phone")),
                remove,
                false,
                0,
            )
            .unwrap();
        w.first
            .iter()
            .filter_map(|r| match &r.body().kind {
                Kind::Revoke(rm) => {
                    assert!(r.body_bytes().len() <= crate::records::MAX_BODY);
                    if rm.seen.is_empty() && rm.keys.len() == 1 {
                        assert_eq!(crate::records::keep::units(r.size()), 1);
                    }
                    Some(rm.clone())
                }
                _ => None,
            })
            .collect()
    };
    let plain = removals(&[k("laptop").hash]);
    assert_eq!(plain.len(), 1);
    assert!(plain[0].seen.is_empty());
    let one = removals(&[k("admin device 7").hash]);
    assert_eq!(one.len(), 1);
    assert_eq!(one[0].seen.iter().map(|s| s.key).collect::<Vec<_>>(), vec![admins[7].hash]);
    let mut many: Vec<KeyHash> = (0..250).map(|i| k(&format!("admin device {i}")).hash).collect();
    many.extend([k("laptop").hash, k("tv").hash]);
    many.extend((0..4).map(|i| k(&format!("stranger {i}")).hash));
    assert_eq!(many.len(), 256);
    let all = removals(&many);
    assert!(!all.is_empty());
    let mut named: Vec<KeyHash> = all.iter().flat_map(|rm| rm.keys.iter().copied()).collect();
    named.sort();
    many.sort();
    assert_eq!(named, many);
}

/// A key a removal does not name is untouched: two members that held
/// different heads of an admin key when the change was written, and then
/// take the same records, end the same, and that key's newest record
/// counts.
#[test]
fn a_key_a_removal_does_not_name_is_untouched() {
    let (mut g, admins) = many_admins();
    let x = &admins[3];
    let from = g.recs.clone();
    let later = g.rec(x, Kind::Copies { incoming_ms: MIN_INCOMING_MS + 1, seen: vec![] });
    let w = write(&mut g, &from, &k("n1"), &k("new phone"), &[k("laptop").hash]);
    let mut a = set_of(&g.root.key);
    sync_all(&mut a, &g.recs, &g.lists);
    let mut b = set_of(&g.root.key);
    let mut rev = g.recs.clone();
    rev.reverse();
    sync_all(&mut b, &rev, &g.lists);
    assert_eq!(a.digest(), b.digest());
    let s = a.state();
    assert_eq!(s, b.state());
    assert!(s.counting.contains(&later.id()));
    assert!(!has(&s, &k("laptop")) && has(&s, &k("new phone")));
    let _ = w;
}

/// What a member keeps aside for a root only a waiting head names reads
/// the same in the set and in evaluate of what it holds: neither counted
/// nor ignored, and naming no device.
#[test]
fn a_waiting_roots_records_read_alike_in_the_set_and_evaluate() {
    let mut g = base();
    let from = g.recs.clone();
    let w = write(&mut g, &from, &k("n1"), &k("new phone"), &[]);
    // The list has not come: the head waits, the new root's records with it.
    let mut m = set_of(&g.root.key);
    sync_all(&mut m, &from, &[]);
    m.insert(w.record.clone()).unwrap();
    for r in &w.first {
        assert_eq!(m.insert(r.clone()), Ok(Added::Waiting));
    }
    let held: Vec<Record> = m.ids().map(|id| m.get(id).unwrap().clone()).collect();
    let lists: Vec<Vec<u8>> = m.lists().map(<[u8]>::to_vec).collect();
    let set = m.state();
    let eval = state_with(&g.root.key, &held, &lists);
    assert_eq!(set, eval);
    for r in &w.first {
        assert!(!eval.ignored.iter().any(|i| i.record == r.id()));
    }
    assert!(!has(&eval, &k("new phone")));
}

/// The new root's record at the head's `from` starts its line: it counts
/// with any prev, here a record of its own below `from` the list leaves
/// out, and the records above it count by it, whether or not the member
/// ever held the one below, in both orders.
#[test]
fn the_record_at_from_starts_the_new_roots_line() {
    let mut g = base();
    g.admin(&k("phone a"), &k("admin a"), POWER_ADMIT);
    let lamp = g.device(&k("admin a"), &k("lamp"), "lamp", |_| {});
    let (seq, _) = g.heads[&k("admin a").hash];
    let list = g.listing();
    assert!(!list.contains(&lamp.id()));
    g.change_from(&k("admin a"), &list, seq + 1);
    let kettle = g.device(&k("admin a"), &k("kettle"), "kettle", |_| {});
    let without: Vec<Record> = g.recs.iter().filter(|r| r.id() != lamp.id()).cloned().collect();
    let want = state_with(&g.root.key, &g.recs, &g.lists);
    assert!(has(&want, &k("kettle")) && !has(&want, &k("lamp")));
    assert!(want.ignored.iter().any(|i| i.record == lamp.id()), "held, and cut");
    assert_eq!(unignored(want.clone()), unignored(state_with(&g.root.key, &without, &g.lists)));
    for recs in [&g.recs, &without] {
        for order in 0..2 {
            let mut recs = recs.clone();
            if order == 1 {
                recs.reverse();
            }
            let mut m = set_of(&g.root.key);
            sync_all(&mut m, &recs, &g.lists);
            let s = m.state();
            assert_eq!(s.roots.last(), Some(&k("admin a").hash));
            assert!(has(&s, &k("kettle")), "order {order}");
            assert!(!has(&s, &k("lamp")));
            assert!(m.contains(&kettle.id()));
        }
    }
}

/// A new root's checkpoint that keeps a record the change cut (its own
/// below `from`, not listed) does not count, whether or not the member
/// holds that record: the two members end equal.
#[test]
fn a_checkpoint_keeping_what_the_change_cut_counts_nowhere() {
    let mut g = base();
    g.admin(&k("phone a"), &k("admin a"), POWER_ADMIT);
    let lamp = g.device(&k("admin a"), &k("lamp"), "lamp", |_| {});
    let (seq, _) = g.heads[&k("admin a").hash];
    let tv =
        g.recs.iter().find(|r| matches!(&r.body().kind, Kind::Device(d) if d.key.hash() == k("tv").hash)).unwrap().id();
    let list = g.listing();
    assert!(list.contains(&tv));
    // Its first checkpoint keeps the list without the TV, and the lamp.
    let mut keep: Vec<RecordId> = list.iter().copied().filter(|id| *id != tv).chain([lamp.id()]).collect();
    keep.sort();
    let (rs, rid) = g.heads[&g.root.hash];
    let cp = g.rec(&k("admin a"), Kind::Checkpoint { heads: vec![Head { key: g.root.hash, seq: rs, id: rid }], keep });
    let l = List(list.clone());
    g.lists.push(l.encode());
    g.rec(
        &k("recovery"),
        Kind::Recovery {
            root: k("admin a").key.clone(),
            list: l.hash(),
            from: seq + 1,
            first: cp.id(),
            signer2: crate::testkit::rk2().key().hash(),
        },
    );
    let without: Vec<Record> = g.recs.iter().filter(|r| r.id() != lamp.id()).cloned().collect();
    let all = state_with(&g.root.key, &g.recs, &g.lists);
    assert_eq!(unignored(all.clone()), unignored(state_with(&g.root.key, &without, &g.lists)));
    assert_eq!(all.roots.last(), Some(&k("admin a").hash));
    assert!(has(&all, &k("tv")));
    for recs in [&g.recs, &without] {
        let mut m = set_of(&g.root.key);
        sync_all(&mut m, recs, &g.lists);
        assert!(has(&m.state(), &k("tv")));
    }
}

/// The old root's removals the writer lacked, whichever way they reach a
/// member: held at the change, or coming after it. Both members keep the
/// same notices, and the notice goes once the new root removes the key
/// again.
#[test]
fn a_late_removal_is_a_notice_and_goes_when_the_key_is_removed_again() {
    let mut g = base();
    let seen = g.seen();
    let rv = g.root_rec(Kind::Revoke(removal(&[k("tv").hash], seen)));
    let from: Vec<Record> = g.recs.iter().filter(|r| r.id() != rv.id()).cloned().collect();
    write(&mut g, &from, &k("n1"), &k("new phone"), &[]);
    let mut held = set_of(&g.root.key);
    sync_all(&mut held, &g.recs, &g.lists);
    let others: Vec<Record> = g.recs.iter().filter(|r| r.id() != rv.id()).cloned().collect();
    let mut late = set_of(&g.root.key);
    sync_all(&mut late, &others, &g.lists);
    assert!(late.notices(&late.state()).is_empty());
    assert_eq!(late.insert(rv.clone()), Ok(Added::NoRoom));
    let want = vec![(rv.id(), vec![k("tv").hash])];
    assert_eq!(late.notices(&late.state()), want);
    assert_eq!(held.notices(&held.state()), want);
    // A copy with another signature is not taken.
    let mut bad = rv.clone();
    bad.sig[10] ^= 1;
    let mut other = set_of(&g.root.key);
    sync_all(&mut other, &others, &g.lists);
    assert!(other.insert(bad).is_err());
    assert!(other.notices(&other.state()).is_empty());
    // The new root removes the TV again: nothing to tell.
    let seen = g.seen();
    let again = g.rec(&k("n1"), Kind::Revoke(removal(&[k("tv").hash], seen)));
    for m in [&mut held, &mut late] {
        m.insert(again.clone()).unwrap();
        assert!(m.notices(&m.state()).is_empty());
    }
}

/// A dismissed notice is not shown again, also when its removal comes
/// again; what the app saved brings the notices and the dismissals back
/// after a restart.
#[test]
fn notices_are_dismissed_and_kept_across_a_restart() {
    let mut g = base();
    let seen = g.seen();
    let tv = g.root_rec(Kind::Revoke(removal(&[k("tv").hash], seen)));
    let seen = g.seen();
    let laptop = g.root_rec(Kind::Revoke(removal(&[k("laptop").hash], seen)));
    let from: Vec<Record> = g.recs.iter().filter(|r| r.id() != tv.id() && r.id() != laptop.id()).cloned().collect();
    write(&mut g, &from, &k("n1"), &k("new phone"), &[]);
    let mut m = set_of(&g.root.key);
    sync_all(&mut m, &g.recs, &g.lists);
    assert_eq!(m.notices(&m.state()).len(), 2);
    m.dismiss(&tv.id());
    assert_eq!(m.notices(&m.state()), vec![(laptop.id(), vec![k("laptop").hash])]);
    assert_eq!(m.insert(tv.clone()), Ok(Added::NoRoom));
    assert_eq!(m.notices(&m.state()).len(), 1);
    // Saved, restarted, taken back.
    let records: Vec<Record> = m.ids().map(|id| m.get(id).unwrap().clone()).collect();
    let lists: Vec<Vec<u8>> = m.lists().map(<[u8]>::to_vec).collect();
    let saved: Vec<Record> = m.notice_records().cloned().collect();
    let dismissed: Vec<RecordId> = m.dismissed().copied().collect();
    let mut back = RecordSet::restore(g.root.key.clone(), rk(), &records, &lists);
    assert!(back.notices(&back.state()).is_empty());
    back.keep_notices(&saved, &dismissed);
    assert_eq!(back.notices(&back.state()), m.notices(&m.state()));
    assert_eq!(back.dismissed().collect::<Vec<_>>(), vec![&tv.id()]);
    // A saved record that is no notice (a record the list names) is not taken.
    let listed = g.recs.iter().find(|r| r.body().signer == g.root.hash && back.contains(&r.id())).unwrap();
    back.keep_notices(core::slice::from_ref(listed), &[]);
    assert_eq!(back.notice_records().count(), 1);
}

/// At most MAX_NOTICES notices, the oldest going first, the same on two
/// members that took the records in other orders.
#[test]
fn notices_are_bounded_alike_on_every_member() {
    let mut g = base();
    let mut removals = Vec::new();
    for i in 0..MAX_NOTICES + 20 {
        let seen = g.seen();
        removals.push(g.root_rec(Kind::Revoke(removal(&[k(&alloc::format!("gone {i}")).hash], seen))));
    }
    let ids: BTreeSet<RecordId> = removals.iter().map(Record::id).collect();
    let from: Vec<Record> = g.recs.iter().filter(|r| !ids.contains(&r.id())).cloned().collect();
    write(&mut g, &from, &k("n1"), &k("new phone"), &[]);
    let mut kept = Vec::new();
    for order in 0..2 {
        let mut recs = g.recs.clone();
        if order == 1 {
            recs.reverse();
        }
        let mut m = set_of(&g.root.key);
        sync_all(&mut m, &recs, &g.lists);
        let n: Vec<RecordId> = m.notices(&m.state()).into_iter().map(|(id, _)| id).collect();
        assert_eq!(n.len(), MAX_NOTICES);
        kept.push(n);
    }
    assert_eq!(kept[0], kept[1]);
    // The newest stay.
    let newest: BTreeSet<RecordId> = removals.iter().skip(20).map(Record::id).collect();
    assert_eq!(kept[0].iter().copied().collect::<BTreeSet<_>>(), newest);
}

/// Two histories of the root halt the group until the recovery key
/// changes the root; what either history removed stays removed after the
/// change, and the group runs again.
#[test]
fn a_change_of_root_ends_two_histories_of_the_root() {
    let mut g = base();
    let root = k("root");
    let below = g.recs.last().unwrap().clone();
    g.root_rec(Kind::Revoke(removal(&[k("laptop").hash], Vec::new())));
    let other = Body {
        seq: below.body().seq + 1,
        prev: Some(below.id()),
        ..g.body(&root, Kind::Revoke(removal(&[k("tv").hash], Vec::new())))
    };
    g.recs.push(Record::sign(other, &root).unwrap());
    let halted = state_with(&g.root.key, &g.recs, &g.lists);
    assert_eq!(halted.stop, Stop::Full);
    let from = g.recs.clone();
    write(&mut g, &from, &k("n1"), &k("new phone"), &[]);
    let s = state_with(&g.root.key, &g.recs, &g.lists);
    assert_eq!(s.stop, Stop::None);
    assert!(s.revoked.contains(&k("laptop").hash) && s.revoked.contains(&k("tv").hash));
    assert!(!has(&s, &k("laptop")) && !has(&s, &k("tv")) && has(&s, &k("new phone")));
    for seed in 1..4 {
        let mut set = set_of(&g.root.key);
        sync_all(&mut set, &shuffled(&g.recs, seed), &g.lists);
        assert_eq!(unignored(set.state()), unignored(s.clone()), "order {seed}");
    }
}

/// What the root's checkpoints on its two histories left out stays out
/// of the change of root that ends them: both pruned a removal with the
/// admin's admission it acts on, and a member that was away offers the
/// admission again, never the removal.
#[test]
fn a_change_of_root_leaves_out_what_either_history_pruned() {
    let mut g = base();
    let root = k("root");
    let (pa, a) = (k("phone a"), k("admin a"));
    g.admin(&pa, &a, POWER_ADMIT | POWER_REMOVE);
    let admitted = g.device(&a, &k("d"), "d", |_| {});
    g.device(&a, &k("e"), "e", |_| {});
    let rv = g.root_rec(Kind::Revoke(removal(&[k("d").hash], g.seen())));
    g.device(&root, &k("x"), "x", |_| {});
    let line = g.recs.clone();
    let set = set_with(&g.root.key, &line, &g.lists);
    let st = set.state();
    let one = set.write_checkpoint(&st, &root, 1).unwrap();
    let two = set.write_checkpoint(&st, &root, 2).unwrap();
    for cp in [&one, &two] {
        let Kind::Checkpoint { keep, heads } = &cp.body().kind else { panic!() };
        assert!(!keep.contains(&rv.id()) && !keep.contains(&admitted.id()) && !heads.iter().any(|h| h.id == rv.id()));
    }
    // Each history compacted by its own checkpoint; the removal is gone
    // everywhere. A member that was away offers the admission again.
    let mut w = set_with(&g.root.key, &line, &g.lists);
    w.insert(one.clone()).unwrap();
    assert!(!w.contains(&rv.id()) && !w.contains(&admitted.id()));
    w.insert(two.clone()).unwrap();
    w.insert(admitted.clone()).unwrap();
    let st = w.state();
    assert_eq!(st.stop, Stop::Full);
    let wr = w
        .write_change(&st, &k("recovery"), crate::testkit::rk2(), &k("n1"), phone(&k("new phone")), &[], false, 0)
        .unwrap();
    let mut after: Vec<Record> = w.in_dependency_order().into_iter().cloned().collect();
    after.extend(wr.first.iter().cloned());
    after.push(wr.record.clone());
    let mut lists = g.lists.clone();
    lists.push(wr.list.encode());
    let s = state_with(&g.root.key, &after, &lists);
    assert_eq!(s.stop, Stop::None);
    assert!(!has(&s, &k("d")) && has(&s, &k("e")) && has(&s, &k("tv")) && has(&s, &k("new phone")));
    let mut m = set_of(&g.root.key);
    sync_all(&mut m, &after, &lists);
    assert!(!has(&m.state(), &k("d")));
}

/// After a change of root the new root's checkpoint prunes an earlier
/// root's listed removal by the same rule as its own, and keeps what else
/// the list carries.
#[test]
fn the_new_roots_checkpoint_prunes_a_listed_removal() {
    let mut g = base();
    let tv = g
        .recs
        .iter()
        .find(|r| matches!(&r.body().kind, Kind::Device(d) if d.key.hash() == k("tv").hash))
        .unwrap()
        .clone();
    let rv = g.root_rec(Kind::Revoke(removal(&[k("tv").hash], g.seen())));
    let from = g.recs.clone();
    let w = write(&mut g, &from, &k("n1"), &k("new phone"), &[]);
    assert!(carried(&w, &rv));
    let set = set_with(&g.root.key, &g.recs, &g.lists);
    let before = set.state();
    assert!(before.revoked.contains(&k("tv").hash));
    let cp = set.write_checkpoint(&before, &k("n1"), 0).unwrap();
    let Kind::Checkpoint { keep, .. } = &cp.body().kind else { panic!() };
    assert!(!keep.contains(&rv.id()) && !keep.contains(&tv.id()));
    g.push(cp.clone());
    let mut m = set_with(&g.root.key, &g.recs, &g.lists);
    let s = m.state();
    assert!(s.checkpoints.contains(&cp.id()));
    assert!(!s.revoked.contains(&k("tv").hash) && !has(&s, &k("tv")));
    assert!(has(&s, &k("laptop")) && has(&s, &k("old phone")) && has(&s, &k("new phone")));
    assert!(!m.contains(&rv.id()) && !m.contains(&tv.id()));
    assert_eq!(m.insert(rv), Ok(Added::NoRoom));
    assert_eq!(unignored(s), unignored(state_with(&g.root.key, &g.recs, &g.lists)));
}

/// A device whose removal a checkpoint pruned on a member, that comes in
/// again through the list of a writer that never held the removal, is a
/// notice there (case b); a writer's own admission is not, and the notice
/// goes when the new root removes the device.
#[test]
fn a_device_that_comes_in_through_the_list_is_a_notice() {
    let mut g = base();
    let root = k("root");
    g.device(&root, &k("d"), "d", |_| {});
    let stale = g.recs.clone();
    let rv = g.root_rec(Kind::Revoke(removal(&[k("d").hash], g.seen())));
    g.device(&root, &k("x"), "x", |_| {});
    let all = g.recs.clone();
    let set = set_with(&g.root.key, &all, &g.lists);
    let cp = set.write_checkpoint(&set.state(), &root, 0).unwrap();
    g.push(cp.clone());
    let mut m = set_with(&g.root.key, &g.recs, &g.lists);
    assert!(!has(&m.state(), &k("d")) && m.notices(&m.state()).is_empty());
    // The writer was away: it holds what came before the removal.
    let w = write(&mut g, &stale, &k("n1"), &k("new phone"), &[]);
    // Nobody offers it the removal again.
    let offered: Vec<Record> = g.recs.iter().filter(|r| r.id() != rv.id()).cloned().collect();
    sync_all(&mut m, &offered, &g.lists);
    let s = m.state();
    assert!(has(&s, &k("d")) && has(&s, &k("new phone")));
    assert_eq!(m.notices(&s), vec![(w.record.id(), vec![k("d").hash])]);
    let (fixed, base) = m.arrivals();
    let mut again = set_with(&g.root.key, &m.in_dependency_order().into_iter().cloned().collect::<Vec<_>>(), &g.lists);
    again.keep_arrivals(&fixed, base);
    assert_eq!(again.notices(&again.state()), m.notices(&s));
    let again_rv = g.rec(&k("n1"), Kind::Revoke(removal(&[k("d").hash], Vec::new())));
    m.insert(again_rv).unwrap();
    assert!(m.notices(&m.state()).is_empty());
}

/// A change of root asked twice for the same new root key gives back the
/// stored head, its list and first records: never a second head at one
/// seq.
#[test]
fn a_change_asked_twice_gives_back_its_head() {
    let mut g = base();
    let from = g.recs.clone();
    let w = write(&mut g, &from, &k("n1"), &k("new phone"), &[k("tv").hash]);
    let mut set = set_with(&g.root.key, &g.recs, &g.lists);
    let again = set
        .write_change(
            &set.state(),
            &k("recovery"),
            crate::testkit::rk2(),
            &k("n1"),
            phone(&k("new phone")),
            &[],
            false,
            9,
        )
        .unwrap();
    assert_eq!(again.record.id(), w.record.id());
    assert_eq!(again.list, w.list);
    assert_eq!(
        again.first.iter().map(Record::id).collect::<Vec<_>>(),
        w.first.iter().map(Record::id).collect::<Vec<_>>()
    );
    // Before it applied too: the head and its first records held, the list
    // with them.
    let mut held = set_with(&g.root.key, &from, &[]);
    held.insert(w.record.clone()).unwrap();
    held.insert_list(&w.list.encode()).unwrap();
    held.insert_all(w.first.iter().cloned());
    let again = held
        .write_change(
            &held.state(),
            &k("recovery"),
            crate::testkit::rk2(),
            &k("n1"),
            phone(&k("new phone")),
            &[],
            false,
            9,
        )
        .unwrap();
    assert_eq!(again.record.id(), w.record.id());
}

/// Two heads at one seq above a head whose list names a root record a
/// checkpoint had pruned: halted, the member takes that record again and
/// shows what the list below the fork names, as a member that got all at
/// once.
#[test]
fn a_halted_member_takes_back_a_listed_record_a_checkpoint_pruned() {
    let mut g = G::new();
    let root = k("root");
    let laptop = g.device(&root, &k("laptop"), "laptop", |_| {});
    let tv = g.device(&root, &k("tv"), "tv", |_| {});
    let (seq, id) = g.heads[&root.hash];
    g.root_rec(Kind::Checkpoint { heads: vec![Head { key: root.hash, seq, id }], keep: vec![tv.id()] });
    let list = List(vec![laptop.id()]);
    g.lists.push(list.encode());
    let head = g.rec(
        &k("recovery"),
        Kind::Recovery {
            root: k("n1").key.clone(),
            list: list.hash(),
            from: 0,
            first: RecordId([0xf1; 32]),
            signer2: crate::testkit::rk2().key().hash(),
        },
    );
    let a = head_at(&g, 2, Some(head.id()), &k("n2"), [2; 32]);
    let b = head_at(&g, 2, Some(head.id()), &k("n3"), [3; 32]);
    let mut all = g.recs.clone();
    all.extend([a, b]);
    let mut member = set_of(&g.root.key);
    for r in &all {
        let _ = member.insert(r.clone());
    }
    sync_all(&mut member, &all, &g.lists);
    let s = member.state();
    assert!(s.halted());
    assert!(s.device_by_key(&k("laptop").hash).is_some());
    let fresh = set_with(&g.root.key, &all, &g.lists);
    assert_eq!(fresh.digest(), member.digest());
    assert_eq!(fresh.state(), s);
    assert_eq!(s.devices, state_with(&g.root.key, &all, &g.lists).devices);
}

/// The new root's checkpoint that narrowed the list counts no more once
/// two heads at a later seq halt the group: the member takes back what the
/// list names.
#[test]
fn a_halted_member_takes_back_what_the_new_roots_checkpoint_left_out() {
    let mut g = G::new();
    let root = k("root");
    let n1 = k("n1");
    let laptop = g.device(&root, &k("laptop"), "laptop", |_| {});
    let list = g.listing();
    let head = g.change(&n1, &list);
    let (seq, id) = g.heads[&n1.hash];
    g.rec(&n1, Kind::Checkpoint { heads: vec![Head { key: n1.hash, seq, id }], keep: vec![] });
    let mut member = set_of(&g.root.key);
    sync_all(&mut member, &g.recs, &g.lists);
    assert!(!member.contains(&laptop.id()));
    let a = head_at(&g, 2, Some(head.id()), &k("n2"), [2; 32]);
    let b = head_at(&g, 2, Some(head.id()), &k("n3"), [3; 32]);
    let mut all = g.recs.clone();
    all.extend([a, b]);
    sync_all(&mut member, &all, &g.lists);
    let s = member.state();
    assert!(s.halted());
    assert!(member.contains(&laptop.id()) && s.device_by_key(&k("laptop").hash).is_some());
    let fresh = set_with(&g.root.key, &all, &g.lists);
    assert_eq!(fresh.digest(), member.digest());
    assert_eq!(fresh.state(), s);
}

/// The writer holds its change before it gives it out: asked again at
/// once, with one more device unticked or one less, it gives back the
/// same change, and a member given both answers holds one change.
#[test]
fn a_change_asked_again_at_once_is_the_same_change() {
    for (first, second) in [(&[][..], &[k("tv").hash][..]), (&[k("tv").hash][..], &[][..])] {
        let g = base();
        let mut set = set_with(&g.root.key, &g.recs, &g.lists);
        let st = set.state();
        let a = set
            .write_change(&st, &k("recovery"), crate::testkit::rk2(), &k("n1"), phone(&k("p1")), first, false, 0)
            .unwrap();
        let b = set
            .write_change(&st, &k("recovery"), crate::testkit::rk2(), &k("n1"), phone(&k("p1")), second, false, 1000)
            .unwrap();
        assert!(!a.again && b.again);
        assert_eq!(a.record.id(), b.record.id());
        let mut member = set_with(&g.root.key, &g.recs, &g.lists);
        for w in [&a, &b] {
            member.insert(w.record.clone()).unwrap();
            let _ = member.insert_list(&w.list.encode());
            member.insert_all(w.first.iter().cloned());
        }
        let s = member.state();
        assert!(!s.halted() && s.fork.is_none());
        assert_eq!(s.roots.last(), Some(&k("n1").hash));
    }
}

/// A writer that took no record from a member since it was restored
/// writes blind, and says so; one that synced does not.
#[test]
fn a_change_written_without_a_sync_says_so() {
    let g = base();
    let saved = set_with(&g.root.key, &g.recs, &g.lists);
    let recs: Vec<Record> = saved.in_dependency_order().into_iter().cloned().collect();
    let mut set = RecordSet::restore(g.root.key.clone(), rk(), &recs, &g.lists);
    let st = set.state();
    let w =
        set.write_change(&st, &k("recovery"), crate::testkit::rk2(), &k("n1"), phone(&k("p1")), &[], false, 0).unwrap();
    assert!(w.blind);
    let again =
        set.write_change(&st, &k("recovery"), crate::testkit::rk2(), &k("n1"), phone(&k("p1")), &[], false, 0).unwrap();
    assert!(again.again && again.blind);
    let mut synced = RecordSet::restore(g.root.key.clone(), rk(), &recs, &g.lists);
    synced.insert_all(g.recs.iter().cloned());
    let st = synced.state();
    assert!(
        !synced
            .write_change(&st, &k("recovery"), crate::testkit::rk2(), &k("n1"), phone(&k("p1")), &[], false, 0)
            .unwrap()
            .blind
    );
}

/// The way out of two histories of the root reaches a stopped member from
/// a key one line admits: the new root's device was admitted on one line,
/// and the member takes the change of root (its head, its list, the new
/// root's records) from it; the group runs again.
#[test]
fn a_change_of_root_reaches_a_member_from_a_key_one_line_admits() {
    let mut g = base();
    let root = k("root");
    let below = g.recs.last().unwrap().clone();
    g.device(&root, &k("m4"), "m4", |_| {});
    let other = Body {
        seq: below.body().seq + 1,
        prev: Some(below.id()),
        ..g.body(&root, Kind::Revoke(removal(&[k("tv").hash], Vec::new())))
    };
    g.recs.push(Record::sign(other, &root).unwrap());
    let stopped = g.recs.clone();
    let w = write(&mut g, &stopped, &k("n1"), &k("m4"), &[]);
    let mut m = set_with(&g.root.key, &stopped, &[]);
    let st = m.state();
    assert!(st.stopped());
    let me = k("laptop").hash;
    assert_eq!(crate::peer::standing(&st, &me, &point_of(&k("m4"))), crate::peer::Standing::ForkProof);
    // The writer's set, before it applied the change, hands it out.
    let mut writer = set_with(&g.root.key, &stopped, &[]);
    writer.insert(w.record.clone()).unwrap();
    let wst = writer.state();
    let given: BTreeSet<RecordId> = writer.for_peer(&wst, &k("m4").hash).iter().map(|r| r.id()).collect();
    assert!(given.contains(&w.record.id()));
    for r in core::iter::once(&w.record).chain(&w.first) {
        assert_ne!(m.insert_proof(r.clone()), Ok(Added::Halted), "{:?}", r.body().kind);
    }
    m.insert_list(&w.list.encode()).unwrap();
    let st = m.state();
    assert!(!st.stopped());
    assert_eq!(st.roots.last(), Some(&k("n1").hash));
}

/// A device the new root removes in a change of root gets, with its
/// removal and the change that proves its signer, the change's list, so
/// it waits for nothing.
#[test]
fn a_removed_device_gets_the_list_of_the_change_that_removed_it() {
    let mut g = base();
    let before = g.recs.clone();
    let w = write(&mut g, &before, &k("n1"), &k("new phone"), &[k("laptop").hash]);
    let set = set_with(&g.root.key, &g.recs, &g.lists);
    let st = set.state();
    assert!(st.revoked.contains(&k("laptop").hash));
    let lists = set.lists_for_peer(&st, &k("laptop").hash);
    assert_eq!(lists, [w.list.encode().as_slice()]);
    let mut laptop = set_with(&g.root.key, &before, &[]);
    laptop.insert_all(set.for_peer(&st, &k("laptop").hash).into_iter().cloned());
    for l in lists {
        laptop.insert_list(l).unwrap();
    }
    assert_eq!(laptop.missing_list(), None);
    assert!(laptop.state().revoked.contains(&k("laptop").hash));
}

/// A head stands only with both halves of the recovery key: K1's signature
/// with a K2 signature that does not hold is refused, and so is K2's with
/// a K1 signature that does not hold; each is told by its own rule, K1's
/// first, and neither half alone enters the set.
#[test]
fn a_head_needs_both_halves_of_the_recovery_key() {
    let g = base();
    let head = head_at(&g, 1, None, &k("root 2"), List(g.listing()).hash());
    let (body, sig, sig2) = (head.body_bytes().to_vec(), head.sig().to_vec(), head.sig2().unwrap().to_vec());
    let with =
        |sig: &[u8], sig2: &[u8]| Record::decode(&crate::format::envelope::write(&body, sig, Some(sig2))).unwrap();
    assert_eq!(with(&sig, &sig2).verify_head(&rk()), Ok(false));
    // K2's signature broken, K1's over it: K1's covers its hash.
    let mut bent2 = sig2.clone();
    bent2[100] ^= 1;
    assert_eq!(with(&sig, &bent2).verify_head(&rk()), Err(Rule::field("recovery", "damaged")));
    // K2's made anew over the body, K1's still over the first: swapped.
    let other2 = crate::records::pq::PqKey::from_seeds(&[7; 16], &[7; 16], &[0x23; 16]);
    let swapped = other2.sign(&body, crate::records::pq::CONTEXT_RECORD).unwrap();
    assert_eq!(with(&sig, &swapped).verify_head(&rk()), Err(Rule::field("recovery", "damaged")));
    // K1's made over a K2 signature that does not hold.
    let k1_over = crate::records::key::sign_es256(&k("recovery"), LABEL_RECORD, &with_sig2(&body, &bent2)).unwrap();
    assert_eq!(with(&k1_over, &bent2).verify_head(&rk()), Err(Rule::new("sig/verify")));
    // K2's good, K1's over the body alone (without K2's hash) or by another key.
    let plain = crate::records::key::sign_es256(&k("recovery"), LABEL_RECORD, &body).unwrap();
    assert_eq!(with(&plain, &sig2).verify_head(&rk()), Err(Rule::field("recovery", "damaged")));
    let thief = crate::records::key::sign_es256(&k("thief"), LABEL_RECORD, &with_sig2(&body, &sig2)).unwrap();
    assert_eq!(with(&thief, &sig2).verify_head(&rk()), Err(Rule::field("recovery", "damaged")));
    for bad in [with(&sig, &bent2), with(&k1_over, &bent2), with(&plain, &sig2)] {
        let mut set = set_of(&g.root.key);
        assert!(set.insert(bad).is_err());
    }
}

/// A head names the group's K2 as `signer2`: one naming another key, even
/// signed by it, is refused, and K1 never signs a head alone.
#[test]
fn a_head_names_the_groups_second_half() {
    let g = base();
    let other2 = crate::records::pq::PqKey::from_seeds(&[7; 16], &[7; 16], &[7; 16]);
    let body = g.body(
        &k("recovery"),
        Kind::Recovery {
            root: k("root 2").key,
            list: List(g.listing()).hash(),
            from: 0,
            first: RecordId([0xf1; 32]),
            signer2: other2.key().hash(),
        },
    );
    let r = Record::sign_head(body.clone(), &k("recovery"), &other2).unwrap();
    assert_eq!(r.verify_head(&rk()), Err(Rule::field("recovery", "signer2")));
    assert!(Record::sign_head(body.clone(), &k("recovery"), crate::testkit::rk2()).is_err(), "signer2 is not that key");
    assert!(Record::sign(body, &k("recovery")).is_err(), "a head is never signed by K1 alone");
    // A held record of the recovery key carries both signatures too.
    let held = super::raw(&g, &k("recovery"), head_at(&g, 1, None, &k("root 2"), [1; 32]).body().kind.clone(), |m| {
        m.push((99, crate::format::cbor::Value::Uint(1)));
    })
    .unwrap();
    assert!(held.body().held);
    assert_eq!(held.verify_head(&rk()), Ok(true));
    let alone = Record::decode(&crate::format::envelope::write(held.body_bytes(), held.sig(), None));
    assert!(alone.is_err() || alone.unwrap().verify_head(&rk()).is_err());
}

/// A member restored, or handed the records in another order, with an
/// earlier root's records filling what waits: the newest head's first
/// checkpoint still waits beside them, so the chain applies and the set
/// ends as the live one (simulator seed 47).
#[test]
fn the_newest_heads_first_checkpoint_waits_whatever_else_does() {
    let mut g = base();
    let from = g.recs.clone();
    let w1 = write(&mut g, &from, &k("n1"), &k("new phone"), &[]);
    let from = g.recs.clone();
    let w2 = write(&mut g, &from, &k("n2"), &k("phone 2"), &[]);
    let n1 = k("n1");
    let ceiling = crate::records::keep::ceiling(true);
    let cp1 = w1.first.last().unwrap().id();
    let many: Vec<Record> =
        (0..ceiling).map(|_| g.rec(&n1, Kind::Copies { incoming_ms: MIN_INCOMING_MS, seen: vec![] })).collect();
    let mut live = set_of(&g.root.key);
    sync_all(&mut live, &g.recs, &g.lists);
    assert_eq!(live.state().roots, vec![k("root").hash, n1.hash, k("n2").hash]);
    // The earlier first checkpoint is gone, n1's records come before n2's.
    let w2_ids: Vec<RecordId> = w2.first.iter().map(Record::id).collect();
    let mut order: Vec<Record> =
        g.recs.iter().filter(|r| r.id() != cp1 && !w2_ids.contains(&r.id()) && !many.contains(r)).cloned().collect();
    order.extend(many.iter().cloned());
    order.extend(w2.first.iter().cloned());
    let mut m = set_of(&g.root.key);
    for l in &g.lists {
        let _ = m.insert_list(l);
    }
    for r in &order {
        let _ = m.insert(r.clone());
        for l in &g.lists {
            let _ = m.insert_list(l);
        }
    }
    // A record of the newest head's group trimmed before its first
    // checkpoint came is asked for again, and taken.
    let asked = m.missing(&m.state());
    let again: Vec<Record> = g.recs.iter().filter(|r| asked.contains(&r.id())).cloned().collect();
    m.insert_all(again);
    assert_eq!(m.state().roots, vec![k("root").hash, n1.hash, k("n2").hash]);
    let restored = RecordSet::restore(g.root.key.clone(), crate::testkit::recovery(), &order, &g.lists);
    assert_eq!(restored.state().roots, m.state().roots);
}

/// A change never leaves out a device that counts: when the removals and
/// the device records that count pass what a change carries, the writer
/// refuses and the set stays as it was; within it, every device stays.
#[test]
fn a_change_carries_every_device_that_counts_or_is_not_written() {
    let small = crate::records::keep::small::Small::new(40, 8, 4);
    let mut g = base();
    let from = g.recs.clone();
    write(&mut g, &from, &k("n1"), &k("new phone"), &[]);
    let n1 = k("n1");
    for i in 0..5 {
        g.rec(&n1, Kind::device(Device::new(k(&format!("e{i}")).key.clone(), "e", ROLE_MEMBER)));
    }
    for r in &g.recs {
        small.units(r.id(), 1);
    }
    let mut set = set_with(&g.root.key, &g.recs, &g.lists);
    let st = set.state();
    let before = set.digest();
    let devices = st.devices.len();
    assert!(devices > 8, "{devices} devices");
    let err = set
        .write_change(&st, &k("recovery"), crate::testkit::rk2(), &k("n2"), phone(&k("phone 2")), &[], false, 0)
        .unwrap_err();
    assert!(alloc::format!("{err}").contains("leave out devices"), "{err}");
    assert_eq!(set.digest(), before);
    // Removing enough of them, the change is written and keeps the rest.
    let gone = [k("e0").hash, k("e1").hash, k("tv").hash];
    let w = set
        .write_change(&st, &k("recovery"), crate::testkit::rk2(), &k("n2"), phone(&k("phone 2")), &gone, false, 0)
        .unwrap();
    let mut all = g.recs.clone();
    all.extend(w.first.iter().cloned());
    all.push(w.record.clone());
    let mut lists = g.lists.clone();
    lists.push(w.list.encode());
    for r in w.first.iter().chain([&w.record]) {
        small.units(r.id(), 1);
    }
    let s = state_with(&g.root.key, &all, &lists);
    assert_eq!(s.roots.last(), Some(&k("n2").hash));
    for d in &st.devices {
        let key = d.key.hash();
        assert_eq!(s.device_by_key(&key).is_some(), !gone.contains(&key), "{}", d.name);
    }
}

/// An admin's key that a waiting head names as the new root: its records
/// are kept aside whether they came before the head or after it, so two
/// members that took them in either order hold the same.
#[test]
fn an_admin_named_root_by_a_waiting_head_has_its_records_aside_in_any_order() {
    let mut g = G::new();
    let (pb, b) = (k("phone b"), k("admin b"));
    g.admin(&pb, &b, POWER_ADMIT);
    g.device(&b, &k("dev 1"), "dev", |_| {});
    let list = g.listing();
    let head = g.change_from(&b, &list, 1);
    // The new root's first checkpoint never comes: the head waits.
    let Kind::Recovery { first, .. } = head.body().kind else { unreachable!() };
    let recs: Vec<Record> = g.recs.iter().filter(|r| r.id() != first).cloned().collect();
    let late: Vec<Record> = recs.iter().filter(|r| r.id() != head.id()).cloned().chain([head.clone()]).collect();
    let mut early = vec![head.clone()];
    early.extend(recs.iter().filter(|r| r.id() != head.id()).cloned());
    let a = set_with(&g.root.key, &early, &g.lists);
    let z = set_with(&g.root.key, &late, &g.lists);
    assert_eq!(a.state().first_missing, Some(first));
    assert!(a.aside().count() > 0);
    assert_eq!(a.aside().collect::<Vec<_>>(), z.aside().collect::<Vec<_>>());
    assert_eq!(a.digest(), z.digest());
    assert_eq!(a.state(), z.state());
}

/// A key a head off the chain names as root signs as a root but has no
/// room: the rooms turn its records away, the one that made another key
/// an admin among them. That key's records then have no known signer in
/// the set, as in an evaluation of what the set keeps.
#[test]
fn an_admin_made_by_a_record_the_rooms_turned_away_is_no_key_of_the_set() {
    let mut g = G::new();
    let (pb, b, na) = (k("phone b"), k("admin b"), k("new root a"));
    g.admin(&pb, &b, POWER_ADMIT);
    let list = g.listing();
    // The first head waits for a first checkpoint that never comes; the
    // second names the same root again and is void; the third, past it,
    // is off the chain and names admin b.
    let mut gone = Vec::new();
    for root in [&na, &na, &b] {
        let head = g.change(root, &list);
        let Kind::Recovery { first, .. } = head.body().kind else { unreachable!() };
        gone.push(first);
    }
    g.device(&b, &k("phone a"), "admin", |d| {
        d.admin = Some(k("admin a").key.clone());
        d.powers = POWER_ADMIT;
    });
    g.device(&k("admin a"), &k("dev 0"), "dev", |_| {});
    let recs: Vec<Record> = g.recs.iter().filter(|r| !gone.contains(&r.id())).cloned().collect();
    let set = set_with(&g.root.key, &recs, &g.lists);
    let kept: Vec<Record> = set.ids().filter_map(|id| set.get(id)).cloned().collect();
    assert_eq!(set.state(), state_with(&g.root.key, &kept, &g.lists));
}
