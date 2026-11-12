// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! Rule 33 as tests: the recovery key changes the root at once, by a head
//! and its list; two heads at one seq stop the group for good; a head the
//! device cannot read stops that device until it is updated; the writer's
//! list carries what it counts of every earlier root, unedited, and the
//! owner's choice is made of removals.

use super::*;
use crate::records::set::Written;

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
    let body = Body { seq, prev, ..g.body(&k("recovery"), Kind::Recovery { root: root.key.clone(), list }) };
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
    let later = raw(&g, &k("recovery"), Kind::Recovery { root: k("n2").key.clone(), list: [5; 32] }, |m| {
        m.push((99, crate::format::cbor::Value::Uint(1)))
    })
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
    g.rec(&k("recovery"), Kind::Recovery { root: k("n1").key.clone(), list: h });
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
        ..g.body(&k("recovery"), Kind::Recovery { root: k("n17").key, list: [1; 32] })
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

/// The new root's first checkpoint closes the list: a listed record that
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
