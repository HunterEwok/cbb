// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! Acknowledgements (section 10): the root's checkpoint lets a removal go
//! only once every live admin key but its signer has acknowledged it, so
//! a removal is forgotten only when everyone who could bring the device
//! back has seen it. An admin's acknowledgement sits on its whole chain:
//! a root that holds it holds all the admin signed before.

use super::*;
use crate::records::set::{ADMIN_KEY_TAKEN_BACK, ADMIN_SILENCE_MS, TakeBack};

fn has(s: &State, member: &K) -> bool {
    s.device_by_key(&member.hash).is_some()
}

/// An acknowledgement of by: the heads it holds but its own.
fn ack(g: &mut G, by: &K) -> Record {
    let seen: Vec<Seen> = g.seen().into_iter().filter(|s| s.key != by.hash).collect();
    g.rec(by, Kind::Ack { seen, spare: None })
}

/// The root admits d and removes it; the admin signs a record for d (an
/// admission or a change, the same bytes) that the root's writer never
/// got; when `admin_first`, the admin admits x before. The root writes
/// tv and a checkpoint from what it holds.
fn late_record(admin_first: bool) -> (G, Record, Vec<Record>) {
    let mut g = G::new();
    let root = k("root");
    let (pa, a) = (k("phone a"), k("admin a"));
    g.admin(&pa, &a, POWER_ADMIT | POWER_MANAGE | POWER_REMOVE);
    if admin_first {
        g.device(&a, &k("x"), "x", |_| {});
    }
    g.device(&root, &k("d"), "d", |_| {});
    let late = g.device(&a, &k("d"), "d by the admin", |_| {});
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

fn removal_of(g: &G, key: &K) -> RecordId {
    g.recs.iter().find(|r| matches!(&r.body().kind, Kind::Revoke(rm) if rm.keys.contains(&key.hash))).unwrap().id()
}

/// The admin has not acknowledged the removal, so the checkpoint keeps it;
/// the admin's late record, admission or change, finds the key removed.
fn a_late_record_waits_for_the_removal(admin_first: bool) {
    let (g, late, mine) = late_record(admin_first);
    let Some(Kind::Checkpoint { keep, .. }) = mine.last().map(|r| &r.body().kind) else { panic!() };
    assert!(keep.contains(&removal_of(&g, &k("d"))), "the removal waits for the admin");
    let mut set = set_with(&g.root.key, &mine, &g.lists);
    assert!(set.state().revoked.contains(&k("d").hash));
    assert_eq!(set.unacknowledged(&set.state()).get(&k("admin a").hash), Some(&1));
    let _ = set.insert(late.clone());
    assert!(!has(&set.state(), &k("d")), "the removed device stays out at the writer");
    assert!(!has(&g.state(), &k("d")), "and in the evaluation of every record");
}

#[test]
fn a_late_record_without_a_head_finds_the_removal_waiting() {
    a_late_record_waits_for_the_removal(false);
}

#[test]
fn a_late_record_above_its_signers_head_finds_the_removal_waiting() {
    a_late_record_waits_for_the_removal(true);
}

/// Once the admin acknowledges, the root holds its whole chain, the late
/// record too: the next checkpoint lets the removal go with every
/// admission of the key, and a copy of the admin's record that comes
/// again is refused as settled.
#[test]
fn an_acknowledged_removal_goes_with_every_admission() {
    let (mut g, late, mut mine) = late_record(false);
    let a = k("admin a");
    mine.push(late.clone());
    mine.push(ack(&mut g, &a));
    let set = set_with(&g.root.key, &mine, &g.lists);
    let st = set.state();
    assert_eq!(set.unacknowledged(&st).get(&a.hash), Some(&0));
    assert!(!set.ack_due(&st, &a.hash));
    mine.push(root_checkpoint(&mut g, &mine));
    let Some(Kind::Checkpoint { keep, .. }) = mine.last().map(|r| &r.body().kind) else { panic!() };
    assert!(!keep.contains(&removal_of(&g, &k("d"))), "every live admin saw it");
    let mut set = set_with(&g.root.key, &mine, &g.lists);
    let st = set.state();
    assert!(!st.revoked.contains(&k("d").hash) && !has(&st, &k("d")));
    assert!(!set.contains(&late.id()));
    let _ = set.insert(late.clone());
    assert!(!has(&set.state(), &k("d")), "the admin's record is settled");
    assert!(!has(&g.state(), &k("d")));
}

/// With no admin keys, a removal goes at the next checkpoint, as before.
#[test]
fn without_admins_a_removal_goes_at_once() {
    let mut g = G::new();
    let root = k("root");
    g.device(&root, &k("d"), "d", |_| {});
    let rv = g.root_rec(Kind::Revoke(removal(&[k("d").hash], g.seen())));
    g.device(&root, &k("tv"), "tv", |_| {});
    let recs = g.recs.clone();
    let cp = root_checkpoint(&mut g, &recs);
    let Kind::Checkpoint { keep, .. } = &cp.body().kind else { panic!() };
    assert!(!keep.contains(&rv.id()));
}

/// The writer's acknowledgement: due after a removal arrives, written
/// once, then no longer due; it names the root's head.
#[test]
fn an_admin_acknowledges_once_after_a_removal_arrives() {
    let mut g = G::new();
    let root = k("root");
    let (pa, a) = (k("phone a"), k("admin a"));
    g.admin(&pa, &a, POWER_ADMIT | POWER_MANAGE | POWER_REMOVE);
    g.device(&root, &k("d"), "d", |_| {});
    let mut set = set_with(&g.root.key, &g.recs, &g.lists);
    assert!(!set.ack_due(&set.state(), &a.hash), "nothing to acknowledge");
    let rv = g.root_rec(Kind::Revoke(removal(&[k("d").hash], g.seen())));
    set.insert(rv.clone()).unwrap();
    let st = set.state();
    assert!(set.ack_due(&st, &a.hash));
    let r = set.write_ack(&st, &a, 0).unwrap();
    let Kind::Ack { seen, spare: None } = &r.body().kind else { panic!() };
    assert!(seen.iter().any(|s| s.key == root.hash && s.seq >= rv.body().seq));
    assert!(!set.ack_due(&set.state(), &a.hash));
}

/// A removed admin key holds nothing back: only live admin keys must
/// acknowledge.
#[test]
fn a_removed_admin_holds_no_removal_back() {
    let mut g = G::new();
    let root = k("root");
    let (pa, a) = (k("phone a"), k("admin a"));
    g.admin(&pa, &a, POWER_ADMIT | POWER_MANAGE | POWER_REMOVE);
    g.device(&root, &k("d"), "d", |_| {});
    g.root_rec(Kind::Revoke(removal(&[a.hash], g.seen())));
    let rv = g.root_rec(Kind::Revoke(removal(&[k("d").hash], g.seen())));
    g.device(&root, &k("tv"), "tv", |_| {});
    let recs = g.recs.clone();
    let cp = root_checkpoint(&mut g, &recs);
    let Kind::Checkpoint { keep, .. } = &cp.body().kind else { panic!() };
    assert!(!keep.contains(&rv.id()), "the lost admin is no live admin");
}

/// Sixteen live admin keys: the removal waits until the last of them
/// acknowledges.
#[test]
fn sixteen_admins_each_hold_a_removal_back_until_they_acknowledge() {
    let mut g = G::new();
    let root = k("root");
    let admins: Vec<(K, K)> =
        (0..16).map(|i| (k(&alloc::format!("phone {i}")), k(&alloc::format!("admin {i}")))).collect();
    for (p, a) in &admins {
        g.admin(p, a, POWER_ADMIT);
    }
    g.device(&root, &k("d"), "d", |_| {});
    let rv = g.root_rec(Kind::Revoke(removal(&[k("d").hash], g.seen())));
    g.device(&root, &k("tv"), "tv", |_| {});
    for (_, a) in admins.iter().take(15) {
        ack(&mut g, a);
    }
    let set = set_with(&g.root.key, &g.recs, &g.lists);
    let waiting = set.unacknowledged(&set.state());
    assert_eq!(waiting.values().filter(|n| **n > 0).count(), 1);
    let recs = g.recs.clone();
    let cp = root_checkpoint(&mut g, &recs);
    let Kind::Checkpoint { keep, .. } = &cp.body().kind else { panic!() };
    assert!(keep.contains(&rv.id()), "one admin still holds it back");
    ack(&mut g, &admins[15].1);
    let recs = g.recs.clone();
    let cp = root_checkpoint(&mut g, &recs);
    let Kind::Checkpoint { keep, .. } = &cp.body().kind else { panic!() };
    assert!(!keep.contains(&rv.id()), "all sixteen saw it");
}

/// A lagging admin and a full room: the writer takes nobody back by
/// itself; the app shows the root's units the admin holds back, the
/// person takes the key back (the root's checkpoint first), the next
/// checkpoint lets the removal go, and the admin's record signed before,
/// delivered after, counts for nothing.
#[test]
fn the_person_takes_a_lagging_admin_back_when_the_room_fills() {
    let small = crate::records::keep::small::Small::new(64, 16, 8);
    let (g, late, mine) = late_record(true);
    let root = k("root");
    let a = k("admin a");
    for r in &mine {
        small.units(r.id(), 1);
    }
    let mut set = set_with(&g.root.key, &mine, &g.lists);
    // Fill the root's room past three quarters.
    let mut g = g;
    let mut extra = Vec::new();
    for i in 0..9 {
        let r = g.root_rec(Kind::Copies { secret_ttl_ms: 0, ttl_ms: 65_000 + i, seen: vec![] });
        small.units(r.id(), 1);
        extra.push(r);
    }
    for r in &extra {
        let _ = set.insert(r.clone());
    }
    let st = set.state();
    let heard: BTreeMap<KeyHash, u64> = [(a.hash, 0)].into();
    assert!(set.take_back_lagging(&st, &root, &heard, DAY_MS).unwrap().is_empty(), "nobody by the room alone");
    assert_eq!(set.unacknowledged_units(&st).get(&a.hash), Some(&1));
    let r = set.take_back(&st, &root, &a.hash, DAY_MS).unwrap();
    small.units(r.id(), 1);
    let st = set.state();
    assert!(st.device_by_key(&k("phone a").hash).is_some_and(|d| d.admin.is_none()), "taken back");
    assert!(has(&st, &k("x")), "what the admin admitted that counted stays");
    assert!(set.unacknowledged_units(&st).is_empty());
    let cp = set.write_checkpoint(&st, &root, DAY_MS).unwrap();
    let Kind::Checkpoint { keep, .. } = &cp.body().kind else { panic!() };
    assert!(!keep.contains(&removal_of(&g, &k("d"))), "no live admin holds it back");
    set.insert(cp).unwrap();
    let _ = set.insert(late.clone());
    let st = set.state();
    assert!(!has(&st, &k("d")), "the late record of the taken-back key counts for nothing");
}

/// The sizes a waiting removal and an acknowledgement take: one unit of
/// 512 bytes each for a plain removal and an acknowledgement of a root
/// and sixteen admin keys.
#[test]
fn a_removal_and_an_acknowledgement_take_a_unit_each() {
    let mut g = G::new();
    let root = k("root");
    let admins: Vec<(K, K)> =
        (0..16).map(|i| (k(&alloc::format!("phone {i}")), k(&alloc::format!("admin {i}")))).collect();
    for (p, a) in &admins {
        g.admin(p, a, POWER_ADMIT);
    }
    g.device(&root, &k("d"), "d", |_| {});
    let rv = g.root_rec(Kind::Revoke(removal(&[k("d").hash], Vec::new())));
    let ak = ack(&mut g, &admins[0].1);
    let units = |r: &Record| crate::records::keep::units(r.bytes.len() + crate::records::ENVELOPE_ALLOWANCE);
    assert_eq!(units(&rv), 1);
    assert!(units(&ak) <= 3, "{}", units(&ak));
}

const DAY_MS: u64 = 24 * 60 * 60 * 1000;

/// An admin key the root received nothing of for ADMIN_SILENCE_MS, on the
/// root device's clock, is taken back whatever the room; a day less is
/// not enough.
#[test]
fn a_silent_admin_is_taken_back_after_the_silence() {
    let (g, _, mine) = late_record(false);
    let root = k("root");
    let a = k("admin a");
    let mut set = set_with(&g.root.key, &mine, &g.lists);
    let heard: BTreeMap<KeyHash, u64> = [(a.hash, 1_000)].into();
    let st = set.state();
    let early = 1_000 + ADMIN_SILENCE_MS - DAY_MS;
    assert!(set.take_back_lagging(&st, &root, &heard, early).unwrap().is_empty(), "not silent long enough");
    let written = set.take_back_lagging(&st, &root, &heard, 1_000 + ADMIN_SILENCE_MS).unwrap();
    assert_eq!(written.len(), 1);
    assert_eq!(written[0].0, TakeBack::Silence);
    let st = set.state();
    assert!(st.device_by_key(&k("phone a").hash).is_some_and(|d| d.admin.is_none()), "taken back");
    assert!(st.device_by_key(&k("phone a").hash).is_some(), "the device stays a device");
}

/// A key the root device never heard from counts from the root record
/// that named it.
#[test]
fn an_admin_never_heard_from_counts_from_its_naming() {
    let (g, _, mine) = late_record(false);
    let root = k("root");
    let mut set = set_with(&g.root.key, &mine, &g.lists);
    let named = mine
        .iter()
        .filter(
            |r| matches!(&r.body().kind, Kind::Device(d) if d.admin.as_ref().map(Key::hash) == Some(k("admin a").hash)),
        )
        .map(|r| r.body().time_ms)
        .max()
        .unwrap();
    let st = set.state();
    let none = BTreeMap::new();
    assert!(set.take_back_lagging(&st, &root, &none, named + ADMIN_SILENCE_MS - 1).unwrap().is_empty());
    let written = set.take_back_lagging(&st, &root, &none, named + ADMIN_SILENCE_MS).unwrap();
    assert_eq!(written.len(), 1);
    assert_eq!(written[0].0, TakeBack::Silence);
}

/// last_ack gives the newest acknowledgement of a key that counts; one
/// above a record of its chain the set lacks counts for nothing yet.
#[test]
fn the_last_acknowledgement_is_the_newest() {
    let (mut g, late, mut mine) = late_record(false);
    let a = k("admin a");
    let set = set_with(&g.root.key, &mine, &g.lists);
    assert_eq!(set.last_ack(&set.state(), &a.hash), None);
    let first = ack(&mut g, &a);
    mine.push(first.clone());
    let set = set_with(&g.root.key, &mine, &g.lists);
    assert_eq!(set.last_ack(&set.state(), &a.hash), None, "its chain has a gap");
    mine.push(late);
    mine.push(g.device(&k("root"), &k("tv2"), "tv2", |_| {}));
    let second = ack(&mut g, &a);
    mine.push(second.clone());
    let set = set_with(&g.root.key, &mine, &g.lists);
    assert_eq!(set.last_ack(&set.state(), &a.hash), Some((second.body().seq, second.body().time_ms)));
}

/// A key taken back is never an admin again: the root's writer refuses
/// to grant it, grants a new key of the same device, and the old key's
/// admission the root never got counts for nothing.
#[test]
fn a_taken_back_key_is_never_granted_again() {
    let (g, late, mine) = late_record(false);
    let root = k("root");
    let (pa, a, a2) = (k("phone a"), k("admin a"), k("admin a new"));
    let mut set = set_with(&g.root.key, &mine, &g.lists);
    let heard: BTreeMap<KeyHash, u64> = [(a.hash, 0)].into();
    let st = set.state();
    for (_, r) in set.take_back_lagging(&st, &root, &heard, ADMIN_SILENCE_MS).unwrap() {
        let _ = set.insert(r);
    }
    let st = set.state();
    let cp = set.write_checkpoint(&st, &root, ADMIN_SILENCE_MS).unwrap();
    set.insert(cp).unwrap();
    let grant = |key: &K| {
        let mut d = Device::new(pa.key.clone(), "admin", ROLE_MEMBER);
        d.admin = Some(key.key.clone());
        d.powers = POWER_ADMIT | POWER_MANAGE | POWER_REMOVE;
        Kind::device(d)
    };
    let st = set.state();
    let err = set.write_record(&st, &root, grant(&a), ADMIN_SILENCE_MS).unwrap_err();
    assert!(alloc::format!("{err}").contains(ADMIN_KEY_TAKEN_BACK), "{err}");
    let r = set.write_record(&st, &root, grant(&a2), ADMIN_SILENCE_MS).unwrap().pop().unwrap();
    let _ = set.insert(r);
    let st = set.state();
    assert!(st.device_by_key(&pa.hash).is_some_and(|d| d.admin == Some(a2.hash)));
    let _ = set.insert(late);
    assert!(!has(&set.state(), &k("d")), "the old key's admission counts for nothing");
}

/// A taken-back key stays known to the honest writer however the device's
/// records go: the checkpoint never drops a record that names an admin
/// key, so the writer refuses the key again, for its device or another.
#[test]
fn a_taken_back_key_is_refused_after_checkpoints() {
    let mut g = G::new();
    let root = k("root");
    let (pa, pb, a) = (k("phone a"), k("phone b"), k("admin a"));
    g.device(&root, &pa, "phone a", |_| {});
    g.device(&root, &pb, "phone b", |_| {});
    let named = g.admin(&pa, &a, POWER_ADMIT | POWER_MANAGE | POWER_REMOVE);
    let mut mine: Vec<Record> = g.recs.clone();
    let mut set = set_with(&g.root.key, &mine, &g.lists);
    let heard: BTreeMap<KeyHash, u64> = [(a.hash, 0)].into();
    let st = set.state();
    for (_, r) in set.take_back_lagging(&st, &root, &heard, ADMIN_SILENCE_MS).unwrap() {
        mine.push(g.push(r));
    }
    for i in 0..3 {
        mine.push(g.device(&root, &pa, &alloc::format!("phone a, renamed {i}"), |_| {}));
        mine.push(root_checkpoint(&mut g, &mine));
    }
    let set = set_with(&g.root.key, &mine, &g.lists);
    assert!(set.contains(&named.id()), "the record that named the key stays");
    let grant = |member: &K| {
        let mut d = Device::new(member.key.clone(), "admin", ROLE_MEMBER);
        d.admin = Some(a.key.clone());
        d.powers = POWER_ADMIT | POWER_MANAGE | POWER_REMOVE;
        Kind::device(d)
    };
    let st = set.state();
    for m in [&pa, &pb] {
        let err = set.clone().write_record(&st, &root, grant(m), ADMIN_SILENCE_MS).unwrap_err();
        assert!(alloc::format!("{err}").contains(ADMIN_KEY_TAKEN_BACK), "{err}");
    }
}

/// What each admin holds back, in the root's units: an admin that
/// acknowledged the first removal holds back only the second; one whose
/// own record saw both holds back none; a removal an admin signed waits
/// for the others but takes nothing of the root's room.
#[test]
fn each_admin_holds_back_the_root_s_units_it_has_not_seen() {
    let mut g = G::new();
    let root = k("root");
    let (pa, a, pb, b) = (k("phone a"), k("admin a"), k("phone b"), k("admin b"));
    g.admin(&pa, &a, POWER_ADMIT | POWER_REMOVE);
    g.admin(&pb, &b, POWER_ADMIT);
    for d in ["d1", "d2"] {
        g.device(&root, &k(d), d, |_| {});
    }
    g.device(&a, &k("d3"), "d3", |_| {});
    let mut set = set_with(&g.root.key, &g.recs.clone(), &g.lists);
    let remove = |g: &mut G, set: &mut RecordSet, d: &str| {
        let st = set.state();
        for r in set.write_removal(&st, &root, &[k(d).hash], 0).unwrap() {
            let r = g.push(r);
            set.insert(r).unwrap();
        }
    };
    remove(&mut g, &mut set, "d1");
    let bk = ack(&mut g, &b);
    set.insert(bk).unwrap();
    remove(&mut g, &mut set, "d2");
    let seen = g.seen();
    let by_a = g.rec(&a, Kind::Revoke(removal(&[k("d3").hash], seen)));
    set.insert(by_a).unwrap();
    let st = set.state();
    let units = set.unacknowledged_units(&st);
    assert_eq!(units.get(&a.hash), Some(&0), "a's removal saw both of the root's");
    assert_eq!(units.get(&b.hash), Some(&1));
    assert_eq!(set.unacknowledged(&st).get(&b.hash), Some(&2), "the admin's removal waits for b too");
}

/// A removal of a device that has an admin key is kept for good, so it
/// waits for no acknowledgement: it is not counted against the other
/// admins, in removals or in units.
#[test]
fn a_removal_kept_for_good_waits_for_nobody() {
    let mut g = G::new();
    let root = k("root");
    let (pa, a, pb, b) = (k("phone a"), k("admin a"), k("phone b"), k("admin b"));
    g.admin(&pa, &a, POWER_ADMIT);
    g.admin(&pb, &b, POWER_ADMIT);
    let mut set = set_with(&g.root.key, &g.recs.clone(), &g.lists);
    let st = set.state();
    for r in set.write_removal(&st, &root, &[pa.hash], 0).unwrap() {
        set.insert(g.push(r)).unwrap();
    }
    set.insert(g.device(&root, &k("tv"), "tv", |_| {})).unwrap();
    let st = set.state();
    assert!(st.revoked.contains(&pa.hash) && st.revoked.contains(&a.hash));
    assert_eq!(set.unacknowledged(&st).get(&b.hash), Some(&0));
    assert!(!set.ack_due(&st, &b.hash));
    assert_eq!(set.unacknowledged_units(&st).get(&b.hash), Some(&0));
    let cp = set.write_checkpoint(&st, &root, 0).unwrap();
    let Kind::Checkpoint { keep, .. } = &cp.body().kind else { panic!() };
    assert!(keep.contains(&removal_of(&g, &pa)), "kept for good");
}

/// A frozen admin cannot acknowledge, so a removal it has not seen waits:
/// the writer takes nobody back for it (a freeze by an admin that may not
/// remove admins must not turn permanent); the app shows the key frozen
/// and holding the removal back, and the person takes it back (or thaws
/// it). Then the next checkpoint lets the removal go, and what the key
/// signed before that the root never got counts for nothing.
#[test]
fn a_frozen_admin_holds_a_removal_back_until_the_person_acts() {
    let (mut g, late, mut mine) = late_record(false);
    let root = k("root");
    let (pa, a) = (k("phone a"), k("admin a"));
    let seen = g.seen();
    mine.push(g.root_rec(Kind::Freeze(removal(&[a.hash], seen))));
    let mut set = set_with(&g.root.key, &mine, &g.lists);
    let st = set.state();
    assert!(st.device_by_key(&pa.hash).is_some_and(|d| d.frozen));
    assert!(RecordSet::frozen_admins(&st).contains(&a.hash));
    assert_eq!(set.unacknowledged(&st).get(&a.hash), Some(&1));
    let heard: BTreeMap<KeyHash, u64> = [(a.hash, 0)].into();
    assert!(set.take_back_lagging(&st, &root, &heard, DAY_MS).unwrap().is_empty(), "nobody by the freeze alone");
    let cp = set.write_checkpoint(&st, &root, DAY_MS).unwrap();
    let Kind::Checkpoint { keep, .. } = &cp.body().kind else { panic!() };
    assert!(keep.contains(&removal_of(&g, &k("d"))), "the settle waits for the frozen admin");
    set.insert(cp).unwrap();
    let st = set.state();
    set.take_back(&st, &root, &a.hash, DAY_MS).unwrap();
    let st = set.state();
    assert!(st.device_by_key(&pa.hash).is_some_and(|d| d.admin.is_none()), "taken back");
    let cp = set.write_checkpoint(&st, &root, DAY_MS).unwrap();
    let Kind::Checkpoint { keep, .. } = &cp.body().kind else { panic!() };
    assert!(!keep.contains(&removal_of(&g, &k("d"))), "no live admin holds it back");
    set.insert(cp).unwrap();
    let _ = set.insert(late);
    assert!(!has(&set.state(), &k("d")), "the frozen key's late record counts for nothing");
}

/// The root's own key is never taken back as an admin key.
#[test]
fn the_root_s_own_key_is_not_taken_back() {
    let (g, _, mine) = late_record(false);
    let root = k("root");
    let mut set = set_with(&g.root.key, &mine, &g.lists);
    let st = set.state();
    let err = set.take_back(&st, &root, &root.hash, 0).unwrap_err();
    assert!(alloc::format!("{err}").contains(crate::records::set::TAKE_BACK_ROOT), "{err}");
}

/// A frozen admin that holds nothing back stays an admin, and its thaw
/// gives it its rights back.
#[test]
fn a_frozen_admin_with_nothing_waiting_stays_and_thaws() {
    let mut g = G::new();
    let root = k("root");
    let (pa, a) = (k("phone a"), k("admin a"));
    g.admin(&pa, &a, POWER_ADMIT);
    g.device(&a, &k("x"), "x", |_| {});
    let seen = g.seen();
    let f = g.root_rec(Kind::Freeze(removal(&[a.hash], seen)));
    let mut set = set_with(&g.root.key, &g.recs.clone(), &g.lists);
    let st = set.state();
    assert!(st.device_by_key(&pa.hash).is_some_and(|d| d.frozen));
    assert!(set.take_back_lagging(&st, &root, &BTreeMap::new(), DAY_MS).unwrap().is_empty());
    let seen = g.seen();
    let thaw = g.root_rec(Kind::Thaw { ids: vec![f.id()], seen });
    set.insert(thaw).unwrap();
    let st = set.state();
    assert!(st.device_by_key(&pa.hash).is_some_and(|d| !d.frozen && d.admin == Some(a.hash)));
    assert!(has(&st, &k("x")), "what it signed before the freeze is back");
}

/// Wide removals by one admin and a removal by another, half the admins
/// acknowledge, a checkpoint, a take-back of one lagging admin
/// (`silence`: by the writer for its silence; else frozen, by the
/// person), and another
/// checkpoint: removals whose signers are still live admins stay held and
/// count while a live admin has not acknowledged them; once all have, a
/// removal under its signer's head goes. An admin's removal of another
/// admin's key counts only with POWER_REMOVE_ADMINS (`remove_admins`):
/// then it is kept for good; without, it never counted, and the
/// checkpoints are free to leave it out.
fn after_a_take_back_other_admins_removals_stay(silence: bool, remove_admins: bool) {
    let mut g = G::new();
    let root = k("root");
    let all = POWER_ADMIT | POWER_MANAGE | POWER_REMOVE;
    let admins: Vec<(K, K)> =
        (0..6).map(|i| (k(&alloc::format!("phone {i}")), k(&alloc::format!("admin {i}")))).collect();
    for (i, (p, a)) in admins.iter().enumerate() {
        g.admin(p, a, if i == 4 && remove_admins { all | POWER_REMOVE_ADMINS } else { all });
    }
    let (a2, a4) = (&admins[2].1, &admins[4].1);
    let wide: Vec<K> = (0..4).map(|i| k(&alloc::format!("wide {i}"))).collect();
    for d in &wide {
        g.device(a2, d, "wide", |_| {});
    }
    g.device(a4, &k("e"), "e", |_| {});
    let seen = g.seen();
    let r2 = g.rec(a2, Kind::Revoke(removal(&wide.iter().map(|d| d.hash).collect::<Vec<_>>(), seen)));
    let seen = g.seen();
    let r4 = g.rec(a4, Kind::Revoke(removal(&[k("e").hash], seen)));
    let seen = g.seen();
    let r45 = g.rec(a4, Kind::Revoke(removal(&[admins[5].1.hash], seen)));
    for (_, a) in admins.iter().take(3) {
        ack(&mut g, a);
    }
    let s0 = g.state();
    assert!(s0.counting.contains(&r2.id()) && s0.counting.contains(&r4.id()));
    assert_eq!(s0.counting.contains(&r45.id()), remove_admins);
    assert_eq!(s0.revoked.contains(&admins[5].1.hash), remove_admins);
    let mut mine = g.recs.clone();
    mine.push(root_checkpoint(&mut g, &mine));
    let lagging = &admins[3];
    if !silence {
        let seen = g.seen();
        mine.push(g.root_rec(Kind::Freeze(removal(&[lagging.1.hash], seen))));
    }
    let mut set = set_with(&g.root.key, &mine, &g.lists);
    let st = set.state();
    assert!(st.counting.contains(&r2.id()) && st.counting.contains(&r4.id()), "both wait after the first checkpoint");
    let mut heard: BTreeMap<KeyHash, u64> = admins.iter().map(|(_, a)| (a.hash, ADMIN_SILENCE_MS)).collect();
    if silence {
        heard.insert(lagging.1.hash, 0);
    }
    let back = set.take_back_lagging(&st, &root, &heard, ADMIN_SILENCE_MS).unwrap();
    if silence {
        assert_eq!(back.len(), 1);
        assert!(
            back[0].0 == TakeBack::Silence
                && matches!(&back[0].1.body().kind, Kind::Device(d) if d.key.hash() == lagging.0.hash)
        );
    } else {
        // Frozen: the writer waits for the person, who takes it back.
        assert!(back.is_empty());
        assert!(RecordSet::frozen_admins(&st).contains(&lagging.1.hash));
        set.take_back(&st, &root, &lagging.1.hash, ADMIN_SILENCE_MS).unwrap();
    }
    let st = set.state();
    let cp = set.write_checkpoint(&st, &root, ADMIN_SILENCE_MS).unwrap();
    set.insert(cp).unwrap();
    let st = set.state();
    if remove_admins {
        // Admin 5 is out: every live admin saw both removals, which go
        // with the admissions; the removal of an admin key stays for good.
        for r in [&r2, &r4] {
            assert!(!set.contains(&r.id()), "settled once the lagging admin is taken back");
        }
        for d in wide.iter().chain([&k("e")]) {
            assert!(!has(&st, d));
        }
        assert!(set.contains(&r45.id()) && st.counting.contains(&r45.id()), "a removal of an admin key stays");
        assert!(st.revoked.contains(&admins[5].1.hash) && st.revoked.contains(&admins[5].0.hash));
        let cp = set.write_checkpoint(&st, &root, ADMIN_SILENCE_MS).unwrap();
        set.insert(cp).unwrap();
        assert!(set.contains(&r45.id()) && set.state().revoked.contains(&admins[5].1.hash), "kept for good");
        return;
    }
    // Admin 5 has acknowledged neither; admin 4 saw admin 2's.
    for r in [&r2, &r4] {
        assert!(set.contains(&r.id()) && st.counting.contains(&r.id()), "a removal waits for live admins");
    }
    for d in wide.iter().chain([&k("e")]) {
        assert!(st.revoked.contains(&d.hash));
    }
    // Once every live admin acknowledges, the next checkpoint lets admin
    // 2's go.
    for i in [0, 1, 2, 4, 5] {
        let a = &admins[i].1;
        let st = set.state();
        if set.ack_due(&st, &a.hash) {
            set.write_ack(&st, a, ADMIN_SILENCE_MS).unwrap();
        }
    }
    let st = set.state();
    assert!(set.unacknowledged(&st).values().all(|n| *n == 0), "{:?}", set.unacknowledged(&st));
    let cp = set.write_checkpoint(&st, &root, ADMIN_SILENCE_MS).unwrap();
    let Kind::Checkpoint { keep, heads } = &cp.body().kind else { panic!() };
    assert!(!keep.contains(&r2.id()), "every live admin saw admin 2's removal");
    assert!(heads.iter().any(|h| h.id == r4.id()), "admin 4's removal stays as its head until it signs again");
}

#[test]
fn after_a_silence_take_back_other_admins_removals_stay() {
    after_a_take_back_other_admins_removals_stay(true, false);
    after_a_take_back_other_admins_removals_stay(true, true);
}

#[test]
fn after_a_frozen_take_back_other_admins_removals_stay() {
    after_a_take_back_other_admins_removals_stay(false, false);
    after_a_take_back_other_admins_removals_stay(false, true);
}

/// The writer gives back every record it added, in the order they go out:
/// an admin key's first record comes after the acknowledgement written
/// before it, so a member that takes exactly what the writer gave misses
/// nothing and counts both; a later record is given alone.
#[test]
fn a_member_that_takes_what_the_writer_gave_misses_nothing() {
    let mut g = G::new();
    let (pa, a) = (k("phone a"), k("admin a"));
    g.admin(&pa, &a, POWER_ADMIT);
    let mut writer = set_with(&g.root.key, &g.recs, &g.lists);
    let mut member = set_with(&g.root.key, &g.recs, &g.lists);
    for (i, alone) in [(0, false), (1, true)] {
        let st = writer.state();
        let d = Device::new(k(&format!("laptop {i}")).key.clone(), "laptop", ROLE_MEMBER);
        let given = writer.write_record(&st, &a, Kind::device(d), 0).unwrap();
        assert_eq!(given.len(), if alone { 1 } else { 2 }, "record {i}");
        if !alone {
            assert!(matches!(given[0].body().kind, Kind::Ack { .. }), "the ack goes first");
        }
        for r in &given {
            member.insert(r.clone()).unwrap();
        }
        let ms = member.state();
        assert!(member.missing(&ms).is_empty(), "record {i}");
        assert!(given.iter().all(|r| ms.counting.contains(&r.id())), "record {i}");
        assert_eq!(ms.devices, writer.state().devices, "record {i}");
    }
}

/// No acknowledgement is due while the group is stopped, where the writer
/// refuses it: a removal the admin has not acknowledged, then a root fork.
#[test]
fn no_ack_is_due_while_the_group_is_stopped() {
    let mut g = G::new();
    let (pa, a) = (k("phone a"), k("admin a"));
    g.admin(&pa, &a, POWER_ADMIT | POWER_REMOVE);
    g.device(&k("root"), &k("d"), "d", |_| {});
    g.root_rec(Kind::Revoke(removal(&[k("d").hash], g.seen())));
    let set = set_with(&g.root.key, &g.recs, &g.lists);
    assert!(set.ack_due(&set.state(), &a.hash));
    let r = g.root_rec(Kind::Copies { secret_ttl_ms: 0, ttl_ms: 110_000, seen: vec![] });
    let twin = root_twin(&g, &r, Kind::Copies { secret_ttl_ms: 0, ttl_ms: 60_000, seen: vec![] });
    g.recs.push(twin);
    let mut set = set_with(&g.root.key, &g.recs, &g.lists);
    let st = set.state();
    assert_eq!(st.stop, crate::records::eval::Stop::Full);
    assert!(set.write_ack(&st, &a, 0).is_err());
    assert!(!set.ack_due(&st, &a.hash));
}
