// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The last root only (L) with the new root's re-issue (B), read from the
//! rules only (L-note, the owner's decision of 00:05Z): after a change,
//! only the new root's records, the records of admin keys it names, and
//! the recovery chain count. The new root re-issues, as its own records,
//! every device that counts at its device (whoever admitted it), except
//! those the person leaves out (no removal is written for them), with the
//! newest settings, hubs and copies records and every counting freeze;
//! every old admin loses its rights (its device stays as a plain device).
//! The change applies whole or not at all. Cases the code before L does
//! not meet are marked to wait for it.

mod pieces;

use cbb_core::records::body::{Device, ROLE_PHONE, Removal, Seen};
use cbb_core::records::set::CHANGE_WAITING;
use cbb_core::records::{Kind, Record, RecordSet};
use pieces::*;

fn names(s: &cbb_core::records::State) -> Vec<String> {
    let mut v: Vec<String> = s.devices.iter().map(|d| d.name.clone()).collect();
    v.sort();
    v
}

/// The group, a member that holds the same records, and the writer's
/// change to root 2 on phone P2, leaving out `leave_out`.
fn changed(tag: &str, leave_out: &[&K]) -> (Group, RecordSet, cbb_core::records::set::Written) {
    let mut g = group(tag);
    let member = g.set.clone();
    g.t += 1_000;
    let out: Vec<_> = leave_out.iter().map(|x| x.hash).collect();
    let w = change(&mut g.set, &k(&format!("{tag} root 2")), &k("P2"), &out, g.t);
    (g, member, w)
}

/// L1.1, with oldRootResolveStays: D and E (the old root's), F (admitted
/// by admin A) and PA (A's own device) are re-issued as the new root's
/// own records and count; A is no longer an admin, PA stays a plain
/// device; every field but the signer is the device's newest counting
/// record's. A member that held the old state reaches the same.
#[test]
#[ignore = "waits for L + B"]
fn after_a_change_only_the_new_root_counts() {
    let (g, mut member, _) = changed("l1", &[]);
    let before = member.state();
    let st = g.set.state();
    assert_eq!(st.roots.last(), Some(&k("l1 root 2").hash));
    assert_eq!(names(&st), ["D", "E", "F", "PA", "new phone"]);
    assert!(
        st.devices.iter().all(|d| d.admin.is_none()),
        "every old admin loses its rights: {:?}",
        st.devices.iter().filter(|d| d.admin.is_some()).map(|d| &d.name).collect::<Vec<_>>()
    );
    assert!(st.devices.iter().all(|d| d.by_root), "every device is the new root's own record");
    for m in ["D", "E", "F"] {
        let (old, new) = (before.device_by_key(&k(m).hash).unwrap(), st.device_by_key(&k(m).hash).unwrap());
        let strip = |d: &cbb_core::records::eval::DeviceState| {
            let mut d = d.clone();
            d.by_root = true;
            d
        };
        assert_eq!(strip(old), strip(new), "{m}: re-issued from its newest counting record");
    }
    let pa = st.device_by_key(&k("PA").hash).unwrap();
    assert!(pa.admin.is_none() && !pa.frozen, "A's own device stays, as a plain device");
    sync(&g.set, &mut member);
    assert_eq!(view(&member.state()), view(&st));
    same_in_every_order(&g.set, "after the change");
}

/// The person's leave-out list: D and F are left out. No removal is
/// written for them; they count at no member after the change, even when
/// an old root's or an old admin's record about them arrives later.
#[test]
#[ignore = "waits for L + B"]
fn a_left_out_device_counts_nowhere_whatever_arrives_later() {
    let (mut g, mut member, w) = changed("l2", &[&k("D"), &k("F")]);
    assert!(w.first.iter().all(|r| !matches!(r.body().kind, Kind::Revoke(_))), "leaving out writes no removal");
    let a = k("A");
    // Late records about D and F, by the old root and by the old admin.
    g.t += 1_000;
    let late_root = g.chain.sign(&g.set, &g.r1, Kind::device(plain(&k("D"), "D back")), g.t);
    let mut chain = Chain::new();
    chain.follow(&member, &g.r1);
    let late_root = {
        let _ = late_root;
        chain.sign(&member, &g.r1, Kind::device(plain(&k("D"), "D back")), g.t)
    };
    g.chain.follow(&member, &a);
    g.t += 1_000;
    let mut f = plain(&k("F"), "F back");
    f.seen = vec![head_of(&member, &g.r1.hash).unwrap()];
    let late_admin = g.chain.sign(&member, &a, Kind::device(f), g.t);
    for set in [&mut g.set, &mut member] {
        let _ = set.insert(late_root.clone());
        let _ = set.insert(late_admin.clone());
    }
    sync(&g.set, &mut member);
    for (who, set) in [("writer", &g.set), ("member", &member)] {
        let st = set.state();
        assert_eq!(st.roots.last(), Some(&k("l2 root 2").hash), "{who}");
        assert!(!has(&st, &k("D")) && !has(&st, &k("F")), "{who}: left out, counts nowhere: {:?}", names(&st));
        assert!(has(&st, &k("E")) && has(&st, &k("PA")), "{who}");
    }
}

/// L1.3: an old root's and an old admin's records that arrive after the
/// change count for nothing and are not kept: a flood of them leaves the
/// set's bytes and state as they were.
#[test]
#[ignore = "waits for L + B"]
fn old_records_after_the_change_are_not_kept() {
    let (mut g, member, _) = changed("l3", &[]);
    let before = (view(&g.set.state()), g.set.bytes(), g.set.len());
    let a = k("A");
    let mut chain = Chain::new();
    chain.follow(&member, &g.r1);
    chain.follow(&member, &a);
    let mut late = Vec::new();
    for i in 0..200u32 {
        g.t += 10;
        let x = k(&format!("flood {i}"));
        let by = if i % 2 == 0 { &g.r1 } else { &a };
        late.push(chain.sign(&member, by, Kind::device(plain(&x, "flood")), g.t));
    }
    for r in late {
        let id = r.id();
        let _ = g.set.insert(r);
        assert!(!g.set.contains(&id), "an old signer's record is not kept");
    }
    assert_eq!((view(&g.set.state()), g.set.bytes(), g.set.len()), before);
}

/// The writer holds D's admission but not the old root's removal of D
/// (a member has it): D is re-issued; after both sync, D counts at both,
/// the old removal counting for nothing (the new root's view is the
/// truth).
#[test]
fn a_removal_the_writer_never_got_does_not_count_after_the_change() {
    let mut g = group("l4");
    let mut member = g.set.clone();
    let st = member.state();
    g.t += 1_000;
    for r in member.write_removal(&st, &g.r1, &[k("D").hash], g.t).unwrap() {
        let _ = member.insert(r);
    }
    assert!(!has(&member.state(), &k("D")));
    g.t += 1_000;
    change(&mut g.set, &k("l4 root 2"), &k("P2"), &[], g.t);
    sync(&g.set, &mut member);
    sync(&member, &mut g.set);
    for (who, set) in [("writer", &g.set), ("member", &member)] {
        assert!(has(&set.state(), &k("D")), "{who}: re-issued, the old removal void");
    }
    assert_eq!(view(&member.state()), view(&g.set.state()));
}

/// oldRootResolveStays, the other side: a device that counted only
/// through a record that does not count at the writer is not re-issued.
/// The root removes A (its device and key) before A's admission of G
/// reaches it; that admission is void there, so G is not re-issued, and
/// a member that counted G stops counting it once the change applies.
#[test]
fn a_device_counting_only_through_a_void_record_is_not_reissued() {
    let mut g = group("l5");
    let a = k("A");
    let mut member = g.set.clone();
    g.t += 1_000;
    let mut gd = plain(&k("G"), "G");
    gd.seen = vec![head_of(&member, &g.r1.hash).unwrap()];
    let g_adm = g.chain.sign(&member, &a, Kind::device(gd), g.t);
    member.insert(g_adm.clone()).unwrap();
    assert!(has(&member.state(), &k("G")), "the member counts G");
    let st = g.set.state();
    g.t += 1_000;
    for r in g.set.write_removal(&st, &g.r1, &[k("PA").hash], g.t).unwrap() {
        let _ = g.set.insert(r);
    }
    let _ = g.set.insert(g_adm);
    assert!(!has(&g.set.state(), &k("G")), "void at the writer");
    g.t += 1_000;
    change(&mut g.set, &k("l5 root 2"), &k("P2"), &[], g.t);
    sync(&g.set, &mut member);
    for (who, set) in [("writer", &g.set), ("member", &member)] {
        let st = set.state();
        assert!(!has(&st, &k("G")), "{who}: not re-issued");
        assert!(!has(&st, &k("PA")), "{who}: removed before the change");
    }
}

/// The gate (L2.1): a member that holds the head and the first checkpoint
/// but not one re-issued record keeps the old state whole; once it
/// arrives, the change applies.
#[test]
#[ignore = "waits for L + B"]
fn the_change_applies_whole_or_not_at_all() {
    let (g, mut member, w) = changed("l6", &[]);
    let old = view(&member.state());
    let missing = w
        .first
        .iter()
        .find(|r| matches!(&r.body().kind, Kind::Device(d) if d.key.hash() == k("F").hash))
        .expect("F's re-issue among the first records")
        .id();
    let lists: Vec<Vec<u8>> = g.set.lists().map(<[u8]>::to_vec).collect();
    let all: Vec<Record> = g.set.in_dependency_order().into_iter().cloned().collect();
    let without: Vec<Record> = all.iter().filter(|r| r.id() != missing).cloned().collect();
    offer(&mut member, &lists, &without);
    assert_eq!(view(&member.state()), old, "pending: the old state, whole");
    offer(&mut member, &lists, &all);
    assert_eq!(view(&member.state()), view(&g.set.state()));
}

/// L2.2 and L2.3: while the change is pending at a member, the old admin
/// still acts there (removes D, admits G); once the change applies, D is
/// back (re-issued) and G is out.
#[test]
#[ignore = "waits for L + B"]
fn what_an_old_admin_does_while_a_change_is_pending_turns_void() {
    let (mut g, mut member, w) = changed("l7", &[]);
    let a = k("A");
    let missing = w
        .first
        .iter()
        .find(|r| matches!(&r.body().kind, Kind::Device(d) if d.key.hash() == k("E").hash))
        .expect("E's re-issue among the first records")
        .id();
    let lists: Vec<Vec<u8>> = g.set.lists().map(<[u8]>::to_vec).collect();
    let all: Vec<Record> = g.set.in_dependency_order().into_iter().cloned().collect();
    let without: Vec<Record> = all.iter().filter(|r| r.id() != missing).cloned().collect();
    offer(&mut member, &lists, &without);
    let root_head = head_of(&member, &g.r1.hash).unwrap();
    g.t += 1_000;
    let rm = g.chain.sign(&member, &a, Kind::Revoke(removal(&[&k("D")], vec![root_head])), g.t);
    member.insert(rm).unwrap();
    g.t += 1_000;
    let mut gd = plain(&k("G"), "G");
    gd.seen = vec![root_head];
    let adm = g.chain.sign(&member, &a, Kind::device(gd), g.t);
    member.insert(adm).unwrap();
    let st = member.state();
    assert!(!has(&st, &k("D")) && has(&st, &k("G")), "pending: the old admin still counts here");
    offer(&mut member, &lists, &all);
    let st = member.state();
    assert!(has(&st, &k("D")), "D came back with the change");
    assert!(!has(&st, &k("G")), "G, admitted by an old admin, is out");
    assert_eq!(view(&st), view(&g.set.state()));
}

/// L3.1 under L: the new root is a fresh key; an old admin key cannot
/// become the root.
#[test]
fn the_new_root_is_a_fresh_key() {
    let mut g = group("l8");
    let st = g.set.state();
    let p = Device::new(k("P2").key.clone(), "new phone", ROLE_PHONE);
    let err = g.set.write_change(&st, &k("recovery"), &rk2(), &k("A"), p, &[], false, g.t + 1);
    assert!(err.is_err(), "an admin key of the old root does not become the root");
}

/// L3.2: the new root does not name an old root's admin key again.
#[test]
#[ignore = "rule changed by architecture 05:33Z: the core lets the new root name it (kit rule); see the attack test below"]
fn the_new_root_does_not_name_an_old_admin_key_again() {
    let (mut g, _, _) = changed("l9", &[]);
    let r2 = k("l9 root 2");
    let st = g.set.state();
    g.t += 1_000;
    let again = g.set.write_record(&st, &r2, Kind::device(admin_device(&k("PA"), "PA", &k("A"))), g.t);
    assert!(again.is_err(), "an admin key under an earlier root is not named again");
    g.t += 1_000;
    let fresh = g.set.write_record(&st, &r2, Kind::device(admin_device(&k("PA"), "PA", &k("A new"))), g.t);
    assert!(fresh.is_ok(), "a fresh key is: {fresh:?}");
}

/// L3.3: the count of admin keys restarts with each root: the old root
/// used 16, the new root names 16 fresh ones.
#[test]
#[ignore = "waits for L + B"]
fn sixteen_fresh_admins_after_a_change() {
    let mut g = group("l10");
    for i in 1..16u32 {
        let st = g.set.state();
        g.t += 1_000;
        let d = admin_device(&k(&format!("old phone {i}")), "old", &k(&format!("old admin {i}")));
        g.set.write_record(&st, &g.r1, Kind::device(d), g.t).unwrap();
    }
    assert_eq!(g.set.state().devices.iter().filter(|d| d.admin.is_some()).count(), 16);
    g.t += 1_000;
    change(&mut g.set, &k("l10 root 2"), &k("P2"), &[], g.t);
    let r2 = k("l10 root 2");
    for i in 0..16u32 {
        let st = g.set.state();
        g.t += 1_000;
        let d = admin_device(&k(&format!("new phone {i}")), "new", &k(&format!("new admin {i}")));
        g.set.write_record(&st, &r2, Kind::device(d), g.t).unwrap_or_else(|e| panic!("new admin {i}: {e:?}"));
    }
    assert_eq!(g.set.state().devices.iter().filter(|d| d.admin.is_some()).count(), 16);
}

/// L3.4: after the change, the old admin signs a removal whose seen names
/// the new root's records: still void, the new root never named it.
#[test]
#[ignore = "waits for L + B"]
fn an_old_admin_s_record_after_the_change_is_void() {
    let (mut g, member, _) = changed("l11", &[]);
    let a = k("A");
    g.chain.follow(&member, &a);
    let seen: Vec<Seen> = [head_of(&g.set, &k("l11 root 2").hash).unwrap()].into();
    g.t += 1_000;
    let rm = g.chain.sign(&g.set, &a, Kind::Revoke(Removal { keys: vec![k("E").hash], seen }), g.t);
    let _ = g.set.insert(rm);
    assert!(has(&g.set.state(), &k("E")));
}

/// L4.1: the re-issue carries the newest settings, hubs and copies
/// records: away-from-home sync goes on after the change.
#[test]
fn settings_hubs_and_copies_are_carried() {
    let (g, member, _) = changed("l12", &[]);
    let (old, st) = (member.state(), g.set.state());
    assert_eq!(st.settings, old.settings, "settings");
    assert_eq!(st.hubs, old.hubs, "hubs");
    assert_eq!(st.incoming_ms, old.incoming_ms, "copies");
}

/// L4.3: a full group (256 devices with settings, hubs and copies) fits
/// the new root's room, with room left for a checkpoint and a removal.
#[test]
fn a_full_group_fits_the_new_root_s_room() {
    let mut g = group("l13");
    let mut i = 0u32;
    while g.set.state().devices.len() < 255 {
        let st = g.set.state();
        g.t += 100;
        let x = k(&format!("many {i}"));
        if let Err(e) = g.set.write_record(&st, &g.r1, Kind::device(plain(&x, "many")), g.t) {
            assert!(format!("{e:?}").contains("checkpoint"), "{e:?}");
            let cp = g.set.write_checkpoint(&st, &g.r1, g.t).unwrap();
            g.set.insert(cp).unwrap();
            continue;
        }
        i += 1;
    }
    g.t += 1_000;
    change(&mut g.set, &k("l13 root 2"), &k("P2"), &[], g.t);
    let st = g.set.state();
    assert_eq!(st.devices.len(), 256);
    let room = g.set.root_room(&st).unwrap();
    println!("a full group's re-issue: {} of {} units", room.used, room.cap);
    let r2 = k("l13 root 2");
    g.t += 1_000;
    let rm = g.set.write_removal(&st, &r2, &[k("many 0").hash], g.t).expect("a removal still fits");
    for r in rm {
        g.set.insert(r).unwrap();
    }
    let st = g.set.state();
    g.t += 1_000;
    g.set.write_checkpoint(&st, &r2, g.t).expect("and a checkpoint");
}

/// L4.5: the re-issue carries every counting freeze (the old root's and an
/// old admin's) as the new root's own freeze of the device's member key
/// (a freeze is on the device, not on the admin key). Here the frozen
/// admins are kept through their spares (S): the root froze B, admin A
/// froze C; after the change PB and PC hold their spares and stay frozen;
/// an old admin's thaw after the change is void; the new root's thaw
/// counts.
#[test]
#[ignore = "waits for L + B and S"]
fn freezes_are_carried_and_only_the_new_root_thaws() {
    let mut g = group("l14");
    let (a, b, c) = (k("A"), k("B"), k("C"));
    for (p, x) in [("PB", &b), ("PC", &c)] {
        let st = g.set.state();
        g.t += 1_000;
        let mut d = admin_device(&k(p), p, x);
        d.powers &= !cbb_core::records::body::POWER_REMOVE_ADMINS;
        g.set.write_record(&st, &g.r1, Kind::device(d), g.t).unwrap();
    }
    for (x, spare) in [(&b, "SB"), (&c, "SC")] {
        g.t += 1_000;
        let seen = vec![head_of(&g.set, &g.r1.hash).unwrap()];
        let ack = g.chain.sign(&g.set, x, Kind::Ack { seen, spare: Some(k(spare).key.clone()) }, g.t);
        g.set.insert(ack).unwrap();
    }
    let st = g.set.state();
    g.t += 1_000;
    let seen = vec![head_of(&g.set, &g.r1.hash).unwrap()];
    g.set.write_record(&st, &g.r1, Kind::Freeze(removal(&[&b], seen.clone())), g.t).unwrap();
    g.t += 1_000;
    let fc = g.chain.sign(&g.set, &a, Kind::Freeze(removal(&[&c], seen)), g.t);
    g.set.insert(fc.clone()).unwrap();
    assert!(frozen(&g.set.state(), &k("PB")), "the root froze B");
    assert!(frozen(&g.set.state(), &k("PC")), "A froze C: {:?}", g.set.state().ignored);
    g.t += 1_000;
    let w = change(&mut g.set, &k("l14 root 2"), &k("P2"), &[], g.t);
    let st = g.set.state();
    assert_eq!(admin_of(&st, &k("PB")), Some(k("SB").hash), "kept through its spare");
    assert_eq!(admin_of(&st, &k("PC")), Some(k("SC").hash), "kept through its spare");
    assert!(frozen(&st, &k("PB")) && frozen(&st, &k("PC")), "frozen stays frozen");
    g.t += 1_000;
    let thaw = g.chain.sign(&g.set, &a, Kind::Thaw { ids: vec![fc.id()], seen: vec![] }, g.t);
    let _ = g.set.insert(thaw);
    assert!(frozen(&g.set.state(), &k("PC")), "an old admin's thaw is void");
    let r2_freeze = w
        .first
        .iter()
        .find(|r| matches!(&r.body().kind, Kind::Freeze(f) if f.keys.contains(&k("PC").hash)))
        .expect("PC's freeze, on its member key, among the first records")
        .id();
    let st = g.set.state();
    g.t += 1_000;
    let r2 = k("l14 root 2");
    g.set.write_record(&st, &r2, Kind::Thaw { ids: vec![r2_freeze], seen: vec![] }, g.t).unwrap();
    assert!(!frozen(&g.set.state(), &k("PC")), "the new root thaws");
    assert!(frozen(&g.set.state(), &k("PB")), "and only what it names");
}

/// A frozen admin without a spare: at the change its device is re-issued
/// as a plain device and stays frozen (only the new root thaws); with a
/// spare, the spare is named, the device stays frozen, and the spare's
/// records do not count until the new root thaws it.
#[test]
#[ignore = "waits for L + B and S"]
fn a_frozen_admin_s_device_stays_frozen_with_or_without_a_spare() {
    let mut g = group("l20");
    let (b, c) = (k("B"), k("C"));
    for (p, x) in [("PB", &b), ("PC", &c)] {
        let st = g.set.state();
        g.t += 1_000;
        let mut d = admin_device(&k(p), p, x);
        d.powers &= !cbb_core::records::body::POWER_REMOVE_ADMINS;
        g.set.write_record(&st, &g.r1, Kind::device(d), g.t).unwrap();
    }
    // Only C publishes a spare.
    g.t += 1_000;
    let seen = vec![head_of(&g.set, &g.r1.hash).unwrap()];
    let ack = g.chain.sign(&g.set, &c, Kind::Ack { seen: seen.clone(), spare: Some(k("SC").key.clone()) }, g.t);
    g.set.insert(ack).unwrap();
    let st = g.set.state();
    g.t += 1_000;
    let seen = vec![head_of(&g.set, &g.r1.hash).unwrap()];
    g.set.write_record(&st, &g.r1, Kind::Freeze(removal(&[&b, &c], seen)), g.t).unwrap();
    assert!(frozen(&g.set.state(), &k("PB")) && frozen(&g.set.state(), &k("PC")));
    g.t += 1_000;
    let w = change(&mut g.set, &k("l20 root 2"), &k("P2"), &[], g.t);
    let r2 = k("l20 root 2");
    let st = g.set.state();
    assert_eq!(admin_of(&st, &k("PB")), None, "no spare: a plain device");
    assert!(frozen(&st, &k("PB")), "and still frozen");
    assert_eq!(admin_of(&st, &k("PC")), Some(k("SC").hash), "the spare is named");
    assert!(frozen(&st, &k("PC")), "and the device still frozen");
    let mut chain = Chain::new();
    g.t += 1_000;
    let seen = vec![head_of(&g.set, &r2.hash).unwrap()];
    let rm = chain.sign(&g.set, &k("SC"), Kind::Revoke(removal(&[&k("E")], seen.clone())), g.t);
    let _ = g.set.insert(rm.clone());
    assert!(has(&g.set.state(), &k("E")), "a frozen device's spare signs nothing that counts");
    let freeze = w
        .first
        .iter()
        .find(|r| matches!(&r.body().kind, Kind::Freeze(f) if f.keys.contains(&k("PC").hash)))
        .expect("PC's freeze among the first records")
        .id();
    let st = g.set.state();
    g.t += 1_000;
    g.set.write_record(&st, &r2, Kind::Thaw { ids: vec![freeze], seen: vec![] }, g.t).unwrap();
    assert!(!frozen(&g.set.state(), &k("PC")));
    g.t += 1_000;
    let seen = vec![head_of(&g.set, &r2.hash).unwrap()];
    let rm2 = chain.sign(&g.set, &k("SC"), Kind::Revoke(removal(&[&k("E")], seen)), g.t);
    g.set.insert(rm2).unwrap();
    assert!(!has(&g.set.state(), &k("E")), "after the thaw the spare's removal counts");
    assert!(frozen(&g.set.state(), &k("PB")), "PB stays frozen");
}

/// L5.1, accepted behaviour (pinned so that nobody "fixes" it): a key the
/// old root removed counts nowhere after the change, and an ordinary
/// admission under the new root admits it again, and it counts.
#[test]
#[ignore = "waits for L + B"]
fn a_key_the_old_root_removed_is_admitted_again_only_by_a_new_admission() {
    let mut g = group("l21");
    let st = g.set.state();
    g.t += 1_000;
    for r in g.set.write_removal(&st, &g.r1, &[k("D").hash], g.t).unwrap() {
        g.set.insert(r).unwrap();
    }
    let mut member = g.set.clone();
    g.t += 1_000;
    change(&mut g.set, &k("l21 root 2"), &k("P2"), &[], g.t);
    sync(&g.set, &mut member);
    for (who, set) in [("writer", &g.set), ("member", &member)] {
        assert!(!has(&set.state(), &k("D")), "{who}: removed before the change, counts nowhere");
    }
    let r2 = k("l21 root 2");
    let st = g.set.state();
    g.t += 1_000;
    g.set
        .write_record(&st, &r2, Kind::device(plain(&k("D"), "D again")), g.t)
        .expect("an ordinary admission under the new root admits the key again");
    sync(&g.set, &mut member);
    for (who, set) in [("writer", &g.set), ("member", &member)] {
        assert!(has(&set.state(), &k("D")), "{who}: admitted again");
    }
}

/// L5.4: a removal that waits for acknowledgements at the change: the
/// device is not re-issued, and nothing of W's waits after the change.
#[test]
#[ignore = "waits for L + B"]
fn a_removal_waiting_for_acks_is_settled_by_the_change() {
    let mut g = group("l15");
    let st = g.set.state();
    g.t += 1_000;
    for r in g.set.write_removal(&st, &g.r1, &[k("E").hash], g.t).unwrap() {
        g.set.insert(r).unwrap();
    }
    assert!(!g.set.removals_waiting(&g.set.state()).is_empty(), "waits for A");
    g.t += 1_000;
    change(&mut g.set, &k("l15 root 2"), &k("P2"), &[], g.t);
    let st = g.set.state();
    assert!(!has(&st, &k("E")));
    assert!(g.set.removals_waiting(&st).is_empty());
    assert!(g.set.unacknowledged(&st).values().all(|n| *n == 0));
    assert!(RecordSet::frozen_admins(&st).is_empty());
}

/// L6.1: two changes in a row; a member that never applied the first
/// takes both and reaches the writer's state, with the device only root 2
/// admitted carried by root 3's re-issue.
#[test]
fn two_changes_in_a_row_reach_a_member_that_slept() {
    let (mut g, mut member, _) = changed("l16", &[]);
    let r2 = k("l16 root 2");
    let st = g.set.state();
    g.t += 1_000;
    g.set.write_record(&st, &r2, Kind::device(plain(&k("H"), "H")), g.t).unwrap();
    g.t += 1_000;
    change(&mut g.set, &k("l16 root 3"), &k("P3"), &[], g.t);
    let st = g.set.state();
    assert_eq!(st.roots.last(), Some(&k("l16 root 3").hash));
    assert!(has(&st, &k("H")));
    sync(&g.set, &mut member);
    assert_eq!(view(&member.state()), view(&st));
}

/// A device that holds a change it has not applied does not write a
/// second change (it would sign a second record at that seq).
#[test]
fn a_writer_holding_an_unapplied_change_refuses() {
    let (g, mut member, w) = changed("l17", &[]);
    let _ = member.insert(w.record.clone());
    let st = member.state();
    assert_ne!(st.roots.last(), Some(&k("l17 root 2").hash), "not applied without its first records");
    let p = Device::new(k("P3").key.clone(), "other phone", ROLE_PHONE);
    let err = member.write_change(&st, &k("recovery"), &rk2(), &k("l17 root 3"), p, &[], false, g.t + 1).unwrap_err();
    assert!(format!("{err}").contains(CHANGE_WAITING), "{err}");
}

/// L6.4: two changes at one seq (the recovery key used on two devices):
/// a member holding both stops for good.
#[test]
fn two_changes_at_one_seq_stop_the_group() {
    let (g, mut member, _) = changed("l18", &[]);
    let mut other = group("l18");
    change(&mut other.set, &k("l18 root 2b"), &k("P2b"), &[], other.t + 1_000);
    sync(&g.set, &mut member);
    sync(&other.set, &mut member);
    let st = member.state();
    assert!(st.fork.is_some() || st.stopped(), "a recovery fork stops the group: {:?}", st.fork);
}

/// L7.1: a member restored from what the writer saves after a change, and
/// joiners given the records in any order, reach the writer's state.
#[test]
fn a_joiner_after_a_change_reaches_the_same_state() {
    let (g, _, _) = changed("l19", &[&k("E")]);
    let saved: Vec<Record> = g.set.in_dependency_order().into_iter().cloned().collect();
    let lists: Vec<Vec<u8>> = g.set.lists().map(<[u8]>::to_vec).collect();
    let restored = RecordSet::restore(g.set.root().clone(), g.set.recovery().clone(), &saved, &lists);
    assert_eq!(view(&restored.state()), view(&g.set.state()));
    same_in_every_order(&g.set, "joiner");
}

/// The pre-signing query (e), as the owner decided it: it lists every
/// device the writer would re-issue (stays / out / admin kept with a
/// spare / admin rights lost / frozen), and the leave-out list is exactly
/// what write_change leaves out.
mod query {
    use super::*;
    use cbb_core::records::set::Outcome;

    #[test]
    fn the_query_lists_every_device_and_the_leave_out_list_matches() {
        let mut g = group("q1");
        let st = g.set.state();
        let p = g.set.change_preview(&st, &[k("F").hash]);
        let status = |m: &K| p.iter().find(|e| e.device == m.key.device_id()).map(|e| e.outcome);
        assert_eq!(status(&k("D")), Some(Outcome::Stays));
        assert_eq!(status(&k("F")), Some(Outcome::Out));
        assert_eq!(status(&k("PA")), Some(Outcome::AdminRightsLost));
        g.t += 1_000;
        change(&mut g.set, &k("q1 root 2"), &k("P2"), &[k("F").hash], g.t);
        let after = g.set.state();
        for e in &p {
            assert_eq!(after.devices.iter().any(|d| d.id == e.device), e.outcome != Outcome::Out);
        }
    }

    #[test]
    fn the_query_lists_a_device_whose_removal_the_writer_never_got() {
        // The writer holds D's admission but not the old root's removal of
        // D: D is listed as staying.
        let g = group("q2");
        let st = g.set.state();
        let p = g.set.change_preview(&st, &[]);
        assert!(p.iter().any(|e| e.device == k("D").key.device_id() && e.outcome == Outcome::Stays));
    }

    #[test]
    fn the_query_shows_frozen_devices_as_frozen() {
        let mut g = group("q3");
        let st = g.set.state();
        g.t += 1_000;
        let seen = vec![head_of(&g.set, &g.r1.hash).unwrap()];
        g.set.write_record(&st, &g.r1, Kind::Freeze(removal(&[&k("D")], seen)), g.t).unwrap();
        let st = g.set.state();
        let p = g.set.change_preview(&st, &[]);
        assert!(p.iter().any(|e| e.device == k("D").key.device_id() && e.outcome == Outcome::Frozen));
    }

    #[test]
    fn the_writer_s_own_device_cannot_be_left_out() {
        let mut g = group("q4");
        let st = g.set.state();
        let p = Device::new(k("P2").key.clone(), "new phone", ROLE_PHONE);
        let err = g.set.write_change(&st, &k("recovery"), &rk2(), &k("q4 root 2"), p, &[k("P2").hash], false, 1);
        assert!(err.is_err());
    }
}

/// Records from a peer this member does not know (L8, round 2): only
/// recovery records are exchanged until a valid head extends the chain;
/// then only that head's new root's records, within its room; never copies
/// or commands. Through `RecordSet::insert_from_unknown`.
mod unknown_peer {
    use super::*;

    /// What an offer from an unknown peer did: whether the set's root
    /// moved (the change applied), and how many of the offered records
    /// (by ID) the set does not hold after it.
    struct FromUnknown {
        applied: bool,
        refused: usize,
    }

    fn lists_of(set: &RecordSet) -> Vec<Vec<u8>> {
        set.lists().map(<[u8]>::to_vec).collect()
    }

    fn from_unknown(set: &mut RecordSet, records: &[Record], lists: &[Vec<u8>]) -> FromUnknown {
        let before = set.state().roots;
        let lists: Vec<&[u8]> = lists.iter().map(Vec::as_slice).collect();
        let _ = set.insert_from_unknown(records, &lists);
        let ids: std::collections::BTreeSet<_> = records.iter().map(Record::id).collect();
        let refused = ids.iter().filter(|id| !set.contains(id)).count();
        FromUnknown { applied: set.state().roots != before, refused }
    }

    /// L8.1: the replaced root phone alone brings a sleeper to the new root.
    #[test]
    fn the_new_phone_alone_brings_a_sleeper_to_the_new_root() {
        let (g, mut sleeper, _) = changed("u1", &[]);
        let offered: Vec<Record> = g.set.in_dependency_order().into_iter().cloned().collect();
        let taken = from_unknown(&mut sleeper, &offered, &lists_of(&g.set));
        assert!(taken.applied, "head, re-issue and first checkpoint taken from an unknown peer");
        assert_eq!(view(&sleeper.state()), view(&g.set.state()));
    }

    /// L8.2: a valid head with part of the re-issue withheld: pending, the
    /// old state whole, nothing of the new root counting yet.
    #[test]
    fn a_withheld_reissue_leaves_the_change_pending() {
        let (g, mut sleeper, w) = changed("u2", &[]);
        let old = view(&sleeper.state());
        let drop = w.first.iter().find(|r| matches!(r.body().kind, Kind::Device(_))).unwrap().id();
        let offered: Vec<Record> =
            g.set.in_dependency_order().into_iter().filter(|r| r.id() != drop).cloned().collect();
        let _ = from_unknown(&mut sleeper, &offered, &lists_of(&g.set));
        assert_eq!(view(&sleeper.state()), old);
    }

    /// L8.3: junk from an unknown peer (old root's and old admins' records,
    /// unknown signers, heads that do not extend the chain) leaves the set
    /// byte-equal.
    #[test]
    fn junk_from_an_unknown_peer_is_not_kept() {
        let (mut g, sleeper, _) = changed("u3", &[]);
        let before = (sleeper.digest(), sleeper.bytes());
        let mut chain = Chain::new();
        chain.follow(&sleeper, &g.r1);
        chain.follow(&sleeper, &k("A"));
        let mut junk = Vec::new();
        let (a, nobody) = (k("A"), k("nobody"));
        for i in 0..50u32 {
            g.t += 10;
            let by = [&g.r1, &a, &nobody][i as usize % 3];
            junk.push(chain.sign(&sleeper, by, Kind::device(plain(&k(&format!("j{i}")), "j")), g.t));
        }
        let mut s = sleeper.clone();
        let _ = from_unknown(&mut s, &junk, &[]);
        assert_eq!((s.digest(), s.bytes()), before);
    }

    /// L8.4: two unknown peers with different valid heads at one seq: a
    /// recovery fork, the group stopped for good, both heads kept as proof.
    #[test]
    fn two_heads_at_one_seq_from_unknown_peers_stop_the_group() {
        let (g, mut sleeper, _) = changed("u4", &[]);
        let mut other = group("u4");
        change(&mut other.set, &k("u4 root 2b"), &k("P2b"), &[], other.t + 1_000);
        let _ = from_unknown(
            &mut sleeper,
            &g.set.in_dependency_order().into_iter().cloned().collect::<Vec<_>>(),
            &lists_of(&g.set),
        );
        let _ = from_unknown(
            &mut sleeper,
            &other.set.in_dependency_order().into_iter().cloned().collect::<Vec<_>>(),
            &lists_of(&other.set),
        );
        assert!(sleeper.state().fork.is_some());
    }

    /// L8.6: more than 64 heads, or 3 records at one seq, from one unknown
    /// peer: the surplus is refused.
    #[test]
    fn an_unknown_peer_is_held_to_the_recovery_chain_s_bounds() {
        let (g, mut sleeper, w) = changed("u6", &[]);
        // Three heads at one seq: three changes the recovery key signed on
        // copies of the old set.
        let mut offered = vec![w.record.clone()];
        let mut lists = lists_of(&g.set);
        for i in 0..2 {
            let mut other = sleeper.clone();
            let o = change(&mut other, &k(&format!("u6 root 2{i}")), &k(&format!("P2{i}")), &[], g.t + 1 + i as u64);
            offered.push(o.record.clone());
            lists.extend(lists_of(&other));
        }
        offered.extend(g.set.in_dependency_order().into_iter().cloned());
        let taken = from_unknown(&mut sleeper, &offered, &lists);
        assert!(taken.refused > 0);
    }
}

/// L, a change whose re-issue never went out: its writer's device is gone
/// right after the recovery record and its list reached the members (the
/// new root's first records never did). The person, holding the recovery
/// key, writes the next change from a device that holds that head
/// (sign N+1, no spares, never a fork), and every member reaches it.
#[test]
#[ignore = "disagreement with 61b698f8: CHANGE_WAITING refuses it"]
fn a_change_whose_reissue_never_went_out_does_not_stop_the_group() {
    let g = group("l30");
    let mut gone = g.set.clone();
    let w = change(&mut gone, &k("l30 root 2"), &k("l30 P2"), &[], g.t + 1_000);
    let lists: Vec<Vec<u8>> = gone.lists().map(<[u8]>::to_vec).collect();
    let mut member = g.set.clone();
    offer(&mut member, &lists, std::slice::from_ref(&w.record));
    let st = member.state();
    assert_eq!(st.roots.last(), Some(&g.r1.hash), "the head alone does not apply");
    let r3 = k("l30 root 3");
    let p = Device::new(k("l30 P3").key.clone(), "new phone", ROLE_PHONE);
    let next = member.write_change(&st, &k("recovery"), &rk2(), &r3, p, &[], false, g.t + 2_000);
    let next = next.unwrap_or_else(|e| panic!("the person's next change from a member holding the head: {e}"));
    assert_eq!(next.record.body().seq, w.record.body().seq + 1, "N+1, on the head it holds");
    assert_eq!(member.state().roots.last(), Some(&r3.hash));
    assert!(member.state().fork.is_none(), "never a fork");
}

/// The same, today: every member that holds the head refuses a change
/// (CHANGE_WAITING), and a change written on a device that never got the
/// head takes the same seq, a fork that stops the group for good.
#[test]
fn today_a_change_whose_reissue_never_went_out_leaves_only_a_fork() {
    let g = group("l31");
    let mut gone = g.set.clone();
    let w = change(&mut gone, &k("l31 root 2"), &k("l31 P2"), &[], g.t + 1_000);
    let lists: Vec<Vec<u8>> = gone.lists().map(<[u8]>::to_vec).collect();
    let mut member = g.set.clone();
    offer(&mut member, &lists, std::slice::from_ref(&w.record));
    let st = member.state();
    let p = Device::new(k("l31 P3").key.clone(), "new phone", ROLE_PHONE);
    let refused = member.write_change(&st, &k("recovery"), &rk2(), &k("l31 root 3"), p, &[], false, g.t + 2_000);
    println!(
        "from a member holding the head: {:?}",
        refused.as_ref().map(|w| w.record.body().seq).map_err(ToString::to_string)
    );
    assert!(refused.is_err());
    // A device that never got the head: the old set as loaded.
    let mut blind = g.set.clone();
    let w2 = change(&mut blind, &k("l31 root 3b"), &k("l31 P3b"), &[], g.t + 3_000);
    assert_eq!(w2.record.body().seq, w.record.body().seq, "the same seq as the head that went out");
    sync(&blind, &mut member);
    println!(
        "after the blind change reaches the member: fork {:?}, roots {}",
        member.state().fork.is_some(),
        member.state().roots.len()
    );
    assert!(member.state().fork.is_some(), "two heads at one seq: the group stops for good");
    let (st, bt) = (member.state(), blind.state());
    assert!(st.devices.is_empty() && st.devices.iter().all(|d| d.admin.is_none()), "the halted state names no device");
    sync(&member, &mut blind);
    assert!(
        blind.state().fork.is_some() && blind.state().devices.is_empty(),
        "nor at the other side: {:?}",
        bt.devices.len()
    );
}

/// The attack on architecture's 05:33Z rule (the new root may name an old
/// admin key again): the new root names A again on PA, and A tries to make
/// what it signed before the change count. A's old admission of F, a
/// record A pre-signed before the change and offered after, a new record
/// on A's old chain (its prev into the old records, its seen on the new
/// root), and the new root's checkpoint naming A's head after that. None
/// of A's records from before the change counts, and the pre-signed one
/// admits nobody.
#[test]
fn an_old_admin_key_named_again_makes_nothing_it_signed_before_count() {
    let mut g = group("l40");
    let a = k("A");
    // Before the change: A pre-signs an admission it keeps back.
    g.t += 1_000;
    let mut x = plain(&k("l40 X"), "X");
    x.seen = vec![head_of(&g.set, &g.r1.hash).unwrap()];
    let kept_back = g.chain.sign(&g.set, &a, Kind::device(x), g.t);
    let old: Vec<_> = g
        .set
        .in_dependency_order()
        .into_iter()
        .filter(|r| r.body().signer == a.hash)
        .map(|r| r.id())
        .chain([kept_back.id()])
        .collect();
    g.t += 1_000;
    let r2 = k("l40 root 2");
    change(&mut g.set, &r2, &k("l40 P2"), &[], g.t);
    let st = g.set.state();
    g.t += 1_000;
    g.set.write_record(&st, &r2, Kind::device(admin_device(&k("PA"), "PA", &a)), g.t).expect("named again (05:33Z)");
    assert!(is_admin(&g.set.state(), &a));
    // The pre-signed record, offered now.
    let _ = g.set.insert(kept_back.clone());
    // A signs on its old chain, seeing the new root.
    g.t += 1_000;
    let seen = vec![head_of(&g.set, &r2.hash).unwrap()];
    let next = g.chain.sign_raw(&g.set, &a, Kind::Ack { seen, spare: None }, g.t);
    let _ = g.set.insert(next.clone());
    // The new root's checkpoint, then everything offered again.
    let st = g.set.state();
    g.t += 1_000;
    if let Ok(cp) = g.set.write_checkpoint(&st, &r2, g.t) {
        let _ = g.set.insert(cp);
    }
    let _ = g.set.insert(kept_back.clone());
    let st = g.set.state();
    for id in &old {
        assert!(!st.counting.contains(id), "a record A signed before the change counts: {id:?}");
    }
    assert!(!has(&st, &k("l40 X")), "the pre-signed admission admits nobody");
    println!("A's record on its old chain after the re-grant counts: {}", st.counting.contains(&next.id()));
    same_in_every_order(&g.set, "old key named again");
}

/// The same attack from a fresh chain: after the re-grant A starts again
/// at seq 1 (a second history beside its old one), and signs a record
/// whose seen names only the old root. Neither lifts any record A signed
/// before the change.
#[test]
fn an_old_admin_key_named_again_cannot_reach_its_old_records_from_a_new_chain() {
    let mut g = group("l41");
    let a = k("A");
    let old: Vec<_> =
        g.set.in_dependency_order().into_iter().filter(|r| r.body().signer == a.hash).map(|r| r.id()).collect();
    let old_root_head = head_of(&g.set, &g.r1.hash).unwrap();
    g.t += 1_000;
    let r2 = k("l41 root 2");
    change(&mut g.set, &r2, &k("l41 P2"), &[], g.t);
    let st = g.set.state();
    g.t += 1_000;
    g.set.write_record(&st, &r2, Kind::device(admin_device(&k("PA"), "PA", &a)), g.t).expect("named again (05:33Z)");
    let mut fresh = Chain::new();
    g.t += 1_000;
    let seen = vec![head_of(&g.set, &r2.hash).unwrap()];
    let first = fresh.sign_raw(&g.set, &a, Kind::Ack { seen, spare: None }, g.t);
    let _ = g.set.insert(first);
    g.t += 1_000;
    let mut y = plain(&k("l41 Y"), "Y");
    y.seen = vec![old_root_head];
    let on_old_seen = fresh.sign_raw(&g.set, &a, Kind::device(y), g.t);
    let _ = g.set.insert(on_old_seen);
    let st = g.set.state();
    g.t += 1_000;
    if let Ok(cp) = g.set.write_checkpoint(&st, &r2, g.t) {
        let _ = g.set.insert(cp);
    }
    let st = g.set.state();
    for id in &old {
        assert!(!st.counting.contains(id), "a record A signed before the change counts: {id:?}");
    }
    println!("Y admitted on an old-root seen: {}", has(&st, &k("l41 Y")));
}
