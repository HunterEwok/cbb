// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! A second, independent set of cases for the seen line, the last root
//! only with the new root's re-issue, and the spare key, written from the
//! rule texts only, with histories of their own.

mod pieces;

use cbb_core::records::body::{POWER_REMOVE_ADMINS, Seen};
use cbb_core::records::set::Added;
use cbb_core::records::{Kind, Record, RecordId, RecordSet};
use pieces::*;

/// A root alone with `n` plain devices named "<tag> n<i>", and its clock.
fn base(tag: &str, n: usize) -> (RecordSet, K, u64) {
    let r = k(&format!("{tag} R"));
    let mut set = RecordSet::new(r.key.clone(), recovery());
    let mut t = 5_000u64;
    t += 500;
    let st = set.state();
    set.write_record(&st, &r, Kind::Copies { incoming_ms: 30_000, seen: vec![] }, t).unwrap();
    for i in 0..n {
        t += 500;
        let st = set.state();
        let m = k(&format!("{tag} n{i}"));
        set.write_record(&st, &r, Kind::device(plain(&m, &format!("n{i}"))), t).unwrap();
    }
    (set, r, t)
}

/// Names admin key `a` on device `p` (it may freeze others, not remove admins).
fn grant(set: &mut RecordSet, r: &K, p: &K, a: &K, t: u64) -> Seen {
    let st = set.state();
    let mut d = admin_device(p, "admin", a);
    d.powers &= !POWER_REMOVE_ADMINS;
    set.write_record(&st, r, Kind::device(d), t).unwrap();
    head_of(set, &r.hash).unwrap()
}

fn root_head(set: &RecordSet, r: &K) -> Seen {
    head_of(set, &r.hash).unwrap()
}

fn records(set: &RecordSet) -> Vec<Record> {
    set.in_dependency_order().into_iter().cloned().collect()
}

fn lists(set: &RecordSet) -> Vec<Vec<u8>> {
    set.lists().map(<[u8]>::to_vec).collect()
}

/// A member given src's records newest first.
fn backwards(src: &RecordSet) -> RecordSet {
    let mut m = RecordSet::new(src.root().clone(), src.recovery().clone());
    let mut rs = records(src);
    rs.reverse();
    for _ in 0..rs.len().min(40) {
        offer(&mut m, &lists(src), &rs);
    }
    m
}

fn counts(set: &RecordSet, id: &RecordId) -> bool {
    set.state().counting.contains(id)
}

fn change_by(set: &mut RecordSet, root: &str, phone: &str, out: &[&K], t: u64) -> cbb_core::records::set::Written {
    let out: Vec<_> = out.iter().map(|x| x.hash).collect();
    change(set, &k(root), &k(phone), &out, t)
}

// ---------------------------------------------------------------------
// The seen line.

/// A seen entry that pairs a real root record's ID with a seq that is not
/// its own (a higher one, at or above the grant) does not lift a record
/// signed before the grant.
#[test]
fn h_seen_mismatched_seq_and_id_stays_void() {
    let (mut set, r, mut t) = base("hs1", 3);
    let a = k("hs1 A");
    let real = seen_at(&set, &r.hash, 2);
    let forged = Seen { key: r.hash, seq: 9, id: real.id };
    let mut c = Chain::new();
    t += 500;
    let pre = c.sign_raw(&set, &a, Kind::Revoke(removal(&[&k("hs1 n0")], vec![forged])), t);
    for _ in 0..5 {
        t += 500;
        let st = set.state();
        set.write_record(&st, &r, Kind::device(plain(&k(&format!("hs1 x{t}")), "x")), t).unwrap();
    }
    t += 500;
    grant(&mut set, &r, &k("hs1 PA"), &a, t);
    let _ = set.insert(pre.clone());
    assert!(!counts(&set, &pre.id()));
    assert!(has(&set.state(), &k("hs1 n0")));
}

/// A seen that holds another admin's head, high as it is, but not the
/// root, does not lift a record signed before the grant.
#[test]
fn h_seen_on_another_admin_only_stays_void() {
    let (mut set, r, mut t) = base("hs2", 2);
    let (b, a) = (k("hs2 B"), k("hs2 A"));
    t += 500;
    grant(&mut set, &r, &k("hs2 PB"), &b, t);
    let mut c = Chain::new();
    for _ in 0..3 {
        t += 500;
        let x = c.sign(&set, &b, Kind::Ack { seen: vec![root_head(&set, &r)], spare: None }, t);
        set.insert(x).unwrap();
    }
    let b_head = head_of(&set, &b.hash).unwrap();
    t += 500;
    let pre = c.sign_raw(&set, &a, Kind::Revoke(removal(&[&k("hs2 n1")], vec![b_head])), t);
    t += 500;
    grant(&mut set, &r, &k("hs2 PA"), &a, t);
    let _ = set.insert(pre.clone());
    assert!(!counts(&set, &pre.id()));
    assert!(has(&set.state(), &k("hs2 n1")));
}

/// Three pre-signed records, then an honest record above the grant, given
/// to a member newest first: the three stay void there too and the honest
/// one counts; the member agrees with the root.
#[test]
fn h_three_void_then_honest_in_reverse_arrival() {
    let (mut set, r, mut t) = base("hs3", 4);
    let a = k("hs3 A");
    let below = root_head(&set, &r);
    let mut c = Chain::new();
    let mut pre = Vec::new();
    for i in 0..3 {
        t += 500;
        let x = c.sign_raw(&set, &a, Kind::Revoke(removal(&[&k(&format!("hs3 n{i}"))], vec![below])), t);
        pre.push(x);
    }
    t += 500;
    grant(&mut set, &r, &k("hs3 PA"), &a, t);
    for x in &pre {
        let _ = set.insert(x.clone());
    }
    t += 500;
    let ok = c.sign_raw(&set, &a, Kind::Revoke(removal(&[&k("hs3 n3")], vec![root_head(&set, &r)])), t);
    set.insert(ok.clone()).unwrap();
    let m = backwards(&set);
    for s in [&set, &m] {
        let st = s.state();
        for i in 0..3 {
            assert!(has(&st, &k(&format!("hs3 n{i}"))), "n{i}");
        }
        assert!(!has(&st, &k("hs3 n3")));
    }
    assert_eq!(view(&m.state()), view(&set.state()));
}

/// A device admitted plain, made an admin later: a record whose seen holds
/// the device's plain admission (below the grant) is void; one whose seen
/// holds the grant counts.
#[test]
fn h_admin_named_later_line_is_the_grant_not_the_admission() {
    let (mut set, r, mut t) = base("hs4", 2);
    let (p, a) = (k("hs4 P"), k("hs4 A"));
    t += 500;
    let st = set.state();
    set.write_record(&st, &r, Kind::device(plain(&p, "P")), t).unwrap();
    let admission = root_head(&set, &r);
    t += 500;
    let g = grant(&mut set, &r, &p, &a, t);
    let mut c = Chain::new();
    t += 500;
    let low = c.sign_raw(&set, &a, Kind::Revoke(removal(&[&k("hs4 n0")], vec![admission])), t);
    set.insert(low.clone()).unwrap();
    assert!(!counts(&set, &low.id()), "seen on the plain admission is below the line");
    t += 500;
    let high = c.sign_raw(&set, &a, Kind::Revoke(removal(&[&k("hs4 n1")], vec![g])), t);
    set.insert(high.clone()).unwrap();
    let st = set.state();
    assert!(counts(&set, &high.id()));
    assert!(has(&st, &k("hs4 n0")) && !has(&st, &k("hs4 n1")));
}

/// The line is at the grant itself: a seen holding exactly the grant's
/// seq counts.
#[test]
fn h_seen_exactly_at_the_grant_counts() {
    let (mut set, r, mut t) = base("hs5", 1);
    let a = k("hs5 A");
    t += 500;
    let g = grant(&mut set, &r, &k("hs5 PA"), &a, t);
    for i in 0..2 {
        t += 500;
        let st = set.state();
        set.write_record(&st, &r, Kind::device(plain(&k(&format!("hs5 y{i}")), "y")), t).unwrap();
    }
    let mut c = Chain::new();
    t += 500;
    let x = c.sign_raw(&set, &a, Kind::Revoke(removal(&[&k("hs5 y1")], vec![g])), t);
    set.insert(x.clone()).unwrap();
    assert!(counts(&set, &x.id()));
    assert!(!has(&set.state(), &k("hs5 y1")));
}

/// A void record, then another record whose own seen is also below the
/// grant, then one with a good seen: only the last and what is above it
/// count.
#[test]
fn h_only_records_from_the_first_good_seen_up_count() {
    let (mut set, r, mut t) = base("hs6", 4);
    let a = k("hs6 A");
    let low = seen_at(&set, &r.hash, 1);
    let mut c = Chain::new();
    t += 500;
    let v1 = c.sign_raw(&set, &a, Kind::Revoke(removal(&[&k("hs6 n0")], vec![low])), t);
    t += 500;
    let g = grant(&mut set, &r, &k("hs6 PA"), &a, t);
    set.insert(v1.clone()).unwrap();
    t += 500;
    let v2 = c.sign_raw(&set, &a, Kind::Revoke(removal(&[&k("hs6 n1")], vec![low])), t);
    set.insert(v2.clone()).unwrap();
    t += 500;
    let good = c.sign_raw(&set, &a, Kind::Revoke(removal(&[&k("hs6 n2")], vec![g])), t);
    set.insert(good.clone()).unwrap();
    t += 500;
    let above = c.sign_raw(&set, &a, Kind::Revoke(removal(&[&k("hs6 n3")], vec![])), t);
    set.insert(above.clone()).unwrap();
    let st = set.state();
    assert!(has(&st, &k("hs6 n0")) && has(&st, &k("hs6 n1")));
    assert!(!has(&st, &k("hs6 n2")) && !has(&st, &k("hs6 n3")));
}

/// A device whose admin key was taken back gets a new key; a record the
/// new key signed before its own grant is void, one after counts, and the
/// old key's later records count for nothing.
#[test]
fn h_new_key_after_a_take_back_starts_its_own_line() {
    let (mut set, r, mut t) = base("hs7", 3);
    let (p, a1, a2) = (k("hs7 P"), k("hs7 A1"), k("hs7 A2"));
    t += 500;
    grant(&mut set, &r, &p, &a1, t);
    let st = set.state();
    t += 500;
    set.take_back(&st, &r, &a1.hash, t).unwrap();
    let mut c = Chain::new();
    t += 500;
    let pre = c.sign_raw(&set, &a2, Kind::Revoke(removal(&[&k("hs7 n0")], vec![root_head(&set, &r)])), t);
    t += 500;
    let g = grant(&mut set, &r, &p, &a2, t);
    let _ = set.insert(pre.clone());
    t += 500;
    let old = c.sign_raw(&set, &a1, Kind::Revoke(removal(&[&k("hs7 n1")], vec![g])), t);
    let _ = set.insert(old);
    t += 500;
    let post = c.sign_raw(&set, &a2, Kind::Revoke(removal(&[&k("hs7 n2")], vec![g])), t);
    set.insert(post).unwrap();
    let st = set.state();
    assert!(has(&st, &k("hs7 n0")), "the new key's pre-grant record is void");
    assert!(has(&st, &k("hs7 n1")), "the old key counts for nothing");
    assert!(!has(&st, &k("hs7 n2")), "the new key above its grant counts");
}

/// GRANT_ABOVE: two root removals before A's grant and one after, B
/// acknowledging everything: only the one after waits, and only for A.
#[test]
fn h_grant_above_only_later_removals_wait() {
    let (mut set, r, mut t) = base("hs8", 4);
    let (b, a) = (k("hs8 B"), k("hs8 A"));
    t += 500;
    grant(&mut set, &r, &k("hs8 PB"), &b, t);
    let mut ids = Vec::new();
    for (i, name) in ["hs8 n0", "hs8 n1"].iter().enumerate() {
        t += 500 + i as u64;
        let st = set.state();
        let rs = set.write_removal(&st, &r, &[k(name).hash], t).unwrap();
        ids.push(rs.last().unwrap().id());
        for x in rs {
            set.insert(x).unwrap();
        }
    }
    t += 500;
    grant(&mut set, &r, &k("hs8 PA"), &a, t);
    t += 500;
    let st = set.state();
    let rs = set.write_removal(&st, &r, &[k("hs8 n2").hash], t).unwrap();
    let late = rs.last().unwrap().id();
    for x in rs {
        set.insert(x).unwrap();
    }
    let mut c = Chain::new();
    t += 500;
    let ack = c.sign(&set, &b, Kind::Ack { seen: vec![root_head(&set, &r)], spare: None }, t);
    set.insert(ack).unwrap();
    let st = set.state();
    let waiting = set.removals_waiting(&st);
    assert!(ids.iter().all(|id| waiting.iter().all(|w| w.removal != *id)), "before the grant: wait for nobody");
    let w = waiting.iter().find(|w| w.removal == late).expect("the later removal waits");
    assert_eq!(w.waits_for, vec![a.hash]);
}

// ---------------------------------------------------------------------
// The last root only, with the re-issue.

/// Two admins: A (no spare) admitted X1 and X2, B (with spare SB)
/// admitted Y. The person leaves X2 out. After the change: X1 and Y are
/// the new root's own, PB holds SB, PA is plain, X2 is gone; three
/// members given the records in different orders agree.
#[test]
fn h_two_admins_mixed_spares_and_a_left_out_device() {
    let (mut set, r, mut t) = base("hl1", 2);
    let (a, b) = (k("hl1 A"), k("hl1 B"));
    t += 500;
    grant(&mut set, &r, &k("hl1 PA"), &a, t);
    t += 500;
    grant(&mut set, &r, &k("hl1 PB"), &b, t);
    let mut c = Chain::new();
    for (by, m) in [(&a, "hl1 X1"), (&a, "hl1 X2"), (&b, "hl1 Y")] {
        t += 500;
        let x = c.sign(&set, by, Kind::device(plain(&k(m), m)), t);
        set.insert(x).unwrap();
    }
    t += 500;
    let ack = c.sign(&set, &b, Kind::Ack { seen: vec![root_head(&set, &r)], spare: Some(k("hl1 SB").key.clone()) }, t);
    set.insert(ack).unwrap();
    t += 500;
    change_by(&mut set, "hl1 R2", "hl1 P2", &[&k("hl1 X2")], t);
    let st = set.state();
    assert!(has(&st, &k("hl1 X1")) && has(&st, &k("hl1 Y")) && !has(&st, &k("hl1 X2")));
    assert!(st.device_by_key(&k("hl1 X1").hash).unwrap().by_root);
    assert_eq!(admin_of(&st, &k("hl1 PB")), Some(k("hl1 SB").hash));
    assert_eq!(admin_of(&st, &k("hl1 PA")), None);
    assert!(!is_admin(&st, &a) && !is_admin(&st, &b));
    let m = backwards(&set);
    assert_eq!(view(&m.state()), view(&st));
    same_in_every_order(&set, "mixed admins");
}

/// A device only another member counted (an admission by A the writer
/// never received) is not re-issued and stops counting at that member
/// once the change applies there: the writer's view is the truth.
#[test]
fn h_a_device_only_a_member_counted_is_dropped() {
    let (mut set, r, mut t) = base("hl2", 1);
    let a = k("hl2 A");
    t += 500;
    grant(&mut set, &r, &k("hl2 PA"), &a, t);
    let mut member = set.clone();
    let mut c = Chain::new();
    t += 500;
    let z = c.sign(&member, &a, Kind::device(plain(&k("hl2 Z"), "Z")), t);
    member.insert(z).unwrap();
    assert!(has(&member.state(), &k("hl2 Z")));
    t += 500;
    change_by(&mut set, "hl2 R2", "hl2 P2", &[], t);
    sync(&set, &mut member);
    assert!(!has(&member.state(), &k("hl2 Z")));
    assert_eq!(member.state().roots.last(), Some(&k("hl2 R2").hash));
}

/// A left-out device is barred by no removal: the new root may admit it
/// again, and then it counts everywhere.
#[test]
fn h_a_left_out_device_can_be_admitted_again() {
    let (mut set, _, mut t) = base("hl3", 3);
    let mut member = set.clone();
    t += 500;
    change_by(&mut set, "hl3 R2", "hl3 P2", &[&k("hl3 n1")], t);
    assert!(!has(&set.state(), &k("hl3 n1")));
    let st = set.state();
    t += 500;
    set.write_record(&st, &k("hl3 R2"), Kind::device(plain(&k("hl3 n1"), "back")), t).unwrap();
    sync(&set, &mut member);
    for s in [&set, &member] {
        assert!(has(&s.state(), &k("hl3 n1")));
    }
}

/// Two changes: root 3 leaves out a device root 2 re-issued; a member that
/// slept through both converges and does not count it.
#[test]
fn h_second_change_leaves_out_what_the_first_carried() {
    let (mut set, _, mut t) = base("hl4", 4);
    let mut sleeper = set.clone();
    t += 500;
    change_by(&mut set, "hl4 R2", "hl4 P2", &[&k("hl4 n0")], t);
    t += 500;
    change_by(&mut set, "hl4 R3", "hl4 P3", &[&k("hl4 n2")], t);
    sync(&set, &mut sleeper);
    let st = sleeper.state();
    assert_eq!(st.roots.last(), Some(&k("hl4 R3").hash));
    assert!(!has(&st, &k("hl4 n0")) && !has(&st, &k("hl4 n2")));
    assert!(has(&st, &k("hl4 n1")) && has(&st, &k("hl4 n3")) && has(&st, &k("hl4 P2")));
    assert_eq!(view(&st), view(&set.state()));
}

/// A freeze made under root 1 is carried by root 2 and again by root 3.
#[test]
fn h_a_freeze_survives_two_changes() {
    let (mut set, r, mut t) = base("hl5", 1);
    let (p, a) = (k("hl5 P"), k("hl5 A"));
    t += 500;
    grant(&mut set, &r, &p, &a, t);
    let st = set.state();
    t += 500;
    set.write_record(&st, &r, Kind::Freeze(removal(&[&a], vec![root_head(&set, &r)])), t).unwrap();
    assert!(frozen(&set.state(), &p));
    t += 500;
    change_by(&mut set, "hl5 R2", "hl5 P2", &[], t);
    assert!(frozen(&set.state(), &p), "after root 2");
    t += 500;
    change_by(&mut set, "hl5 R3", "hl5 P3", &[], t);
    assert!(frozen(&set.state(), &p), "after root 3");
    let m = backwards(&set);
    assert!(frozen(&m.state(), &p));
}

/// The old root's settings record dated after the change changes nothing.
#[test]
fn h_old_root_settings_after_the_change_change_nothing() {
    let (mut set, r, mut t) = base("hl6", 2);
    let before = set.clone();
    t += 500;
    change_by(&mut set, "hl6 R2", "hl6 P2", &[], t);
    let want = set.state().settings.clone();
    let mut c = Chain::new();
    c.follow(&before, &r);
    t += 500;
    let s = cbb_core::records::body::Settings { shared: true, key_level: 1, ..Default::default() };
    let late = c.sign_raw(&before, &r, Kind::settings(s), t);
    let _ = set.insert(late);
    assert_eq!(set.state().settings, want);
}

/// A member pending on the change receives a later admission by root 2:
/// it does not count there until the change applies, then it does.
#[test]
fn h_new_root_records_wait_for_the_change_at_a_pending_member() {
    let (mut set, _, mut t) = base("hl7", 3);
    let mut member = set.clone();
    t += 500;
    let w = change_by(&mut set, "hl7 R2", "hl7 P2", &[], t);
    let st = set.state();
    t += 500;
    set.write_record(&st, &k("hl7 R2"), Kind::device(plain(&k("hl7 H"), "H")), t).unwrap();
    let held_back =
        w.first.iter().find(|x| matches!(&x.body().kind, Kind::Device(d) if d.key.hash() == k("hl7 n2").hash));
    let held_back = held_back.expect("n2's re-issue").id();
    let some: Vec<Record> = records(&set).into_iter().filter(|x| x.id() != held_back).collect();
    offer(&mut member, &lists(&set), &some);
    assert!(!has(&member.state(), &k("hl7 H")), "not before the change applies");
    sync(&set, &mut member);
    assert!(has(&member.state(), &k("hl7 H")));
}

/// The writer's own phone and the new root cannot be left out.
#[test]
fn h_the_writer_s_own_device_is_never_left_out() {
    let (mut set, _, t) = base("hl8", 1);
    let st = set.state();
    for out in ["hl8 P2", "hl8 R2"] {
        let p = cbb_core::records::body::Device::new(k("hl8 P2").key.clone(), "p", cbb_core::records::body::ROLE_PHONE);
        let res = set.write_change(&st, &k("recovery"), &rk2(), &k("hl8 R2"), p, &[k(out).hash], false, t + 1);
        assert!(res.is_err(), "{out} left out");
    }
}

/// From an unknown peer, a head not signed by the group's recovery key is
/// not kept.
#[test]
fn h_unknown_peer_forged_head_is_not_kept() {
    let (mut set, _, t) = base("hl9", 1);
    let mut other = RecordSet::new(k("hl9 other R").key.clone(), recovery());
    let _ = t;
    let before = (set.digest(), set.bytes());
    let lists: Vec<Vec<u8>> = other.lists().map(<[u8]>::to_vec).collect();
    let lists: Vec<&[u8]> = lists.iter().map(Vec::as_slice).collect();
    let _ = set.insert_from_unknown(&records(&other), &lists);
    assert_eq!((set.digest(), set.bytes()), before);
    let _ = &mut other;
}

// ---------------------------------------------------------------------
// The spare key.

/// A (spare SA), B (no spare), C (spare SC) whose device is left out:
/// only PA holds a spare after the change; PB is plain; PC is gone.
#[test]
fn h_spares_mixed_with_a_left_out_admin() {
    let (mut set, r, mut t) = base("hk1", 1);
    let (a, b, c) = (k("hk1 A"), k("hk1 B"), k("hk1 C"));
    for (p, x) in [("hk1 PA", &a), ("hk1 PB", &b), ("hk1 PC", &c)] {
        t += 500;
        grant(&mut set, &r, &k(p), x, t);
    }
    let mut ch = Chain::new();
    for (x, s) in [(&a, Some("hk1 SA")), (&b, None), (&c, Some("hk1 SC"))] {
        t += 500;
        let spare = s.map(|s| k(s).key.clone());
        let ack = ch.sign(&set, x, Kind::Ack { seen: vec![root_head(&set, &r)], spare }, t);
        set.insert(ack).unwrap();
    }
    t += 500;
    change_by(&mut set, "hk1 R2", "hk1 P2", &[&k("hk1 PC")], t);
    let st = set.state();
    assert_eq!(admin_of(&st, &k("hk1 PA")), Some(k("hk1 SA").hash));
    assert_eq!(admin_of(&st, &k("hk1 PB")), None);
    assert!(!has(&st, &k("hk1 PC")) && !is_admin(&st, &k("hk1 SC")));
}

/// A spare published in an acknowledgement that does not count (signed
/// after its key's device was removed) is not named.
#[test]
fn h_a_spare_in_a_void_ack_is_not_named() {
    let (mut set, r, mut t) = base("hk2", 1);
    let (p, a) = (k("hk2 PA"), k("hk2 A"));
    t += 500;
    grant(&mut set, &r, &p, &a, t);
    let mut ch = Chain::new();
    t += 500;
    let first = ch.sign(&set, &a, Kind::Ack { seen: vec![root_head(&set, &r)], spare: None }, t);
    set.insert(first).unwrap();
    let st = set.state();
    t += 500;
    for x in set.write_removal(&st, &r, &[p.hash], t).unwrap() {
        set.insert(x).unwrap();
    }
    t += 500;
    let late =
        ch.sign(&set, &a, Kind::Ack { seen: vec![root_head(&set, &r)], spare: Some(k("hk2 SA").key.clone()) }, t);
    let _ = set.insert(late);
    t += 500;
    change_by(&mut set, "hk2 R2", "hk2 P2", &[], t);
    let st = set.state();
    assert!(!is_admin(&st, &k("hk2 SA")) && !has(&st, &p));
}

/// After the change, the spare's first record with a seen below the
/// record that named it (root 2's first record, its own device) is void;
/// one whose seen holds root 2's head counts.
#[test]
fn h_a_spare_counts_from_the_record_that_named_it() {
    let (mut set, r, mut t) = base("hk3", 3);
    let a = k("hk3 A");
    t += 500;
    grant(&mut set, &r, &k("hk3 PA"), &a, t);
    let mut ch = Chain::new();
    t += 500;
    let ack = ch.sign(&set, &a, Kind::Ack { seen: vec![root_head(&set, &r)], spare: Some(k("hk3 SA").key.clone()) }, t);
    set.insert(ack).unwrap();
    t += 500;
    change_by(&mut set, "hk3 R2", "hk3 P2", &[], t);
    let r2 = k("hk3 R2");
    let first = seen_at(&set, &r2.hash, 1);
    let sa = k("hk3 SA");
    t += 500;
    let low = ch.sign_raw(&set, &sa, Kind::Revoke(removal(&[&k("hk3 n0")], vec![first])), t);
    set.insert(low.clone()).unwrap();
    assert!(!counts(&set, &low.id()), "below the naming record");
    t += 500;
    let high = ch.sign_raw(&set, &sa, Kind::Revoke(removal(&[&k("hk3 n1")], vec![root_head(&set, &r2)])), t);
    set.insert(high.clone()).unwrap();
    assert!(counts(&set, &high.id()));
    assert!(has(&set.state(), &k("hk3 n0")) && !has(&set.state(), &k("hk3 n1")));
}

/// Two admins whose newest spares are the same key (B's spare is A's): it
/// is named for at most one, and the change goes through.
#[test]
fn h_one_spare_two_admins_at_most_one_named() {
    let (mut set, r, mut t) = base("hk4", 1);
    let (a, b) = (k("hk4 A"), k("hk4 B"));
    for (p, x) in [("hk4 PA", &a), ("hk4 PB", &b)] {
        t += 500;
        grant(&mut set, &r, &k(p), x, t);
    }
    let s = k("hk4 S");
    let mut ch = Chain::new();
    for x in [&b, &a] {
        t += 500;
        let ack = ch.sign(&set, x, Kind::Ack { seen: vec![root_head(&set, &r)], spare: Some(s.key.clone()) }, t);
        let _ = set.insert(ack);
    }
    t += 500;
    change_by(&mut set, "hk4 R2", "hk4 P2", &[], t);
    let st = set.state();
    assert!(st.devices.iter().filter(|d| d.admin == Some(s.hash)).count() <= 1);
    assert!(has(&st, &k("hk4 PA")) && has(&st, &k("hk4 PB")));
}

/// An admin taken back before the change: its published spare is not
/// named.
#[test]
fn h_a_taken_back_admin_s_spare_is_not_named() {
    let (mut set, r, mut t) = base("hk5", 1);
    let (p, a) = (k("hk5 PA"), k("hk5 A"));
    t += 500;
    grant(&mut set, &r, &p, &a, t);
    let mut ch = Chain::new();
    t += 500;
    let ack = ch.sign(&set, &a, Kind::Ack { seen: vec![root_head(&set, &r)], spare: Some(k("hk5 SA").key.clone()) }, t);
    set.insert(ack).unwrap();
    let st = set.state();
    t += 500;
    set.take_back(&st, &r, &a.hash, t).unwrap();
    t += 500;
    change_by(&mut set, "hk5 R2", "hk5 P2", &[], t);
    let st = set.state();
    assert!(has(&st, &p));
    assert_eq!(admin_of(&st, &p), None);
}

/// An admin awake between two changes: after root 2 names SA, SA
/// acknowledges with a new spare SA2; root 3 names SA2.
#[test]
fn h_an_awake_admin_survives_a_second_change() {
    let (mut set, r, mut t) = base("hk6", 1);
    let (p, a) = (k("hk6 PA"), k("hk6 A"));
    t += 500;
    grant(&mut set, &r, &p, &a, t);
    let mut ch = Chain::new();
    t += 500;
    let ack = ch.sign(&set, &a, Kind::Ack { seen: vec![root_head(&set, &r)], spare: Some(k("hk6 SA").key.clone()) }, t);
    set.insert(ack).unwrap();
    t += 500;
    change_by(&mut set, "hk6 R2", "hk6 P2", &[], t);
    let r2 = k("hk6 R2");
    t += 500;
    let ack2 = ch.sign(
        &set,
        &k("hk6 SA"),
        Kind::Ack { seen: vec![root_head(&set, &r2)], spare: Some(k("hk6 SA2").key.clone()) },
        t,
    );
    set.insert(ack2).unwrap();
    t += 500;
    change_by(&mut set, "hk6 R3", "hk6 P3", &[], t);
    assert_eq!(admin_of(&set.state(), &p), Some(k("hk6 SA2").hash));
}

/// The newest counting acknowledgement carries no spare (an older one
/// did): no spare is named.
#[test]
fn h_a_newer_ack_without_a_spare_withdraws_it() {
    let (mut set, r, mut t) = base("hk7", 1);
    let (p, a) = (k("hk7 PA"), k("hk7 A"));
    t += 500;
    grant(&mut set, &r, &p, &a, t);
    let mut ch = Chain::new();
    for spare in [Some(k("hk7 SA").key.clone()), None] {
        t += 500;
        let ack = ch.sign(&set, &a, Kind::Ack { seen: vec![root_head(&set, &r)], spare }, t);
        set.insert(ack).unwrap();
    }
    t += 500;
    change_by(&mut set, "hk7 R2", "hk7 P2", &[], t);
    let st = set.state();
    assert_eq!(admin_of(&st, &p), None);
    assert!(!is_admin(&st, &k("hk7 SA")));
}

/// A frozen admin with a spare, left out by the person: left out wins.
#[test]
fn h_left_out_wins_over_spare_and_freeze() {
    let (mut set, r, mut t) = base("hk8", 1);
    let (p, a) = (k("hk8 PA"), k("hk8 A"));
    t += 500;
    grant(&mut set, &r, &p, &a, t);
    let mut ch = Chain::new();
    t += 500;
    let ack = ch.sign(&set, &a, Kind::Ack { seen: vec![root_head(&set, &r)], spare: Some(k("hk8 SA").key.clone()) }, t);
    set.insert(ack).unwrap();
    let st = set.state();
    t += 500;
    set.write_record(&st, &r, Kind::Freeze(removal(&[&a], vec![root_head(&set, &r)])), t).unwrap();
    t += 500;
    change_by(&mut set, "hk8 R2", "hk8 P2", &[&p], t);
    let st = set.state();
    assert!(!has(&st, &p) && !is_admin(&st, &k("hk8 SA")));
}

#[allow(dead_code, reason = "kept for the unknown peer's cases")]
fn _added(_: Added) {}
