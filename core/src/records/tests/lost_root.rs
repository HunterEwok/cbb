// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The change of root by the recovery key is the way out for a lost
//! root, which cannot checkpoint first: under table A it is never refused
//! for room when the outgoing root's room is full and it wrote no
//! checkpoint, for one change and for changes in a row where each new root
//! wrote nothing but its first records before it was lost too.

use super::*;
use crate::records::set::Written;

fn phone(member: &K) -> Device {
    let mut d = Device::new(member.key.clone(), "new phone", ROLE_PHONE);
    d.rights = RIGHT_READ | RIGHT_SEND | RIGHT_SECRETS;
    d.holds_root = true;
    d
}

/// Signs kind by `by` and keeps it only if a set of g's records takes it.
fn try_rec(g: &mut G, set: &mut RecordSet, by: &K, kind: Kind) -> bool {
    let r = crate::testkit::sign_by(g.body(by, kind), by);
    let before = set.len();
    match set.insert(r.clone()) {
        Ok(Added::Stored) if set.contains(&r.id()) && set.len() == before + 1 => {
            g.push(r);
            true
        }
        _ => false,
    }
}

/// The recovery key's change from everything g holds, the set taking it.
/// Its list names no removal one of its re-issued removals covers.
fn change(g: &mut G, new_root: &K, member: &K) -> crate::error::Result<Written> {
    let mut set = set_with(&g.root.key, &g.recs, &g.lists);
    let st = set.state();
    let w = set.write_change(&st, &k("recovery"), crate::testkit::rk2(), new_root, phone(member), &[], false, 0)?;
    let zs: Vec<&Removal> = w
        .first
        .iter()
        .filter_map(|r| match &r.body().kind {
            Kind::Revoke(rm) => Some(rm),
            _ => None,
        })
        .collect();
    for id in &w.list.0 {
        let Some(Kind::Revoke(x)) = g.recs.iter().find(|r| r.id() == *id).map(|r| &r.body().kind) else { continue };
        let concerns: alloc::collections::BTreeSet<KeyHash> =
            x.keys.iter().copied().chain(x.seen.iter().map(|s| s.key)).collect();
        let seen_of = |rm: &Removal| -> alloc::collections::BTreeSet<Seen> {
            rm.seen.iter().filter(|s| concerns.contains(&s.key)).copied().collect()
        };
        let covered = zs.iter().any(|z| x.keys.iter().all(|k| z.keys.contains(k)) && seen_of(z) == seen_of(x));
        assert!(!covered, "the list names a removal a re-issued one covers");
    }
    for r in &w.first {
        g.push(r.clone());
    }
    g.push(w.record.clone());
    g.lists.push(w.list.encode());
    Ok(w)
}

/// Fills root's room: `devices` device records, then removals of one key
/// each (keys nobody holds) until the room takes no more.
fn fill(g: &mut G, root: &K, devices: usize, tag: &str) -> (usize, usize) {
    let mut set = set_with(&g.root.key, &g.recs, &g.lists);
    let mut d = 0;
    while d < devices
        && try_rec(g, &mut set, root, Kind::device(Device::new(k(&format!("{tag} d{d}")).key, "d", ROLE_MEMBER)))
    {
        d += 1;
    }
    let mut r = 0;
    while r < 4 * MAX_ROOT_RECORDS {
        let gone = k(&format!("{tag} gone {r}")).hash;
        if !try_rec(g, &mut set, root, Kind::Revoke(Removal { keys: vec![gone], seen: Vec::new() })) {
            break;
        }
        r += 1;
    }
    (d, r)
}

fn live(g: &G, member: &K) -> bool {
    g.state().device_by_key(&member.hash).is_some()
}

/// One change: the first root's room is full of device records and
/// removals, it wrote no checkpoint, and the recovery key's holder changes
/// the root. Then a second and a third change, each new root lost after
/// its first records. None is refused, and every device that counted
/// before still counts after.
#[test]
fn a_lost_roots_full_room_never_refuses_the_recovery_key() {
    if !full_size("a_lost_roots_full_room_never_refuses_the_recovery_key") {
        return;
    }
    for devices in [MAX_DEVICES - 4] {
        let mut g = G::new();
        let root = k("root");
        let (d, r) = fill(&mut g, &root, devices, "r0");
        assert_eq!(d, devices);
        assert!(r > 0);
        let before: Vec<K> = (0..d).map(|i| k(&format!("r0 d{i}"))).collect();
        for n in 1..=3 {
            let w = change(&mut g, &k(&format!("n{n}")), &k(&format!("p{n}")));
            let w = w.unwrap_or_else(|e| panic!("change {n} with {devices} devices and {r} removals: {e}"));
            assert!(w.list.0.len() <= LIST_MAX);
            for m in &before {
                assert!(live(&g, m), "change {n} dropped a device");
            }
            for p in 1..=n {
                assert!(live(&g, &k(&format!("p{p}"))), "change {n} dropped phone {p}");
            }
        }
    }
}

/// The case a later root adds to: the first root's room full of removals
/// and lost; the change to n1, which fills its own room with removals of
/// other keys and is lost; the change to n2.
#[test]
fn two_cut_roots_full_of_removals_and_the_recovery_key() {
    let mut g = G::new();
    let root = k("root");
    let (_, r0) = fill(&mut g, &root, 0, "r0");
    change(&mut g, &k("n1"), &k("p1")).unwrap();
    let (_, r1) = fill(&mut g, &k("n1"), 0, "r1");
    assert!(r0 > 0 && r1 > 0);
    change(&mut g, &k("n2"), &k("p2")).unwrap();
}

/// Builds the first root's room full of what a change must carry: its
/// 16 admins' device records and removals of devices the admins admitted,
/// one key each. The admins admit `per` devices each. It returns the keys
/// admitted, the removed first, and how many were removed.
fn carried_room(g: &mut G, per: usize) -> (Vec<KeyHash>, usize) {
    let mut admitted = Vec::new();
    for a in 0..ADMIN_KEYS_MAX {
        let admin = k(&format!("admin {a}"));
        g.admin(&k(&format!("admin phone {a}")), &admin, POWER_ADMIT);
        for i in 0..per {
            let m = k(&format!("a{a} d{i}"));
            g.device(&admin, &m, "d", |_| {});
            admitted.push(m.hash);
        }
    }
    let mut set = set_with(&g.root.key, &g.recs, &g.lists);
    let root = k("root");
    let mut n = 0;
    while n < admitted.len()
        && try_rec(g, &mut set, &root, Kind::Revoke(Removal { keys: vec![admitted[n]], seen: Vec::new() }))
    {
        n += 1;
    }
    (admitted, n)
}

/// No removed key counts, every admin does.
fn removed_stay_out(g: &G, removed: &[KeyHash], what: &str) {
    let s = g.state();
    for x in removed {
        assert!(s.device_by_key(x).is_none(), "{what}: a removed device counts again");
    }
    for a in 0..ADMIN_KEYS_MAX {
        assert!(s.device_by_key(&k(&format!("admin phone {a}")).hash).is_some(), "{what}: admin {a} is out");
    }
}

/// The first root's room full of carried records; then the change to n1,
/// lost after its first records; the change to n2; to n3.
#[test]
fn a_full_room_of_carried_records_and_three_changes() {
    if !full_size("a_full_room_of_carried_records_and_three_changes") {
        return;
    }
    let mut g = G::new();
    let (admitted, n) = carried_room(&mut g, MAX_ROOT_RECORDS / ADMIN_KEYS_MAX);
    assert!(n > MAX_ROOT_RECORDS - 2 * ADMIN_KEYS_MAX, "{n}");
    let removed = &admitted[..n];
    removed_stay_out(&g, removed, "before");
    for n in 1..=3 {
        let w = change(&mut g, &k(&format!("n{n}")), &k(&format!("p{n}")));
        let w = w.unwrap_or_else(|e| panic!("change {n}: {e}"));
        // The removals ride re-issued: the list holds the admins' records.
        assert!(w.list.0.len() <= 4 * ADMIN_KEYS_MAX, "change {n}: list of {}", w.list.0.len());
        removed_stay_out(&g, removed, &format!("change {n}"));
        for x in &admitted[removed.len()..] {
            assert!(g.state().device_by_key(x).is_some(), "change {n}: a device that counted is out");
        }
    }
}

/// The same, and n1 removes devices the admins admitted, one key each,
/// until its room is full, before it is lost too; then the change to n2.
#[test]
fn a_later_root_adds_removals_before_it_is_lost() {
    if !full_size("a_later_root_adds_removals_before_it_is_lost") {
        return;
    }
    let mut g = G::new();
    let (admitted, n) = carried_room(&mut g, MAX_ADMIN_RECORDS);
    let mut removed: Vec<KeyHash> = admitted[..n].to_vec();
    change(&mut g, &k("n1"), &k("p1")).unwrap();
    let n1 = k("n1");
    let mut set = set_with(&g.root.key, &g.recs, &g.lists);
    for x in &admitted[removed.len()..] {
        if !try_rec(&mut g, &mut set, &n1, Kind::Revoke(Removal { keys: vec![*x], seen: Vec::new() })) {
            break;
        }
        removed.push(*x);
    }
    assert!(removed.len() - n > MAX_ROOT_RECORDS / 2);
    removed_stay_out(&g, &removed, "n1");
    for n in 2..=3 {
        let w = change(&mut g, &k(&format!("n{n}")), &k(&format!("p{n}")));
        let w = w.unwrap_or_else(|e| panic!("change {n}: {e}"));
        // The removals ride re-issued: the list holds the admins' records.
        assert!(w.list.0.len() <= 4 * ADMIN_KEYS_MAX, "change {n}: list of {}", w.list.0.len());
        removed_stay_out(&g, &removed, &format!("change {n}"));
    }
}

/// A removal of a key the writer of a change holds no admission of: an
/// admin of the old root admitted it, the old root removed it, and the
/// writer never got the admission. The admission arriving after the
/// change must not count.
#[test]
fn an_admission_after_the_change_of_a_key_the_old_root_removed() {
    let mut g = G::new();
    let admin = k("admin a");
    g.admin(&k("phone a"), &admin, POWER_ADMIT);
    let x = k("x");
    let adm = g.device(&admin, &x, "x", |_| {});
    let seen = vec![g.seen_at(&admin.hash, adm.body().seq)];
    g.root_rec(Kind::Revoke(Removal { keys: vec![x.hash], seen }));
    // The writer lacks the admission.
    let all = g.recs.clone();
    g.recs.retain(|r| r.id() != adm.id());
    change(&mut g, &k("n1"), &k("p1")).unwrap();
    let mut with: Vec<Record> = all;
    with.extend(g.recs.iter().filter(|r| !with.contains(r)).cloned().collect::<Vec<_>>());
    let s = state_with(&g.root.key, &with, &g.lists);
    assert!(s.device_by_key(&x.hash).is_none(), "the removed key counts again");
    let set = set_with(&g.root.key, &with, &g.lists);
    assert!(set.state().device_by_key(&x.hash).is_none(), "the removed key counts again in a set");
}

/// A change applies whole or not at all: a member that holds its head
/// without the whole group (head alone; head and list; all but the first
/// checkpoint) is a member that has not seen the head: the roots stay and
/// the old removals bar, also after a restart. Once the rest comes, its
/// state is the sender's.
#[test]
fn a_change_cut_inside_its_group_applies_nothing() {
    let mut g = G::new();
    let admin = k("admin a");
    g.admin(&k("phone a"), &admin, POWER_ADMIT);
    let xs: Vec<K> = (0..6).map(|i| k(&format!("x{i}"))).collect();
    for x in &xs {
        g.device(&admin, x, "x", |_| {});
    }
    for x in &xs[..4] {
        g.root_rec(Kind::Revoke(Removal { keys: vec![x.hash], seen: Vec::new() }));
    }
    let before = g.recs.clone();
    let w = change(&mut g, &k("n1"), &k("p1")).unwrap();
    assert!(w.first.iter().any(|r| matches!(r.body().kind, Kind::Revoke(_))), "no removal re-issued");
    let sender = set_with(&g.root.key, &g.recs, &g.lists);
    let unseen = set_with(&g.root.key, &before, &[]).state();
    let list = w.list.encode();
    let n = w.first.len();
    let z = w.first.iter().position(|r| matches!(r.body().kind, Kind::Revoke(_))).unwrap();
    // usize::MAX: every first record but the re-issued removal.
    for (firsts, with_list) in [(0, false), (0, true), (n - 1, true), (usize::MAX, true)] {
        let mut recs = before.clone();
        if firsts == usize::MAX {
            recs.extend(w.first.iter().enumerate().filter(|(i, _)| *i != z).map(|(_, r)| r.clone()));
        } else {
            recs.extend(w.first[..firsts].iter().cloned());
        }
        recs.push(w.record.clone());
        let lists = if with_list { vec![list.clone()] } else { Vec::new() };
        let mut m = set_with(&g.root.key, &recs, &lists);
        let what = format!("{firsts} first records, list {with_list}");
        let s = m.state();
        for x in &xs[..4] {
            assert!(s.device_by_key(&x.hash).is_none(), "{what}: a removed device counts");
        }
        assert_eq!(s.roots, unseen.roots, "{what}");
        assert_eq!(s.devices, unseen.devices, "{what}");
        assert_eq!(s.revoked, unseen.revoked, "{what}");
        // A restart there: the saved records and lists come back the same.
        let saved: Vec<Record> = m.ids().filter_map(|id| m.get(id)).cloned().collect();
        let held: Vec<Vec<u8>> = m.lists().map(<[u8]>::to_vec).collect();
        let back = set_with(&g.root.key, &saved, &held);
        assert_eq!(back.state(), s, "{what}: a restart changes the state");
        assert_eq!(back.digest(), m.digest(), "{what}: a restart changes the digest");
        // Then the rest comes.
        let _ = m.insert_list(&list);
        m.insert_all(w.first.iter().cloned());
        let _ = m.insert_list(&list);
        assert_eq!(m.state(), sender.state(), "{what}: not the sender's state at the end");
        assert_eq!(m.digest(), sender.digest(), "{what}");
    }
}

/// The root removes an admin key, the key signs once more, and the root
/// removes it again with the newer record seen. The two removals saw the
/// key differently: the change re-issues them as two removals, and what
/// the key signed after the first never counts, before the change or
/// after. The second removal does not stand for the first in a
/// checkpoint either.
#[test]
fn two_removals_of_one_key_seen_apart() {
    let mut g = G::new();
    let a = k("admin a");
    g.admin(&k("phone a"), &a, POWER_ADMIT);
    for i in 0..4 {
        g.device(&a, &k(&format!("early {i}")), "early", |_| {});
    }
    let seen = vec![g.seen_at(&a.hash, g.heads[&a.hash].0)];
    let first = g.root_rec(Kind::Revoke(Removal { keys: vec![a.hash], seen }));
    let five = k("five");
    let late = g.device(&a, &five, "five", |_| {});
    let seen = vec![g.seen_at(&a.hash, late.body().seq)];
    let second = g.root_rec(Kind::Revoke(Removal { keys: vec![a.hash], seen: seen.clone() }));
    let s = g.state();
    assert!(s.counting.contains(&first.id()) && s.counting.contains(&second.id()));
    assert!(s.device_by_key(&five.hash).is_none(), "counts before the change");
    // A checkpoint keeps the first: the second saw more.
    let set = set_with(&g.root.key, &g.recs, &g.lists);
    let cp = set.write_checkpoint(&set.state(), &k("root"), 0).unwrap();
    match &cp.body().kind {
        Kind::Checkpoint { keep, .. } => assert!(keep.contains(&first.id())),
        other => panic!("{other:?}"),
    }
    let w = change(&mut g, &k("n1"), &k("p1")).unwrap();
    let zs: Vec<&Removal> = w
        .first
        .iter()
        .filter_map(|r| match &r.body().kind {
            Kind::Revoke(rm) if rm.keys.contains(&a.hash) => Some(rm),
            _ => None,
        })
        .collect();
    let listed = w.list.0.contains(&first.id());
    let apart = zs.len() == 2 && zs.iter().any(|z| z.seen != seen);
    assert!(listed || apart, "one removal stands for both: {zs:?}");
    let s = g.state();
    assert!(s.device_by_key(&five.hash).is_none(), "counts after the change");
    let st = set_with(&g.root.key, &g.recs, &g.lists).state();
    assert_eq!((&st.devices, &st.revoked, &st.counting), (&s.devices, &s.revoked, &s.counting));
    // One removal by hand, by the new root, with the newer record seen,
    // leaves the first in force.
    let n1 = k("n1");
    g.rec(&n1, Kind::Revoke(Removal { keys: vec![a.hash], seen }));
    assert!(g.state().device_by_key(&five.hash).is_none(), "counts after one removal by hand");
}

/// Two changes of root, each re-issuing removals; the newest root
/// checkpoints, which leaves out the first records of the roots before
/// it, and the member compacts by it. What it saves restores to the same
/// state, in the order it saves and in any other.
#[test]
fn a_restart_after_two_changes_and_a_checkpoint() {
    let mut g = G::new();
    let admin = k("admin a");
    g.admin(&k("phone a"), &admin, POWER_ADMIT);
    for i in 0..3 {
        g.device(&k("root"), &k(&format!("d{i}")), "d", |_| {});
    }
    let x = k("x");
    g.device(&admin, &x, "x", |_| {});
    let seen = g.seen();
    g.root_rec(Kind::Revoke(Removal { keys: vec![x.hash], seen }));
    change(&mut g, &k("n1"), &k("p1")).unwrap();
    let n1 = k("n1");
    let y = k("y");
    g.device(&n1, &y, "y", |_| {});
    let seen = g.seen();
    g.rec(&n1, Kind::Revoke(Removal { keys: vec![y.hash], seen }));
    change(&mut g, &k("n2"), &k("p2")).unwrap();
    let n2 = k("n2");
    g.device(&n2, &k("z"), "z", |_| {});
    for rounds in 0..2 {
        let mut set = set_with(&g.root.key, &g.recs, &g.lists);
        if rounds == 1 {
            let cp = set.write_checkpoint(&set.state(), &n2, 0).unwrap();
            g.push(cp.clone());
            set.insert(cp).unwrap();
        }
        let st = set.state();
        set.compact(&st);
        let st = set.state();
        assert_eq!(st.roots.len(), 3);
        assert!(st.device_by_key(&x.hash).is_none() && st.device_by_key(&y.hash).is_none());
        let saved: Vec<Record> = set.in_dependency_order().into_iter().cloned().collect();
        let lists: Vec<Vec<u8>> = set.lists().map(<[u8]>::to_vec).collect();
        for (i, records) in [saved.clone(), shuffled(&saved, 7), shuffled(&saved, 8)].into_iter().enumerate() {
            for lists in [lists.clone(), lists.iter().rev().cloned().collect()] {
                let back = RecordSet::restore(set.root().clone(), set.recovery().clone(), &records, &lists);
                assert_eq!(back.digest(), set.digest(), "round {rounds}, order {i}");
                assert_eq!(back.state(), st, "round {rounds}, order {i}");
            }
        }
        // A device that joins now gets the same in parts, as the Welcome
        // sends them.
        let peer = k("d0").hash;
        let mut joiner = set_of(&g.root.key);
        for p in set.parts_for_peer(&st, &peer) {
            let records: Vec<Record> = p.records.iter().map(|r| (*r).clone()).collect();
            joiner.take_part(&records, &p.lists);
        }
        assert_eq!(joiner.digest(), set.digest(), "round {rounds}: a joiner");
        assert_eq!(joiner.state(), st, "round {rounds}: a joiner");
    }
}
