// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The records of an admin key that only a waiting root's records name
//! wait aside with that root's: taken when the change applies, never at
//! the cost of the root's own records, in any order, and dropped with the
//! root when its change is no longer on the way.

use super::*;
use crate::records::set::Written;

fn phone(member: &K) -> Device {
    let mut d = Device::new(member.key.clone(), "new phone", ROLE_PHONE);
    d.rights = RIGHT_READ | RIGHT_SEND | RIGHT_SECRETS;
    d
}

/// A group whose admin a published spare a, and the change to new_root
/// written on it, which names a on spare a. The change's records are not
/// in g: the caller hands them out.
fn changed(new_root: &str) -> (G, Written) {
    let mut g = G::new();
    g.device(&k("root"), &k("laptop"), "laptop", |_| {});
    g.admin(&k("phone a"), &k("admin a"), POWER_ADMIT | POWER_REMOVE);
    let mut set = set_with(&g.root.key, &g.recs, &g.lists);
    let st = set.state();
    let r = set.write_ack_spare(&st, &k("admin a"), &k("spare a").key, 0).unwrap();
    g.push(r);
    let mut set = set_with(&g.root.key, &g.recs, &g.lists);
    let st = set.state();
    let w = set
        .write_change(&st, &k("recovery"), crate::testkit::rk2(), &k(new_root), phone(&k("p1")), &[], false, 0)
        .unwrap();
    (g, w)
}

/// The spare's records after the change: its ack of the grant, then n
/// admissions, signed on top of the change's records.
fn spare_records(g: &G, w: &Written, n: usize) -> Vec<Record> {
    let mut h = g.clone();
    for r in w.first.iter().chain([&w.record]) {
        h.push(r.clone());
    }
    let start = h.recs.len();
    let (seq, id) = h.heads[&k("n1").hash];
    h.rec_as_is(&k("spare a"), Kind::Ack { seen: vec![Seen { key: k("n1").hash, seq, id }], spare: None });
    for i in 0..n {
        h.device(&k("spare a"), &k(&format!("tv {i}")), "tv", |_| {});
    }
    h.recs[start..].to_vec()
}

/// A member that holds the change and the new root's records but not the
/// list: the change waits, and what the spare signs waits aside with it.
fn waiting_member(g: &G, w: &Written) -> RecordSet {
    let mut recs = g.recs.clone();
    recs.extend(w.first.iter().cloned());
    recs.push(w.record.clone());
    let m = set_with(&g.root.key, &recs, &[]);
    assert_eq!(m.state().list_missing, Some(w.list.hash()));
    m
}

/// Room: the spare signs past a root's room in all; the new root's own
/// records stay aside (the spare's go first when the room is full, the
/// lowest seqs staying), and the change applies when its list comes.
#[test]
fn a_named_admin_never_pushes_the_roots_records_out() {
    let (g, w) = changed("n1");
    let mut m = waiting_member(&g, &w);
    let spare = spare_records(&g, &w, 1600);
    assert!(spare.len() as u64 > crate::records::keep::ceiling(true), "past one root's room");
    m.insert_all(spare.clone());
    for r in &w.first {
        assert!(m.contains(&r.id()), "the new root's record stays aside");
    }
    assert!(m.contains(&spare[0].id()), "the spare's lowest seq stays");
    m.insert_list(&w.list.encode()).unwrap();
    let s = m.state();
    assert_eq!(s.roots.last(), Some(&k("n1").hash));
    assert!(s.counting.contains(&spare[0].id()));
    crate::testkit::closed(&m);
}

/// Order: the spare's records before the record that names its key, in a
/// restore or one by one, end where they end in dependency order.
#[test]
fn the_admins_records_before_its_naming_record_end_the_same() {
    let (g, w) = changed("n1");
    let spare = spare_records(&g, &w, 2);
    let mut all = g.recs.clone();
    all.extend(w.first.iter().cloned());
    all.push(w.record.clone());
    all.extend(spare.iter().cloned());
    let lists = vec![w.list.encode()];
    let want = RecordSet::restore(g.root.key.clone(), rk(), &all, &lists).state();
    assert!(spare.iter().all(|r| want.counting.contains(&r.id())));
    let mut reversed = all.clone();
    reversed.reverse();
    let back = RecordSet::restore(g.root.key.clone(), rk(), &reversed, &lists);
    assert_eq!(back.state(), want);
    // Without the list first: the spare's records wait aside, then count.
    let mut m = set_of(&g.root.key);
    for r in &reversed {
        let _ = m.insert(r.clone());
    }
    for r in &reversed {
        let _ = m.insert(r.clone());
    }
    m.insert_list(&lists[0]).unwrap();
    assert_eq!(m.state(), want);
}

/// Fork: a second change at the same step halts the group; what waited
/// aside, the root's records and the spare's, is dropped with it.
#[test]
fn a_fork_drops_the_admins_records_with_the_root() {
    let (g, w) = changed("n1");
    let (_, w2) = changed("n2");
    let mut m = waiting_member(&g, &w);
    let spare = spare_records(&g, &w, 2);
    m.insert_all(spare.clone());
    assert!(spare.iter().all(|r| m.contains(&r.id())), "aside while the change waits");
    m.insert(w2.record.clone()).unwrap();
    let s = m.state();
    assert!(s.halted());
    assert!(spare.iter().all(|r| !m.contains(&r.id())), "dropped with the waiting root");
    assert!(w.first.iter().all(|r| !m.contains(&r.id())));
}
