// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! A change written past a waiting one, as tests: a writer that holds the
//! head of change N without N's group writes N+1 when the person asks
//! (`write_change_over_waiting`); members apply N+1 over N, N's root and
//! all it signs never count, even when N's records come later, no spare
//! is named, and N travels with N+1.

use super::*;
use crate::records::set::{CHANGE_WAITING, Written};

fn phone(member: &K) -> Device {
    let mut d = Device::new(member.key.clone(), "new phone", ROLE_PHONE);
    d.rights = RIGHT_READ | RIGHT_SEND | RIGHT_SECRETS;
    d
}

const POWERS: u64 = POWER_ADMIT | POWER_REMOVE;

/// The first root's group: a laptop, and admin a on phone a, whose ack
/// publishes a spare.
fn group() -> G {
    let mut g = G::new();
    g.device(&k("root"), &k("laptop"), "laptop", |_| {});
    g.admin(&k("phone a"), &k("admin a"), POWERS);
    let mut set = set_with(&g.root.key, &g.recs, &g.lists);
    let st = set.state();
    let r = set.write_ack_spare(&st, &k("admin a"), &k("spare a").key, 0).unwrap();
    g.push(r);
    g
}

/// Change N, written on g's records (n1 on p1): g takes only its head and
/// list, as a writer that has the head and not the new root's records.
fn change_n(g: &mut G) -> Written {
    let mut set = set_with(&g.root.key, &g.recs, &g.lists);
    let st = set.state();
    let w =
        set.write_change(&st, &k("recovery"), crate::testkit::rk2(), &k("n1"), phone(&k("p1")), &[], false, 0).unwrap();
    g.push(w.record.clone());
    g.lists.push(w.list.encode());
    w
}

/// N+1 by the writer that holds N's head (n2 on p2), past the waiting
/// change; g takes all of it. Returns it and the writer's set.
fn change_over(g: &mut G) -> (Written, RecordSet) {
    let mut set = set_with(&g.root.key, &g.recs, &g.lists);
    let st = set.state();
    let e = set
        .clone()
        .write_change(&st, &k("recovery"), crate::testkit::rk2(), &k("n2"), phone(&k("p2")), &[], false, 0)
        .unwrap_err();
    assert_eq!(e.to_string(), CHANGE_WAITING, "the default stays the advice to sync first");
    let w = set
        .write_change_over_waiting(&st, &k("recovery"), crate::testkit::rk2(), &k("n2"), phone(&k("p2")), &[], false, 0)
        .unwrap();
    for r in &w.first {
        g.push(r.clone());
    }
    g.push(w.record.clone());
    g.lists.push(w.list.encode());
    (w, set)
}

fn has(s: &State, m: &K) -> bool {
    s.device_by_key(&m.hash).is_some()
}

/// N+1 follows N's head, re-issues the state before N and names no spare;
/// the group's root is n2 and n1 never commands.
#[test]
fn the_next_change_applies_over_a_waiting_one() {
    let mut g = group();
    let n = change_n(&mut g);
    let (w, _) = change_over(&mut g);
    assert_eq!(w.record.body().seq, n.record.body().seq + 1);
    assert_eq!(w.record.body().prev, Some(n.record.id()));
    let phone_a = w
        .first
        .iter()
        .find_map(|r| match &r.body().kind {
            Kind::Device(d) if d.key == k("phone a").key => Some((**d).clone()),
            _ => None,
        })
        .expect("phone a re-issued");
    assert!(phone_a.admin.is_none() && phone_a.powers == 0, "no spare past a waiting change");
    let s = g.state();
    assert_eq!(s.roots, vec![k("root").hash, k("n1").hash, k("n2").hash]);
    assert!(s.counting.contains(&n.record.id()) && s.counting.contains(&w.record.id()));
    assert!(has(&s, &k("laptop")) && has(&s, &k("phone a")) && has(&s, &k("p2")));
    assert!(!has(&s, &k("p1")));
    for key in ["n1", "admin a", "spare a"] {
        assert!(!s.may_command(&k(key).hash), "{key}");
    }
    let mut m = set_of(&g.root.key);
    sync_all(&mut m, &g.recs, &g.lists);
    assert_eq!(m.state().devices, s.devices);
}

/// N's group arriving after N+1 changes nothing: none of n1's records
/// counts, its device is not admitted, and n1 signs nothing that counts
/// afterwards, in either order of arrival.
#[test]
fn the_waiting_changes_records_never_count_when_they_come() {
    let mut g = group();
    let n = change_n(&mut g);
    change_over(&mut g);
    let before = g.state();
    for r in &n.first {
        g.push(r.clone());
    }
    let late = g.device(&k("n1"), &k("tv"), "tv", |_| {});
    let s = g.state();
    assert_eq!(s.roots.last(), Some(&k("n2").hash));
    assert!(n.first.iter().chain([&late]).all(|r| !s.counting.contains(&r.id())));
    assert_eq!(s.devices, before.devices);
    assert!(!has(&s, &k("p1")) && !has(&s, &k("tv")));
    for order in 0..2 {
        let mut recs = g.recs.clone();
        if order == 1 {
            recs.reverse();
        }
        let mut m = set_of(&g.root.key);
        sync_all(&mut m, &recs, &g.lists);
        assert_eq!(m.state().devices, s.devices, "order {order}");
        assert_eq!(m.state().roots.last(), Some(&k("n2").hash), "order {order}");
    }
}

/// N travels with N+1: what the writer gives a member holds both heads
/// and N+1's group, and a member that takes only that ends where the
/// writer is.
#[test]
fn the_waiting_head_travels_with_the_next() {
    let mut g = group();
    let n = change_n(&mut g);
    let (w, set) = change_over(&mut g);
    let st = set.state();
    let given: Vec<Record> = set.for_peer(&st, &k("laptop").hash).into_iter().cloned().collect();
    assert!(given.iter().any(|r| r.id() == n.record.id()) && given.iter().any(|r| r.id() == w.record.id()));
    assert!(w.first.iter().all(|f| given.iter().any(|r| r.id() == f.id())));
    let lists: Vec<Vec<u8>> = set.lists_for_peer(&st, &k("laptop").hash).into_iter().map(<[u8]>::to_vec).collect();
    let mut m = set_of(&g.root.key);
    let old: Vec<Record> = g.recs.iter().filter(|r| r.body().signer == k("root").hash).cloned().collect();
    sync_all(&mut m, &old, &[]);
    sync_all(&mut m, &given, &lists);
    let t = m.state();
    assert_eq!(t.roots.last(), Some(&k("n2").hash));
    assert_eq!(t.devices, st.devices);
}

/// Past a waiting change the writer refuses N's root as the new root;
/// with nothing waiting it writes as `write_change` does.
#[test]
fn past_a_waiting_change_the_writer_still_refuses() {
    let mut g = group();
    change_n(&mut g);
    let set = set_with(&g.root.key, &g.recs, &g.lists);
    let st = set.state();
    assert!(
        set.clone()
            .write_change_over_waiting(
                &st,
                &k("recovery"),
                crate::testkit::rk2(),
                &k("n1"),
                phone(&k("p2")),
                &[],
                false,
                0
            )
            .is_err(),
        "N's root is not a new root"
    );
    // Nothing waits: the same as write_change.
    let g2 = group();
    let mut s2 = set_with(&g2.root.key, &g2.recs, &g2.lists);
    let st2 = s2.state();
    let w = s2
        .write_change_over_waiting(
            &st2,
            &k("recovery"),
            crate::testkit::rk2(),
            &k("n9"),
            phone(&k("p9")),
            &[],
            false,
            0,
        )
        .unwrap();
    assert_eq!((w.record.body().seq, w.record.body().prev), (1, None));
}
