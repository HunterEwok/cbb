// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The root pair from a peer the set does not know, read from its rule
//! only: when the last root has two histories, a peer that is not removed
//! and not a device of the group gets that pair (and only it) in sync,
//! and a set takes from such a peer exactly one valid pair of the last
//! root it counts: two records of that root at one step. Nothing else
//! comes in by that path, and a set that takes the pair stops (`Full`),
//! neither halted nor emptied.

mod pieces;

use cbb_core::records::eval::Stop;
use cbb_core::records::{Kind, Record, RecordSet};
use pieces::*;

/// Two records of `by` at the step after the head the set holds, each
/// a different plain admission.
fn fork(set: &RecordSet, by: &K, tag: &str, t: u64) -> (Record, Record) {
    let mut one = Chain::new();
    one.follow(set, by);
    let mut two = Chain::new();
    two.follow(set, by);
    let seen = vec![head_of(set, &by.hash).unwrap()];
    let mut x = plain(&k(&format!("{tag} x")), "x");
    x.seen = seen.clone();
    let mut y = plain(&k(&format!("{tag} y")), "y");
    y.seen = seen;
    (one.sign_raw(set, by, Kind::device(x), t), two.sign_raw(set, by, Kind::device(y), t + 1))
}

/// Whether the set is unchanged by a stranger's offer: no record new, the
/// group not stopped.
fn untouched(set: &RecordSet, len: usize, what: &str) {
    let st = set.state();
    assert_eq!(set.len(), len, "{what}: nothing taken");
    assert_eq!(st.stop, Stop::None, "{what}: not stopped");
    assert!(has(&st, &k("D")) && has(&st, &k("F")), "{what}: nothing lost");
}

/// The valid pair of the current root: the set takes both, stops Full,
/// is not halted and keeps every device.
#[test]
fn a_valid_pair_of_the_last_root_stops_the_set() {
    let g = group("pf1");
    let mut to = g.set.clone();
    let (x, y) = fork(&g.set, &g.r1, "pf1", g.t + 1_000);
    let n = to.insert_from_unknown(&[x.clone(), y.clone()], &[]);
    let st = to.state();
    assert_eq!(n, 2, "both records of the pair");
    assert!(to.contains(&x.id()) && to.contains(&y.id()));
    assert_eq!(st.stop, Stop::Full, "the root has two histories");
    assert!(!st.halted(), "a root fork stops, it does not halt");
    assert!(has(&st, &k("D")) && has(&st, &k("E")) && has(&st, &k("F")), "not emptied");
}

/// A pair of a cut root (the one before a change) is not the last root's:
/// nothing is taken.
#[test]
fn a_pair_of_an_old_root_is_not_taken() {
    let mut g = group("pf2");
    let old = g.set.clone();
    g.t += 1_000;
    change(&mut g.set, &k("pf2 root 2"), &k("P2"), &[], g.t);
    let len = g.set.len();
    let (x, y) = fork(&old, &g.r1, "pf2", g.t + 1_000);
    g.set.insert_from_unknown(&[x, y], &[]);
    untouched(&g.set, len, "an old root's pair");
}

/// Two pairs, at two steps: at most one pair comes in, the lower; the one
/// above it is not taken.
#[test]
fn a_pair_above_another_is_not_taken() {
    let g = group("pf3");
    let mut to = g.set.clone();
    let (x, y) = fork(&g.set, &g.r1, "pf3", g.t + 1_000);
    let mut above = g.set.clone();
    let _ = above.insert(x.clone());
    let (u, v) = fork(&above, &g.r1, "pf3 up", g.t + 3_000);
    let len = to.len();
    let n = to.insert_from_unknown(&[u.clone(), v.clone(), x.clone(), y.clone()], &[]);
    assert!(n <= 2, "one pair at most: {n}");
    assert!(!to.contains(&u.id()) && !to.contains(&v.id()), "not the pair above");
    assert!(to.len() <= len + 2);
    let st = to.state();
    assert!(!st.halted() && has(&st, &k("D")), "neither halted nor emptied");
    // Only the higher pair, the step below it missing: still two records
    // of the root at one step, so it may come in, and stops the set as any
    // pair; never halted, never emptied.
    let mut to = g.set.clone();
    let n = to.insert_from_unknown(&[u.clone(), v.clone()], &[]);
    let st = to.state();
    eprintln!("a pair over a gap: {n} taken, stop {:?}", st.stop);
    assert!(n <= 2 && !st.halted() && has(&st, &k("D")) && has(&st, &k("F")));
    assert!(n == 0 || st.stop == Stop::Full, "taken, it stops the set");
}

/// Three records of the root at one step are not a pair: at most two come
/// in, never the third.
#[test]
fn three_records_at_one_step_are_not_a_pair() {
    let g = group("pf4");
    let mut to = g.set.clone();
    let (x, y) = fork(&g.set, &g.r1, "pf4", g.t + 1_000);
    let (z, _) = fork(&g.set, &g.r1, "pf4 z", g.t + 5_000);
    let len = to.len();
    let n = to.insert_from_unknown(&[x.clone(), y.clone(), z.clone()], &[]);
    let held = [&x, &y, &z].iter().filter(|r| to.contains(&r.id())).count();
    assert!(n <= 2 && held <= 2 && to.len() <= len + 2, "three offered, {held} held");
    let st = to.state();
    assert!(!st.halted() && has(&st, &k("D")) && has(&st, &k("F")), "neither halted nor emptied");
}

/// A pair and one more root record: the extra record is not taken.
#[test]
fn a_pair_and_one_more_root_record_takes_no_more() {
    let g = group("pf5");
    let mut to = g.set.clone();
    let (x, y) = fork(&g.set, &g.r1, "pf5", g.t + 1_000);
    let mut on_x = g.set.clone();
    let _ = on_x.insert(x.clone());
    let mut chain = Chain::new();
    chain.follow(&on_x, &g.r1);
    let more = chain.sign_raw(&on_x, &g.r1, Kind::device(plain(&k("pf5 more"), "more")), g.t + 4_000);
    let len = to.len();
    to.insert_from_unknown(&[x.clone(), y.clone(), more.clone()], &[]);
    assert!(!to.contains(&more.id()), "the record past the pair");
    assert!(to.len() <= len + 2);
    assert!(!has(&to.state(), &k("pf5 more")));
    assert!(!to.state().halted());
}

/// A pair from an admin key is no root pair: nothing is taken.
#[test]
fn a_pair_from_an_admin_key_is_not_taken() {
    let g = group("pf6");
    let mut to = g.set.clone();
    let len = to.len();
    let (x, y) = fork(&g.set, &k("A"), "pf6", g.t + 1_000);
    to.insert_from_unknown(&[x, y], &[]);
    untouched(&to, len, "an admin's pair");
}

/// In sync a stranger gets the pair and only it; a removed device gets no
/// pair; a device of the group gets its records as before.
#[test]
fn a_stranger_gets_the_pair_and_a_removed_key_does_not() {
    let mut g = group("pf7");
    let st = g.set.state();
    g.t += 1_000;
    g.set.write_record(&st, &g.r1, Kind::Revoke(removal(&[&k("E")], vec![])), g.t).unwrap();
    let (x, y) = fork(&g.set, &g.r1, "pf7", g.t + 1_000);
    let before = g.set.clone();
    let _ = g.set.insert(x.clone());
    let _ = g.set.insert(y.clone());
    let st = g.set.state();
    assert_eq!(st.stop, Stop::Full);
    let ids = |peer: &K| g.set.for_peer(&st, &peer.hash).iter().map(|r| r.id()).collect::<Vec<_>>();
    let stranger = ids(&k("pf7 stranger"));
    assert!(stranger.contains(&x.id()) && stranger.contains(&y.id()), "the pair");
    assert_eq!(stranger.len(), 2, "and only it");
    let removed = ids(&k("E"));
    assert!(!removed.contains(&x.id()) && !removed.contains(&y.id()), "a removed key gets no pair");
    // A member that holds the group, fed what a stranger gets, stops too.
    let fed: Vec<Record> = g.set.for_peer(&st, &k("pf7 stranger").hash).into_iter().cloned().collect();
    let mut known = before;
    assert_eq!(known.insert_from_unknown(&fed, &[]), 2);
    let ks = known.state();
    assert_eq!(ks.stop, Stop::Full);
    assert!(!ks.halted() && has(&ks, &k("D")), "neither halted nor emptied");
}
