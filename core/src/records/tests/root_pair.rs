// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The pair that proves a root fork travels to every peer: a member that
//! holds both heads hands the two records to a key it does not know, and a
//! set takes them from such a peer only as a valid pair of the root it
//! counts, and nothing else of that root.

use super::*;
use crate::records::eval::Stop;

/// g with a laptop, a root record r and its twin at one seq; the side that
/// holds only the twin.
fn forked() -> (G, Record, Record, Vec<Record>) {
    let mut g = G::new();
    g.device(&k("root"), &k("laptop"), "laptop", |_| {});
    let r = g.root_rec(Kind::Copies { incoming_ms: 50_000, seen: vec![] });
    let twin = root_twin(&g, &r, Kind::Copies { incoming_ms: 60_000, seen: vec![] });
    let side: Vec<Record> = g.recs.iter().filter(|q| q.id() != r.id()).cloned().chain([twin.clone()]).collect();
    g.recs.push(twin.clone());
    (g, r, twin, side)
}

/// A member holding both heads gives the pair to a key it does not know;
/// a set on one line takes it from that peer and stops in full.
#[test]
fn a_key_it_does_not_know_gets_the_pair_and_stops() {
    let (g, r, twin, side) = forked();
    let m = set_with(&g.root.key, &g.recs, &g.lists);
    let ms = m.state();
    assert_eq!(ms.stop, Stop::Full);
    let given: Vec<Record> = m.for_peer(&ms, &k("stranger").hash).into_iter().cloned().collect();
    assert!(given.iter().any(|x| x.id() == r.id()) && given.iter().any(|x| x.id() == twin.id()));
    assert!(given.iter().all(|x| x.id() == r.id() || x.id() == twin.id()), "the pair and nothing else");
    let mut one = set_with(&g.root.key, &side, &g.lists);
    assert_ne!(one.state().stop, Stop::Full);
    assert_eq!(one.insert_from_unknown(&given, &[]), 1);
    assert_eq!(one.state().stop, Stop::Full);
}

/// From a peer it does not know a set takes no lone record of its root,
/// nor a pair of a root it does not count, nor other records of its root
/// beside the pair.
#[test]
fn only_a_valid_pair_of_the_counted_root_is_taken() {
    let (mut g, r, twin, side) = forked();
    let mut one = set_with(&g.root.key, &side, &g.lists);
    let n = one.len();
    assert_eq!(one.insert_from_unknown(core::slice::from_ref(&r), &[]), 0, "a lone record");
    // A pair signed by a key that is not the root.
    let other = k("other");
    let body = |kind| Body { group: g.gid, signer: other.hash, seq: 1, prev: None, time_ms: 0, kind, held: false };
    let fake = [
        Record::sign(body(Kind::Copies { incoming_ms: 50_000, seen: vec![] }), &other).unwrap(),
        Record::sign(body(Kind::Copies { incoming_ms: 60_000, seen: vec![] }), &other).unwrap(),
    ];
    assert_eq!(one.insert_from_unknown(&fake, &[]), 0, "not the root's");
    assert_eq!(one.len(), n);
    // The pair with another record of the root beside it: only the pair.
    let extra = g.device(&k("root"), &k("tv"), "tv", |_| {});
    let offered = [r.clone(), twin.clone(), extra.clone()];
    assert_eq!(one.insert_from_unknown(&offered, &[]), 1);
    assert!(!one.contains(&extra.id()) && one.contains(&r.id()));
}
