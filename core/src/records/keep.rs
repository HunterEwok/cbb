// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! Which records a set keeps (rule 6): a ceiling for each key, then the
//! set's room shared fairly between keys, so that no key, an old root's
//! included, can push another key's records out by making many of its own.
//!
//! The room is counted in units: a record takes one unit for each 512
//! bytes it starts (2 MiB over 4096 records), and a claim 79 more: 63 since
//! it brings a new root key, and 16 paid ahead for that root's records.
//! 4096 units hold at most 4096 records and 2 MiB.
//!
//! Each key's records are taken in its own order: a root's removals,
//! freezes and resolves first, by seq, so that nothing of the root's
//! drops them, its checkpoints included; then its checkpoints, the newest
//! first, so that a key at its ceiling can still checkpoint and free room;
//! then the rest by seq, then ID (records of one seq with other IDs count
//! against the same ceiling). The order is each record's own, never what
//! else the set holds, so that a set that drops records as they come keeps
//! what one that saw them all at once keeps. At level s a
//! key keeps the longest start of that order within min(s, its ceiling)
//! units. A key's demand at s is min(s, its ceiling, all its units); s is
//! the highest level at which the demands fit in 4096 units. So a key whose
//! records take few units keeps them all whatever the others make: another
//! key's records only lower the level down to the first key's own.
//!
//! The ceilings: the group's first root's 1024 units, and a root the
//! member's evaluation put on the path (`RecordSet::compact`) the same;
//! an admin key's 256. The root a claim names has no room of its own: its
//! records are kept, at most 16 units of them, while a kept claim names it,
//! out of what the claim paid ahead. A claim that is dropped takes its
//! root's records with it.
//!
//! What is kept depends on the records alone, never on the order they came
//! in. A member that drops records as they come remembers a little of what
//! it dropped (`Cut`: the level, which only falls as records are added, and
//! for each key the first record it dropped), and so keeps exactly what one
//! that saw them all at once keeps.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;

use super::key::{KeyHash, RecordId};
use super::{MAX_ADMIN_RECORDS, MAX_RECORDS, MAX_ROOT_RECORDS, MAX_SET_BYTES};

/// The bytes of one unit.
pub const UNIT: usize = MAX_SET_BYTES / MAX_RECORDS;
/// The units of the whole set.
pub const ROOM: u64 = MAX_RECORDS as u64;
/// What a claim adds to its units: 63 for its new key, and 16 paid ahead
/// for its root's records.
pub const CLAIM_EXTRA: u64 = 63 + FUTURE;
/// The units of a claimed root's records while its claim is all that
/// names it.
pub const FUTURE: u64 = super::MAX_FUTURE_ROOT_RECORDS as u64;

/// One record as the keeping sees it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Item {
    pub signer: KeyHash,
    pub seq: u64,
    pub id: RecordId,
    pub units: u64,
    /// A checkpoint: it comes after a root's removals, before the rest.
    pub checkpoint: bool,
    /// A root's revoke, freeze or resolve: it comes first.
    pub early: bool,
    /// A claim: the root it names.
    pub names: Option<KeyHash>,
}

/// A record's place in its key's order.
pub type Pos = (u8, u64, RecordId);

impl Item {
    /// Its place in its key's order: a root's removals and resolves first,
    /// by seq; then checkpoints, the newest first; then the rest by seq
    /// and ID.
    pub fn pos(&self) -> Pos {
        if self.early {
            (0, self.seq, self.id)
        } else if self.checkpoint {
            (1, u64::MAX.saturating_sub(self.seq), self.id)
        } else {
            (2, self.seq, self.id)
        }
    }
}

/// The units of a record of size bytes.
pub fn units(size: usize, claim: bool) -> u64 {
    let u = size.div_ceil(UNIT).max(1) as u64;
    if claim { u.saturating_add(CLAIM_EXTRA) } else { u }
}

/// A key's ceiling in units: a root's on the path 1024, an admin key's
/// 256.
pub fn ceiling(root: bool) -> u64 {
    if root { MAX_ROOT_RECORDS as u64 } else { MAX_ADMIN_RECORDS as u64 }
}

/// What a set that drops records as they come remembers of them.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Cut {
    level: u64,
    /// For each key, the first record of its order it dropped and the
    /// units of the records dropped from there: nothing after it is kept,
    /// and the units still count in the key's demand.
    marks: BTreeMap<KeyHash, (Pos, u64)>,
    /// The same for the roots claims name, within their 16 units.
    future: BTreeMap<KeyHash, Pos>,
}

/// The highest level: past it no ceiling binds.
const TOP: u64 = MAX_ROOT_RECORDS as u64;

impl Default for Cut {
    fn default() -> Cut {
        Cut { level: TOP, marks: BTreeMap::new(), future: BTreeMap::new() }
    }
}

impl Cut {
    /// Reports whether the set dropped nothing yet.
    pub fn is_empty(&self) -> bool {
        self.marks.is_empty() && self.future.is_empty()
    }

    /// The level the shares stand at.
    pub fn level(&self) -> u64 {
        self.level.min(TOP)
    }

    /// The units key dropped, when it dropped any.
    pub fn dropped(&self, key: &KeyHash) -> Option<u64> {
        self.marks.get(key).map(|(_, u)| *u)
    }

    /// The keys that dropped records, with their units.
    pub fn dropped_all(&self) -> impl Iterator<Item = (&KeyHash, u64)> {
        self.marks.iter().map(|(k, (_, u))| (k, *u))
    }

    /// Reports whether a record comes at or after the first record its key
    /// dropped: it is not kept.
    pub fn past(&self, it: &Item) -> bool {
        self.marks.get(&it.signer).is_some_and(|(m, _)| it.pos() >= *m)
            || self.future.get(&it.signer).is_some_and(|m| it.pos() >= *m)
    }

    /// Forgets where a key stopped while it had no room of its own: it has
    /// a ceiling now (an admin key, or a promoted root).
    pub fn forget_future(&mut self, key: &KeyHash) {
        self.future.remove(key);
    }
}

/// The IDs of the records a set keeps. ceiling_of gives a key's ceiling
/// when it has room of its own, None for a root only claims name.
pub fn keep(items: &[Item], ceiling_of: impl Fn(&KeyHash) -> Option<u64>) -> BTreeSet<RecordId> {
    keep_after(items, ceiling_of, &Cut::default()).0
}

/// keep for a set that already dropped records: cut is what it remembers
/// of them; the new cut comes back.
pub fn keep_after(
    items: &[Item],
    ceiling_of: impl Fn(&KeyHash) -> Option<u64>,
    cut: &Cut,
) -> (BTreeSet<RecordId>, Cut) {
    let mut by_key: BTreeMap<KeyHash, Vec<&Item>> = BTreeMap::new();
    let mut claimed: BTreeMap<KeyHash, Vec<&Item>> = BTreeMap::new();
    // A key with a ceiling of its own no longer stops where it stopped as
    // a claim's root.
    let mut cut = cut.clone();
    let owned: Vec<KeyHash> = cut.future.keys().filter(|k| ceiling_of(k).is_some()).copied().collect();
    for k in &owned {
        cut.forget_future(k);
    }
    let cut = &cut;
    for it in items {
        if cut.past(it) {
            continue;
        }
        if ceiling_of(&it.signer).is_some() {
            by_key.entry(it.signer).or_default().push(it);
        } else {
            claimed.entry(it.signer).or_default().push(it);
        }
    }
    struct Key<'a> {
        hash: KeyHash,
        ceiling: u64,
        items: Vec<&'a Item>,
        /// All its units, those of the records it dropped included.
        total: u64,
    }
    let keys: Vec<Key> = by_key
        .into_iter()
        .map(|(hash, mut items)| {
            items.sort_by_key(|it| it.pos());
            items.dedup_by_key(|it| it.id);
            let dropped = cut.marks.get(&hash).map_or(0, |(_, u)| *u);
            let total = items.iter().fold(dropped, |t, it| t.saturating_add(it.units));
            Key { hash, ceiling: ceiling_of(&hash).unwrap_or(0), items, total }
        })
        .collect();
    let demand = |s: u64| keys.iter().fold(0u64, |d, k| d.saturating_add(s.min(k.ceiling).min(k.total)));
    let top = cut.level.min(TOP);
    let level = if demand(top) <= ROOM {
        top
    } else {
        let (mut lo, mut hi) = (0u64, top);
        // demand(lo) fits (nothing at 0), demand(hi) does not.
        while hi.saturating_sub(lo) > 1 {
            let mid = lo.saturating_add(hi.saturating_sub(lo) / 2);
            if demand(mid) <= ROOM { lo = mid } else { hi = mid }
        }
        lo
    };
    let mut kept = BTreeSet::new();
    let mut next = Cut { level, marks: BTreeMap::new(), future: cut.future.clone() };
    for k in &keys {
        let cap = level.min(k.ceiling);
        let mut used = 0u64;
        let mut first_out: Option<Pos> = None;
        let mut out_units = 0u64;
        for it in &k.items {
            let u = used.saturating_add(it.units);
            if first_out.is_none() && u <= cap {
                used = u;
                kept.insert(it.id);
            } else {
                first_out.get_or_insert(it.pos());
                out_units = out_units.saturating_add(it.units);
            }
        }
        let old = cut.marks.get(&k.hash);
        let mark = match (first_out, old) {
            (Some(f), Some((m, u))) => Some((f.min(*m), out_units.saturating_add(*u))),
            (Some(f), None) => Some((f, out_units)),
            (None, Some(m)) => Some(*m),
            (None, None) => None,
        };
        if let Some(m) = mark {
            next.marks.insert(k.hash, m);
        }
    }
    // Keys with no record left keep what they dropped.
    for (h, m) in &cut.marks {
        next.marks.entry(*h).or_insert(*m);
    }
    // The roots that kept claims name: each its first 16 units, paid by
    // the claims; a root no kept claim names keeps nothing.
    let named: BTreeSet<KeyHash> = items.iter().filter(|it| kept.contains(&it.id)).filter_map(|it| it.names).collect();
    for (hash, mut items) in claimed {
        if !named.contains(&hash) {
            continue;
        }
        items.sort_by_key(|it| it.pos());
        items.dedup_by_key(|it| it.id);
        let mut used = 0u64;
        for it in items {
            let u = used.saturating_add(it.units);
            if u > FUTURE {
                let m = next.future.entry(hash).or_insert(it.pos());
                *m = (*m).min(it.pos());
                break;
            }
            used = u;
            kept.insert(it.id);
        }
    }
    (kept, next)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn item(signer: u8, seq: u64, n: u32, size: usize) -> Item {
        let mut id = [0u8; 32];
        id[0] = signer;
        id[1..5].copy_from_slice(&n.to_be_bytes());
        id[5..13].copy_from_slice(&seq.to_be_bytes());
        // One ID is one record: the size is part of it.
        id[13..21].copy_from_slice(&(size as u64).to_be_bytes());
        Item {
            signer: KeyHash([signer; 32]),
            seq,
            id: RecordId(id),
            units: units(size, false),
            checkpoint: false,
            early: false,
            names: None,
        }
    }

    /// Key 0 plays the group's first root.
    /// Key 7 plays a root only claims name.
    fn ceil(k: &KeyHash) -> Option<u64> {
        (k.0[0] != 7).then(|| ceiling(k.0[0] == 0))
    }

    fn kept_of(items: &[Item], kept: &BTreeSet<RecordId>, signer: u8) -> usize {
        items.iter().filter(|it| it.signer.0[0] == signer && kept.contains(&it.id)).count()
    }

    /// One key making far more than the set holds, with forks at seq 1,
    /// pushes out no record of a key that holds fewer.
    #[test]
    fn one_key_cannot_crowd_out_the_others() {
        // The first root's key in the wrong hands after a takeover.
        let mut items = Vec::new();
        for n in 0..20_000 {
            items.push(item(0, 1, n, 300));
        }
        for k in 8..20u8 {
            for s in 1..=250 {
                items.push(item(k, s, 0, 300));
            }
        }
        let kept = keep(&items, ceil);
        for k in 8..20u8 {
            assert_eq!(kept_of(&items, &kept, k), 250);
        }
        let flood = kept_of(&items, &kept, 0);
        assert!((250..=MAX_ROOT_RECORDS).contains(&flood), "{flood}");
        let units: u64 = items.iter().filter(|it| kept.contains(&it.id)).map(|it| it.units).sum();
        assert!(units <= ROOM);
        // Big records: a key of 40 small ones keeps them all.
        let mut items = Vec::new();
        for n in 0..100 {
            items.push(item(0, 1, n, 60_000));
        }
        for s in 1..=40 {
            items.push(item(1, s, 0, 400));
        }
        let kept = keep(&items, ceil);
        let units: u64 = items.iter().filter(|it| kept.contains(&it.id)).map(|it| it.units).sum();
        assert!(units as usize * UNIT <= MAX_SET_BYTES);
        assert_eq!(kept_of(&items, &kept, 1), 40);
        // Many keys each wanting much: they share alike.
        let mut items = Vec::new();
        for k in 8..47u8 {
            for s in 1..=256 {
                items.push(item(k, s, 0, 300));
            }
        }
        let kept = keep(&items, ceil);
        let counts: BTreeSet<usize> = (8..47u8).map(|k| kept_of(&items, &kept, k)).collect();
        assert_eq!(counts.len(), 1, "{counts:?}");
    }

    #[test]
    fn the_ceilings_of_one_key() {
        let mut items: Vec<Item> = (1..=300).map(|s| item(10, s, 0, 100)).collect();
        assert_eq!(keep(&items, ceil).len(), MAX_ADMIN_RECORDS);
        for it in items.iter_mut().take(10) {
            it.units = units(100, true);
        }
        // Three claims take 240 units; the fourth does not fit.
        assert_eq!(keep(&items, ceil).len(), 3);
    }

    /// A key at its ceiling still keeps its newest checkpoint.
    #[test]
    fn a_full_key_keeps_its_checkpoint() {
        let mut items: Vec<Item> = (1..=300).map(|s| item(0, s, 0, 100)).collect();
        let mut cp = item(0, 301, 0, 60_000);
        cp.checkpoint = true;
        items.push(cp);
        let mut old = item(0, 150, 1, 60_000);
        old.checkpoint = true;
        items.push(old);
        let kept = keep(&items, ceil);
        assert!(kept.contains(&cp.id) && kept.contains(&old.id));
        let (_, cut) = keep_after(&items[..300], ceil, &Cut::default());
        let (kept, _) = keep_after(&[cp], ceil, &cut);
        assert!(kept.contains(&cp.id));
    }

    fn arb_items() -> impl Strategy<Value = Vec<Item>> {
        prop::collection::vec(
            (0u8..8, 1u64..60, 0u32..4, prop::sample::select(vec![200usize, 700, 2_000, 9_000, 60_000]), 0u8..8),
            0..500,
        )
        .prop_map(|v| {
            v.into_iter()
                .map(|(k, s, n, b, c)| {
                    let mut it = item(k, s, n, b);
                    // A checkpoint, or a claim naming key 7, is another
                    // record: its own ID.
                    if c == 0 {
                        it.checkpoint = true;
                        it.id.0[31] = 1;
                    } else if c == 1 && k != 7 {
                        it.names = Some(KeyHash([7; 32]));
                        it.units = units(b, true);
                        it.id.0[31] = 2;
                    }
                    it
                })
                .collect()
        })
    }

    /// What sync brings: a peer offers again every record the set dropped
    /// without remembering it (a claimed root's, while no kept claim named
    /// it), until nothing changes.
    fn synced(mut held: Vec<Item>, mut cut: Cut, all: &[Item]) -> Vec<Item> {
        loop {
            let ids: BTreeSet<RecordId> = held.iter().map(|it| it.id).collect();
            let more: Vec<Item> = all.iter().filter(|it| !ids.contains(&it.id) && !cut.past(it)).copied().collect();
            let before = ids.len();
            held.extend(more);
            let (k, c) = keep_after(&held, ceil, &cut);
            held.retain(|it| k.contains(&it.id));
            held.sort_by_key(|it| it.id);
            held.dedup_by_key(|it| it.id);
            cut = c;
            if held.len() == before {
                return held;
            }
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig { cases: 128, failure_persistence: None, ..ProptestConfig::default() })]

        /// Keeping in two steps, or one record at a time, dropping what is
        /// not kept and remembering the cut, keeps what one step keeps: so
        /// the order records come in does not matter.
        #[test]
        fn any_order_keeps_the_same(a in arb_items(), b in arb_items()) {
            let all: Vec<Item> = a.iter().chain(b.iter()).copied().collect();
            let want = keep(&all, ceil);
            let units: u64 = all
                .iter()
                .filter(|it| want.contains(&it.id))
                .map(|it| (it.id, it.units))
                .collect::<BTreeMap<_, _>>()
                .values()
                .sum();
            prop_assert!(units <= ROOM);
            let (first, cut) = keep_after(&a, ceil, &Cut::default());
            let mut again: Vec<Item> = a.iter().filter(|it| first.contains(&it.id)).copied().collect();
            again.extend(b.iter().copied());
            let (k, cut) = keep_after(&again, ceil, &cut);
            again.retain(|it| k.contains(&it.id));
            let ids: BTreeSet<RecordId> = synced(again, cut, &all).iter().map(|it| it.id).collect();
            prop_assert_eq!(&ids, &want);
            for order in 0..2 {
                let (mut held, mut cut) = (Vec::<Item>::new(), Cut::default());
                let seq: Vec<Item> = if order == 0 { all.iter().rev().copied().collect() } else { all.clone() };
                for it in seq {
                    held.push(it);
                    let (k, c) = keep_after(&held, ceil, &cut);
                    held.retain(|it| k.contains(&it.id));
                    cut = c;
                }
                let held = synced(held, cut, &all);
                let ids: BTreeSet<RecordId> = held.iter().map(|it| it.id).collect();
                prop_assert_eq!(&ids, &want);
            }
        }
    }
}
