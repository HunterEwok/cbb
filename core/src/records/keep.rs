// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! Which records a set keeps (rule 6): a cap for each key, fixed by the
//! roster, so that no key, an old root's included, can push another key's
//! records out by making many of its own.
//!
//! The room is counted in units: a record takes one unit for each 512
//! bytes it starts (3.5 MiB over 7168 units). 7168 units hold at most
//! 7168 records and 3.5 MiB.
//!
//! Each key's records are taken in its own order: a root's removals,
//! freezes and resolves first, by seq, so that nothing of the root's
//! drops them, its checkpoints included; then its newest checkpoint, so
//! that a key at its ceiling can still checkpoint and free room; then the
//! rest by seq, then ID (records of one seq with other IDs count against
//! the same ceiling); then its older checkpoints, the newest first, so
//! that checkpoints that never count push none of its other records out
//! (`newest_only`). Of a root a takeover followed only what the
//! takeover lists is kept, within that root's ceiling (rule 32), and the
//! recovery chain is kept outside the rooms (rule 33). The order is each
//! record's own and which checkpoint is its key's newest, never anything
//! else the set holds. A key keeps the longest start of that order, in
//! whole records, within its cap less what it holds first (`keep_tiers`).
//! The cap is fixed by the roster alone, never by what other keys hold,
//! so a key whose records stay within its cap keeps them all whatever
//! the others make.
//!
//! The ceilings: the group's first root's 1536 units, and a root the
//! member's evaluation put on the path (`RecordSet::compact`) the same;
//! the roots a takeover cut 1536 together (the reserve); an admin key's
//! 256. Any other key has no room and keeps nothing.
//!
//! A set holds the records it would keep of what it holds (each insert
//! ends judged), and two members that exchange everything both end at
//! what one would keep of both sets. With records of unequal sizes a key
//! that passed its cap may keep other records than one that saw them all
//! at once would: what a member ends with can hang on the order the
//! records came in. A key that never passes its cap loses nothing.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;

use super::key::{KeyHash, RecordId};
use super::{MAX_ADMIN_RECORDS, MAX_RECORDS, MAX_ROOT_RECORDS, MAX_SET_BYTES};

/// The bytes of one unit.
pub const UNIT: usize = MAX_SET_BYTES / MAX_RECORDS;
/// The units of the whole set.
pub const ROOM: u64 = MAX_RECORDS as u64;

/// The units of the whole set: ROOM, or a test's small rooms.
pub fn room() -> u64 {
    #[cfg(test)]
    if let Some(r) = small::ROOMS.with(core::cell::Cell::get) {
        return r.0;
    }
    ROOM
}

/// Small rooms for tests (`Small`), so that a trace of the records model,
/// whose rooms are a few units, runs as it is: the set's room, a root's
/// ceiling and an admin's, and the units each record takes.
#[cfg(test)]
pub(crate) mod small {
    use alloc::collections::BTreeMap;
    use core::cell::{Cell, RefCell};

    use super::RecordId;

    std::thread_local! {
        pub static ROOMS: Cell<Option<(u64, u64, u64)>> = const { Cell::new(None) };
        pub static UNITS: RefCell<BTreeMap<RecordId, u64>> = const { RefCell::new(BTreeMap::new()) };
    }

    /// Small rooms on this thread while it lives.
    pub struct Small;

    impl Small {
        pub fn new(room: u64, root: u64, admin: u64) -> Small {
            ROOMS.with(|r| r.set(Some((room, root, admin))));
            Small
        }

        /// The units record id takes.
        pub fn units(&self, id: RecordId, units: u64) {
            UNITS.with(|u| u.borrow_mut().insert(id, units));
        }
    }

    impl Drop for Small {
        fn drop(&mut self) {
            ROOMS.with(|r| r.set(None));
            UNITS.with(|u| u.borrow_mut().clear());
        }
    }

    /// The units a test gave record id.
    pub fn units_of(id: &RecordId) -> Option<u64> {
        UNITS.with(|u| u.borrow().get(id).copied())
    }
}

/// One record as the keeping sees it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Item {
    pub signer: KeyHash,
    pub seq: u64,
    pub id: RecordId,
    pub units: u64,
    /// Its key's newest checkpoint (`newest_only`): it comes after a
    /// root's removals, before the rest.
    pub checkpoint: bool,
    /// An older checkpoint of its key (`newest_only`): it comes last.
    pub older: bool,
    /// A root's revoke, freeze or resolve: it comes first.
    pub early: bool,
}

/// A record's place in its key's order.
pub type Pos = (u8, u64, RecordId);

impl Item {
    /// Its place in its key's order: a root's removals and resolves first,
    /// by seq; then the key's newest checkpoint; then the rest by seq and
    /// ID; then its older checkpoints, the newest first. (A root a takeover cut keeps only what the takeover lists:
    /// `eval::kept_of`.)
    pub fn pos(&self) -> Pos {
        if self.early {
            (0, self.seq, self.id)
        } else if self.checkpoint {
            (1, u64::MAX.saturating_sub(self.seq), self.id)
        } else if self.older {
            (3, u64::MAX.saturating_sub(self.seq), self.id)
        } else {
            (2, self.seq, self.id)
        }
    }
}

/// Keeps the checkpoint mark on each key's newest checkpoint alone: the
/// highest seq, of two at one seq the smaller ID (two at one seq are a
/// root's two histories, which halt the group), among items and those
/// kept first (`first`, which take their part of the rooms before them).
/// Older checkpoints come after the rest of the room, so that checkpoints
/// that never count cannot push a key's other records out of it, while
/// the newest still finds a place. It returns each key's newest.
pub fn newest_only(items: &mut [Item], first: &[Item]) -> BTreeMap<KeyHash, RecordId> {
    let mut newest: BTreeMap<KeyHash, (u64, RecordId)> = BTreeMap::new();
    for it in items.iter().chain(first).filter(|it| it.checkpoint) {
        let n = newest.entry(it.signer).or_insert((it.seq, it.id));
        if (it.seq, core::cmp::Reverse(it.id)) > (n.0, core::cmp::Reverse(n.1)) {
            *n = (it.seq, it.id);
        }
    }
    for it in items.iter_mut().filter(|it| it.checkpoint) {
        it.checkpoint = newest.get(&it.signer).is_some_and(|n| n.1 == it.id);
        it.older = !it.checkpoint;
    }
    newest.into_iter().map(|(k, (_, id))| (k, id)).collect()
}

/// The units of a record of size bytes.
pub fn units(size: usize) -> u64 {
    size.div_ceil(UNIT).max(1) as u64
}

/// A key's ceiling in units: a root's on the path 1536, an admin key's
/// 256.
pub fn ceiling(root: bool) -> u64 {
    #[cfg(test)]
    if let Some((_, r, a)) = small::ROOMS.with(core::cell::Cell::get) {
        return if root { r } else { a };
    }
    if root { MAX_ROOT_RECORDS as u64 } else { MAX_ADMIN_RECORDS as u64 }
}

/// The units the roots before the current one keep together: none. After
/// a change of root only the last root's records, the admin keys it names
/// and the recovery chain count (L, "the last root only"), so a cut root's
/// record, listed or not, has no room: it is not charged and is dropped
/// like a record of a key the set does not know. `CUT_ROOTS_RESERVE`
/// stays only as the bound of a list's length in the format.
pub fn reserve() -> u64 {
    0
}

/// The IDs of the records a set keeps. ceiling_of gives a key's ceiling
/// when it has room of its own, None for a key that keeps nothing.
pub fn keep(items: &[Item], ceiling_of: impl Fn(&KeyHash) -> Option<u64>) -> BTreeSet<RecordId> {
    keep_tiers(items, ceiling_of, &BTreeMap::new(), &BTreeSet::new())
}

/// The IDs of the records a set keeps, each key within a cap fixed by the
/// roster alone, never by what other keys hold, where each key already
/// holds `pre` units before the rooms are judged (each root's newest
/// checkpoint, kept first): the roots' rooms, the cut roots' reserve and
/// each live admin key at its ceiling, which add up to the set's room;
/// the keys of `second` (admin keys that are no longer admins or not
/// among the live ones, `eval::rooms`) have no room. Each key keeps the
/// longest run of its first records, whole, within its cap less what it
/// holds first. So what a key keeps hangs on its own records and the
/// roster only, never on what other keys hold. A key that passed its cap
/// with records of unequal sizes may keep other records after it dropped
/// some than at once (see the module's last paragraph).
pub fn keep_tiers(
    items: &[Item],
    ceiling_of: impl Fn(&KeyHash) -> Option<u64>,
    pre: &BTreeMap<KeyHash, u64>,
    second: &BTreeSet<KeyHash>,
) -> BTreeSet<RecordId> {
    let pre_of = |k: &KeyHash| pre.get(k).copied().unwrap_or(0);
    let mut by_key: BTreeMap<KeyHash, Vec<&Item>> = BTreeMap::new();
    for it in items {
        if ceiling_of(&it.signer).is_some() {
            by_key.entry(it.signer).or_default().push(it);
        }
    }
    let mut kept = BTreeSet::new();
    for (hash, mut items) in by_key {
        items.sort_by_key(|it| it.pos());
        items.dedup_by_key(|it| it.id);
        let ceiling = ceiling_of(&hash).unwrap_or(0);
        let cap = if second.contains(&hash) { 0 } else { ceiling };
        let mut room = cap.saturating_sub(pre_of(&hash));
        for it in items {
            let Some(left) = room.checked_sub(it.units) else { break };
            room = left;
            kept.insert(it.id);
        }
    }
    kept
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
            units: units(size),
            checkpoint: false,
            older: false,
            early: false,
        }
    }

    /// Key 0 plays the group's first root.
    /// Key 7 plays a key with no room.
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
            it.units = 80;
        }
        // Three big records take 240 units; the fourth does not fit.
        assert_eq!(keep(&items, ceil).len(), 3);
        // A key with no room keeps nothing.
        let none: Vec<Item> = (1..=3).map(|s| item(7, s, 0, 100)).collect();
        assert!(keep(&none, ceil).is_empty());
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
        let kept = keep(&[cp], ceil);
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
                    // A checkpoint, or a root's removal, is another record:
                    // its own ID.
                    if c == 0 {
                        it.checkpoint = true;
                        it.id.0[31] = 1;
                    } else if c == 1 {
                        it.early = true;
                        it.id.0[31] = 2;
                    }
                    it
                })
                .collect()
        })
    }

    /// What sync brings: a peer offers again every record the set dropped
    /// without remembering it, until nothing changes.
    fn synced(mut held: Vec<Item>, all: &[Item]) -> Vec<Item> {
        loop {
            let ids: BTreeSet<RecordId> = held.iter().map(|it| it.id).collect();
            let more: Vec<Item> = all.iter().filter(|it| !ids.contains(&it.id)).copied().collect();
            let before = ids.len();
            held.extend(more);
            let k = keep(&held, ceil);
            held.retain(|it| k.contains(&it.id));
            held.sort_by_key(|it| it.id);
            held.dedup_by_key(|it| it.id);
            if held.len() == before {
                return held;
            }
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig { cases: 128, failure_persistence: None, ..ProptestConfig::default() })]

        /// Keeping in two steps, or one record at a time, dropping what is
        /// not kept, then offered again what was dropped, keeps what one
        /// step keeps.
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
            let first = keep(&a, ceil);
            let mut again: Vec<Item> = a.iter().filter(|it| first.contains(&it.id)).copied().collect();
            again.extend(b.iter().copied());
            let k = keep(&again, ceil);
            again.retain(|it| k.contains(&it.id));
            let ids: BTreeSet<RecordId> = synced(again, &all).iter().map(|it| it.id).collect();
            prop_assert_eq!(&ids, &want);
            for order in 0..2 {
                let mut held = Vec::<Item>::new();
                let seq: Vec<Item> = if order == 0 { all.iter().rev().copied().collect() } else { all.clone() };
                for it in seq {
                    held.push(it);
                    let k = keep(&held, ceil);
                    held.retain(|it| k.contains(&it.id));
                }
                let held = synced(held, &all);
                let ids: BTreeSet<RecordId> = held.iter().map(|it| it.id).collect();
                prop_assert_eq!(&ids, &want);
            }
        }
    }
}
