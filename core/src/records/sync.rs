// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! Sync by parts: what a sender gives a peer, and the IDs it says it
//! holds, split so that each message stays inside the frame's limit and
//! its fields' counts (format section 9.2: `records` and `have` carry at
//! most 4096 items each, a frame at most 7 MiB). A full set with the
//! records outside the rooms (the recovery chain, the firsts, a waiting
//! root's records) and up to 64 lists of changes of root does not fit one
//! frame (about 8.3 MiB at the widest), so nothing here assumes it does.
//!
//! A part keeps each change of root's list beside the head that names it,
//! and the parts keep the order of `RecordSet::for_peer`, so a receiver
//! that takes the parts one by one, each as records, lists, records,
//! ends with what one message of everything would have given it.

use alloc::vec::Vec;

use super::body::{Kind, list_hash};
use super::eval::State;
use super::set::RecordSet;
use super::{KeyHash, Record, RecordId};
use crate::wire::MAX_FRAME;

/// The most record envelopes one part carries: message `records`, field 2.
pub const PART_RECORDS: usize = 4096;

/// The most record IDs one `have` message names: message `have`, field 2.
pub const HAVE_IDS: usize = 4096;

/// What a part's items may take of a frame: the frame's limit less room
/// for the message's map, its type, the arrays' heads and `pad`. A frame
/// is padded up to the grid, and the limit is on the grid (448 · 16 KiB),
/// so a message under the limit stays under it once padded.
pub const PART_BYTES: usize = MAX_FRAME - (16 << 10);

/// What one item costs in a part beyond its own bytes: its head in the
/// array (at most 5 bytes for a length under 2^32) and some to spare.
const ITEM_HEAD: usize = 9;

/// One message's worth of sync: record envelopes in the order a receiver
/// takes them, and the lists the recovery heads among them name.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Part<'a> {
    pub records: Vec<&'a Record>,
    pub lists: Vec<&'a [u8]>,
}

impl Part<'_> {
    /// The bytes the part's items take in a message, with each item's head.
    pub fn bytes(&self) -> usize {
        let r = self.records.iter().fold(0usize, |n, r| n.saturating_add(r.envelope().len()).saturating_add(ITEM_HEAD));
        let l = self.lists.iter().fold(0usize, |n, l| n.saturating_add(l.len()).saturating_add(ITEM_HEAD));
        r.saturating_add(l)
    }
}

/// Splits records (in the order they are sent) and lists into parts of at
/// most max_records records and max_bytes bytes each. A change of root
/// travels whole in one part: its head, the list it names and the new
/// root's records up to the first checkpoint the head names, which move up
/// to right after the head (they depend on it alone), so that a receiver
/// never holds a head without the means to apply it. Lists no head among
/// the records names go after the records, packed by the same bytes.
pub fn split<'a>(records: &[&'a Record], lists: &[&'a [u8]], max_records: usize, max_bytes: usize) -> Vec<Part<'a>> {
    let mut placed = alloc::vec![false; lists.len()];
    let hash_of: Vec<[u8; 32]> = lists.iter().map(|l| list_hash(l)).collect();
    let size = |r: &Record| r.envelope().len().saturating_add(ITEM_HEAD);
    // The groups: a change of root with its list and first records, or a
    // record alone.
    let mut taken: alloc::collections::BTreeSet<RecordId> = alloc::collections::BTreeSet::new();
    let mut groups: Vec<(Vec<&'a Record>, Option<usize>)> = Vec::new();
    for &r in records {
        if taken.contains(&r.id()) {
            continue;
        }
        let mut group = alloc::vec![r];
        let mut with = None;
        if let Kind::Recovery { root, list, first, .. } = &r.body().kind {
            if let Some(i) = hash_of.iter().position(|h| h == list)
                && placed.get(i) == Some(&false)
            {
                if let Some(p) = placed.get_mut(i) {
                    *p = true;
                }
                with = Some(i);
            }
            let h = root.hash();
            if let Some(cp) = records.iter().find(|x| x.id() == *first).map(|x| x.body().seq) {
                let mut firsts: Vec<&'a Record> = records
                    .iter()
                    .copied()
                    .filter(|x| x.body().signer == h && x.body().seq <= cp && !taken.contains(&x.id()))
                    .collect();
                firsts.sort_by_key(|x| x.body().seq);
                taken.extend(firsts.iter().map(|x| x.id()));
                group.extend(firsts);
            }
        }
        taken.insert(r.id());
        groups.push((group, with));
    }
    let mut parts: Vec<Part<'a>> = Vec::new();
    let mut cur = Part::default();
    let mut used = 0usize;
    for (group, with) in groups {
        let list = with.and_then(|i| lists.get(i).copied());
        let item = group
            .iter()
            .fold(0usize, |n, r| n.saturating_add(size(r)))
            .saturating_add(list.map_or(0, |l| l.len().saturating_add(ITEM_HEAD)));
        let count = cur.records.len().saturating_add(group.len());
        if !cur.records.is_empty() && (count > max_records || used.saturating_add(item) > max_bytes) {
            parts.push(core::mem::take(&mut cur));
            used = 0;
        }
        cur.records.extend(group);
        cur.lists.extend(list);
        used = used.saturating_add(item);
    }
    for l in lists.iter().zip(&placed).filter(|(_, p)| !**p).map(|(l, _)| l) {
        let item = l.len().saturating_add(ITEM_HEAD);
        if !(cur.records.is_empty() && cur.lists.is_empty()) && used.saturating_add(item) > max_bytes {
            parts.push(core::mem::take(&mut cur));
            used = 0;
        }
        cur.lists.push(l);
        used = used.saturating_add(item);
    }
    if !(cur.records.is_empty() && cur.lists.is_empty()) {
        parts.push(cur);
    }
    parts
}

/// Splits sorted IDs into `have` messages of at most [`HAVE_IDS`] each;
/// 4096 IDs are 4096 · 34 bytes, far inside a frame.
pub fn have_parts<'a>(ids: impl IntoIterator<Item = &'a RecordId>) -> Vec<Vec<RecordId>> {
    let ids: Vec<RecordId> = ids.into_iter().copied().collect();
    ids.chunks(HAVE_IDS).map(<[RecordId]>::to_vec).collect()
}

impl RecordSet {
    /// What `for_peer` and `lists_for_peer` give peer, as parts that each
    /// fit one message.
    pub fn parts_for_peer<'a>(&'a self, state: &State, peer: &KeyHash) -> Vec<Part<'a>> {
        let records = self.for_peer(state, peer);
        let lists = self.lists_for_peer(state, peer);
        split(&records, &lists, PART_RECORDS, PART_BYTES)
    }

    /// The IDs the set holds, as `have` messages.
    pub fn have(&self) -> Vec<Vec<RecordId>> {
        have_parts(self.ids())
    }

    /// Takes one part of a peer's sync: its records, its lists, its
    /// records again, so that the records a change of root's list keeps
    /// are taken once the list is. It returns how many records were new.
    pub fn take_part(&mut self, records: &[Record], lists: &[&[u8]]) -> usize {
        let before = self.len();
        self.insert_all(records.iter().cloned());
        for l in lists {
            let _ = self.insert_list(l);
        }
        self.insert_all(records.iter().cloned());
        self.len().saturating_sub(before)
    }
}
