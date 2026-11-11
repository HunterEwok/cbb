// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The record set a member keeps: records by ID, each checked before it is
//! stored, within the format's ceilings, the same whatever order they came
//! in (rules 1 and 6).

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;

use super::eval::{self, Checked, Keys, Role, State, Why};
use super::key::{Key, KeyHash, RecordId};
use super::{Kind, Record, Rule};

/// What inserting a record did.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Added {
    /// It is new and kept.
    Stored,
    /// The set holds it already (by ID).
    Known,
    /// It verified, but the set's ceilings leave no room for it: it is not
    /// kept.
    NoRoom,
}

/// Why a record was not taken.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Refused {
    /// It is of another group.
    Group,
    /// Its signer is no key the set knows yet; a sender sends records in
    /// the order of their dependencies, so it may come again later.
    UnknownSigner,
    /// It breaks a rule of the format.
    Broken(Rule),
}

struct Entry {
    record: Record,
    role: Role,
    held: bool,
}

/// A member's record set.
pub struct RecordSet {
    root: Key,
    group_root: KeyHash,
    keys: Keys,
    records: BTreeMap<RecordId, Entry>,
    bytes: usize,
}

impl RecordSet {
    /// An empty set for the group whose first root key is root.
    pub fn new(root: Key) -> RecordSet {
        let group_root = root.hash();
        let keys = Keys::new(&root);
        RecordSet { root, group_root, keys, records: BTreeMap::new(), bytes: 0 }
    }

    pub fn root(&self) -> &Key {
        &self.root
    }

    pub fn len(&self) -> usize {
        self.records.len()
    }

    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// The bytes the set's records take.
    pub fn bytes(&self) -> usize {
        self.bytes
    }

    pub fn contains(&self, id: &RecordId) -> bool {
        self.records.contains_key(id)
    }

    pub fn get(&self, id: &RecordId) -> Option<&Record> {
        self.records.get(id).map(|e| &e.record)
    }

    /// The IDs, sorted.
    pub fn ids(&self) -> impl Iterator<Item = &RecordId> {
        self.records.keys()
    }

    /// The set digest two members compare.
    pub fn digest(&self) -> [u8; 32] {
        super::digest(self.records.keys())
    }

    /// Checks a record and stores it: its group, its signer among the keys
    /// the set knows, its fields and its signature, all before it takes a
    /// place; then the set is cut back to its ceilings.
    pub fn insert(&mut self, r: Record) -> Result<Added, Refused> {
        if r.body().group != self.root.device_id() {
            return Err(Refused::Group);
        }
        let id = r.id();
        if self.records.contains_key(&id) {
            // One record, one place: another envelope of the same body (a
            // second signature by the key holder) changes nothing.
            return Ok(Added::Known);
        }
        let Some((key, role)) = self.keys.signer(&r.body().signer) else { return Err(Refused::UnknownSigner) };
        let held = r.verify(key).map_err(Refused::Broken)?;
        self.keys.learn(r.body(), role, held);
        self.bytes = self.bytes.saturating_add(r.size());
        self.records.insert(id, Entry { record: r, role, held });
        self.cut();
        Ok(if self.records.contains_key(&id) { Added::Stored } else { Added::NoRoom })
    }

    /// Inserts records in any order: those whose signer the set learns
    /// from another of them are tried again until none is left that can be
    /// taken. It returns how many were stored and the refusals.
    pub fn insert_all(&mut self, records: impl IntoIterator<Item = Record>) -> (usize, Vec<(RecordId, Refused)>) {
        let mut todo: Vec<Record> = records.into_iter().collect();
        let mut stored = 0usize;
        let mut refused = Vec::new();
        loop {
            let mut waiting = Vec::new();
            let mut progress = false;
            for r in todo {
                if r.body().group == self.root.device_id() && self.keys.signer(&r.body().signer).is_none() {
                    waiting.push(r);
                    continue;
                }
                let id = r.id();
                match self.insert(r) {
                    Ok(Added::Stored) => {
                        stored = stored.saturating_add(1);
                        progress = true;
                    }
                    Ok(_) => {}
                    Err(e) => refused.push((id, e)),
                }
            }
            if !progress || waiting.is_empty() {
                refused.extend(waiting.iter().map(|r| (r.id(), Refused::UnknownSigner)));
                return (stored, refused);
            }
            todo = waiting;
        }
    }

    /// Drops the records past the set's ceilings: the set keeps the first
    /// records in an order that depends on each record alone (the group's
    /// first root's first, then by seq), so what it keeps is the same
    /// whatever order the records came in.
    fn cut(&mut self) {
        if self.records.len() <= super::MAX_RECORDS && self.bytes <= super::MAX_SET_BYTES {
            return;
        }
        let mut order: Vec<(_, RecordId)> =
            self.records.iter().map(|(id, e)| (eval::order_key(&self.group_root, e.record.body(), id), *id)).collect();
        order.sort();
        let keep = eval::fits(order.iter().filter_map(|(_, id)| self.records.get(id).map(|e| &e.record)));
        for (_, id) in order.get(keep..).unwrap_or_default() {
            if let Some(e) = self.records.remove(id) {
                self.bytes = self.bytes.saturating_sub(e.record.size());
            }
        }
    }

    fn checked(&self) -> Vec<Checked<'_>> {
        // Roles are read from the final table: a key learned late may make
        // an admin of a key first taken for a claim's root.
        self.records
            .values()
            .map(|e| Checked {
                r: &e.record,
                role: self.keys.signer(&e.record.body().signer).map_or(e.role, |(_, role)| role),
                held: e.held,
            })
            .collect()
    }

    /// The group's state. held_ms is how long the device has held each
    /// claim (rule 7).
    pub fn state(&self, held_ms: &BTreeMap<RecordId, u64>) -> State {
        eval::evaluate_checked(&self.root, self.checked(), BTreeMap::new(), held_ms)
    }

    /// Drops what the counting checkpoint of state leaves out: a root's
    /// checkpoint resets the set's count.
    pub fn compact(&mut self, state: &State) -> usize {
        let Some(cp) = state.checkpoint else { return 0 };
        let Some(Kind::Checkpoint { heads, keep }) = self.get(&cp).map(|r| r.body().kind.clone()) else { return 0 };
        let anchors = eval::anchors_of(&heads, &keep);
        let drop: Vec<RecordId> = self
            .records
            .values()
            .filter(|e| eval::pruned_by(&e.record, &heads, &anchors))
            .map(|e| e.record.id())
            .collect();
        for id in &drop {
            if let Some(e) = self.records.remove(id) {
                self.bytes = self.bytes.saturating_sub(e.record.size());
            }
        }
        drop.len()
    }

    /// The records in the order a sender sends them: each after the
    /// records that name its signer's key, so that a receiver that takes
    /// them one by one knows every signer (section 4.9).
    pub fn in_dependency_order(&self) -> Vec<&Record> {
        let mut keys = Keys::new(&self.root);
        let mut out = Vec::with_capacity(self.records.len());
        let mut left: Vec<&Entry> = self.records.values().collect();
        left.sort_by_key(|e| eval::order_key(&self.group_root, e.record.body(), &e.record.id()));
        loop {
            let mut rest = Vec::new();
            let mut learned = false;
            for e in left {
                match keys.signer(&e.record.body().signer) {
                    Some((_, role)) => {
                        learned |= keys.learn(e.record.body(), role, e.held);
                        out.push(&e.record);
                    }
                    None => rest.push(e),
                }
            }
            if rest.is_empty() || !learned {
                out.extend(rest.into_iter().map(|e| &e.record));
                return out;
            }
            left = rest;
        }
    }

    /// What a peer gets in sync (design-records-v3 section 3): a device of
    /// the group all of it; a removed device only the counting removals
    /// that name it; any other key nothing.
    pub fn for_peer<'a>(&'a self, state: &State, peer: &KeyHash) -> Vec<&'a Record> {
        if state.revoked.contains(peer) {
            let mut out: Vec<&Record> = self
                .records
                .values()
                .filter(|e| {
                    state.counting.contains(&e.record.id())
                        && matches!(&e.record.body().kind, Kind::Revoke(rm) if rm.keys.binary_search(peer).is_ok())
                })
                .map(|e| &e.record)
                .collect();
            out.sort_by_key(|r| r.id());
            return out;
        }
        if state.device_by_key(peer).is_some() {
            return self.in_dependency_order();
        }
        Vec::new()
    }

    /// The IDs a state's evaluation left out for each reason, for a
    /// member's log.
    pub fn ignored(state: &State) -> BTreeMap<Why, BTreeSet<RecordId>> {
        let mut out: BTreeMap<Why, BTreeSet<RecordId>> = BTreeMap::new();
        for i in &state.ignored {
            out.entry(i.why).or_default().insert(i.record);
        }
        out
    }
}
