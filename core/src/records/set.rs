// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The record set a member keeps: records by ID, each checked before it is
//! stored, within the format's ceilings, the same whatever order they came
//! in (rules 1 and 6).

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;

use super::body::Head;
use super::eval::{self, Checked, ClaimState, Counted, Cut, Keys, Role, State, Why};
use super::key::{Key, KeyHash, RecordId};
use super::{Kind, Mark, Record, Rule, keep};

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

#[derive(Clone)]
struct Entry {
    record: Record,
    role: Role,
    held: bool,
}

/// A member's record set.
#[derive(Clone)]
pub struct RecordSet {
    root: Key,
    keys: Keys,
    /// Each signer's units, to know when one is past its ceiling.
    units: BTreeMap<KeyHash, u64>,
    /// What the set remembers of the records it dropped.
    cut: keep::Cut,
    /// The roots after the first that the member's evaluation put on the
    /// path (`compact`): they have a root's room.
    promoted: BTreeSet<KeyHash>,
    /// The claims the member has counted, in order, with what its path
    /// needs of each: final here (`Input::counted`).
    counted: Vec<Counted>,
    /// Counted claims the caller named whose records the set does not hold
    /// yet; read in order as they come.
    pending: Vec<RecordId>,
    /// The takeovers' cuts of the roots before the promoted ones (`compact`):
    /// such a root keeps only the records its counted claim lists.
    cuts: BTreeMap<KeyHash, Cut>,
    /// The checkpoints that counted when the set last compacted: what
    /// they prune is not taken again.
    checkpoints: Vec<(Vec<Head>, BTreeSet<RecordId>)>,
    records: BTreeMap<RecordId, Entry>,
    bytes: usize,
}

impl RecordSet {
    /// An empty set for the group whose first root key is root.
    pub fn new(root: Key) -> RecordSet {
        let keys = Keys::new(&root);
        RecordSet {
            root,
            keys,
            units: BTreeMap::new(),
            cut: keep::Cut::default(),
            promoted: BTreeSet::new(),
            counted: Vec::new(),
            pending: Vec::new(),
            cuts: BTreeMap::new(),
            checkpoints: Vec::new(),
            records: BTreeMap::new(),
            bytes: 0,
        }
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
        let id = r.id();
        let added = self.insert_only(r, None);
        if matches!(added, Ok(Added::Stored)) && !self.pending.is_empty() {
            // A claim the records do not prove yet waits for more.
            let _ = self.read_pending(false);
            if !self.records.contains_key(&id) {
                return Ok(Added::NoRoom);
            }
        }
        added
    }

    /// insert without reading the waiting counted claims, which insert_all
    /// reads once a round.
    fn insert_only(&mut self, r: Record, mark: Option<(&[u8; 32], &Mark)>) -> Result<Added, Refused> {
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
        let key = key.clone();
        let signer = r.body().signer;
        // What the set would not keep is turned away before its signature
        // is verified: a record offered again after the set dropped it
        // costs no verification, and none of these steps stores it.
        if self.checkpoints.iter().any(|(heads, anchors)| eval::pruned_by(&r, role, heads, anchors)) {
            // A counting checkpoint left it out.
            return Ok(Added::NoRoom);
        }
        match self.cuts.get(&signer) {
            // A root a takeover followed: only what the claim lists stays,
            // outside the rooms.
            Some(cut) if !cut.keeps(&id) => return Ok(Added::NoRoom),
            Some(_) => {}
            None => {
                if self.ceiling(&signer).is_some() {
                    // It depends on the key alone: one with room of its
                    // own has no place where it stopped without.
                    self.cut.forget_future(&signer);
                }
                if self.cut.past(&eval::item(&r, role)) {
                    // Its key dropped a record before it: it would not be
                    // kept.
                    return Ok(Added::NoRoom);
                }
            }
        }
        let held = r.verify_marked(&key, mark).map_err(Refused::Broken)?;
        self.keys.learn(r.body(), role, held);
        let units = self.units.entry(signer).or_default();
        *units = units.saturating_add(eval::item(&r, role).units);
        self.bytes = self.bytes.saturating_add(r.size());
        self.records.insert(id, Entry { record: r, role, held });
        if self.needs_cut(&signer) {
            self.cut();
        }
        Ok(if self.records.contains_key(&id) { Added::Stored } else { Added::NoRoom })
    }

    /// Inserts records in any order: those whose signer the set learns
    /// from another of them are tried again until none is left that can be
    /// taken. It returns how many were stored and the refusals.
    pub fn insert_all(&mut self, records: impl IntoIterator<Item = Record>) -> (usize, Vec<(RecordId, Refused)>) {
        self.insert_all_marked(records.into_iter().map(|r| (r, None)), None)
    }

    /// insert_all for the records of the device's own store, each with the
    /// mark it was saved with (`marked`): a record whose mark holds under
    /// local is taken without verifying its signature; one with a missing
    /// or wrong mark is verified as if new. Records from peers always go
    /// through insert or insert_all.
    pub fn load_marked(
        &mut self,
        local: &[u8; 32],
        records: impl IntoIterator<Item = (Record, Option<Mark>)>,
    ) -> (usize, Vec<(RecordId, Refused)>) {
        self.insert_all_marked(records, Some(local))
    }

    /// The records to save in the device's own store, in dependency order,
    /// each with its mark under local; saving them again marks the ones
    /// load_marked verified by their signature.
    pub fn marked(&self, local: &[u8; 32]) -> Vec<(&Record, Mark)> {
        self.in_dependency_order().into_iter().map(|r| (r, r.mark(local))).collect()
    }

    fn insert_all_marked(
        &mut self,
        records: impl IntoIterator<Item = (Record, Option<Mark>)>,
        local: Option<&[u8; 32]>,
    ) -> (usize, Vec<(RecordId, Refused)>) {
        let mut stored = 0usize;
        let mut refused = Vec::new();
        // Only the records that wait for their signer are held aside; the
        // others go straight in.
        let mut waiting = Vec::new();
        let mut progress = self.insert_each(records, local, &mut waiting, &mut stored, &mut refused);
        while progress && !waiting.is_empty() {
            let todo = core::mem::take(&mut waiting);
            progress = self.insert_each(todo, local, &mut waiting, &mut stored, &mut refused);
        }
        refused.extend(waiting.iter().map(|(r, _)| (r.id(), Refused::UnknownSigner)));
        (stored, refused)
    }

    /// One round of insert_all: whether it stored any.
    fn insert_each(
        &mut self,
        records: impl IntoIterator<Item = (Record, Option<Mark>)>,
        local: Option<&[u8; 32]>,
        waiting: &mut Vec<(Record, Option<Mark>)>,
        stored: &mut usize,
        refused: &mut Vec<(RecordId, Refused)>,
    ) -> bool {
        let mut progress = false;
        for (r, mark) in records {
            if r.body().group == self.root.device_id() && self.keys.signer(&r.body().signer).is_none() {
                waiting.push((r, mark));
                continue;
            }
            let id = r.id();
            let with = local.zip(mark.as_ref());
            match self.insert_only(r, with) {
                Ok(Added::Stored) => {
                    *stored = stored.saturating_add(1);
                    progress = true;
                }
                Ok(_) => {}
                Err(e) => refused.push((id, e)),
            }
        }
        if progress && !self.pending.is_empty() {
            // The waiting counted claims are read once a round, not once a
            // record; one read may teach a root's key the next round needs.
            let _ = self.read_pending(false);
        }
        progress
    }

    /// Drops the records the set does not keep (`keep`): each key within
    /// its ceiling, the set's ceilings shared fairly between keys. What is
    /// kept depends on the records alone, and dropping what is not kept
    /// changes nothing, so the set is the same whatever order the records
    /// came in.
    fn cut(&mut self) {
        let off = eval::off_cuts(&self.cuts, self.records.values().map(|e| &e.record));
        for id in &off {
            self.remove(id);
        }
        // What a counted claim lists of the root it followed is kept
        // outside the rooms.
        let items: Vec<keep::Item> = self
            .records
            .values()
            .filter(|e| !self.cuts.contains_key(&e.record.body().signer))
            .map(|e| eval::item(&e.record, self.role_of(e)))
            .collect();
        let ceilings: BTreeMap<KeyHash, Option<u64>> =
            items.iter().map(|it| (it.signer, self.ceiling(&it.signer))).collect();
        let (kept, cut) = keep::keep_after(&items, |k| ceilings.get(k).copied().flatten(), &self.cut);
        self.cut = cut;
        let drop: Vec<RecordId> = self
            .records
            .iter()
            .filter(|(id, e)| !kept.contains(*id) && !self.cuts.contains_key(&e.record.body().signer))
            .map(|(id, _)| *id)
            .collect();
        for id in drop {
            self.remove(&id);
        }
        // A dropped claim takes its root's key with it.
        let named: BTreeSet<KeyHash> = self
            .records
            .values()
            .filter(|e| e.role == Role::Admin && !e.held)
            .filter_map(|e| match &e.record.body().kind {
                Kind::Claim { root, .. } => Some(root.hash()),
                _ => None,
            })
            .collect();
        let (promoted, first) = (&self.promoted, self.root.hash());
        let counted: BTreeSet<KeyHash> = self.counted.iter().map(|c| c.root.hash()).collect();
        self.keys.retain_roots(|h| *h == first || named.contains(h) || promoted.contains(h) || counted.contains(h));
        // And the records that root's key signed.
        let gone: Vec<RecordId> = self
            .records
            .values()
            .filter(|e| self.keys.signer(&e.record.body().signer).is_none())
            .map(|e| e.record.id())
            .collect();
        for id in &gone {
            self.remove(id);
        }
    }

    /// Learns the keys again from the stored records for the roots the
    /// member promoted, and drops the records whose signer it no longer
    /// knows.
    fn relearn(&mut self) {
        let mut keys = Keys::trusting(&self.root, &self.promoted);
        for c in &self.counted {
            keys.add_root(&c.root);
        }
        loop {
            let mut learned = false;
            for e in self.records.values() {
                if let Some((_, role)) = keys.signer(&e.record.body().signer) {
                    learned |= keys.learn(e.record.body(), role, e.held);
                }
            }
            if !learned {
                break;
            }
        }
        let unknown: Vec<RecordId> = self
            .records
            .values()
            .filter(|e| keys.signer(&e.record.body().signer).is_none())
            .map(|e| e.record.id())
            .collect();
        self.keys = keys;
        for id in &unknown {
            self.remove(id);
        }
    }

    /// Reports whether a record of signer just stored may change what the
    /// set keeps. Before the set dropped anything, only a key past its
    /// ceiling or a set past its room does. After, the units it dropped
    /// still count in the shares, so the level can bind while the stored
    /// units fit: the record is kept as it is only when its key dropped
    /// nothing, stays within the level, and the shares, dropped units
    /// included, still fit.
    fn needs_cut(&self, signer: &KeyHash) -> bool {
        let units = |k: &KeyHash| self.units.get(k).copied().unwrap_or(0);
        if self.cut.is_empty() {
            let total: u64 = self.units.values().sum();
            return units(signer) > self.ceiling(signer).unwrap_or(keep::FUTURE) || total > keep::ROOM;
        }
        let Some(ceiling) = self.ceiling(signer) else { return true };
        let level = self.cut.level();
        if self.cut.dropped(signer).is_some() || units(signer) > level.min(ceiling) {
            return true;
        }
        let mut demand = 0u64;
        for (k, u) in &self.units {
            if let Some(c) = self.ceiling(k) {
                let total = u.saturating_add(self.cut.dropped(k).unwrap_or(0));
                demand = demand.saturating_add(total.min(c).min(level));
            }
        }
        for (k, u) in self.cut.dropped_all() {
            if !self.units.contains_key(k)
                && let Some(c) = self.ceiling(k)
            {
                demand = demand.saturating_add(u.min(c).min(level));
            }
        }
        demand > keep::ROOM
    }

    /// A key's ceiling: a root's on the path, an admin key's, or None for a
    /// root only claims name.
    fn ceiling(&self, k: &KeyHash) -> Option<u64> {
        let admins: BTreeSet<KeyHash> = if self.keys.is_admin(k) { BTreeSet::from([*k]) } else { BTreeSet::new() };
        eval::ceiling_of(&self.root.hash(), &self.promoted, &admins, k)
    }

    fn remove(&mut self, id: &RecordId) {
        if let Some(e) = self.records.remove(id) {
            self.bytes = self.bytes.saturating_sub(e.record.size());
            if let Some(u) = self.units.get_mut(&e.record.body().signer) {
                *u = u.saturating_sub(eval::item(&e.record, e.role).units);
            }
        }
    }

    /// A record's role, read from the final table: a key learned late may
    /// make an admin of a key first taken for a claim's root.
    fn role_of(&self, e: &Entry) -> Role {
        self.keys.signer(&e.record.body().signer).map_or(e.role, |(_, role)| role)
    }

    fn checked(&self) -> Vec<Checked<'_>> {
        self.records.values().map(|e| Checked { r: &e.record, role: self.role_of(e), held: e.held }).collect()
    }

    /// The group's state. held_ms is how long the device has held each
    /// claim (rule 7).
    pub fn state(&self, held_ms: &BTreeMap<RecordId, u64>) -> State {
        let by = eval::Compacted { promoted: &self.promoted, cuts: &self.cuts, proven: &self.checkpoints };
        eval::evaluate_checked(&self.root, self.checked(), BTreeMap::new(), held_ms, &self.counted, &by)
    }

    /// The claims the member has counted, which its caller keeps across
    /// restarts and hands a joiner with the claims' ages.
    pub fn counted(&self) -> Vec<RecordId> {
        self.counted.iter().map(|c| c.claim).chain(self.pending.iter().copied()).collect()
    }

    /// The counted claims with what their path needs, which the caller
    /// keeps across restarts.
    pub fn counted_claims(&self) -> &[Counted] {
        &self.counted
    }

    /// The records a counted claim lists of the root it followed that
    /// the set does not hold: a member fetches them from its peers as it
    /// fetches any record it lacks.
    pub fn missing(&self) -> Vec<RecordId> {
        self.cuts.values().flat_map(|c| c.keep.iter()).filter(|id| !self.records.contains_key(*id)).copied().collect()
    }

    /// Takes claims as counted, in the order they were counted: those the
    /// caller kept from before a restart, or those its admitter counted.
    /// Each is read from its record, under the root the one before it
    /// named; those whose records the set does not hold yet wait. A
    /// counted claim stays counted, in its place.
    ///
    /// Each is checked once, when its record is read: the records must
    /// prove that its claimant held the takeover power under that root as
    /// of its own seen and was not removed, and the claim must list what
    /// the counted claim keeps. One they do not prove is
    /// refused with those after it, and its ID comes back.
    pub fn remember_counted(&mut self, ids: impl IntoIterator<Item = RecordId>) -> Result<(), RecordId> {
        for id in ids {
            if !self.counted.iter().any(|c| c.claim == id) && !self.pending.contains(&id) {
                self.pending.push(id);
            }
        }
        self.read_pending(true)
    }

    /// Takes counted claims with what their path needs, as the caller kept
    /// them. Nothing is checked: it is for the device's own store only,
    /// what this set's `counted_claims` gave before a restart. Claims from
    /// anyone else, an admitter's among them, go through
    /// `remember_counted`.
    pub fn remember_counted_claims(&mut self, claims: impl IntoIterator<Item = Counted>) {
        for c in claims {
            if !self.counted.iter().any(|x| x.claim == c.claim) {
                self.keys.add_root(&c.root);
                self.counted.push(c);
            }
        }
        self.keep_by(self.promoted.clone(), self.cuts.clone());
    }

    /// Reads the waiting counted claims whose records are here, in order.
    /// Keeps by the roots promoted and the cuts, with those of the counted
    /// claims always among them: a counted takeover's root has a root's
    /// room and its old root keeps only its chain, whatever path a state
    /// showed.
    fn keep_by(&mut self, mut promoted: BTreeSet<KeyHash>, mut cuts: BTreeMap<KeyHash, Cut>) {
        for c in &self.counted {
            promoted.insert(c.root.hash());
            cuts.insert(c.cut.key, c.cut.clone());
        }
        if promoted != self.promoted || cuts != self.cuts {
            self.promoted = promoted;
            self.cuts = cuts;
            self.relearn();
            self.cut = keep::Cut::default();
            self.cut();
        }
    }

    /// strict: a claim the records do not prove is refused, with the ones
    /// after it; otherwise it waits for more records.
    fn read_pending(&mut self, strict: bool) -> Result<(), RecordId> {
        let group = self.root.hash();
        let more = eval::Counted::chain(&self.counted.last().map_or(group, |c| c.root.hash()), &self.pending, |id| {
            self.records.get(id).map(|e| &e.record)
        });
        if more.is_empty() {
            return Ok(());
        }
        // The set verified each record when it took it.
        let records: Vec<&Record> = self.records.values().map(|e| &e.record).collect();
        let mut sigs = eval::Sigs::verified(self.records.values().map(|e| e.held));
        for c in more {
            if !eval::proven(&self.root, &records, &mut sigs, &self.counted, &c) {
                if strict {
                    self.pending.clear();
                }
                return Err(c.claim);
            }
            self.pending.remove(0);
            self.keys.add_root(&c.root);
            self.counted.push(c);
        }
        self.keep_by(self.promoted.clone(), self.cuts.clone());
        Ok(())
    }

    /// Drops what the counting checkpoints of state leave out: a root's
    /// checkpoint resets the set's count.
    ///
    /// It also gives the roots state put on the path after the first a
    /// root's room (and takes it from those it no longer puts there): the
    /// set's count starts again, and what it dropped before comes again
    /// in sync. A member where the takeover does not count yet keeps only
    /// 16 units of the new root's records until it does.
    pub fn compact(&mut self, state: &State) -> usize {
        // The claims that took effect, in the order of the path; a list
        // that already holds an earlier path's keeps it.
        let mut along: Vec<Counted> = Vec::new();
        for (under, next) in state.roots.iter().zip(state.roots.iter().skip(1)) {
            let found =
                state.claims.iter().find(|c| c.state == ClaimState::Effective && c.root == *next).and_then(|c| {
                    match self.counted.get(along.len()) {
                        Some(old) if old.claim == c.record => Some(old.clone()),
                        _ => self.records.get(&c.record).and_then(|e| Counted::of(&e.record, under)),
                    }
                });
            match found {
                Some(c) => along.push(c),
                None => break,
            }
        }
        if self.pending.is_empty() && along.len() > self.counted.len() && along.starts_with(&self.counted) {
            self.counted = along;
        }
        let promoted: BTreeSet<KeyHash> = state.roots.iter().skip(1).copied().collect();
        let cuts: BTreeMap<KeyHash, Cut> = state.cuts.iter().map(|c| (c.key, c.clone())).collect();
        self.keep_by(promoted, cuts);
        self.checkpoints = state
            .checkpoints
            .iter()
            .filter_map(|cp| match self.get(cp).map(|r| &r.body().kind) {
                Some(Kind::Checkpoint { heads, keep }) => Some((heads.clone(), eval::anchors_of(heads, keep))),
                _ => None,
            })
            .collect();
        let drop: Vec<RecordId> = self
            .records
            .values()
            .filter(|e| {
                self.checkpoints
                    .iter()
                    .any(|(heads, anchors)| eval::pruned_by(&e.record, self.role_of(e), heads, anchors))
            })
            .map(|e| e.record.id())
            .collect();
        for id in &drop {
            self.remove(id);
        }
        // The checkpoint starts the count again; a key whose naming record
        // it left out is not known any more, nor kept.
        if !drop.is_empty() {
            self.cut = keep::Cut::default();
            self.relearn();
        }
        drop.len()
    }

    /// The records in the order a sender sends them: each after the
    /// records that name its signer's key, so that a receiver that takes
    /// them one by one knows every signer (section 4.9).
    pub fn in_dependency_order(&self) -> Vec<&Record> {
        let mut keys = Keys::trusting(&self.root, &self.promoted);
        let mut out = Vec::with_capacity(self.records.len());
        let mut left: Vec<&Entry> = self.records.values().collect();
        left.sort_by_key(|e| eval::order_key(e.record.body(), &e.record.id()));
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
