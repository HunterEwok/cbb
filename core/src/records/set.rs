// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The record set a member keeps: records by ID, each checked before it is
//! stored, within the format's ceilings, the same whatever order they came
//! in (rules 1 and 6).

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;

use super::body::Seen;
use super::eval::{self, Checked, ClaimState, Counted, Keys, Role, State, Why};
use super::key::{Key, KeyHash, RecordId};
use super::{Kind, Record, Rule, keep};

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
    /// such a root keeps nothing off its cut.
    cuts: BTreeMap<KeyHash, Seen>,
    /// A record off a cut came after the cuts were known: its root still
    /// signs, and this member and that root disagree about the owner.
    split: bool,
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
            split: false,
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
        let signer = r.body().signer;
        if let Some(cut) = self.cuts.get(&signer) {
            let cuts = BTreeMap::from([(signer, *cut)]);
            let mine = self.records.values().map(|e| &e.record).filter(|x| x.body().signer == signer);
            if eval::off_cuts(&cuts, mine.chain([&r])).contains(&id) {
                // Its root signed it off the chain the takeover saw; one
                // that would have cancelled a counted claim tells the
                // member that it and that root disagree about the owner.
                self.split |= self.cancels_counted(&r);
                return Ok(Added::NoRoom);
            }
        }
        if self.ceiling(&signer).is_some() {
            self.cut.forget_future(&signer);
        }
        if self.cut.past(&eval::item_cut(&r, role, &self.cuts)) {
            // Its key dropped a record before it: it would not be kept.
            return Ok(Added::NoRoom);
        }
        self.keys.learn(r.body(), role, held);
        let units = self.units.entry(signer).or_default();
        *units = units.saturating_add(eval::item(&r, role).units);
        self.bytes = self.bytes.saturating_add(r.size());
        self.records.insert(id, Entry { record: r, role, held });
        if self.needs_cut(&signer) {
            self.cut();
        }
        if !self.pending.is_empty() {
            self.read_pending();
        }
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
        let items: Vec<keep::Item> =
            self.records.values().map(|e| eval::item_cut(&e.record, self.role_of(e), &self.cuts)).collect();
        let ceilings: BTreeMap<KeyHash, Option<u64>> =
            items.iter().map(|it| (it.signer, self.ceiling(&it.signer))).collect();
        let (kept, cut) = keep::keep_after(&items, |k| ceilings.get(k).copied().flatten(), &self.cut);
        self.cut = cut;
        let drop: Vec<RecordId> = self.records.keys().filter(|id| !kept.contains(*id)).copied().collect();
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
        self.keys
            .retain_roots(|h| *h == first || named.contains(h) || promoted.contains(h) || counted.contains(h));
    }

    /// Reports whether r would cancel a claim the member counted: a
    /// resolve that names it, or a revoke of its signer.
    fn cancels_counted(&self, r: &Record) -> bool {
        match &r.body().kind {
            Kind::Resolve(ids) => ids.iter().any(|id| self.counted.iter().any(|c| c.claim == *id)),
            Kind::Revoke(rm) => self.counted.iter().any(|c| rm.keys.binary_search(&c.claimant).is_ok()),
            _ => false,
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
        let mut state = eval::evaluate_checked(
            &self.root,
            self.checked(),
            BTreeMap::new(),
            held_ms,
            &self.counted,
            &self.promoted,
            &self.cuts,
        );
        state.owner_split |= self.split;
        state
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

    /// Takes claims as counted, in the order they were counted: those the
    /// caller kept from before a restart, or those its admitter counted.
    /// Each is read from its record, under the root the one before it
    /// named; those whose records the set does not hold yet wait. A
    /// counted claim stays counted, in its place.
    pub fn remember_counted(&mut self, ids: impl IntoIterator<Item = RecordId>) {
        for id in ids {
            if !self.counted.iter().any(|c| c.claim == id) && !self.pending.contains(&id) {
                self.pending.push(id);
            }
        }
        self.read_pending();
    }

    /// Takes counted claims with what their path needs, as the caller kept
    /// them.
    pub fn remember_counted_claims(&mut self, claims: impl IntoIterator<Item = Counted>) {
        for c in claims {
            if !self.counted.iter().any(|x| x.claim == c.claim) {
                self.keys.add_root(&c.root);
                self.counted.push(c);
            }
        }
    }

    /// Reads the waiting counted claims whose records are here, in order.
    fn read_pending(&mut self) {
        let group = self.root.hash();
        let more = eval::Counted::chain(
            &self.counted.last().map_or(group, |c| c.root.hash()),
            &self.pending,
            |id| self.records.get(id).map(|e| &e.record),
        );
        if more.is_empty() {
            return;
        }
        self.pending.drain(..more.len());
        for c in &more {
            self.keys.add_root(&c.root);
        }
        self.counted.extend(more);
    }

    /// Drops what the counting checkpoint of state leaves out: a root's
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
            let found = state
                .claims
                .iter()
                .find(|c| c.state == ClaimState::Effective && c.root == *next)
                .and_then(|c| match self.counted.get(along.len()) {
                    Some(old) if old.claim == c.record => Some(old.clone()),
                    _ => self.records.get(&c.record).and_then(|e| Counted::of(&e.record, under)),
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
        let cuts: BTreeMap<KeyHash, Seen> = state.cuts.iter().map(|c| (c.key, *c)).collect();
        if promoted != self.promoted || cuts != self.cuts {
            self.promoted = promoted;
            self.cuts = cuts;
            self.relearn();
            self.cut = keep::Cut::default();
            self.cut();
        }
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
