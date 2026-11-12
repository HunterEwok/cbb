// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The record set a member keeps: records by ID, each checked before it is
//! stored, within the format's ceilings, the same whatever order they came
//! in (rules 1 and 6).

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;

use super::body::{Body, Head, List, Settings};
use super::eval::{self, Checked, Cut, Keys, Role, State, Why};
use super::key::{GroupId, Key, KeyHash, RecordId, group_id};
use super::{Kind, MAX_NOTICES, Mark, Record, Rule, keep};
use crate::identity::ExternalKey;

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
    /// Its signer is a root that a recovery record names while that
    /// record waits for its list: it is kept aside, within that root's
    /// room, and taken when the list comes. Until then it counts for
    /// nothing.
    Waiting,
    /// The group is halted here (`State::halted`): the set takes only the
    /// recovery key's records and what the newest list applied below the
    /// fork names.
    Halted,
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
    recovery: Key,
    group: GroupId,
    keys: Keys,
    /// Each signer's units, to know when one is past its ceiling.
    units: BTreeMap<KeyHash, u64>,
    /// What the set remembers of the records it dropped.
    cut: keep::Cut,
    /// The roots after the first that the recovery chain put on the path:
    /// they have a root's room.
    promoted: BTreeSet<KeyHash>,
    /// The newest recovery record's cut, by each root before the current
    /// one: such a root keeps only the records its list names, narrowed by
    /// the current root's first checkpoint once it counted (`compact`).
    cuts: BTreeMap<KeyHash, Cut>,
    /// The lists the held recovery records name, by hash: their bytes as
    /// they came, and what they read as.
    lists: BTreeMap<[u8; 32], (Vec<u8>, List)>,
    /// The list the next valid recovery record waits for.
    waiting: Option<[u8; 32]>,
    /// The roots the held recovery records name that the path has not
    /// reached (their record waits for its list, or for the record before
    /// it), but for the two sides of a fork, by key hash.
    /// With each its key and the lowest recovery seq that names it.
    early_roots: BTreeMap<KeyHash, (u64, Key)>,
    /// While the group is halted, what the set takes besides the recovery
    /// key's records: the IDs the newest list applied below the fork
    /// names (`State::halted`).
    halted: Option<BTreeSet<RecordId>>,
    /// The first checkpoints kept outside the rooms (`eval::Chain::firsts`):
    /// the newest applied recovery record's and that of the one the chain
    /// waits for; never cut off or pruned while they are.
    firsts: BTreeSet<RecordId>,
    /// The records set aside that the chain now applies, verified when
    /// they came: taken without verifying again.
    trusted: BTreeSet<RecordId>,
    /// The records of those roots, verified, kept aside until the list
    /// comes; all of them within one root's room, the lowest recovery seq
    /// first, then the lowest seq, then the smallest ID. They count for
    /// nothing.
    early: BTreeMap<RecordId, Record>,
    /// The removals of a root before the current one that the newest list
    /// dropped, or that came after it: the app tells "removed before, back
    /// now" and offers their keys to the new root's device. At most
    /// MAX_NOTICES, the oldest going first (`notice_rank`); kept across
    /// restarts by the app (`notice_records`, `keep_notices`).
    notices: BTreeMap<RecordId, Record>,
    /// The notices the device's user dismissed: not shown again, also when
    /// the removal comes again. At most MAX_NOTICES, the smallest IDs going
    /// first.
    dismissed: BTreeSet<RecordId>,
    /// The checkpoints that counted when the set last compacted: what
    /// they prune is not taken again.
    checkpoints: Vec<(Vec<Head>, BTreeSet<RecordId>)>,
    records: BTreeMap<RecordId, Entry>,
    bytes: usize,
    /// How many rounds each missing record was asked for (`missing`).
    asked: BTreeMap<RecordId, u32>,
}

/// The most removals of the roots before the current one a list carries:
/// a share of its 1024 IDs, so that the current root's records always have
/// room.
pub const EARLIER_REMOVALS: usize = 256;

/// Why the writer does not write a change of root while the set holds a
/// recovery record it has not applied.
pub const CHANGE_WAITING: &str = "a change of root is waiting here: sync with the group, then try again";

/// Whether k is a root on the state's path.
fn path_has(state: &State, k: &KeyHash) -> bool {
    state.roots.contains(k)
}

/// The rounds a member asks its peers for a missing record before it gives
/// up on it (`RecordSet::missing`).
pub const MISSING_ROUNDS: u32 = 16;

/// What a change of root writes (rule 33): the recovery record, its list,
/// and the new root's first records, in their order: its device record,
/// the copies of the old root's settings and hubs record (so that nothing
/// of them falls to its default), the owner's removals, and its first
/// checkpoint, which the recovery record names (field 13). They go out
/// together, the recovery record and its list first: a member does not
/// keep a list that comes before its head (it reports `list_missing` and
/// takes the list when it comes again), and applies the head once it
/// holds the list and the first checkpoint.
#[derive(Clone, Debug)]
pub struct Written {
    pub record: Record,
    pub list: List,
    pub first: Vec<Record>,
}

impl RecordSet {
    /// An empty set for the group whose first root key is root and whose
    /// recovery key is recovery: the Group ID commits to both.
    pub fn new(root: Key, recovery: Key) -> RecordSet {
        let keys = Keys::new(&root, &recovery);
        let group = group_id(&root, &recovery);
        RecordSet {
            root,
            recovery,
            group,
            keys,
            units: BTreeMap::new(),
            cut: keep::Cut::default(),
            promoted: BTreeSet::new(),
            cuts: BTreeMap::new(),
            lists: BTreeMap::new(),
            waiting: None,
            early_roots: BTreeMap::new(),
            halted: None,
            firsts: BTreeSet::new(),
            trusted: BTreeSet::new(),
            early: BTreeMap::new(),
            notices: BTreeMap::new(),
            dismissed: BTreeSet::new(),
            checkpoints: Vec::new(),
            records: BTreeMap::new(),
            bytes: 0,
            asked: BTreeMap::new(),
        }
    }

    /// The set a member saved, rebuilt: its records (`in_dependency_order`
    /// or any other order) and its lists (`lists`), taken round by round
    /// until a round takes nothing new, as a record may wait for a list or
    /// for another record. Saving and restoring keeps the digest, the
    /// state and what is kept aside for a root whose change waits.
    pub fn restore(root: Key, recovery: Key, records: &[Record], lists: &[Vec<u8>]) -> RecordSet {
        let mut set = RecordSet::new(root, recovery);
        // Each round that changes something takes at least one record or
        // list for good; the bound only guards against a loop.
        let rounds = records.len().saturating_add(lists.len()).saturating_add(2);
        let mut last = None;
        for _ in 0..rounds {
            for l in lists {
                let _ = set.insert_list(l);
            }
            set.insert_all(records.iter().cloned());
            let now = (set.digest(), set.lists.len(), set.state());
            if last.as_ref() == Some(&now) {
                break;
            }
            last = Some(now);
        }
        set
    }

    /// An empty set for the keys the device's own store pinned, with the
    /// mark it saved beside them (`super::pin_mark`); None when the mark
    /// does not hold, so that a store whose recovery key was changed is
    /// not taken.
    pub fn pinned(root: Key, recovery: Key, local: &[u8; 32], mark: &Mark) -> Option<RecordSet> {
        crate::secret::ct_eq(&super::pin_mark(local, &root, &recovery), mark).then(|| RecordSet::new(root, recovery))
    }

    pub fn root(&self) -> &Key {
        &self.root
    }

    pub fn recovery(&self) -> &Key {
        &self.recovery
    }

    pub fn group(&self) -> GroupId {
        self.group
    }

    /// How many records count in the state, without those kept aside.
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

    /// Whether the set holds the record: among what counts or what is
    /// kept aside for a root whose change waits. A peer asked for it gets
    /// it either way.
    pub fn contains(&self, id: &RecordId) -> bool {
        self.records.contains_key(id) || self.early.contains_key(id)
    }

    /// The record, among what counts or what is kept aside.
    pub fn get(&self, id: &RecordId) -> Option<&Record> {
        self.held(id).or_else(|| self.early.get(id))
    }

    /// The record among what the state counts, not among what is kept
    /// aside.
    fn held(&self, id: &RecordId) -> Option<&Record> {
        self.records.get(id).map(|e| &e.record)
    }

    /// The IDs, sorted: what counts and what is kept aside for a root
    /// whose change waits, as both sync.
    pub fn ids(&self) -> impl Iterator<Item = &RecordId> {
        let mut out: Vec<&RecordId> = self.records.keys().chain(self.early.keys()).collect();
        out.sort();
        out.into_iter()
    }

    /// The IDs kept aside for a root whose change waits, sorted: they
    /// sync with the rest and count for nothing in the state.
    pub fn aside(&self) -> impl Iterator<Item = &RecordId> {
        self.early.keys()
    }

    /// The set digest two members compare: of every ID the set holds,
    /// the records kept aside among them.
    pub fn digest(&self) -> [u8; 32] {
        super::digest(self.records.keys().chain(self.early.keys()))
    }

    /// The lists the set holds, as their bytes, which a sender sends
    /// with the records that name them.
    pub fn lists(&self) -> impl Iterator<Item = &[u8]> {
        self.lists.values().map(|(b, _)| b.as_slice())
    }

    /// The first checkpoints kept outside the rooms (`eval::Chain::firsts`).
    pub(crate) fn firsts(&self) -> &BTreeSet<RecordId> {
        &self.firsts
    }

    /// The bytes of the list of hash, when the set holds it.
    pub fn list(&self, hash: &[u8; 32]) -> Option<&[u8]> {
        self.lists.get(hash).map(|(b, _)| b.as_slice())
    }

    /// The notices to show with state: each dropped removal with the keys
    /// it names that state has not removed again, by record ID. A removal
    /// whose keys are all removed again shows nothing.
    pub fn notices(&self, state: &State) -> Vec<(RecordId, Vec<KeyHash>)> {
        self.notices
            .iter()
            .filter(|(id, _)| !self.dismissed.contains(id))
            .filter_map(|(id, r)| {
                let Kind::Revoke(rm) = &r.body().kind else { return None };
                let keys: Vec<KeyHash> = rm.keys.iter().copied().filter(|k| !state.revoked.contains(k)).collect();
                (!keys.is_empty()).then_some((*id, keys))
            })
            .collect()
    }

    /// The removal records the notices keep, for the app to save.
    pub fn notice_records(&self) -> impl Iterator<Item = &Record> {
        self.notices.values()
    }

    /// The notices dismissed, for the app to save.
    pub fn dismissed(&self) -> impl Iterator<Item = &RecordId> {
        self.dismissed.iter()
    }

    /// Dismisses the notice of the removal id: it is not shown again.
    pub fn dismiss(&mut self, id: &RecordId) {
        self.notices.remove(id);
        self.dismissed.insert(*id);
        while self.dismissed.len() > MAX_NOTICES {
            self.dismissed.pop_first();
        }
    }

    /// Takes back what the app saved (`notice_records`, `dismissed`) after
    /// the set was restored. A record becomes a notice again only if it
    /// still is one: a removal of a root before the current one, its
    /// signature valid, that the newest list does not name.
    pub fn keep_notices(&mut self, records: &[Record], dismissed: &[RecordId]) {
        for id in dismissed {
            self.dismiss(id);
        }
        for r in records {
            let Some((key, Role::Root)) = self.keys.signer(&r.body().signer) else { continue };
            let key = key.clone();
            if self.is_notice(r) && r.verify(&key).is_ok() {
                self.notice(r.clone());
            }
        }
    }

    /// Checks a record and stores it: its group, its signer among the keys
    /// the set knows, its fields and its signature, all before it takes a
    /// place; then the set is cut back to its ceilings.
    pub fn insert(&mut self, r: Record) -> Result<Added, Refused> {
        self.insert_only(r, None)
    }

    fn insert_only(&mut self, r: Record, mark: Option<(&[u8; 32], &Mark)>) -> Result<Added, Refused> {
        if r.body().group != self.group {
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
        if role != Role::Recovery && self.halted.as_ref().is_some_and(|keep| !keep.contains(&id)) {
            return Ok(Added::Halted);
        }
        if self.early_roots.contains_key(&signer) && !self.promoted.contains(&signer) {
            return self.insert_early(r);
        }
        if role == Role::Recovery {
            return self.insert_recovery(r, &key, mark);
        }
        // What the set would not keep is turned away before its signature
        // is verified: a record offered again after the set dropped it
        // costs no verification, and none of these steps stores it.
        // A second record of a key at a seq the set holds one of is the
        // proof of two histories, outside the rooms; a counting checkpoint
        // that covers it settles it, unless both are checkpoints
        // (`eval::proof_stays`).
        let twin = matches!(role, Role::Root | Role::Admin)
            && self.records.values().any(|e| {
                let b = e.record.body();
                b.signer == signer && b.seq == r.body().seq && e.record.id() != id
            });
        let listed = self.cuts.get(&signer).is_some_and(|cut| cut.covers(&signer, r.body().seq) && cut.keeps(&id));
        let twin_checkpoint = twin && matches!(r.body().kind, Kind::Checkpoint { .. });
        // A head's first checkpoint is kept whatever cut or checkpoint.
        let first = self.firsts.contains(&id);
        if !listed
            && !twin_checkpoint
            && !first
            && self.checkpoints.iter().any(|(heads, anchors)| eval::pruned_by(&r, role, heads, anchors))
        {
            // A counting checkpoint left it out.
            return Ok(Added::NoRoom);
        }
        if !first && self.cuts.get(&signer).is_some_and(|cut| !cut.lets(&r)) {
            // A root before the current one: only what the newest list
            // names may stay, within that root's room. Its removal that
            // comes after the change is a notice.
            if role == Role::Root && self.is_notice(&r) && !self.notices.contains_key(&id) {
                r.verify_marked(&key, mark).map_err(Refused::Broken)?;
                self.notice(r);
            }
            return Ok(Added::NoRoom);
        }
        // A record a held checkpoint names, which it may wait for to
        // count, is taken whatever the rooms say; they are judged after
        // the checkpoint's pruning.
        let wanted = self.wanted(&id);
        if !twin && !first && !wanted && self.cut.past(&eval::item(&r, role)) {
            // Its key dropped a record before it: it would not be kept.
            return Ok(Added::NoRoom);
        }
        let held = if self.trusted.contains(&id) {
            r.body().check().map_err(Refused::Broken)?
        } else {
            r.verify_marked(&key, mark).map_err(Refused::Broken)?
        };
        self.keys.learn(r.body(), role, held);
        let units = self.units.entry(signer).or_default();
        *units = units.saturating_add(eval::item(&r, role).units);
        self.bytes = self.bytes.saturating_add(r.size());
        self.records.insert(id, Entry { record: r, role, held });
        // A checkpoint that may count now, or a record it names, compacts
        // before the rooms are judged: what it prunes takes no room, so
        // what stays does not depend on the order the two came in. A
        // record it named stays only if the rooms then hold it.
        let early = self.trusted.is_empty() && (wanted || self.may_count(&id));
        if early {
            self.settle();
        }
        if self.needs_cut(&signer) {
            self.cut();
        }
        if first && self.trusted.is_empty() {
            // A head's first checkpoint: the head may apply now.
            self.rechain();
        }
        // A second history of a root, or a root's resolve once its chain
        // is whole, may take a checkpoint the set compacted by out of the
        // count: the set forgets it, and what it left out is taken again.
        let unsettles = role == Role::Root
            && !self.checkpoints.is_empty()
            && (twin
                || self
                    .records
                    .values()
                    .any(|e| e.role == Role::Root && matches!(e.record.body().kind, Kind::Resolve(_))));
        if self.trusted.is_empty() && self.records.contains_key(&id) && (unsettles || !early && self.may_count(&id)) {
            // A counting checkpoint compacts at once: what it leaves out
            // takes no room and is not held from the moment it counts, so
            // a member is in one state whenever it compacts.
            self.settle();
        }
        Ok(if self.records.contains_key(&id) { Added::Stored } else { Added::NoRoom })
    }

    /// A record of a root that a waiting recovery record names: kept aside,
    /// within that root's
    /// room (its lowest seqs, then smallest IDs), so that what is kept
    /// does not depend on the order the records came in.
    fn insert_early(&mut self, r: Record) -> Result<Added, Refused> {
        let signer = r.body().signer;
        let Some((_, key)) = self.early_roots.get(&signer) else { return Err(Refused::UnknownSigner) };
        let id = r.id();
        if self.early.contains_key(&id) {
            return Ok(Added::Known);
        }
        r.verify(key).map_err(Refused::Broken)?;
        self.early.insert(id, r);
        self.trim_early();
        if !self.early.contains_key(&id) {
            return Ok(Added::NoRoom);
        }
        // A head's first checkpoint: the head may apply now.
        let names = self
            .records
            .values()
            .any(|e| matches!(&e.record.body().kind, Kind::Recovery { first, .. } if *first == id));
        if names {
            self.rechain();
            if self.records.contains_key(&id) {
                return Ok(Added::Stored);
            }
        }
        Ok(Added::Waiting)
    }

    /// Keeps the records set aside within one root's room in all, the
    /// lowest recovery seq first, then the lowest seq, then the smallest
    /// ID: what stays does not depend on the order they came in.
    fn trim_early(&mut self) {
        let rank = |r: &Record| self.early_roots.get(&r.body().signer).map_or(u64::MAX, |(s, _)| *s);
        let mut all: Vec<(u64, u64, RecordId, u64)> =
            self.early.values().map(|r| (rank(r), r.body().seq, r.id(), eval::item(r, Role::Root).units)).collect();
        all.sort();
        let mut units = 0u64;
        for (_, _, id, u) in all {
            units = units.saturating_add(u);
            if units > keep::ceiling(true) {
                self.early.remove(&id);
            }
        }
    }

    /// A record of the recovery key: a recovery record, or one this
    /// version cannot read (held), which stops the group (rule 33). It
    /// signs nothing else. Its records are kept outside the rooms, at most
    /// two at one seq, the proof of a fork; the path and the cut follow at
    /// once.
    fn insert_recovery(&mut self, r: Record, key: &Key, mark: Option<(&[u8; 32], &Mark)>) -> Result<Added, Refused> {
        let held = r.verify_marked(key, mark).map_err(Refused::Broken)?;
        let b = r.body();
        if b.seq > super::body::MAX_RECOVERY || !held && !matches!(b.kind, Kind::Recovery { .. }) {
            return Err(Refused::Broken(Rule::new("records/recovery")));
        }
        let (id, seq) = (r.id(), b.seq);
        self.keys.learn(r.body(), Role::Recovery, held);
        self.bytes = self.bytes.saturating_add(r.size());
        self.records.insert(id, Entry { record: r, role: Role::Recovery, held });
        // Of one seq the two smallest IDs: any two prove the fork, and
        // which two does not depend on the order they came in.
        let mut at: Vec<RecordId> = self
            .records
            .values()
            .filter(|e| e.role == Role::Recovery && e.record.body().seq == seq)
            .map(|e| e.record.id())
            .collect();
        at.sort();
        for extra in at.into_iter().skip(2) {
            self.remove(&extra);
        }
        if !self.records.contains_key(&id) {
            return Ok(Added::NoRoom);
        }
        self.rechain();
        Ok(Added::Stored)
    }

    /// Takes a recovery record's list, from anyone: it is taken only when
    /// a held recovery record names the hash of its bytes, so the bytes
    /// prove it; bytes that do not read are the empty list. A list that
    /// comes before its head is not kept: lists travel with their head,
    /// and the member asks for it again (`missing_list`). It reports
    /// whether the list is new.
    pub fn insert_list(&mut self, bytes: &[u8]) -> Result<bool, Refused> {
        let hash = super::body::list_hash(bytes);
        if self.lists.contains_key(&hash) {
            return Ok(false);
        }
        let named = self.records.values().any(|e| {
            e.role == Role::Recovery && matches!(&e.record.body().kind, Kind::Recovery { list, .. } if *list == hash)
        });
        if !named {
            return Err(Refused::Broken(Rule::new("records/list/unnamed")));
        }
        let list = List::of(bytes, &hash).unwrap_or_default();
        self.lists.insert(hash, (bytes.to_vec(), list));
        self.rechain();
        Ok(true)
    }

    fn list_refs(&self) -> BTreeMap<[u8; 32], &List> {
        self.lists.iter().map(|(h, (_, l))| (*h, l)).collect()
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
            if r.body().group == self.group && self.keys.signer(&r.body().signer).is_none() {
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
        progress
    }

    /// Walks the recovery chain again after a recovery record or a list
    /// came: the roots it puts on the path get a root's room, and of the
    /// roots before the current one only what the newest list names stays.
    /// A cut the set already narrowed by the current root's checkpoint
    /// stays as it is while the chain and its list do not change.
    fn rechain(&mut self) {
        let lists = self.list_refs();
        let held: BTreeMap<RecordId, &Record> =
            self.records.values().map(|e| &e.record).chain(self.early.values()).map(|r| (r.id(), r)).collect();
        let chain =
            eval::chain(&self.root.hash(), self.records.values().map(|e| (&e.record, e.role)), &lists, |id, root| {
                eval::first_held(&held, id, root)
            });
        let promoted = chain.promoted();
        let mut cuts = chain.cuts();
        self.waiting = chain.waiting;
        self.firsts = chain.firsts.clone();
        // Halted: what the set holds besides the recovery key's records is
        // what the newest list applied below the fork names, nothing else,
        // so that every member holding the proof holds the same.
        // The newest applied record's first checkpoint stays too: the
        // chain below the fork needs it to apply.
        self.halted = chain.halted().then(|| {
            let mut keep = chain.cut.as_ref().map(|c| c.keep.clone()).unwrap_or_default();
            keep.extend(chain.firsts.iter().copied());
            keep
        });
        if let Some(keep) = self.halted.clone() {
            let gone: Vec<RecordId> = self
                .records
                .values()
                .filter(|e| e.role != Role::Recovery && !keep.contains(&e.record.id()))
                .map(|e| e.record.id())
                .collect();
            for id in &gone {
                self.remove(id);
            }
            self.early.retain(|id, _| keep.contains(id));
        }
        // The roots the chain's records name that have not applied yet: a
        // record off the chain (one side of a fork, past a gap, after a
        // void one) has nothing kept aside.
        self.early_roots = if self.halted.is_some() { BTreeMap::new() } else { chain.waiting_roots(&self.root.hash()) };
        if let (Some(old), Some(new)) = (self.cuts.values().next(), cuts.values().next())
            && old.record == new.record
        {
            cuts = self.cuts.clone();
        }
        self.keep_by(promoted, cuts);
        // What waited for a root the chain now applies is taken; what
        // waited for a root no waiting record names any more (one side of
        // a fork, or a record that is no longer valid) is dropped.
        let early = core::mem::take(&mut self.early);
        let (now, still): (Vec<Record>, Vec<Record>) =
            early.into_values().partition(|r| self.promoted.contains(&r.body().signer));
        self.early = still
            .into_iter()
            .filter(|r| self.early_roots.contains_key(&r.body().signer))
            .map(|r| (r.id(), r))
            .collect();
        self.trim_early();
        if !now.is_empty() {
            self.trusted = now.iter().map(Record::id).collect();
            let ids: Vec<RecordId> = now.iter().map(Record::id).collect();
            self.insert_all(now);
            self.trusted.clear();
            if ids.iter().any(|id| self.may_count(id)) {
                self.settle();
            }
        }
    }

    /// Keeps by the roots promoted and the cuts: when they changed, the
    /// keys are learned again and the set's count starts again.
    fn keep_by(&mut self, promoted: BTreeSet<KeyHash>, cuts: BTreeMap<KeyHash, Cut>) {
        if promoted != self.promoted || cuts != self.cuts {
            self.promoted = promoted;
            self.cuts = cuts;
            // What the newest list drops goes first: an admin key only a
            // dropped record named is then no key of the set.
            self.drop_off_cuts();
            self.relearn();
            self.cut = keep::Cut::default();
            self.cut();
        }
    }

    /// Drops the records the set does not keep (`keep`): each key within
    /// its ceiling, the set's ceilings shared fairly between keys. What is
    /// kept depends on the records alone, and dropping what is not kept
    /// changes nothing, so the set is the same whatever order the records
    /// came in. The recovery key's records are outside the rooms.
    fn cut(&mut self) {
        self.drop_off_cuts();
        let proof = self.proof();
        let items: Vec<keep::Item> = self
            .records
            .values()
            .filter(|e| {
                self.role_of(e) != Role::Recovery
                    && !proof.contains(&e.record.id())
                    && !self.firsts.contains(&e.record.id())
            })
            .map(|e| eval::item(&e.record, self.role_of(e)))
            .collect();
        let ceilings: BTreeMap<KeyHash, Option<u64>> =
            items.iter().map(|it| (it.signer, self.ceiling(&it.signer))).collect();
        let (kept, cut) = keep::keep_after(&items, |k| ceilings.get(k).copied().flatten(), &self.cut);
        self.cut = cut;
        let drop: Vec<RecordId> = self
            .records
            .values()
            .filter(|e| {
                self.role_of(e) != Role::Recovery
                    && !kept.contains(&e.record.id())
                    && !proof.contains(&e.record.id())
                    && !self.firsts.contains(&e.record.id())
            })
            .map(|e| e.record.id())
            .collect();
        for id in drop {
            self.remove(&id);
        }
    }

    /// The proof of a key's two histories among the records
    /// (`eval::fork_proof`): outside the rooms.
    fn proof(&self) -> BTreeSet<RecordId> {
        eval::fork_proof(self.records.values().map(|e| (&e.record, self.role_of(e))))
    }

    /// Drops the records of a root before the current one that the newest
    /// list does not name; a removal among them stays as a notice.
    fn drop_off_cuts(&mut self) {
        let mut off = eval::off_cuts(&self.cuts, self.records.values().map(|e| &e.record));
        off.retain(|id| !self.firsts.contains(id));
        for id in &off {
            if let Some(r) = self.held(id).filter(|r| self.is_notice(r)).cloned() {
                self.notice(r);
            }
            self.remove(id);
        }
    }

    /// Whether r is a removal of a root before the current one that the
    /// newest list does not name: what a notice keeps.
    fn is_notice(&self, r: &Record) -> bool {
        let b = r.body();
        matches!(b.kind, Kind::Revoke(_))
            && b.group == self.group
            && self.cuts.get(&b.signer).is_some_and(|cut| cut.roots.contains(&b.signer) && !cut.lets(r))
    }

    /// Keeps r, a verified removal (`is_notice`), as a notice, unless
    /// dismissed; past MAX_NOTICES the oldest goes.
    fn notice(&mut self, r: Record) {
        let id = r.id();
        if self.dismissed.contains(&id) {
            return;
        }
        self.notices.insert(id, r);
        while self.notices.len() > MAX_NOTICES {
            let oldest = self.notices.iter().min_by_key(|(id, r)| self.notice_rank(id, r)).map(|(id, _)| *id);
            let Some(oldest) = oldest else { break };
            self.notices.remove(&oldest);
        }
    }

    /// A notice's age: its root's place on the path, then its seq; of two
    /// alike the larger ID is older. The smallest goes first, so two
    /// members with the same records keep the same notices.
    fn notice_rank(&self, id: &RecordId, r: &Record) -> (usize, u64, core::cmp::Reverse<RecordId>) {
        let b = r.body();
        let place = self.cuts.values().next().and_then(|c| c.roots.iter().position(|k| *k == b.signer)).unwrap_or(0);
        (place, b.seq, core::cmp::Reverse(*id))
    }

    /// Learns the keys again from the stored records, and drops the
    /// records whose signer it no longer knows.
    fn relearn(&mut self) {
        let mut keys = Keys::new(&self.root, &self.recovery);
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
            return self.ceiling(signer).is_none_or(|c| units(signer) > c) || total > keep::ROOM;
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

    /// A key's ceiling: a root's on the path, an admin key's, or None for
    /// any other.
    fn ceiling(&self, k: &KeyHash) -> Option<u64> {
        let admins: BTreeSet<KeyHash> = if self.keys.is_admin(k) { BTreeSet::from([*k]) } else { BTreeSet::new() };
        eval::ceiling_of(&self.root.hash(), &self.promoted, &admins, k)
    }

    fn remove(&mut self, id: &RecordId) {
        if let Some(e) = self.records.remove(id) {
            self.bytes = self.bytes.saturating_sub(e.record.size());
            if e.role != Role::Recovery
                && let Some(u) = self.units.get_mut(&e.record.body().signer)
            {
                *u = u.saturating_sub(eval::item(&e.record, e.role).units);
            }
        }
    }

    /// A record's role, read from the final table.
    fn role_of(&self, e: &Entry) -> Role {
        self.keys.signer(&e.record.body().signer).map_or(e.role, |(_, role)| role)
    }

    fn checked(&self) -> Vec<Checked<'_>> {
        self.records.values().map(|e| Checked { r: &e.record, role: self.role_of(e), held: e.held }).collect()
    }

    /// The group's state.
    pub fn state(&self) -> State {
        let lists = self.list_refs();
        let by = eval::Compacted { proven: &self.checkpoints };
        let early: Vec<&Record> = self.early.values().collect();
        eval::evaluate_checked(&self.root, &self.recovery, self.checked(), BTreeMap::new(), &lists, &by, &early)
    }

    /// The list a change of root carries (rule 33), not edited: every
    /// record of every root on the path that counts in state; every root's
    /// removal the set holds that names a key some record the set holds
    /// names (of the roots before the current one at most
    /// `EARLIER_REMOVALS`, the later root's and the newest first); what the
    /// current list keeps that the set holds (lists do not add up, so each
    /// carries it forward, under the same rule for removals); and the
    /// heads the current root's counting checkpoint names, as anchors. No
    /// checkpoint record. At most a root's room, the removals first.
    pub fn change_list(&self, state: &State) -> List {
        let roots: BTreeSet<&KeyHash> = state.roots.iter().collect();
        let cur = state.roots.last();
        // The keys some record the set holds names: a removal of keys
        // nobody names carries nothing.
        let mut named: BTreeSet<KeyHash> = BTreeSet::new();
        for e in self.records.values() {
            named.insert(e.record.body().signer);
            if let Kind::Device(d) = &e.record.body().kind {
                named.insert(d.key.hash());
                named.extend(d.admin.as_ref().map(Key::hash));
            }
        }
        // A removal is listed only when it names a named key. The earlier
        // roots' take at most their share: the later root's first, the
        // newest by seq first.
        let at = |k: &KeyHash| state.roots.iter().position(|r| r == k).unwrap_or(0);
        let mut earlier: Vec<(usize, u64, RecordId)> = self
            .records
            .values()
            .filter(|e| roots.contains(&e.record.body().signer) && Some(&e.record.body().signer) != cur && !e.held)
            .filter_map(|e| match &e.record.body().kind {
                Kind::Revoke(rm) if rm.keys.iter().any(|k| named.contains(k)) => {
                    Some((at(&e.record.body().signer), e.record.body().seq, e.record.id()))
                }
                _ => None,
            })
            .collect();
        earlier.sort_by(|a, b| b.cmp(a));
        let earlier: BTreeSet<RecordId> = earlier.into_iter().take(EARLIER_REMOVALS).map(|(_, _, id)| id).collect();
        let mut out: BTreeSet<RecordId> = earlier.clone();
        for e in self.records.values().filter(|e| Some(&e.record.body().signer) == cur && !e.held) {
            let b = e.record.body();
            let counts = state.counting.contains(&e.record.id());
            match &b.kind {
                Kind::Revoke(rm) => {
                    if rm.keys.iter().any(|k| named.contains(k)) {
                        out.insert(e.record.id());
                    }
                }
                Kind::Checkpoint { .. } => {}
                _ if counts => {
                    out.insert(e.record.id());
                }
                _ => {}
            }
        }
        if let Some(cut) = &state.cut {
            out.extend(cut.keep.iter().copied().filter(|id| self.records.contains_key(id)));
        }
        for cp in &state.checkpoints {
            if let Some(r) = self.held(cp)
                && Some(&r.body().signer) == cur
                && let Kind::Checkpoint { heads, .. } = &r.body().kind
            {
                out.extend(heads.iter().map(|h| h.id).filter(|id| self.records.contains_key(id)));
            }
        }
        out.remove(&RecordId::default());
        // A checkpoint is never listed: what it pruned, the new root's
        // first checkpoint prunes again.
        // An earlier root's removal is listed only within the share, even
        // when an earlier list named it.
        out.retain(|id| match self.held(id).map(|r| r.body()) {
            Some(b) if matches!(b.kind, Kind::Checkpoint { .. }) => false,
            Some(b) if matches!(b.kind, Kind::Revoke(_)) && roots.contains(&b.signer) && Some(&b.signer) != cur => {
                earlier.contains(id)
            }
            _ => true,
        });
        List(self.within_ceiling(out))
    }

    /// At most a root's room of IDs, the removals first, then in the
    /// keeping's order; sorted.
    fn within_ceiling(&self, ids: BTreeSet<RecordId>) -> Vec<RecordId> {
        let mut items: Vec<(bool, keep::Pos, RecordId, u64)> = ids
            .iter()
            .filter_map(|id| self.records.get(id))
            .map(|e| {
                let it = eval::item(&e.record, self.role_of(e));
                (!matches!(e.record.body().kind, Kind::Revoke(_)), it.pos(), it.id, it.units)
            })
            .collect();
        items.sort();
        let mut out = BTreeSet::new();
        let mut units = 0u64;
        for (_, _, id, u) in items {
            if out.len() >= super::MAX_ROOT_RECORDS || units.saturating_add(u) > keep::ceiling(true) {
                break;
            }
            units = units.saturating_add(u);
            out.insert(id);
        }
        out.into_iter().collect()
    }

    /// Writes a change of root (rule 33) on the device that becomes the
    /// root, where the recovery key was entered. First the new root's own
    /// records, all signed before the head is released and sent with it:
    /// its device record (device, with holds_root); a settings record that
    /// copies the old root's; a hubs record that copies the counting one
    /// unless drop_hubs; a removal of the keys the owner unticked (remove:
    /// "who stays" is made of removals); and its first checkpoint. Then the
    /// recovery record
    /// at the seq after the chain's tip, naming new_root and the list's
    /// hash. It refuses a set whose chain waits for a list (an earlier
    /// change it has not taken yet), a group stopped for good, a 17th record, a key that
    /// is not the group's recovery key, and a new root key the state
    /// already knows.
    #[allow(clippy::too_many_arguments, reason = "the parts of one act")]
    pub fn write_change(
        &self,
        state: &State,
        recovery: &dyn ExternalKey,
        new_root: &dyn ExternalKey,
        device: super::body::Device,
        remove: &[KeyHash],
        drop_hubs: bool,
        time_ms: u64,
    ) -> crate::error::Result<Written> {
        use crate::error::Error;
        // Any recovery record the set holds and has not applied (one that
        // waits for its list or for the record before it, one this device
        // cannot read, a void one) means a change is on its way: writing
        // now would sign a second record at its seq.
        let applied: BTreeSet<RecordId> = state.chain().into_iter().collect();
        let unapplied = self.waiting.is_some()
            || state.update_needed
            || self.records.values().any(|e| e.role == Role::Recovery && !applied.contains(&e.record.id()));
        if unapplied {
            return Err(Error::msg(CHANGE_WAITING));
        }
        if state.conflicts.iter().any(|c| c.kind == eval::ConflictKind::Fork) {
            return Err(Error::msg("the group is stopped for good: two recovery records at one seq"));
        }
        if Key::es256(recovery.public()) != self.recovery {
            return Err(Error::msg("this is not the group's recovery key"));
        }
        let tip = state.chain();
        // One above the highest recovery seq the set holds, never only the
        // applied chain's.
        let held = self.records.values().filter(|e| e.role == Role::Recovery).map(|e| e.record.body().seq).max();
        let seq = held.unwrap_or(0).max(tip.len() as u64).saturating_add(1);
        if seq > super::body::MAX_RECOVERY {
            return Err(Error::msg("the group has used all its changes of root"));
        }
        let root_key = Key::es256(new_root.public());
        let h = root_key.hash();
        let known = self.keys.signer(&h).is_some()
            || state.revoked.contains(&h)
            || state.devices.iter().any(|d| d.key.hash() == h || d.admin == Some(h))
            || self.records.values().any(|e| e.record.body().signer == h);
        if known {
            return Err(Error::msg("the new root key must be a new key"));
        }
        let device_key = device.key.hash();
        if state.revoked.contains(&device_key) {
            return Err(Error::msg("this device was removed from the group: it joins again with a new key"));
        }
        let rank = |k: &KeyHash| *k == h || *k == device_key || *k == self.recovery.hash() || path_has(state, k);
        if remove.iter().any(rank) {
            return Err(Error::msg("the new root, its device, the recovery key and the roots cannot be removed"));
        }
        let list = self.change_list(state);
        let mut next = 1u64;
        let mut prev = None;
        let mut sign = |kind: Kind| -> crate::error::Result<Record> {
            let body = Body { group: self.group, signer: h, seq: next, prev, time_ms, kind, held: false };
            let r = Record::sign(body, new_root)?;
            next = next.saturating_add(1);
            prev = Some(r.id());
            Ok(r)
        };
        let mut device = device;
        device.holds_root = true;
        let mut first = alloc::vec![sign(Kind::device(device))?];
        if state.settings != Settings::default() {
            first.push(sign(Kind::settings(state.settings.clone()))?);
        }
        let old_hubs = list.0.iter().find_map(|id| match self.held(id).map(|r| &r.body().kind) {
            Some(Kind::Hubs { hubs, .. }) if state.counting.contains(id) => Some(hubs.clone()),
            _ => None,
        });
        if let (Some(hubs), false) = (old_hubs, drop_hubs) {
            first.push(sign(Kind::Hubs { hubs, seen: Vec::new() })?);
        }
        let mut keys: Vec<KeyHash> = remove.to_vec();
        keys.sort();
        keys.dedup();
        // What the writer saw of the keys a removal concerns (the keys it
        // names and their admin or member key), as an ordinary removal
        // carries: what they signed up to it still counts. A key it does
        // not name is untouched, so its heads are not listed. As many
        // removals as their bodies need.
        let mut rest = keys.as_slice();
        while !rest.is_empty() {
            let mut n = rest.len();
            loop {
                let part = rest.get(..n).unwrap_or_default();
                let rm = super::body::Removal { keys: part.to_vec(), seen: self.heads_of(state, part) };
                // Sized with the widest seq and prev the record can have.
                let widest = Body {
                    group: self.group,
                    signer: h,
                    seq: super::MAX_SEQ,
                    prev: Some(RecordId([0; 32])),
                    time_ms,
                    kind: Kind::Revoke(rm),
                    held: false,
                };
                if widest.encode().len() <= super::MAX_BODY || n == 1 {
                    first.push(sign(widest.kind)?);
                    break;
                }
                n = n.div_ceil(2);
            }
            rest = rest.get(n..).unwrap_or_default();
        }
        // The new root's first checkpoint, signed now so that the pruning
        // of the old root's counting checkpoint never lapses: the heads it
        // named of keys that are no roots, and its own head; it keeps the
        // whole list, what the old checkpoint kept of those keys, and the
        // new root's records before it. It closes the list without
        // narrowing it.
        let path: BTreeSet<&KeyHash> = state.roots.iter().collect();
        let cur = state.roots.last();
        let mut heads: BTreeMap<KeyHash, super::body::Head> = BTreeMap::new();
        let mut keep: BTreeSet<RecordId> = list.0.iter().copied().collect();
        for cp in &state.checkpoints {
            let Some(r) = self.held(cp) else { continue };
            let Kind::Checkpoint { heads: hs, keep: kept } = &r.body().kind else { continue };
            if Some(&r.body().signer) != cur {
                continue;
            }
            for hd in hs.iter().filter(|hd| !path.contains(&hd.key)) {
                let e = heads.entry(hd.key).or_insert(*hd);
                if hd.seq > e.seq {
                    *e = *hd;
                }
            }
            keep.extend(kept.iter().copied().filter(|id| {
                self.held(id).is_some_and(|x| !path.contains(&x.body().signer)) && self.records.contains_key(id)
            }));
        }
        let mut own = first.iter().map(Record::id).collect::<Vec<_>>();
        let own_head = own.pop();
        keep.extend(own);
        if let (Some(id), Some(last)) = (own_head, first.last()) {
            heads.insert(h, super::body::Head { key: h, seq: last.body().seq, id });
        }
        let checkpoint =
            sign(Kind::Checkpoint { heads: heads.into_values().collect(), keep: keep.into_iter().collect() })?;
        let first_id = checkpoint.id();
        first.push(checkpoint);
        let body = Body {
            group: self.group,
            signer: self.recovery.hash(),
            seq,
            prev: tip.last().copied(),
            time_ms,
            kind: Kind::Recovery { root: root_key, list: list.hash(), from: 0, first: first_id },
            held: false,
        };
        let record = Record::sign(body, recovery)?;
        Ok(Written { record, list, first })
    }

    /// The heads the set holds of the keys a removal of `keys` concerns:
    /// each key and its device's admin key or its admin key's device key;
    /// of each its highest seq (of two at one seq, the smaller ID).
    fn heads_of(&self, state: &State, keys: &[KeyHash]) -> Vec<super::body::Seen> {
        let mut concerned: BTreeSet<KeyHash> = keys.iter().copied().collect();
        for d in &state.devices {
            let member = d.key.hash();
            match &d.admin {
                Some(a) if keys.contains(&member) => {
                    concerned.insert(*a);
                }
                Some(a) if keys.contains(a) => {
                    concerned.insert(member);
                }
                _ => {}
            }
        }
        self.heads_where(|k| concerned.contains(k))
    }

    /// The heads of the keys want takes, but the recovery key's.
    fn heads_where(&self, want: impl Fn(&KeyHash) -> bool) -> Vec<super::body::Seen> {
        let mut out: BTreeMap<KeyHash, super::body::Seen> = BTreeMap::new();
        for e in self.records.values().filter(|e| e.role != Role::Recovery && !e.held && want(&e.record.body().signer))
        {
            let b = e.record.body();
            let s = super::body::Seen { key: b.signer, seq: b.seq, id: e.record.id() };
            let better = out
                .get(&b.signer)
                .is_none_or(|o| (b.seq, core::cmp::Reverse(s.id)) > (o.seq, core::cmp::Reverse(o.id)));
            if better {
                out.insert(b.signer, s);
            }
        }
        out.into_values().collect()
    }

    /// The records to ask the peers for in this round: those the newest
    /// list names that the set does not hold. A record whose ID a verified
    /// list names is taken from anyone. Each call is one round; a record
    /// asked for in MISSING_ROUNDS rounds without coming is given up, so an
    /// ID nobody holds is not asked for for ever; the new root's first
    /// checkpoint closes the list for good.
    pub fn missing(&mut self, state: &State) -> Vec<RecordId> {
        // The state's cut: the new root's first counting checkpoint has
        // narrowed it to what that checkpoint keeps.
        // And the new root's first checkpoint the next head waits for.
        let want: BTreeSet<RecordId> = state
            .cut
            .iter()
            .flat_map(|c| c.keep.iter())
            .chain(state.first_missing.iter())
            .filter(|id| !self.records.contains_key(*id) && !self.early.contains_key(*id))
            .copied()
            .collect();
        self.asked.retain(|id, _| want.contains(id));
        let mut out = Vec::new();
        for id in want {
            let n = self.asked.entry(id).or_insert(0);
            if *n < MISSING_ROUNDS {
                *n = n.saturating_add(1);
                out.push(id);
            }
        }
        out
    }

    /// The hash of the list the next valid recovery record waits for:
    /// ask the peers for it.
    pub fn missing_list(&self) -> Option<[u8; 32]> {
        self.waiting
    }

    /// Whether the record id may make a root's checkpoint the set has not
    /// compacted by count: it is such a checkpoint, a record it names, or
    /// a record of its key below it.
    /// Whether a held root's checkpoint that does not count yet names id
    /// (a head or a kept record).
    fn wanted(&self, id: &RecordId) -> bool {
        self.records.values().any(|e| {
            let Kind::Checkpoint { heads, keep } = &e.record.body().kind else { return false };
            e.role == Role::Root
                && (heads.iter().any(|h| h.id == *id) || keep.contains(id))
                && !self.checkpoints.iter().any(|(h, _)| h == heads)
        })
    }

    fn may_count(&self, id: &RecordId) -> bool {
        let Some(r) = self.held(id) else { return false };
        let (signer, seq) = (r.body().signer, r.body().seq);
        self.records.values().any(|e| {
            let b = e.record.body();
            let Kind::Checkpoint { heads, keep } = &b.kind else { return false };
            if e.role != Role::Root {
                return false;
            }
            let anchors = eval::anchors_of(heads, keep);
            if self.checkpoints.iter().any(|(h, a)| h == heads && *a == anchors) {
                return false;
            }
            e.record.id() == *id || anchors.contains(id) || b.signer == signer && seq < b.seq
        })
    }

    /// Compacts by the set's own state until nothing more goes.
    fn settle(&mut self) {
        for _ in 0..4 {
            let st = self.state();
            let before = self.checkpoints.clone();
            if self.compact(&st) == 0 && self.checkpoints == before {
                break;
            }
        }
    }

    /// Drops what the counting checkpoints of state leave out: a root's
    /// checkpoint resets the set's count. The cut takes state's, which the
    /// current root's first checkpoint narrows.
    pub(super) fn compact(&mut self, state: &State) -> usize {
        let promoted: BTreeSet<KeyHash> = state.roots.iter().skip(1).copied().collect();
        let cuts = eval::cuts_of(state.cut.as_ref());
        self.keep_by(promoted, cuts);
        self.checkpoints = state
            .checkpoints
            .iter()
            .filter_map(|cp| match self.held(cp).map(|r| &r.body().kind) {
                Some(Kind::Checkpoint { heads, keep }) => Some((heads.clone(), eval::anchors_of(heads, keep))),
                _ => None,
            })
            .collect();
        let proof = self.proof();
        let drop: Vec<RecordId> = self
            .records
            .values()
            .filter(|e| !eval::proof_stays(&proof, &e.record) && !self.firsts.contains(&e.record.id()))
            .filter(|e| {
                let b = e.record.body();
                let listed =
                    self.cuts.get(&b.signer).is_some_and(|c| c.covers(&b.signer, b.seq) && c.keeps(&e.record.id()));
                !listed
                    && self
                        .checkpoints
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
        let mut keys = Keys::new(&self.root, &self.recovery);
        let mut out = Vec::with_capacity(self.records.len());
        let mut left: Vec<&Entry> = self.records.values().collect();
        // The proof of a key's two histories goes first, as soon as its
        // signer is known.
        let proof = self.proof();
        left.sort_by_key(|e| (!proof.contains(&e.record.id()), eval::order_key(e.record.body(), &e.record.id())));
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
                // The records that wait for their root's list, after the
                // recovery record that names that root.
                let mut early: Vec<&Record> = self.early.values().collect();
                early.sort_by_key(|r| eval::order_key(r.body(), &r.id()));
                out.extend(early);
                return out;
            }
            left = rest;
        }
    }

    /// What a peer gets in sync (design-records-v3 section 3): a device of
    /// the group all of it; a removed device only the counting removals
    /// that name it; any other key nothing. While the group is halted,
    /// every peer, whatever the records say of it, gets the recovery key's
    /// records and nothing else: after a fork the two that prove it, each
    /// valid by its own bytes; otherwise the chain, the record this
    /// version cannot read with it.
    pub fn for_peer<'a>(&'a self, state: &State, peer: &KeyHash) -> Vec<&'a Record> {
        if state.halted() {
            let mut out: Vec<&Record> = match state.fork {
                Some((_, a, b)) => [a, b].iter().filter_map(|id| self.held(id)).collect(),
                None => self.records.values().filter(|e| e.role == Role::Recovery).map(|e| &e.record).collect(),
            };
            out.sort_by_key(|r| (r.body().seq, r.id()));
            return out;
        }
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
