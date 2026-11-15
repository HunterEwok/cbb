// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The record set a member keeps: records by ID, each checked before it is
//! stored, within the format's ceilings, the same whatever order they came
//! in (rules 1 and 6).

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;

use super::body::{Body, Head, List, Settings};
use super::eval::{self, Checked, Cut, Keys, Role, State, Why};
use super::key::{GroupId, Key, KeyHash, RecordId, Recovery, group_id};
use super::{DeviceId, Kind, MAX_NOTICES, Mark, Record, Rule, keep};
use crate::identity::ExternalKey;

mod notice;
pub use notice::{
    AckOwed, AdminSilent, ChangeArriving, FrozenHolding, Offer, RemovalWarning, Room, RootRoomWaiting, TurnedAway,
    WaitingRemoval,
};

/// The rooms judged over what a set holds (`RecordSet::judge`).
struct Judged {
    /// What the rooms turn away.
    drop: Vec<RecordId>,
    /// The units kept first, by key.
    pre: BTreeMap<KeyHash, u64>,
    /// The keys with no room (`eval::rooms`).
    second: BTreeSet<KeyHash>,
    /// What the checkpoints above the counting one keep.
    wanted: BTreeSet<RecordId>,
}

/// The units the current root's writer keeps back below its ceiling, past
/// its records and its next checkpoint, for its removals, freezes and
/// resolves (`write_one`'s floor): a 24th of the root's ceiling, 64 such
/// records of one unit each at the real rooms, four for every admin key
/// the group may have. A writer's number only: no member judges a record
/// by it.
fn root_floor_margin() -> u64 {
    keep::ceiling(true) / 24
}

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
    /// room, and taken when the list comes. Or a checkpoint of the current
    /// root above its counting one keeps it while the set does not hold
    /// it among the rest: it waits in the place aside until that
    /// checkpoint may count. Until then it counts for nothing.
    Waiting,
    /// The group is halted here (`State::halted`): the set takes only the
    /// recovery key's records.
    Halted,
    /// A counting checkpoint settled its key up to seq `head`: it is not
    /// kept. A root whose record is refused so shows that its last action
    /// did not count, and takes its next seq above head after a sync.
    Settled { head: u64 },
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

/// The devices that came in through an earlier change of root: its
/// recovery record, its seq and their keys (`RecordSet::arrivals`).
pub type Arrival = (RecordId, u64, Vec<KeyHash>);

/// The newest change of root a set applied, with the devices that
/// counted before it (`RecordSet::arrivals`).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Base {
    /// The recovery record of the change, and its seq.
    pub change: RecordId,
    pub seq: u64,
    pub before: BTreeSet<super::DeviceId>,
}

/// The settled root records a set keeps a while (`RecordSet::settled`):
/// at most this many, and at most SETTLED_BYTES of their envelopes, the
/// oldest arrival going first.
pub(super) const SETTLED_KEPT: usize = 16;
const SETTLED_BYTES: usize = 256 << 10;
/// The IDs of settled root records a set remembers by seq and key
/// (`RecordSet::settled_ids`), the oldest arrival going first.
const SETTLED_IDS: usize = 1024;

/// Why a checkpoint of the current root is still not whole after its
/// records were asked for in MISSING_ROUNDS rounds
/// ([`RecordSet::stuck_checkpoints`]).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum Stuck {
    /// A record it keeps was never offered: "a checkpoint of the root is
    /// waiting for records nobody has".
    NeverOffered,
    /// Its records were offered, but the place aside had no room for them
    /// beside what a newer checkpoint of the root keeps: "a checkpoint of
    /// the root is held back by a newer one".
    NoRoom,
}

#[cfg(test)]
std::thread_local! {
    /// Tests only: the set asks what waits before every record, as it did
    /// before it asked only where the answer decides
    /// (`tests/insert_cost.rs` compares the two ways).
    pub(super) static OLD_WAITS: core::cell::Cell<bool> = const { core::cell::Cell::new(false) };
}

#[cfg(all(debug_assertions, feature = "std"))]
std::thread_local! {
    /// Debug builds: true while a test that times the set runs without
    /// the check after every insert (`check_judged`, `unchecked`).
    static UNCHECKED: core::cell::Cell<bool> = const { core::cell::Cell::new(false) };
    /// The state checks this thread made (`check_state`).
    static STATE_CHECKS: core::cell::Cell<u64> = const { core::cell::Cell::new(0) };
}

#[cfg(test)]
std::thread_local! {
    /// Tests only: true while the state is checked after every insert,
    /// whatever the set's size (`check_every_insert`).
    static STATE_EVERY: core::cell::Cell<bool> = const { core::cell::Cell::new(false) };
}

/// While it lives, the debug check that a set's state is the evaluation
/// of what it holds runs after every insert of this thread, not only at
/// the usual intervals (`RecordSet::check_state`).
#[cfg(test)]
pub(super) struct EveryInsert(bool);

#[cfg(test)]
pub(super) fn check_every_insert() -> EveryInsert {
    EveryInsert(STATE_EVERY.with(|c| c.replace(true)))
}

#[cfg(test)]
impl Drop for EveryInsert {
    fn drop(&mut self) {
        STATE_EVERY.with(|c| c.set(self.0));
    }
}

/// While it lives, the debug check that what a set holds is what its
/// rooms keep (`RecordSet::check_judged`), which judges the rooms again
/// after every insert, is off on this thread: for the tests that time a
/// set.
#[cfg(all(test, feature = "std"))]
pub(super) struct Unchecked;

#[cfg(all(test, feature = "std"))]
impl Unchecked {
    pub(super) fn new() -> Unchecked {
        #[cfg(debug_assertions)]
        UNCHECKED.with(|u| u.set(true));
        Unchecked
    }
}

#[cfg(all(test, feature = "std"))]
impl Drop for Unchecked {
    fn drop(&mut self) {
        #[cfg(debug_assertions)]
        UNCHECKED.with(|u| u.set(false));
    }
}

/// A member's record set.
#[derive(Clone)]
pub struct RecordSet {
    root: Key,
    /// The hash of root, which never changes: asked for at every record.
    root_hash: KeyHash,
    recovery: Recovery,
    group: GroupId,
    keys: Keys,
    /// Each signer's units, to know when one is past its ceiling.
    units: BTreeMap<KeyHash, u64>,
    /// The roots after the first that the recovery chain put on the path:
    /// they have a root's room.
    promoted: BTreeSet<KeyHash>,
    /// The path of roots, in order: the group's root first.
    path: Vec<KeyHash>,
    /// The keys with an admin's ceiling that are no longer admins, or not
    /// among the live ones, when the rooms were last judged: they have no
    /// room (`keep::keep_tiers`).
    second: BTreeSet<KeyHash>,
    /// While a batch's judgment runs (`insert_all`): the root's
    /// checkpoints the rooms turned away, judged for the place aside once
    /// the counting checkpoints compacted (`aside_turned`).
    turned: Option<Vec<(Record, Role, bool)>>,
    /// The newest recovery record's cut, by each root before the current
    /// one: such a root keeps only the records its list names, narrowed by
    /// the current root's first checkpoint once it counted (`compact`).
    cuts: BTreeMap<KeyHash, Cut>,
    /// The lists the held recovery records name, by hash: their bytes as
    /// they came, and what they read as.
    lists: BTreeMap<[u8; 32], (Vec<u8>, List)>,
    /// The list the next valid recovery record waits for.
    waiting: Option<[u8; 32]>,
    /// The first record of each waiting change's group the set does not
    /// hold (`eval::first_gap`): when one comes, that change may apply.
    gaps: BTreeSet<RecordId>,
    /// The roots the held recovery records name that the path has not
    /// reached (their record waits for its list, or for the record before
    /// it), but for the two sides of a fork, by key hash.
    /// With each its key and the lowest recovery seq that names it.
    early_roots: BTreeMap<KeyHash, (u64, Key)>,
    /// While the group is halted by a recovery fork, what the set takes
    /// besides the recovery key's records: nothing (`State::halted`).
    halted: Option<BTreeSet<RecordId>>,
    /// The first checkpoints kept outside the rooms (`eval::Chain::firsts`):
    /// the newest applied recovery record's and that of the one the chain
    /// waits for; never cut off or pruned while they are.
    firsts: eval::Firsts,
    /// The units each key's records kept first took when the rooms were
    /// last judged (`cut`): outside the rooms, within the key's cap.
    pre: BTreeMap<KeyHash, u64>,
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
    /// The devices that came in through a change of root (case b): a
    /// device that counts after it, did not before it, and that no record
    /// of the new root admits. For the newest change the devices that
    /// counted before it (`base`), so that what its list brings later is
    /// told too; for each earlier one the keys, fixed when the next change
    /// came. Shown with the notices; at most MAX_NOTICES, the lowest
    /// recovery seq going first; kept across restarts by the app
    /// (`arrivals`, `keep_arrivals`).
    arrivals: BTreeMap<RecordId, (u64, Vec<KeyHash>)>,
    base: Option<Base>,
    /// Root records a counting checkpoint settled, kept a while by seq and
    /// key so that the other record at that seq makes the pair (a fork at
    /// any depth): verified, with the order they came in, at most
    /// SETTLED_KEPT records and SETTLED_BYTES, the oldest going first;
    /// local, never stored or sent. Two that come together always make the
    /// pair (`insert_all` takes them one after the other).
    settled: BTreeMap<(u64, KeyHash), (u64, Record)>,
    /// The IDs of the settled root records verified, by seq and key, with
    /// the order they came in: a record of another ID at that seq that
    /// comes later is kept (`halves`) and the other asked for (`missing`).
    settled_ids: BTreeMap<(u64, KeyHash), (u64, RecordId)>,
    /// Settled root records whose seq holds another ID the set verified,
    /// each with that ID: the pair waits for it. At most SETTLED_KEPT
    /// records and SETTLED_BYTES, the oldest arrival going first. Only a
    /// record the root signed at a seq where it signed another comes here.
    halves: BTreeMap<(u64, KeyHash), (u64, Record, RecordId)>,
    /// The order of arrival of settled records.
    arrived: u64,
    /// Whether the set took records from a peer (`insert`, `insert_all`)
    /// since it was made, restored or loaded from the device's own store.
    reached: bool,
    /// The keys of root removals this set dropped at a checkpoint's prune,
    /// each with the order it came in, the root and that root's head in
    /// the checkpoint: a key that counts again other than by a newer
    /// record of a root is a notice (an admission the root never saw).
    /// Local and best effort: at most MAX_NOTICES, the oldest going first,
    /// never on the wire, never a rule.
    marks: BTreeMap<KeyHash, (u64, KeyHash, u64)>,
    marked: u64,
    /// The checkpoints that counted when the set last compacted: what
    /// they prune is not taken again.
    checkpoints: Vec<(KeyHash, Vec<Head>, BTreeSet<RecordId>)>,
    records: BTreeMap<RecordId, Entry>,
    bytes: usize,
    /// How many rounds each missing record was asked for (`missing`).
    asked: BTreeMap<RecordId, u32>,
    /// The place aside: the records a checkpoint of the current root above
    /// its counting one keeps that the set does not hold among the rest,
    /// as the counting one pruned them or the rooms turned them away. With
    /// each its role and whether it is held. They count for nothing, take
    /// no unit and are not compacted; they are taken into the set when a
    /// checkpoint that keeps them is whole with them and may count
    /// (`switch`), and leave in the step that no such checkpoint keeps them
    /// any more (`trim_aside`). At most one ROOM of units in all, what the
    /// newest of them keeps staying first, then by (seq, ID); local,
    /// outside the digest, never stored or sent but to a peer that asks
    /// for one by its ID (`for_peer_by_id`).
    kept_aside: BTreeMap<RecordId, (Record, Role, bool)>,
    /// While a batch goes in (`insert_all`): the rooms are judged once,
    /// over what is held and the whole batch, when it ends. Some(true)
    /// when a judgment is due then.
    batch: Option<bool>,
    /// The current root's checkpoints that wait for records nobody gave
    /// in MISSING_ROUNDS rounds (`missing`): a notice, once per checkpoint,
    /// at most MAX_NOTICES, the oldest going first. Local, never on the
    /// wire, never a rule.
    stuck: BTreeMap<RecordId, (u64, Stuck)>,
    /// Records the place aside had no room for, among those still asked
    /// for (`missing`): they were offered.
    no_room: BTreeSet<RecordId>,
}

/// The units of the new root's room a change's re-issued removals leave to
/// its other first records: its device, settings and hubs records and the
/// owner's removals.
/// How long an admin key may stay silent: the root takes it back when it
/// has received no acknowledgement of the key for this long, on the root
/// device's own clock (a device silent for 35 days, as copies'
/// statements). Not a rule members judge: the root's record decides.
pub const ADMIN_SILENCE_MS: u64 = crate::copies::STATEMENT_MAX_AGE_MS;

/// The writer's refusal to name an admin key a root took back: what the
/// key signed that the root never got would count again.
pub const ADMIN_KEY_TAKEN_BACK: &str =
    "this admin key was taken back: the device makes a new admin key before it is an admin again";

/// Why the root's writer takes an admin key back by itself
/// (`RecordSet::take_back_lagging`). A full room and a frozen admin key
/// that holds removals back are not reasons: there the person chooses,
/// from what `unacknowledged`, `unacknowledged_units` and
/// `frozen_admins` show, to thaw the key or take it back
/// (`RecordSet::take_back`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TakeBack {
    /// The root received nothing of the key for ADMIN_SILENCE_MS.
    Silence,
}

/// The writer's refusal to take back the current root's own key.
pub const TAKE_BACK_ROOT: &str = "the current root's key is not taken back as an admin key";

/// The writer's refusal of a root removal that would leave the person no
/// room to take back the admin keys that hold removals back and write the
/// checkpoint that settles them (`RecordSet::unacknowledged` names them).
pub const TAKE_BACK_FIRST: &str = "take back the admin keys that hold removals back first";

/// The writer's refusal of a change whose re-issue would not fit the new
/// root's room with room for its next checkpoint: the person leaves out
/// devices.
pub const CHANGE_TOO_BIG: &str = "the change does not fit the new root's room: leave out some devices";

/// The writer's refusal of a new root key that was an admin key: every new
/// root is a fresh key (L), so that nothing it signed under an earlier
/// root sits on its line.
pub const CHANGE_FORMER_ADMIN: &str = "the new root key was an admin key: a new root is always a new key";

/// The writer's refusal of a spare admin key the group has used (S): a
/// spare is a fresh key.
pub const SPARE_USED: &str = "the spare key is not a new key";

/// The most recovery records of one seq a set takes from a peer it does
/// not know (`RecordSet::insert_from_unknown`): two are a fork's proof.
pub const UNKNOWN_PER_SEQ: usize = 2;

/// Why the writer does not write a change of root while the set holds a
/// recovery record it has not applied, or the records of a change it
/// holds the head of.
pub const CHANGE_WAITING: &str = "a change of root is waiting here: sync with the group, then try again";

/// Why the writer does not write a change of root after two recovery
/// records at one seq: the group has no way on (rule 33) and is made again.
pub const CHANGE_STOPPED: &str =
    "this group has stopped for good: two changes of root were signed at one number; make the group again";

/// Whether k is a root on the state's path.
fn path_has(state: &State, k: &KeyHash) -> bool {
    state.roots.contains(k)
}

/// The rounds a member asks its peers for a missing record before it gives
/// up on it (`RecordSet::missing`).
pub const MISSING_ROUNDS: u32 = 16;

/// What a change of root does to one device (`RecordSet::change_preview`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Outcome {
    /// Re-issued by the new root as it counts now.
    Stays,
    /// Left out by the person: not re-issued, no removal written.
    Out,
    /// An admin whose spare key the new root names (S).
    AdminKeptWithSpare,
    /// An admin that loses its rights: its device stays as a plain one.
    AdminRightsLost,
    /// A frozen device that is no admin: re-issued with the new root's
    /// freeze, thawed only by it. A frozen admin's line says what happens
    /// to its rights, with `frozen` set.
    Frozen,
}

/// One line of the query before a change of root.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Preview {
    pub device: DeviceId,
    pub outcome: Outcome,
    /// Re-issued with the new root's freeze: it acts only once the new
    /// root thaws it (an admin's spare too).
    pub frozen: bool,
}

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
    /// Whether this is the change the set already held, given back: the
    /// writer was asked again and signed nothing.
    pub again: bool,
    /// Whether the writer wrote it from records it holds without having
    /// taken any from a member since it was loaded: the app warns before
    /// sending a change written blind, which a member on the other side
    /// of a split may be writing too.
    pub blind: bool,
}

impl RecordSet {
    /// An empty set for the group whose first root key is root and whose
    /// recovery key is recovery: the Group ID commits to both.
    pub fn new(root: Key, recovery: Recovery) -> RecordSet {
        let keys = Keys::new(&root, &recovery);
        let group = group_id(&root, &recovery);
        let root_hash = root.hash();
        RecordSet {
            root_hash,
            root,
            recovery,
            group,
            keys,
            units: BTreeMap::new(),
            promoted: BTreeSet::new(),
            path: alloc::vec![root_hash],
            second: BTreeSet::new(),
            turned: None,
            cuts: BTreeMap::new(),
            lists: BTreeMap::new(),
            waiting: None,
            gaps: BTreeSet::new(),
            early_roots: BTreeMap::new(),
            halted: None,
            firsts: BTreeMap::new(),
            pre: BTreeMap::new(),
            trusted: BTreeSet::new(),
            early: BTreeMap::new(),
            notices: BTreeMap::new(),
            dismissed: BTreeSet::new(),
            arrivals: BTreeMap::new(),
            base: None,
            settled: BTreeMap::new(),
            settled_ids: BTreeMap::new(),
            halves: BTreeMap::new(),
            arrived: 0,
            reached: false,
            marks: BTreeMap::new(),
            marked: 0,
            checkpoints: Vec::new(),
            records: BTreeMap::new(),
            bytes: 0,
            asked: BTreeMap::new(),
            kept_aside: BTreeMap::new(),
            batch: None,
            stuck: BTreeMap::new(),
            no_room: BTreeSet::new(),
        }
    }

    /// The set a member saved, rebuilt: its records (`in_dependency_order`
    /// or any other order) and its lists (`lists`), taken round by round
    /// until a round takes nothing new, as a record may wait for a list or
    /// for another record. Saving and restoring keeps the digest, the
    /// state and what is kept aside for a root whose change waits.
    pub fn restore(root: Key, recovery: Recovery, records: &[Record], lists: &[Vec<u8>]) -> RecordSet {
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
        // What came in through a change is told from what the app saved
        // (`keep_arrivals`): after a change the set no longer holds the
        // earlier root's records (L), so the state before it cannot be
        // rebuilt here, and every re-issued device would look new.
        set.base = None;
        set.arrivals.clear();
        set.reached = false;
        set
    }

    /// An empty set for the keys the device's own store pinned, with the
    /// mark it saved beside them (`super::pin_mark`); None when the mark
    /// does not hold, so that a store whose recovery key was changed is
    /// not taken.
    pub fn pinned(root: Key, recovery: Recovery, local: &[u8; 32], mark: &Mark) -> Option<RecordSet> {
        (root != recovery.k1 && crate::secret::ct_eq(&super::pin_mark(local, &root, &recovery), mark))
            .then(|| RecordSet::new(root, recovery))
    }

    pub fn root(&self) -> &Key {
        &self.root
    }

    pub fn recovery(&self) -> &Recovery {
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
        self.records.contains_key(id) || self.early.contains_key(id) || self.kept_aside.contains_key(id)
    }

    /// The record, among what counts or what is kept aside.
    pub fn get(&self, id: &RecordId) -> Option<&Record> {
        self.held(id).or_else(|| self.early.get(id)).or_else(|| self.kept_aside.get(id).map(|(r, _, _)| r))
    }

    /// Whether the record waits in the place aside for a checkpoint of the
    /// current root that keeps it (`kept_aside`): held, counting for
    /// nothing, outside the digest.
    pub fn waits_aside(&self, id: &RecordId) -> bool {
        self.kept_aside.contains_key(id)
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
    #[allow(dead_code, reason = "the tests read it; the Welcome in parts no longer does")]
    pub(crate) fn firsts(&self) -> &eval::Firsts {
        &self.firsts
    }

    /// The bytes of the list of hash, when the set holds it.
    pub fn list(&self, hash: &[u8; 32]) -> Option<&[u8]> {
        self.lists.get(hash).map(|(b, _)| b.as_slice())
    }

    /// The notices to show with state: each dropped removal with the keys
    /// it names that are devices of state again, by record ID. A removal
    /// none of whose keys is a device again shows nothing.
    pub fn notices(&self, state: &State) -> Vec<(RecordId, Vec<KeyHash>)> {
        let removals = self.notices.iter().filter_map(|(id, r)| match &r.body().kind {
            Kind::Revoke(rm) => Some((*id, rm.keys.as_slice())),
            _ => None,
        });
        let shown = |id: &RecordId, keys: &[KeyHash]| -> Option<(RecordId, Vec<KeyHash>)> {
            let keys: Vec<KeyHash> = keys.iter().copied().filter(|k| !state.revoked.contains(k)).collect();
            (!self.dismissed.contains(id) && !keys.is_empty()).then_some((*id, keys))
        };
        // A dropped removal tells of the keys that are devices again: after
        // a change only what the new root re-issued counts (L), so a key
        // it did not carry is simply out, not back.
        let mut out: Vec<(RecordId, Vec<KeyHash>)> = removals
            .filter_map(|(id, keys)| {
                let back: Vec<KeyHash> = keys.iter().copied().filter(|k| state.device_by_key(k).is_some()).collect();
                shown(&id, &back)
            })
            .collect();
        // A device a removal notice already tells of is not told again.
        // A device one notice tells of is not told again: removals first,
        // then what came in through a change, then the marked keys.
        let mut told: BTreeSet<KeyHash> = out.iter().flat_map(|(_, keys)| keys.iter().copied()).collect();
        let live = self.base.as_ref().map(|b| (b.change, self.came_in(state, &b.before)));
        let fixed = self.arrivals.iter().map(|(id, (_, keys))| (*id, keys.clone()));
        for (id, keys) in fixed.chain(live).chain(self.marked_back(state)) {
            let keys: Vec<KeyHash> = keys.into_iter().filter(|k| !told.contains(k)).collect();
            if let Some(n) = shown(&id, &keys) {
                told.extend(n.1.iter().copied());
                out.push(n);
            }
        }
        out.sort();
        out
    }

    /// The devices that came in through each earlier change of root (the
    /// recovery record's ID, its seq and their keys), and the newest
    /// change with the devices that counted before it: for the app to
    /// save.
    pub fn arrivals(&self) -> (Vec<Arrival>, Option<Base>) {
        let fixed = self.arrivals.iter().map(|(id, (seq, keys))| (*id, *seq, keys.clone())).collect();
        (fixed, self.base.clone())
    }

    /// Takes back what the app saved (`arrivals`) after the set was
    /// restored: each for a recovery record the set holds at that seq.
    pub fn keep_arrivals(&mut self, fixed: &[Arrival], base: Option<Base>) {
        let held = |set: &RecordSet, id: &RecordId, seq: u64| {
            set.records.get(id).is_some_and(|e| e.role == Role::Recovery && e.record.body().seq == seq)
        };
        for (id, seq, keys) in fixed {
            if held(self, id, *seq) {
                self.arrive(*id, *seq, keys.clone());
            }
        }
        if let Some(b) = base.filter(|b| held(self, &b.change, b.seq) && b.before.len() <= super::MAX_DEVICES) {
            self.base = Some(b);
        }
    }

    /// Keeps the keys of the devices that came in through the change id
    /// at seq; past MAX_NOTICES the lowest seq goes.
    fn arrive(&mut self, id: RecordId, seq: u64, keys: Vec<KeyHash>) {
        if keys.is_empty() || self.dismissed.contains(&id) {
            return;
        }
        self.arrivals.insert(id, (seq, keys));
        while self.arrivals.len() > MAX_NOTICES {
            let lowest = self.arrivals.iter().min_by_key(|(id, (seq, _))| (*seq, **id)).map(|(id, _)| *id);
            let Some(lowest) = lowest else { break };
            self.arrivals.remove(&lowest);
        }
    }

    /// The keys of the devices of state that are not among before and
    /// that came in through the change: only the new root's re-issue (its
    /// records up to its first checkpoint) admits them, not its own device
    /// nor a record it wrote after.
    fn came_in(&self, state: &State, before: &BTreeSet<super::DeviceId>) -> Vec<KeyHash> {
        let Some(root) = state.roots.last() else { return Vec::new() };
        // The seq of the new root's first checkpoint, from the newest
        // change that applied.
        let first = state
            .chain()
            .last()
            .and_then(|id| self.held(id))
            .and_then(|r| match &r.body().kind {
                Kind::Recovery { first, .. } => self.held(first).map(|cp| cp.body().seq),
                _ => None,
            })
            .unwrap_or(0);
        let by_root = |dev: &super::DeviceId| {
            self.records.values().any(|e| {
                e.record.body().signer == *root
                    && state.counting.contains(&e.record.id())
                    && matches!(&e.record.body().kind, Kind::Device(d) if d.id() == *dev
                        && (d.holds_root || e.record.body().seq > first))
            })
        };
        state.devices.iter().filter(|d| !before.contains(&d.id) && !by_root(&d.id)).map(|d| d.key.hash()).collect()
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
        // The devices a dismissed removal notice told of are not told
        // again as having come in through the change.
        if let Some(Kind::Revoke(rm)) = self.notices.get(id).map(|r| r.body().kind.clone()) {
            if let Some(b) = self.base.as_mut() {
                b.before.extend(rm.keys.iter().map(super::DeviceId::of));
            }
            for (_, keys) in self.arrivals.values_mut() {
                keys.retain(|k| !rm.keys.contains(k));
            }
            self.arrivals.retain(|_, (_, keys)| !keys.is_empty());
        }
        self.notices.remove(id);
        self.arrivals.remove(id);
        if self.base.as_ref().is_some_and(|b| b.change == *id) {
            self.base = None;
        }
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
        self.reached = true;
        let added = self.insert_only(r, None);
        self.check_judged();
        added
    }

    fn insert_only(&mut self, r: Record, mark: Option<(&[u8; 32], &Mark)>) -> Result<Added, Refused> {
        // A group whose root key is its recovery key is no group: its set
        // takes nothing.
        if r.body().group != self.group || self.root == self.recovery.k1 {
            return Err(Refused::Group);
        }
        let id = r.id();
        if self.records.contains_key(&id) || self.kept_aside.contains_key(&id) {
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
            return self.insert_recovery(r, mark);
        }
        if !eval::is_first(&self.firsts, &r)
            && self.cuts.get(&signer).is_some_and(|cut| cut.covers(&signer, r.body().seq))
        {
            // A root before the current one: nothing of it stays, listed or
            // not (L: the cut roots have no room, `keep::reserve`), and it
            // is turned away before its signature is verified. Its removal
            // that comes after the change is a notice.
            if role == Role::Root && self.is_notice(&r) && !self.notices.contains_key(&id) {
                r.verify_marked(&key, mark).map_err(Refused::Broken)?;
                self.notice(r);
            }
            return Ok(Added::NoRoom);
        }
        // An admin key no root of the current era names (L: after a change
        // the admin keys of the roots before it have no room) is turned
        // away the same way, unless its record is a fork's proof or a held
        // checkpoint names it.
        if role == Role::Admin
            && !self.cuts.is_empty()
            && self.second.contains(&signer)
            && !self.wanted(&id)
            && !self.records.values().any(|e| e.record.body().signer == signer && e.record.body().seq == r.body().seq)
        {
            return Ok(Added::NoRoom);
        }
        // What the set would not keep is turned away before its signature
        // is verified: a record offered again after the set dropped it
        // costs no verification, and none of these steps stores it.
        // A second record of a key at a seq the set holds one of is the
        // proof of two histories, outside the rooms; a counting checkpoint
        // that covers it settles it, unless both are checkpoints
        // (`eval::proof_stays`).
        let twin_of = |set: &RecordSet| {
            matches!(role, Role::Root | Role::Admin)
                && set.records.values().any(|e| {
                    let b = e.record.body();
                    b.signer == signer && b.seq == r.body().seq && e.record.id() != id
                })
        };
        // Compaction memory decides here only whether the record is stored,
        // never the state: what it prunes, the evaluation leaves out too.
        let pruned = |set: &RecordSet| {
            set.checkpoints.iter().any(|(_, heads, anchors)| eval::pruned_by(&r, role, heads, anchors))
        };
        // What the newest list names, and a head's first checkpoint, are
        // kept whatever a checkpoint says.
        let listed = self.cuts.get(&signer).is_some_and(|cut| cut.covers(&signer, r.body().seq) && cut.keeps(&id));
        let first = eval::is_first(&self.firsts, &r);
        // What a checkpoint of the current root above the counting one
        // keeps goes to the place aside, after the judgment of the pair.
        // It walks the set's checkpoints, so it is asked only where it
        // decides.
        #[cfg(test)]
        let asked = OLD_WAITS.with(|o| o.get()).then(|| self.waits_for(&id));
        let waits = |set: &RecordSet| {
            #[cfg(test)]
            if let Some(w) = asked {
                return w;
            }
            set.waits_for(&id)
        };
        if role == Role::Root && !listed && !first && !twin_of(self) && pruned(self) && !self.links(&id) {
            // A root's record a counting checkpoint settled: alone it is
            // refused, but two at one seq are a fork at any depth, so the
            // set keeps it a while to make the pair with the other.
            let at = (r.body().seq, signer);
            let other = self
                .settled
                .get(&at)
                .map(|(_, o)| o)
                .or_else(|| self.halves.get(&at).map(|(_, o, _)| o))
                .or_else(|| self.aside_at(&at))
                .filter(|o| o.id() != id)
                .cloned();
            let held = r.verify_marked(&key, mark).map_err(Refused::Broken)?;
            self.arrived = self.arrived.saturating_add(1);
            let n = self.arrived;
            match other {
                Some(o) => {
                    self.settled.remove(&at);
                    self.halves.remove(&at);
                    let o_held = self.kept_aside.remove(&o.id()).is_some_and(|(_, _, h)| h);
                    self.store(o, role, o_held);
                }
                None => {
                    let seen = self.settled_ids.get(&at).map(|(_, i)| *i).filter(|i| *i != id);
                    if let Some(o) = seen {
                        // The other at this seq was verified and is gone:
                        // this one waits for it, and the set asks for it.
                        // A checkpoint above the counting one that keeps
                        // it has it aside too, as a half.
                        let copy = waits(self).then(|| r.clone());
                        self.halves.insert(at, (n, r, o));
                        while self.halves.len() > SETTLED_KEPT
                            || self.halves.values().map(|(_, r, _)| r.size()).sum::<usize>() > SETTLED_BYTES
                        {
                            let Some(old) = self.halves.iter().min_by_key(|(_, v)| v.0).map(|(k, _)| *k) else { break };
                            self.halves.remove(&old);
                        }
                        if let Some(r) = copy {
                            return Ok(self.put_aside(r, role, held));
                        }
                    } else {
                        self.remember(at, n, id);
                        if waits(self) {
                            return Ok(self.put_aside(r, role, held));
                        }
                        self.settled.insert(at, (n, r));
                        while self.settled.len() > SETTLED_KEPT
                            || self.settled.values().map(|(_, r)| r.size()).sum::<usize>() > SETTLED_BYTES
                        {
                            let Some(old) = self.settled.iter().min_by_key(|(_, v)| v.0).map(|(k, _)| *k) else {
                                break;
                            };
                            self.settled.remove(&old);
                        }
                    }
                    return Ok(Added::Settled { head: self.settled_head(&signer) });
                }
            }
        }
        let twin = twin_of(self);
        let twin_checkpoint = twin && matches!(r.body().kind, Kind::Checkpoint { .. });
        if !listed && !twin_checkpoint && !(twin && role == Role::Root) && !first && pruned(self) && !self.links(&id) {
            if role != Role::Root && waits(self) {
                let held = r.verify_marked(&key, mark).map_err(Refused::Broken)?;
                return Ok(self.put_aside(r, role, held));
            }
            // A counting checkpoint left it out.
            return Ok(Added::Settled { head: self.settled_head(&signer) });
        }
        // A record a held checkpoint names, which it may wait for to
        // count, is taken whatever the rooms say; they are judged after
        // the checkpoint's pruning.
        let wanted = self.wanted(&id) || self.newest_checkpoint(&r, role);
        // A checkpoint goes before the rest of its room only as its newest
        // (`keep::newest_only`).
        let mut item = eval::room_item(&r, role, &self.cuts);
        if item.checkpoint {
            let at = (item.seq, core::cmp::Reverse(item.id));
            item.checkpoint = self.records.values().all(|e| {
                let o = eval::room_item(&e.record, e.role, &self.cuts);
                !o.checkpoint || o.signer != item.signer || (o.seq, core::cmp::Reverse(o.id)) < at
            });
            item.older = !item.checkpoint;
        }
        // An older checkpoint is judged by the rooms after it is stored:
        // one that counts is kept first there, whatever came before it.
        // A root record that may change who is an admin is judged by the
        // rooms after it is stored too (`eval::not_live`).
        let tiers = self.moves_tiers(&r, role);
        if !twin && !first && !wanted && !item.older && !tiers && self.beyond(&item) && !waits(self) {
            // Past its key's last record, over its key's cap: the rooms
            // would not keep it.
            return Ok(Added::NoRoom);
        }
        let held = if self.trusted.contains(&id) {
            r.body().check().map_err(Refused::Broken)?
        } else {
            r.verify_marked(&key, mark).map_err(Refused::Broken)?
        };
        self.store(r, role, held);
        if twin && role == Role::Root {
            // The pair leaves the rooms: what they turned away before is
            // taken when offered again.
            self.cut();
        }
        // A checkpoint that may count now, or a record it names, compacts
        // before the rooms are judged: what it prunes takes no room, so
        // what stays does not depend on the order the two came in. A
        // record it named stays only if the rooms then hold it.
        let early = self.trusted.is_empty() && (wanted || self.may_count(&id));
        if early {
            self.settle();
        }
        if tiers || self.needs_cut(&signer) {
            self.cut();
        }
        let settles = !self.gaps.is_empty()
            && matches!(self.records.get(&id).map(|e| &e.record.body().kind), Some(Kind::Checkpoint { .. }));
        if (first || settles || self.gaps.contains(&id)) && self.trusted.is_empty() {
            // A head's first checkpoint, or the record its group lacked:
            // the head may apply now.
            self.rechain();
        }
        // A second history of a root halts the group and takes the
        // checkpoints above its fork out of the count: the set settles
        // again. It keeps them: what any of them left out stays out of the
        // change of root (`change_list`, `write_change`).
        // Compaction memory here only triggers a compaction (`settle`).
        let unsettles = role == Role::Root && twin && !self.checkpoints.is_empty();
        if self.trusted.is_empty() && self.records.contains_key(&id) && (unsettles || !early && self.may_count(&id)) {
            // A counting checkpoint compacts at once: what it leaves out
            // takes no room and is not held from the moment it counts, so
            // a member is in one state whenever it compacts.
            self.settle();
        }
        if self.trusted.is_empty() {
            // The rooms may have put aside the last of what a waiting
            // checkpoint names: it may count now.
            if self.switch() {
                self.cut();
                self.settle();
            }
            self.trim_aside();
        }
        Ok(if self.records.contains_key(&id) {
            Added::Stored
        } else if self.kept_aside.contains_key(&id) {
            Added::Waiting
        } else {
            Added::NoRoom
        })
    }

    /// Remembers id, a settled root record verified at `at` (seq, key),
    /// with the order n it came in (`settled_ids`).
    fn remember(&mut self, at: (u64, KeyHash), n: u64, id: RecordId) {
        self.settled_ids.insert(at, (n, id));
        while self.settled_ids.len() > SETTLED_IDS {
            let Some(old) = self.settled_ids.iter().min_by_key(|(_, v)| v.0).map(|(k, _)| *k) else {
                break;
            };
            self.settled_ids.remove(&old);
        }
    }

    /// The record of the place aside at `at` (seq, key), if any.
    fn aside_at(&self, at: &(u64, KeyHash)) -> Option<&Record> {
        self.kept_aside.values().map(|(r, _, _)| r).find(|r| (r.body().seq, r.body().signer) == *at)
    }

    /// Puts a verified record r, which role signed, in the place aside;
    /// a checkpoint whole with it then may count (`switch`).
    fn put_aside(&mut self, r: Record, role: Role, held: bool) -> Added {
        let id = r.id();
        self.kept_aside.insert(id, (r, role, held));
        if self.trusted.is_empty() && self.switch() {
            self.cut();
            self.settle();
        }
        self.trim_aside();
        if self.records.contains_key(&id) {
            Added::Stored
        } else if self.kept_aside.contains_key(&id) {
            Added::Waiting
        } else {
            Added::NoRoom
        }
    }

    /// The highest head the counting checkpoints name for signer. Only the
    /// caller reads it (`Added::Settled`), never the state.
    fn settled_head(&self, signer: &KeyHash) -> u64 {
        self.checkpoints
            .iter()
            .filter_map(|(_, heads, _)| heads.iter().find(|h| h.key == *signer).map(|h| h.seq))
            .max()
            .unwrap_or(0)
    }

    /// Stores a checked record r, which role signed.
    fn store(&mut self, r: Record, role: Role, held: bool) {
        let signer = r.body().signer;
        self.keys.learn(r.body(), role, held);
        let units = self.units.entry(signer).or_default();
        *units = units.saturating_add(eval::item(&r, role).units);
        self.bytes = self.bytes.saturating_add(r.size());
        self.records.insert(r.id(), Entry { record: r, role, held });
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
        // A later checkpoint may settle the record a change lacks.
        let settles = !self.gaps.is_empty()
            && matches!(self.early.get(&id).map(|r| &r.body().kind), Some(Kind::Checkpoint { .. }));
        let names = self.gaps.contains(&id)
            || settles
            || self
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
    /// ID: what stays does not depend on the order they came in. A first
    /// checkpoint the chain waits for stays outside that room, as it does
    /// in the set: without it the chain never applies, and the records of
    /// earlier roots that fill the room would hold it out for good.
    fn trim_early(&mut self) {
        // The newest head's group goes first once its first checkpoint is
        // held: the new root's records up to it. The chain applies only
        // with the whole group (`eval::first_gap`), and it applies every
        // head before it with it. A record of the group trimmed before
        // the checkpoint came is asked for again (`State::first_missing`).
        let newest = self
            .records
            .values()
            .filter(|e| e.role == Role::Recovery)
            .max_by_key(|e| (e.record.body().seq, e.record.id()))
            .and_then(|e| match &e.record.body().kind {
                Kind::Recovery { root, first, .. } => Some((root.hash(), *first)),
                _ => None,
            });
        let group_top = newest.map(|(h, first)| {
            let top = self.early.get(&first).or_else(|| self.held(&first)).map_or(0, |r| r.body().seq);
            (h, top)
        });
        let in_group = |r: &Record| group_top.is_some_and(|(h, top)| r.body().signer == h && r.body().seq <= top);
        let rank = |r: &Record| {
            if in_group(r) {
                0
            } else {
                self.early_roots.get(&r.body().signer).map_or(u64::MAX, |(s, _)| s.saturating_add(1))
            }
        };
        let mut all: Vec<(u64, u64, RecordId, u64)> = self
            .early
            .values()
            .filter(|r| !eval::is_first(&self.firsts, r))
            .map(|r| (rank(r), r.body().seq, r.id(), eval::item(r, Role::Root).units))
            .collect();
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
    fn insert_recovery(&mut self, r: Record, mark: Option<(&[u8; 32], &Mark)>) -> Result<Added, Refused> {
        let held = r.verify_head_marked(&self.recovery, mark).map_err(Refused::Broken)?;
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
        let out = self.insert_all_marked(records.into_iter().map(|r| (r, None)), None);
        self.check_judged();
        out
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
        let out = self.insert_all_marked(records, Some(local));
        self.check_judged();
        out
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
        if local.is_none() {
            self.reached = true;
        }
        let mut stored: Vec<RecordId> = Vec::new();
        let mut refused = Vec::new();
        // Two records of one key at one seq that come together are judged
        // together, first and one after the other: whatever the set pruned
        // and whatever it remembers, the second makes the pair.
        let mut records: Vec<(Record, Option<Mark>)> = records.into_iter().collect();
        let mut ids_at: BTreeMap<(KeyHash, u64), BTreeSet<RecordId>> = BTreeMap::new();
        for (r, _) in &records {
            ids_at.entry((r.body().signer, r.body().seq)).or_default().insert(r.id());
        }
        let paired = |r: &Record| ids_at.get(&(r.body().signer, r.body().seq)).is_some_and(|ids| ids.len() > 1);
        records.sort_by_key(
            |(r, _)| if paired(r) { (0, r.body().signer, r.body().seq) } else { (1, KeyHash([0; 32]), 0) },
        );
        // Only the records that wait for their signer are held aside; the
        // others go straight in.
        let mut waiting = Vec::new();
        // The rooms are a function of what is held: judged once, over the
        // set and the whole batch, the batch ends where the same records
        // at once would, whatever their order.
        let outer = self.batch.is_some();
        if !outer {
            self.batch = Some(false);
        }
        let mut progress = self.insert_each(records, local, &mut waiting, &mut stored, &mut refused);
        while progress && !waiting.is_empty() {
            let todo = core::mem::take(&mut waiting);
            progress = self.insert_each(todo, local, &mut waiting, &mut stored, &mut refused);
        }
        if !outer && self.batch.take() == Some(true) {
            // Judged once over the set and the whole batch: what the rooms
            // turn away is final (held == f(held ∪ batch)); nothing is
            // offered again. The place aside is judged in the same pass,
            // after the counting checkpoints compacted: a checkpoint of the
            // root the rooms turned away has a place aside when it waits
            // above the one that counts, as when it came after them.
            self.turned = Some(Vec::new());
            self.cut();
            if self.trusted.is_empty() {
                self.settle();
                self.aside_turned();
                if self.switch() {
                    self.cut();
                    self.settle();
                }
                self.trim_aside();
            }
            self.turned = None;
        }
        refused.extend(waiting.iter().map(|(r, _)| (r.id(), Refused::UnknownSigner)));
        // What the judgment turned away is not stored.
        let stored = stored.iter().filter(|id| self.records.contains_key(*id)).count();
        (stored, refused)
    }

    /// One round of insert_all: whether it stored any.
    fn insert_each(
        &mut self,
        records: impl IntoIterator<Item = (Record, Option<Mark>)>,
        local: Option<&[u8; 32]>,
        waiting: &mut Vec<(Record, Option<Mark>)>,
        stored: &mut Vec<RecordId>,
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
                    stored.push(id);
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
        let chain = eval::chain(
            &self.root_hash,
            self.records.values().map(|e| (&e.record, e.role)),
            &lists,
            |id, root, from, settle| eval::first_gap(&held, &self.checkpoints, settle, id, root, from),
        );
        let path = chain.path(&self.root_hash);
        let mut cuts = chain.cuts();
        self.waiting = chain.waiting;
        self.gaps = chain.gaps.clone();
        self.firsts = chain.firsts.clone();
        // Halted by a recovery fork: the set holds the recovery key's
        // records and nothing else, so that every member holding the proof
        // holds the same; the group is stopped for good. A recovery record
        // this version cannot read stops the group only until the update:
        // the set keeps what it holds, and nothing else counts meanwhile.
        self.halted = (!chain.fork.is_empty()).then(BTreeSet::new);
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
        self.early_roots = if self.halted.is_some() { BTreeMap::new() } else { chain.waiting_roots(&self.root_hash) };
        // Halted, no checkpoint counts: the cut is the list as it stands.
        if let (Some(old), Some(new)) = (self.cuts.values().next(), cuts.values().next())
            && old.record == new.record
            && self.halted.is_none()
        {
            cuts = self.cuts.clone();
        }
        // A change of root the set applies now: what counted before it.
        let change = cuts
            .values()
            .next()
            .map(|c| c.record)
            .filter(|r| self.halted.is_none() && self.cuts.values().next().map(|c| c.record) != Some(*r));
        let before = change.and_then(|r| self.held(&r).map(|x| x.body().seq)).map(|seq| (seq, self.state_before(seq)));
        self.keep_by(path, cuts);
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
        // A key a waiting record now names as root (an admin's, say) has
        // its records kept aside, as they are when they come after that
        // record: where they stay does not depend on the order.
        let aside: Vec<RecordId> = self
            .records
            .values()
            .filter(|e| {
                let k = e.record.body().signer;
                e.role != Role::Recovery && self.early_roots.contains_key(&k) && !self.promoted.contains(&k)
            })
            .map(|e| e.record.id())
            .collect();
        for id in &aside {
            if let Some(r) = self.held(id).cloned() {
                self.remove(id);
                self.early.insert(*id, r);
            }
        }
        if !aside.is_empty() {
            self.relearn();
        }
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
        if let (Some(id), Some((seq, before))) = (change, before) {
            // The change before it is fixed as it stood then.
            if let Some(old) = self.base.take() {
                let keys = self.came_in(&before, &old.before);
                self.arrive(old.change, old.seq, keys);
            }
            if !self.dismissed.contains(&id) {
                let devices = before.devices.iter().map(|d| d.id).collect();
                self.base = Some(Base { change: id, seq, before: devices });
            }
        }
        // A root the path left has nothing aside, nor a halted set.
        self.trim_aside();
    }

    /// The state as it was before the recovery records at seq and after:
    /// what counted before the change of root.
    fn state_before(&self, seq: u64) -> State {
        let lists = self.list_refs();
        let by = eval::Compacted { proven: &self.checkpoints };
        let checked: Vec<Checked<'_>> =
            self.checked().into_iter().filter(|c| !(c.role == Role::Recovery && c.r.body().seq >= seq)).collect();
        eval::evaluate_checked(&self.root, &self.recovery, checked, BTreeMap::new(), &lists, &by, &[])
    }

    /// Keeps by the roots promoted and the cuts: when they changed, the
    /// keys are learned again and the set's count starts again.
    fn keep_by(&mut self, path: Vec<KeyHash>, cuts: BTreeMap<KeyHash, Cut>) {
        let promoted: BTreeSet<KeyHash> = path.iter().skip(1).copied().collect();
        if promoted != self.promoted || cuts != self.cuts || path != self.path {
            self.promoted = promoted;
            self.path = path;
            self.cuts = cuts;
            // What the newest list drops goes first: an admin key only a
            // dropped record named is then no key of the set.
            self.drop_off_cuts();
            self.relearn();
            self.cut();
        }
    }

    /// Drops the records the set does not keep (`keep`): each key within
    /// its cap, which the roster fixes. What is kept depends on the records
    /// held alone, and dropping what is not kept changes nothing. The
    /// recovery key's records are outside the rooms.
    fn cut(&mut self) {
        if let Some(due) = self.batch.as_mut() {
            *due = true;
            return;
        }
        self.drop_off_cuts();
        let j = self.judge();
        // Who is no longer an admin, as the rooms just read it (`beyond`).
        self.second = j.second;
        // A record the rooms turned away may be the only one that named an
        // admin key: that key's records then have no known signer, as in
        // an evaluation of what the set keeps, and go too.
        let names_key = j
            .drop
            .iter()
            .any(|id| self.held(id).is_some_and(|r| matches!(&r.body().kind, Kind::Device(d) if d.admin.is_some())));
        for id in j.drop {
            self.drop_or_aside(&id, &j.wanted);
        }
        if names_key {
            self.relearn();
        }
        self.pre = j.pre;
        self.trim_aside();
    }

    /// The rooms judged over what the set holds now, without changing it
    /// (`cut` applies it): what goes, and what the caps read.
    fn judge(&self) -> Judged {
        let mut proof = self.proof();
        // Each root's checkpoint that may count is kept first with what it
        // names: the rooms are judged in the set it prunes, and it takes
        // its part of them before the others (`keep::keep_tiers`). What the
        // rooms turn away that a checkpoint of the current root above the
        // counting one keeps goes to the place aside.
        let (first, above) = self.line();
        let wanted = self.aside_wanted(&above);
        let mut pre: BTreeMap<KeyHash, u64> = BTreeMap::new();
        let mut firsts: Vec<keep::Item> = Vec::new();
        for id in first.iter().filter(|id| !proof.contains(*id)) {
            if let Some(e) = self.records.get(id) {
                let it = eval::room_item(&e.record, self.role_of(e), &self.cuts);
                let u = pre.entry(it.signer).or_default();
                *u = u.saturating_add(it.units);
                firsts.push(it);
            }
        }
        proof.extend(first);
        let mut items: Vec<keep::Item> = self
            .records
            .values()
            .filter(|e| {
                self.role_of(e) != Role::Recovery
                    && !proof.contains(&e.record.id())
                    && !eval::is_first(&self.firsts, &e.record)
            })
            .map(|e| eval::room_item(&e.record, self.role_of(e), &self.cuts))
            .collect();
        keep::newest_only(&mut items, &firsts);
        // Who is no longer an admin is read from the root records the
        // roots' rooms keep (`eval::rooms`).
        let ceilings: BTreeMap<KeyHash, Option<u64>> =
            items.iter().map(|it| (it.signer, self.ceiling(&it.signer))).collect();
        let (kept, second) = eval::rooms(
            &mut items,
            |k| ceilings.get(k).copied().flatten(),
            &pre,
            &self.path,
            &self.cuts,
            self.records
                .values()
                .filter(|e| !eval::off_cut(&self.cuts, &e.record))
                .map(|e| (&e.record, self.role_of(e))),
        );
        let drop: Vec<RecordId> = self
            .records
            .values()
            .filter(|e| {
                self.role_of(e) != Role::Recovery
                    && !kept.contains(&e.record.id())
                    && !proof.contains(&e.record.id())
                    && !eval::is_first(&self.firsts, &e.record)
            })
            .map(|e| e.record.id())
            .collect();
        Judged { drop, pre, second, wanted }
    }

    /// Checks, in debug builds, that what the set holds is what the rooms
    /// keep of it (held == f(held)): any path that stores a record
    /// without judging the rooms where they would turn something away
    /// fails at once. Not inside a batch, which is judged when it is in,
    /// nor while trusted records are restored.
    fn check_judged(&self) {
        #[cfg(all(debug_assertions, feature = "std"))]
        if self.batch.is_none() && self.trusted.is_empty() && !UNCHECKED.with(core::cell::Cell::get) {
            let j = self.judge();
            debug_assert!(j.drop.is_empty(), "the set holds {} records the rooms would turn away", j.drop.len());
            self.check_state();
        }
    }

    /// Debug builds: the set's state is the evaluation from scratch of
    /// every record it holds (those aside too) and its lists. After every
    /// insert under `check_every_insert` and while the set is small; then
    /// every 64th time up to 1024 records, aside ones included, and every
    /// 4096th beyond, since the evaluation verifies every signature again.
    #[cfg(all(debug_assertions, feature = "std"))]
    fn check_state(&self) {
        let n = STATE_CHECKS.with(|c| {
            let n = c.get().wrapping_add(1);
            c.set(n);
            n
        });
        #[cfg(test)]
        let every = STATE_EVERY.with(core::cell::Cell::get);
        #[cfg(not(test))]
        let every = false;
        let due = match self.records.len().saturating_add(self.early.len()) {
            0..=32 => true,
            33..=1024 => n.is_multiple_of(64),
            _ => n.is_multiple_of(4096),
        };
        if !every && !due {
            return;
        }
        let counted: Vec<Record> =
            self.records.values().map(|e| e.record.clone()).chain(self.early.values().cloned()).collect();
        let lists: Vec<Vec<u8>> = self.lists.values().map(|(b, _)| b.clone()).collect();
        #[cfg(test)]
        let verified = super::VERIFIED.with(core::cell::Cell::get);
        let fresh = eval::evaluate(&eval::Input {
            root: &self.root,
            recovery: &self.recovery,
            records: &counted,
            lists: &lists,
        });
        // The tests that count signatures count the set's own.
        #[cfg(test)]
        super::VERIFIED.with(|v| v.set(verified));
        debug_assert_eq!(self.state(), fresh, "the set's state is not the evaluation of what it holds");
    }

    /// Whether signer, which signs as role, is a root on the set's path.
    fn on_path(&self, signer: &KeyHash, role: Role) -> bool {
        role == Role::Root && (*signer == self.root_hash || self.promoted.contains(signer))
    }

    /// The newest checkpoint of each root the set holds, of a root a
    /// change cut not one its list covers: what the evaluation tries
    /// first, whatever the rooms hold.
    fn kept_first(&self) -> BTreeSet<RecordId> {
        let mut newest: BTreeMap<KeyHash, (u64, RecordId)> = BTreeMap::new();
        for e in self.records.values() {
            let b = e.record.body();
            if e.held || !self.on_path(&b.signer, e.role) || !matches!(b.kind, Kind::Checkpoint { .. }) {
                continue;
            }
            if self.cuts.get(&b.signer).is_some_and(|c| c.covers(&b.signer, b.seq)) {
                continue;
            }
            let id = e.record.id();
            let better = newest.get(&b.signer).is_none_or(|(s, o)| b.seq > *s || b.seq == *s && id < *o);
            if better {
                newest.insert(b.signer, (b.seq, id));
            }
        }
        newest.into_values().map(|(_, id)| id).collect()
    }

    /// Whether a checkpoint of the current root above its counting one
    /// keeps id: it is taken though the counting one settled it, into the
    /// place aside (`kept_aside`).
    fn waits_for(&self, id: &RecordId) -> bool {
        self.aside_wanted(&self.line().1).contains(id)
    }

    /// What the checkpoints `above` keep: the place aside may hold these.
    fn aside_wanted(&self, above: &[RecordId]) -> BTreeSet<RecordId> {
        let mut out = BTreeSet::new();
        for cp in above {
            if let Some(r) = self.get(cp) {
                out.extend(Self::named_by(r));
            }
        }
        out
    }

    /// What a waiting checkpoint names: itself, what it keeps, and the
    /// record of its key just below it (its prev), which it waits for.
    fn named_by(cp: &Record) -> Vec<RecordId> {
        let mut out = alloc::vec![cp.id()];
        if let Kind::Checkpoint { keep, .. } = &cp.body().kind {
            out.extend(keep.iter().copied());
        }
        out.extend(cp.body().prev);
        out
    }

    /// The current root: the root of the newest change applied, else the
    /// group's first.
    fn current_root(&self) -> KeyHash {
        self.cuts.values().next().map_or(self.root_hash, |c| c.current)
    }

    /// The lowest seq at which the set holds two records of key k: its
    /// fork seq, when it holds the pair.
    fn fork_seq(&self, k: &KeyHash) -> Option<u64> {
        let mut at: BTreeMap<u64, RecordId> = BTreeMap::new();
        let mut fork: Option<u64> = None;
        for e in self.records.values().filter(|e| e.record.body().signer == *k) {
            let seq = e.record.body().seq;
            if at.insert(seq, e.record.id()).is_some_and(|o| o != e.record.id()) {
                fork = Some(fork.map_or(seq, |f| f.min(seq)));
            }
        }
        fork
    }

    /// Whether checkpoint cp may count on the records the set holds, with
    /// those of the place aside when aside: whole (`eval::checkpoint_ok`)
    /// and what it names fits the rooms on its own (`eval::fits_alone`).
    fn may_count_with(&self, cp: &Record, aside: bool) -> bool {
        let rec = |id: &RecordId| {
            self.records
                .get(id)
                .map(|n| (&n.record, self.role_of(n)))
                .or_else(|| aside.then(|| self.kept_aside.get(id).map(|(r, role, _)| (r, *role))).flatten())
        };
        // Whole first: a record it keeps that the set lacks ends it there.
        eval::checkpoint_ok(cp, |id| rec(id).map(|(r, _)| r)) && {
            let named = self.named_held(cp, aside, |id| rec(id).is_some());
            eval::fits_alone(named.iter().filter_map(rec), &self.root_hash, &self.promoted, &self.cuts)
        }
    }

    /// Whether what a checkpoint names, of what the set holds or keeps
    /// aside, fits the rooms on its own: once it does not, it never will,
    /// as more of what it names only adds units.
    fn could_fit(&self, cp: &Record) -> bool {
        let rec = |id: &RecordId| {
            self.records
                .get(id)
                .map(|n| (&n.record, self.role_of(n)))
                .or_else(|| self.kept_aside.get(id).map(|(r, role, _)| (r, *role)))
                .or_else(|| (*id == cp.id()).then_some((cp, Role::Root)))
        };
        let named = self.named_held(cp, true, |id| rec(id).is_some());
        eval::fits_alone(named.iter().filter_map(rec), &self.root_hash, &self.promoted, &self.cuts)
    }

    /// `eval::named_first` of what the set holds (and with aside, of what
    /// it keeps aside), held telling which: a checkpoint that keeps more
    /// IDs than the set has records is read from the records' side.
    fn named_held(&self, cp: &Record, aside: bool, held: impl Fn(&RecordId) -> bool) -> BTreeSet<RecordId> {
        let Kind::Checkpoint { keep, .. } = &cp.body().kind else { return eval::named_first(cp, held) };
        let ours = self.records.len().saturating_add(if aside { self.kept_aside.len() } else { 0 });
        if keep.len() <= ours {
            return eval::named_first(cp, held);
        }
        let mut out = BTreeSet::from([cp.id()]);
        let mine = self.records.keys().chain(self.kept_aside.keys().filter(|_| aside));
        out.extend(mine.filter(|id| keep.binary_search(id).is_ok() && held(id)).copied());
        out.extend(cp.body().prev.filter(|id| held(id)));
        out
    }

    /// The records kept ahead of the rooms, and the current root's
    /// checkpoints that may wait. Of each root on the path, the
    /// newest checkpoint that is whole and whose named records fit the
    /// rooms on their own is the one that may count: it and what it names
    /// are kept first (`eval::named_first`, `eval::fits_alone`). Nothing
    /// that waits is kept first: the checkpoints above the counting one
    /// are ordinary records of the root's room, and one the room turns
    /// away waits aside with what it names. A checkpoint whose named
    /// records do not fit the rooms on their own never waits.
    ///
    /// What is kept first, and the current root's
    /// checkpoints above its counting one, newest first, of two at one seq
    /// the smaller ID first: those that may wait. None waits while the set
    /// is halted, nor at or above the fork seq of the current root while
    /// the set holds its pair.
    fn line(&self) -> (BTreeSet<RecordId>, Vec<RecordId>) {
        let mut by_root: BTreeMap<KeyHash, Vec<(u64, RecordId)>> = BTreeMap::new();
        // The checkpoints the set holds, and those the rooms turned away
        // that wait aside: a waiting checkpoint is an ordinary record of
        // its root's room, held aside when the room has no place for it.
        let aside = self.kept_aside.values().map(|(r, role, held)| (r, *role, *held));
        for (r, role, held) in self.records.values().map(|e| (&e.record, e.role, e.held)).chain(aside) {
            let b = r.body();
            if held || !self.on_path(&b.signer, role) || !matches!(b.kind, Kind::Checkpoint { .. }) {
                continue;
            }
            if self.cuts.get(&b.signer).is_some_and(|c| c.covers(&b.signer, b.seq)) {
                continue;
            }
            by_root.entry(b.signer).or_default().push((b.seq, r.id()));
        }
        let floor = eval::first_floor(&self.firsts, |id| self.records.get(id).map(|n| &n.record));
        by_root.retain(|k, cps| {
            cps.retain(|(seq, _)| floor.get(k).is_none_or(|f| seq >= f));
            !cps.is_empty()
        });
        let current = self.current_root();
        let (mut first, mut above) = (BTreeSet::new(), Vec::new());
        for (root, cps) in by_root.iter_mut() {
            // Newest first; of two at one seq the smaller ID.
            cps.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(&b.1)));
            // While the current root has two histories nothing at or above
            // the fork seq counts (as in the evaluation).
            let fork = if *root == current { self.fork_seq(root) } else { None };
            let counts = |seq: u64, id: &RecordId| {
                fork.is_none_or(|f| seq < f) && self.held(id).is_some_and(|r| self.may_count_with(r, false))
            };
            let at = cps.iter().position(|(seq, id)| counts(*seq, id));
            if let Some(e) = at.and_then(|i| cps.get(i)).and_then(|(_, id)| self.held(id)) {
                first.extend(eval::named_first(e, |id| self.records.contains_key(id)));
            }
            if *root == current && self.halted.is_none() {
                let end = at.unwrap_or(cps.len());
                // One whose named records already fail the rooms on their
                // own never counts: it is an ordinary record and waits for
                // nothing.
                above.extend(
                    cps.iter()
                        .take(end)
                        .filter(|(seq, _)| fork.is_none_or(|f| *seq < f))
                        .filter(|(_, id)| self.get(id).is_some_and(|cp| self.could_fit(cp)))
                        .map(|(_, id)| *id),
                );
            }
        }
        (first, above)
    }

    /// Takes into the set what the place aside holds for the newest
    /// checkpoint of the current root above its counting one that is whole
    /// with it and may count: reports whether it took any. The set then
    /// judges its rooms and compacts by that checkpoint.
    fn switch(&mut self) -> bool {
        if self.kept_aside.is_empty() {
            return false;
        }
        if let Some(due) = self.batch.as_mut() {
            *due = true;
            return false;
        }
        let (_, above) = self.line();
        let keep: Vec<RecordId> = above
            .iter()
            .filter_map(|id| self.get(id))
            .find_map(|cp| {
                let named = Self::named_by(cp);
                (named.iter().any(|id| self.kept_aside.contains_key(id)) && self.may_count_with(cp, true))
                    .then_some(named)
            })
            .unwrap_or_default();
        let mut todo: Vec<(Record, Role, bool)> = keep.iter().filter_map(|id| self.kept_aside.remove(id)).collect();
        // Each after the record that names its signer.
        todo.sort_by_key(|(r, _, _)| eval::order_key(r.body(), &r.id()));
        let mut took = false;
        loop {
            let mut rest = Vec::new();
            let mut progress = false;
            for (r, role, held) in todo {
                match self.keys.signer(&r.body().signer) {
                    Some((_, now)) => {
                        self.store(r, now, held);
                        progress = true;
                        took = true;
                    }
                    None => rest.push((r, role, held)),
                }
            }
            if rest.is_empty() || !progress {
                for (r, role, held) in rest {
                    self.kept_aside.insert(r.id(), (r, role, held));
                }
                return took;
            }
            todo = rest;
        }
    }

    /// Keeps the place aside to what a checkpoint of the current root
    /// above its counting one keeps that the set does not hold among the
    /// rest, within one ROOM of units: what the newest of them keeps first,
    /// then the next newest, each by the lowest (seq, ID); never by
    /// arrival. An honest root's newest checkpoint is the one that becomes
    /// whole, and its writer keeps nothing it pruned. A root
    /// record that leaves it leaves its (seq, key, ID) remembered, so that
    /// the other record at that seq still makes the pair.
    fn trim_aside(&mut self) {
        if self.kept_aside.is_empty() {
            return;
        }
        // The place aside is judged with the rooms, once a batch is in.
        if let Some(due) = self.batch.as_mut() {
            *due = true;
            return;
        }
        let (_, above) = self.line();
        // Each wanted record by the newest checkpoint that keeps it: what
        // the newest keeps stays first, then the next, each by (seq, ID).
        // The checkpoint itself before what it names.
        let mut by: BTreeMap<RecordId, (usize, u8)> = BTreeMap::new();
        for (i, cp) in above.iter().enumerate() {
            by.entry(*cp).or_insert((i, 0));
            if let Some(r) = self.get(cp) {
                for id in Self::named_by(r) {
                    by.entry(id).or_insert((i, 1));
                }
            }
        }
        let mut rank: Vec<((usize, u8), u64, RecordId, u64)> = self
            .kept_aside
            .iter()
            .filter(|(id, _)| !self.records.contains_key(*id))
            .filter_map(|(id, (r, role, _))| Some((*by.get(id)?, r.body().seq, *id, eval::item(r, *role).units)))
            .collect();
        rank.sort();
        let mut units = 0u64;
        let mut keep = BTreeSet::new();
        for (_, _, id, u) in rank {
            units = units.saturating_add(u);
            if units <= keep::room() {
                keep.insert(id);
            }
        }
        let gone: Vec<RecordId> = self.kept_aside.keys().filter(|id| !keep.contains(*id)).copied().collect();
        for id in gone {
            if !self.records.contains_key(&id) {
                self.no_room.insert(id);
            }
            if let Some((r, role, _)) = self.kept_aside.remove(&id)
                && role == Role::Root
                && !self.records.contains_key(&id)
            {
                let at = (r.body().seq, r.body().signer);
                if self.settled_ids.get(&at).is_none_or(|(_, o)| *o == id) {
                    self.arrived = self.arrived.saturating_add(1);
                    let n = self.arrived;
                    self.remember(at, n, id);
                }
            }
        }
    }

    /// Takes id out of the rooms: into the place aside when a checkpoint of
    /// the current root above its counting one keeps it (`wanted`), else
    /// out of the set.
    fn drop_or_aside(&mut self, id: &RecordId, wanted: &BTreeSet<RecordId>) {
        if wanted.contains(id)
            && let Some(e) = self.records.get(id)
        {
            let (r, role, held) = (e.record.clone(), self.role_of(e), e.held);
            self.remove(id);
            self.kept_aside.insert(*id, (r, role, held));
            return;
        }
        if let Some(e) = self.records.get(id)
            && self.turned.is_some()
            && self.on_path(&e.record.body().signer, e.role)
            && matches!(e.record.body().kind, Kind::Checkpoint { .. })
        {
            let t = (e.record.clone(), e.role, e.held);
            if let Some(turned) = self.turned.as_mut() {
                turned.push(t);
            }
        }
        self.remove(id);
    }

    /// The root's checkpoints a batch's rooms turned away (`turned`) that
    /// wait above the counting checkpoint go to the place aside, as one
    /// that came after the rooms judged would: each is tried there, and
    /// only those a checkpoint above the counting one names stay
    /// (`aside_wanted`), within the place's room (`trim_aside`).
    fn aside_turned(&mut self) {
        let turned = self.turned.take().unwrap_or_default();
        let mut tried = Vec::new();
        for (r, role, held) in turned {
            let id = r.id();
            if !self.records.contains_key(&id) && !self.kept_aside.contains_key(&id) {
                self.kept_aside.insert(id, (r, role, held));
                tried.push(id);
            }
        }
        if tried.is_empty() {
            return;
        }
        let wanted = self.aside_wanted(&self.line().1);
        for id in tried.iter().filter(|id| !wanted.contains(*id)) {
            self.kept_aside.remove(id);
        }
    }

    /// Whether r, which role signed, would be its root's newest
    /// checkpoint (`kept_first`): no earlier drop turns it away.
    fn newest_checkpoint(&self, r: &Record, role: Role) -> bool {
        let b = r.body();
        self.on_path(&b.signer, role)
            && matches!(b.kind, Kind::Checkpoint { .. })
            && !self.cuts.get(&b.signer).is_some_and(|c| c.covers(&b.signer, b.seq))
            && !self.records.values().any(|e| {
                let o = e.record.body();
                o.signer == b.signer
                    && matches!(o.kind, Kind::Checkpoint { .. })
                    && (o.seq > b.seq || o.seq == b.seq && e.record.id() < r.id())
            })
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
        off.retain(|id| !self.held(id).is_some_and(|r| eval::is_first(&self.firsts, r)));
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

    /// Whether a root's record may change who is an admin: a removal, or
    /// a device record whose admin key differs from another root record's
    /// of the same device (`eval::not_live`).
    fn moves_tiers(&self, r: &Record, role: Role) -> bool {
        if role != Role::Root {
            return false;
        }
        match &r.body().kind {
            Kind::Revoke(_) => true,
            // A new admin key may put another past the first 16.
            Kind::Device(d) if d.admin.is_some() => true,
            Kind::Device(d) => {
                let a = d.admin.as_ref().map(Key::hash);
                self.records.values().any(|e| {
                    self.role_of(e) == Role::Root
                        && matches!(&e.record.body().kind, Kind::Device(o) if o.id() == d.id() && o.admin.as_ref().map(Key::hash) != a)
                })
            }
            _ => false,
        }
    }

    /// Whether the rooms would turn item away, told before its signature
    /// is checked: it comes after every record its key holds, and with it
    /// the key would pass its cap, which the roster fixes, so the rooms
    /// over what is held and item would not keep it either.
    fn beyond(&self, item: &keep::Item) -> bool {
        // A batch is judged once, when it is in: nothing before.
        if item.checkpoint || item.early || self.batch.is_some() {
            return false;
        }
        let k = self.room_key(&item.signer);
        let Some(share) = self.cap(&k) else { return false };
        // All the key holds, first records too: if even that fits, it does.
        let all = self.units.iter().filter(|(s, _)| self.room_key(s) == k).fold(0u64, |t, (_, u)| t.saturating_add(*u));
        if all.saturating_add(item.units) <= share {
            return false;
        }
        // The key's records in its room, as the rooms count them (a fork's
        // proof is of one signer's records, so it is read from these).
        let of_key: Vec<&Entry> = self
            .records
            .values()
            .filter(|e| e.role != Role::Recovery && self.room_key(&e.record.body().signer) == k)
            .collect();
        let proof = eval::fork_proof(of_key.iter().map(|e| (&e.record, self.role_of(e))));
        let mine: Vec<keep::Item> = of_key
            .iter()
            .filter(|e| !proof.contains(&e.record.id()) && !eval::is_first(&self.firsts, &e.record))
            .map(|e| eval::room_item(&e.record, self.role_of(e), &self.cuts))
            .collect();
        let held = mine.iter().fold(0u64, |t, it| t.saturating_add(it.units));
        let pos = item.pos();
        held.saturating_add(item.units) > share && mine.iter().all(|it| it.pos() < pos)
    }

    /// Whether the rooms must be judged after signer's record is stored:
    /// its room passes its cap. Each key's cap hangs on the roster alone
    /// (`keep::keep_tiers`), so below it the key keeps all it holds and no
    /// other key is touched.
    fn needs_cut(&self, signer: &KeyHash) -> bool {
        // By room: the cut roots share one.
        let mut by_room: BTreeMap<KeyHash, u64> = BTreeMap::new();
        for (k, u) in &self.units {
            let e = by_room.entry(self.room_key(k)).or_default();
            *e = e.saturating_add(*u);
        }
        let signer = &self.room_key(signer);
        let units = by_room.get(signer).copied().unwrap_or(0);
        self.cap(signer).is_none_or(|c| units > c)
    }

    /// The cap in units of the room key's records go to (the cut roots
    /// share one, `room_key`), from the roster the rooms last read: a
    /// root's or the reserve's ceiling, a live admin key's ceiling, 0 for
    /// a key that is no longer an admin or not among the live ones; None
    /// for a key with no room. What it holds first (`pre`) counts in it.
    fn cap(&self, key: &KeyHash) -> Option<u64> {
        let k = self.room_key(key);
        let ceiling = self.ceiling(&k)?;
        Some(if self.second.contains(&k) { 0 } else { ceiling })
    }

    /// A key's ceiling: a root's on the path, an admin key's, or None for
    /// any other.
    fn ceiling(&self, k: &KeyHash) -> Option<u64> {
        if *k == eval::CUT_ROOTS {
            return Some(keep::reserve());
        }
        let admins: BTreeSet<KeyHash> = if self.keys.is_admin(k) { BTreeSet::from([*k]) } else { BTreeSet::new() };
        eval::ceiling_of(&self.root_hash, &self.promoted, &admins, k)
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

    /// The room a key's records take: the cut roots share one.
    fn room_key(&self, k: &KeyHash) -> KeyHash {
        if eval::is_cut_root(&self.cuts, k) { eval::CUT_ROOTS } else { *k }
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

    /// The current root's checkpoints the set holds while two histories of
    /// that root stop the group, counting or not, each history's: what any
    /// of them leaves out stays out of the change of root that ends the
    /// stop, but a root's removal, which counts on either history.
    fn lines(&self, state: &State) -> Vec<RecordId> {
        let Some(cur) = state.roots.last() else { return Vec::new() };
        let halted = state.conflicts.iter().any(|c| c.kind == eval::ConflictKind::TwoHistories && c.signers == [*cur]);
        if !halted {
            return Vec::new();
        }
        self.records
            .values()
            .filter(|e| e.role == Role::Root && !e.held && e.record.body().signer == *cur)
            .filter(|e| matches!(e.record.body().kind, Kind::Checkpoint { .. }))
            .map(|e| e.record.id())
            .collect()
    }

    /// Whether one of the checkpoints `lines` gives leaves id out.
    fn left_out(&self, lines: &[RecordId], id: &RecordId) -> bool {
        let Some(e) = self.records.get(id) else { return false };
        if e.role == Role::Root && matches!(e.record.body().kind, Kind::Revoke(_)) {
            return false;
        }
        lines.iter().filter_map(|cp| self.held(cp)).any(|cp| match &cp.body().kind {
            Kind::Checkpoint { heads, keep } => {
                eval::pruned_by(&e.record, e.role, heads, &eval::anchors_of(heads, keep))
            }
            _ => false,
        })
    }

    /// The root removals the fold leaves out: a removal of a root on the
    /// path folds into a newer one (a later root, else a higher seq) that
    /// names every key it names and saw the same of them (the same `seen`
    /// entries for the keys either names), and that is not itself left
    /// out. What it bars, the newer one bars; what the removed keys signed
    /// up to it counts under the newer one alike. Removals are the only
    /// records that grow without bound, so the fold keeps a checkpoint and
    /// a change of root within their rooms.
    fn folded(&self, state: &State, skip: &BTreeSet<RecordId>) -> BTreeSet<RecordId> {
        let at = |k: &KeyHash| state.roots.iter().position(|r| r == k);
        let rms: Vec<(usize, u64, RecordId, &super::body::Removal)> = self
            .records
            .values()
            .filter(|e| e.role == Role::Root && !e.held && !skip.contains(&e.record.id()))
            .filter_map(|e| match (&e.record.body().kind, at(&e.record.body().signer)) {
                (Kind::Revoke(rm), Some(p)) => Some((p, e.record.body().seq, e.record.id(), rm)),
                _ => None,
            })
            .collect();
        let concerns = |rm: &super::body::Removal| -> BTreeSet<KeyHash> {
            rm.keys.iter().copied().chain(rm.seen.iter().map(|x| x.key)).collect()
        };
        let seen_of = |rm: &super::body::Removal, ks: &BTreeSet<KeyHash>| -> Vec<super::body::Seen> {
            let mut v: Vec<super::body::Seen> = rm.seen.iter().filter(|x| ks.contains(&x.key)).cloned().collect();
            v.sort_by_key(|x| (x.key, x.seq, x.id));
            v
        };
        let mut out = BTreeSet::new();
        for (p1, s1, id1, r1) in &rms {
            let ks = concerns(r1);
            let covered = rms.iter().any(|(p2, s2, id2, r2)| {
                id2 != id1
                    && (p2, s2) > (p1, s1)
                    && r1.keys.iter().all(|k| r2.keys.contains(k))
                    && seen_of(r1, &ks) == seen_of(r2, &ks)
            });
            if covered {
                out.insert(*id1);
            }
        }
        out
    }

    /// The list a change of root carries (rule 33), not edited: every
    /// record of every root on the path that counts in state, every root's
    /// removal among them (one whose admission the writer never got still
    /// bars it); what the
    /// current list keeps that the set holds (lists do not add up, so each
    /// carries it forward, under the same rule for removals); and the
    /// heads the current root's counting checkpoint names, as anchors. No
    /// checkpoint record. At most a root's room, the removals first.
    pub fn change_list(&self, state: &State) -> List {
        List(self.within_ceiling(state, self.change_ids(state), &[]).0)
    }

    fn change_ids(&self, state: &State) -> BTreeSet<RecordId> {
        let roots: BTreeSet<&KeyHash> = state.roots.iter().collect();
        let cur = state.roots.last();
        // Every root's removal that counts: one whose admission the writer
        // never got still bars it, and nothing else would.
        let earlier: BTreeSet<RecordId> = self
            .records
            .values()
            .filter(|e| roots.contains(&e.record.body().signer) && Some(&e.record.body().signer) != cur && !e.held)
            .filter(|e| matches!(e.record.body().kind, Kind::Revoke(_)) && state.counting.contains(&e.record.id()))
            .map(|e| e.record.id())
            .collect();
        let mut out: BTreeSet<RecordId> = earlier.clone();
        for e in self.records.values().filter(|e| Some(&e.record.body().signer) == cur && !e.held) {
            let b = e.record.body();
            let counts = state.counting.contains(&e.record.id());
            match &b.kind {
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
        let lines = self.lines(state);
        out.retain(|id| !self.left_out(&lines, id));
        // A checkpoint is never listed: what it pruned, the new root's
        // first checkpoint prunes again. An earlier root's removal is
        // listed only while it counts.
        out.retain(|id| match self.held(id).map(|r| r.body()) {
            Some(b) if matches!(b.kind, Kind::Checkpoint { .. }) => false,
            Some(b) if matches!(b.kind, Kind::Revoke(_)) && roots.contains(&b.signer) && Some(&b.signer) != cur => {
                earlier.contains(id)
            }
            _ => true,
        });
        // A removal a newer listed one covers is not carried.
        let off: BTreeSet<RecordId> = self.records.keys().filter(|id| !out.contains(*id)).copied().collect();
        let folded = self.folded(state, &off);
        out.retain(|id| !folded.contains(id));
        out
    }

    /// At most the cut roots' reserve of IDs and units: the removals
    /// first, then the device records that count (an admission is never
    /// dropped while its device counts), then the rest in the keeping's
    /// order; sorted. With it whether the removals and the counting device
    /// records alone fit (the carry-over: a change that would leave out a
    /// device that counts is not written).
    fn within_ceiling(&self, state: &State, ids: BTreeSet<RecordId>, remove: &[KeyHash]) -> (Vec<RecordId>, bool) {
        // Of a device's root records the newest is its admission; the
        // older ones it superseded go first when the reserve is short.
        let at = |k: &KeyHash| state.roots.iter().position(|r| r == k).unwrap_or(0);
        let mut newest: BTreeMap<KeyHash, (usize, u64, RecordId)> = BTreeMap::new();
        for id in &ids {
            let Some(e) = self.records.get(id) else { continue };
            let b = e.record.body();
            if let Kind::Device(d) = &b.kind
                && state.counting.contains(id)
            {
                let k = (at(&b.signer), b.seq, *id);
                let n = newest.entry(d.key.hash()).or_insert(k);
                if k > *n {
                    *n = k;
                }
            }
        }
        let class = |e: &Entry| -> u8 {
            match &e.record.body().kind {
                Kind::Revoke(_) => 0,
                Kind::Device(d)
                    if state.counting.contains(&e.record.id())
                        && newest.get(&d.key.hash()).is_some_and(|n| n.2 == e.record.id())
                        && !remove.contains(&d.key.hash())
                        && !d.admin.as_ref().is_some_and(|a| remove.contains(&a.hash())) =>
                {
                    1
                }
                _ => 2,
            }
        };
        let mut items: Vec<(u8, keep::Pos, RecordId, u64)> = ids
            .iter()
            .filter_map(|id| self.records.get(id))
            .map(|e| {
                let it = eval::item(&e.record, self.role_of(e));
                (class(e), it.pos(), it.id, it.units)
            })
            .collect();
        items.sort();
        let mut out = BTreeSet::new();
        let mut units = 0u64;
        let mut whole = true;
        for (c, _, id, u) in items {
            if out.len() >= super::LIST_MAX || units.saturating_add(u) > keep::reserve() {
                whole &= c == 2;
                if c == 2 {
                    break;
                }
                continue;
            }
            units = units.saturating_add(u);
            out.insert(id);
        }
        (out.into_iter().collect(), whole)
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
        &mut self,
        state: &State,
        recovery: &dyn ExternalKey,
        recovery2: &super::pq::PqKey,
        new_root: &dyn ExternalKey,
        device: super::body::Device,
        leave_out: &[KeyHash],
        drop_hubs: bool,
        time_ms: u64,
    ) -> crate::error::Result<Written> {
        self.write_change_with(state, recovery, recovery2, new_root, device, leave_out, drop_hubs, time_ms, false)
    }

    /// `write_change` past a change the set holds and has not applied
    /// (`CHANGE_WAITING`): the person chose not to sync first, the head
    /// of change N has come, its new root's records have not. The record
    /// is N+1, after the newest valid head the set holds; it re-issues
    /// what counts here, the state before N, and names no spare (an
    /// admin's spare may be N's grant). Members apply N+1 over N without
    /// N's group, and N's root and all it signs never count, even if N's
    /// records come later: the newest head whose group is whole applies
    /// and cuts every root before it. N travels with N+1 (`for_peer`
    /// gives every head the set holds). It still refuses a group stopped
    /// for good, a record this device cannot read, and a held recovery
    /// record off the chain (a void one).
    #[allow(clippy::too_many_arguments, reason = "the parts of one act")]
    pub fn write_change_over_waiting(
        &mut self,
        state: &State,
        recovery: &dyn ExternalKey,
        recovery2: &super::pq::PqKey,
        new_root: &dyn ExternalKey,
        device: super::body::Device,
        leave_out: &[KeyHash],
        drop_hubs: bool,
        time_ms: u64,
    ) -> crate::error::Result<Written> {
        self.write_change_with(state, recovery, recovery2, new_root, device, leave_out, drop_hubs, time_ms, true)
    }

    /// The valid heads past the applied chain the set holds, in order:
    /// each names the one before it as prev. None when a held recovery
    /// record past the chain is not one of them (a void one, or one off
    /// the chain), where no record may follow.
    fn heads_past_chain(&self, state: &State) -> Option<Vec<&Record>> {
        let applied: BTreeSet<RecordId> = state.chain().into_iter().collect();
        let mut rest: Vec<&Record> = self
            .records
            .values()
            .filter(|e| e.role == Role::Recovery && !applied.contains(&e.record.id()))
            .map(|e| &e.record)
            .collect();
        rest.sort_by_key(|r| r.body().seq);
        let mut tip = state.chain().last().copied();
        let mut path: Vec<KeyHash> = state.roots.clone();
        for r in &rest {
            let Kind::Recovery { root, .. } = &r.body().kind else { return None };
            if r.body().prev != tip || r.body().held || path.contains(&root.hash()) {
                return None;
            }
            path.push(root.hash());
            tip = Some(r.id());
        }
        Some(rest)
    }

    #[allow(clippy::too_many_arguments, reason = "the parts of one act")]
    fn write_change_with(
        &mut self,
        state: &State,
        recovery: &dyn ExternalKey,
        recovery2: &super::pq::PqKey,
        new_root: &dyn ExternalKey,
        device: super::body::Device,
        leave_out: &[KeyHash],
        drop_hubs: bool,
        time_ms: u64,
        over: bool,
    ) -> crate::error::Result<Written> {
        use crate::error::Error;
        // Asked again for the same new root key (the screen seemed stuck,
        // the key was typed twice): the stored head is given back, never a
        // second head at one seq.
        if let Some(w) = self.written(&Key::es256(new_root.public())) {
            return Ok(Written { again: true, blind: !self.reached, ..w });
        }
        // Any recovery record the set holds and has not applied (one that
        // waits for its list or for the record before it, one this device
        // cannot read, a void one) means a change is on its way: writing
        // now would sign a second record at its seq.
        // Two recovery records at one seq: nothing writes on, and syncing
        // changes nothing.
        if state.fork.is_some() || state.conflicts.iter().any(|c| c.kind == eval::ConflictKind::Fork) {
            return Err(Error::msg(CHANGE_STOPPED));
        }
        let applied: BTreeSet<RecordId> = state.chain().into_iter().collect();
        let unapplied = self.waiting.is_some()
            || state.update_needed
            || self.records.values().any(|e| e.role == Role::Recovery && !applied.contains(&e.record.id()));
        // Past a waiting change the record follows the newest valid head
        // held; its roots are no new root's.
        let past: Vec<Record> = if over && !state.update_needed {
            self.heads_past_chain(state).ok_or_else(|| Error::msg(CHANGE_WAITING))?.into_iter().cloned().collect()
        } else if unapplied {
            return Err(Error::msg(CHANGE_WAITING));
        } else {
            Vec::new()
        };
        let past_roots: Vec<KeyHash> = past
            .iter()
            .filter_map(|r| match &r.body().kind {
                Kind::Recovery { root, .. } => Some(root.hash()),
                _ => None,
            })
            .collect();
        if Key::es256(recovery.public()) != self.recovery.k1 || recovery2.key() != self.recovery.k2 {
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
        let was_admin = self.keys.is_admin(&h)
            || state.devices.iter().any(|d| d.admin == Some(h))
            || self.records.values().any(
                |e| matches!(&e.record.body().kind, Kind::Device(d) if d.admin.as_ref().is_some_and(|a| a.hash() == h)),
            );
        if was_admin {
            return Err(Error::msg(CHANGE_FORMER_ADMIN));
        }
        let known = self.keys.signer(&h).is_some()
            || past_roots.contains(&h)
            || self.early_roots.contains_key(&h)
            || state.revoked.contains(&h)
            || state.devices.iter().any(|d| d.key.hash() == h || d.admin == Some(h))
            || self.records.values().any(|e| e.record.body().signer == h);
        if known {
            return Err(Error::msg("the new root key must be a new key"));
        }
        let device_key = device.key.hash();
        let device_id = device.key.device_id();
        if state.revoked.contains(&device_key) {
            return Err(Error::msg("this device was removed from the group: it joins again with a new key"));
        }
        let rank = |k: &KeyHash| *k == h || *k == device_key || *k == self.recovery.hash() || path_has(state, k);
        if leave_out.iter().any(rank) {
            return Err(Error::msg("the new root's own device cannot be left out"));
        }
        // L: after the change only the new root's records count, so the
        // new root re-issues as its own records what counts at its device
        // (B): every device but the ones the person leaves out, the newest
        // settings, hubs and copies, and every freeze. No removal is
        // written: a device left out, or removed before, is simply not
        // carried.
        let mut carried = self.change_carries(state, &device_key, leave_out);
        if !past.is_empty() {
            // No spare past a waiting change: the device is carried plain.
            for d in &mut carried {
                if d.admin.take().is_some() {
                    d.powers = 0;
                    d.commands = 0;
                }
            }
        }
        let list = List(Vec::new());
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
        // The hubs record that counts, as written (a hub's right may come
        // later), of the devices the change carries.
        let cur = state.roots.last().copied();
        let counting_hubs = self
            .records
            .values()
            .filter(|e| Some(e.record.body().signer) == cur && state.counting.contains(&e.record.id()))
            .filter_map(|e| match &e.record.body().kind {
                Kind::Hubs { hubs, .. } => Some((e.record.body().seq, hubs)),
                _ => None,
            })
            .max_by_key(|(seq, _)| *seq)
            .map(|(_, hubs)| hubs.clone())
            .unwrap_or_default();
        let hubs: Vec<DeviceId> = counting_hubs
            .into_iter()
            .filter(|id| *id == device_id || carried.iter().any(|d| d.key.device_id() == *id))
            .collect();
        if !hubs.is_empty() && !drop_hubs {
            first.push(sign(Kind::Hubs { hubs, seen: Vec::new() })?);
        }
        if let Some(incoming_ms) = state.incoming_ms {
            first.push(sign(Kind::Copies { incoming_ms, seen: Vec::new() })?);
        }
        let mut frozen = Vec::new();
        for d in &carried {
            let key = d.key.hash();
            let was_frozen = state.device_by_key(&key).is_some_and(|s| s.frozen);
            first.push(sign(Kind::device(d.clone()))?);
            if was_frozen {
                frozen.push(key);
            }
        }
        // A freeze is on the device: one freeze of its member key for each
        // frozen device, so that the new root thaws each by its own hand.
        for key in frozen {
            first.push(sign(Kind::Freeze(super::body::Removal { keys: alloc::vec![key], seen: Vec::new() }))?);
        }
        // The new root's first checkpoint: its own head, keeping every
        // record before it, so that the change applies whole or not at
        // all (`eval::first_gap`).
        let mut own = first.iter().map(Record::id).collect::<Vec<_>>();
        let own_head = own.pop();
        let mut heads = Vec::new();
        if let (Some(id), Some(last)) = (own_head, first.last()) {
            heads.push(super::body::Head { key: h, seq: last.body().seq, id });
        }
        own.sort();
        let checkpoint = sign(Kind::Checkpoint { heads, keep: own })?;
        // Within the new root's room as its ordinary records are: room left
        // for its next checkpoint, which keeps as much as this one, and the
        // margin for removals.
        let units_of = |r: &Record| eval::item(r, Role::Root).units;
        let units: u64 = first.iter().map(units_of).fold(units_of(&checkpoint).saturating_mul(2), u64::saturating_add);
        if units.saturating_add(root_floor_margin()) > keep::ceiling(true) {
            return Err(Error::msg(CHANGE_TOO_BIG));
        }
        let first_id = checkpoint.id();
        first.push(checkpoint);
        let body = Body {
            group: self.group,
            signer: self.recovery.hash(),
            seq,
            prev: past.last().map(Record::id).or(tip.last().copied()),
            time_ms,
            kind: Kind::Recovery {
                root: root_key,
                list: list.hash(),
                from: 0,
                first: first_id,
                signer2: self.recovery.hash2(),
            },
            held: false,
        };
        let record = Record::sign_head(body, recovery, recovery2)?;
        let blind = !self.reached;
        // The set takes the change before it is given out: asked again,
        // with any ticks, the writer gives back this one, never a second
        // record at its seq. The caller saves the set before it sends.
        let mut trial = self.clone();
        let _ = trial.insert(record.clone());
        let _ = trial.insert_list(&list.encode());
        trial.insert_all(first.iter().cloned());
        // The writer's own set takes the change and counts the new root's
        // first records, or the change reaches nobody for sure.
        let st = trial.state();
        if st.roots.last() != Some(&h) || first.iter().any(|r| !st.counting.contains(&r.id())) {
            return Err(Error::msg("the change of root would not count in the writer's own records"));
        }
        *self = trial;
        // Its own records are no peer's.
        self.reached = !blind;
        Ok(Written { record, list, first, again: false, blind })
    }

    /// The devices a change of root re-issues (B): every device of state
    /// but the new root's own (`own`) and those the person leaves out (by
    /// member or admin key), each from what counts of it now, as the new
    /// root's own record. An old admin loses its rights: its device is
    /// carried as a plain device.
    fn change_carries(&self, state: &State, own: &KeyHash, leave_out: &[KeyHash]) -> Vec<super::body::Device> {
        state
            .devices
            .iter()
            .filter(|d| d.key.hash() != *own && !self.change_leaves_out(state, d, leave_out))
            .map(|d| {
                // S: an admin whose newest counting ack names a spare key
                // keeps its rights under the new root on that key, with
                // the powers it had; any other admin's device is carried
                // as a plain device.
                let spare = d.admin.and_then(|a| self.spare_of(state, &a));
                let (powers, commands) = if spare.is_some() { (d.powers, d.commands) } else { (0, 0) };
                (d, spare, powers, commands)
            })
            .map(|(d, spare, powers, commands)| super::body::Device {
                key: d.key.clone(),
                name: d.name.clone(),
                role: d.role,
                rights: d.rights,
                skip: d.skip,
                caps: d.caps,
                os: d.os,
                store: d.store,
                proof: d.proof,
                admin: spare,
                powers,
                commands,
                holds_root: false,
                replaces: d.replaces,
                guarded: d.guarded,
                seen: Vec::new(),
            })
            .collect()
    }

    /// The spare admin key a change of root names for admin key a (S): the
    /// `spare` of a's newest ack that counts under the root being replaced
    /// (S1: a spare is one-time and comes only from an ack that counts
    /// now), when a is a live admin and the spare is a key the group has
    /// never used (no root, recovery key, device or admin key, nor one a
    /// record names as an admin key or that signed a record). An admin
    /// asleep through two changes keeps nothing: its spare was named by
    /// the first, and the second finds no ack under the root it replaces.
    pub fn spare_of(&self, state: &State, a: &KeyHash) -> Option<Key> {
        if !Self::live_admins(state).contains(a) {
            return None;
        }
        // The newest ack that counts decides: one without a spare
        // withdraws the spare an older one published.
        let spare = self
            .records
            .values()
            .filter(|e| e.record.body().signer == *a && state.counting.contains(&e.record.id()))
            .filter_map(|e| match &e.record.body().kind {
                Kind::Ack { spare, .. } => Some((e.record.body().seq, spare)),
                _ => None,
            })
            .max_by_key(|(seq, _)| *seq)
            .and_then(|(_, sp)| sp.clone())?;
        self.fresh_key(state, &spare.hash()).then_some(spare)
    }

    /// Whether k is a key the group has never used: no root on the path or
    /// waiting, not the recovery key, no device's member or admin key, no
    /// key removed or taken back, none a held device record names as an
    /// admin key, and none that signed a record the set holds.
    fn fresh_key(&self, state: &State, k: &KeyHash) -> bool {
        *k != self.recovery.hash()
            && *k != self.root_hash
            && !self.promoted.contains(k)
            && !self.early_roots.contains_key(k)
            && self.keys.signer(k).is_none()
            && !state.revoked.contains(k)
            && !state.devices.iter().any(|d| d.key.hash() == *k || d.admin == Some(*k))
            && !self.records.values().any(|e| {
                e.record.body().signer == *k
                    || matches!(&e.record.body().kind, Kind::Device(d)
                        if d.key.hash() == *k || d.admin.as_ref().is_some_and(|x| x.hash() == *k))
            })
    }

    /// Whether a change of root leaves device d out: the person named it
    /// (by its member key or its admin key), or a root's checkpoint the
    /// writer holds settled it (`pruned`).
    fn change_leaves_out(&self, state: &State, d: &eval::DeviceState, leave_out: &[KeyHash]) -> bool {
        leave_out.contains(&d.key.hash()) || d.admin.is_some_and(|a| leave_out.contains(&a)) || self.pruned(state, d)
    }

    /// Whether every admission of device d the writer holds sits below a
    /// head of a checkpoint of a root on the path the writer holds, on
    /// either history of a root that signed two, and that checkpoint does
    /// not keep it: the root let it go, with what acted on it, and a
    /// member that offers it again later does not bring the device into
    /// the change of root.
    fn pruned(&self, state: &State, d: &eval::DeviceState) -> bool {
        let key = d.key.hash();
        let checkpoints: Vec<(&[super::body::Head], &[RecordId])> = self
            .records
            .values()
            .filter(|e| state.roots.contains(&e.record.body().signer))
            .filter_map(|e| match &e.record.body().kind {
                Kind::Checkpoint { keep, heads } => Some((heads.as_slice(), keep.as_slice())),
                _ => None,
            })
            .collect();
        let mut admissions = self
            .records
            .values()
            .filter(|e| matches!(&e.record.body().kind, Kind::Device(x) if x.key.hash() == key))
            .peekable();
        admissions.peek().is_some()
            && admissions.all(|e| {
                let b = e.record.body();
                let id = e.record.id();
                checkpoints.iter().any(|(heads, keep)| {
                    heads.iter().any(|h| h.key == b.signer && b.seq < h.seq) && !keep.contains(&id)
                })
            })
    }

    /// What a change of root would do to each device of state (the query
    /// the app shows before the person signs a change): every device but
    /// the writer's own, with what the change does to it when the person
    /// leaves out `leave_out`. `write_change` with the same list carries
    /// exactly the devices this lists as not `Out`.
    pub fn change_preview(&self, state: &State, leave_out: &[KeyHash]) -> Vec<Preview> {
        state
            .devices
            .iter()
            .map(|d| {
                let outcome = if self.change_leaves_out(state, d, leave_out) {
                    Outcome::Out
                } else if d.admin.is_some_and(|a| self.spare_of(state, &a).is_some()) {
                    Outcome::AdminKeptWithSpare
                } else if d.admin.is_some() {
                    Outcome::AdminRightsLost
                } else if d.frozen {
                    Outcome::Frozen
                } else {
                    Outcome::Stays
                };
                let frozen = outcome != Outcome::Out && d.frozen;
                Preview { device: d.id, outcome, frozen }
            })
            .collect()
    }

    /// The change of root the set holds that makes root the root: its
    /// recovery record, its list and the new root's first records up to
    /// the first checkpoint the record names, when the set holds them all.
    fn written(&self, root: &Key) -> Option<Written> {
        let record = self.records.values().find_map(|e| match &e.record.body().kind {
            Kind::Recovery { root: r, .. } if e.role == Role::Recovery && r == root => Some(e.record.clone()),
            _ => None,
        })?;
        let Kind::Recovery { list, first: first_id, .. } = &record.body().kind else { return None };
        let list = self.lists.get(list).map(|(_, l)| l.clone())?;
        let h = root.hash();
        let mut first: Vec<Record> =
            self.records.values().filter(|e| e.record.body().signer == h).map(|e| e.record.clone()).collect();
        first.extend(self.early.values().filter(|r| r.body().signer == h).cloned());
        let cp = first.iter().find(|r| r.id() == *first_id)?.body().seq;
        first.retain(|r| r.body().seq <= cp);
        first.sort_by_key(|r| r.body().seq);
        Some(Written { record, list, first, again: false, blind: false })
    }

    /// The live admin keys: those a device of state holds.
    fn live_admins(state: &State) -> BTreeSet<KeyHash> {
        state.devices.iter().filter_map(|d| d.admin).collect()
    }

    /// Whether admin key a has acknowledged signer's records up to seq: a
    /// record of a that counts names signer at seq or above in its seen.
    ///
    /// GRANT_ABOVE: a removal of the root signed below the root's oldest
    /// record that names a needs no acknowledgement of a. A member that
    /// counts that grant holds the root's chain below it, the removal
    /// too, and the seen line voids whatever a signed before it saw its
    /// grant.
    fn acked_by(&self, state: &State, a: &KeyHash, signer: &KeyHash, seq: u64) -> bool {
        let granted_above = self
            .records
            .values()
            .filter(|e| !e.held && e.record.body().signer == *signer && state.counting.contains(&e.record.id()))
            .filter(|e| matches!(&e.record.body().kind, Kind::Device(d) if d.admin.as_ref().map(Key::hash) == Some(*a)))
            .map(|e| e.record.body().seq)
            .min()
            .is_some_and(|named| seq < named);
        if granted_above && state.roots.contains(signer) {
            return true;
        }
        self.records.values().filter(|e| !e.held && e.record.body().signer == *a).any(|e| {
            state.counting.contains(&e.record.id())
                && seen_of(&e.record.body().kind).iter().any(|x| x.key == *signer && x.seq >= seq)
        })
    }

    /// Whether every live admin key but signer has acknowledged signer's
    /// records up to seq. With no admin keys, at once.
    fn acked(&self, state: &State, signer: &KeyHash, seq: u64) -> bool {
        Self::live_admins(state).iter().filter(|a| *a != signer).all(|a| self.acked_by(state, a, signer, seq))
    }

    /// The counting removals each live admin key has not acknowledged,
    /// by key: what waits for it in the rooms. Read-only, for the app
    /// (which admin keys hold removals back, and how many).
    pub fn unacknowledged(&self, state: &State) -> BTreeMap<KeyHash, usize> {
        let removals = self.waiting(state);
        Self::live_admins(state)
            .into_iter()
            .map(|a| {
                let n = removals
                    .iter()
                    .filter(|r| r.body().signer != a && !self.acked_by(state, &a, &r.body().signer, r.body().seq))
                    .count();
                (a, n)
            })
            .collect()
    }

    /// The counting removals a checkpoint could let go but for the admins'
    /// acknowledgements: every key they name is a plain device key whose
    /// admissions the set holds, none names an admin key, and nothing the
    /// key signed counts. A removal of an admin key, or of a device that
    /// had one, is kept for good whatever the admins saw, so it waits for
    /// nobody.
    fn waiting(&self, state: &State) -> Vec<&Record> {
        self.records
            .values()
            .filter(|e| e.role != Role::Recovery && !e.held && state.counting.contains(&e.record.id()))
            .filter(|e| matches!(&e.record.body().kind, Kind::Revoke(rm) if rm.keys.iter().all(|k| self.settleable(state, k))))
            .map(|e| &e.record)
            .collect()
    }

    /// The device records the set holds that name key k, as its member key
    /// or its admin key.
    fn admissions_of(&self, k: &KeyHash) -> impl Iterator<Item = &Record> {
        self.records.values().filter(|e| e.role != Role::Recovery).map(|e| &e.record).filter(move |r| {
            match &r.body().kind {
                Kind::Device(d) => d.key.hash() == *k || d.admin.as_ref().map(Key::hash) == Some(*k),
                _ => false,
            }
        })
    }

    /// Whether a removal of key k may ever go (`settleable`): k is a plain
    /// device key whose admissions the set holds, none of them names an
    /// admin key, and nothing k signed counts. The checkpoint's settle
    /// adds that every admission sits below its signer's head, and the
    /// admins' acknowledgements; `waiting`, `unacknowledged`,
    /// `unacknowledged_units`, `ack_due` and `take_back_lagging` count
    /// only removals of such keys.
    fn settleable(&self, state: &State, k: &KeyHash) -> bool {
        self.admissions_of(k).next().is_some()
            && !self.admissions_of(k).any(|r| matches!(&r.body().kind, Kind::Device(d) if d.admin.is_some()))
            && !self.records.values().any(|e| {
                e.role != Role::Recovery && e.record.body().signer == *k && state.counting.contains(&e.record.id())
            })
    }

    /// Whether admin key a holds a removal it has not acknowledged: its
    /// device then writes an acknowledgement (`write_ack`), once after
    /// the sync that brought it, so that acknowledgements never flood.
    /// Never while the group is stopped, where the writer refuses every
    /// record (`write_one`).
    pub fn ack_due(&self, state: &State, a: &KeyHash) -> bool {
        if state.stop == eval::Stop::Full || state.halted() {
            return false;
        }
        self.unacknowledged(state).get(a).is_some_and(|n| *n > 0)
    }

    /// The newest acknowledgement of admin key a the set holds that
    /// counts: its seq and the time its signer wrote in it (the signer's
    /// claim; the app keeps when the root received it).
    pub fn last_ack(&self, state: &State, a: &KeyHash) -> Option<(u64, u64)> {
        self.records
            .values()
            .filter(|e| !e.held && e.record.body().signer == *a && state.counting.contains(&e.record.id()))
            .filter(|e| matches!(e.record.body().kind, Kind::Ack { .. }))
            .map(|e| (e.record.body().seq, e.record.body().time_ms))
            .max()
    }

    /// The time the newest counting root record that names admin key a
    /// carries: when the root named it, on the root's own clock.
    fn named_at(&self, state: &State, a: &KeyHash) -> Option<u64> {
        self.records
            .values()
            .filter(|e| e.role == Role::Root && !e.held && state.counting.contains(&e.record.id()))
            .filter(|e| matches!(&e.record.body().kind, Kind::Device(d) if d.admin.as_ref().map(Key::hash) == Some(*a)))
            .map(|e| e.record.body().time_ms)
            .max()
    }

    /// The admin keys a root took back or removed, from the root records
    /// the set holds: a key a root's device record named that no device
    /// of state holds now. Such a key is never an admin again.
    fn taken_back(&self, state: &State) -> BTreeSet<KeyHash> {
        let live = Self::live_admins(state);
        self.records
            .values()
            .filter(|e| e.role == Role::Root && !e.held)
            .filter_map(|e| match &e.record.body().kind {
                Kind::Device(d) => d.admin.as_ref().map(Key::hash),
                _ => None,
            })
            .filter(|a| !live.contains(a))
            .collect()
    }

    /// Writes admin key signer's acknowledgement: the heads it holds of the
    /// current root and of the other live admin keys.
    pub fn write_ack(&mut self, state: &State, signer: &dyn ExternalKey, time_ms: u64) -> crate::error::Result<Record> {
        self.write_ack_with(state, signer, None, time_ms)
    }

    /// write_ack that also publishes a spare admin key (S): the public key
    /// of a key the admin's device made and signs nothing with, which a
    /// change of root names as the admin's key under the new root. The
    /// device keeps the secret of every spare it published until a newer
    /// ack of its own counts. It refuses a spare the group has used.
    pub fn write_ack_spare(
        &mut self,
        state: &State,
        signer: &dyn ExternalKey,
        spare: &Key,
        time_ms: u64,
    ) -> crate::error::Result<Record> {
        if *spare == Key::es256(signer.public()) || !self.fresh_key(state, &spare.hash()) {
            return Err(crate::error::Error::msg(SPARE_USED));
        }
        self.write_ack_with(state, signer, Some(spare.clone()), time_ms)
    }

    fn write_ack_with(
        &mut self,
        state: &State,
        signer: &dyn ExternalKey,
        spare: Option<Key>,
        time_ms: u64,
    ) -> crate::error::Result<Record> {
        let me = Key::es256(signer.public()).hash();
        let admins = Self::live_admins(state);
        let root = state.roots.last().copied();
        let seen = self.heads_where(|k| *k != me && (Some(*k) == root || admins.contains(k)));
        if seen.is_empty() {
            return Err(crate::error::Error::msg("there is nothing to acknowledge"));
        }
        // An ack is a key's acknowledgement itself: the call adds it alone.
        Self::only(self.write_record(state, signer, Kind::Ack { seen, spare }, time_ms)?)
    }

    /// The root's units each live admin key holds back: the sizes of the
    /// root's own waiting removals (`waiting`) the key has not
    /// acknowledged. Read-only, for the app, which shows them when the
    /// root's room fills, so that the person chooses whom to take back.
    pub fn unacknowledged_units(&self, state: &State) -> BTreeMap<KeyHash, u64> {
        let Some(h) = state.roots.last().copied() else { return BTreeMap::new() };
        let own: Vec<&Record> = self.waiting(state).into_iter().filter(|r| r.body().signer == h).collect();
        Self::live_admins(state)
            .into_iter()
            .map(|a| {
                let units = own
                    .iter()
                    .filter(|r| !self.acked_by(state, &a, &h, r.body().seq))
                    .map(|r| eval::item(r, Role::Root).units)
                    .sum();
                (a, units)
            })
            .collect()
    }

    /// The admin keys whose devices are frozen. A frozen key cannot
    /// acknowledge while it is frozen, so a removal it has not seen waits;
    /// the app shows it with `unacknowledged`, and the person thaws the
    /// key or takes it back (`take_back`).
    pub fn frozen_admins(state: &State) -> BTreeSet<KeyHash> {
        state.devices.iter().filter(|d| d.frozen).filter_map(|d| d.admin).collect()
    }

    /// The root's writer takes live admin keys back by itself for one
    /// reason only: a key the root received nothing of for
    /// ADMIN_SILENCE_MS (heard_ms: when the root device last received a
    /// record of each key, on its own clock; time_ms, its now). A full
    /// room and a frozen key that holds removals back take nobody back by
    /// themselves: the person does (`take_back`), or thaws the key, which
    /// then acknowledges; a frozen key whose device is gone falls to the
    /// silence. It returns each record with its reason, none when nothing
    /// is due.
    pub fn take_back_lagging(
        &mut self,
        state: &State,
        root: &dyn ExternalKey,
        heard_ms: &BTreeMap<KeyHash, u64>,
        time_ms: u64,
    ) -> crate::error::Result<Vec<(TakeBack, Record)>> {
        let h = Key::es256(root.public()).hash();
        if state.roots.last() != Some(&h) {
            return Ok(Vec::new());
        }
        let mut lagging: BTreeMap<KeyHash, TakeBack> = BTreeMap::new();
        for a in Self::live_admins(state).into_iter().filter(|a| *a != h) {
            // A key the root device never heard from counts from the root
            // record that named it, on the root's own clock.
            let since = heard_ms.get(&a).copied().or_else(|| self.named_at(state, &a));
            if since.is_some_and(|t| time_ms.saturating_sub(t) >= ADMIN_SILENCE_MS) {
                lagging.insert(a, TakeBack::Silence);
            }
        }
        let mut out = Vec::new();
        for (a, why) in lagging {
            let now = self.state();
            out.push((why, self.take_back(&now, root, &a, time_ms)?));
        }
        Ok(out)
    }

    /// The root takes live admin key a back: its device stays, without
    /// the key. The root's checkpoint goes first, as before any record of
    /// it, so what the key signed that the root holds and counts stays,
    /// and what it signed that the root never got counts for nothing for
    /// good; the key is never an admin again (`write_record` refuses it),
    /// its device makes a new one. It passes the root's floor, as a
    /// removal does. The person calls it when the root's room fills
    /// (`unacknowledged_units`), the writer when a key is silent or frozen
    /// (`take_back_lagging`).
    pub fn take_back(
        &mut self,
        state: &State,
        root: &dyn ExternalKey,
        a: &KeyHash,
        time_ms: u64,
    ) -> crate::error::Result<Record> {
        if state.roots.last() == Some(a) {
            return Err(crate::error::Error::msg(TAKE_BACK_ROOT));
        }
        let Some(d) = state.devices.iter().find(|d| d.admin == Some(*a)) else {
            return Err(crate::error::Error::msg("no device holds this admin key"));
        };
        let mut back = super::body::Device::new(d.key.clone(), &d.name, d.role);
        back.rights = d.rights;
        back.skip = d.skip;
        back.caps = d.caps;
        back.os = d.os;
        back.store = d.store;
        back.proof = d.proof;
        back.replaces = d.replaces;
        back.guarded = d.guarded;
        back.seen = self.heads_where(|k| k == a);
        // The root's record goes alone: a root writes no acknowledgement.
        Self::only(self.write_record(state, root, Kind::device(back), time_ms)?)
    }

    /// Writes the current root's checkpoint (section 10, "Checkpoints"):
    /// for every key but the roots' and the recovery key's, a head at its
    /// highest record that counts, and the root's own head; it keeps every
    /// record below a head that counts or that this version cannot read,
    /// so what is above a gap or past two histories is not touched, and
    /// every record of an earlier root the list keeps.
    ///
    /// A root's removal, the current root's or a listed one of an earlier
    /// root, counts for good while it is kept. The writer leaves one out,
    /// with the records of the keys it names, only when every key it names
    /// is a plain device key whose admissions it holds: the set holds a
    /// device record that names it, none of these names an admin key,
    /// every one is below its signer's head (not the head itself), and no
    /// record that key signed counts. A removal written with nothing seen
    /// of the admission is kept, as is one of an admin key. After that a
    /// replayed old record sits below a head and is refused as settled;
    /// only a new record admits the device again.
    ///
    /// It refuses a key that is not the current root's and a group that
    /// is stopped in full.
    pub fn write_checkpoint(
        &self,
        state: &State,
        root: &dyn ExternalKey,
        time_ms: u64,
    ) -> crate::error::Result<Record> {
        use crate::error::Error;
        let h = Key::es256(root.public()).hash();
        if state.roots.last() != Some(&h) {
            return Err(Error::msg("only the current root writes a checkpoint"));
        }
        if state.stop == eval::Stop::Full || state.stopped() {
            return Err(Error::msg("the group is stopped: no root action works until the root is changed"));
        }
        let body = self.checkpoint_body(state, h, time_ms)?;
        let cp = Record::sign(body, root)?;
        // What it names must fit the rooms by itself, or it would count
        // for nobody (`eval::fits_alone`).
        let named = eval::named_first(&cp, |id| self.records.contains_key(id));
        let others = named.iter().filter_map(|id| self.records.get(id)).map(|e| (&e.record, self.role_of(e)));
        if !eval::fits_alone(others.chain([(&cp, Role::Root)]), &self.root_hash, &self.promoted, &self.cuts) {
            return Err(Error::msg("what the checkpoint names would not fit the rooms by itself"));
        }
        // The writer's own set keeps it and counts it, or it reaches
        // nobody for sure.
        let mut trial = self.clone();
        let _ = trial.insert(cp.clone());
        if trial.state().checkpoint != Some(cp.id()) {
            return Err(Error::msg("the checkpoint would not count in the writer's own records"));
        }
        Ok(cp)
    }

    /// The body of the checkpoint root h would write now, unsigned: its
    /// heads, what it keeps, its seq and prev. `write_checkpoint` signs it;
    /// the floor in `write_one` reads its size.
    fn checkpoint_body(&self, state: &State, h: KeyHash, time_ms: u64) -> crate::error::Result<Body> {
        use crate::error::Error;
        let path: BTreeSet<&KeyHash> = state.roots.iter().collect();
        let recovery = self.recovery.hash();
        let entries = || self.records.values().filter(|e| e.role != Role::Recovery);
        // The root's own head: its newest record, which the checkpoint
        // follows.
        let own = self.heads_where(|k| *k == h).into_iter().next();
        let mut heads: BTreeMap<KeyHash, super::body::Head> = BTreeMap::new();
        for e in entries().filter(|e| !e.held && state.counting.contains(&e.record.id())) {
            let b = e.record.body();
            if path.contains(&b.signer) || b.signer == recovery {
                continue;
            }
            let id = e.record.id();
            let better = heads
                .get(&b.signer)
                .is_none_or(|o| (b.seq, core::cmp::Reverse(id)) > (o.seq, core::cmp::Reverse(o.id)));
            if better {
                heads.insert(b.signer, super::body::Head { key: b.signer, seq: b.seq, id });
            }
        }
        if let Some(o) = own {
            heads.insert(h, super::body::Head { key: h, seq: o.seq, id: o.id });
        }
        // No head goes down: a key's head in a counting checkpoint stays
        // where the writer holds nothing above it (its record need not be
        // held), or the records between the two would be settled no more.
        for cp in state.checkpoints.iter().filter_map(|id| self.held(id)) {
            let Kind::Checkpoint { heads: old, .. } = &cp.body().kind else { continue };
            for o in old.iter().filter(|o| !path.contains(&o.key) && o.key != recovery) {
                if heads.get(&o.key).is_none_or(|hd| hd.seq < o.seq) {
                    heads.insert(o.key, *o);
                }
            }
        }
        // A record of a root before the current one stays only while the
        // list keeps it and the current root's checkpoint keeps it in turn
        // (`eval::closed`): left out, it goes as a record under a head.
        let listed = |r: &Record| {
            path.contains(&r.body().signer)
                && r.body().signer != h
                && state.cut.as_ref().is_some_and(|c| c.keep.contains(&r.id()))
        };
        let below = |r: &Record| listed(r) || heads.get(&r.body().signer).is_some_and(|hd| r.body().seq <= hd.seq);
        // Below a head and not the head itself, which stays as an anchor.
        let under = |r: &Record| listed(r) || heads.get(&r.body().signer).is_some_and(|hd| r.body().seq < hd.seq);
        // The keys of a device record, with its other key.
        let names = |r: &Record| -> Vec<KeyHash> {
            match &r.body().kind {
                Kind::Device(d) => core::iter::once(d.key.hash()).chain(d.admin.as_ref().map(Key::hash)).collect(),
                _ => Vec::new(),
            }
        };
        // Only a plain device key's removal goes (`settleable`): one that
        // names an admin key, or a device that has one, is kept for good,
        // since a key that may sign could bring back what it signed while
        // removed.
        let settled = |k: &KeyHash| self.settleable(state, k) && self.admissions_of(k).all(&under);
        let mut dropped: BTreeSet<RecordId> = BTreeSet::new();
        let mut gone: BTreeSet<KeyHash> = BTreeSet::new();
        // A removal by an admin goes as a root's does: what it removed is
        // settled below the heads, and a replayed admission is refused.
        // And only once every live admin key but its signer has
        // acknowledged it (`acked`): an admin that has not seen the
        // removal may still sign for the key, so the removal waits.
        for e in entries().filter(|e| state.counting.contains(&e.record.id())) {
            if let Kind::Revoke(rm) = &e.record.body().kind
                && under(&e.record)
                && rm.keys.iter().all(settled)
                && self.acked(state, &e.record.body().signer, e.record.body().seq)
            {
                dropped.insert(e.record.id());
                gone.extend(rm.keys.iter().copied());
            }
        }
        // A removal a newer kept one covers goes too (the fold).
        let folded = self.folded(state, &dropped);
        dropped.extend(
            folded
                .into_iter()
                .filter(|id| self.records.get(id).is_some_and(|e| under(&e.record) && state.counting.contains(id))),
        );
        dropped.extend(self.superseded(state, h, &under));
        // An admin's acknowledgement under its head that a newer one of
        // the same key stands for: the newer holds at least as much.
        let mut newest_ack: BTreeMap<KeyHash, u64> = BTreeMap::new();
        for e in entries().filter(|e| matches!(e.record.body().kind, Kind::Ack { .. })) {
            let b = e.record.body();
            let n = newest_ack.entry(b.signer).or_insert(b.seq);
            *n = (*n).max(b.seq);
        }
        dropped.extend(
            entries()
                .filter(|e| matches!(e.record.body().kind, Kind::Ack { .. }) && under(&e.record))
                .filter(|e| newest_ack.get(&e.record.body().signer).is_some_and(|n| *n > e.record.body().seq))
                .map(|e| e.record.id()),
        );
        let head_ids: BTreeSet<RecordId> = heads.values().map(|hd| hd.id).collect();
        let mut keep: BTreeSet<RecordId> = BTreeSet::new();
        // A head stays as its key's anchor in the key's room. An admin key's
        // head that counts is kept here too: a key that is no longer an
        // admin has no room (`eval::rooms`), so what it signed stays only as
        // the root's checkpoint keeps it, the head included.
        for e in entries() {
            let r = &e.record;
            let id = r.id();
            let anchor = head_ids.contains(&id) && (r.body().signer == h || !state.counting.contains(&id));
            if anchor || dropped.contains(&id) || !below(r) {
                continue;
            }
            if names(r).iter().any(|k| gone.contains(k)) {
                continue;
            }
            // The root's own older checkpoints never stay: this one carries
            // their heads and takes their place, the counting one too, or
            // each would keep all before it and the root's room would fill.
            if r.body().signer == h && matches!(r.body().kind, Kind::Checkpoint { .. }) {
                continue;
            }
            // The root's own records under its head stay too: it signed
            // them, so its checkpoint mends its own chain where the rooms
            // turned a record of it away. Not an admission past the cap of
            // devices, which would not count: what the checkpoint keeps
            // stays bounded by the devices the group may have.
            let past_cap = |r: &Record| match &r.body().kind {
                Kind::Device(d) => state.device(&d.id()).is_none() && state.devices.len() >= super::MAX_DEVICES,
                _ => false,
            };
            let own = r.body().signer == h && !past_cap(r);
            if e.held || state.counting.contains(&id) || listed(r) || own {
                keep.insert(id);
            }
        }
        // A resolve whose every target goes stays no longer: it voids
        // nothing that is left. Its targets are held records below their
        // heads that the checkpoint does not keep, so none comes back.
        let goes = |id: &RecordId| {
            !keep.contains(id) && !head_ids.contains(id) && self.records.get(id).is_some_and(|t| below(&t.record))
        };
        let void: Vec<RecordId> = keep
            .iter()
            .copied()
            .filter(|id| {
                self.records.get(id).is_some_and(|e| {
                    under(&e.record)
                        && matches!(&e.record.body().kind, Kind::Resolve(ids) if !ids.is_empty() && ids.iter().all(goes))
                })
            })
            .collect();
        for id in void {
            keep.remove(&id);
        }
        let (seq, prev) = own.map_or((1, None), |o| (o.seq.saturating_add(1), Some(o.id)));
        let body = Body {
            group: self.group,
            signer: h,
            seq,
            prev,
            time_ms,
            kind: Kind::Checkpoint { heads: heads.into_values().collect(), keep: keep.into_iter().collect() },
            held: false,
        };
        if body.encode().len() > super::MAX_CHECKPOINT_BODY {
            return Err(Error::msg("the checkpoint would be larger than a checkpoint may be"));
        }
        if let Kind::Checkpoint { heads, keep } = &body.kind
            && eval::revives(heads, keep, self.records.values().map(|e| (&e.record, self.role_of(e))), |id| {
                state.counting.contains(id)
            })
        {
            return Err(Error::msg("the checkpoint would keep a removed key's admission"));
        }
        Ok(body)
    }

    /// The current root h's own records under its head (`under`) that a
    /// newer record of it stands for in full, so its checkpoint leaves
    /// them out and a long-lived group does not fill its root's room with
    /// old values: of its settings, hubs and copies records, all but the
    /// newest of each type, where that one counts; of its records of one
    /// device, those between the oldest (whether the device is the root's
    /// and a leaf) and the newest, where the newest counts and each left
    /// out names the same key and no admin key and guards the leaf only
    /// where the newest does too. What names an admin key stays: older
    /// root records that name one tell which admin keys are live.
    /// The state is the same before and after: a device of a root is its
    /// newest record, guarded if any of them is, a leaf by its oldest.
    fn superseded(&self, state: &State, h: KeyHash, under: &dyn Fn(&Record) -> bool) -> BTreeSet<RecordId> {
        let mine: Vec<&Record> = self
            .records
            .values()
            .filter(|e| !e.held && e.role == Role::Root && e.record.body().signer == h)
            .map(|e| &e.record)
            .collect();
        let counts = |r: &Record| state.counting.contains(&r.id());
        let mut out = BTreeSet::new();
        // The values: one type each.
        let tag = |k: &Kind| match k {
            Kind::Settings(_) => Some(0u8),
            Kind::Hubs { .. } => Some(1),
            Kind::Copies { .. } => Some(2),
            _ => None,
        };
        for t in 0u8..3 {
            let of: Vec<&&Record> = mine.iter().filter(|r| tag(&r.body().kind) == Some(t)).collect();
            let Some(newest) = of.iter().max_by_key(|r| r.body().seq) else { continue };
            if !counts(newest) {
                continue;
            }
            out.extend(of.iter().filter(|r| r.body().seq < newest.body().seq && under(r)).map(|r| r.id()));
        }
        // The devices.
        let mut by_device: BTreeMap<super::DeviceId, Vec<(&Record, &super::body::Device)>> = BTreeMap::new();
        for r in &mine {
            if let Kind::Device(d) = &r.body().kind {
                by_device.entry(d.id()).or_default().push((r, d));
            }
        }
        for rs in by_device.values() {
            let (Some(&(newest, nd)), Some(&(oldest, od))) =
                (rs.iter().max_by_key(|(r, _)| r.body().seq), rs.iter().min_by_key(|(r, _)| r.body().seq))
            else {
                continue;
            };
            if !counts(newest) || nd.admin.is_some() {
                continue;
            }
            let leaf = od.role == super::body::ROLE_LEAF;
            for &(r, d) in rs {
                let id = r.id();
                if id != newest.id()
                    && id != oldest.id()
                    && under(r)
                    && counts(r)
                    && d.admin.is_none()
                    && d.key == nd.key
                    && (d.role == super::body::ROLE_LEAF) == leaf
                    && (!d.guarded || nd.guarded)
                {
                    out.insert(id);
                }
            }
        }
        out
    }

    /// The units the current root's checkpoint would take if written now,
    /// from its body (`checkpoint_body`), with room for a few bytes more
    /// of time; None when the root could not write one.
    fn checkpoint_units(&self, state: &State, h: KeyHash, time_ms: u64) -> Option<u64> {
        let body = self.checkpoint_body(state, h, time_ms).ok()?;
        Some(keep::units(body.encode().len().saturating_add(super::ENVELOPE_ALLOWANCE).saturating_add(16)))
    }

    /// Whether the current root should write a checkpoint now: one more
    /// ordinary record of one unit (and its ID in the checkpoint, which may
    /// take one unit more) would reach its floor (`root_floor_margin` below
    /// its ceiling), where the writer takes only its removals, freezes and
    /// resolves. True too when no checkpoint of it would fit.
    pub fn checkpoint_due(&self, state: &State, time_ms: u64) -> bool {
        let Some(h) = state.roots.last().copied() else { return false };
        let Some(ceiling) = self.ceiling(&h) else { return false };
        let used = self.units.get(&h).copied().unwrap_or(0);
        self.checkpoint_units(state, h, time_ms)
            .is_none_or(|cp| used.saturating_add(cp).saturating_add(root_floor_margin()).saturating_add(2) > ceiling)
    }

    /// The admin keys a record of kind by the current root makes no
    /// longer admins: of a removal, the admin keys it names and those of
    /// the devices whose keys it names; of a device record, its device's
    /// admin key when it names another or none (a take-back). Such a key
    /// then has no room (`eval::rooms`): what it signed stays only as far
    /// as a checkpoint of the root keeps it, so the writer writes one
    /// first.
    fn admins_going(state: &State, kind: &Kind) -> BTreeSet<KeyHash> {
        match kind {
            Kind::Revoke(rm) => state
                .devices
                .iter()
                .filter_map(|d| d.admin.filter(|a| rm.keys.contains(a) || rm.keys.contains(&d.key.hash())))
                .collect(),
            Kind::Device(d) => state
                .device(&d.id())
                .and_then(|x| x.admin)
                .filter(|a| d.admin.as_ref().map(Key::hash) != Some(*a))
                .into_iter()
                .collect(),
            _ => BTreeSet::new(),
        }
    }

    /// The live admin keys (`eval::not_live`) that an admin's removal
    /// removed in state, when a root record naming admin key `new`, not
    /// named yet, would be past the first ADMIN_KEYS_MAX: what the root
    /// removes before it names `new`.
    fn live_removed_by_admins(&self, state: &State, new: &KeyHash) -> Vec<KeyHash> {
        let recs = || {
            self.records
                .values()
                .filter(|e| !eval::off_cut(&self.cuts, &e.record))
                .map(|e| (&e.record, self.role_of(e)))
        };
        let named: BTreeSet<KeyHash> = recs()
            .filter(|(r, role)| *role == Role::Root && self.path.contains(&r.body().signer))
            .filter_map(|(r, _)| match &r.body().kind {
                Kind::Device(d) => d.admin.as_ref().map(Key::hash),
                _ => None,
            })
            .collect();
        if named.contains(new) {
            return Vec::new();
        }
        let (_, _, live) = eval::not_live(&self.path, &self.cuts, recs());
        if live.len() < super::ADMIN_KEYS_MAX {
            return Vec::new();
        }
        let mut out: Vec<KeyHash> =
            named.into_iter().filter(|k| live.contains(k) && state.revoked.contains(k)).collect();
        out.sort();
        out
    }

    /// Writes signer's next ordinary record of kind (every type but a
    /// checkpoint, which `write_checkpoint` writes, and a change of root,
    /// which `write_change` writes): its seq and prev follow the key's
    /// head in the set, and the set takes it. It refuses, leaving the set
    /// as it was and using no seq, when the key has no room of its own,
    /// when the key's records would pass its ceiling, and when the set
    /// would not keep the record or it would not count: a record its own
    /// writer drops reaches nobody for sure, and one that passes the key's
    /// ceiling pushes the key's own older records out. The writer of every
    /// ordinary record of a group goes through it.
    /// A removal that names a key in two histories goes through
    /// `write_removal`, which keeps out what that key's removals bar.
    ///
    /// It gives back every record it added, in the order they go out: an
    /// admin key's first record after its grant counts comes after the
    /// acknowledgement the writer adds before it (the seen line), so that
    /// a caller that sends exactly what it gets leaves no gap.
    pub fn write_record(
        &mut self,
        state: &State,
        signer: &dyn ExternalKey,
        mut kind: Kind,
        time_ms: u64,
    ) -> crate::error::Result<Vec<Record>> {
        // A removal or a freeze cuts what the keys it names signed that
        // its seen does not hold: the honest writer fills the seen with
        // the heads it holds of those keys (and of their devices' other
        // key), as `write_removal` does. A caller's seen may add to them,
        // never shorten them: a short one would cut an admin's newest ack,
        // and with it the spare a change names.
        if let Kind::Revoke(rm) | Kind::Freeze(rm) = &mut kind {
            let mut seen: BTreeMap<KeyHash, super::body::Seen> = rm.seen.iter().map(|s| (s.key, *s)).collect();
            for h in self.heads_of(state, &rm.keys) {
                if seen.get(&h.key).is_none_or(|o| o.seq < h.seq) {
                    seen.insert(h.key, h);
                }
            }
            rm.seen = seen.into_values().collect();
        }
        if let Kind::Revoke(rm) = &kind
            && rm.keys.iter().any(|k| state.two_histories(k))
        {
            return Err(crate::error::Error::msg("a removal of a key in two histories is written with write_removal"));
        }
        if let Kind::Device(d) = &kind
            && let Some(a) = d.admin.as_ref().map(Key::hash)
            && self.taken_back(state).contains(&a)
        {
            return Err(crate::error::Error::msg(ADMIN_KEY_TAKEN_BACK));
        }
        // The seen line: an admin key's first record after its grant
        // counts is an acknowledgement, whose seen holds the root record
        // that named it; what the key signs after stands on that line. It
        // signs as an admin only once its state counts the grant.
        let h = Key::es256(signer.public()).hash();
        if !state.roots.contains(&h)
            && Self::live_admins(state).contains(&h)
            && !matches!(kind, Kind::Ack { .. })
            && !self.records.values().any(|e| e.record.body().signer == h && state.counting.contains(&e.record.id()))
        {
            let mut trial = self.clone();
            let ack = trial.write_ack(state, signer, time_ms)?;
            let now = trial.state();
            let r = trial.write_one(&now, signer, kind, time_ms)?;
            *self = trial;
            return Ok(alloc::vec![ack, r]);
        }
        Ok(alloc::vec![self.write_one(state, signer, kind, time_ms)?])
    }

    /// The one record a writer call added, where the call adds one.
    fn only(mut v: Vec<Record>) -> crate::error::Result<Record> {
        match (v.pop(), v.is_empty()) {
            (Some(r), true) => Ok(r),
            _ => Err(crate::error::Error::msg("the writer added other records than the one it gives back")),
        }
    }

    /// The root removes keys, some of them in two histories (F-7): the
    /// removal of such a key carries one seen head for it, so its removals
    /// on the other line would stop counting. First the root's own
    /// removals of every key those removals bar that no root removal bars
    /// yet (they count by themselves, in any order), then the removal of
    /// keys, as many records as their bodies need; all or nothing.
    pub fn write_removal(
        &mut self,
        state: &State,
        root: &dyn ExternalKey,
        keys: &[KeyHash],
        time_ms: u64,
    ) -> crate::error::Result<Vec<Record>> {
        use crate::error::Error;
        let h = Key::es256(root.public()).hash();
        if state.roots.last() != Some(&h) {
            return Err(Error::msg("only the current root writes this removal"));
        }
        let forked: BTreeSet<KeyHash> = keys.iter().copied().filter(|k| state.two_histories(k)).collect();
        let by_root: BTreeSet<KeyHash> = self
            .records
            .values()
            .filter(|e| e.record.body().signer == h && state.counting.contains(&e.record.id()))
            .filter_map(|e| match &e.record.body().kind {
                Kind::Revoke(rm) => Some(rm.keys.clone()),
                _ => None,
            })
            .flatten()
            .collect();
        let mut barred: BTreeSet<KeyHash> = BTreeSet::new();
        for e in self.records.values().filter(|e| forked.contains(&e.record.body().signer)) {
            if let Kind::Revoke(rm) = &e.record.body().kind
                && state.counting.contains(&e.record.id())
            {
                barred.extend(rm.keys.iter().copied());
            }
        }
        barred.retain(|k| !by_root.contains(k) && !keys.contains(k) && *k != h && *k != self.recovery.hash());
        let mut trial = self.clone();
        let mut out = Vec::new();
        let barred: Vec<KeyHash> = barred.into_iter().collect();
        for part in [barred, keys.to_vec()] {
            let mut rest = part.as_slice();
            while !rest.is_empty() {
                let mut n = rest.len();
                loop {
                    let chunk = rest.get(..n).unwrap_or_default();
                    let st = trial.state();
                    let rm = super::body::Removal { keys: chunk.to_vec(), seen: trial.heads_of(&st, chunk) };
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
                        let r = trial.write_one(&st, root, widest.kind, time_ms).map_err(|e| {
                            Error::msg(alloc::format!(
                                "the root's room cannot hold the removals that keep these devices out: {e}"
                            ))
                        })?;
                        out.push(r);
                        break;
                    }
                    n = n.div_ceil(2);
                }
                rest = rest.get(n..).unwrap_or_default();
            }
        }
        // The person keeps a way out from every state the writer reaches:
        // after this removal the root can still take back every live admin
        // key that holds removals back and write the checkpoint that then
        // settles them. A removal of only such keys is itself that way out.
        let holders: BTreeSet<KeyHash> = self.holders(state);
        let only_holders = keys.iter().all(|k| {
            holders.contains(k) || state.device_by_key(k).and_then(|d| d.admin).is_some_and(|a| holders.contains(&a))
        });
        if !only_holders && !trial.way_out(root, time_ms) {
            return Err(Error::msg(TAKE_BACK_FIRST));
        }
        *self = trial;
        Ok(out)
    }

    /// The live admin keys that hold a removal back: each has a counting
    /// removal it has not acknowledged (`unacknowledged`).
    fn holders(&self, state: &State) -> BTreeSet<KeyHash> {
        self.unacknowledged(state).into_iter().filter(|(_, n)| *n > 0).map(|(a, _)| a).collect()
    }

    /// Whether the root can still take back, one by one, every admin key
    /// that holds removals back, writing a checkpoint first where its room
    /// asks for one, and then write the checkpoint that settles: tried on
    /// a copy of the set, with the root's own key.
    fn way_out(&self, root: &dyn ExternalKey, time_ms: u64) -> bool {
        let mut t = self.clone();
        let checkpoint = |t: &mut RecordSet| -> bool {
            let st = t.state();
            let Ok(cp) = t.write_checkpoint(&st, root, time_ms) else { return false };
            let id = cp.id();
            let _ = t.insert(cp);
            t.state().counting.contains(&id)
        };
        let st = t.state();
        for a in t.holders(&st) {
            let st = t.state();
            if t.take_back(&st, root, &a, time_ms).is_err() {
                if !checkpoint(&mut t) {
                    return false;
                }
                let st = t.state();
                if t.take_back(&st, root, &a, time_ms).is_err() {
                    return false;
                }
            }
        }
        checkpoint(&mut t)
    }

    fn write_one(
        &mut self,
        state: &State,
        signer: &dyn ExternalKey,
        kind: Kind,
        time_ms: u64,
    ) -> crate::error::Result<Record> {
        self.write_one_after(state, signer, kind, time_ms, false)
    }

    /// write_one; `checkpointed` when the root just wrote the checkpoint
    /// that goes before a record that makes an admin key no longer an
    /// admin (`admins_going`).
    fn write_one_after(
        &mut self,
        state: &State,
        signer: &dyn ExternalKey,
        kind: Kind,
        time_ms: u64,
        checkpointed: bool,
    ) -> crate::error::Result<Record> {
        use crate::error::Error;
        if matches!(kind, Kind::Checkpoint { .. } | Kind::Recovery { .. }) {
            return Err(Error::msg("a checkpoint or a change of root has its own writer"));
        }
        if state.stop == eval::Stop::Full || state.halted() {
            return Err(Error::msg("the group is stopped: no record counts until the root is changed"));
        }
        let h = Key::es256(signer.public()).hash();
        if h == self.recovery.hash() {
            return Err(Error::msg("the recovery key writes only changes of root"));
        }
        if state.two_histories(&h) {
            return Err(Error::msg("this key signed two histories; the root must resolve them before it signs again"));
        }
        let Some(ceiling) = self.ceiling(&h) else {
            return Err(Error::msg("this key has no room in the group's records"));
        };
        // The 17th admin key the root names: a live key an admin removed
        // still holds one of the 16 places, since who is an admin is read
        // from root records alone (`eval::not_live`). The root removes it
        // first, so the new key is live (all or nothing).
        if state.roots.last() == Some(&h)
            && let Kind::Device(d) = &kind
            && let Some(a) = d.admin.as_ref().map(Key::hash)
        {
            let removed = self.live_removed_by_admins(state, &a);
            if !removed.is_empty() {
                let mut trial = self.clone();
                let rm = super::body::Removal { seen: trial.heads_of(state, &removed), keys: removed };
                trial.write_one(state, signer, Kind::Revoke(rm), time_ms)?;
                let now = trial.state();
                let r = trial.write_one(&now, signer, kind, time_ms)?;
                *self = trial;
                return Ok(r);
            }
        }
        // Checkpoint first before an admin key is no longer an admin: the
        // key then has no room, and what it signed that counts stays only
        // as the checkpoint keeps it (all or nothing). A removal is never
        // blocked: where no checkpoint can be written the record goes
        // alone, and `removal_warning` names the devices that leave.
        if !checkpointed && state.roots.last() == Some(&h) && !Self::admins_going(state, &kind).is_empty() {
            let written = self.write_checkpoint(state, signer, time_ms).ok().and_then(|cp| {
                let mut trial = self.clone();
                let id = cp.id();
                (trial.insert(cp).is_ok() && trial.state().checkpoint == Some(id)).then_some(trial)
            });
            if let Some(mut trial) = written {
                let now = trial.state();
                let r = trial.write_one_after(&now, signer, kind, time_ms, true)?;
                *self = trial;
                return Ok(r);
            }
        }
        let own = self.heads_where(|k| *k == h).into_iter().next();
        let (seq, prev) = own.map_or((1, None), |o| (o.seq.saturating_add(1), Some(o.id)));
        let body = Body { group: self.group, signer: h, seq, prev, time_ms, kind, held: false };
        if body.encode().len() > super::MAX_BODY {
            return Err(Error::msg("the record would be larger than a record may be"));
        }
        // Checkpoint first: a removal, freeze or resolve of the current
        // root passes the floor, but where it would leave no room for one
        // more of its size and the root's next checkpoint, the root writes
        // that checkpoint before it (unless its newest record is one), so
        // what the checkpoint settles frees room and removals go on.
        // Decided before signing, so the record is signed once.
        let early = matches!(body.kind, Kind::Revoke(_) | Kind::Freeze(_) | Kind::Resolve(_));
        let newest_is_checkpoint =
            own.and_then(|o| self.held(&o.id)).is_some_and(|r| matches!(r.body().kind, Kind::Checkpoint { .. }));
        if early && state.roots.last() == Some(&h) && !newest_is_checkpoint {
            let one = keep::units(body.encode().len().saturating_add(super::ENVELOPE_ALLOWANCE));
            let used = self.units.get(&h).copied().unwrap_or(0);
            let tight = self
                .checkpoint_units(state, h, time_ms)
                .is_some_and(|cp| used.saturating_add(one.saturating_mul(2)).saturating_add(cp) > ceiling);
            // All or nothing: where the record is refused after all, the
            // checkpoint is not kept either.
            if tight && let Ok(cp) = self.write_checkpoint(state, signer, time_ms) {
                let mut trial = self.clone();
                if trial.insert(cp).is_ok() {
                    let now = trial.state();
                    let r = trial.write_one(&now, signer, body.kind, time_ms)?;
                    *self = trial;
                    return Ok(r);
                }
            }
        }
        let r = Record::sign(body, signer)?;
        let role = self.keys.signer(&h).map_or(Role::Admin, |(_, role)| role);
        let used = self.units.get(&h).copied().unwrap_or(0);
        if used.saturating_add(eval::item(&r, role).units) > ceiling {
            return Err(Error::msg("this key's records would pass its room: the root must write a checkpoint first"));
        }
        let mut trial = self.clone();
        trial.insert(r.clone()).map_err(|e| Error::msg(alloc::format!("the set refuses the record: {e:?}")))?;
        let id = r.id();
        let after = trial.state();
        if let Kind::Device(d) = &r.body().kind
            && state.device(&d.id()).is_none()
            && state.devices.len() >= super::MAX_DEVICES
        {
            return Err(Error::msg(alloc::format!(
                "the group has {} devices already: remove one before adding another",
                super::MAX_DEVICES
            )));
        }
        if !trial.records.contains_key(&id) || !after.counting.contains(&id) {
            return Err(Error::msg("the group's records have no room for the record: it would not count"));
        }
        // The floor: the current root never writes itself out of its own
        // next checkpoint. After an ordinary record of it, its records and
        // the checkpoint it would then write stay root_floor_margin() below
        // its ceiling; the margin is for its removals, freezes, resolves
        // and take-backs, which pass the floor, as a lost device is removed
        // whatever the room says.
        // Taking an admin key back passes the floor too: it is how the root
        // frees removals its admins hold back (`take_back`).
        let takes_back = matches!(&r.body().kind, Kind::Device(d)
            if d.admin.is_none() && state.device_by_key(&d.key.hash()).is_some_and(|x| x.admin.is_some()));
        if state.roots.last() == Some(&h) && !eval::item(&r, Role::Root).early && !takes_back {
            let used = trial.units.get(&h).copied().unwrap_or(0);
            let fits = trial
                .checkpoint_units(&after, h, time_ms)
                .is_some_and(|cp| used.saturating_add(cp).saturating_add(root_floor_margin()) <= ceiling);
            if !fits {
                return Err(Error::msg(
                    "the root's records would leave no room for its next checkpoint: write a checkpoint first",
                ));
            }
        }
        // An admission never puts out a device that counted (the cap takes
        // devices in the order of their first record, which a new one may
        // come before).
        if matches!(r.body().kind, Kind::Device(_)) && state.devices.iter().any(|d| after.device(&d.id).is_none()) {
            return Err(Error::msg(alloc::format!(
                "the group has {} devices already: remove one before adding another",
                super::MAX_DEVICES
            )));
        }
        if let Kind::Device(d) = &r.body().kind
            && let Some(a) = &d.admin
            && !after.devices.iter().any(|x| x.admin == Some(a.hash()))
        {
            return Err(Error::msg(alloc::format!(
                "the group has {} admin keys already: remove one before making another device an admin",
                super::ADMIN_KEYS_MAX
            )));
        }
        *self = trial;
        Ok(r)
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
    /// list names, and those a root's newest checkpoint that does not count
    /// yet names (its heads, its keep and the record below it), that the
    /// set does not hold. A record whose ID a verified
    /// list names is taken from anyone. Each call is one round; a record
    /// asked for in MISSING_ROUNDS rounds without coming is given up, so an
    /// ID nobody holds is not asked for for ever; the new root's first
    /// checkpoint closes the list for good.
    pub fn missing(&mut self, state: &State) -> Vec<RecordId> {
        // The state's cut: the new root's first counting checkpoint has
        // narrowed it to what that checkpoint keeps.
        // And the new root's first checkpoint the next head waits for.
        // And what each root's newest checkpoint names that does not count
        // yet, and what every checkpoint of the current root above the
        // counting one names: it counts only when the set holds every
        // record it keeps.
        let (_, above) = self.line();
        let waiting: BTreeSet<RecordId> = self.kept_first().into_iter().chain(above.iter().copied()).collect();
        let named: Vec<RecordId> = waiting
            .iter()
            .filter(|id| !state.checkpoints.contains(id))
            .filter_map(|id| match self.get(id).map(|r| &r.body().kind) {
                Some(Kind::Checkpoint { heads, keep }) => {
                    Some(heads.iter().map(|h| h.id).chain(keep.iter().copied()).chain(self.get(id)?.body().prev))
                }
                _ => None,
            })
            .flatten()
            .collect();
        // And what the counting checkpoint names that the set lacks; while
        // the current root has two histories, what its checkpoints below
        // the fork seq name: one that pruned before its twin came (the
        // pair stops the group and nothing at or above it prunes) dropped
        // records a peer may still hold.
        let names = |r: &Record| -> Vec<RecordId> {
            match &r.body().kind {
                Kind::Checkpoint { heads, keep } => {
                    heads.iter().map(|h| h.id).chain(keep.iter().copied()).chain(r.body().prev).collect()
                }
                _ => Vec::new(),
            }
        };
        let counting: Vec<RecordId> = match (state.root_pair, state.roots.last()) {
            (Some((fork, _, _)), Some(cur)) => self
                .records
                .values()
                .filter(|e| e.record.body().signer == *cur && e.record.body().seq < fork)
                .flat_map(|e| names(&e.record))
                .collect(),
            _ => state.checkpoint.and_then(|id| self.get(&id)).map(names).unwrap_or_default(),
        };
        let want: BTreeSet<RecordId> = state
            .cut
            .iter()
            .flat_map(|c| c.keep.iter())
            .chain(state.first_missing.iter())
            .chain(named.iter())
            .chain(counting.iter())
            .chain(self.halves.values().map(|(_, _, o)| o))
            .filter(|id| !self.contains(id))
            .copied()
            .collect();
        self.asked.retain(|id, _| want.contains(id));
        self.no_room.retain(|id| want.contains(id));
        let mut out = Vec::new();
        for id in want {
            let n = self.asked.entry(id).or_insert(0);
            if *n < MISSING_ROUNDS {
                *n = n.saturating_add(1);
                out.push(id);
            }
        }
        // A checkpoint above the counting one whose records were asked for
        // in every round without staying is told once, with its reason
        // (`stuck_checkpoints`): one nobody offered, or only records the
        // place aside had no room for.
        let below: Vec<RecordId> = match (state.root_pair, state.roots.last()) {
            (Some((fork, _, _)), Some(cur)) => self
                .records
                .values()
                .filter(|e| {
                    let b = e.record.body();
                    b.signer == *cur && b.seq < fork && matches!(b.kind, Kind::Checkpoint { .. })
                })
                .map(|e| e.record.id())
                .collect(),
            _ => state.checkpoint.into_iter().collect(),
        };
        for cp in above.iter().chain(below.iter()) {
            let Some(Kind::Checkpoint { keep, .. }) = self.get(cp).map(|r| &r.body().kind) else { continue };
            let mut given_up = keep.iter().filter(|id| self.asked.get(*id).is_some_and(|n| *n >= MISSING_ROUNDS));
            let Some(first) = given_up.next() else { continue };
            if !self.stuck.contains_key(cp) {
                let offered = |id: &RecordId| self.no_room.contains(id);
                let why = if offered(first) && given_up.all(offered) { Stuck::NoRoom } else { Stuck::NeverOffered };
                self.marked = self.marked.saturating_add(1);
                self.stuck.insert(*cp, (self.marked, why));
                while self.stuck.len() > MAX_NOTICES {
                    let Some(old) = self.stuck.iter().min_by_key(|(_, (n, _))| *n).map(|(k, _)| *k) else { break };
                    self.stuck.remove(&old);
                }
            }
        }
        out
    }

    /// The current root's checkpoints still not whole after their records
    /// were asked for in MISSING_ROUNDS rounds (the counting one too, which
    /// a twin of a newer one brought back after that one pruned), each with its reason
    /// ([`Stuck`]), for the app to tell. Local, once per checkpoint; what
    /// counts does not change.
    pub fn stuck_checkpoints(&self) -> Vec<(RecordId, Stuck)> {
        let (first, above) = self.line();
        let st = self.state();
        let below = |cp: &RecordId| match (st.root_pair, st.roots.last(), self.held(cp)) {
            (Some((fork, _, _)), Some(cur), Some(r)) => r.body().signer == *cur && r.body().seq < fork,
            _ => false,
        };
        self.stuck
            .iter()
            .filter(|(cp, _)| above.contains(cp) || first.contains(cp) || below(cp))
            .map(|(cp, (_, why))| (*cp, *why))
            .collect()
    }

    /// The record id for peer, asked by its ID: only one `for_peer` would
    /// give it in state, else, for a device of the group, one the set
    /// holds among the rest, kept aside for a root whose change waits, or
    /// in the place aside. A removed key and a key that gets only a root
    /// fork's proof get nothing else by ID.
    pub fn for_peer_by_id<'a>(&'a self, state: &State, peer: &KeyHash, id: &RecordId) -> Option<&'a Record> {
        if state.halted() || state.revoked.contains(peer) || state.device_by_key(peer).is_none() {
            return self.for_peer(state, peer).into_iter().find(|r| r.id() == *id);
        }
        self.get(id)
    }

    /// The hash of the list the next valid recovery record waits for:
    /// ask the peers for it.
    pub fn missing_list(&self) -> Option<[u8; 32]> {
        self.waiting
    }

    /// Whether a held root's checkpoint that does not count yet names id
    /// (a head or a kept record). It only triggers a compaction.
    fn wanted(&self, id: &RecordId) -> bool {
        self.records.values().any(|e| {
            let Kind::Checkpoint { heads, keep } = &e.record.body().kind else { return false };
            e.role == Role::Root
                && (heads.iter().any(|h| h.id == *id) || keep.binary_search(id).is_ok())
                && !self.checkpoints.iter().any(|(s, h, _)| *s == e.record.body().signer && h == heads)
        })
    }

    /// Whether the record id is the first link a held checkpoint of a root
    /// lacks down its own chain, one the set has not compacted by: without
    /// it that checkpoint never counts, so an older checkpoint's pruning
    /// does not turn it away.
    fn links(&self, id: &RecordId) -> bool {
        self.records.values().any(|e| {
            let b = e.record.body();
            let Kind::Checkpoint { heads, keep } = &b.kind else { return false };
            if e.role != Role::Root {
                return false;
            }
            let mut at = b.prev;
            while let Some(p) = at {
                if p == *id {
                    let anchors = eval::anchors_of(heads, keep);
                    return !self.checkpoints.iter().any(|(s, h, a)| *s == b.signer && h == heads && *a == anchors);
                }
                at = self.records.get(&p).and_then(|e| e.record.body().prev);
            }
            false
        })
    }

    /// Whether the record id may make a root's checkpoint the set has not
    /// compacted by count: it is such a checkpoint, a record it names, or
    /// a record of its key below it. It only triggers a compaction.
    fn may_count(&self, id: &RecordId) -> bool {
        let Some(r) = self.held(id) else { return false };
        let (signer, seq) = (r.body().signer, r.body().seq);
        self.records.values().any(|e| {
            let b = e.record.body();
            let Kind::Checkpoint { heads, keep } = &b.kind else { return false };
            if e.role != Role::Root {
                return false;
            }
            let names = e.record.id() == *id
                || heads.iter().any(|h| h.id == *id)
                || keep.binary_search(id).is_ok()
                || b.signer == signer && seq < b.seq;
            // Compacted by already: only then are its anchors worth making.
            names
                && !self
                    .checkpoints
                    .iter()
                    .any(|(s, h, a)| *s == b.signer && h == heads && *a == eval::anchors_of(heads, keep))
        })
    }

    /// Compacts by the set's own state until nothing more goes.
    fn settle(&mut self) {
        for _ in 0..4 {
            let st = self.state();
            let before = self.checkpoints.clone();
            if self.compact(&st) == 0 && self.checkpoints == before {
                if self.switch() {
                    self.cut();
                    continue;
                }
                break;
            }
            // What the checkpoints keep first changed with what they
            // prune: the rooms are judged again over what is held.
            self.cut();
        }
        self.trim_aside();
    }

    /// Marks the keys of id, a root's removal a checkpoint prunes
    /// (`marks`).
    fn mark(&mut self, id: &RecordId) {
        let Some(e) = self.records.get(id) else { return };
        let (Role::Root, Kind::Revoke(rm)) = (e.role, &e.record.body().kind) else { return };
        let root = e.record.body().signer;
        let head = self
            .checkpoints
            .iter()
            .filter_map(|(_, heads, _)| heads.iter().find(|h| h.key == root).map(|h| h.seq))
            .max()
            .unwrap_or(0);
        for k in rm.keys.clone() {
            self.marked = self.marked.saturating_add(1);
            self.marks.insert(k, (self.marked, root, head));
        }
        while self.marks.len() > MAX_NOTICES {
            let oldest = self.marks.iter().min_by_key(|(_, (n, _, _))| *n).map(|(k, _)| *k);
            let Some(oldest) = oldest else { break };
            self.marks.remove(&oldest);
        }
    }

    /// The marked keys that count again in state other than by a newer
    /// record of a root, each with the record that admits it.
    fn marked_back(&self, state: &State) -> Vec<(RecordId, Vec<KeyHash>)> {
        let mut out = Vec::new();
        for (k, (_, root, head)) in &self.marks {
            if state.revoked.contains(k) || state.device_by_key(k).is_none() {
                continue;
            }
            let admits: Vec<&Record> = self
                .records
                .values()
                .map(|e| &e.record)
                .filter(|r| state.counting.contains(&r.id()))
                .filter(|r| matches!(&r.body().kind, Kind::Device(d) if d.key.hash() == *k))
                .collect();
            let newer = |r: &Record| {
                let b = r.body();
                state.roots.contains(&b.signer) && (b.signer != *root || b.seq > *head)
            };
            if let Some(r) = admits.iter().find(|r| !newer(r)) {
                out.push((r.id(), alloc::vec![*k]));
            }
        }
        out
    }

    /// Drops what the counting checkpoints of state leave out: a root's
    /// checkpoint resets the set's count. The cut takes state's, which the
    /// current root's first checkpoint narrows.
    pub(super) fn compact(&mut self, state: &State) -> usize {
        let path = state.roots.clone();
        let cuts = eval::cuts_of(state.cut.as_ref());
        self.keep_by(path, cuts);
        self.checkpoints = state
            .checkpoints
            .iter()
            .filter_map(|cp| {
                let b = self.held(cp)?.body();
                match &b.kind {
                    Kind::Checkpoint { heads, keep } => Some((b.signer, heads.clone(), eval::anchors_of(heads, keep))),
                    _ => None,
                }
            })
            .collect();
        let proof = self.proof();
        let wanted = self.aside_wanted(&self.line().1);
        let drop: Vec<RecordId> = self
            .records
            .values()
            .filter(|e| {
                !eval::proof_stays(&proof, &e.record, self.role_of(e)) && !eval::is_first(&self.firsts, &e.record)
            })
            .filter(|e| {
                let b = e.record.body();
                let listed =
                    self.cuts.get(&b.signer).is_some_and(|c| c.covers(&b.signer, b.seq) && c.keeps(&e.record.id()));
                !listed
                    && self
                        .checkpoints
                        .iter()
                        .any(|(_, heads, anchors)| eval::pruned_by(&e.record, self.role_of(e), heads, anchors))
            })
            .map(|e| e.record.id())
            .collect();
        for id in &drop {
            self.mark(id);
            self.drop_or_aside(id, &wanted);
        }
        // A key whose naming record the checkpoint left out is not known
        // any more, nor kept.
        if !drop.is_empty() {
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
    /// that name it; any other key the changes of root the set holds. While the group is halted,
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
            // In a root fork its removals count on every line (F-7), so it
            // is told them at any seq, also one that is half of the pair;
            // but never the pair as such: of two removals that make it, the
            // one with the smaller ID, and no other record of the pair.
            let pair = state.root_pair.map(|(_, a, b)| (a, b));
            let forked = |r: &Record| pair.is_some_and(|(a, b)| r.id() == a || r.id() == b);
            let names_it = |e: &&Entry| {
                matches!(&e.record.body().kind, Kind::Revoke(rm) if rm.keys.binary_search(peer).is_ok())
                    && (state.counting.contains(&e.record.id()) || forked(&e.record))
            };
            let mut out: Vec<&Record> = self.records.values().filter(names_it).map(|e| &e.record).collect();
            if let Some((a, b)) = pair
                && out.iter().any(|r| r.id() == a)
                && out.iter().any(|r| r.id() == b)
            {
                let drop = a.max(b);
                out.retain(|r| r.id() != drop);
            }
            if out.is_empty() {
                return out;
            }
            // And what proves each removal's signer to a device that may
            // not know it: the recovery chain with each new root's first
            // checkpoint (their lists ride beside, `lists`), and for an
            // admin the root's device record that names its admin key.
            // Nothing else: no copies, no settings, no other member.
            let own: BTreeSet<RecordId> = out.iter().map(|r| r.id()).collect();
            let mut ids = own.clone();
            // An admin's removal counts only on its whole chain, which the
            // device may not hold (it never got its own admission, or lost
            // it): the removal's own prev chain goes with it, down to seq 1
            // or to a counting checkpoint's anchor (which then goes too).
            // Only that key's records below the removal, one line: a twin
            // at some seq is on no prev chain. A root's removal counts by
            // itself and needs none.
            for r in out.iter().filter(|r| self.keys.is_admin(&r.body().signer)) {
                let (signer, mut seq) = (r.body().signer, r.body().seq);
                let mut prev = r.body().prev;
                while let Some(p) = prev {
                    match self.held(&p) {
                        Some(x) if x.body().signer == signer && x.body().seq < seq => {
                            ids.insert(p);
                            seq = x.body().seq;
                            prev = x.body().prev;
                        }
                        _ => {
                            ids.extend(state.checkpoints.iter().copied());
                            break;
                        }
                    }
                }
            }
            if out.iter().any(|r| r.body().signer != self.root_hash) {
                ids.extend(self.records.values().filter(|e| e.role == Role::Recovery).map(|e| e.record.id()));
                // Each new root's first checkpoint with its whole group: a
                // change applies whole or not at all (`eval::first_gap`).
                for id in self.firsts.keys() {
                    let Some(cp) = self.held(id) else { continue };
                    let (h, top) = (cp.body().signer, cp.body().seq);
                    ids.extend(
                        self.records
                            .values()
                            .filter(|e| e.record.body().signer == h && e.record.body().seq <= top)
                            .map(|e| e.record.id()),
                    );
                    // A record of the group a later checkpoint settled may
                    // be gone: the checkpoints that may settle it go too,
                    // with what they keep (`eval::first_gap`), those of the
                    // new root above the first and of the roots after it.
                    let settlers: BTreeSet<KeyHash> =
                        core::iter::once(h).chain(state.roots.iter().copied().skip_while(|k| *k != h)).collect();
                    for e in self.records.values() {
                        let b = e.record.body();
                        if !settlers.contains(&b.signer) || (b.signer == h && b.seq <= top) {
                            continue;
                        }
                        if let Kind::Checkpoint { heads, keep } = &b.kind
                            && heads.iter().any(|hd| hd.key == h)
                        {
                            ids.insert(e.record.id());
                            ids.extend(keep.iter().filter(|k| self.held(k).is_some()).copied());
                        }
                    }
                }
            }
            let admins: BTreeSet<KeyHash> =
                out.iter().map(|r| r.body().signer).filter(|k| self.keys.is_admin(k)).collect();
            for e in self.records.values().filter(|e| state.counting.contains(&e.record.id()) && !forked(&e.record)) {
                if let Kind::Device(d) = &e.record.body().kind
                    && d.admin.as_ref().is_some_and(|a| admins.contains(&a.hash()))
                    && self.on_path(&e.record.body().signer, self.role_of(e))
                {
                    // With its chain down to the root's first record or to
                    // a counting checkpoint's anchor, which then goes too.
                    ids.insert(e.record.id());
                    let mut prev = e.record.body().prev;
                    while let Some(p) = prev {
                        if !ids.insert(p) {
                            break;
                        }
                        match self.held(&p) {
                            Some(r) => prev = r.body().prev,
                            None => {
                                ids.remove(&p);
                                ids.extend(state.checkpoints.iter().copied());
                                break;
                            }
                        }
                    }
                }
            }
            out = self
                .in_dependency_order()
                .into_iter()
                .filter(|r| ids.contains(&r.id()) && (own.contains(&r.id()) || !forked(r)))
                .collect();
            return out;
        }
        if state.device_by_key(peer).is_some() {
            return self.in_dependency_order();
        }
        // A key a held record of the forked current root admits gets the
        // proof, the lowest pair, and the way out: a change of root the
        // set holds (the recovery records and each new root's records up
        // to its first checkpoint); nothing else.
        if state.proof_to.binary_search(peer).is_ok()
            && let Some((_, a, b)) = state.root_pair
        {
            let mut out: Vec<&Record> = [a, b].iter().filter_map(|id| self.held(id)).collect();
            out.extend(self.changes());
            return out;
        }
        // Any other key, one this set does not know (a sleeper whose only
        // peer is a replaced root's new phone, a device the person left
        // out, a device admitted on the other line of a root fork): the
        // pair that proves the current root's fork, which proves itself,
        // then the changes of root the set holds, the recovery records and
        // each new root's records up to its first checkpoint, so that it
        // can reach the last root (`insert_from_unknown`); nothing else.
        let mut out = self.root_pair_records(state);
        out.extend(self.changes());
        out
    }

    /// The two records that prove the current root's fork
    /// (`State::root_pair`), when the set holds both; else none.
    fn root_pair_records(&self, state: &State) -> Vec<&Record> {
        let Some((_, a, b)) = state.root_pair else { return Vec::new() };
        match (self.held(&a), self.held(&b)) {
            (Some(x), Some(y)) => alloc::vec![x, y],
            _ => Vec::new(),
        }
    }

    /// The changes of root the set holds: each recovery record, then the
    /// records of the root it names up to that root's first checkpoint.
    fn changes(&self) -> Vec<&Record> {
        let mut heads: Vec<&Record> =
            self.records.values().filter(|e| e.role == Role::Recovery).map(|e| &e.record).collect();
        heads.sort_by_key(|r| (r.body().seq, r.id()));
        let mut out = Vec::new();
        for head in heads {
            out.push(head);
            let Kind::Recovery { root, first, .. } = &head.body().kind else { continue };
            let h = root.hash();
            let mut firsts: Vec<&Record> = self
                .records
                .values()
                .map(|e| &e.record)
                .chain(self.early.values())
                .filter(|r| r.body().signer == h)
                .collect();
            let Some(cp) = firsts.iter().find(|r| r.id() == *first).map(|r| r.body().seq) else { continue };
            firsts.retain(|r| r.body().seq <= cp);
            firsts.sort_by_key(|r| r.body().seq);
            out.extend(firsts);
        }
        out
    }

    /// The lists a peer gets with what `for_peer` gives it: every list for
    /// a device of the group; for any other peer those the recovery
    /// records it is given name (a removed device, to place its removal's
    /// signer; a key that gets the proof, with the way out). A list is
    /// record IDs only.
    pub fn lists_for_peer(&self, state: &State, peer: &KeyHash) -> Vec<&[u8]> {
        if !state.halted() && !state.revoked.contains(peer) && state.device_by_key(peer).is_some() {
            return self.lists().collect();
        }
        let mut out: Vec<&[u8]> = Vec::new();
        for r in self.for_peer(state, peer) {
            if let Kind::Recovery { list, .. } = &r.body().kind
                && let Some(b) = self.list(list)
                && !out.contains(&b)
            {
                out.push(b);
            }
        }
        out
    }

    /// Takes a record from a peer that the set cannot place as a device,
    /// whose key a held record of the forked current root admits
    /// (`peer::Standing::ForkProof`): a halt stops acting, not taking. A
    /// record the current root signed, on either line and at any seq, goes
    /// through the ordinary insert (the pair judgment, the root room, the
    /// settled rules); so does a change of root (a recovery record, and the
    /// records of a root a held recovery record names), whose list comes
    /// by `insert_list`, which takes only a list a recovery record names.
    /// Nothing another key signed is read: `Added::Halted`. Once these
    /// records make the sender a device, the ordinary path takes the rest.
    pub fn insert_proof(&mut self, r: Record) -> Result<Added, Refused> {
        let b = r.body();
        let named = self.records.values().any(|e| {
            e.role == Role::Recovery
                && matches!(&e.record.body().kind, Kind::Recovery { root, .. } if root.hash() == b.signer)
        });
        let ours = b.signer == self.current_root() || b.signer == self.recovery.hash() || named;
        if b.group != self.group || !ours {
            return Ok(Added::Halted);
        }
        self.insert(r)
    }

    /// Takes a part of a sync from a peer the set does not know
    /// (`peer::Standing::Unknown`): a sleeper whose only peer is a replaced
    /// root's new phone, whose device key no record it counts names. The
    /// change of root is how such a peer becomes known, so the set takes
    /// what can carry the change and nothing else (L, "round 2 B"):
    /// - the recovery key's records, at most `UNKNOWN_PER_SEQ` of each seq
    ///   and none past `MAX_RECOVERY`, as the chain keeps them;
    /// - the lists those records name (`insert_list` takes no other);
    /// - once a recovery record the set holds names a root (on the path or
    ///   waiting for its record to apply), that root's records, within its
    ///   room as any record of it.
    ///
    /// Everything else (another key's records, records of a root no held
    /// recovery record names) is not read. The recovery key signs every
    /// head and each head's root signs what the head lets in, so such a
    /// peer can make up nothing the set counts: it can only withhold, which
    /// leaves the change pending as any peer can. Copies and commands are
    /// never taken from such a peer (the caller's rule). It returns how
    /// many records were new.
    pub fn insert_from_unknown(&mut self, records: &[Record], lists: &[&[u8]]) -> usize {
        let before = self.len();
        let recovery = self.recovery.hash();
        let mut per_seq: BTreeMap<u64, usize> = BTreeMap::new();
        let heads: Vec<Record> = records
            .iter()
            .filter(|r| {
                let b = r.body();
                b.group == self.group
                    && b.signer == recovery
                    && (b.held || matches!(b.kind, Kind::Recovery { .. }))
                    && (1..=super::body::MAX_RECOVERY).contains(&b.seq)
            })
            .filter(|r| {
                let n = per_seq.entry(r.body().seq).or_default();
                *n = n.saturating_add(1);
                *n <= UNKNOWN_PER_SEQ
            })
            .cloned()
            .collect();
        self.insert_all(heads);
        for l in lists {
            let _ = self.insert_list(l);
        }
        // The pair that proves a fork of the root this set counts: two
        // records of that root at one seq, the lowest such seq and its two
        // smallest IDs, taken only both together and only as such a pair
        // (one pair per root; nothing else of the root).
        if let Some(root) = self.path.last().copied() {
            let mut at: BTreeMap<u64, BTreeSet<RecordId>> = BTreeMap::new();
            for r in
                records.iter().filter(|r| r.body().group == self.group && r.body().signer == root && !r.body().held)
            {
                at.entry(r.body().seq).or_default().insert(r.id());
            }
            if let Some(pair) = at.values().find(|ids| ids.len() > 1) {
                let pair: Vec<RecordId> = pair.iter().take(2).copied().collect();
                let mut trial = self.clone();
                trial.insert_all(records.iter().filter(|r| pair.contains(&r.id())).cloned());
                let st = trial.state();
                if st.root_pair.is_some_and(|(_, a, b)| pair.contains(&a) && pair.contains(&b)) {
                    *self = trial;
                }
            }
        }
        // The roots a held recovery record names: those the chain put on
        // the path, and those whose record waits to apply.
        for _ in 0..2 {
            let named: BTreeSet<KeyHash> = self.promoted.iter().chain(self.early_roots.keys()).copied().collect();
            let theirs: Vec<Record> = records
                .iter()
                .filter(|r| r.body().group == self.group && named.contains(&r.body().signer))
                .cloned()
                .collect();
            self.insert_all(theirs);
        }
        self.len().saturating_sub(before)
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

/// The heads a record names in its seen, of any kind that carries one.
fn seen_of(k: &Kind) -> &[super::body::Seen] {
    match k {
        Kind::Revoke(r) | Kind::Freeze(r) => &r.seen,
        Kind::Thaw { seen, .. } | Kind::Hubs { seen, .. } | Kind::Copies { seen, .. } | Kind::Ack { seen, .. } => seen,
        Kind::Device(d) => &d.seen,
        _ => &[],
    }
}
