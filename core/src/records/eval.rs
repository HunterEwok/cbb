// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! Turns a set of records v3 into the group's state.
//!
//! The way conflicts between records are decided is that of records v2
//! (`crate::authority`), which the model and the vectors checked: chains
//! by `prev`, a resolve voiding a branch, the grounded labelling of admins'
//! removals, freezes and thaws, claims and their disputes, epochs along the
//! path of roots, checkpoints. What changes is around it: keys in place of
//! certificates, devices named by their key, who may sign which device
//! record, the limits, and no clock in any rule.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec;
use alloc::vec::Vec;

use super::body::{
    self, Body, Device, Head, Kind, POWER_ADMIT, POWER_FREEZE, POWER_HUB, POWER_MANAGE, POWER_REMOVE,
    POWER_REMOVE_ADMINS, POWER_TAKEOVER, POWER_THAW, RIGHT_HUB, RIGHT_READ, RIGHT_SECRETS, RIGHT_SEND, ROLE_LEAF,
    ROLE_WATCH, Removal, Seen, Settings,
};
use super::key::{DeviceId, GroupId, Key, KeyHash, RecordId};
use super::{
    MAX_ADMIN_RECORDS, MAX_DEVICES, MAX_FUTURE_ROOT_RECORDS, MAX_NEWER, MAX_PATH, MAX_ROOT_RECORDS, MAX_SEQ,
    RULES_VERSION, Record,
};

/// What the evaluation takes.
pub struct Input<'a> {
    /// The group's first root key; the group ID is its device ID.
    pub root: &'a Key,
    pub records: &'a [Record],
    /// How long the device itself has held each claim, by record ID: time
    /// it counted while running, kept across restarts by the caller. A
    /// claim missing here has been held for no time (rule 7).
    pub held_ms: &'a BTreeMap<RecordId, u64>,
    /// The claims this device has counted, by record ID, kept across
    /// restarts by the caller (`RecordSet::counted`): such a claim is
    /// final here, whatever records come later.
    pub counted: &'a BTreeSet<RecordId>,
}

/// Why a record of the set does not count.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum Why {
    /// It is of another group.
    Group,
    /// Its signer is no key the set names.
    Signer,
    /// It breaks a field's row, or its signature does not verify.
    Signature,
    /// Past a limit of the format or of the settings.
    Limit,
    /// Its prev chain is broken, on a voided branch, or past a fork.
    History,
    /// Its signer is no root on the path.
    NotRoot,
    /// A root's removal, freeze or thaw cut it off, or it is past its
    /// root's cut.
    Cut,
    /// Its signer has no power for it.
    Power,
    /// An admin's removal or freeze that counts cut it off.
    Removed,
    /// It is in a conflict between admins.
    Undecided,
    /// Two keys with one device ID: neither counts.
    IdConflict,
    /// A root's record that makes a leaf of another device, or another
    /// device of a leaf.
    Role,
}

impl Why {
    pub fn name(&self) -> &'static str {
        match self {
            Why::Group => "group",
            Why::Signer => "signer",
            Why::Signature => "signature",
            Why::Limit => "limit",
            Why::History => "history",
            Why::NotRoot => "not_root",
            Why::Cut => "cut",
            Why::Power => "power",
            Why::Removed => "removed",
            Why::Undecided => "undecided",
            Why::IdConflict => "id-conflict",
            Why::Role => "role",
        }
    }
}

/// A record that does not count, with why.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Ignored {
    pub record: RecordId,
    pub why: Why,
}

/// How many records a state lists in ignored.
pub const MAX_IGNORED: usize = 64;

/// How far the group is stopped.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Default)]
pub enum Stop {
    #[default]
    None,
    /// An admin has two histories: no secrets are sealed.
    Secrets,
    /// Competing claims, a conflict between admins, or a root with two
    /// histories: the group stops until a root resolves it. A root's own
    /// records still count (rule 8).
    Full,
}

/// A conflict of the state.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum ConflictKind {
    Admins,
    Claims,
    TwoHistories,
    /// Two admins admitted one device with different records.
    Admits,
    /// Two keys with one device ID.
    Ids,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Conflict {
    pub kind: ConflictKind,
    pub records: Vec<RecordId>,
    pub signers: Vec<KeyHash>,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ClaimState {
    Pending,
    Effective,
    Cancelled,
    Void,
    Competing,
    Disputed,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Claim {
    pub record: RecordId,
    pub claimant: KeyHash,
    pub root: KeyHash,
    pub state: ClaimState,
    /// How much longer the device must hold it before it takes effect.
    pub left_ms: u64,
}

/// One device of the state.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct DeviceState {
    pub id: DeviceId,
    pub key: Key,
    pub name: alloc::string::String,
    pub role: u64,
    pub rights: u64,
    pub skip: u64,
    pub caps: u64,
    pub os: u64,
    pub store: u64,
    pub proof: u64,
    pub admin: Option<KeyHash>,
    pub powers: u64,
    pub commands: u64,
    pub frozen: bool,
    pub replaces: Option<KeyHash>,
    /// A guarded leaf: its records are a root's alone.
    pub guarded: bool,
    /// Its records are a root's (else an admin admitted it).
    pub by_root: bool,
}

/// The group's state.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct State {
    pub group: GroupId,
    /// The path of roots, the current one last.
    pub roots: Vec<KeyHash>,
    pub root_device: Option<DeviceId>,
    pub devices: Vec<DeviceState>,
    pub revoked: Vec<KeyHash>,
    pub claims: Vec<Claim>,
    pub conflicts: Vec<Conflict>,
    pub stop: Stop,
    pub no_secrets_to: Vec<DeviceId>,
    pub nothing_to: Vec<DeviceId>,
    /// Held records a current root or admin signed: update to apply them.
    pub newer: Vec<RecordId>,
    pub ignored: Vec<Ignored>,
    /// The root's checkpoint that counts.
    pub checkpoint: Option<RecordId>,
    pub hubs: Vec<DeviceId>,
    /// The current root's newest settings that count, or the defaults.
    pub settings: Settings,
    /// The settings ask for newer rules than these: no secrets here.
    pub too_old: bool,
    pub incoming_ms: Option<u64>,
    pub recovery: Option<KeyHash>,
    /// The records that count.
    pub counting: BTreeSet<RecordId>,
    /// Every device ID a kept device record names, counting or not, a
    /// removed device's included: a new device never takes one.
    pub named: BTreeSet<DeviceId>,
    /// This device counted a takeover that records it now holds would
    /// have cancelled, disputed or rivalled: it and the group may
    /// disagree about the owner, and the app asks to join again.
    pub owner_split: bool,
    /// The takeovers' cuts of the roots before the current one: each the
    /// claim's seen entry for the root it cut.
    pub cuts: Vec<Seen>,
}

impl State {
    /// The device of the state with the member key k.
    pub fn device_by_key(&self, k: &KeyHash) -> Option<&DeviceState> {
        self.devices.iter().find(|d| &d.key.hash() == k)
    }

    pub fn device(&self, id: &DeviceId) -> Option<&DeviceState> {
        self.devices.binary_search_by(|d| d.id.cmp(id)).ok().and_then(|i| self.devices.get(i))
    }

    /// Reports whether a root's key signs: its records count whatever the
    /// stop (rule 8).
    pub fn is_root(&self, k: &KeyHash) -> bool {
        self.roots.last() == Some(k)
    }

    /// Reports whether key k has two histories.
    pub fn two_histories(&self, k: &KeyHash) -> bool {
        self.conflicts.iter().any(|c| c.kind == ConflictKind::TwoHistories && c.signers.contains(k))
    }

    /// Reports whether a device ID is taken: a kept device record names it.
    pub fn id_taken(&self, id: &DeviceId) -> bool {
        self.named.contains(id)
    }

    /// Reports whether a command signed by key k may be carried out: the
    /// current root's, unless it has two histories; an admin's that is
    /// neither removed nor frozen, while the group is not stopped and the
    /// key has one history. Nothing else signs commands.
    pub fn may_command(&self, k: &KeyHash) -> bool {
        if self.two_histories(k) || self.revoked.contains(k) {
            return false;
        }
        if self.is_root(k) {
            return true;
        }
        self.stop != Stop::Full && self.devices.iter().any(|d| d.admin.as_ref() == Some(k) && !d.frozen)
    }
}

/// The signer of a record: a root key or an admin key.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Role {
    Root,
    Admin,
}

/// The keys a set names: its first root, the new roots of admins'
/// claims, and the admin keys of the device and recovery records of the
/// first root and the roots the member promoted. A root that only a claim
/// names teaches no key. A record is verified with the key of its signer;
/// a signer the table does not know cannot be verified, and its record is
/// not stored.
#[derive(Clone, Default, Debug)]
pub struct Keys {
    keys: BTreeMap<KeyHash, Key>,
    roots: BTreeSet<KeyHash>,
    admins: BTreeSet<KeyHash>,
    /// The roots whose records teach admin keys: the first and the
    /// promoted ones.
    trusted: BTreeSet<KeyHash>,
}

impl Keys {
    pub fn new(root: &Key) -> Keys {
        Keys::trusting(root, &BTreeSet::new())
    }

    /// The table of a member that promoted roots after the first.
    pub fn trusting(root: &Key, promoted: &BTreeSet<KeyHash>) -> Keys {
        let mut k = Keys::default();
        let h = root.hash();
        k.keys.insert(h, root.clone());
        k.roots.insert(h);
        k.trusted.insert(h);
        k.trusted.extend(promoted.iter().copied());
        k
    }

    /// The signer's key and role. A key that is both an admin key and a
    /// claim's new root is an admin's: such a claim is void.
    pub fn signer(&self, h: &KeyHash) -> Option<(&Key, Role)> {
        let key = self.keys.get(h)?;
        if self.admins.contains(h) {
            Some((key, Role::Admin))
        } else if self.roots.contains(h) {
            Some((key, Role::Root))
        } else {
            None
        }
    }

    /// Learns the keys a verified record names; it reports whether it
    /// learned one.
    pub fn learn(&mut self, body: &Body, role: Role, held: bool) -> bool {
        if held {
            return false;
        }
        let trusted = self.trusted.contains(&body.signer);
        let (k, admin) = match (&body.kind, role) {
            (Kind::Device(Device { admin: Some(a), .. }), Role::Root) if trusted => (a, true),
            (Kind::Recovery { admin }, Role::Root) if trusted => (admin, true),
            (Kind::Claim { root, .. }, Role::Admin) => (root, false),
            _ => return false,
        };
        let h = k.hash();
        self.keys.entry(h).or_insert_with(|| k.clone());
        if admin { self.admins.insert(h) } else { self.roots.insert(h) }
    }

    pub fn is_admin(&self, h: &KeyHash) -> bool {
        self.admins.contains(h)
    }

    /// Forgets the roots of claims that keep does not hold: their claims
    /// were dropped, and their records with them.
    pub fn retain_roots(&mut self, keep: impl Fn(&KeyHash) -> bool) {
        let gone: Vec<KeyHash> = self.roots.iter().filter(|h| !keep(h)).copied().collect();
        for h in gone {
            self.roots.remove(&h);
            if !self.admins.contains(&h) {
                self.keys.remove(&h);
            }
        }
    }
}

/// A record the set verified, with its signer's role.
#[derive(Clone, Copy)]
pub(crate) struct Checked<'a> {
    pub r: &'a Record,
    pub role: Role,
    pub held: bool,
}

/// Verifies every record of a set: the keys are learned until no record
/// adds one, so the order of the set does not matter. It returns the
/// records that verify and why the others do not.
pub(crate) fn check_all<'a>(
    root: &Key,
    promoted: &BTreeSet<KeyHash>,
    records: &'a [Record],
) -> (Vec<Checked<'a>>, BTreeMap<RecordId, Why>) {
    let group = root.device_id();
    let mut keys = Keys::trusting(root, promoted);
    let mut failed = BTreeMap::new();
    let mut todo: Vec<&Record> = Vec::new();
    for r in records {
        if r.body().group != group {
            fail(&mut failed, r.id(), Why::Group);
        } else {
            todo.push(r);
        }
    }
    let mut done: BTreeMap<RecordId, Checked<'a>> = BTreeMap::new();
    loop {
        let mut learned = false;
        let mut rest = Vec::new();
        for r in todo {
            if done.contains_key(&r.id()) {
                continue;
            }
            match keys.signer(&r.body().signer) {
                None => rest.push(r),
                Some((key, role)) => match r.verify(key) {
                    Ok(held) => {
                        learned |= keys.learn(r.body(), role, held);
                        done.insert(r.id(), Checked { r, role, held });
                    }
                    Err(_) => fail(&mut failed, r.id(), Why::Signature),
                },
            }
        }
        todo = rest;
        if !learned || todo.is_empty() {
            break;
        }
    }
    for r in todo {
        if !done.contains_key(&r.id()) {
            fail(&mut failed, r.id(), Why::Signer);
        }
    }
    // A key learned late may make an admin of a key first taken for a
    // claim's root; roles are read again from the final table.
    let checked = done
        .into_values()
        .map(|mut c| {
            if let Some((_, role)) = keys.signer(&c.r.body().signer) {
                c.role = role;
            }
            c
        })
        .collect();
    (checked, failed)
}

/// Notes why a record was left out; of two reasons, the first in order is
/// kept, whatever the order of the set.
fn fail(failed: &mut BTreeMap<RecordId, Why>, id: RecordId, why: Why) {
    let old = failed.entry(id).or_insert(why);
    if why < *old {
        *old = why;
    }
}

/// A record's order where nothing else decides: seq, signer, ID; it
/// depends on the record alone.
pub(crate) fn order_key(b: &Body, id: &RecordId) -> (u64, KeyHash, RecordId) {
    (b.seq, b.signer, *id)
}

/// The record as the keeping sees it (`keep`).
pub(crate) fn item(r: &Record, role: Role) -> super::keep::Item {
    let claim = matches!(r.body().kind, Kind::Claim { .. });
    let early = role == Role::Root && matches!(r.body().kind, Kind::Revoke(_) | Kind::Freeze(_) | Kind::Resolve(_));
    super::keep::Item {
        early,
        signer: r.body().signer,
        seq: r.body().seq,
        id: r.id(),
        units: super::keep::units(r.size(), claim),
        checkpoint: matches!(r.body().kind, Kind::Checkpoint { .. }),
        names: match &r.body().kind {
            Kind::Claim { root, .. } => Some(root.hash()),
            _ => None,
        },
    }
}

/// The records of checked the set keeps: each key within its ceiling, the
/// set's room shared between keys. promoted are the roots the member's
/// evaluation put on the path after the first: they have a root's room; a
/// root only claims name has none of its own. cuts are the takeovers'
/// cuts of the roots before them: such a root keeps nothing off its cut
/// (`off_cuts`), and its checkpoints do not come first in its order.
pub(crate) fn kept_of(
    group_root: &KeyHash,
    promoted: &BTreeSet<KeyHash>,
    cuts: &BTreeMap<KeyHash, Seen>,
    checked: &[Checked<'_>],
) -> BTreeSet<RecordId> {
    let admins: BTreeSet<KeyHash> =
        checked.iter().filter(|c| c.role == Role::Admin).map(|c| c.r.body().signer).collect();
    let off = off_cuts(cuts, checked.iter().map(|c| c.r));
    let items: Vec<super::keep::Item> =
        checked.iter().filter(|c| !off.contains(&c.r.id())).map(|c| item_cut(c.r, c.role, cuts)).collect();
    super::keep::keep(&items, |k| ceiling_of(group_root, promoted, &admins, k))
}

/// A record's place in its key's order, where a root a takeover cut has
/// no checkpoint first.
pub(crate) fn item_cut(r: &Record, role: Role, cuts: &BTreeMap<KeyHash, Seen>) -> super::keep::Item {
    let mut it = item(r, role);
    if cuts.contains_key(&r.body().signer) {
        it.checkpoint = false;
    }
    it
}

/// The records off the cut of their signer: above the cut's seq, or at or
/// below it and not on the chain that ends at the cut's ID, as far as the
/// records show that chain (below a record the set does not hold, a
/// record is kept).
pub(crate) fn off_cuts<'r>(
    cuts: &BTreeMap<KeyHash, Seen>,
    records: impl Iterator<Item = &'r Record> + Clone,
) -> BTreeSet<RecordId> {
    let mut off = BTreeSet::new();
    if cuts.is_empty() {
        return off;
    }
    let by_id: BTreeMap<RecordId, &Record> =
        records.clone().filter(|r| cuts.contains_key(&r.body().signer)).map(|r| (r.id(), r)).collect();
    for (signer, cut) in cuts {
        // The chain from the cut's ID down, while the records show it.
        let mut chain: BTreeMap<u64, RecordId> = BTreeMap::new();
        let mut at = Some(cut.id);
        while let Some(r) = at.and_then(|id| by_id.get(&id)) {
            let b = r.body();
            if b.signer != *signer || chain.first_key_value().is_some_and(|(s, _)| b.seq >= *s) {
                break;
            }
            chain.insert(b.seq, r.id());
            at = b.prev;
        }
        for r in records.clone().filter(|r| r.body().signer == *signer) {
            let b = r.body();
            if b.seq > cut.seq || chain.get(&b.seq).is_some_and(|id| *id != r.id()) {
                off.insert(r.id());
            }
        }
    }
    off
}

/// A key's ceiling in the keeping: a root's on the path, an admin key's,
/// or None for a root only claims name.
pub(crate) fn ceiling_of(
    group_root: &KeyHash,
    promoted: &BTreeSet<KeyHash>,
    admins: &BTreeSet<KeyHash>,
    k: &KeyHash,
) -> Option<u64> {
    if k == group_root || promoted.contains(k) {
        Some(super::keep::ceiling(true))
    } else if admins.contains(k) {
        Some(super::keep::ceiling(false))
    } else {
        None
    }
}

/// Turns a record set into the group's state. Records that do not verify
/// are dropped; the result depends only on the set, never on its order.
///
/// It evaluates as a member that has compacted until its path no longer
/// changes: a root after the first that is on the path has a root's room
/// and teaches admin keys, and an old root keeps nothing off its cut.
pub fn evaluate(input: &Input) -> State {
    let mut promoted: BTreeSet<KeyHash> = BTreeSet::new();
    let mut cuts: BTreeMap<KeyHash, Seen> = BTreeMap::new();
    let mut split = false;
    let mut n = 0usize;
    loop {
        let (checked, failed) = check_all(input.root, &promoted, input.records);
        let mut state = evaluate_checked(input.root, checked, failed, input.held_ms, input.counted, &promoted, &cuts);
        // What a member held before it compacted still tells it that the
        // records dispute what it counted.
        split |= state.owner_split;
        let p: BTreeSet<KeyHash> = state.roots.iter().skip(1).copied().collect();
        let c: BTreeMap<KeyHash, Seen> = state.cuts.iter().map(|c| (c.key, *c)).collect();
        n = n.saturating_add(1);
        if (p == promoted && c == cuts) || n > MAX_PATH {
            state.owner_split = split;
            return state;
        }
        promoted = p;
        cuts = c;
    }
}

pub(crate) fn evaluate_checked(
    root: &Key,
    checked: Vec<Checked<'_>>,
    failed: BTreeMap<RecordId, Why>,
    held_ms: &BTreeMap<RecordId, u64>,
    counted: &BTreeSet<RecordId>,
    promoted: &BTreeSet<KeyHash>,
    cuts: &BTreeMap<KeyHash, Seen>,
) -> State {
    let group_root = root.hash();
    let full = Evaluation::new(root, checked.clone(), failed.clone(), BTreeSet::new(), promoted, cuts);
    // The set a root's checkpoint prunes is evaluated as if the member had
    // dropped what it leaves out; the checkpoint that counts is the newest
    // that still counts there.
    let mut best: Option<((usize, u64, RecordId), State)> = None;
    let plain = full.run(held_ms, counted);
    for c in full.checkpoints(&plain.path, &plain.cuts) {
        let Some(x) = full.recs.get(c) else { continue };
        let (Kind::Checkpoint { heads, keep }, id) = (&x.b().kind, x.id) else { continue };
        let anchors = anchors_of(heads, keep);
        let pruned: Vec<Checked> = checked.iter().copied().filter(|c| !pruned_by(c.r, heads, &anchors)).collect();
        let e = Evaluation::new(root, pruned, failed.clone(), anchors, promoted, cuts);
        let ep = e.run(held_ms, counted);
        let Some(i) = e.recs.iter().position(|r| r.id == id) else { continue };
        if !ep.root_record(i) {
            continue;
        }
        let key = (ep.on_path.get(&x.b().signer).copied().unwrap_or(0), x.b().seq, id);
        let better = match &best {
            None => true,
            Some((b, _)) => key.0 > b.0 || key.0 == b.0 && (key.1 > b.1 || key.1 == b.1 && key.2 < b.2),
        };
        if better {
            let mut state = ep.finish();
            state.checkpoint = Some(id);
            best = Some((key, state));
        }
    }
    let mut state = match best {
        Some((_, state)) => state,
        None => plain.finish(),
    };
    state.group = DeviceId::of(&group_root);
    state
}

/// Reports whether checkpoint heads (with anchors, its heads' and keep's
/// IDs) prune r: a record at or below its signer's head that is neither a
/// head nor kept.
pub(crate) fn pruned_by(r: &Record, heads: &[Head], anchors: &BTreeSet<RecordId>) -> bool {
    let b = r.body();
    heads
        .binary_search_by(|h| h.key.cmp(&b.signer))
        .ok()
        .and_then(|i| heads.get(i))
        .is_some_and(|h| b.seq <= h.seq && !anchors.contains(&r.id()))
}

pub(crate) fn anchors_of(heads: &[Head], keep: &[RecordId]) -> BTreeSet<RecordId> {
    heads.iter().map(|h| h.id).chain(keep.iter().copied()).collect()
}

struct Rec<'a> {
    r: &'a Record,
    id: RecordId,
    role: Role,
    held: bool,
    /// The device a device record is for.
    device: Option<DeviceId>,
}

impl Rec<'_> {
    fn b(&self) -> &Body {
        self.r.body()
    }
    fn admin(&self) -> bool {
        self.role == Role::Admin
    }
    /// A root's revoke, freeze or resolve: it comes early in its key's
    /// order (`keep`).
    fn early(&self) -> bool {
        item(self.r, self.role).early
    }
    fn dev(&self) -> Option<&Device> {
        match &self.b().kind {
            Kind::Device(d) if !self.held => Some(d),
            _ => None,
        }
    }
    fn removal(&self) -> Option<&Removal> {
        match &self.b().kind {
            Kind::Revoke(r) | Kind::Freeze(r) if !self.held => Some(r),
            _ => None,
        }
    }
    fn is_revoke(&self) -> bool {
        !self.held && matches!(self.b().kind, Kind::Revoke(_))
    }
    fn is_freeze(&self) -> bool {
        !self.held && matches!(self.b().kind, Kind::Freeze(_))
    }
    fn thaw(&self) -> Option<&[RecordId]> {
        match &self.b().kind {
            Kind::Thaw(v) if !self.held => Some(v),
            _ => None,
        }
    }
    fn claim(&self) -> Option<(&Key, &[Seen])> {
        match &self.b().kind {
            Kind::Claim { root, seen } if !self.held => Some((root, seen)),
            _ => None,
        }
    }
    fn seen_of(&self, k: &KeyHash) -> u64 {
        self.seen_entry(k).map_or(0, |s| s.seq)
    }
    fn seen_entry(&self, k: &KeyHash) -> Option<Seen> {
        match &self.b().kind {
            Kind::Claim { seen, .. } => body::seen_entry(seen, k),
            Kind::Revoke(r) | Kind::Freeze(r) => body::seen_entry(&r.seen, k),
            _ => None,
        }
    }
}

/// A takeover's cut of a root: the head of that root's chain the claim
/// saw. The root's records above it, or at or below it off that chain,
/// do not count once the claim does.
type Cut = Seen;

struct Evaluation<'a> {
    group_root: KeyHash,
    /// The heads and keep of the checkpoint it prunes by, where a prev
    /// chain may end.
    anchors: BTreeSet<RecordId>,
    failed: BTreeMap<RecordId, Why>,
    /// The new root of each claim, by its key hash.
    claim_roots: BTreeMap<KeyHash, Key>,
    /// The verified records within the set's ceilings.
    recs: Vec<Rec<'a>>,
    by_sig: BTreeMap<KeyHash, Vec<usize>>,
    /// Each record's position, by its ID.
    by_id: BTreeMap<RecordId, usize>,
    devices: BTreeMap<DeviceId, Vec<usize>>,
    /// Device records over MAX_DEVICES; of the same length as recs.
    capped_devices: Vec<bool>,
}

// The evaluation keeps its records in one Vec and refers to them by their
// positions, which it takes from that Vec itself, and its per-record flags
// are Vecs of the same length; so an index here is always in range.
#[allow(clippy::indexing_slicing, reason = "positions come from the records' own Vec")]
impl<'a> Evaluation<'a> {
    fn new(
        root: &Key,
        mut checked: Vec<Checked<'a>>,
        failed: BTreeMap<RecordId, Why>,
        anchors: BTreeSet<RecordId>,
        promoted: &BTreeSet<KeyHash>,
        cuts: &BTreeMap<KeyHash, Seen>,
    ) -> Evaluation<'a> {
        let group_root = root.hash();
        let kept = kept_of(&group_root, promoted, cuts, &checked);
        let mut failed = failed;
        for c in &checked {
            if !kept.contains(&c.r.id()) {
                fail(&mut failed, c.r.id(), Why::Limit);
            }
        }
        checked.retain(|c| kept.contains(&c.r.id()));
        checked.sort_by_key(|c| order_key(c.r.body(), &c.r.id()));
        let mut e = Evaluation {
            group_root,
            anchors,
            failed,
            claim_roots: BTreeMap::new(),
            recs: Vec::with_capacity(checked.len()),
            by_sig: BTreeMap::new(),
            by_id: BTreeMap::new(),
            devices: BTreeMap::new(),
            capped_devices: Vec::new(),
        };
        for (i, c) in checked.iter().enumerate() {
            let b = c.r.body();
            let device = match &b.kind {
                Kind::Device(d) if !c.held => Some(d.id()),
                _ => None,
            };
            if let (Kind::Claim { root, .. }, Role::Admin, false) = (&b.kind, c.role, c.held) {
                e.claim_roots.entry(root.hash()).or_insert_with(|| root.clone());
            }
            e.by_sig.entry(b.signer).or_default().push(i);
            e.by_id.insert(c.r.id(), i);
            if let Some(d) = device {
                e.devices.entry(d).or_default().push(i);
            }
            e.recs.push(Rec { r: c.r, id: c.r.id(), role: c.role, held: c.held, device });
        }
        // Over MAX_DEVICES: devices are taken in the order of their first
        // record (the records are in order_key order).
        let mut first: Vec<(usize, DeviceId)> = e.devices.iter().map(|(d, rs)| (rs[0], *d)).collect();
        first.sort();
        let over: BTreeSet<DeviceId> = first.into_iter().skip(MAX_DEVICES).map(|(_, d)| d).collect();
        e.capped_devices = e.recs.iter().map(|r| r.device.is_some_and(|d| over.contains(&d))).collect();
        e
    }

    /// Reports whether record t is on the chain that ends at the record
    /// with ID head: walking prev from head down to t's seq lands on t.
    /// Where the walk cannot go on (a record the set does not hold, or
    /// below a checkpoint's anchor), t is on it only when it is an anchor.
    fn on_chain(&self, head: &RecordId, t: usize) -> bool {
        let Some(tr) = self.recs.get(t) else { return false };
        let (signer, ts) = (tr.b().signer, tr.b().seq);
        let mut at = self.by_id.get(head).copied();
        loop {
            let Some(r) = at.and_then(|i| self.recs.get(i)) else { return self.anchors.contains(&tr.id) };
            if r.b().signer != signer || r.b().seq < ts {
                return false;
            }
            if r.b().seq == ts {
                return r.id == tr.id;
            }
            let next = r.b().prev.as_ref().and_then(|p| self.by_id.get(p)).copied();
            if next.and_then(|i| self.recs.get(i)).is_some_and(|p| p.b().seq >= r.b().seq) {
                return false;
            }
            at = next;
        }
    }

    /// Reports whether record t is within cut (one signer's seen head):
    /// at or below its seq and on its chain.
    fn within(&self, cut: &Seen, t: usize) -> bool {
        self.recs.get(t).is_some_and(|r| r.b().seq <= cut.seq) && self.on_chain(&cut.id, t)
    }

    /// Reports whether record h (a revoke, freeze or claim) saw record t.
    fn saw(&self, h: usize, t: usize) -> bool {
        let (Some(hr), Some(tr)) = (self.recs.get(h), self.recs.get(t)) else { return false };
        hr.seen_entry(&tr.b().signer).is_some_and(|cut| self.within(&cut, t))
    }

    /// The checkpoints the evaluation tries, by index: for each root on
    /// the path, its newest checkpoint within its cut (the highest seq,
    /// then the smallest ID).
    fn checkpoints(&self, path: &[KeyHash], cuts: &BTreeMap<KeyHash, Cut>) -> Vec<usize> {
        let mut newest: BTreeMap<KeyHash, usize> = BTreeMap::new();
        for (i, r) in self.recs.iter().enumerate() {
            let b = r.b();
            if r.held
                || r.role != Role::Root
                || !matches!(b.kind, Kind::Checkpoint { .. })
                || !path.contains(&b.signer)
                || cuts.get(&b.signer).is_some_and(|cut| !self.within(cut, i))
            {
                continue;
            }
            let better = newest.get(&b.signer).is_none_or(|&o| {
                let o = &self.recs[o];
                b.seq > o.b().seq || b.seq == o.b().seq && r.id < o.id
            });
            if better {
                newest.insert(b.signer, i);
            }
        }
        newest.into_values().collect()
    }

    /// The records of rs (one signer's, by_id their IDs) whose prev chain
    /// down to seq 1, or to an anchor, is held, each step one seq lower.
    /// A root's revoke, freeze or resolve counts by itself, without its
    /// chain (a full set keeps it before its key's other records); it does
    /// not make the records above it whole, since it states nothing about
    /// those below it.
    fn wholes(&self, rs: &[usize], by_id: &BTreeMap<RecordId, usize>, skip: &[bool]) -> BTreeSet<usize> {
        let step = |i: usize| -> Result<bool, usize> {
            let Some(r) = self.recs.get(i) else { return Ok(false) };
            if skip.get(i).copied().unwrap_or(false) {
                return Ok(false);
            }
            if r.b().seq <= 1 || self.anchors.contains(&r.id) {
                return Ok(true);
            }
            // A checkpoint's anchor stands for its chain even when the set
            // no longer holds it (a full key keeps its checkpoint first).
            let Some(&p) = r.b().prev.as_ref().and_then(|p| by_id.get(p)) else {
                return Ok(r.b().prev.as_ref().is_some_and(|p| self.anchors.contains(p)));
            };
            let Some(prev) = self.recs.get(p) else { return Ok(false) };
            if Some(prev.b().seq) != r.b().seq.checked_sub(1) {
                return Ok(false);
            }
            Err(p)
        };
        let mut memo = BTreeMap::new();
        let early = |i: usize| !skip.get(i).copied().unwrap_or(false) && self.recs.get(i).is_some_and(|r| r.early());
        rs.iter().copied().filter(|&i| early(i) || walk(&mut memo, i, step)).collect()
    }

    /// Turns the evaluation into its last epoch, with the claims of the
    /// roots before the current one.
    ///
    /// A claim the device has counted is final: under its root, that
    /// root's records above the claim's cut do not count, the claim takes
    /// effect without being decided again, and other claims of that epoch
    /// are left out.
    fn run(&self, held_ms: &BTreeMap<RecordId, u64>, counted: &BTreeSet<RecordId>) -> Epoch<'_, 'a> {
        let mut path = vec![self.group_root];
        let mut cuts = BTreeMap::new();
        let mut earlier = Vec::new();
        let mut split = false;
        loop {
            let cur = *path.last().unwrap_or(&KeyHash::default());
            let step = match self.counted_claim(&path, counted) {
                Some((c, cut)) => {
                    // What the records alone would decide, to know whether
                    // they now dispute what the device counted.
                    let mut plain = Epoch::new(self, path.clone(), cuts.clone());
                    let decided = plain.decide_claims(held_ms);
                    let id = self.recs[c].id;
                    let root = self.recs[c].claim().map(|(k, _)| k.hash());
                    split |= plain.claims.iter().any(|cl| {
                        cl.record == id
                            && matches!(
                                cl.state,
                                ClaimState::Cancelled | ClaimState::Competing | ClaimState::Disputed | ClaimState::Void
                            )
                    }) || decided.is_some_and(|(next, _)| Some(next) != root);
                    cuts.insert(cur, cut);
                    let mut ep = Epoch::new(self, path.clone(), cuts.clone());
                    let step = ep.decide_counted(c);
                    earlier.append(&mut ep.claims);
                    match step {
                        Some(next) => Some(next),
                        None => {
                            cuts.remove(&cur);
                            None
                        }
                    }
                }
                None => None,
            };
            if let Some(next) = step {
                path.push(next);
                continue;
            }
            let mut ep = Epoch::new(self, path.clone(), cuts.clone());
            match ep.decide_claims(held_ms) {
                Some((next, cut)) => {
                    earlier.append(&mut ep.claims);
                    cuts.insert(cur, cut);
                    path.push(next);
                }
                None => {
                    earlier.append(&mut ep.claims);
                    ep.claims = earlier;
                    ep.split = split;
                    return ep;
                }
            }
        }
    }

    /// The claim the device counted under the last root of path: an
    /// admin's claim it counted that saw that root, whose root is not on
    /// the path yet, and that saw no other such claim; of several, the
    /// smallest ID.
    fn counted_claim(&self, path: &[KeyHash], counted: &BTreeSet<RecordId>) -> Option<(usize, Cut)> {
        if counted.is_empty() || path.len() >= MAX_PATH {
            return None;
        }
        let cur = *path.last()?;
        let cands: Vec<usize> = (0..self.recs.len())
            .filter(|&i| {
                let r = &self.recs[i];
                r.admin()
                    && counted.contains(&r.id)
                    && r.seen_of(&cur) > 0
                    && r.claim().is_some_and(|(k, _)| !path.contains(&k.hash()))
            })
            .collect();
        cands
            .iter()
            .copied()
            .filter(|&c| {
                !cands.iter().any(|&o| {
                    o != c && self.saw(c, o)
                })
            })
            .min_by_key(|&c| self.recs[c].id)
            .and_then(|c| Some((c, self.recs[c].seen_entry(&cur)?)))
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Label {
    Unlabelled,
    In,
    Out,
    Undecided,
}

/// The evaluation under one path of roots.
struct Epoch<'e, 'a> {
    e: &'e Evaluation<'a>,
    path: Vec<KeyHash>,
    on_path: BTreeMap<KeyHash, usize>,
    cuts: BTreeMap<KeyHash, Cut>,
    cur: KeyHash,
    /// Records past a limit in this epoch: the per-key ceilings, the
    /// settings' admin limit, the future root's, and MAX_DEVICES.
    capped: Vec<bool>,
    voided: BTreeSet<RecordId>,
    counted: Vec<bool>,
    forked: BTreeMap<KeyHash, u64>,
    /// Each admin key with the device record that names it and gives its
    /// powers (or the recovery record).
    admins: BTreeMap<KeyHash, usize>,
    recovery: Option<usize>,
    /// For each device an admin admitted, the one record that counts by
    /// the power to admit.
    admitted: BTreeMap<DeviceId, usize>,
    /// The first records of admins that admitted one device differently.
    undecided_admits: BTreeSet<usize>,
    label: Vec<Label>,
    why: Vec<Option<super::eval::Why>>,
    revoked: BTreeSet<KeyHash>,
    frozen: BTreeSet<KeyHash>,
    conflicts: Vec<Conflict>,
    claims: Vec<Claim>,
    stop_full: bool,
    pending: Option<KeyHash>,
    settings: Settings,
    /// The device counted a claim that the records alone now dispute.
    split: bool,
}

#[allow(clippy::indexing_slicing, reason = "positions come from the records' own Vec")]
impl<'e, 'a> Epoch<'e, 'a> {
    fn new(e: &'e Evaluation<'a>, path: Vec<KeyHash>, cuts: BTreeMap<KeyHash, Cut>) -> Epoch<'e, 'a> {
        let cur = *path.last().unwrap_or(&KeyHash::default());
        let on_path = path.iter().enumerate().map(|(i, h)| (*h, i)).collect();
        let n = e.recs.len();
        let mut ep = Epoch {
            e,
            path,
            on_path,
            cuts,
            cur,
            capped: e.capped_devices.clone(),
            voided: BTreeSet::new(),
            counted: vec![false; n],
            forked: BTreeMap::new(),
            admins: BTreeMap::new(),
            recovery: None,
            admitted: BTreeMap::new(),
            undecided_admits: BTreeSet::new(),
            label: vec![Label::Unlabelled; n],
            why: vec![None; n],
            revoked: BTreeSet::new(),
            frozen: BTreeSet::new(),
            conflicts: Vec::new(),
            claims: Vec::new(),
            stop_full: false,
            pending: None,
            settings: Settings::default(),
            split: false,
        };
        // Roots on the path first: their ceilings do not depend on the
        // settings, which are a root's record.
        ep.cap_roots();
        ep.voided = ep.voids();
        let signers: Vec<KeyHash> = ep.on_path.keys().copied().collect();
        for s in &signers {
            ep.chain(*s);
        }
        if let Some(i) = ep.settings_record()
            && let Kind::Settings(s) = &ep.r(i).b().kind
        {
            ep.settings = s.clone();
        }
        ep.cap_others();
        let others: Vec<KeyHash> = e.by_sig.keys().filter(|k| !ep.on_path.contains_key(*k)).copied().collect();
        for s in others {
            ep.chain(s);
        }
        ep.find_admins();
        ep.find_admitted();
        ep.do_label();
        ep.collect();
        ep
    }

    fn r(&self, i: usize) -> &'e Rec<'a> {
        &self.e.recs[i]
    }

    fn all(&self) -> core::ops::Range<usize> {
        0..self.e.recs.len()
    }

    fn of(&self, signer: &KeyHash) -> &'e [usize] {
        self.e.by_sig.get(signer).map_or(&[], |v| v.as_slice())
    }

    /// One signer's records in the order its limit takes them: by seq,
    /// then ID.
    fn in_order(&self, signer: &KeyHash) -> Vec<usize> {
        let mut rs = self.of(signer).to_vec();
        rs.sort_by_key(|&i| (self.r(i).b().seq, self.r(i).id));
        rs
    }

    /// A root's ceiling, its records taken in the keeping's order: its
    /// checkpoints first, so that a full root can still checkpoint.
    fn cap_roots(&mut self) {
        let roots: Vec<KeyHash> = self.on_path.keys().copied().collect();
        for k in roots {
            let mut rs = self.of(&k).to_vec();
            rs.sort_by_key(|&i| item(self.r(i).r, self.r(i).role).pos());
            for i in rs.into_iter().skip(MAX_ROOT_RECORDS) {
                self.capped[i] = true;
            }
        }
    }

    /// The ceilings of the admins and of the future roots: an admin's
    /// records past the settings' admin limit; a future root's past 16,
    /// counted in its claimant's own.
    fn cap_others(&mut self) {
        let limit = MAX_ADMIN_RECORDS;
        let mut future_of: BTreeMap<KeyHash, Vec<KeyHash>> = BTreeMap::new();
        let mut taken: BTreeSet<KeyHash> = BTreeSet::new();
        for (k, rs) in &self.e.by_sig {
            if self.on_path.contains_key(k) || rs.first().is_none_or(|&i| self.r(i).admin()) {
                continue;
            }
            // A root not on the path: the root of claims; the first
            // claimant in key order counts its records.
            let mut claimants: Vec<KeyHash> = self
                .all()
                .filter(|&i| self.r(i).admin() && self.r(i).claim().is_some_and(|(root, _)| &root.hash() == k))
                .map(|i| self.r(i).b().signer)
                .collect();
            claimants.sort();
            match claimants.first() {
                Some(c) if taken.insert(*k) => future_of.entry(*c).or_default().push(*k),
                _ => {
                    for &i in rs {
                        self.capped[i] = true;
                    }
                }
            }
        }
        let admins: Vec<KeyHash> = self
            .e
            .by_sig
            .iter()
            .filter(|(k, rs)| !self.on_path.contains_key(*k) && rs.first().is_some_and(|&i| self.r(i).admin()))
            .map(|(k, _)| *k)
            .collect();
        for a in admins {
            let own = self.in_order(&a);
            let kept = own.len().min(limit);
            for &i in own.get(kept..).unwrap_or_default() {
                self.capped[i] = true;
            }
            let mut future: Vec<usize> =
                future_of.get(&a).into_iter().flatten().flat_map(|k| self.in_order(k)).collect();
            future.sort_by_key(|&i| (self.r(i).b().seq, self.r(i).b().signer, self.r(i).id));
            let room = limit.saturating_sub(kept).min(MAX_FUTURE_ROOT_RECORDS);
            for &i in future.get(room..).unwrap_or_default() {
                self.capped[i] = true;
            }
        }
        // Future roots whose claimant has no records here count nothing.
        for (a, ks) in &future_of {
            if self.e.by_sig.contains_key(a) {
                continue;
            }
            for k in ks {
                for &i in self.of(k) {
                    self.capped[i] = true;
                }
            }
        }
    }

    /// Reports whether record i is a root's own record that counts in this
    /// epoch: its root is on the path and it is within that root's cut.
    fn root_record(&self, i: usize) -> bool {
        let r = self.r(i);
        if r.admin() || r.held || !self.counted[i] || self.capped[i] || !self.on_path.contains_key(&r.b().signer) {
            return false;
        }
        self.cuts.get(&r.b().signer).is_none_or(|cut| self.e.within(cut, i))
    }

    /// The records the path's roots' resolve records name, each root's
    /// up to its cut; a resolve counts here when its own chain is whole.
    /// A root's removal is final: no resolve voids a revoke a root signed,
    /// its own or an earlier root's; a removed device comes back only with
    /// a new key.
    fn voids(&self) -> BTreeSet<RecordId> {
        let final_: BTreeSet<RecordId> =
            self.all().map(|i| self.r(i)).filter(|r| r.role == Role::Root && r.is_revoke()).map(|r| r.id).collect();
        let mut v = BTreeSet::new();
        for signer in self.on_path.keys() {
            let rs = self.of(signer);
            let by_id: BTreeMap<RecordId, usize> = rs.iter().map(|&i| (self.r(i).id, i)).collect();
            let wholes = self.e.wholes(rs, &by_id, &self.capped);
            let cut = self.cuts.get(signer);
            for &i in rs {
                let r = self.r(i);
                if let (Kind::Resolve(ids), Role::Root, false) = (&r.b().kind, r.role, r.held)
                    && cut.is_none_or(|cut| self.e.within(cut, i))
                    && wholes.contains(&i)
                {
                    v.extend(ids.iter().copied().filter(|id| !final_.contains(id)));
                }
            }
        }
        v
    }

    /// Finds which of one signer's records count: whole chains within the
    /// limits, not on a branch a resolve voided, below the lowest seq with
    /// two records.
    fn chain(&mut self, signer: KeyHash) {
        // A root a takeover cut has only the chain the claim saw.
        let cut = self.cuts.get(&signer).copied();
        let rs: Vec<usize> = self
            .of(&signer)
            .iter()
            .copied()
            .filter(|&i| !self.capped[i] && cut.is_none_or(|c| self.e.within(&c, i)))
            .collect();
        let by_id: BTreeMap<RecordId, usize> = rs.iter().map(|&i| (self.r(i).id, i)).collect();
        let mut by_seq: BTreeMap<u64, usize> = BTreeMap::new();
        for &i in &rs {
            let n = by_seq.entry(self.r(i).b().seq).or_default();
            *n = n.saturating_add(1);
        }
        let twins = |seq: u64| by_seq.get(&seq).copied().unwrap_or(0) > 1;
        // A record is dead when it or a record below it is voided and has
        // a twin of its seq; only whole chains are walked.
        let dead = |i: usize| -> Result<bool, usize> {
            let r = self.r(i);
            if self.voided.contains(&r.id) && twins(r.b().seq) {
                return Ok(true);
            }
            if r.b().seq == 1 || self.e.anchors.contains(&r.id) {
                return Ok(false);
            }
            match r.b().prev.as_ref().and_then(|p| by_id.get(p)) {
                Some(&p) => Err(p),
                None => Ok(false),
            }
        };
        let wholes = self.e.wholes(&rs, &by_id, &self.capped);
        let mut dead_memo = BTreeMap::new();
        let mut live: BTreeMap<u64, Vec<usize>> = BTreeMap::new();
        for &i in &rs {
            if wholes.contains(&i) && !walk(&mut dead_memo, i, dead) {
                live.entry(self.r(i).b().seq).or_default().push(i);
            }
        }
        let fork = live.iter().find(|(_, l)| l.len() > 1).map_or(MAX_SEQ.saturating_add(1), |(s, _)| *s);
        if fork <= MAX_SEQ {
            self.forked.insert(signer, fork);
        }
        for (seq, l) in live {
            for i in l {
                if seq < fork && !self.voided.contains(&self.r(i).id) {
                    self.counted[i] = true;
                }
            }
        }
    }

    /// Reports whether root record a is newer than b: a later root on the
    /// path, then a higher seq.
    fn newer(&self, a: usize, b: usize) -> bool {
        let (a, b) = (self.r(a).b(), self.r(b).b());
        let pa = self.on_path.get(&a.signer).copied().unwrap_or(0);
        let pb = self.on_path.get(&b.signer).copied().unwrap_or(0);
        if pa != pb {
            return pa > pb;
        }
        a.seq > b.seq
    }

    /// The admin keys: the admin of a device record a root on the path
    /// signed, with the powers of the newest such record; and the recovery
    /// key, with takeover only.
    fn find_admins(&mut self) {
        for rs in self.e.devices.values() {
            for &i in rs {
                let Some(a) = self.r(i).dev().and_then(|d| d.admin.as_ref()).map(Key::hash) else { continue };
                if !self.root_record(i) {
                    continue;
                }
                match self.admins.get(&a) {
                    Some(&old) if !self.newer(i, old) => {}
                    _ => {
                        self.admins.insert(a, i);
                    }
                }
            }
        }
        self.recovery = None;
        let roots: Vec<KeyHash> = self.on_path.keys().copied().collect();
        for signer in &roots {
            for &i in self.of(signer) {
                if matches!(self.r(i).b().kind, Kind::Recovery { .. })
                    && self.root_record(i)
                    && self.recovery.is_none_or(|old| self.newer(i, old))
                {
                    self.recovery = Some(i);
                }
            }
        }
        if let Some(i) = self.recovery
            && let Kind::Recovery { admin } = &self.r(i).b().kind
        {
            self.admins.entry(admin.hash()).or_insert(i);
        }
    }

    fn powers(&self, admin: &KeyHash) -> u64 {
        self.admins.get(admin).map_or(0, |&i| match &self.r(i).b().kind {
            Kind::Recovery { .. } => POWER_TAKEOVER,
            Kind::Device(d) => d.powers,
            _ => 0,
        })
    }

    fn has(&self, admin: &KeyHash, power: u64) -> bool {
        self.powers(admin) & power != 0
    }

    /// Reports whether k is the recovery key.
    fn is_recovery(&self, k: &KeyHash) -> bool {
        self.recovery.is_some_and(|i| matches!(&self.r(i).b().kind, Kind::Recovery { admin } if &admin.hash() == k))
    }

    /// The member key of the device whose record names admin key a.
    fn member_of_admin(&self, a: &KeyHash) -> Option<KeyHash> {
        self.admins.get(a).and_then(|&i| self.r(i).dev()).map(|d| d.key.hash())
    }

    /// Reports whether k is an admin key or the member key of a device
    /// whose newest root record names one.
    fn is_admin(&self, k: &KeyHash) -> bool {
        self.admins.contains_key(k) || self.admins.keys().any(|a| self.member_of_admin(a).as_ref() == Some(k))
    }

    /// Reports whether k is a root key or the member key of the root's own
    /// device.
    fn is_root(&self, k: &KeyHash) -> bool {
        self.e.claim_roots.contains_key(k)
            || k == &self.e.group_root
            || self.root_device().and_then(|d| self.r(d).dev()).is_some_and(|d| &d.key.hash() == k)
    }

    /// The current root's newest device record with holds_root.
    fn root_device(&self) -> Option<usize> {
        let mut best: Option<usize> = None;
        for &i in self.of(&self.cur) {
            if self.r(i).dev().is_some_and(|d| d.holds_root)
                && self.root_record(i)
                && best.is_none_or(|x| self.r(i).b().seq > self.r(x).b().seq)
            {
                best = Some(i);
            }
        }
        best
    }

    /// Reports whether any root record of the path counts for device d.
    fn root_has(&self, d: &DeviceId) -> bool {
        self.e.devices.get(d).is_some_and(|rs| rs.iter().any(|&i| self.root_record(i)))
    }

    /// The rights an admin may give: read and send, and secrets when the
    /// admin's own device has them (owner, 11.11).
    fn base_rights(&self, admin: &KeyHash) -> u64 {
        let own = self.admins.get(admin).and_then(|&i| self.r(i).dev()).map_or(0, |d| d.rights);
        RIGHT_READ | RIGHT_SEND | (own & RIGHT_SECRETS)
    }

    /// Reports whether device record i keeps within what admin a may sign
    /// for any device: base rights, no admin key, nothing a
    /// root alone gives. An admin may admit an ordinary leaf, never a
    /// watch or a guarded leaf (owner, 11.11).
    fn admin_device_ok(&self, a: &KeyHash, d: &Device) -> bool {
        d.rights & !self.base_rights(a) == 0
            && d.admin.is_none()
            && d.powers == 0
            && d.commands == 0
            && !d.holds_root
            && d.replaces.is_none()
            && d.role != ROLE_WATCH
            && !d.guarded
    }

    /// For each device no root recorded, the admin record that counts by
    /// the power to admit: of the counted records of admins with admit
    /// that keep within base rights, each admin's first, the one with the
    /// smallest ID. Every
    /// other admin record for the device needs manage (rule 3).
    fn find_admitted(&mut self) {
        let mut admitted = BTreeMap::new();
        let mut admit_conflicts = Vec::new();
        for (d, rs) in &self.e.devices {
            if self.root_has(d) {
                continue;
            }
            let best = rs
                .iter()
                .copied()
                .filter(|&i| {
                    let r = self.r(i);
                    r.admin()
                        && self.counted[i]
                        && !self.capped[i]
                        && self.has(&r.b().signer, POWER_ADMIT)
                        && r.dev().is_some_and(|dv| self.admin_device_ok(&r.b().signer, dv))
                })
                .collect::<Vec<usize>>();
            // Each admin's first record for the device (its lowest seq),
            // then of those the smallest ID.
            let firsts = best.iter().copied().filter(|&i| {
                let b = self.r(i).b();
                !best.iter().any(|&j| self.r(j).b().signer == b.signer && self.r(j).b().seq < b.seq)
            });
            let firsts: Vec<usize> = firsts.collect();
            // Two admins admitting one device differently: neither counts
            // until a root records it, so that no admin wins by its
            // record's ID (owner's call pending; see the PR).
            let same = firsts.windows(2).all(|w| matches!(w, [x, y] if self.r(*x).dev() == self.r(*y).dev()));
            if !same {
                admit_conflicts.push(firsts);
                continue;
            }
            if let Some(i) = firsts.into_iter().min_by_key(|&i| self.r(i).id) {
                admitted.insert(*d, i);
            }
        }
        for rs in admit_conflicts {
            let mut c = Conflict { kind: ConflictKind::Admits, records: Vec::new(), signers: Vec::new() };
            for i in rs {
                c.records.push(self.r(i).id);
                c.signers.push(self.r(i).b().signer);
                self.undecided_admits.insert(i);
            }
            self.conflicts.push(c);
        }
        self.admitted = admitted;
    }

    /// Reports whether an admin may sign record i.
    fn permitted(&self, i: usize) -> bool {
        let r = self.r(i);
        let a = &r.b().signer;
        if r.held || !self.admins.contains_key(a) || self.capped[i] {
            return false;
        }
        // The recovery key signs a claim and nothing else.
        if self.admins.get(a).is_some_and(|&j| matches!(self.r(j).b().kind, Kind::Recovery { .. }))
            && !matches!(r.b().kind, Kind::Claim { .. })
        {
            return false;
        }
        match &r.b().kind {
            Kind::Device(d) => {
                let Some(dev) = r.device else { return false };
                if self.root_has(&dev) || !self.admin_device_ok(a, d) {
                    // A device a root recorded is the root's to change.
                    return false;
                }
                match self.admitted.get(&dev) {
                    Some(&first) if first == i => true,
                    // Later records narrow the admitted one: its role,
                    // rights within its, skip covering its.
                    Some(&first) => {
                        let base = self.r(first).dev();
                        self.has(a, POWER_MANAGE)
                            && base.is_some_and(|b| {
                                d.role == b.role && d.rights & !b.rights == 0 && d.skip & b.skip == b.skip
                            })
                    }
                    None => false,
                }
            }
            Kind::Revoke(rm) => rm.keys.iter().all(|k| {
                if self.is_root(k) {
                    false
                } else if self.is_admin(k) {
                    self.has(a, POWER_REMOVE_ADMINS)
                } else {
                    self.has(a, POWER_REMOVE)
                }
            }),
            Kind::Freeze(rm) => {
                self.has(a, POWER_FREEZE)
                    && rm.keys.iter().all(|k| {
                        self.admins.contains_key(k)
                            && !self.has(k, POWER_REMOVE_ADMINS)
                            // The recovery key is frozen only by those who may remove it.
                            && (!self.is_recovery(k) || self.has(a, POWER_REMOVE_ADMINS))
                    })
            }
            Kind::Thaw(_) => self.has(a, POWER_THAW) && self.has(a, POWER_REMOVE_ADMINS),
            Kind::Claim { seen, .. } => self.has(a, POWER_TAKEOVER) && body::seen_of(seen, &self.cur) >= 1,
            Kind::Hubs(_) => self.has(a, POWER_HUB),
            // Any admin sets how long incoming copies stay live.
            Kind::Copies { .. } => true,
            _ => false,
        }
    }

    /// Reports whether a, a revoke or freeze, cuts off b: it names b's
    /// signer and saw fewer of its records than b's seq. A removal of its
    /// own signer's key cuts off only what that key signs after it, so
    /// that two of them never cut each other.
    fn cuts_off(&self, a: usize, b: usize) -> bool {
        let (ra, rb) = (self.r(a), self.r(b));
        let own = ra.b().signer == rb.b().signer;
        a != b
            && ra.removal().is_some_and(|rm| {
                self.with_pair(&rb.b().signer).iter().any(|k| rm.keys.binary_search(k).is_ok())
                    && if own { rb.b().seq > ra.b().seq } else { !self.e.saw(a, b) }
            })
    }

    fn thawed_by_root(&self) -> BTreeSet<RecordId> {
        let mut t = BTreeSet::new();
        for i in self.all() {
            if let Some(ids) = self.r(i).thaw()
                && self.root_record(i)
            {
                t.extend(ids.iter().copied());
            }
        }
        t
    }

    /// Gives every admin record its label: the grounded labelling of the
    /// attacks of removals, freezes and thaws.
    fn do_label(&mut self) {
        let thawed = self.thawed_by_root();
        let mut admin_recs = Vec::new();
        let mut root_acts = Vec::new();
        for i in self.all() {
            let r = self.r(i);
            if self.root_record(i) {
                if r.is_revoke() || r.is_freeze() && !thawed.contains(&r.id) {
                    root_acts.push(i);
                }
            } else if r.admin() && self.counted[i] && !r.held {
                if self.undecided_admits.contains(&i) {
                    self.label[i] = Label::Undecided;
                } else if !self.permitted(i) {
                    self.label[i] = Label::Out;
                    self.why[i] = Some(Why::Power);
                }
                admin_recs.push(i);
            }
        }
        for &b in &admin_recs {
            if self.label[b] == Label::Out {
                continue;
            }
            if self.r(b).is_freeze() && thawed.contains(&self.r(b).id) || root_acts.iter().any(|&a| self.cuts_off(a, b))
            {
                self.label[b] = Label::Out;
                self.why[b] = Some(Why::Cut);
            }
        }
        // Who attacks whom, by signer, so that this stays near linear: a
        // record is attacked by the removals naming its signer and by the
        // thaws naming it.
        let mut removals_of: BTreeMap<KeyHash, Vec<usize>> = BTreeMap::new();
        let mut thaws_of: BTreeMap<RecordId, Vec<usize>> = BTreeMap::new();
        for &a in &admin_recs {
            if self.label[a] == Label::Out {
                continue;
            }
            if let Some(rm) = self.r(a).removal() {
                for k in &rm.keys {
                    removals_of.entry(*k).or_default().push(a);
                }
            }
            if let Some(ids) = self.r(a).thaw() {
                for id in ids {
                    thaws_of.entry(*id).or_default().push(a);
                }
            }
        }
        let mut attackers: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
        for &b in &admin_recs {
            let rb = self.r(b);
            let mut by = Vec::new();
            // An admin's removal of a claimant does not cut its claim:
            // decide_claims sees it as a dispute.
            if rb.claim().is_none() {
                for &a in removals_of.get(&rb.b().signer).map_or(&[][..], |v| v.as_slice()) {
                    if self.cuts_off(a, b) {
                        by.push(a);
                    }
                }
            }
            if rb.is_freeze() {
                by.extend(thaws_of.get(&rb.id).into_iter().flatten().copied());
            }
            if !by.is_empty() {
                attackers.insert(b, by);
            }
        }
        let mut changed = true;
        while changed {
            changed = false;
            for &b in &admin_recs {
                if self.label[b] != Label::Unlabelled {
                    continue;
                }
                let mut all = true;
                for &a in attackers.get(&b).map_or(&[][..], |v| v.as_slice()) {
                    if self.label[a] == Label::In {
                        self.label[b] = Label::Out;
                        self.why[b] = Some(Why::Removed);
                        changed = true;
                        break;
                    }
                    if self.label[a] != Label::Out {
                        all = false;
                    }
                }
                if self.label[b] == Label::Unlabelled && all {
                    self.label[b] = Label::In;
                    changed = true;
                }
            }
        }
        let mut undec = Vec::new();
        for &b in &admin_recs {
            if self.label[b] == Label::Unlabelled {
                self.label[b] = Label::Undecided;
                let r = self.r(b);
                if r.removal().is_some() || r.thaw().is_some() {
                    undec.push(b);
                }
            }
        }
        self.conflicts_of(&undec, &attackers);
    }

    /// Groups undecided records that attack each other into conflicts.
    fn conflicts_of(&mut self, undec: &[usize], attackers: &BTreeMap<usize, Vec<usize>>) {
        let mut parent: BTreeMap<usize, usize> = undec.iter().map(|&r| (r, r)).collect();
        fn find(parent: &BTreeMap<usize, usize>, mut r: usize) -> usize {
            while let Some(&p) = parent.get(&r) {
                if p == r {
                    break;
                }
                r = p;
            }
            r
        }
        for &b in undec {
            for &a in attackers.get(&b).map_or(&[][..], |v| v.as_slice()) {
                if parent.contains_key(&a) {
                    let (ra, rb) = (find(&parent, a), find(&parent, b));
                    parent.insert(ra, rb);
                }
            }
        }
        let mut by_root: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
        for &r in undec {
            by_root.entry(find(&parent, r)).or_default().push(r);
        }
        for rs in by_root.values() {
            let mut c = Conflict { kind: ConflictKind::Admins, records: Vec::new(), signers: Vec::new() };
            for &r in rs {
                c.records.push(self.r(r).id);
                if !c.signers.contains(&self.r(r).b().signer) {
                    c.signers.push(self.r(r).b().signer);
                }
            }
            self.conflicts.push(c);
            self.stop_full = true;
        }
    }

    /// Reports whether record i counts: a root's record in this epoch, or
    /// an admin record that is in.
    fn counts(&self, i: usize) -> bool {
        self.root_record(i) || self.r(i).admin() && self.label[i] == Label::In
    }

    /// Finds the revoked and frozen keys and the two histories.
    fn collect(&mut self) {
        let thawed = self.thawed_by_root();
        for i in self.all() {
            if !self.counts(i) {
                continue;
            }
            let r = self.r(i);
            if let Some(rm) = r.removal() {
                if r.is_revoke() {
                    self.revoked.extend(rm.keys.iter().copied());
                } else if !thawed.contains(&r.id) {
                    self.frozen.extend(rm.keys.iter().copied());
                }
            }
        }
        // A device's member key and its admin key go together.
        let pairs: Vec<(KeyHash, KeyHash)> =
            self.admins.keys().filter_map(|a| self.member_of_admin(a).map(|m| (*a, m))).collect();
        for set in [&mut self.revoked, &mut self.frozen] {
            for (a, m) in &pairs {
                if set.contains(a) || set.contains(m) {
                    set.insert(*a);
                    set.insert(*m);
                }
            }
        }
        let forked: Vec<(KeyHash, u64)> = self.forked.iter().map(|(k, v)| (*k, *v)).collect();
        for (signer, seq) in forked {
            let records =
                self.of(&signer).iter().filter(|&&i| self.r(i).b().seq == seq).map(|&i| self.r(i).id).collect();
            self.conflicts.push(Conflict { kind: ConflictKind::TwoHistories, records, signers: vec![signer] });
            if self.on_path.contains_key(&signer) {
                self.stop_full = true;
            }
        }
    }

    /// The admin removals and freezes that count and name the admin key k
    /// or the member key of its device.
    fn removals(&self, k: &KeyHash) -> Vec<usize> {
        let mut keys = vec![*k];
        if let Some(m) = self.member_of_admin(k) {
            keys.push(m);
        }
        self.all()
            .filter(|&i| {
                let r = self.r(i);
                r.admin()
                    && self.label[i] == Label::In
                    && r.removal().is_some_and(|rm| keys.iter().any(|key| rm.keys.binary_search(key).is_ok()))
            })
            .collect()
    }

    /// Reports whether a root's freeze, not thawed by a root, names k.
    fn root_frozen(&self, k: &KeyHash) -> bool {
        if !self.frozen.contains(k) {
            return false;
        }
        let thawed = self.thawed_by_root();
        self.all().any(|i| {
            let r = self.r(i);
            r.is_freeze()
                && self.root_record(i)
                && !thawed.contains(&r.id)
                && r.removal().is_some_and(|rm| self.with_pair(k).iter().any(|k| rm.keys.binary_search(k).is_ok()))
        })
    }

    /// k with the other key of its device: an admin key's member key, or
    /// the admin key of the device whose member key k is.
    fn with_pair(&self, k: &KeyHash) -> Vec<KeyHash> {
        let mut keys = vec![*k];
        keys.extend(self.member_of_admin(k));
        keys.extend(self.admins.keys().filter(|a| self.member_of_admin(a).as_ref() == Some(k)).copied());
        keys
    }

    fn claim(&self, i: usize, state: ClaimState) -> Claim {
        let r = self.r(i);
        let root = r.claim().map(|(k, _)| k.hash()).unwrap_or_default();
        Claim { record: r.id, claimant: r.b().signer, root, state, left_ms: 0 }
    }

    /// The current root's newest record of a type that counts.
    fn newest_of_cur(&self, want: impl Fn(&Kind) -> bool) -> Option<usize> {
        let mut best: Option<usize> = None;
        for &i in self.of(&self.cur) {
            if !self.r(i).held
                && want(&self.r(i).b().kind)
                && self.root_record(i)
                && best.is_none_or(|s| self.r(i).b().seq > self.r(s).b().seq)
            {
                best = Some(i);
            }
        }
        best
    }

    fn settings_record(&self) -> Option<usize> {
        self.newest_of_cur(|k| matches!(k, Kind::Settings(_)))
    }

    fn handover(&self) -> Option<usize> {
        self.newest_of_cur(|k| matches!(k, Kind::Handover { .. }))
    }

    /// Reports whether a claim's new root is void by its key: the first
    /// root, a root already on the path, a key with the Group ID of one on
    /// the path, or a key the set uses as an admin key or a member key.
    fn void_root(&self, root: &KeyHash, claimant: &KeyHash) -> bool {
        let gid = DeviceId::of(root);
        root == claimant
            || self.on_path.contains_key(root)
            || self.path.iter().any(|p| DeviceId::of(p) == gid)
            || self.e.by_sig.get(root).is_some_and(|rs| rs.iter().any(|&i| self.r(i).admin()))
            || self.e.devices.values().flatten().any(|&i| self.r(i).dev().is_some_and(|d| d.key.hash() == *root))
    }

    /// Looks at the claims under the current root and returns the next
    /// root and the current root's cut when one takes effect.
    /// Takes claim c, which the device counted, as in effect; the other
    /// claims of this epoch are left out. None when the claim cannot be
    /// taken at all: it is capped here.
    fn decide_counted(&mut self, c: usize) -> Option<KeyHash> {
        if self.capped[c] {
            return None;
        }
        let mut cl = self.claim(c, ClaimState::Effective);
        cl.left_ms = 0;
        let next = cl.root;
        self.claims.push(cl);
        Some(next)
    }

    fn decide_claims(&mut self, held_ms: &BTreeMap<RecordId, u64>) -> Option<(KeyHash, Cut)> {
        let mut delay = self.settings.delay_ms();
        let cancelled = |c: usize| {
            let c = self.r(c);
            self.of(&self.cur).iter().any(|&i| {
                let r = self.r(i);
                self.root_record(i)
                    && match &r.b().kind {
                        Kind::Resolve(ids) => ids.binary_search(&c.id).is_ok(),
                        Kind::Revoke(rm) => rm.keys.binary_search(&c.b().signer).is_ok(),
                        _ => false,
                    }
            })
        };
        let mut live = Vec::new();
        let mut decided = Vec::new();
        for i in self.all() {
            let c = self.r(i);
            let Some((root, _)) = c.claim() else { continue };
            // A claim under this root: its claimant saw at least one of the
            // root's records.
            if !c.admin()
                || c.seen_of(&self.cur) == 0
                || !self.counted[i] && !self.voided.contains(&c.id)
                || self.capped[i]
            {
                continue;
            }
            let root = root.hash();
            let state = if self.void_root(&root, &c.b().signer) {
                Some(ClaimState::Void)
            } else if cancelled(i) {
                Some(ClaimState::Cancelled)
            } else if self.label[i] == Label::Out {
                Some(ClaimState::Void)
            } else {
                None
            };
            match state {
                Some(s) => decided.push(self.claim(i, s)),
                None => live.push(i),
            }
        }
        self.claims.append(&mut decided);
        // One claim for each admin key: of its live claims, its first.
        live.sort_by_key(|&i| (self.r(i).b().signer, self.r(i).b().seq, self.r(i).id));
        let mut one = Vec::new();
        for (n, &c) in live.iter().enumerate() {
            let again =
                n > 0 && live.get(n.saturating_sub(1)).is_some_and(|&p| self.r(p).b().signer == self.r(c).b().signer);
            if again {
                let cl = self.claim(c, ClaimState::Void);
                self.claims.push(cl);
            } else {
                one.push(c);
            }
        }
        // An admin's removal or freeze of a claimant that the claimant had
        // seen voids its claim; one it had not seen disputes it.
        let mut disputes: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
        let mut kept = Vec::new();
        for &c in &one {
            let cs = self.r(c).b().signer;
            let mut void = false;
            for r in self.removals(&cs) {
                if self.e.saw(c, r) {
                    void = true;
                } else {
                    disputes.entry(c).or_default().push(r);
                }
            }
            if void {
                let cl = self.claim(c, ClaimState::Void);
                self.claims.push(cl);
            } else {
                kept.push(c);
            }
        }
        // One claim at a time: a claim whose author held another live claim
        // counts for nothing.
        let mut first = Vec::new();
        for &c in &kept {
            let later = kept.iter().any(|&o| o != c && self.e.saw(c, o));
            if later {
                let cl = self.claim(c, ClaimState::Void);
                self.claims.push(cl);
            } else {
                first.push(c);
            }
        }
        if first.len() > 1 {
            let mut conflict = Conflict { kind: ConflictKind::Claims, records: Vec::new(), signers: Vec::new() };
            for &r in &first {
                let cl = self.claim(r, ClaimState::Competing);
                self.claims.push(cl);
                conflict.records.push(self.r(r).id);
                conflict.signers.push(self.r(r).b().signer);
            }
            self.conflicts.push(conflict);
            self.stop_full = true;
            return None;
        }
        let &c = first.first()?;
        if let Some(ds) = disputes.get(&c) {
            let cl = self.claim(c, ClaimState::Disputed);
            self.claims.push(cl);
            let mut conflict = Conflict {
                kind: ConflictKind::Claims,
                records: vec![self.r(c).id],
                signers: vec![self.r(c).b().signer],
            };
            for &r in ds {
                conflict.records.push(self.r(r).id);
                if !conflict.signers.contains(&self.r(r).b().signer) {
                    conflict.signers.push(self.r(r).b().signer);
                }
            }
            self.conflicts.push(conflict);
            self.stop_full = true;
            return None;
        }
        let r = self.r(c);
        let mut cl = self.claim(c, ClaimState::Pending);
        if let Some(h) = self.handover()
            && let Kind::Handover { admin } = &self.r(h).b().kind
            && *admin == r.b().signer
            && self.e.saw(c, h)
        {
            // The root handed the group to this admin: its claim, made after
            // it held the handover, takes effect without the delay.
            delay = 0;
        }
        let held = held_ms.get(&r.id).copied().unwrap_or(0);
        if self.label[c] != Label::In || self.root_frozen(&r.b().signer) || held < delay {
            cl.left_ms = delay.saturating_sub(held);
            self.claims.push(cl);
            self.pending = Some(r.b().signer);
            return None;
        }
        if self.path.len() >= MAX_PATH {
            cl.state = ClaimState::Void;
            self.claims.push(cl);
            return None;
        }
        cl.state = ClaimState::Effective;
        let next = cl.root;
        self.claims.push(cl);
        Some((next, r.seen_entry(&self.cur)?))
    }

    /// The record of a type, one a root or an admin signs, that counts for
    /// the state: a root's beats an admin's, then the later root on the
    /// path and the higher seq; of two admins', the smaller signer, then
    /// the higher seq (no clock decides, rule 7).
    fn best(&self, want: impl Fn(&Kind) -> bool) -> Option<usize> {
        let mut best: Option<usize> = None;
        for i in self.all() {
            if !self.r(i).held && want(&self.r(i).b().kind) && self.counts(i) && best.is_none_or(|b| self.beats(i, b)) {
                best = Some(i);
            }
        }
        best
    }

    fn beats(&self, a: usize, b: usize) -> bool {
        let (ra, rb) = (!self.r(a).admin(), !self.r(b).admin());
        if ra != rb {
            return ra;
        }
        if ra {
            return self.newer(a, b);
        }
        let (ba, bb) = (self.r(a).b(), self.r(b).b());
        if ba.signer != bb.signer {
            return ba.signer < bb.signer;
        }
        ba.seq > bb.seq
    }

    /// The counting records of a device that are not revoked.
    fn counting_of(&self, rs: &[usize]) -> Vec<usize> {
        rs.iter()
            .copied()
            .filter(|&i| self.counts(i) && !self.r(i).dev().is_some_and(|d| self.revoked.contains(&d.key.hash())))
            .collect()
    }

    /// Builds one device of the state from its counting records: a root's
    /// newest when a root recorded it; else the admitted record, narrowed
    /// by the counting manage records (rights intersected, skips joined),
    /// with the name of the newest of them.
    fn device(&self, id: &DeviceId, rs: &[usize]) -> Option<DeviceState> {
        let off = self.role_off(rs);
        let counting: Vec<usize> = self.counting_of(rs).into_iter().filter(|i| !off.contains(i)).collect();
        let roots: Vec<usize> = counting.iter().copied().filter(|&i| !self.r(i).admin()).collect();
        // Once a root's record guards the leaf, it stays guarded.
        let guarded = roots.iter().any(|&i| self.r(i).dev().is_some_and(|d| d.guarded));
        let (top, rights, skip) = if let Some(&first) = roots.first() {
            let top = roots.iter().copied().fold(first, |b, i| if self.newer(i, b) { i } else { b });
            let d = self.r(top).dev()?;
            (top, d.rights, d.skip)
        } else {
            let &first = self.admitted.get(id)?;
            if !counting.contains(&first) {
                return None;
            }
            let base = self.r(first).dev()?;
            let (mut rights, mut skip, mut top) = (base.rights, base.skip, first);
            for &i in &counting {
                if i == first {
                    continue;
                }
                let d = self.r(i).dev()?;
                rights &= d.rights;
                skip |= d.skip;
                let (bi, bt) = (self.r(i).b(), self.r(top).b());
                if top == first || (bi.seq, core::cmp::Reverse(bi.signer)) > (bt.seq, core::cmp::Reverse(bt.signer)) {
                    top = i;
                }
            }
            (top, rights, skip)
        };
        let n = self.r(top).dev()?;
        let by_root = !self.r(top).admin();
        let mut d = DeviceState {
            id: *id,
            key: n.key.clone(),
            name: n.name.clone(),
            role: n.role,
            rights,
            skip,
            caps: n.caps,
            os: n.os,
            store: n.store,
            proof: n.proof,
            admin: None,
            powers: 0,
            commands: 0,
            frozen: false,
            replaces: n.replaces,
            guarded,
            by_root,
        };
        if let Some(a) = n.admin.as_ref().map(Key::hash)
            && by_root
            && !self.revoked.contains(&a)
            && self.admins.get(&a) == Some(&top)
        {
            d.admin = Some(a);
            d.powers = n.powers;
            d.commands = n.commands;
            d.frozen = self.frozen.contains(&a);
        }
        Some(d)
    }

    /// A device's root records that make it a leaf when its oldest root
    /// record does not, or the other way: they do not count, so a leaf
    /// stays a leaf and a computer or a phone never becomes one.
    fn role_off(&self, rs: &[usize]) -> BTreeSet<usize> {
        let roots: Vec<usize> = rs.iter().copied().filter(|&i| self.root_record(i)).collect();
        let Some(&first) = roots.first() else { return BTreeSet::new() };
        let oldest = roots.iter().copied().fold(first, |b, i| if self.newer(b, i) { i } else { b });
        let leaf = |i: usize| self.r(i).dev().is_some_and(|d| d.role == ROLE_LEAF);
        roots.into_iter().filter(|&i| leaf(i) != leaf(oldest)).collect()
    }

    /// The devices with two keys for one ID: neither counts (owner, 11.11).
    fn id_conflicts(&self) -> BTreeMap<DeviceId, Vec<usize>> {
        let mut out = BTreeMap::new();
        for (id, rs) in &self.e.devices {
            let counting = self.counting_of(rs);
            let keys: BTreeSet<KeyHash> =
                counting.iter().filter_map(|&i| self.r(i).dev()).map(|d| d.key.hash()).collect();
            if keys.len() > 1 {
                out.insert(*id, counting);
            }
        }
        out
    }

    /// Builds the state of the last epoch.
    fn state(&self) -> State {
        let mut s = State { roots: self.path.clone(), ..State::default() };
        s.named = self.e.devices.keys().copied().collect();
        let id_conflicts = self.id_conflicts();
        let forked_admin = self.forked.keys().any(|k| !self.on_path.contains_key(k));
        for (id, rs) in &self.e.devices {
            if let Some(cs) = id_conflicts.get(id) {
                let mut c = Conflict { kind: ConflictKind::Ids, records: Vec::new(), signers: Vec::new() };
                for &i in cs {
                    c.records.push(self.r(i).id);
                    if let Some(d) = self.r(i).dev() {
                        c.signers.push(d.key.hash());
                    }
                }
                c.signers.dedup();
                s.conflicts.push(c);
                continue;
            }
            if let Some(d) = self.device(id, rs) {
                s.devices.push(d);
            }
            // The devices that an admin with two histories alone admitted
            // get nothing.
            let alone = !rs.is_empty()
                && rs.iter().all(|&i| self.forked.contains_key(&self.r(i).b().signer) && self.r(i).admin());
            if alone {
                s.nothing_to.push(*id);
            }
            if let Some(p) = self.pending
                && rs.iter().any(|&i| {
                    self.root_record(i) && self.r(i).dev().and_then(|d| d.admin.as_ref()).is_some_and(|a| a.hash() == p)
                })
            {
                s.no_secrets_to.push(*id);
            }
        }
        if let Some(d) = self.root_device()
            && let Some(dv) = self.r(d).dev()
            && !self.revoked.contains(&dv.key.hash())
            && !id_conflicts.contains_key(&dv.id())
        {
            s.root_device = Some(dv.id());
        }
        s.devices.sort_by_key(|d| d.id);
        s.nothing_to.sort();
        s.no_secrets_to.sort();
        s.revoked = self.revoked.iter().copied().collect();
        // A checkpoint may prune a removed device's record; its removal
        // still names its key.
        s.named.extend(self.revoked.iter().map(DeviceId::of));
        s.claims = self.claims.clone();
        s.claims.sort_by_key(|c| c.record);
        s.conflicts.extend(self.conflicts.iter().cloned());
        for c in &mut s.conflicts {
            c.records.sort();
            c.signers.sort();
            c.signers.dedup();
        }
        s.conflicts.sort_by(|a, b| (a.kind, a.records.first()).cmp(&(b.kind, b.records.first())));
        if let Some(best) = self.best(|k| matches!(k, Kind::Hubs(_)))
            && let Kind::Hubs(h) = &self.r(best).b().kind
        {
            s.hubs = h.iter().filter(|d| s.device(d).is_some_and(|d| d.rights & RIGHT_HUB != 0)).copied().collect();
        }
        if let Some(best) = self.best(|k| matches!(k, Kind::Copies { .. }))
            && let Kind::Copies { incoming_ms } = &self.r(best).b().kind
        {
            s.incoming_ms = Some(*incoming_ms);
        }
        s.settings = self.settings.clone();
        s.too_old = self.settings.rules() > RULES_VERSION;
        if let Some(i) = self.recovery
            && let Kind::Recovery { admin } = &self.r(i).b().kind
        {
            let a = admin.hash();
            if self.admins.get(&a) == Some(&i) && !self.revoked.contains(&a) && !self.frozen.contains(&a) {
                s.recovery = Some(a);
            }
        }
        s.stop = if self.stop_full {
            Stop::Full
        } else if forked_admin {
            Stop::Secrets
        } else {
            Stop::None
        };
        let mut conflicted: BTreeSet<usize> = id_conflicts.values().flatten().copied().collect();
        for rs in self.e.devices.values() {
            conflicted.extend(self.role_off(rs));
        }
        for i in self.all() {
            let claim_effective =
                self.claims.iter().any(|c| c.record == self.r(i).id && c.state == ClaimState::Effective);
            if (self.counts(i) || claim_effective) && !conflicted.contains(&i) {
                s.counting.insert(self.r(i).id);
            }
        }
        s
    }

    /// Why record i does not count in this epoch; None when it counts.
    fn why_not(&self, i: usize, counting: &BTreeSet<RecordId>, conflicted: &BTreeSet<RecordId>) -> Option<Why> {
        let r = self.r(i);
        Some(if counting.contains(&r.id) {
            return None;
        } else if conflicted.contains(&r.id) {
            Why::IdConflict
        } else if self
            .r(i)
            .device
            .is_some_and(|d| self.e.devices.get(&d).is_some_and(|rs| self.role_off(rs).contains(&i)))
        {
            Why::Role
        } else if self.capped[i] {
            Why::Limit
        } else if !self.counted[i] {
            Why::History
        } else if !r.admin() {
            if self.on_path.contains_key(&r.b().signer) { Why::Cut } else { Why::NotRoot }
        } else if self.label[i] == Label::Undecided {
            Why::Undecided
        } else {
            self.why[i].unwrap_or(Why::Power)
        })
    }

    /// The state, with the held records and those left out.
    fn finish(&self) -> State {
        let mut state = self.state();
        state.owner_split = self.split;
        state.cuts = self.cuts.values().copied().collect();
        let admins: BTreeSet<KeyHash> = state.devices.iter().filter_map(|d| d.admin).chain(state.recovery).collect();
        let cur = state.roots.last().copied();
        let mut newer: BTreeSet<RecordId> = BTreeSet::new();
        for i in self.all() {
            let r = self.r(i);
            if r.held && (Some(r.b().signer) == cur || admins.contains(&r.b().signer)) {
                newer.insert(r.id);
            }
        }
        state.newer = newer.iter().copied().take(MAX_NEWER).collect();
        let conflicted: BTreeSet<RecordId> = state
            .conflicts
            .iter()
            .filter(|c| c.kind == ConflictKind::Ids)
            .flat_map(|c| c.records.iter().copied())
            .collect();
        let mut why = self.e.failed.clone();
        for i in self.all() {
            let id = self.r(i).id;
            why.remove(&id);
            if self.r(i).held {
                continue;
            }
            if let Some(w) = self.why_not(i, &state.counting, &conflicted) {
                why.insert(id, w);
            }
        }
        state.ignored = why.into_iter().map(|(record, why)| Ignored { record, why }).take(MAX_IGNORED).collect();
        state
    }
}

/// Follows a chain from i by step, which either decides a record (Ok) or
/// names the record below it (Err), and gives every record on the way the
/// answer at its end; memo keeps the answers, so that each record is
/// stepped at most once across calls.
fn walk(memo: &mut BTreeMap<usize, bool>, mut i: usize, step: impl Fn(usize) -> Result<bool, usize>) -> bool {
    let mut path = Vec::new();
    let v = loop {
        if let Some(&v) = memo.get(&i) {
            break v;
        }
        match step(i) {
            Ok(v) => {
                memo.insert(i, v);
                break v;
            }
            Err(p) => {
                path.push(i);
                i = p;
            }
        }
    };
    for j in path {
        memo.insert(j, v);
    }
    v
}
