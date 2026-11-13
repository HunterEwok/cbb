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
use core::cell::RefCell;

use super::body::{
    self, Body, Device, Head, Kind, List, MAX_RECOVERY, POWER_ADMIT, POWER_FREEZE, POWER_HUB, POWER_MANAGE,
    POWER_REMOVE, POWER_REMOVE_ADMINS, POWER_THAW, RIGHT_HUB, RIGHT_READ, RIGHT_SECRETS, RIGHT_SEND, ROLE_LEAF,
    ROLE_WATCH, Removal, Seen, Settings,
};
use super::key::{DeviceId, GroupId, Key, KeyHash, RecordId, Recovery};
use super::{MAX_ADMIN_RECORDS, MAX_DEVICES, MAX_NEWER, MAX_ROOT_RECORDS, MAX_SEQ, RULES_VERSION, Record};

/// What the evaluation takes.
pub struct Input<'a> {
    /// The group's first root key.
    pub root: &'a Key,
    /// The group's recovery key, made with the group (rule 33): its two
    /// halves; the Group ID commits to all three keys (`key::group_id`).
    pub recovery: &'a Recovery,
    pub records: &'a [Record],
    /// The recovery records' lists the device holds, as their bytes
    /// (`List`).
    pub lists: &'a [Vec<u8>],
}

/// The newest recovery record's cut of every root before the current one
/// (rules 32 and 33): of those roots only the records its list names
/// count, and are kept; lists do not add up.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Cut {
    /// The roots before the current one, in the order of the path.
    pub roots: Vec<KeyHash>,
    /// The current root, and the seq its records as the root start at
    /// (the record's `from`): a key that signed as an admin before the
    /// chain made it the root keeps of its records below it only what the
    /// list names; 0 for a new key.
    pub current: KeyHash,
    pub from: u64,
    /// The recovery record.
    pub record: RecordId,
    /// The hash of its list.
    pub list: [u8; 32],
    /// The IDs that stay: its list, narrowed by the current root's first
    /// checkpoint once one counts.
    pub keep: BTreeSet<RecordId>,
}

impl Cut {
    /// Whether the cut covers a record of signer at seq.
    pub fn covers(&self, signer: &KeyHash, seq: u64) -> bool {
        self.roots.contains(signer) || *signer == self.current && seq < self.from
    }

    /// Whether r, of a cut root, is listed.
    pub fn keeps(&self, r: &RecordId) -> bool {
        self.keep.contains(r)
    }

    /// Whether r counts as far as the cut goes: it is not covered, or
    /// listed.
    pub fn lets(&self, r: &Record) -> bool {
        !self.covers(&r.body().signer, r.body().seq) || self.keep.contains(&r.id())
    }
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
    /// A root's removal, freeze or thaw cut it off, or a takeover
    /// followed its root and does not list it.
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
    /// A conflict between admins, or a root with two histories: the group
    /// stops until a root resolves it, and a root's own records still
    /// count (rule 8). Two records at one step of the recovery chain: the
    /// group stops for good and nothing acts, the root neither
    /// ([`State::halted`], rule 33).
    Full,
}

/// A conflict of the state.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum ConflictKind {
    Admins,
    /// Two recovery records at one seq, or one the device cannot read: the
    /// group stops for good (rule 33).
    Fork,
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

/// What a recovery record came to (rule 33).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ChangeState {
    /// It changed the root.
    Effective,
    /// Its new root is a root already on the path: it changes nothing,
    /// and the chain ends before it.
    Void,
    /// Another record stands at its seq: the group stops for good.
    Competing,
}

/// A recovery record of the chain.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Change {
    pub record: RecordId,
    pub seq: u64,
    pub root: KeyHash,
    pub state: ChangeState,
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
    /// The recovery records, by seq.
    pub changes: Vec<Change>,
    pub conflicts: Vec<Conflict>,
    pub stop: Stop,
    pub no_secrets_to: Vec<DeviceId>,
    pub nothing_to: Vec<DeviceId>,
    /// Held records a current root or admin signed: update to apply them.
    pub newer: Vec<RecordId>,
    pub ignored: Vec<Ignored>,
    /// The root's checkpoint that counts: the last of checkpoints.
    pub checkpoint: Option<RecordId>,
    /// The roots' checkpoints that count, in the order of the path, at
    /// most one for each root: a member drops what each leaves out.
    pub checkpoints: Vec<RecordId>,
    pub hubs: Vec<DeviceId>,
    /// The current root's newest settings that count, or the defaults.
    pub settings: Settings,
    /// The settings ask for newer rules than these: no secrets here.
    pub too_old: bool,
    pub incoming_ms: Option<u64>,
    /// The group's recovery key.
    pub recovery: KeyHash,
    /// The records that count.
    pub counting: BTreeSet<RecordId>,
    /// Every device ID a kept device record names, counting or not, a
    /// removed device's included: a new device never takes one.
    pub named: BTreeSet<DeviceId>,
    /// The newest recovery record's cut of the roots before the current
    /// one.
    pub cut: Option<Cut>,
    /// The list of the next valid recovery record, which the device does
    /// not hold yet: the change waits for it; ask the peers.
    pub list_missing: Option<[u8; 32]>,
    /// A recovery record this version cannot read: the device stops by
    /// itself until it is updated (not a fork, not final).
    pub update_needed: bool,
    /// The new root's first checkpoint the next valid recovery record
    /// names, which the device does not hold yet: the change waits for
    /// it; ask the peers.
    pub first_missing: Option<RecordId>,
    /// The lowest seq at which the set holds two recovery records, and
    /// the two (the smaller ID first): the proof of a fork.
    pub fork: Option<(u64, RecordId, RecordId)>,
    /// While the current root has two histories: the lowest seq at which
    /// the set holds two of its records, and the two smallest IDs there
    /// (the smaller first). The proof a member hands on (`proof_to`).
    pub root_pair: Option<(u64, RecordId, RecordId)>,
    /// While the current root has two histories: the keys a held record of
    /// that root admits, on either line, that no held root removal names
    /// and that are no device of the state, sorted. Each gets the proof
    /// (`root_pair`) and nothing else (`peer::Standing::ForkProof`).
    pub proof_to: Vec<KeyHash>,
    /// A removed key that had two histories, with the keys its removals
    /// on a whole chain named that no longer count (the removal of the key
    /// saw one line) and that nothing else bars, sorted: a notice for the
    /// app ("a forked key was removed; its removals on the other line no
    /// longer count"). `RecordSet::write_removal` leaves none.
    pub forked_removed: Vec<(KeyHash, Vec<KeyHash>)>,
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

    /// Reports whether a peer whose recovery chain is peer (its
    /// `chain`) disagrees with this device about the owner: neither chain
    /// starts with the other. A peer whose chain is shorter has not got
    /// the newest record yet, and one whose is longer has one more; only
    /// two chains that part say that the two count different owners, and
    /// the records of both are a fork (rule 33).
    pub fn disagrees(&self, peer: &[RecordId]) -> bool {
        let mine = self.chain();
        !(mine.starts_with(peer) || peer.starts_with(&mine))
    }

    /// The recovery records that moved the path, in order.
    pub fn chain(&self) -> Vec<RecordId> {
        self.changes.iter().filter(|c| c.state == ChangeState::Effective).map(|c| c.record).collect()
    }

    /// Reports whether the group is halted on this device (rule 33): it
    /// holds two recovery records at one seq, the proof of a fork, and is
    /// stopped for good; or a recovery record it cannot read, and is
    /// stopped until it is updated. Nothing in the state acts then: no root
    /// or admin commands, no device is admitted, no copy is sealed or
    /// opened. The state stays readable, so the owner sees the devices when
    /// making the next group, and the device still passes the recovery
    /// records on.
    ///
    /// What a halted state shows is computed from the recovery chain below
    /// the fork (or below the record it cannot read) and the records the
    /// newest list applied there names, and nothing else: the roots of
    /// that chain, and the devices and removals those listed records make.
    /// The last root's records that list does not name do not show; after
    /// a fork at seq 1 the state is the first root and the recovery chain
    /// alone. So every member that holds the proof shows the same, however
    /// its records came, and `fork` names the seq and the two records.
    pub fn halted(&self) -> bool {
        self.update_needed || self.conflicts.iter().any(|c| c.kind == ConflictKind::Fork)
    }

    /// Whether the group is stopped for every action: halted (`halted`),
    /// or the current root has two histories (a root fork, which only a
    /// change of root by the recovery key ends). Nothing is sealed,
    /// opened, sealed again, admitted, taken from a waiting joiner or
    /// commanded, and no checkpoint is written, while it holds. Sync goes
    /// on in a root fork: only `halted` stops it (`peer::standing`,
    /// `RecordSet::for_peer`), so that the pair and the writer's list
    /// reach every member.
    pub fn stopped(&self) -> bool {
        self.halted() || self.roots.last().is_some_and(|r| self.two_histories(r))
    }

    /// Reports whether a command signed by key k may be carried out: the
    /// current root's, unless it has two histories; an admin's that is
    /// neither removed nor frozen, while the group is not stopped and the
    /// key has one history. Nothing else signs commands, and no key does
    /// while the group is stopped (`stopped`).
    pub fn may_command(&self, k: &KeyHash) -> bool {
        if self.stopped() || self.two_histories(k) || self.revoked.contains(k) {
            return false;
        }
        if self.is_root(k) {
            return true;
        }
        self.stop != Stop::Full && self.devices.iter().any(|d| d.admin.as_ref() == Some(k) && !d.frozen)
    }
}

/// The signer of a record: the recovery key, a root key or an admin key.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Role {
    Root,
    Admin,
    /// The group's recovery key: it signs recovery records, nothing else
    /// (rule 33). It is never replaced.
    Recovery,
}

/// The keys a set names: its first root and its recovery key, the new
/// roots of the recovery records, and the admin keys of the device
/// records of the roots. A record is verified with the
/// key of its signer; a signer the table does not know cannot be
/// verified, and its record is not stored.
#[derive(Clone, Default, Debug)]
pub struct Keys {
    keys: BTreeMap<KeyHash, Key>,
    roots: BTreeSet<KeyHash>,
    admins: BTreeSet<KeyHash>,
    recovery: KeyHash,
}

impl Keys {
    pub fn new(root: &Key, recovery: &Recovery) -> Keys {
        let mut k = Keys { recovery: recovery.hash(), ..Keys::default() };
        k.roots.insert(root.hash());
        k.keys.insert(root.hash(), root.clone());
        k.keys.insert(recovery.hash(), recovery.k1.clone());
        k
    }

    /// The signer's key and role. The recovery key is one whatever else
    /// names it, and a root one before an admin key: only the recovery key
    /// names roots, so no root's record changes either (rule 33).
    pub fn signer(&self, h: &KeyHash) -> Option<(&Key, Role)> {
        let key = self.keys.get(h)?;
        if self.recovery == *h {
            Some((key, Role::Recovery))
        } else if self.roots.contains(h) {
            Some((key, Role::Root))
        } else if self.admins.contains(h) {
            Some((key, Role::Admin))
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
        let (k, set) = match (&body.kind, role) {
            (Kind::Device(d), Role::Root) => match &d.admin {
                Some(a) => (a, &mut self.admins),
                None => return false,
            },
            (Kind::Recovery { root, .. }, Role::Recovery) => (root, &mut self.roots),
            _ => return false,
        };
        let h = k.hash();
        self.keys.entry(h).or_insert_with(|| k.clone());
        set.insert(h)
    }

    pub fn is_admin(&self, h: &KeyHash) -> bool {
        self.admins.contains(h) && !self.roots.contains(h) && self.recovery != *h
    }
}

/// A record the set verified, with its signer's role.
#[derive(Clone, Copy)]
pub(crate) struct Checked<'a> {
    pub r: &'a Record,
    pub role: Role,
    pub held: bool,
}

/// What the signatures of a list of records came to, by place in the
/// list: each is verified once, however often the list is checked.
pub(crate) struct Sigs(Vec<Option<Option<bool>>>);

impl Sigs {
    /// Nothing verified yet for n records.
    pub fn new(n: usize) -> Sigs {
        Sigs(alloc::vec![None; n])
    }

    /// Whether record r, at place i, verifies under key: whether it is
    /// held, or None when it does not verify.
    fn verify(&mut self, i: usize, r: &Record, key: &Key, recovery: Option<&Recovery>) -> Option<bool> {
        match self.0.get(i).copied().flatten() {
            Some(known) => known,
            None => {
                let v = match recovery {
                    Some(rec) => r.verify_head(rec).ok(),
                    None => r.verify(key).ok(),
                };
                if let Some(slot) = self.0.get_mut(i) {
                    *slot = Some(v);
                }
                v
            }
        }
    }
}

/// Verifies every record of a set: the keys are learned until no record
/// adds one, so the order of the set does not matter. It returns the
/// records that verify and why the others do not. sigs holds what the
/// records' signatures already came to, by place in records.
pub(crate) fn check_all<'a>(
    root: &Key,
    recovery: &Recovery,
    records: &[&'a Record],
    sigs: &mut Sigs,
) -> (Vec<Checked<'a>>, BTreeMap<RecordId, Why>) {
    let group = super::key::group_id(root, recovery);
    let mut keys = Keys::new(root, recovery);
    let mut failed = BTreeMap::new();
    let mut todo: Vec<(usize, &'a Record)> = Vec::new();
    for (i, &r) in records.iter().enumerate() {
        if r.body().group != group {
            fail(&mut failed, r.id(), Why::Group);
        } else {
            todo.push((i, r));
        }
    }
    let mut done: BTreeMap<RecordId, Checked<'a>> = BTreeMap::new();
    loop {
        let mut learned = false;
        let mut rest = Vec::new();
        for (i, r) in todo {
            if done.contains_key(&r.id()) {
                continue;
            }
            match keys.signer(&r.body().signer) {
                None => rest.push((i, r)),
                Some((key, role)) => match sigs.verify(i, r, key, (role == Role::Recovery).then_some(recovery)) {
                    Some(held) => {
                        learned |= keys.learn(r.body(), role, held);
                        done.insert(r.id(), Checked { r, role, held });
                    }
                    None => fail(&mut failed, r.id(), Why::Signature),
                },
            }
        }
        todo = rest;
        if !learned || todo.is_empty() {
            break;
        }
    }
    for (_, r) in todo {
        if !done.contains_key(&r.id()) {
            fail(&mut failed, r.id(), Why::Signer);
        }
    }
    // A key learned late may change a role (a root over an admin key);
    // roles are read again from the final table.
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
/// The units r takes in the rooms (a test's small rooms may say).
fn units_of(r: &Record) -> u64 {
    #[cfg(test)]
    if let Some(u) = super::keep::small::units_of(&r.id()) {
        return u;
    }
    super::keep::units(r.size())
}

pub(crate) fn item(r: &Record, role: Role) -> super::keep::Item {
    let early = role == Role::Root && matches!(r.body().kind, Kind::Revoke(_) | Kind::Freeze(_) | Kind::Resolve(_));
    super::keep::Item {
        early,
        signer: r.body().signer,
        seq: r.body().seq,
        id: r.id(),
        units: units_of(r),
        checkpoint: matches!(r.body().kind, Kind::Checkpoint { .. }),
    }
}

/// Reports whether r is the recovery key's: kept outside the rooms, never
/// pruned (rule 33). Of its records at one seq the set keeps two, the
/// proof of a fork.
pub(crate) fn chain_kind(r: &Record, role: Role) -> bool {
    role == Role::Recovery
        && r.body().seq <= MAX_RECOVERY
        && (r.body().held || matches!(r.body().kind, Kind::Recovery { .. }))
}

/// The recovery key's records checked keeps: of each seq the two with the
/// smallest IDs.
pub(crate) fn chain_kept<'r>(checked: impl Iterator<Item = (&'r Record, Role)>) -> BTreeSet<RecordId> {
    let mut by: BTreeMap<u64, BTreeSet<RecordId>> = BTreeMap::new();
    for (r, role) in checked {
        if chain_kind(r, role) {
            by.entry(r.body().seq).or_default().insert(r.id());
        }
    }
    by.into_values().flat_map(|ids| ids.into_iter().take(2)).collect()
}

/// The proof that a key has two histories: of each root's or admin key's
/// lowest seq that holds two records, the two smallest IDs. Like the
/// recovery chain's twins, they are kept outside the rooms. A root's pair
/// is a fork at any depth, as two recovery heads are: no checkpoint
/// prunes it, and no checkpoint of that root at or above its seq counts.
/// Of an admin's, a counting checkpoint settles what is below it, twins
/// included: twins it prunes go as any record it prunes, and the stop
/// they made with them; twins it does not cover, and two checkpoints at
/// one seq, stay a fork (`proof_stays`).
pub(crate) fn proof_stays(proof: &BTreeSet<RecordId>, r: &Record, role: Role) -> bool {
    proof.contains(&r.id()) && (role == Role::Root || matches!(r.body().kind, Kind::Checkpoint { .. }))
}

/// The seq of the pair of root's records in proof (`fork_proof`), if any.
pub(crate) fn root_fork<'r>(
    proof: &BTreeSet<RecordId>,
    root: &KeyHash,
    records: impl Iterator<Item = (&'r Record, Role)>,
) -> Option<u64> {
    records
        .filter(|(r, role)| *role == Role::Root && r.body().signer == *root && proof.contains(&r.id()))
        .map(|(r, _)| r.body().seq)
        .min()
}

pub(crate) fn fork_proof<'r>(checked: impl Iterator<Item = (&'r Record, Role)>) -> BTreeSet<RecordId> {
    let mut by: BTreeMap<KeyHash, BTreeMap<u64, BTreeSet<RecordId>>> = BTreeMap::new();
    for (r, role) in checked {
        if matches!(role, Role::Root | Role::Admin) {
            by.entry(r.body().signer).or_default().entry(r.body().seq).or_default().insert(r.id());
        }
    }
    by.into_values()
        .filter_map(|seqs| seqs.into_values().find(|ids| ids.len() > 1))
        .flat_map(|ids| ids.into_iter().take(2))
        .collect()
}

/// The first checkpoints the recovery chain names, each with the root
/// whose checkpoint it must be (`Chain::firsts`).
pub(crate) type Firsts = BTreeMap<RecordId, KeyHash>;

/// Whether r is a first checkpoint the chain names: that ID, a checkpoint
/// of the root the head names. Another record with that ID is no first
/// checkpoint and is kept, pruned or dropped as any other.
pub(crate) fn is_first(firsts: &Firsts, r: &Record) -> bool {
    firsts.get(&r.id()) == Some(&r.body().signer) && matches!(r.body().kind, Kind::Checkpoint { .. })
}

/// Of each root a head named, the seq of its first checkpoint (of several
/// heads naming that root, the highest): no checkpoint of that root below
/// it may count, since it was signed before the root took the group.
pub(crate) fn first_floor<'r>(
    firsts: &Firsts,
    get: impl Fn(&RecordId) -> Option<&'r Record>,
) -> BTreeMap<KeyHash, u64> {
    let mut out: BTreeMap<KeyHash, u64> = BTreeMap::new();
    for (id, root) in firsts {
        if let Some(r) = get(id).filter(|r| is_first(firsts, r)) {
            let e = out.entry(*root).or_default();
            *e = (*e).max(r.body().seq);
        }
    }
    out
}

/// Whether held has a head's first checkpoint: a checkpoint of root with
/// that ID, verified (a set verifies what it holds, `check_all` what it
/// takes).
pub(crate) fn first_held(held: &BTreeMap<RecordId, &Record>, id: &RecordId, root: &Key) -> bool {
    held.get(id).is_some_and(|r| r.body().signer == root.hash() && matches!(r.body().kind, Kind::Checkpoint { .. }))
}

/// What the recovery chain comes to (rule 33): the roots it put on the
/// path in order, the newest list's cut of the roots before the current
/// one, and the records that stop the group for good.
#[derive(Clone, Debug, Default)]
pub(crate) struct Chain {
    /// (recovery record, new root), in order.
    pub steps: Vec<(RecordId, Key)>,
    pub cut: Option<Cut>,
    pub changes: Vec<Change>,
    /// Two different records at one seq.
    pub fork: Vec<RecordId>,
    /// The lowest such seq and its two records, the smaller ID first.
    pub fork_at: Option<(u64, RecordId, RecordId)>,
    /// A record the device cannot read where the chain goes on.
    pub unreadable: bool,
    /// The list the next valid record waits for.
    pub waiting: Option<[u8; 32]>,
    /// The first checkpoint of the new root the next valid record names,
    /// which it waits for.
    pub first_missing: Option<RecordId>,
    /// The chain's records that count.
    pub records: BTreeSet<RecordId>,
    /// The first checkpoints kept outside the rooms: the newest applied
    /// record's, and the one of the record the chain waits for. A record
    /// off the chain keeps none, and an earlier first goes when a later
    /// record applies.
    pub firsts: Firsts,
    /// The roots of the chain's records that have not applied yet, each
    /// with its record's seq: what the set keeps aside is theirs.
    pub pending: Vec<(u64, Key)>,
}

impl Chain {
    /// Whether the chain halts the group: a fork, or a record the device
    /// cannot read.
    pub fn halted(&self) -> bool {
        !self.fork.is_empty() || self.unreadable
    }

    pub fn promoted(&self) -> BTreeSet<KeyHash> {
        self.steps.iter().map(|(_, k)| k.hash()).collect()
    }

    /// The roots whose records wait aside, each with the lowest seq of a
    /// record that names it: the roots of the chain's records that have
    /// not applied yet, not a root of the path. A halted group keeps
    /// nothing aside. Their records are neither counted nor ignored until
    /// the record naming the root applies; the set keeps them apart and
    /// evaluate leaves them out the same way.
    pub fn waiting_roots(&self, group_root: &KeyHash) -> BTreeMap<KeyHash, (u64, Key)> {
        let mut out: BTreeMap<KeyHash, (u64, Key)> = BTreeMap::new();
        if self.halted() {
            return out;
        }
        let promoted = self.promoted();
        for (seq, root) in &self.pending {
            let h = root.hash();
            if promoted.contains(&h) || h == *group_root {
                continue;
            }
            let slot = out.entry(h).or_insert((*seq, root.clone()));
            slot.0 = slot.0.min(*seq);
        }
        out
    }

    /// The cut, by each key it covers.
    pub fn cuts(&self) -> BTreeMap<KeyHash, Cut> {
        cuts_of(self.cut.as_ref())
    }
}

/// A cut by each key it covers: the roots before the current one, and the
/// current one when its records start above seq 1.
pub(crate) fn cuts_of(cut: Option<&Cut>) -> BTreeMap<KeyHash, Cut> {
    let mut out = BTreeMap::new();
    if let Some(c) = cut {
        for k in c.roots.iter().chain((c.from > 1).then_some(&c.current)) {
            out.insert(*k, c.clone());
        }
    }
    out
}

/// Walks the recovery chain: the recovery key's records from seq 1. A
/// record is valid by its own bytes and the records before it alone: its
/// prev is the tip, and its root is new (neither the recovery key, which
/// `Body::check` refuses, nor a root on the path); what its list holds
/// never voids it. A valid record applies once the device holds its list,
/// or a newer valid record's list (the newest list stands for all before
/// it); until then the chain waits there. Two different records at one
/// seq, at any depth, whether or not either is otherwise valid, stop the
/// group for good: the two are the proof. A record the device cannot read
/// (held) where the chain goes on stops that device until it is updated;
/// that is not a fork. Any other record is ignored. Nothing but the
/// recovery key's own records and their lists decides it.
pub(crate) fn chain<'r>(
    group_root: &KeyHash,
    records: impl Iterator<Item = (&'r Record, Role)>,
    lists: &BTreeMap<[u8; 32], &List>,
    held_first: impl Fn(&RecordId, &Key) -> bool,
) -> Chain {
    let mut by: BTreeMap<u64, Vec<&Record>> = BTreeMap::new();
    let mut out = Chain::default();
    for (r, role) in records {
        if chain_kind(r, role) {
            by.entry(r.body().seq).or_default().push(r);
        }
    }
    for rs in by.values_mut() {
        rs.sort_by_key(|r| r.id());
        rs.dedup_by_key(|r| r.id());
        // Two are the proof; a set keeps the two smallest IDs at a seq.
        rs.truncate(2);
        if let [a, b] = rs.as_slice()
            && out.fork_at.is_none()
        {
            out.fork_at = Some((a.body().seq, a.id(), b.id()));
        }
        if rs.len() > 1 {
            out.fork.extend(rs.iter().map(|r| r.id()));
            for r in rs.iter() {
                if let Kind::Recovery { root, .. } = &r.body().kind {
                    let (record, seq, root) = (r.id(), r.body().seq, root.hash());
                    out.changes.push(Change { record, seq, root, state: ChangeState::Competing });
                }
            }
        }
    }
    // The valid records, in order, by their bytes and their predecessors.
    let mut path = vec![*group_root];
    let mut tip: Option<RecordId> = None;
    let mut valid: Vec<(&Record, &Key, &[u8; 32], u64, RecordId)> = Vec::new();
    for seq in 1..=MAX_RECOVERY {
        let Some([r]) = by.get(&seq).map(Vec::as_slice) else { break };
        if r.body().held {
            out.unreadable = true;
            break;
        }
        let Kind::Recovery { root, list, from, first, .. } = &r.body().kind else { break };
        if r.body().prev != tip {
            break;
        }
        let h = root.hash();
        if path.contains(&h) {
            out.changes.push(Change { record: r.id(), seq, root: h, state: ChangeState::Void });
            break;
        }
        path.push(h);
        tip = Some(r.id());
        valid.push((r, root, list, *from, *first));
    }
    // They apply up to the newest whose list the device holds, and the
    // new root's first checkpoint when the record names one: the newest
    // list is the whole truth about every root before it, so the lists of
    // the records before it are not needed. Past it the chain waits for
    // the newest record's list, or its first checkpoint.
    // Halted, the chain below the fork applies by its lists alone: the
    // state is shown as it stood, nothing is compacted or commanded by it,
    // and the first checkpoint of a record a later one followed is gone.
    let halted = !out.fork.is_empty() || out.unreadable;
    let ready =
        |list: &[u8; 32], root: &Key, first: &RecordId| lists.contains_key(list) && (halted || held_first(first, root));
    let applied =
        valid.iter().rposition(|(_, root, list, _, first)| ready(list, root, first)).map_or(0, |i| i.saturating_add(1));
    if applied < valid.len()
        && let Some((_, root, list, _, first)) = valid.last()
    {
        out.waiting = (!lists.contains_key(*list)).then_some(**list);
        out.first_missing = (!halted && !held_first(first, root)).then_some(*first);
    }
    if let Some((_, root, _, _, first)) = applied.checked_sub(1).and_then(|i| valid.get(i))
        && !halted
    {
        out.firsts.insert(*first, root.hash());
    }
    if applied < valid.len()
        && !halted
        && let Some((_, root, _, _, first)) = valid.last()
    {
        out.firsts.insert(*first, root.hash());
    }
    out.pending = valid.iter().skip(applied).map(|(r, root, _, _, _)| (r.body().seq, (*root).clone())).collect();
    let mut path = vec![*group_root];
    let mut last: Option<(&Record, &[u8; 32], &List, u64)> = None;
    for (r, root, list, from, _) in valid.iter().take(applied) {
        let h = root.hash();
        out.changes.push(Change { record: r.id(), seq: r.body().seq, root: h, state: ChangeState::Effective });
        out.records.insert(r.id());
        out.steps.push((r.id(), (*root).clone()));
        path.push(h);
        last = lists.get(*list).map(|l| (*r, *list, *l, *from));
    }
    if let Some((r, list, l, from)) = last {
        let current = *path.last().unwrap_or(group_root);
        out.cut = Some(Cut {
            roots: path.iter().take(path.len().saturating_sub(1)).copied().collect(),
            current,
            from,
            record: r.id(),
            list: *list,
            keep: l.0.iter().copied().collect(),
        });
    }
    out.changes.sort_by_key(|c| (c.seq, c.record));
    out
}

/// The records of checked the set keeps: the recovery chain's (rule 33),
/// and each other key within its ceiling, the set's room shared between
/// keys. promoted are the roots the chain put on the path after the
/// first: they have a root's room; a root only a void takeover names has
/// none. cuts are the takeovers' cuts of the roots before them: of such a
/// root only the records its takeover lists may stay, within that root's
/// own room (rule 32).
pub(crate) fn kept_of(
    group_root: &KeyHash,
    promoted: &BTreeSet<KeyHash>,
    cuts: &BTreeMap<KeyHash, Cut>,
    is_first: impl Fn(&Record) -> bool,
    kept_first: &BTreeSet<RecordId>,
    checked: &[Checked<'_>],
) -> BTreeSet<RecordId> {
    let admins: BTreeSet<KeyHash> =
        checked.iter().filter(|c| c.role == Role::Admin).map(|c| c.r.body().signer).collect();
    let proof = fork_proof(checked.iter().filter(|c| !off_cut(cuts, c.r)).map(|c| (c.r, c.role)));
    // What a takeover cut stays out, named or not.
    let first = |c: &Checked<'_>| kept_first.contains(&c.r.id()) && !off_cut(cuts, c.r);
    let items: Vec<super::keep::Item> = checked
        .iter()
        .filter(|c| {
            c.role != Role::Recovery
                && !off_cut(cuts, c.r)
                && !proof.contains(&c.r.id())
                && !is_first(c.r)
                && !kept_first.contains(&c.r.id())
        })
        .map(|c| item(c.r, c.role))
        .collect();
    // The checkpoint kept first takes its part of the rooms before them.
    let mut pre: BTreeMap<KeyHash, u64> = BTreeMap::new();
    for c in checked.iter().filter(|c| first(c) && !proof.contains(&c.r.id())) {
        let u = pre.entry(c.r.body().signer).or_default();
        *u = u.saturating_add(item(c.r, c.role).units);
    }
    let ceiling = |k: &KeyHash| ceiling_of(group_root, promoted, &admins, k);
    let mut kept = super::keep::keep_with(&items, ceiling, &super::keep::Cut::default(), &pre).0;
    kept.extend(checked.iter().filter(|c| first(c)).map(|c| c.r.id()));
    kept.extend(chain_kept(checked.iter().map(|c| (c.r, c.role))));
    kept.extend(proof);
    kept.extend(checked.iter().filter(|c| is_first(c.r)).map(|c| c.r.id()));
    kept
}

/// The records of a root a takeover cut that it does not list.
pub(crate) fn off_cuts<'r>(
    cuts: &BTreeMap<KeyHash, Cut>,
    records: impl Iterator<Item = &'r Record>,
) -> BTreeSet<RecordId> {
    records.filter(|r| off_cut(cuts, r)).map(Record::id).collect()
}

/// Whether r is the current root's record at the recovery record's
/// `from` (above 1): the start of its line as the root, which the record
/// vouches for whatever its prev names.
pub(crate) fn starts_line(cuts: &BTreeMap<KeyHash, Cut>, r: &Record) -> bool {
    let b = r.body();
    cuts.get(&b.signer).is_some_and(|c| c.current == b.signer && c.from > 1 && b.seq == c.from)
}

/// Whether r is of a root a takeover cut and the takeover does not list
/// it.
pub(crate) fn off_cut(cuts: &BTreeMap<KeyHash, Cut>, r: &Record) -> bool {
    cuts.get(&r.body().signer).is_some_and(|cut| !cut.lets(r))
}

/// A key's ceiling in the keeping: a root's on the path, an admin key's,
/// or None for any other.
/// What a root's checkpoint cp keeps first, of what held holds: cp, the
/// records it keeps and its key's record just below it (its prev). They
/// are kept ahead of the rooms and take their part of them, so that
/// whether cp counts depends on cp and these alone.
pub(crate) fn named_first(cp: &Record, held: impl Fn(&RecordId) -> bool) -> BTreeSet<RecordId> {
    let mut out = BTreeSet::from([cp.id()]);
    if let Kind::Checkpoint { keep, .. } = &cp.body().kind {
        out.extend(keep.iter().copied().filter(|id| held(id)));
    }
    out.extend(cp.body().prev.filter(|id| held(id)));
    out
}

/// Whether the records a checkpoint names, each with its signer's role,
/// fit the room rules on their own: all within the set's room, and each
/// signer within its ceiling, where only the roots on the path and the
/// admin keys the root's records among them name have one; the recovery
/// key's records take no room. It reads nothing but those records, so every member judges it alike; a
/// checkpoint whose named records do not fit counts for no member.
pub(crate) fn fits_alone<'r>(
    named: impl Iterator<Item = (&'r Record, Role)> + Clone,
    group_root: &KeyHash,
    promoted: &BTreeSet<KeyHash>,
) -> bool {
    let admins: BTreeSet<KeyHash> = named
        .clone()
        .filter_map(|(r, role)| match (&r.body().kind, role) {
            (Kind::Device(d), Role::Root) => d.admin.as_ref().map(Key::hash),
            _ => None,
        })
        .collect();
    let mut by: BTreeMap<KeyHash, u64> = BTreeMap::new();
    let mut total = 0u64;
    for (r, role) in named.filter(|(_, role)| *role != Role::Recovery) {
        let u = item(r, role).units;
        let e = by.entry(r.body().signer).or_default();
        *e = e.saturating_add(u);
        total = total.saturating_add(u);
    }
    total <= super::keep::room()
        && by.iter().all(|(k, u)| ceiling_of(group_root, promoted, &admins, k).is_some_and(|c| *u <= c))
}

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
/// are dropped; the result depends only on the set and the lists, never on
/// their order. The recovery chain sets the path of roots (rule 33), and
/// the rest is evaluated as a member that compacted by it.
pub fn evaluate(input: &Input) -> State {
    let records: Vec<&Record> = input.records.iter().collect();
    let mut sigs = Sigs::new(records.len());
    let (checked, failed) = check_all(input.root, input.recovery, &records, &mut sigs);
    let lists: Vec<([u8; 32], List)> =
        input.lists.iter().map(|b| (super::body::list_hash(b), List::decode(b).unwrap_or_default())).collect();
    let lists: BTreeMap<[u8; 32], &List> = lists.iter().map(|(h, l)| (*h, l)).collect();
    evaluate_checked(input.root, input.recovery, checked, failed, &lists, &Compacted { proven: &[] }, &[])
}

/// The records whose signer the others still name once a checkpoint
/// pruned some: a key whose naming record it left out is not known, as on
/// a member that dropped what it pruned.
fn still_known<'a>(root: &Key, recovery: &Recovery, checked: Vec<Checked<'a>>) -> Vec<Checked<'a>> {
    let mut keys = Keys::new(root, recovery);
    loop {
        let mut learned = false;
        for c in &checked {
            if let Some((_, role)) = keys.signer(&c.r.body().signer) {
                learned |= keys.learn(c.r.body(), role, c.held);
            }
        }
        if !learned {
            break;
        }
    }
    checked.into_iter().filter(|c| keys.signer(&c.r.body().signer).is_some()).collect()
}

/// The checkpoints of each root on the path among checked, held or not
/// past the rooms, in the order of the path and of each root the newest
/// first (the newest that counts is the root's); a checkpoint of a root
/// the path left (or of the current root below its `from`) is an anchor
/// only, listed or not: the new root's first checkpoint is what prunes.
fn checkpoints_of<'r>(
    checked: &[Checked<'r>],
    path: &[KeyHash],
    on_path: &BTreeMap<KeyHash, usize>,
    cuts: &BTreeMap<KeyHash, Cut>,
) -> Vec<&'r Record> {
    let mut out: Vec<&'r Record> = checked
        .iter()
        .filter(|c| {
            let b = c.r.body();
            !c.held
                && c.role == Role::Root
                && matches!(b.kind, Kind::Checkpoint { .. })
                && path.contains(&b.signer)
                && !cuts.get(&b.signer).is_some_and(|cut| cut.covers(&b.signer, b.seq))
        })
        .map(|c| c.r)
        .collect();
    // In the order of the path; of each root the newest first, of two at
    // one seq the smaller ID.
    out.sort_by(|a, b| {
        let at = |r: &Record| on_path.get(&r.body().signer).copied().unwrap_or(0);
        at(a).cmp(&at(b)).then(b.body().seq.cmp(&a.body().seq)).then(a.id().cmp(&b.id()))
    });
    out
}

/// What a member's compactions left it with: the checkpoints it pruned by
/// (`RecordSet`).
pub(crate) struct Compacted<'c> {
    pub proven: &'c [(Vec<Head>, BTreeSet<RecordId>)],
}

/// The cuts with the list narrowed to what the current root's checkpoint
/// with anchors keeps: the new root's first checkpoint closes the list
/// (rule 33).
pub(crate) fn closed(cuts: &BTreeMap<KeyHash, Cut>, anchors: &BTreeSet<RecordId>) -> BTreeMap<KeyHash, Cut> {
    cuts.iter()
        .map(|(k, c)| {
            let mut c = c.clone();
            c.keep = c.keep.intersection(anchors).copied().collect();
            (*k, c)
        })
        .collect()
}

/// The state of checked as a member that compacted by. The recovery
/// chain gives the path and the cut before anything else: no root's or
/// admin's record changes them (rule 33), and what the newest list names
/// counts by itself at once (rule 32).
pub(crate) fn evaluate_checked(
    root: &Key,
    recovery: &Recovery,
    checked: Vec<Checked<'_>>,
    failed: BTreeMap<RecordId, Why>,
    lists: &BTreeMap<[u8; 32], &List>,
    by: &Compacted<'_>,
    early: &[&Record],
) -> State {
    let group_root = root.hash();
    let chain = {
        let held: BTreeMap<RecordId, &Record> =
            checked.iter().map(|c| c.r).chain(early.iter().copied()).map(|r| (r.id(), r)).collect();
        chain(&group_root, checked.iter().map(|c| (c.r, c.role)), lists, |id, root| first_held(&held, id, root))
    };
    // The records of a root only a waiting record names stay aside, as
    // in the set (Chain::waiting_roots).
    let waiting = chain.waiting_roots(&group_root);
    let checked: Vec<Checked> = checked.into_iter().filter(|c| !waiting.contains_key(&c.r.body().signer)).collect();
    // Halted: only the recovery chain and what the newest list applied
    // below the fork names (State::halted).
    let checked = if chain.halted() {
        let listed = chain.cut.as_ref().map(|c| &c.keep);
        checked
            .into_iter()
            .filter(|c| c.role == Role::Recovery || listed.is_some_and(|k| k.contains(&c.r.id())))
            .collect()
    } else {
        checked
    };
    let root_recs: Vec<&Record> = checked.iter().filter(|c| c.role == Role::Root && !c.held).map(|c| c.r).collect();
    let mut cuts = chain.cuts();
    let proven = by.proven;
    // The recovery key's records off the chain: a twin, past its tip, or of
    // a kind it does not sign.
    let mut failed = failed;
    for c in checked.iter().filter(|c| c.role == Role::Recovery) {
        if !chain.records.contains(&c.r.id()) {
            let why = if chain_kind(c.r, c.role) { Why::History } else { Why::Power };
            fail(&mut failed, c.r.id(), why);
        }
    }
    let none = BTreeSet::new();
    let full = Evaluation::new(root, recovery, checked.clone(), failed.clone(), BTreeSet::new(), &chain, &cuts, &none);
    // The set a root's checkpoint prunes is evaluated as if the member had
    // dropped what it leaves out. The roots' checkpoints are taken in the
    // order of the path, each the newest of its root (a cut root's,
    // listed or not, is an anchor only and prunes nothing), as a member
    // that compacted under each root in turn took them: one counts when it still counts in the set the ones
    // before it pruned. What the list names is never pruned.
    let plain = full.run(&chain, &cuts);
    let cur = plain.cur;
    // The candidates come from the whole set, the rooms aside: a root's
    // checkpoint is kept first, and the rooms are judged in the set it
    // prunes, so one that brings the set back under them counts though
    // the set before it is past them.
    let cands = checkpoints_of(&checked, &plain.path, &plain.on_path, &cuts);
    let mut kept: Vec<Checked> = checked.clone();
    let mut anchors_all: BTreeSet<RecordId> = BTreeSet::new();
    let mut applied: Vec<RecordId> = Vec::new();
    let mut best: Option<State> = None;
    // Of each root the newest checkpoint that counts; a newer one that
    // does not (yet) waits, and the one below it may still count.
    let mut counted: BTreeSet<KeyHash> = BTreeSet::new();
    let by_id: BTreeMap<RecordId, &Record> = checked.iter().map(|c| (c.r.id(), c.r)).collect();
    let floor = first_floor(&chain.firsts, |id| by_id.get(id).copied());
    for x in cands {
        let (Kind::Checkpoint { heads, keep }, id) = (&x.body().kind, x.id()) else { continue };
        if counted.contains(&x.body().signer) || floor.get(&x.body().signer).is_some_and(|f| x.body().seq < *f) {
            continue;
        }
        // A checkpoint at or above its root's pair counts for nobody that
        // holds the pair, whatever it pruned before.
        let pair = fork_proof(kept.iter().map(|c| (c.r, c.role)));
        if root_fork(&pair, &x.body().signer, kept.iter().map(|c| (c.r, c.role))).is_some_and(|f| x.body().seq >= f) {
            continue;
        }
        let anchors = anchors_of(heads, keep);
        // A checkpoint counts only where the member holds what it names,
        // on its chains; one the set already pruned by stays (proven). A
        // record the cut drops (a cut root's, or the current root's below
        // its `from`, unlisted) is not held for it: nothing below the line
        // the recovery record starts is followed.
        if !proven.iter().any(|(h, a)| h == heads && *a == anchors) {
            let held: BTreeMap<RecordId, &Record> =
                kept.iter().filter(|c| !off_cut(&cuts, c.r)).map(|c| (c.r.id(), c.r)).collect();
            if !checkpoint_ok(x, |id| held.get(id).copied()) {
                continue;
            }
        }
        // What it names is kept first and must fit the rooms by itself; a
        // record the cut drops is not named.
        let by_id: BTreeMap<RecordId, &Checked> =
            kept.iter().filter(|c| !off_cut(&cuts, c.r)).map(|c| (c.r.id(), c)).collect();
        let first = named_first(x, |id| by_id.contains_key(id));
        let named = first.iter().filter_map(|id| by_id.get(id)).map(|c| (c.r, c.role));
        if !fits_alone(named, &root.hash(), &chain.promoted()) {
            continue;
        }
        let these = if x.body().signer == cur && chain.cut.is_some() { closed(&cuts, &anchors) } else { cuts.clone() };
        let mut all = anchors_all.clone();
        all.extend(anchors.iter().copied());
        let listed = |r: &Record| {
            these
                .get(&r.body().signer)
                .is_some_and(|cut| cut.covers(&r.body().signer, r.body().seq) && cut.keeps(&r.id()))
        };
        let proof = fork_proof(kept.iter().map(|c| (c.r, c.role)));
        let firsts = &chain.firsts;
        let pruned: Vec<Checked> = kept
            .iter()
            .copied()
            .filter(|c| {
                listed(c.r)
                    || proof_stays(&proof, c.r, c.role)
                    || is_first(firsts, c.r)
                    || !pruned_by(c.r, c.role, heads, &anchors)
            })
            .collect();
        let known = still_known(root, recovery, pruned.clone());
        let e = Evaluation::new(root, recovery, known, failed.clone(), all.clone(), &chain, &these, &first);
        let ep = e.run(&chain, &these);
        let Some(i) = e.recs.iter().position(|r| r.id == id) else { continue };
        if !ep.root_record(i) {
            continue;
        }
        applied.push(id);
        counted.insert(x.body().signer);
        let mut state = ep.finish();
        state.checkpoint = Some(id);
        state.checkpoints = applied.clone();
        best = Some(state);
        kept = pruned;
        anchors_all = all;
        cuts = these;
    }
    let mut state = best.unwrap_or_else(|| plain.finish());
    state.group = super::key::group_id(root, recovery);
    state.list_missing = chain.waiting;
    state.first_missing = chain.first_missing;
    state.update_needed = chain.unreadable;
    state.fork = chain.fork_at;
    if chain.unreadable {
        state.stop = Stop::Full;
    }
    root_proof(&mut state, &root_recs);
    state
}

/// While the current root of state has two histories, its lowest pair
/// among the root records held and the keys that get it (`State::root_pair`,
/// `State::proof_to`): what the held records give, nothing remembered.
fn root_proof(state: &mut State, root_recs: &[&Record]) {
    let Some(cur) = state.roots.last().copied() else { return };
    if state.halted() || !state.two_histories(&cur) {
        return;
    }
    let mut at: BTreeMap<u64, BTreeSet<RecordId>> = BTreeMap::new();
    for r in root_recs.iter().filter(|r| r.body().signer == cur) {
        at.entry(r.body().seq).or_default().insert(r.id());
    }
    state.root_pair = at.iter().find(|(_, ids)| ids.len() > 1).and_then(|(seq, ids)| {
        let mut two = ids.iter();
        Some((*seq, *two.next()?, *two.next()?))
    });
    let removed: BTreeSet<KeyHash> = root_recs
        .iter()
        .filter(|r| state.roots.contains(&r.body().signer))
        .filter_map(|r| match &r.body().kind {
            Kind::Revoke(rm) => Some(rm.keys.iter().copied()),
            _ => None,
        })
        .flatten()
        .collect();
    let admitted: BTreeSet<KeyHash> = root_recs
        .iter()
        .filter(|r| r.body().signer == cur)
        .filter_map(|r| match &r.body().kind {
            Kind::Device(d) => Some(d.key.hash()),
            _ => None,
        })
        .filter(|k| !removed.contains(k) && !state.revoked.contains(k) && state.device_by_key(k).is_none())
        .collect();
    state.proof_to = admitted.into_iter().collect();
}

/// Reports whether checkpoint heads (with anchors, its heads' and keep's
/// IDs) prune r, which role signed: a record at or below its signer's
/// head that is neither a head nor kept, and not a root's removal.
pub(crate) fn pruned_by(r: &Record, role: Role, heads: &[Head], anchors: &BTreeSet<RecordId>) -> bool {
    let b = r.body();
    if role == Role::Recovery {
        // The recovery chain is never pruned.
        return false;
    }
    heads
        .binary_search_by(|h| h.key.cmp(&b.signer))
        .ok()
        .and_then(|i| heads.get(i))
        .is_some_and(|h| b.seq <= h.seq && !anchors.contains(&r.id()))
}

pub(crate) fn anchors_of(heads: &[Head], keep: &[RecordId]) -> BTreeSet<RecordId> {
    heads.iter().map(|h| h.id).chain(keep.iter().copied()).collect()
}

/// Reports whether checkpoint cp may count on a member that holds the
/// records get finds: it holds every record cp keeps, and of a head key's
/// named records (its head and those it keeps) none is above the head and
/// no two share a seq. So no ID can stand for a record nobody held.
///
/// A counting checkpoint settles what is below its heads, forks included:
/// it may keep any record of a key below that key's head, whichever
/// sibling its own chain ran through, and prunes the rest, twins with
/// them. It is not asked whether a kept record is on the chain below a
/// head: a member cannot always know that chain (it may have pruned it),
/// and the answer would then depend on the order the records came in.
/// Twins it does not cover, and two checkpoints at one seq, stay a fork
/// with the proof kept outside the rooms (`proof_stays`). Only the root
/// signs checkpoints.
pub(crate) fn checkpoint_ok<'r>(cp: &'r Record, get: impl Fn(&RecordId) -> Option<&'r Record>) -> bool {
    let Kind::Checkpoint { heads, keep } = &cp.body().kind else { return false };
    let head_of = |k: &KeyHash| heads.binary_search_by(|h| h.key.cmp(k)).ok().and_then(|i| heads.get(i));
    let mut named: BTreeMap<KeyHash, BTreeMap<u64, RecordId>> = BTreeMap::new();
    for h in heads {
        named.entry(h.key).or_default().insert(h.seq, h.id);
    }
    for id in keep {
        let Some(r) = get(id) else { return false };
        let b = r.body();
        if let Some(h) = head_of(&b.signer)
            && (b.seq > h.seq || named.entry(b.signer).or_default().insert(b.seq, *id).is_some_and(|o| o != *id))
        {
            return false;
        }
    }
    true
}

/// Whether a checkpoint with heads and keep, among the records held, keeps
/// an admission of a key while it prunes a root's removal naming that key:
/// it would bring a removed key back through an old record, which the
/// core's writer never writes.
pub(crate) fn revives<'r>(
    heads: &[Head],
    keep: &[RecordId],
    held: impl Iterator<Item = (&'r Record, Role)> + Clone,
) -> bool {
    let anchors = anchors_of(heads, keep);
    let removed: BTreeSet<KeyHash> = held
        .clone()
        .filter(|(r, role)| *role == Role::Root && pruned_by(r, *role, heads, &anchors))
        .filter_map(|(r, _)| match &r.body().kind {
            Kind::Revoke(rm) => Some(rm.keys.iter().copied()),
            _ => None,
        })
        .flatten()
        .collect();
    held.filter(|(r, _)| keep.binary_search(&r.id()).is_ok()).any(|(r, _)| match &r.body().kind {
        Kind::Device(d) => {
            removed.contains(&d.key.hash()) || d.admin.as_ref().is_some_and(|a| removed.contains(&a.hash()))
        }
        _ => false,
    })
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
            Kind::Thaw { ids: v, .. } if !self.held => Some(v),
            _ => None,
        }
    }
    fn seen_entry(&self, k: &KeyHash) -> Option<Seen> {
        match &self.b().kind {
            Kind::Revoke(r) | Kind::Freeze(r) => body::seen_entry(&r.seen, k),
            Kind::Thaw { seen, .. } | Kind::Hubs { seen, .. } | Kind::Copies { seen, .. } => body::seen_entry(seen, k),
            Kind::Device(d) => body::seen_entry(&d.seen, k),
            _ => None,
        }
    }
}

struct Evaluation<'a> {
    group_root: KeyHash,
    recovery: KeyHash,
    /// The heads and keep of the checkpoint it prunes by, where a prev
    /// chain may end.
    anchors: BTreeSet<RecordId>,
    /// The current root's records at the chain's `from` (`starts_line`).
    starts: BTreeSet<RecordId>,
    failed: BTreeMap<RecordId, Why>,
    /// The verified records within the set's ceilings.
    recs: Vec<Rec<'a>>,
    by_sig: BTreeMap<KeyHash, Vec<usize>>,
    /// Each record's position, by its ID.
    by_id: BTreeMap<RecordId, usize>,
    /// The chains walked from listed heads, by head (`on_chain`).
    chains: RefCell<BTreeMap<RecordId, BTreeMap<u64, RecordId>>>,
    devices: BTreeMap<DeviceId, Vec<usize>>,
    /// Device records over MAX_DEVICES; of the same length as recs.
    capped_devices: Vec<bool>,
}

// The evaluation keeps its records in one Vec and refers to them by their
// positions, which it takes from that Vec itself, and its per-record flags
// are Vecs of the same length; so an index here is always in range.
#[allow(clippy::indexing_slicing, reason = "positions come from the records' own Vec")]
impl<'a> Evaluation<'a> {
    #[allow(clippy::too_many_arguments, reason = "the parts of one evaluation")]
    fn new(
        root: &Key,
        recovery: &Recovery,
        mut checked: Vec<Checked<'a>>,
        failed: BTreeMap<RecordId, Why>,
        anchors: BTreeSet<RecordId>,
        chain: &Chain,
        cuts: &BTreeMap<KeyHash, Cut>,
        first: &BTreeSet<RecordId>,
    ) -> Evaluation<'a> {
        let group_root = root.hash();
        let promoted = &chain.promoted();
        // The checkpoint being judged and what it names are kept first,
        // ahead of the rooms (`named_first`).
        let kept = kept_of(&group_root, promoted, cuts, |r: &Record| is_first(&chain.firsts, r), first, &checked);
        // What a takeover keeps of the root it cut counts by itself, as a
        // checkpoint's anchor does: not by that root's chain.
        let mut anchors = anchors;
        anchors.extend(cuts.values().flat_map(|c| c.keep.iter().copied()));
        // The current root's record at the chain's `from` starts its line
        // as the root: the recovery record vouches for it, it counts with
        // any prev, and nothing below it by that key is followed.
        let starts: BTreeSet<RecordId> = checked.iter().filter(|c| starts_line(cuts, c.r)).map(|c| c.r.id()).collect();
        anchors.extend(starts.iter().copied());
        let mut failed = failed;
        for c in &checked {
            if !kept.contains(&c.r.id()) {
                // A record of a root the path left that the newest list
                // does not name is cut, not over a ceiling.
                let why = if off_cut(cuts, c.r) { Why::Cut } else { Why::Limit };
                fail(&mut failed, c.r.id(), why);
            }
        }
        // The recovery keys' records are the chain's alone (`chain`).
        checked.retain(|c| kept.contains(&c.r.id()) && c.role != Role::Recovery);
        checked.sort_by_key(|c| order_key(c.r.body(), &c.r.id()));
        let mut e = Evaluation {
            group_root,
            recovery: recovery.hash(),
            anchors,
            starts,
            failed,
            recs: Vec::with_capacity(checked.len()),
            by_sig: BTreeMap::new(),
            by_id: BTreeMap::new(),
            chains: RefCell::new(BTreeMap::new()),
            devices: BTreeMap::new(),
            capped_devices: Vec::new(),
        };
        for (i, c) in checked.iter().enumerate() {
            let b = c.r.body();
            let device = match &b.kind {
                Kind::Device(d) if !c.held => Some(d.id()),
                _ => None,
            };
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
        let mut chains = self.chains.borrow_mut();
        let chain = chains.entry(*head).or_insert_with(|| self.walk(head));
        match chain.get(&tr.b().seq) {
            Some(id) => *id == tr.id,
            // Below where the walk stopped, only an anchor.
            None => chain.first_key_value().is_none_or(|(low, _)| tr.b().seq < *low) && self.anchors.contains(&tr.id),
        }
    }

    /// The chain that ends at head, by seq, as far as the records show it:
    /// each step to its prev, one signer, the seq going down.
    fn walk(&self, head: &RecordId) -> BTreeMap<u64, RecordId> {
        let mut chain = BTreeMap::new();
        let mut at = self.by_id.get(head).copied();
        let mut signer = None;
        while let Some(r) = at.and_then(|i| self.recs.get(i)) {
            let b = r.b();
            if signer.is_some_and(|s| s != b.signer) || chain.first_key_value().is_some_and(|(s, _)| b.seq >= *s) {
                break;
            }
            signer = Some(b.signer);
            chain.insert(b.seq, r.id);
            if self.starts.contains(&r.id) {
                break;
            }
            at = b.prev.as_ref().and_then(|p| self.by_id.get(p)).copied();
        }
        chain
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

    /// Turns the evaluation into the epoch of the path the recovery chain
    /// gives (rule 33), with its takeovers. Two records at one step of the
    /// chain stop the group in full.
    fn run(&self, chain: &Chain, cuts: &BTreeMap<KeyHash, Cut>) -> Epoch<'_, 'a> {
        let mut path = vec![self.group_root];
        path.extend(chain.steps.iter().map(|(_, k)| k.hash()));
        let mut ep = Epoch::new(self, path, cuts.clone());
        ep.changes = chain.changes.clone();
        ep.chain_records = chain.records.clone();
        ep.recovery = self.recovery;
        if !chain.fork.is_empty() {
            ep.stop_full = true;
            ep.conflicts.push(Conflict {
                kind: ConflictKind::Fork,
                records: chain.fork.clone(),
                signers: vec![self.recovery],
            });
        }
        ep
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
    /// powers.
    admins: BTreeMap<KeyHash, usize>,
    /// The current recovery key (`Chain`).
    recovery: KeyHash,
    /// The recovery chain's records that count.
    chain_records: BTreeSet<RecordId>,
    /// For each device an admin admitted, the one record that counts by
    /// the power to admit.
    admitted: BTreeMap<DeviceId, usize>,
    /// The first records of admins that admitted one device differently.
    undecided_admits: BTreeSet<usize>,
    /// The first records of admins for a device several admins admitted.
    contested: BTreeSet<usize>,
    label: Vec<Label>,
    why: Vec<Option<super::eval::Why>>,
    revoked: BTreeSet<KeyHash>,
    frozen: BTreeSet<KeyHash>,
    conflicts: Vec<Conflict>,
    changes: Vec<Change>,
    stop_full: bool,
    settings: Settings,
    /// The other key of each admin's device (`with_pair`).
    pairs: BTreeMap<KeyHash, Vec<KeyHash>>,
    /// Admin keys a newer root record of their device no longer names,
    /// with that record: what the key signed and the record saw still
    /// counts, the rest does not.
    superseded: BTreeMap<KeyHash, usize>,
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
            recovery: e.recovery,
            chain_records: BTreeSet::new(),
            admitted: BTreeMap::new(),
            undecided_admits: BTreeSet::new(),
            contested: BTreeSet::new(),
            label: vec![Label::Unlabelled; n],
            why: vec![None; n],
            revoked: BTreeSet::new(),
            frozen: BTreeSet::new(),
            conflicts: Vec::new(),
            changes: Vec::new(),
            stop_full: false,
            settings: Settings::default(),
            pairs: BTreeMap::new(),
            superseded: BTreeMap::new(),
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
            ep.settings = (**s).clone();
        }
        ep.cap_others();
        let others: Vec<KeyHash> = e.by_sig.keys().filter(|k| !ep.on_path.contains_key(*k)).copied().collect();
        for s in others {
            ep.chain(s);
        }
        ep.find_admins();
        ep.find_pairs();
        ep.admit_and_label();
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
        // The proof of two histories is outside the rooms, as in the set.
        let proof = fork_proof(self.e.recs.iter().map(|r| (r.r, r.role)));
        for k in roots {
            let mut rs: Vec<usize> = self.of(&k).iter().copied().filter(|&i| !proof.contains(&self.r(i).id)).collect();
            rs.sort_by_key(|&i| item(self.r(i).r, self.r(i).role).pos());
            for i in rs.into_iter().skip(MAX_ROOT_RECORDS) {
                self.capped[i] = true;
            }
        }
    }

    /// The admins' ceilings: an admin's records past the admin limit. A
    /// key neither on the path nor an admin's counts nothing.
    fn cap_others(&mut self) {
        let limit = MAX_ADMIN_RECORDS;
        for (k, rs) in &self.e.by_sig {
            if self.on_path.contains_key(k) {
                continue;
            }
            if rs.first().is_none_or(|&i| !self.r(i).admin()) {
                for &i in rs {
                    self.capped[i] = true;
                }
                continue;
            }
            let own = self.in_order(k);
            for &i in own.get(limit..).unwrap_or_default() {
                self.capped[i] = true;
            }
        }
    }

    /// Reports whether record i is a root's own record that counts in this
    /// epoch: its root is on the path and, for a root a takeover cut, its
    /// claim lists it.
    fn root_record(&self, i: usize) -> bool {
        let r = self.r(i);
        if r.admin() || r.held || !self.counted[i] || self.capped[i] || !self.on_path.contains_key(&r.b().signer) {
            return false;
        }
        self.cuts.get(&r.b().signer).is_none_or(|cut| cut.lets(r.r))
    }

    /// The records the path's roots' resolve records name, of a root a
    /// takeover cut those its claim lists; a resolve counts here when its
    /// own chain is whole. A resolve voids only records of keys that are
    /// no roots on the path (admins): a root's record is never voided, so a
    /// root's removal stays final and its checkpoint never stops counting
    /// by a resolve; two histories of a root end only by a change of root.
    fn voids(&self) -> BTreeSet<RecordId> {
        let rooted: BTreeSet<RecordId> =
            self.all().map(|i| self.r(i)).filter(|r| self.on_path.contains_key(&r.b().signer)).map(|r| r.id).collect();
        let mut v = BTreeSet::new();
        for signer in self.on_path.keys() {
            let rs = self.of(signer);
            let by_id: BTreeMap<RecordId, usize> = rs.iter().map(|&i| (self.r(i).id, i)).collect();
            let wholes = self.e.wholes(rs, &by_id, &self.capped);
            let cut = self.cuts.get(signer);
            for &i in rs {
                let r = self.r(i);
                if let (Kind::Resolve(ids), Role::Root, false) = (&r.b().kind, r.role, r.held)
                    && cut.is_none_or(|cut| cut.lets(r.r))
                    && wholes.contains(&i)
                {
                    v.extend(ids.iter().copied().filter(|id| !rooted.contains(id)));
                }
            }
        }
        v
    }

    /// Finds which of one signer's records count: whole chains within the
    /// limits, not on a branch a resolve voided, below the lowest seq with
    /// two records.
    fn chain(&mut self, signer: KeyHash) {
        // A root a takeover cut has only what its claim lists.
        let cut = self.cuts.get(&signer);
        let rs: Vec<usize> = self
            .of(&signer)
            .iter()
            .copied()
            .filter(|&i| !self.capped[i] && cut.is_none_or(|c| c.lets(self.r(i).r)))
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
        // Two records of a root at one seq prove two histories whether or
        // not their chains are whole here: both carry the root's signature.
        // A member that misses a record below them stops as the others do.
        let root = self.on_path.contains_key(&signer);
        let proven = if root { by_seq.iter().find(|(_, n)| **n > 1).map(|(s, _)| *s) } else { None };
        let fork = live
            .iter()
            .find(|(_, l)| l.len() > 1)
            .map(|(s, _)| *s)
            .into_iter()
            .chain(proven)
            .min()
            .unwrap_or(MAX_SEQ.saturating_add(1));
        if fork <= MAX_SEQ {
            self.forked.insert(signer, fork);
        }
        // A removal on a whole chain counts at or above the fork too, on
        // either history, whoever signed it (F-7 for every key): a key in
        // two histories brings nothing back that it removed, and its
        // admissions and other grants at or above the fork stop counting.
        // For the current root the group stops, and what either history
        // removed stays out of the change of root that ends the stop.
        for (seq, l) in live {
            for i in l {
                let r = self.r(i);
                if (seq < fork || r.is_revoke()) && !self.voided.contains(&r.id) {
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
    /// signed, with the powers of the newest such record.
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
        // An admin key counts only from the newest root record of its
        // device: a newer one that names another key, or none, works as a
        // removal of it.
        self.superseded.clear();
        let mut current = BTreeSet::new();
        let mut taken = Vec::new();
        for rs in self.e.devices.values() {
            let Some(newest) =
                rs.iter().copied().filter(|&i| self.root_record(i)).reduce(|a, b| if self.newer(b, a) { b } else { a })
            else {
                continue;
            };
            let now = self.r(newest).dev().and_then(|d| d.admin.as_ref()).map(Key::hash);
            current.extend(now);
            for &i in rs {
                if let Some(a) = self.r(i).dev().and_then(|d| d.admin.as_ref()).map(Key::hash)
                    && self.root_record(i)
                    && Some(a) != now
                {
                    taken.push((a, newest));
                }
            }
        }
        for (a, by) in taken {
            if !current.contains(&a) {
                self.superseded.insert(a, by);
            }
        }
    }

    fn powers(&self, admin: &KeyHash) -> u64 {
        self.admins.get(admin).map_or(0, |&i| match &self.r(i).b().kind {
            Kind::Device(d) => d.powers,
            _ => 0,
        })
    }

    fn has(&self, admin: &KeyHash, power: u64) -> bool {
        self.powers(admin) & power != 0
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
        self.on_path.contains_key(k)
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
    fn find_admitted(&mut self, not_counting: &BTreeSet<usize>) {
        self.contested.clear();
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
                        && !not_counting.contains(&i)
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
            if firsts.len() > 1 {
                self.contested.extend(firsts.iter().copied());
            }
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

    /// Finds the admitted devices and labels the admins' records. A first
    /// record that does not count stands in the way of none that does:
    /// when several admins' first records admit one device, the records
    /// are labelled once as they are, and those a removal, a freeze or a
    /// new admin key cut are left out of the admits before the labelling
    /// that counts.
    fn admit_and_label(&mut self) {
        let base = self.conflicts.len();
        self.find_admitted(&BTreeSet::new());
        if !self.contested.is_empty() {
            self.undecided_admits.clear();
            self.do_label();
            let out: BTreeSet<usize> = core::mem::take(&mut self.contested)
                .into_iter()
                .filter(|&i| self.label[i] == Label::Out && matches!(self.why[i], Some(Why::Cut | Why::Removed)))
                .collect();
            self.label.fill(Label::Unlabelled);
            self.why.fill(None);
            self.conflicts.truncate(base);
            self.find_admitted(&out);
        }
        self.do_label();
    }

    /// Reports whether an admin may sign record i.
    fn permitted(&self, i: usize) -> bool {
        let r = self.r(i);
        let a = &r.b().signer;
        if r.held || !self.admins.contains_key(a) || self.capped[i] {
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
                // No admin outranks a root or the recovery key.
                if self.is_root(k) || *k == self.recovery {
                    false
                } else if self.is_admin(k) {
                    self.has(a, POWER_REMOVE_ADMINS)
                } else {
                    self.has(a, POWER_REMOVE)
                }
            }),
            Kind::Freeze(rm) => {
                self.has(a, POWER_FREEZE)
                    && rm.keys.iter().all(|k| self.admins.contains_key(k) && !self.has(k, POWER_REMOVE_ADMINS))
            }
            Kind::Thaw { .. } => self.has(a, POWER_THAW) && self.has(a, POWER_REMOVE_ADMINS),
            Kind::Hubs { .. } => self.has(a, POWER_HUB),
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

    /// The freezes the thaws that count name, with those thaws: a root's
    /// in this epoch, or an admin's that is in.
    fn thaws_that_count(&self) -> BTreeMap<RecordId, Vec<usize>> {
        self.thaws_where(|i| self.counts(i))
    }

    /// The freezes the root's thaws of this epoch name, with those thaws.
    fn root_thaws(&self) -> BTreeMap<RecordId, Vec<usize>> {
        self.thaws_where(|i| self.root_record(i))
    }

    fn thaws_where(&self, ok: impl Fn(usize) -> bool) -> BTreeMap<RecordId, Vec<usize>> {
        let mut t: BTreeMap<RecordId, Vec<usize>> = BTreeMap::new();
        for i in self.all() {
            if let Some(ids) = self.r(i).thaw()
                && ok(i)
            {
                for id in ids {
                    t.entry(*id).or_default().push(i);
                }
            }
        }
        t
    }

    /// Reports whether one of thaws (of a freeze) lifts it for record b
    /// (`lifts`).
    fn spared(&self, thaws: Option<&Vec<usize>>, b: usize) -> bool {
        thaws.is_some_and(|ts| ts.iter().any(|&t| self.lifts(t, b)))
    }

    /// Reports whether thaw t lifts its freeze for record b of a frozen
    /// key: t saw b, or b's own seen lists t (signed after the thaw). What
    /// the key signed in the frozen time counts only if the thaw saw it.
    fn lifts(&self, t: usize, b: usize) -> bool {
        self.e.saw(t, b) || self.e.saw(b, t)
    }

    /// Gives every admin record its label: the grounded labelling of the
    /// attacks of removals and freezes. A freeze's cut of a record is
    /// lifted by a thaw of that freeze that counts and saw the record, or
    /// that the record's own seen lists; the rest stays cut.
    fn do_label(&mut self) {
        let root_thaws = self.root_thaws();
        let mut admin_recs = Vec::new();
        let mut root_acts = Vec::new();
        for i in self.all() {
            let r = self.r(i);
            if self.root_record(i) {
                if r.is_revoke() || r.is_freeze() {
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
            let gone = self.superseded.get(&self.r(b).b().signer).is_some_and(|&by| !self.e.saw(by, b));
            if gone || root_acts.iter().any(|&a| self.cuts_off(a, b) && !self.spared(root_thaws.get(&self.r(a).id), b))
            {
                self.label[b] = Label::Out;
                self.why[b] = Some(Why::Cut);
            }
        }
        // Who attacks whom, by signer, so that this stays near linear: a
        // record is attacked by the removals and freezes naming its signer;
        // a freeze's attack is lifted by its thaws that lift it (`lifts`).
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
        // Each attack with the thaws that lift it.
        let mut attacks: BTreeMap<usize, Vec<(usize, Vec<usize>)>> = BTreeMap::new();
        for &b in &admin_recs {
            let rb = self.r(b);
            let mut by = Vec::new();
            for &a in removals_of.get(&rb.b().signer).map_or(&[][..], |v| v.as_slice()) {
                let ra = self.r(a);
                if !self.cuts_off(a, b) || ra.is_freeze() && self.spared(root_thaws.get(&ra.id), b) {
                    continue;
                }
                let lift: Vec<usize> = if ra.is_freeze() {
                    thaws_of.get(&ra.id).into_iter().flatten().copied().filter(|&t| self.lifts(t, b)).collect()
                } else {
                    Vec::new()
                };
                by.push((a, lift));
            }
            if !by.is_empty() {
                attacks.insert(b, by);
            }
        }
        let attackers: BTreeMap<usize, Vec<usize>> = attacks
            .iter()
            .map(|(&b, by)| {
                (b, by.iter().flat_map(|(a, lift)| core::iter::once(*a).chain(lift.iter().copied())).collect())
            })
            .collect();
        let mut changed = true;
        while changed {
            changed = false;
            for &b in &admin_recs {
                if self.label[b] != Label::Unlabelled {
                    continue;
                }
                let mut all = true;
                for (a, lift) in attacks.get(&b).map_or(&[][..], |v| v.as_slice()) {
                    let lifted = lift.iter().any(|&t| self.label[t] == Label::In);
                    let pending = lift.iter().any(|&t| self.label[t] != Label::Out);
                    if self.label[*a] == Label::In && !pending {
                        self.label[b] = Label::Out;
                        self.why[b] = Some(Why::Removed);
                        changed = true;
                        break;
                    }
                    if self.label[*a] != Label::Out && !lifted {
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
        let thawed = self.thaws_that_count();
        for i in self.all() {
            if !self.counts(i) {
                continue;
            }
            let r = self.r(i);
            if let Some(rm) = r.removal() {
                if r.is_revoke() {
                    // The recovery key is never removed (rule 33).
                    let recovery = self.recovery;
                    self.revoked.extend(rm.keys.iter().copied().filter(|k| *k != recovery));
                } else if !thawed.contains_key(&r.id) {
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
            // Only the current root or a live admin of this epoch: the two
            // histories of another key decide nothing, and those of a root
            // before the current one ended with the change of root, whose
            // list carries what counts of it.
            let current = signer == self.cur;
            if !current && !self.live_admin(&signer) {
                continue;
            }
            let records =
                self.of(&signer).iter().filter(|&&i| self.r(i).b().seq == seq).map(|&i| self.r(i).id).collect();
            self.conflicts.push(Conflict { kind: ConflictKind::TwoHistories, records, signers: vec![signer] });
            if current {
                // Two histories of the current root halt the group until the
                // recovery key changes the root.
                self.stop_full = true;
            }
        }
    }

    /// Reports whether k is an admin key of this epoch that is not removed.
    fn live_admin(&self, k: &KeyHash) -> bool {
        self.admins.contains_key(k) && !self.revoked.contains(k) && !self.superseded.contains_key(k)
    }

    /// k with the other key of its device: an admin key's member key, or
    /// the admin key of the device whose member key k is.
    fn with_pair(&self, k: &KeyHash) -> Vec<KeyHash> {
        let mut keys = vec![*k];
        if let Some(p) = self.pairs.get(k) {
            keys.extend(p.iter().copied());
        }
        keys
    }

    /// Each admin key with its device's member key, both ways.
    fn find_pairs(&mut self) {
        let mut pairs: BTreeMap<KeyHash, Vec<KeyHash>> = BTreeMap::new();
        for a in self.admins.keys() {
            if let Some(m) = self.member_of_admin(a) {
                pairs.entry(*a).or_default().push(m);
                pairs.entry(m).or_default().push(*a);
            }
        }
        self.pairs = pairs;
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

    /// The record of a type, one a root or an admin signs, that counts for
    /// the state: a root's beats an admin's, then the later root on the
    /// path and the higher seq; of one admin's, the higher seq; of two
    /// admins', the one that saw the other, and when both or neither did,
    /// the smaller ID (no clock decides, rule 7).
    fn best(&self, want: impl Fn(&Kind) -> bool) -> Option<usize> {
        let mut best: Option<usize> = None;
        for i in self.all() {
            // A removed admin's record is left out, whatever it saw.
            let removed = self.r(i).admin() && self.revoked.contains(&self.r(i).b().signer);
            if !self.r(i).held
                && !removed
                && want(&self.r(i).b().kind)
                && self.counts(i)
                && best.is_none_or(|b| self.beats(i, b))
            {
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
        if ba.signer == bb.signer {
            return ba.seq > bb.seq;
        }
        match (self.e.saw(a, b), self.e.saw(b, a)) {
            (true, false) => true,
            (false, true) => false,
            _ => self.r(a).id < self.r(b).id,
        }
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
        let forked_admin = self.forked.keys().any(|k| !self.on_path.contains_key(k) && self.live_admin(k));
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
        for signer in self.forked.keys().filter(|k| self.revoked.contains(*k)) {
            let mut lost: Vec<KeyHash> = self
                .of(signer)
                .iter()
                .filter(|&&i| self.counted[i] && !self.counts(i))
                .filter_map(|&i| self.r(i).removal().filter(|_| self.r(i).is_revoke()))
                .flat_map(|rm| rm.keys.iter().copied())
                .filter(|k| !self.revoked.contains(k))
                .collect();
            lost.sort();
            lost.dedup();
            if !lost.is_empty() {
                s.forked_removed.push((*signer, lost));
            }
        }
        // A checkpoint may prune a removed device's record; its removal
        // still names its key.
        s.named.extend(self.revoked.iter().map(DeviceId::of));
        s.changes = self.changes.clone();
        s.conflicts.extend(self.conflicts.iter().cloned());
        for c in &mut s.conflicts {
            c.records.sort();
            c.signers.sort();
            c.signers.dedup();
        }
        s.conflicts.sort_by(|a, b| (a.kind, a.records.first()).cmp(&(b.kind, b.records.first())));
        if let Some(best) = self.best(|k| matches!(k, Kind::Hubs { .. }))
            && let Kind::Hubs { hubs: h, .. } = &self.r(best).b().kind
        {
            s.hubs = h.iter().filter(|d| s.device(d).is_some_and(|d| d.rights & RIGHT_HUB != 0)).copied().collect();
        }
        if let Some(best) = self.best(|k| matches!(k, Kind::Copies { .. }))
            && let Kind::Copies { incoming_ms, .. } = &self.r(best).b().kind
        {
            s.incoming_ms = Some(*incoming_ms);
        }
        s.settings = self.settings.clone();
        s.too_old = self.settings.rules() > RULES_VERSION;
        s.recovery = self.recovery;
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
            if self.counts(i) && !conflicted.contains(&i) {
                s.counting.insert(self.r(i).id);
            }
        }
        s.counting.extend(self.chain_records.iter().copied());
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
        state.cut = self.cuts.values().next().cloned();
        let admins: BTreeSet<KeyHash> = state.devices.iter().filter_map(|d| d.admin).chain([state.recovery]).collect();
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
