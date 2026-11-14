// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok
//! Nothing silent: what a set tells the app about its rooms and about a
//! change of root that waits, and the writer's warning before an admin
//! removal. Every call here reads the set (on a copy where it must judge
//! the rooms); none changes what the set holds or how a record is judged.

use alloc::collections::BTreeSet;
use alloc::vec;
use alloc::vec::Vec;

use super::super::body::{Body, Removal};
use super::super::eval::{self, Checked, Role, State};
use super::super::key::{DeviceId, KeyHash, RecordId};
use super::super::{Kind, Record, keep};
use super::{Added, RecordSet};

/// Which tier of the rooms a key is in (docs/protocol.md, section 10,
/// "Tiers inside the rooms").
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Tier {
    /// The root, the live admin keys and the cut roots' room.
    First,
    /// The keys that are no longer admins: they share what the first tier
    /// leaves.
    Second,
}

/// A key's room, as the rooms judge what the set holds now.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Room {
    /// The key whose room it is (the cut roots share one).
    pub key: KeyHash,
    pub tier: Tier,
    /// The units of 512 bytes the key may hold at most (its ceiling).
    pub ceiling: u64,
    /// What the key may hold at its tier's level now, its ceiling at most;
    /// with the units its records kept first take.
    pub share: u64,
    /// The units the key's records take, kept first ones included.
    pub used: u64,
}

impl Room {
    /// The units the key may still add at the level now. While the group
    /// is full (`Fullness::squeezed`) a new record of any key lowers the
    /// level, so this is the most it may add, not a promise.
    pub fn left(&self) -> u64 {
        self.share.saturating_sub(self.used)
    }
}

/// How full the rooms are, from what the set holds.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Fullness {
    /// The units all the rooms' records take.
    pub used: u64,
    /// The units the rooms have in all.
    pub room: u64,
    /// Fewer units are left than a record of the largest size takes: the
    /// next record may be turned away, whatever its key's share. The app
    /// shows "the group is full". Whether one given record would be is
    /// `RecordSet::turned_away`.
    pub full: bool,
}

impl Fullness {
    /// The units left in all the rooms.
    pub fn free(&self) -> u64 {
        self.room.saturating_sub(self.used)
    }
}

/// Why the rooms turn a record away: its key's room once the record is
/// counted in, and the record's own units.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct TurnedAway {
    pub record: RecordId,
    pub units: u64,
    pub room: Room,
}

/// A change of root the set waits for: the app shows "a change of root is
/// arriving" and the driver sends its records again on every connection
/// (docs/core-api.md, "Sync of records: what a driver must do").
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ChangeArriving {
    /// The first record of the change's group the set lacks: the new
    /// root's first checkpoint, or a record of it below that.
    pub first_missing: Option<RecordId>,
    /// The hash of the change's list, when the set lacks it.
    pub list_missing: Option<[u8; 32]>,
}

/// What a removal of admin keys would take from the group, told before it
/// is written.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct RemovalWarning {
    /// The devices that would no longer be in the group.
    pub out: Vec<DeviceId>,
    /// The devices that would stay but no longer hold an admin key.
    pub no_longer_admin: Vec<DeviceId>,
}

impl RecordSet {
    /// A copy of the set whose rooms are judged afresh over what it holds:
    /// the levels of what is held, whatever the set did before.
    fn judged(&self) -> RecordSet {
        let mut t = self.clone();
        t.batch = None;
        t.cut = keep::Cut::default();
        t.cut();
        t
    }

    fn room_in(&self, key: &KeyHash) -> Option<Room> {
        let k = self.room_key(key);
        let ceiling = self.ceiling(&k)?;
        let tier = if self.second.contains(&k) { Tier::Second } else { Tier::First };
        let level = self.cut.level(tier == Tier::Second);
        let used =
            self.units.iter().filter(|(s, _)| self.room_key(s) == k).fold(0u64, |t, (_, u)| t.saturating_add(*u));
        Some(Room { key: k, tier, ceiling, share: level.min(ceiling), used })
    }

    /// The room of a key that may sign records (the root, an admin key, a
    /// cut root), as the rooms judge what the set holds now; None for a
    /// key with no room.
    pub fn room_of(&self, key: &KeyHash) -> Option<Room> {
        self.judged().room_in(key)
    }

    /// The current root's room (`room_of` of the last root of the path).
    pub fn root_room(&self, state: &State) -> Option<Room> {
        state.roots.last().and_then(|r| self.room_of(r))
    }

    /// How full the rooms are now.
    pub fn fullness(&self) -> Fullness {
        let used = self.units.values().fold(0u64, |a, u| a.saturating_add(*u));
        let room = keep::room();
        let largest = keep::units(super::super::MAX_BODY.saturating_add(super::super::ENVELOPE_ALLOWANCE));
        Fullness { used, room, full: room.saturating_sub(used) < largest }
    }

    /// Why the rooms would turn record r away if it came now, or None when
    /// they would keep it, the set holds it already, or it is refused for
    /// another reason (its signature, its signer, its place in a chain):
    /// the record is tried on a copy of the set.
    pub fn turned_away(&self, r: &Record) -> Option<TurnedAway> {
        if self.contains(&r.id()) {
            return None;
        }
        let mut t = self.clone();
        let got = t.insert(r.clone()).ok()?;
        let away = matches!(got, Added::NoRoom) || (got == Added::Stored && !t.contains(&r.id()));
        if !away {
            return None;
        }
        let role = self.keys.signer(&r.body().signer).map_or(Role::Admin, |(_, role)| role);
        let units = eval::item(r, role).units;
        let room = t.judged().room_in(&r.body().signer)?;
        Some(TurnedAway { record: r.id(), units, room })
    }

    /// The change of root the set waits for, if any: the new root's first
    /// records or its list. `stuck_checkpoints` does not cover it.
    pub fn change_arriving(&self, state: &State) -> Option<ChangeArriving> {
        (state.first_missing.is_some() || state.list_missing.is_some())
            .then_some(ChangeArriving { first_missing: state.first_missing, list_missing: state.list_missing })
    }

    /// The writer's warning before remover removes the admin keys in
    /// removed: the devices that would leave the group and those that
    /// would no longer hold an admin key, from the records the set holds.
    /// Nothing is signed or written; the removal is evaluated as if it
    /// were the remover's next record.
    pub fn removal_warning(
        &self,
        state: &State,
        remover: &KeyHash,
        removed: &[KeyHash],
        time_ms: u64,
    ) -> RemovalWarning {
        let Some((_, role)) = self.keys.signer(remover) else { return RemovalWarning::default() };
        let own = self.heads_where(|k| k == remover).into_iter().next();
        let (seq, prev) = own.map_or((1, None), |o| (o.seq.saturating_add(1), Some(o.id)));
        let mut keys: Vec<KeyHash> = removed.to_vec();
        keys.sort();
        keys.dedup();
        let kind = Kind::Revoke(Removal { keys, seen: Vec::new() });
        let body = Body { group: self.group, signer: *remover, seq, prev, time_ms, kind, held: false };
        let bytes = body.encode();
        let id = RecordId(crate::certs::sha256(&bytes));
        // Never signed and never stored: evaluated as checked, beside the
        // set's own records, for this answer only.
        let trial = Record { bytes, sig: vec![], sig2: None, body, id };
        let mut checked: Vec<Checked<'_>> = self.checked();
        checked.push(Checked { r: &trial, role, held: false });
        let lists = self.list_refs();
        let by = eval::Compacted { proven: &self.checkpoints };
        let early: Vec<&Record> = self.early.values().collect();
        let after = eval::evaluate_checked(
            &self.root,
            &self.recovery,
            checked,
            alloc::collections::BTreeMap::new(),
            &lists,
            &by,
            &early,
        );
        let stays: BTreeSet<DeviceId> = after.devices.iter().map(|d| d.id).collect();
        let mut warning = RemovalWarning::default();
        for d in &state.devices {
            if !stays.contains(&d.id) {
                warning.out.push(d.id);
            } else if d.admin.is_some() && after.devices.iter().any(|a| a.id == d.id && a.admin.is_none()) {
                warning.no_longer_admin.push(d.id);
            } else if d.admin.as_ref().is_some_and(|a| removed.contains(a)) {
                // The device stays, but its admin key no longer counts.
                warning.no_longer_admin.push(d.id);
            }
        }
        warning
    }
}
