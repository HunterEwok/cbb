// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok
//! Nothing silent: what a set tells the app about its rooms and about a
//! change of root that waits, and the writer's warning before an admin
//! removal. Every call here reads the set (on a copy where it must judge
//! the rooms); none changes what the set holds or how a record is judged.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec;
use alloc::vec::Vec;

use super::super::body::{Body, Removal};
use super::super::eval::{self, Checked, Role, State};
use super::super::key::{DeviceId, KeyHash, RecordId};
use super::super::{Kind, Record};
use super::{Added, RecordSet};

/// A day in milliseconds, for the days the notices count.
const DAY_MS: u64 = 86_400_000;

/// A key's room: its fixed cap and what its records take now. The cap is
/// the root's, the reserve of the roots a change cut, a live admin key's,
/// or 0 for a key that is no longer an admin (docs/protocol.md, section
/// 10, "Tiers inside the rooms").
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Room {
    /// The key whose room it is (the roots a change cut share one).
    pub key: KeyHash,
    /// The units of 512 bytes the room holds at most, read from the roster
    /// (what is kept first included).
    pub cap: u64,
    /// The units its records take now, those kept first included.
    pub used: u64,
}

impl Room {
    /// The units the key may still add. Exact: caps do not move with what
    /// other keys hold, only with the roster.
    pub fn left(&self) -> u64 {
        self.cap.saturating_sub(self.used)
    }

    /// No record of the key's next in its order fits any more: a record of
    /// `units` past the key's last would be turned away. The app shows
    /// "this key's room is full".
    pub fn full_for(&self, units: u64) -> bool {
        self.left() < units
    }
}

/// What the rooms would do with a record that came now, told without
/// taking it (`RecordSet::would_take`).
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Offer {
    /// Kept, and nothing of what the set holds leaves for it.
    Kept,
    /// Kept, and these records of the same room leave for it: it comes
    /// earlier in the key's order than they do, and with it they no longer
    /// fit.
    PushesOut(Vec<RecordId>),
    /// Turned away by the rooms, with why.
    TurnedAway(TurnedAway),
}

/// Why the rooms turn a record away: its room once the record is counted
/// in, and the record's own units.
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

/// A live admin key the root has not heard from for a while
/// (`RecordSet::admins_silent`): the root takes it back after
/// `ADMIN_SILENCE_MS` (`take_back_lagging`).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct AdminSilent {
    pub key: KeyHash,
    /// The device that holds it.
    pub device: DeviceId,
    /// Since when the silence counts, on the root device's clock: when it
    /// last received a record of the key, else when the root named it.
    pub since_ms: u64,
    /// Whole days left before the take-back is due; 0 when it is due now.
    pub days_left: u64,
    /// The removals this key has not acknowledged (`unacknowledged`).
    pub holds_back: usize,
}

/// A counting removal some live admin key has not acknowledged yet
/// (`RecordSet::removals_waiting`): a checkpoint keeps it until they do.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct WaitingRemoval {
    pub removal: RecordId,
    /// The keys it removes.
    pub keys: Vec<KeyHash>,
    /// The live admin keys that still owe an acknowledgement.
    pub waits_for: Vec<KeyHash>,
}

/// The current root's room taken by removals that wait for
/// acknowledgements (`RecordSet::root_room_waiting`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct RootRoomWaiting {
    /// The root's room as `root_room` gives it.
    pub room: Room,
    /// How many of the root's own removals wait.
    pub waiting: usize,
    /// The units they take.
    pub waiting_units: u64,
}

/// On an admin's own device: an acknowledgement is owed
/// (`RecordSet::ack_owed`). A phone's admin key signs only after the
/// person unlocks it, so the app shows this quietly and writes the
/// acknowledgement with the next admin action the person takes, in the
/// same unlock; it never asks out of nowhere.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct AckOwed {
    pub key: KeyHash,
    /// The removals that wait for this key.
    pub removals: usize,
    /// Whole days left before the root may take the key back for silence,
    /// as far as this device can tell: from the key's last
    /// acknowledgement that counts here, else from when the root named it.
    /// The root's own clock decides.
    pub days_left: u64,
}

impl RecordSet {
    /// The fixed cap of the room key's records go to.
    fn cap_of(&self, key: &KeyHash) -> Option<u64> {
        self.cap(key)
    }

    /// The room of a key that may sign records (the root, an admin key, a
    /// key no longer an admin with cap 0, a cut root); None for any other
    /// key.
    pub fn room_of(&self, key: &KeyHash) -> Option<Room> {
        let k = self.room_key(key);
        let cap = self.cap_of(&k)?;
        let used =
            self.units.iter().filter(|(s, _)| self.room_key(s) == k).fold(0u64, |t, (_, u)| t.saturating_add(*u));
        Some(Room { key: k, cap, used })
    }

    /// The current root's room (`room_of` of the last root of the path).
    pub fn root_room(&self, state: &State) -> Option<Room> {
        state.roots.last().and_then(|r| self.room_of(r))
    }

    /// What the rooms would do with record r if it came now, tried on a
    /// copy of the set: None when the set holds it already or refuses it
    /// for another reason than room (its signature, its signer, its place
    /// in a chain), or when it waits for something before it is judged.
    pub fn would_take(&self, r: &Record) -> Option<Offer> {
        if self.contains(&r.id()) {
            return None;
        }
        let mut t = self.clone();
        let got = t.insert(r.clone()).ok()?;
        if !matches!(got, Added::NoRoom | Added::Stored) {
            return None;
        }
        if !t.contains(&r.id()) {
            let role = self.keys.signer(&r.body().signer).map_or(Role::Admin, |(_, role)| role);
            let units = eval::item(r, role).units;
            let room = t.room_of(&r.body().signer)?;
            return Some(Offer::TurnedAway(TurnedAway { record: r.id(), units, room }));
        }
        let k = self.room_key(&r.body().signer);
        let out: Vec<RecordId> = self
            .records
            .values()
            .filter(|e| self.room_key(&e.record.body().signer) == k && !t.contains(&e.record.id()))
            .map(|e| e.record.id())
            .collect();
        Some(if out.is_empty() { Offer::Kept } else { Offer::PushesOut(out) })
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
    /// Being settled: the root's writer writes a checkpoint before such a
    /// removal; this judges the removal without it, so it can name devices
    /// that checkpoint would keep.
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

    /// The live admin keys silent for at least `after_ms` at `now_ms`, the
    /// longest silence first. `heard_ms` is when the root device last
    /// received a record of each key, on its own clock (the app keeps it);
    /// a key it never heard from counts from the root record that named it,
    /// as `take_back_lagging` counts.
    pub fn admins_silent(
        &self,
        state: &State,
        heard_ms: &BTreeMap<KeyHash, u64>,
        now_ms: u64,
        after_ms: u64,
    ) -> Vec<AdminSilent> {
        let held = self.unacknowledged(state);
        let mut out: Vec<AdminSilent> = state
            .devices
            .iter()
            .filter_map(|d| {
                let key = d.admin?;
                let since_ms = heard_ms.get(&key).copied().or_else(|| self.named_at(state, &key))?;
                let silent = now_ms.saturating_sub(since_ms);
                (silent >= after_ms).then(|| AdminSilent {
                    key,
                    device: d.id,
                    since_ms,
                    days_left: super::ADMIN_SILENCE_MS.saturating_sub(silent).div_ceil(DAY_MS),
                    holds_back: held.get(&key).copied().unwrap_or(0),
                })
            })
            .collect();
        out.sort_by_key(|s| (s.since_ms, s.key));
        out
    }

    /// The counting removals that wait for acknowledgements, with the live
    /// admin keys each waits for, in the order of the set.
    pub fn removals_waiting(&self, state: &State) -> Vec<WaitingRemoval> {
        let admins = Self::live_admins(state);
        self.records
            .values()
            .filter(|e| !e.held && state.counting.contains(&e.record.id()))
            .filter_map(|e| {
                let b = e.record.body();
                let Kind::Revoke(rm) = &b.kind else { return None };
                let waits_for: Vec<KeyHash> = admins
                    .iter()
                    .filter(|a| **a != b.signer && !self.acked_by(state, a, &b.signer, b.seq))
                    .copied()
                    .collect();
                (!waits_for.is_empty()).then(|| WaitingRemoval {
                    removal: e.record.id(),
                    keys: rm.keys.clone(),
                    waits_for,
                })
            })
            .collect()
    }

    /// The current root's removals that wait, when they take at least
    /// `warn_at_percent` of its room; None below that, or with no root
    /// room. The app says which admins must come online or be taken back
    /// (`admins_silent`, `removals_waiting`).
    pub fn root_room_waiting(&self, state: &State, warn_at_percent: u64) -> Option<RootRoomWaiting> {
        let room = self.root_room(state)?;
        let root = room.key;
        let mut waiting = 0usize;
        let mut waiting_units = 0u64;
        for w in self.removals_waiting(state) {
            let Some(r) = self.get(&w.removal) else { continue };
            if r.body().signer == root {
                waiting = waiting.saturating_add(1);
                waiting_units = waiting_units.saturating_add(super::keep::units(
                    r.body().encode().len().saturating_add(super::super::ENVELOPE_ALLOWANCE),
                ));
            }
        }
        (waiting > 0 && waiting_units.saturating_mul(100) >= room.cap.saturating_mul(warn_at_percent))
            .then_some(RootRoomWaiting { room, waiting, waiting_units })
    }

    /// Whether admin key `own` owes an acknowledgement at `now_ms`, on its
    /// own device: some removal waits for it (`ack_due`).
    pub fn ack_owed(&self, state: &State, own: &KeyHash, now_ms: u64) -> Option<AckOwed> {
        let removals = self.unacknowledged(state).get(own).copied().unwrap_or(0);
        if removals == 0 {
            return None;
        }
        let since = self.last_ack(state, own).map(|(_, t)| t).or_else(|| self.named_at(state, own))?;
        let days_left = super::ADMIN_SILENCE_MS.saturating_sub(now_ms.saturating_sub(since)).div_ceil(DAY_MS);
        Some(AckOwed { key: *own, removals, days_left })
    }
}
