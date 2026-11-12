// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The intro (format 11.3, design-no-certificates section 3): the first
//! message of a member whose key the peer does not know yet, such as a
//! device admitted a minute ago by an admin the peer has not heard from.
//! It carries the sender's own record and the records that prove it up to
//! the group's first root: the root changes, and for each signer on the way
//! the record that gave it its admin key. At most 32 records and 16 KiB.
//!
//! The receiver checks every signature up to the root it holds, on a copy
//! of its set; only when the sender's key then stands as a member does it
//! keep them. Anything else closes the connection and keeps nothing.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;

use crate::format::{Rule, Value, cbor};
use crate::peer::{Standing, standing};
use crate::records::body::Kind;
use crate::records::set::{Added, RecordSet};
use crate::records::{KeyHash, Record, RecordId, State};

/// The most records an intro carries.
pub const MAX_RECORDS: usize = 32;
/// The most bytes its records take together.
pub const MAX_BYTES: usize = 16 * 1024;

pub const RULE_SHAPE: Rule = Rule::field("intro/shape");
pub const RULE_SIZE: Rule = Rule::field("intro/size");
/// A record of the intro that does not read (`Record::decode`).
pub const RULE_RECORD: Rule = Rule::field("intro/record");

/// Why an intro is refused; the connection closes.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Refusal {
    /// More than 32 records or 16 KiB.
    TooBig,
    /// A record that does not verify, of another group, or whose signer
    /// leads nowhere.
    Broken,
    /// With its records the sender's key is still not a member of the group.
    NotMember,
}

/// The records that lead from the group's first root to the device with
/// member key `device`: every counting claim and handover (the root
/// changes), the device's counting records, and for each admin key that
/// signed one of them the counting record that named that key, up to the
/// roots.
pub fn chain(set: &RecordSet, state: &State, device: &KeyHash) -> BTreeSet<RecordId> {
    let records: Vec<&Record> =
        set.in_dependency_order().into_iter().filter(|r| state.counting.contains(&r.id())).collect();
    let mut out: BTreeSet<RecordId> = BTreeSet::new();
    let mut signers: Vec<KeyHash> = Vec::new();
    for r in records.iter() {
        match &r.body().kind {
            Kind::Claim { .. } | Kind::Handover { .. } => {
                out.insert(r.id());
                signers.push(r.body().signer);
            }
            Kind::Device(d) if &d.key.hash() == device => {
                out.insert(r.id());
                signers.push(r.body().signer);
            }
            _ => {}
        }
    }
    let mut seen: BTreeSet<KeyHash> = BTreeSet::new();
    while let Some(s) = signers.pop() {
        if !seen.insert(s) || state.roots.contains(&s) || set.root().hash() == s {
            continue;
        }
        for r in records.iter() {
            if let Kind::Device(d) = &r.body().kind
                && d.admin.as_ref().is_some_and(|a| a.hash() == s)
                && out.insert(r.id())
            {
                signers.push(r.body().signer);
            }
        }
    }
    out
}

/// The intro a member sends: its chain in dependency order, and its keys
/// statement.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct Intro {
    pub records: Vec<Record>,
    pub keys: Option<Vec<u8>>,
}

impl Intro {
    /// The intro for the device with member key `own`.
    pub fn of(set: &RecordSet, state: &State, own: &KeyHash, keys: Option<Vec<u8>>) -> Result<Intro, Refusal> {
        let ids = chain(set, state, own);
        let records: Vec<Record> =
            set.in_dependency_order().into_iter().filter(|r| ids.contains(&r.id())).cloned().collect();
        let intro = Intro { records, keys };
        intro.check_size()?;
        Ok(intro)
    }

    fn check_size(&self) -> Result<(), Refusal> {
        let bytes: usize = self.records.iter().map(Record::size).fold(0, usize::saturating_add);
        if self.records.len() > MAX_RECORDS || bytes > MAX_BYTES {
            return Err(Refusal::TooBig);
        }
        Ok(())
    }

    /// The message (t = 8), unpadded: field 2 the record envelopes, field 3
    /// the statement.
    pub fn message(&self) -> Vec<u8> {
        let envs: Vec<Vec<u8>> = self.records.iter().map(Record::envelope).collect();
        let decoded: Vec<Value<'_>> = envs.iter().filter_map(|e| cbor::decode(e).ok()).collect();
        let keys = self.keys.as_ref().and_then(|k| cbor::decode(k).ok());
        let mut m = alloc::vec![(0u16, Value::Uint(super::T_INTRO)), (2, Value::Array(decoded))];
        if let Some(k) = keys {
            m.push((3, k));
        }
        Value::Map(m).encode()
    }

    /// The record envelopes and the statement of an intro message, before
    /// each record is read (`Record::decode`, the records' reader).
    #[allow(clippy::type_complexity, reason = "the parts as they come")]
    pub fn envelopes(msg: &[u8]) -> Result<(Vec<Vec<u8>>, Option<Vec<u8>>), Rule> {
        let v = cbor::decode(msg)?;
        if v.get(0).and_then(Value::as_uint) != Some(super::T_INTRO) {
            return Err(RULE_SHAPE);
        }
        let arr = v.get(2).and_then(Value::as_array).ok_or(RULE_SHAPE)?;
        if arr.len() > MAX_RECORDS {
            return Err(RULE_SIZE);
        }
        let envs: Vec<Vec<u8>> = arr.iter().map(Value::encode).collect();
        if envs.iter().map(Vec::len).fold(0, usize::saturating_add) > MAX_BYTES {
            return Err(RULE_SIZE);
        }
        Ok((envs, v.get(3).map(Value::encode)))
    }

    /// Reads an intro message: its envelopes, each record read with the
    /// records' reader (the signatures are checked by [`Intro::check`]).
    pub fn read(msg: &[u8]) -> Result<Intro, Rule> {
        let (envs, keys) = Intro::envelopes(msg)?;
        let records = envs.iter().map(|e| Record::decode(e).map_err(|_| RULE_RECORD)).collect::<Result<Vec<_>, _>>()?;
        Ok(Intro { records, keys })
    }

    /// Checks an intro from the peer with key `peer` against the set the
    /// receiver holds: every record verifies up to the receiver's root, and
    /// with them the peer is a member. Returns the records to keep (those
    /// the set did not hold); the caller inserts them into its set.
    pub fn check(
        &self,
        set: &RecordSet,
        held_ms: &BTreeMap<RecordId, u64>,
        own: &crate::format::KeyHash,
        peer: &[u8; 65],
    ) -> Result<Vec<Record>, Refusal> {
        self.check_size()?;
        // Before any work on the set: the records end in the record of the
        // sender's key.
        let ends_in_peer = matches!(self.records.last().map(|r| &r.body().kind), Some(Kind::Device(d)) if d.key.public.as_slice() == peer);
        if !ends_in_peer {
            return Err(Refusal::NotMember);
        }
        // The set's records are verified already: a copy, not a new set.
        let mut trial = set.clone();
        let mut new = Vec::new();
        for r in &self.records {
            match trial.insert(r.clone()) {
                Ok(Added::Stored) => new.push(r.clone()),
                Ok(Added::Known) => {}
                Ok(Added::NoRoom) | Err(_) => return Err(Refusal::Broken),
            }
        }
        let state = trial.state(held_ms);
        match standing(&state, own, peer) {
            Standing::Member(_) => Ok(new),
            _ => Err(Refusal::NotMember),
        }
    }
}

/// The most intros one address may send in a window.
pub const MAX_PER_WINDOW: u32 = 4;
/// The window.
pub const WINDOW_MS: u64 = 60_000;
/// The most addresses a [`Limiter`] tracks at once.
pub const MAX_ADDRESSES: usize = 256;

/// Counts intros per address, so that one address cannot make a member
/// check intro after intro.
#[derive(Clone, Default, Debug)]
pub struct Limiter {
    seen: BTreeMap<Vec<u8>, (u64, u32)>,
}

impl Limiter {
    /// Whether an intro from `addr` (its IP address's bytes) at `now_ms` may
    /// be checked; it counts it.
    pub fn allow(&mut self, addr: &[u8], now_ms: u64) -> bool {
        self.seen.retain(|_, (start, _)| now_ms.saturating_sub(*start) < WINDOW_MS);
        if let Some((_, n)) = self.seen.get_mut(addr) {
            if *n >= MAX_PER_WINDOW {
                return false;
            }
            *n = n.saturating_add(1);
            return true;
        }
        if self.seen.len() >= MAX_ADDRESSES {
            return false;
        }
        self.seen.insert(addr.to_vec(), (now_ms, 1));
        true
    }
}
