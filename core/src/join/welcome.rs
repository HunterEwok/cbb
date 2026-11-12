// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The Welcome (format 11.2): what an admitter sends the joiner once CPace
//! confirmed, and the joiner's checks of it (design-no-certificates
//! section 4). No certificate: the group's first root key, which gives the
//! group ID, and records in dependency order: the root changes, the
//! admitter's records with its rights, the joiner's own record, then the
//! others while the frame holds them. For each claim, how long the admitter
//! has held it (a duration, never a time).
//!
//! The joiner checks: the group ID from the code exchange is the root key's;
//! the records verify up to that root; its own record carries its own key;
//! the admitter's key from TLS stands in the records and the key that
//! signed the joiner's record is the root's or that admitter's admin key
//! with `admit`; the path of roots comes from the records, never from the
//! admitter's word.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;

use crate::format::{Alg, GroupId, Rule, Value, cbor};
use crate::records::body::{Kind, POWER_ADMIT};
use crate::records::eval::ClaimState;
use crate::records::set::RecordSet;
use crate::records::{Key, KeyHash, Record, RecordId, State};

use super::intro::chain;

/// What a Welcome may take of a pairing frame (64 KiB) for its records.
pub const RECORDS_BUDGET: usize = 56 * 1024;

pub const RULE_SHAPE: Rule = Rule::field("welcome/shape");
pub const RULE_ROOT: Rule = Rule::field("welcome/root");
/// A record of the Welcome that does not read (`Record::decode`).
pub const RULE_RECORD: Rule = Rule::field("welcome/record");
pub const RULE_AGES: Rule = Rule::field("welcome/claim-ages");

/// The Welcome.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct Welcome {
    /// The group's first root key, its point.
    pub root: Vec<u8>,
    pub records: Vec<Record>,
    /// `[record ID, held_ms]`, sorted: how long the admitter held each claim.
    pub claim_ages: Vec<(RecordId, u64)>,
    /// Statements of the group's devices, as envelopes.
    pub keys: Vec<Vec<u8>>,
    /// The admitter's clock, for a joiner without one (A-47).
    pub time_ms: u64,
    /// A leaf's first grant: the map of message `grant`'s fields 2–5, as
    /// its encoding.
    pub grant: Option<Vec<u8>>,
    /// The current period's server credentials, as envelopes.
    pub credentials: Vec<Vec<u8>>,
    /// The claims the admitter has counted, sorted: a takeover a member
    /// counted is final for it, and the joiner takes them as its own.
    pub counted: Vec<RecordId>,
}

/// Why the joiner does not take a Welcome.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Refusal {
    /// The root key's group ID is not the one the code exchange gave.
    OtherGroup,
    /// The records do not hold the joiner's own record with its own key.
    NotAdmitted,
    /// The admitter's key is not a device of the group, or the key that
    /// signed the joiner's record is neither the root's nor the admitter's
    /// admin key with `admit`.
    NotAdmitter,
    /// The Welcome is damaged.
    Damaged,
    /// A takeover the admitter counted is not in effect by the Welcome's own
    /// records and ages (its signer may not take over, its key is void, it
    /// was cancelled, it has not waited the root's delay), or counting it
    /// puts the joiner at odds with them.
    Takeover,
}

impl Welcome {
    /// The Welcome an admitter sends: its set already holds the joiner's
    /// record. `admitter` and `joiner` are the member keys' hashes; `held`
    /// how long the admitter has held each claim.
    pub fn build(
        set: &RecordSet,
        state: &State,
        admitter: &KeyHash,
        joiner: &KeyHash,
        held: &BTreeMap<RecordId, u64>,
        time_ms: u64,
    ) -> Welcome {
        let mut needed: BTreeSet<RecordId> = chain(set, state, admitter);
        needed.extend(chain(set, state, joiner));
        let order = set.in_dependency_order();
        let mut records: Vec<Record> =
            order.iter().filter(|r| needed.contains(&r.id())).map(|r| (*r).clone()).collect();
        let mut used: usize = records.iter().map(Record::size).fold(0, usize::saturating_add);
        for r in order.iter().filter(|r| !needed.contains(&r.id())) {
            let n = used.saturating_add(r.size());
            if n > RECORDS_BUDGET {
                break;
            }
            used = n;
            records.push((*r).clone());
        }
        let mut claim_ages: Vec<(RecordId, u64)> = records
            .iter()
            .filter(|r| matches!(r.body().kind, Kind::Claim { .. }))
            .map(|r| (r.id(), held.get(&r.id()).copied().unwrap_or(0)))
            .collect();
        claim_ages.sort();
        Welcome {
            root: set.root().public.clone(),
            records,
            claim_ages,
            keys: Vec::new(),
            time_ms,
            grant: None,
            credentials: Vec::new(),
            counted: set.counted().iter().copied().collect(),
        }
    }

    /// The Welcome's encoding (the map of format 11.2).
    pub fn encode(&self) -> Vec<u8> {
        let envs: Vec<Vec<u8>> = self.records.iter().map(Record::envelope).collect();
        fn values(v: &[Vec<u8>]) -> Option<Vec<Value<'_>>> {
            v.iter().map(|e| cbor::decode(e).ok()).collect()
        }
        let mut m: Vec<(u16, Value<'_>)> = Vec::new();
        m.push((1, Value::Array(alloc::vec![Value::Uint(Alg::Es256.number()), Value::Bytes(&self.root)])));
        m.push((2, Value::Array(values(&envs).unwrap_or_default())));
        if !self.claim_ages.is_empty() {
            m.push((
                3,
                Value::Array(
                    self.claim_ages
                        .iter()
                        .map(|(id, ms)| Value::Array(alloc::vec![Value::Bytes(&id.0), Value::Uint(*ms)]))
                        .collect(),
                ),
            ));
        }
        if !self.keys.is_empty() {
            m.push((4, Value::Array(values(&self.keys).unwrap_or_default())));
        }
        m.push((5, Value::Uint(self.time_ms)));
        let grant = self.grant.as_ref().and_then(|g| cbor::decode(g).ok());
        if let Some(g) = grant {
            m.push((6, g));
        }
        if !self.credentials.is_empty() {
            m.push((7, Value::Array(values(&self.credentials).unwrap_or_default())));
        }
        let mut counted = self.counted.clone();
        counted.sort();
        counted.dedup();
        if !counted.is_empty() {
            m.push((8, Value::Array(counted.iter().map(|id| Value::Bytes(&id.0)).collect())));
        }
        Value::Map(m).encode()
    }

    /// The parts of an encoded Welcome before each record is read: the
    /// root's point, the record envelopes, the claim ages, the time.
    #[allow(clippy::type_complexity, reason = "the parts as they come")]
    pub fn parts(b: &[u8]) -> Result<(Vec<u8>, Vec<Vec<u8>>, Vec<(RecordId, u64)>, u64), Rule> {
        let v = cbor::decode(b)?;
        crate::msg::check_map(&crate::msg::tables::WELCOME, &v)?;
        let root = crate::format::Key::from_value(v.get(1).ok_or(RULE_ROOT)?).map_err(|_| RULE_ROOT)?;
        if root.alg != Alg::Es256 || root.check().is_err() {
            return Err(RULE_ROOT);
        }
        let envs = v.get(2).and_then(Value::as_array).ok_or(RULE_SHAPE)?.iter().map(Value::encode).collect();
        let mut ages = Vec::new();
        if let Some(a) = v.get(3) {
            for e in a.as_array().ok_or(RULE_SHAPE)? {
                let pair = e.as_array().ok_or(RULE_SHAPE)?;
                let (Some(id), Some(ms)) = (
                    pair.first().and_then(Value::as_bytes).and_then(|b| <[u8; 32]>::try_from(b).ok()),
                    pair.get(1).and_then(Value::as_uint),
                ) else {
                    return Err(RULE_SHAPE);
                };
                ages.push((RecordId(id), ms));
            }
            // One age per claim: the IDs rise.
            if ages.windows(2).any(|w| w.first().map(|a| a.0) >= w.last().map(|a| a.0)) {
                return Err(RULE_AGES);
            }
        }
        let time = v.get(5).and_then(Value::as_uint).ok_or(RULE_SHAPE)?;
        Ok((root.public.to_vec(), envs, ages, time))
    }

    /// Reads a Welcome: its fields, each record read with the records'
    /// reader (signatures are checked by [`Welcome::check`]).
    pub fn decode(b: &[u8]) -> Result<Welcome, Rule> {
        let (root, envs, claim_ages, time_ms) = Welcome::parts(b)?;
        let records = envs.iter().map(|e| Record::decode(e).map_err(|_| RULE_RECORD)).collect::<Result<Vec<_>, _>>()?;
        let v = cbor::decode(b)?;
        let list = |k: u16| -> Result<Vec<Vec<u8>>, Rule> {
            match v.get(k) {
                None => Ok(Vec::new()),
                Some(a) => Ok(a.as_array().ok_or(RULE_SHAPE)?.iter().map(Value::encode).collect()),
            }
        };
        let grant = match v.get(6) {
            None => None,
            Some(g) if g.as_map().is_some() => Some(g.encode()),
            Some(_) => return Err(RULE_SHAPE),
        };
        let counted = match v.get(8) {
            None => Vec::new(),
            Some(a) => a
                .as_array()
                .ok_or(RULE_SHAPE)?
                .iter()
                .map(|x| x.as_bytes().and_then(|b| <[u8; 32]>::try_from(b).ok()).map(RecordId).ok_or(RULE_SHAPE))
                .collect::<Result<Vec<_>, _>>()?,
        };
        Ok(Welcome { root, records, claim_ages, keys: list(4)?, time_ms, grant, credentials: list(7)?, counted })
    }

    /// The joiner's checks. `group` is the group ID the code exchange gave
    /// (`ADb` 1), `admitter` the key the TLS handshake proved, `own` the
    /// joiner's member key. Returns the joiner's record set, its state and
    /// the claims' held times, which it keeps as its own (A-69).
    ///
    /// `guarded`: the joiner is a guarded leaf (A-50). It takes only a record
    /// the root signed itself, and no claim its admitter counted.
    pub fn check(
        &self,
        group: &GroupId,
        admitter: &[u8; 65],
        own: &[u8; 65],
        guarded: bool,
    ) -> Result<(RecordSet, State, BTreeMap<RecordId, u64>), Refusal> {
        let root = Key::es256(self.root.clone());
        if root.check().is_err() {
            return Err(Refusal::Damaged);
        }
        if root.device_id().0 != group.0 {
            return Err(Refusal::OtherGroup);
        }
        if guarded && !self.counted.is_empty() {
            return Err(Refusal::Takeover);
        }
        // The counted claims and the claim ages name only claims among the
        // Welcome's records.
        let claims: BTreeSet<RecordId> =
            self.records.iter().filter(|r| matches!(r.body().kind, Kind::Claim { .. })).map(Record::id).collect();
        if self.counted.iter().chain(self.claim_ages.iter().map(|(id, _)| id)).any(|id| !claims.contains(id)) {
            return Err(Refusal::Damaged);
        }
        let mut set = RecordSet::new(root);
        set.insert_all(self.records.iter().cloned());
        let held: BTreeMap<RecordId, u64> = self.claim_ages.iter().copied().collect();
        // A takeover the admitter counted is final for the joiner too, once
        // the Welcome's records and its own ages put it in effect: its
        // signer may take over, its key is not void, nobody cancelled it,
        // and it waited the root's delay.
        if !self.counted.is_empty() {
            let plain = set.state(&held);
            let stands =
                |id: &RecordId| plain.claims.iter().any(|c| c.record == *id && c.state == ClaimState::Effective);
            if !self.counted.iter().all(stands) {
                return Err(Refusal::Takeover);
            }
        }
        set.remember_counted(self.counted.iter().copied());
        let state = set.state(&held);
        if state.owner_split {
            return Err(Refusal::Takeover);
        }
        let own_key = Key::es256(own.to_vec());
        let me = own_key.hash();
        if state.device_by_key(&me).is_none() {
            return Err(Refusal::NotAdmitted);
        }
        // The key that signed my counting record.
        let signer = set
            .in_dependency_order()
            .into_iter()
            .filter(|r| state.counting.contains(&r.id()))
            .find_map(|r| match &r.body().kind {
                Kind::Device(d) if d.key.hash() == me => Some(r.body().signer),
                _ => None,
            })
            .ok_or(Refusal::NotAdmitted)?;
        let adm = state.device_by_key(&Key::es256(admitter.to_vec()).hash()).ok_or(Refusal::NotAdmitter)?;
        if adm.frozen {
            return Err(Refusal::NotAdmitter);
        }
        let by_root = state.is_root(&signer) && state.root_device == Some(adm.id);
        let by_admin = adm.admin == Some(signer) && adm.powers & POWER_ADMIT != 0;
        if !(by_root || by_admin) || (guarded && !by_root) {
            return Err(Refusal::NotAdmitter);
        }
        Ok((set, state, held))
    }
}
