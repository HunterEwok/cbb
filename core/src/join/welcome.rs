// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The Welcome (format 11.2): what an admitter sends the joiner once CPace
//! confirmed, and the joiner's checks of it (design-no-certificates
//! section 4). No certificate: the group's first root key and its recovery
//! key, which give the Group ID together (rule 33), and records in
//! dependency order. What it must carry: the recovery records and the
//! newest one's list, the new roots' first checkpoints, the removals that
//! count, the admitter's records with its rights and the joiner's own
//! record; a set whose must-carry does not fit the budget gives no Welcome
//! (`TooLarge`), nothing of it is cut. Each of them comes with its chain
//! down to seq 1 or to the counting checkpoint that names it, which comes
//! too. Then the others while the budget holds them.
//!
//! The joiner checks: the Group ID from the code exchange is the one the
//! two keys give, so no admitter can pin a false recovery key; the records
//! verify up to those keys; its own record carries its own key; the
//! admitter's key from TLS stands in the records and the key that signed
//! the joiner's record is the root's or that admitter's admin key with
//! `admit`; the path of roots comes from the recovery records, never from
//! the admitter's word.

use alloc::collections::BTreeSet;
use alloc::vec::Vec;

use crate::format::{Alg, GroupId, Rule, Value, cbor};
use crate::records::body::{Kind, POWER_ADMIT};
use crate::records::set::RecordSet;
use crate::records::{Key, KeyHash, Record, RecordId, Recovery, State, group_id};

use super::intro::chain;

/// What a Welcome may take of a pairing frame (1 MiB) for its records and
/// its list: the rest is left for its keys, the grant, the credentials and
/// the padding.
pub const RECORDS_BUDGET: usize = crate::format::frame::LIMIT_PAIRING - 64 * 1024;

/// The set's must-carry (its recovery records and list, first checkpoints,
/// counting removals and the two devices' records) passes RECORDS_BUDGET:
/// no Welcome is built.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct TooLarge;

pub const RULE_SHAPE: Rule = Rule::field("welcome/shape");
pub const RULE_ROOT: Rule = Rule::field("welcome/root");
pub const RULE_RECOVERY: Rule = Rule::field("welcome/recovery");
/// The recovery key's second half is missing or not a 32-byte SLH-DSA key.
pub const RULE_RECOVERY2: Rule = Rule::field("welcome/recovery2");
pub const RULE_LIST: Rule = Rule::field("welcome/list");
/// A record of the Welcome that does not read (`Record::decode`).
pub const RULE_RECORD: Rule = Rule::field("welcome/record");
/// Fields 3 (claim ages) and 8 (counted claims) of earlier drafts.
pub const RULE_RETIRED: Rule = Rule::field("welcome/retired");

/// The Welcome.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct Welcome {
    /// The group's first root key, its point.
    pub root: Vec<u8>,
    pub records: Vec<Record>,
    /// Statements of the group's devices, as envelopes.
    pub keys: Vec<Vec<u8>>,
    /// The admitter's clock, for a joiner without one (A-47).
    pub time_ms: u64,
    /// A leaf's first grant: the map of message `grant`'s fields 2–5, as
    /// its encoding.
    pub grant: Option<Vec<u8>>,
    /// The current period's server credentials, as envelopes.
    pub credentials: Vec<Vec<u8>>,
    /// The group's recovery key: K1's point.
    pub recovery: Vec<u8>,
    /// The recovery key's second half, K2: its 32 bytes (E-6).
    pub recovery2: Vec<u8>,
    /// The newest recovery record's list, as its encoding.
    pub list: Option<Vec<u8>>,
}

/// How the joiner took its Welcome.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Joining {
    Ordinary,
    /// A guarded leaf (A-50): it takes only a record the root signed
    /// itself.
    Guarded,
}

/// What binds the member to the joiner in this pairing, which the joiner
/// shows to take a Welcome.
#[derive(Clone, Copy, Debug)]
pub enum Way<'a> {
    /// An invitation: its secret, CPace's password, binds the member.
    Invited(&'a super::invitation::Invitation),
    /// At home without an invitation nothing secret binds the member: only
    /// the person's "they match" at the joiner, in this session
    /// (`invitation::JoinerAttempts::answered`). Without it, or after "they
    /// do not match", there is no Welcome to take, and the session ends.
    Home(&'a super::invitation::Matched),
}

/// Why the joiner does not take a Welcome.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Refusal {
    /// The two keys' Group ID is not the one the code exchange gave.
    OtherGroup,
    /// The records do not hold the joiner's own record with its own key.
    NotAdmitted,
    /// The admitter's key is not a device of the group, or the key that
    /// signed the joiner's record is neither the root's nor the admitter's
    /// admin key with `admit`.
    NotAdmitter,
    /// The Welcome is damaged.
    Damaged,
    /// At home without an invitation, the person's "they match" is of
    /// another session than the one with the joiner's own key.
    Unconfirmed,
    /// The group is stopped (`State::stopped`): two recovery records at
    /// one seq, one this version cannot read, or two histories of the
    /// current root. An admitter in such a group does not admit, and a
    /// joiner does not join it.
    Stopped,
}

impl Welcome {
    /// The Welcome an admitter sends: its set already holds the joiner's
    /// record. `admitter` and `joiner` are the member keys' hashes.
    pub fn build(
        set: &RecordSet,
        state: &State,
        admitter: &KeyHash,
        joiner: &KeyHash,
        time_ms: u64,
    ) -> Result<Welcome, TooLarge> {
        Self::build_within(set, state, admitter, joiner, time_ms, RECORDS_BUDGET)
    }

    /// build under a budget of budget bytes for the records and the list.
    pub(crate) fn build_within(
        set: &RecordSet,
        state: &State,
        admitter: &KeyHash,
        joiner: &KeyHash,
        time_ms: u64,
        budget: usize,
    ) -> Result<Welcome, TooLarge> {
        let list = state.cut.as_ref().and_then(|c| set.list(&c.list)).map(<[u8]>::to_vec);
        let order = set.in_dependency_order();
        // What it must carry: the recovery records (in `chain`), the first
        // checkpoints, the counting removals, the two devices' records and
        // the counting checkpoints.
        let mut must: BTreeSet<RecordId> = chain(set, state, admitter);
        must.extend(chain(set, state, joiner));
        must.extend(
            set.firsts()
                .keys()
                .copied()
                .filter(|id| set.get(id).is_some_and(|r| crate::records::eval::is_first(set.firsts(), r))),
        );
        must.extend(
            order
                .iter()
                .filter(|r| state.counting.contains(&r.id()) && matches!(r.body().kind, Kind::Revoke(_)))
                .map(|r| r.id()),
        );
        // A record counts by its chain: each must-carry record's prev down
        // to seq 1 or to what a counting checkpoint names, which goes too.
        let mut anchors: BTreeSet<RecordId> = BTreeSet::new();
        for id in &state.checkpoints {
            if let Some(Kind::Checkpoint { heads, keep }) = set.get(id).map(|r| &r.body().kind) {
                must.insert(*id);
                anchors.extend(heads.iter().map(|h| h.id).chain(keep.iter().copied()));
            }
        }
        // A removal counts by itself (`eval::Evaluation::wholes`).
        let walks: Vec<RecordId> = must
            .iter()
            .copied()
            .filter(|id| set.get(id).is_some_and(|r| !matches!(r.body().kind, Kind::Revoke(_))))
            .collect();
        for id in walks {
            let mut at = set.get(&id).and_then(|r| r.body().prev);
            while let Some(p) = at {
                if !must.insert(p) && anchors.contains(&p) {
                    break;
                }
                let Some(r) = set.get(&p) else {
                    must.remove(&p);
                    break;
                };
                if anchors.contains(&p) {
                    break;
                }
                at = r.body().prev;
            }
        }
        let mut used: usize = order
            .iter()
            .filter(|r| must.contains(&r.id()))
            .map(|r| r.size())
            .fold(list.as_ref().map_or(0, Vec::len), usize::saturating_add);
        if used > budget {
            return Err(TooLarge);
        }
        // Then the rest, while it fits.
        let mut take = must;
        for r in order.iter().filter(|r| !take.contains(&r.id())).collect::<Vec<_>>() {
            let n = used.saturating_add(r.size());
            if n > budget {
                continue;
            }
            used = n;
            take.insert(r.id());
        }
        let records: Vec<Record> = order.iter().filter(|r| take.contains(&r.id())).map(|r| (*r).clone()).collect();
        Ok(Welcome {
            root: set.root().public.clone(),
            records,
            keys: Vec::new(),
            time_ms,
            grant: None,
            credentials: Vec::new(),
            recovery: set.recovery().k1.public.clone(),
            recovery2: set.recovery().k2.public.clone(),
            list,
        })
    }

    /// The Welcome's encoding (the map of format 11.2).
    pub fn encode(&self) -> Vec<u8> {
        let envs: Vec<Vec<u8>> = self.records.iter().map(Record::envelope).collect();
        fn values(v: &[Vec<u8>]) -> Option<Vec<Value<'_>>> {
            v.iter().map(|e| cbor::decode(e).ok()).collect()
        }
        let es256 = |p: &[u8]| -> Vec<u8> {
            Value::Array(alloc::vec![Value::Uint(Alg::Es256.number()), Value::Bytes(p)]).encode()
        };
        let (root, recovery) = (es256(&self.root), es256(&self.recovery));
        let mut m: Vec<(u16, Value<'_>)> = Vec::new();
        m.push((1, cbor::decode(&root).unwrap_or(Value::Uint(0))));
        m.push((2, Value::Array(values(&envs).unwrap_or_default())));
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
        m.push((9, cbor::decode(&recovery).unwrap_or(Value::Uint(0))));
        if let Some(l) = &self.list {
            m.push((10, Value::Bytes(l)));
        }
        m.push((11, Value::Array(alloc::vec![Value::Uint(Alg::SlhDsa.number()), Value::Bytes(&self.recovery2)])));
        Value::Map(m).encode()
    }

    /// The parts of an encoded Welcome before each record is read: the
    /// root's point, the record envelopes, the time, the recovery key's
    /// point and its second half's 32 bytes.
    #[allow(clippy::type_complexity, reason = "the parts as they come")]
    pub fn parts(b: &[u8]) -> Result<(Vec<u8>, Vec<Vec<u8>>, u64, Vec<u8>, Vec<u8>), Rule> {
        let v = cbor::decode(b)?;
        crate::msg::check_map(&crate::msg::tables::WELCOME, &v)?;
        let key = |n: u16, alg: Alg, rule: Rule| -> Result<Vec<u8>, Rule> {
            let k = crate::format::Key::from_value(v.get(n).ok_or(rule)?).map_err(|_| rule)?;
            if k.alg != alg || k.check().is_err() {
                return Err(rule);
            }
            Ok(k.public.to_vec())
        };
        let root = key(1, Alg::Es256, RULE_ROOT)?;
        let recovery = key(9, Alg::Es256, RULE_RECOVERY)?;
        if root == recovery {
            return Err(RULE_RECOVERY);
        }
        let recovery2 = key(11, Alg::SlhDsa, RULE_RECOVERY2)?;
        let envs = v.get(2).and_then(Value::as_array).ok_or(RULE_SHAPE)?.iter().map(Value::encode).collect();
        let time = v.get(5).and_then(Value::as_uint).ok_or(RULE_SHAPE)?;
        Ok((root, envs, time, recovery, recovery2))
    }

    /// Reads a Welcome: its fields, each record read with the records'
    /// reader (signatures are checked by [`Welcome::check`]).
    pub fn decode(b: &[u8]) -> Result<Welcome, Rule> {
        let (root, envs, time_ms, recovery, recovery2) = Welcome::parts(b)?;
        let records = envs.iter().map(|e| Record::decode(e).map_err(|_| RULE_RECORD)).collect::<Result<Vec<_>, _>>()?;
        let v = cbor::decode(b)?;
        let list_of = |k: u16| -> Result<Vec<Vec<u8>>, Rule> {
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
        let list = match v.get(10) {
            None => None,
            // Its hash is checked against the recovery record that names it.
            Some(l) => Some(l.as_bytes().ok_or(RULE_LIST)?.to_vec()),
        };
        Ok(Welcome {
            root,
            records,
            keys: list_of(4)?,
            time_ms,
            grant,
            credentials: list_of(7)?,
            recovery,
            recovery2,
            list,
        })
    }

    /// The joiner's checks. `group` is the group ID the code exchange gave
    /// (`ADb` 1), `admitter` the key the TLS handshake proved, `own` the
    /// joiner's member key, `way` what binds the member to the joiner.
    /// Returns the joiner's record set and its state. A guarded leaf
    /// (A-50) takes only a record the root signed itself.
    pub fn check(
        &self,
        group: &GroupId,
        admitter: &[u8; 65],
        own: &[u8; 65],
        joining: Joining,
        way: Way<'_>,
    ) -> Result<(RecordSet, State), Refusal> {
        if let Way::Home(m) = way
            && m.local() != Key::es256(own.to_vec()).device_id()
        {
            return Err(Refusal::Unconfirmed);
        }
        let root = Key::es256(self.root.clone());
        let k2 = Key { alg: crate::records::key::ALG_SLH_DSA, public: self.recovery2.clone() };
        let Some(recovery) = Recovery::new(Key::es256(self.recovery.clone()), k2) else {
            return Err(Refusal::Damaged);
        };
        if root.check().is_err() {
            return Err(Refusal::Damaged);
        }
        if group_id(&root, &recovery).0 != group.0 {
            return Err(Refusal::OtherGroup);
        }
        let mut set = RecordSet::new(root, recovery);
        // The heads and their list first, so that the new root's records
        // count when they come.
        set.insert_all(self.records.iter().filter(|r| matches!(r.body().kind, Kind::Recovery { .. })).cloned());
        if let Some(l) = &self.list {
            set.insert_list(l).map_err(|_| Refusal::Damaged)?;
        }
        set.insert_all(self.records.iter().cloned());
        let state = set.state();
        if state.stopped() {
            return Err(Refusal::Stopped);
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
        if !(by_root || by_admin) || (joining == Joining::Guarded && !by_root) {
            return Err(Refusal::NotAdmitter);
        }
        Ok((set, state))
    }
}
