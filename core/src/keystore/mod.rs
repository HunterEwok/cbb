// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! A device's own keys, behind one interface for every platform (A-11):
//! the member key that signs (in the Secure Enclave, a TPM, the Keystore or
//! a file, as the platform has it), and the sealing secrets of its keys
//! statements, one per epoch.
//!
//! The sealing key changes once a week (A-8): the device makes a new secret,
//! signs a statement of its new epoch with its own member key (nobody else
//! can sign it, design-records-v3 rule 4), and keeps the previous secret one
//! more week, so that a copy sealed to it a little late still opens; then
//! it erases it. A copy sealed to an epoch it no longer holds is sealed
//! again on request (`crate::copies::reseal`).
//!
//! The weeks are counted on the device's own clock, or on a leaf's running
//! time; a clock that goes back makes no new epoch and erases nothing.
//!
//! A-66, reusing a key set for frequent messages, has its room in the format
//! (the copy header's field 7 `reuse`, refused in 0.6); nothing here uses
//! it yet.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use crate::error::{Error, Result};
use crate::format::Rule;
use crate::format::cbor::Value;
use crate::format::envelope::Envelope;
use crate::identity::ExternalKey;
use crate::records::key::{ALG_XWING, GroupId, Key, KeyHash, XWING_PUBLIC};
use crate::records::statement::{Body, MAX_STATEMENT_BODY, Statement};

/// A week, in milliseconds: how long an epoch is the newest, and how long
/// the previous one is kept after it.
pub const WEEK_MS: u64 = 604_800_000;

/// One epoch a device holds: its number, when it was made (on the device's
/// clock or running time), and its statement's envelope.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Epoch {
    pub epoch: u64,
    pub made_ms: u64,
    pub statement: Vec<u8>,
    /// On the newest epoch of a device with a wall clock: the first time
    /// [`rotate`] saw the clock more than [`AHEAD_MS`] behind `made_ms`,
    /// while it stays behind; None otherwise.
    pub behind_since_ms: Option<u64>,
}

/// Where a device keeps its keys. A platform implements it over its own
/// store; the core decides when epochs change and what is erased.
pub trait KeyStore {
    /// The device's member key.
    fn member(&self) -> &dyn ExternalKey;
    /// The sealing secret of an epoch the device still holds.
    fn sealing(&self, epoch: u64) -> Option<[u8; 32]>;
    /// The epochs it holds, in any order.
    fn epochs(&self) -> Vec<Epoch>;
    /// Keeps a new epoch with its secret.
    fn put(&mut self, epoch: Epoch, secret: [u8; 32]) -> Result<()>;
    /// Erases an epoch's secret and statement for good.
    fn erase(&mut self, epoch: u64) -> Result<()>;
}

/// How far ahead of now the newest epoch's time may be before [`rotate`]
/// takes it for a clock that was wrong and makes a new epoch: one day.
pub const AHEAD_MS: u64 = 86_400_000;

/// What [`rotate`] did.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct Rotated {
    /// The new epoch's statement envelope, to pass on in message `keys`.
    pub made: Option<Vec<u8>>,
    /// The epochs erased.
    pub erased: Vec<u64>,
}

/// Keeps the device's sealing keys current at time now_ms (its weeks: the
/// wall clock, or a leaf's running time): a first epoch
/// when it has none, a new one when the newest is a week old, and erases
/// every epoch but the newest once the newest has been the newest for a
/// week (the previous one is kept that long). Time going back a little
/// changes nothing.
///
/// A newest epoch made more than [`AHEAD_MS`] ahead of now is either a
/// clock that is wrong now (a default date after a restart, a clock moved
/// back) or one that was wrong when the epoch was made. With a wall clock
/// the call makes nothing and erases nothing then: it notes when it first
/// saw the clock behind, and only once the clock has stayed behind a whole
/// week by its own count is the epoch due, so a clock once far ahead never
/// stops the weekly change, and a clock moved back and forth makes no
/// more than one epoch a week. A leaf on its running time, which goes back
/// only at a restart, makes its new epoch at once: the epoch is then made at
/// the start of the run, and the next restarts do not rotate.
///
/// The caller should call it once the device's clock is set.
///
/// A new statement's `time_ms` is `wall_ms`, the device's wall clock, and
/// only that: a device without one (a leaf counting on its running time)
/// passes None and writes no time, so its statement has no age.
pub fn rotate(store: &mut dyn KeyStore, group: &GroupId, now_ms: u64, wall_ms: Option<u64>) -> Result<Rotated> {
    let mut out = Rotated::default();
    let mut epochs = store.epochs();
    epochs.sort_by_key(|e| e.epoch);
    let newest = epochs.last().map(|e| (e.epoch, e.made_ms));
    let due = match epochs.last() {
        None => true,
        Some(e) if e.made_ms > now_ms.saturating_add(AHEAD_MS) => {
            if wall_ms.is_none() {
                true
            } else {
                // The clock is behind the newest epoch: count a week from
                // the first call that saw it so (or from now, if the clock
                // went back further since).
                let since = e.behind_since_ms.filter(|t| *t <= now_ms);
                match since {
                    Some(t) if now_ms >= t.saturating_add(WEEK_MS) => true,
                    Some(_) => return Ok(out),
                    None => {
                        mark_behind(store, e, Some(now_ms))?;
                        return Ok(out);
                    }
                }
            }
        }
        Some(e) => {
            if e.behind_since_ms.is_some() {
                mark_behind(store, e, None)?;
            }
            now_ms >= e.made_ms.saturating_add(WEEK_MS)
        }
    };
    let mut newest_made = newest.map(|(_, m)| m);
    if due {
        let epoch = newest.map_or(Some(1), |(e, _)| e.checked_add(1)).ok_or_else(|| Error::msg("no epoch is left"))?;
        let secret = crate::seal::generate_secret()?;
        let seal = Key { alg: ALG_XWING, public: crate::seal::public_key(&secret)? };
        let signer = Key::es256(store.member().public()).hash();
        let body = Body { group: *group, signer, epoch, time_ms: wall_ms.unwrap_or(0), seal, held: false };
        let st = Statement::sign(body, store.member())?;
        let env = statement_envelope(&st);
        store.put(Epoch { epoch, made_ms: now_ms, statement: env.clone(), behind_since_ms: None }, secret)?;
        out.made = Some(env);
        newest_made = Some(now_ms);
        epochs.push(Epoch { epoch, made_ms: now_ms, statement: Vec::new(), behind_since_ms: None });
    }
    let last = epochs.last().map(|e| e.epoch);
    if let (Some(made), Some(last)) = (newest_made, last) {
        let keep_prev = now_ms < made.saturating_add(WEEK_MS);
        for e in &epochs {
            if e.epoch == last || (keep_prev && e.epoch.checked_add(1) == Some(last)) {
                continue;
            }
            store.erase(e.epoch)?;
            out.erased.push(e.epoch);
        }
    }
    Ok(out)
}

/// Keeps an epoch again with its note of a clock behind it changed.
fn mark_behind(store: &mut dyn KeyStore, e: &Epoch, since: Option<u64>) -> Result<()> {
    let secret = store.sealing(e.epoch).ok_or_else(|| Error::msg("an epoch without its secret"))?;
    store.put(Epoch { behind_since_ms: since, ..e.clone() }, secret)
}

/// A statement's envelope `[body, sig]`.
pub fn statement_envelope(st: &Statement) -> Vec<u8> {
    st.envelope()
}

/// A statement read from its envelope.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum ReadStatement {
    /// One this version applies, its signature still to check against the
    /// device's member key (`records::statement::choose`).
    Take(Statement),
    /// One with a type, a critical field or a key algorithm this version
    /// does not know, or a second signer: kept and passed on, never counted
    /// (format section 3.3). Its ID and envelope.
    Held { id: [u8; 32], envelope: Vec<u8> },
}

/// A statement's type of 0.6.
const STATEMENT_FIELDS: [u16; 6] = [1, 2, 3, 4, 6, 10];

/// Reads a keys statement from its envelope (format section 5): its size
/// (2 KiB of body), the envelope and the profile, the fields' rows, and the
/// signature's form. The signature is checked with the device's member key
/// once the reader knows the device.
pub fn read_statement(envelope: &[u8]) -> core::result::Result<ReadStatement, Rule> {
    let e = Envelope::parse_limited(envelope, MAX_STATEMENT_BODY)?;
    let m = &e.map;
    crate::format::sig::check_form(e.sig)?;
    let bytes = |f, n, rule| m.get(f).and_then(Value::as_bytes).filter(|b| b.len() == n).ok_or(rule);
    // What every type has decides first: a later type is held whatever its
    // other fields are.
    let typ = m.get(1).and_then(Value::as_uint).filter(|t| *t >= 1).ok_or(Rule::field("statements/type"))?;
    let group =
        GroupId::from_slice(bytes(2, 16, Rule::field("statements/group"))?).ok_or(Rule::field("statements/group"))?;
    let signer =
        KeyHash::from_slice(bytes(3, 32, Rule::field("statements/signer"))?).ok_or(Rule::field("statements/signer"))?;
    let epoch = m.get(4).and_then(Value::as_uint).filter(|e| *e >= 1).ok_or(Rule::field("statements/epoch"))?;
    let unknown_field = m.as_map().unwrap_or(&[]).iter().any(|(k, _)| *k < 256 && !STATEMENT_FIELDS.contains(k));
    let held = || ReadStatement::Held { id: e.id(), envelope: envelope.to_vec() };
    if typ != 1 || unknown_field || e.sig2.is_some() {
        return Ok(held());
    }
    let time_ms = match m.get(6) {
        None => 0,
        Some(Value::Uint(0)) => return Err(Rule::FORM_DEFAULT),
        Some(t) => t.as_uint().ok_or(Rule::field("statements/time"))?,
    };
    let seal = crate::format::Key::from_value(m.get(10).ok_or(Rule::field("statements/seal"))?)?;
    // A sealing algorithm of a later version is held; one this version
    // knows that is not a sealing key (ES256, X25519) is refused below.
    if matches!(seal.alg, crate::format::Alg::Unknown(_)) {
        return Ok(held());
    }
    seal.check()?;
    if seal.alg != crate::format::Alg::XWing || seal.public.len() != XWING_PUBLIC {
        return Err(Rule::KEYS_XWING);
    }
    let body =
        Body { group, signer, epoch, time_ms, seal: Key { alg: ALG_XWING, public: seal.public.to_vec() }, held: false };
    Ok(ReadStatement::Take(Statement::from_read(e.body.to_vec(), e.sig.to_vec(), body)))
}

/// A key store in memory: for the tests and for a device that keeps its
/// secrets elsewhere itself.
pub struct MemoryStore<K: ExternalKey> {
    member: K,
    epochs: BTreeMap<u64, (Epoch, [u8; 32])>,
}

impl<K: ExternalKey> MemoryStore<K> {
    pub fn new(member: K) -> Self {
        MemoryStore { member, epochs: BTreeMap::new() }
    }
}

impl<K: ExternalKey> KeyStore for MemoryStore<K> {
    fn member(&self) -> &dyn ExternalKey {
        &self.member
    }
    fn sealing(&self, epoch: u64) -> Option<[u8; 32]> {
        self.epochs.get(&epoch).map(|(_, s)| *s)
    }
    fn epochs(&self) -> Vec<Epoch> {
        self.epochs.values().map(|(e, _)| e.clone()).collect()
    }
    fn put(&mut self, epoch: Epoch, secret: [u8; 32]) -> Result<()> {
        self.epochs.insert(epoch.epoch, (epoch, secret));
        Ok(())
    }
    fn erase(&mut self, epoch: u64) -> Result<()> {
        if let Some((_, s)) = self.epochs.get_mut(&epoch) {
            *s = [0; 32];
        }
        self.epochs.remove(&epoch);
        Ok(())
    }
}

#[cfg(test)]
mod tests;
