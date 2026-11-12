// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! Whether a reader writes a copy as new, decided from signed fields only.
//!
//! A copy's `age_ms` is outside the signature: it grows on the way, and a
//! member in between could set it back. So a reader never takes it alone:
//!
//! - With a clock, the age it uses is at least the time since the copy's
//!   signed wall time, less an allowance for the origin's clock being ahead
//!   ([`effective_age`]). A copy held back and sent again later is as old as
//!   it really is.
//! - It writes no copy whose signed time is not after the newest copy it
//!   wrote (A-61), so an old copy is never written over a newer one; a
//!   device without a clock decides by this alone.
//! - A secret it has seen once (opened, written or not) is never written
//!   again, by its ID or, past the list's length, by its time.
//!
//! [`Marks`] holds what it saw; the device saves it ([`Marks::encode`]) and
//! reads it back after a restart, so a restart forgets nothing of it.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use crate::format::Rule;
use crate::format::cbor::{self, Value};
use crate::hlc::Timestamp;

/// How far ahead of the reader's clock an origin's clock may be: the
/// allowance taken off the time since a copy's signed wall time.
pub const ALLOWANCE_MS: u64 = 300_000;

/// The most secrets [`Marks`] lists by ID; older ones are covered by its
/// floor.
pub const MAX_SECRETS: usize = 1024;

/// What a reader saw: the newest copy it wrote, and the secrets it saw.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct Marks {
    /// The signed time of the newest copy written here.
    pub written: Timestamp,
    /// Secrets seen, by ID, with their signed times.
    pub secrets: BTreeMap<[u8; 16], Timestamp>,
    /// Every secret at or before this time counts as seen: the newest of
    /// those that fell off the list.
    pub floor: Timestamp,
}

/// The verdict on a copy that opened.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Fresh {
    /// It may be written, if the rule of incoming copies (`crate::rule`)
    /// says so with the age given.
    New { age_ms: u64 },
    /// Its signed time is not after the newest copy written here.
    Behind,
    /// A secret seen before: never written again.
    SeenSecret,
}

/// The age a reader uses for a copy: the larger of its `age_ms` and the
/// time since its signed wall time on the reader's clock, less
/// [`ALLOWANCE_MS`]. Without a clock (`now_ms` None) only `age_ms`.
pub fn effective_age(age_ms: u64, signed: Timestamp, now_ms: Option<u64>) -> u64 {
    let since = now_ms
        .zip(u64::try_from(signed.wall).ok())
        .map_or(0, |(now, wall)| now.saturating_sub(wall).saturating_sub(ALLOWANCE_MS));
    age_ms.max(since)
}

fn ts_value(t: &Timestamp) -> Value<'static> {
    Value::Array(alloc::vec![Value::Uint(u64::try_from(t.wall).unwrap_or(0)), Value::Uint(u64::from(t.logical))])
}

fn ts_read(v: &Value<'_>) -> Option<Timestamp> {
    match v.as_array() {
        Some([Value::Uint(w), Value::Uint(l)]) => {
            Some(Timestamp { wall: i64::try_from(*w).ok()?, logical: u32::try_from(*l).ok()? })
        }
        _ => None,
    }
}

impl Marks {
    /// Judges a copy that opened here, with its ID, signed time, `age_ms`
    /// and whether it is a secret, on the reader's clock (None without one).
    /// A secret is noted as seen whatever the verdict.
    pub fn judge(&mut self, id: &[u8; 16], signed: Timestamp, age_ms: u64, secret: bool, now_ms: Option<u64>) -> Fresh {
        let seen = secret && (self.secrets.contains_key(id) || signed <= self.floor);
        if secret {
            self.see_secret(id, signed);
        }
        if seen {
            Fresh::SeenSecret
        } else if signed <= self.written {
            Fresh::Behind
        } else {
            Fresh::New { age_ms: effective_age(age_ms, signed, now_ms) }
        }
    }

    /// Notes that a copy with this signed time was written.
    pub fn wrote(&mut self, signed: Timestamp) {
        self.written = self.written.max(signed);
    }

    fn see_secret(&mut self, id: &[u8; 16], t: Timestamp) {
        self.secrets.insert(*id, t);
        while self.secrets.len() > MAX_SECRETS {
            let Some((oldest, ot)) = self.secrets.iter().min_by_key(|(k, v)| (**v, **k)).map(|(k, v)| (*k, *v)) else {
                break;
            };
            self.secrets.remove(&oldest);
            self.floor = self.floor.max(ot);
        }
    }

    /// The marks as bytes to save: a map in the profile, 1 `written`,
    /// 2 `floor`, 3 the secrets `[ID, time]` sorted by ID.
    pub fn encode(&self) -> Vec<u8> {
        let secrets: Vec<Value<'_>> =
            self.secrets.iter().map(|(id, t)| Value::Array(alloc::vec![Value::Bytes(id), ts_value(t)])).collect();
        let mut m = alloc::vec![(1, ts_value(&self.written)), (2, ts_value(&self.floor))];
        if !secrets.is_empty() {
            m.push((3, Value::Array(secrets)));
        }
        Value::Map(m).encode()
    }

    /// Reads marks saved by [`Marks::encode`].
    pub fn decode(b: &[u8]) -> Result<Marks, Rule> {
        let bad = Rule::field("marks/shape");
        let v = cbor::decode(b)?;
        let written = v.get(1).and_then(ts_read).ok_or(bad)?;
        let floor = v.get(2).and_then(ts_read).ok_or(bad)?;
        let mut secrets = BTreeMap::new();
        for e in v.get(3).and_then(Value::as_array).unwrap_or(&[]) {
            match e.as_array() {
                Some([Value::Bytes(id), t]) => {
                    let id: [u8; 16] = (*id).try_into().map_err(|_| bad)?;
                    secrets.insert(id, ts_read(t).ok_or(bad)?);
                }
                _ => return Err(bad),
            }
        }
        Ok(Marks { written, secrets, floor })
    }
}
