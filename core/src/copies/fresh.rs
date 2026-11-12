// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! Whether a reader writes a copy as new, decided from signed fields only.
//!
//! A copy's `age_ms` is outside the signature: it grows on the way, and a
//! member in between could set it back. So a reader never takes it alone:
//!
//! - With a clock, the age it uses is at least the time since the copy's
//!   signed wall time, less an allowance for the origin's clock being ahead
//!   ([`effective_age`]): [`ALLOWANCE_MS`], and at most a quarter of the
//!   content's lifetime when it has one. A copy held back and sent again
//!   later is as old as it really is.
//! - With a clock, a copy signed more than [`ALLOWANCE_MS`] ahead of it is
//!   refused ([`Fresh::Ahead`]): not written, and not taken as the newest.
//! - It writes no copy whose signed time is not after the newest copy it
//!   wrote (A-61), so an old copy is never written over a newer one; a
//!   device without a clock decides by this alone. The newest is kept for
//!   each origin, and only the origins the records still name and have not
//!   frozen count: a removed or frozen device's copy dated ahead stops no
//!   one.
//! - A secret it has seen once (opened, written or not) is never written
//!   again, by its origin and ID, or, past the list's length, by its time.
//!
//! [`Marks`] holds what it saw; the device saves it ([`Marks::encode`])
//! before it writes, and reads it back after a restart, so a restart
//! forgets nothing of it.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use crate::format::Rule;
use crate::format::cbor::{self, Value};
use crate::hlc::Timestamp;
use crate::records::eval::State;
use crate::records::key::DeviceId;

/// How far ahead of the reader's clock an origin's clock may be: the
/// allowance taken off the time since a copy's signed wall time, and the
/// most a copy may be signed ahead of the reader's clock.
pub const ALLOWANCE_MS: u64 = 300_000;

/// The most secrets [`Marks`] lists by ID; older ones are covered by its
/// floor.
pub const MAX_SECRETS: usize = 1024;

/// The most origins [`Marks`] keeps a newest time for.
pub const MAX_ORIGINS: usize = 1024;

/// What a reader saw: the newest copy it wrote from each origin, and the
/// secrets it saw.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct Marks {
    /// The signed time of the newest copy written here, by origin.
    pub written: BTreeMap<DeviceId, Timestamp>,
    /// Secrets seen, by origin and ID, with their signed times.
    pub secrets: BTreeMap<(DeviceId, [u8; 16]), Timestamp>,
    /// Every secret at or before this time counts as seen: the newest of
    /// those that fell off the list.
    pub floor: Timestamp,
}

/// A copy that opened, as the reader judges it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Seen {
    pub origin: DeviceId,
    pub id: [u8; 16],
    /// Its time on the origin's clock, inside the signature.
    pub signed: Timestamp,
    /// Its `age_ms`, outside the signature.
    pub age_ms: u64,
    pub secret: bool,
    /// The content's own lifetime, if it has one.
    pub ttl_ms: Option<u64>,
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
    /// Signed more than [`ALLOWANCE_MS`] ahead of this reader's clock, or
    /// at a time no clock reaches: not written, not taken as the newest.
    Ahead,
}

/// The allowance for a copy: [`ALLOWANCE_MS`], and at most a quarter of
/// its lifetime when it has one.
pub fn allowance(ttl_ms: Option<u64>) -> u64 {
    ttl_ms.map_or(ALLOWANCE_MS, |t| ALLOWANCE_MS.min(t / 4))
}

/// The age a reader uses for a copy: the larger of its `age_ms` and the
/// time since its signed wall time on the reader's clock, less the
/// [`allowance`]. Without a clock (`now_ms` None) only `age_ms`.
pub fn effective_age(age_ms: u64, signed: Timestamp, ttl_ms: Option<u64>, now_ms: Option<u64>) -> u64 {
    let since = now_ms
        .zip(u64::try_from(signed.wall).ok())
        .map_or(0, |(now, wall)| now.saturating_sub(wall).saturating_sub(allowance(ttl_ms)));
    age_ms.max(since)
}

fn ts_value(t: &Timestamp) -> Value<'static> {
    Value::Array(alloc::vec![Value::Uint(u64::try_from(t.wall).unwrap_or(0)), Value::Uint(u64::from(t.logical))])
}

fn ts_read(v: &Value<'_>) -> Option<Timestamp> {
    match v.as_array() {
        Some([Value::Uint(w), Value::Uint(l)]) => {
            let t = Timestamp { wall: i64::try_from(*w).ok()?, logical: u32::try_from(*l).ok()? };
            t.valid().then_some(t)
        }
        _ => None,
    }
}

fn standing(state: &State, origin: &DeviceId) -> bool {
    state.device(origin).is_some_and(|d| !d.frozen)
}

impl Marks {
    /// The newest copy written here from the origins that still stand.
    pub fn newest(&self, state: &State) -> Timestamp {
        self.written.iter().filter(|(o, _)| standing(state, o)).map(|(_, t)| *t).max().unwrap_or_default()
    }

    /// Judges a copy that opened here, on the reader's clock (None without
    /// one) and its records. A secret is noted as seen whatever the verdict,
    /// unless it is [`Fresh::Ahead`].
    pub fn judge(&mut self, s: &Seen, now_ms: Option<u64>, state: &State) -> Fresh {
        let ahead = match (now_ms, u64::try_from(s.signed.wall)) {
            _ if !s.signed.valid() => true,
            (Some(now), Ok(wall)) => wall > now.saturating_add(ALLOWANCE_MS),
            _ => false,
        };
        if ahead {
            return Fresh::Ahead;
        }
        let key = (s.origin, s.id);
        let seen = s.secret && (self.secrets.contains_key(&key) || s.signed <= self.floor);
        if s.secret {
            self.see_secret(key, s.signed);
        }
        if seen {
            Fresh::SeenSecret
        } else if s.signed <= self.newest(state) {
            Fresh::Behind
        } else {
            Fresh::New { age_ms: effective_age(s.age_ms, s.signed, s.ttl_ms, now_ms) }
        }
    }

    /// Notes that a copy from this origin with this signed time was
    /// written. Origins the records no longer name are forgotten.
    pub fn wrote(&mut self, origin: &DeviceId, signed: Timestamp, state: &State) {
        self.written.retain(|o, _| state.device(o).is_some());
        let t = self.written.entry(*origin).or_default();
        *t = (*t).max(signed);
        while self.written.len() > MAX_ORIGINS {
            let Some(oldest) = self.written.iter().min_by_key(|(o, t)| (**t, **o)).map(|(o, _)| *o) else { break };
            self.written.remove(&oldest);
        }
    }

    fn see_secret(&mut self, key: (DeviceId, [u8; 16]), t: Timestamp) {
        self.secrets.insert(key, t);
        while self.secrets.len() > MAX_SECRETS {
            let Some((oldest, ot)) = self.secrets.iter().min_by_key(|(k, v)| (**v, **k)).map(|(k, v)| (*k, *v)) else {
                break;
            };
            self.secrets.remove(&oldest);
            self.floor = self.floor.max(ot);
        }
    }

    /// The marks as bytes to save: a map in the profile, 1 the newest
    /// written `[origin, time]` sorted by origin, 2 `floor`, 3 the secrets
    /// `[origin, ID, time]` sorted by origin and ID.
    pub fn encode(&self) -> Vec<u8> {
        let written: Vec<Value<'_>> =
            self.written.iter().map(|(o, t)| Value::Array(alloc::vec![Value::Bytes(&o.0), ts_value(t)])).collect();
        let secrets: Vec<Value<'_>> = self
            .secrets
            .iter()
            .map(|((o, id), t)| Value::Array(alloc::vec![Value::Bytes(&o.0), Value::Bytes(id), ts_value(t)]))
            .collect();
        let mut m = Vec::new();
        if !written.is_empty() {
            m.push((1, Value::Array(written)));
        }
        m.push((2, ts_value(&self.floor)));
        if !secrets.is_empty() {
            m.push((3, Value::Array(secrets)));
        }
        Value::Map(m).encode()
    }

    /// Reads marks saved by [`Marks::encode`].
    pub fn decode(b: &[u8]) -> Result<Marks, Rule> {
        let bad = Rule::field("marks/shape");
        let v = cbor::decode(b)?;
        let id16 = |v: &Value<'_>| v.as_bytes().and_then(|b| <[u8; 16]>::try_from(b).ok());
        let mut written = BTreeMap::new();
        for e in v.get(1).and_then(Value::as_array).unwrap_or(&[]) {
            match e.as_array() {
                Some([o, t]) => {
                    written.insert(DeviceId(id16(o).ok_or(bad)?), ts_read(t).ok_or(bad)?);
                }
                _ => return Err(bad),
            }
        }
        let floor = v.get(2).and_then(ts_read).ok_or(bad)?;
        let mut secrets = BTreeMap::new();
        for e in v.get(3).and_then(Value::as_array).unwrap_or(&[]) {
            match e.as_array() {
                Some([o, id, t]) => {
                    secrets.insert((DeviceId(id16(o).ok_or(bad)?), id16(id).ok_or(bad)?), ts_read(t).ok_or(bad)?);
                }
                _ => return Err(bad),
            }
        }
        if written.len() > MAX_ORIGINS || secrets.len() > MAX_SECRETS {
            return Err(bad);
        }
        Ok(Marks { written, secrets, floor })
    }
}
