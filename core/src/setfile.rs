// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The set file: how a member keeps its group's records v3 between runs
//! (docs/core-api.md, "The group"). One CBOR map in the format's profile
//! (`crate::format::cbor`), written whole:
//!
//! | key | value |
//! |---|---|
//! | 1 | the file's version, 1 |
//! | 2 | the group's first root key |
//! | 3, 4 | the two halves of the group's recovery key, K1 and K2 |
//! | 5 | the pin: [`crate::records::pin_mark`] under the device's local key (optional) |
//! | 6 | the records, in dependency order: each `[envelope]` or `[envelope, mark]` |
//! | 7 | the lists the records name |
//! | 8 | the removal records the notices keep |
//! | 9 | the notices dismissed (record IDs) |
//! | 10 | the devices that came in through each change of root: `[id, seq, [key hash...]]` |
//! | 11 | the newest change applied with the devices before it: `[id, seq, [device ID...]]` |
//!
//! Absent fields are empty. The rules of the set are the records' own
//! ([`RecordSet`]); this file only saves what [`RecordSet::restore`],
//! [`RecordSet::load_marked`], [`RecordSet::keep_notices`] and
//! [`RecordSet::keep_arrivals`] take back. A record with a mark that holds
//! under the local key is taken without its signature checked again; every
//! other record is checked as if it came from a peer. A file whose pin does
//! not hold under the local key is refused whole: its keys were changed.

use alloc::collections::BTreeSet;
use alloc::vec::Vec;

use crate::error::{Error, Result};
use crate::format::cbor::{self, Encoder, Value};
use crate::records::set::{Arrival, Base};
use crate::records::{DeviceId, Key, KeyHash, Mark, Record, RecordId, RecordSet, Recovery};

/// The version of the set file this core writes and reads.
pub const VERSION: u64 = 1;

const F_VERSION: u16 = 1;
const F_ROOT: u16 = 2;
const F_K1: u16 = 3;
const F_K2: u16 = 4;
const F_PIN: u16 = 5;
const F_RECORDS: u16 = 6;
const F_LISTS: u16 = 7;
const F_NOTICES: u16 = 8;
const F_DISMISSED: u16 = 9;
const F_ARRIVALS: u16 = 10;
const F_BASE: u16 = 11;

/// The set's bytes, with each record's mark and the pin under local when
/// one is given.
pub fn save(set: &RecordSet, local: Option<&[u8; 32]>) -> Vec<u8> {
    let records: Vec<(&Record, Option<Mark>)> = match local {
        Some(l) => set.marked(l).into_iter().map(|(r, m)| (r, Some(m))).collect(),
        None => set.in_dependency_order().into_iter().map(|r| (r, None)).collect(),
    };
    let lists: Vec<&[u8]> = set.lists().collect();
    let notices: Vec<&Record> = set.notice_records().collect();
    let dismissed: Vec<&RecordId> = set.dismissed().collect();
    let (arrivals, base) = set.arrivals();

    let n = 4usize.saturating_add(
        [
            local.is_some(),
            !records.is_empty(),
            !lists.is_empty(),
            !notices.is_empty(),
            !dismissed.is_empty(),
            !arrivals.is_empty(),
            base.is_some(),
        ]
        .into_iter()
        .filter(|p| *p)
        .count(),
    );
    let mut e = Encoder::new();
    e.map(n);
    e.uint(u64::from(F_VERSION)).uint(VERSION);
    e.uint(u64::from(F_ROOT)).raw(&set.root().encode());
    e.uint(u64::from(F_K1)).raw(&set.recovery().k1.encode());
    e.uint(u64::from(F_K2)).raw(&set.recovery().k2.encode());
    if let Some(l) = local {
        e.uint(u64::from(F_PIN)).bytes(&crate::records::pin_mark(l, set.root(), set.recovery()));
    }
    if !records.is_empty() {
        e.uint(u64::from(F_RECORDS)).array(records.len());
        for (r, m) in &records {
            match m {
                Some(m) => e.array(2).bytes(&r.envelope()).bytes(m),
                None => e.array(1).bytes(&r.envelope()),
            };
        }
    }
    if !lists.is_empty() {
        e.uint(u64::from(F_LISTS)).array(lists.len());
        for l in &lists {
            e.bytes(l);
        }
    }
    if !notices.is_empty() {
        e.uint(u64::from(F_NOTICES)).array(notices.len());
        for r in &notices {
            e.bytes(&r.envelope());
        }
    }
    if !dismissed.is_empty() {
        e.uint(u64::from(F_DISMISSED)).array(dismissed.len());
        for id in &dismissed {
            e.bytes(&id.0);
        }
    }
    if !arrivals.is_empty() {
        e.uint(u64::from(F_ARRIVALS)).array(arrivals.len());
        for (id, seq, keys) in &arrivals {
            e.array(3).bytes(&id.0).uint(*seq).array(keys.len());
            for k in keys {
                e.bytes(&k.0);
            }
        }
    }
    if let Some(b) = &base {
        e.uint(u64::from(F_BASE)).array(3).bytes(&b.change.0).uint(b.seq).array(b.before.len());
        for d in &b.before {
            e.bytes(&d.0);
        }
    }
    e.finish()
}

/// What a set file holds before its records are taken into a set.
pub struct Saved {
    pub root: Key,
    pub recovery: Recovery,
    pub pin: Option<Mark>,
    pub records: Vec<(Record, Option<Mark>)>,
    pub lists: Vec<Vec<u8>>,
    pub notices: Vec<Record>,
    pub dismissed: Vec<RecordId>,
    pub arrivals: Vec<Arrival>,
    pub base: Option<Base>,
}

fn bad(what: &str) -> Error {
    Error::msg(alloc::format!("the set file is not valid: {what}"))
}

fn array<'a, 'b>(v: &'b Value<'a>, what: &str) -> Result<&'b [Value<'a>]> {
    v.as_array().ok_or_else(|| bad(what))
}

fn bytes<'a>(v: &Value<'a>, what: &str) -> Result<&'a [u8]> {
    v.as_bytes().ok_or_else(|| bad(what))
}

fn fixed<const N: usize>(v: &Value<'_>, what: &str) -> Result<[u8; N]> {
    bytes(v, what)?.try_into().map_err(|_| bad(what))
}

fn record(b: &[u8]) -> Result<Record> {
    Record::decode(b).map_err(|r| bad(&alloc::format!("a record breaks {r}")))
}

/// Reads a set file without taking its records into a set.
pub fn read(b: &[u8]) -> Result<Saved> {
    let v = cbor::decode(b).map_err(|r| bad(&alloc::format!("{r}")))?;
    let map = v.as_map().ok_or_else(|| bad("not a map"))?;
    match v.get(F_VERSION).and_then(Value::as_uint) {
        Some(VERSION) => {}
        Some(n) if n > VERSION => {
            return Err(Error::msg("the set file was written by a newer version of cbb: update this one"));
        }
        _ => return Err(bad("no version")),
    }
    let key = |f: u16, what: &str| -> Result<Key> {
        Key::read(v.get(f).ok_or_else(|| bad(what))?).map_err(|r| bad(&alloc::format!("{what}: {r}")))
    };
    let root = key(F_ROOT, "the root key")?;
    let recovery = Recovery::new(key(F_K1, "the recovery key")?, key(F_K2, "the recovery key")?)
        .ok_or_else(|| bad("the recovery key"))?;
    let mut s = Saved {
        root,
        recovery,
        pin: None,
        records: Vec::new(),
        lists: Vec::new(),
        notices: Vec::new(),
        dismissed: Vec::new(),
        arrivals: Vec::new(),
        base: None,
    };
    for (k, val) in map {
        match *k {
            F_VERSION | F_ROOT | F_K1 | F_K2 => {}
            F_PIN => s.pin = Some(fixed::<32>(val, "the pin")?),
            F_RECORDS => {
                for item in array(val, "the records")? {
                    let parts = array(item, "a record")?;
                    let (env, mark) = match parts {
                        [env] => (env, None),
                        [env, mark] => (env, Some(fixed::<32>(mark, "a record's mark")?)),
                        _ => return Err(bad("a record")),
                    };
                    s.records.push((record(bytes(env, "a record")?)?, mark));
                }
            }
            F_LISTS => {
                for l in array(val, "the lists")? {
                    s.lists.push(bytes(l, "a list")?.to_vec());
                }
            }
            F_NOTICES => {
                for r in array(val, "the notices")? {
                    s.notices.push(record(bytes(r, "a notice")?)?);
                }
            }
            F_DISMISSED => {
                for id in array(val, "the notices dismissed")? {
                    s.dismissed.push(RecordId(fixed::<32>(id, "a notice dismissed")?));
                }
            }
            F_ARRIVALS => {
                for a in array(val, "the arrivals")? {
                    let [id, seq, keys] = array(a, "an arrival")? else { return Err(bad("an arrival")) };
                    let keys = array(keys, "an arrival")?
                        .iter()
                        .map(|k| fixed::<32>(k, "an arrival").map(KeyHash))
                        .collect::<Result<Vec<_>>>()?;
                    let seq = seq.as_uint().ok_or_else(|| bad("an arrival"))?;
                    s.arrivals.push((RecordId(fixed::<32>(id, "an arrival")?), seq, keys));
                }
            }
            F_BASE => {
                let [id, seq, before] = array(val, "the base")? else { return Err(bad("the base")) };
                let before = array(before, "the base")?
                    .iter()
                    .map(|d| fixed::<16>(d, "the base").map(DeviceId))
                    .collect::<Result<BTreeSet<_>>>()?;
                s.base = Some(Base {
                    change: RecordId(fixed::<32>(id, "the base")?),
                    seq: seq.as_uint().ok_or_else(|| bad("the base"))?,
                    before,
                });
            }
            // A field of a later version of the same file: kept by none,
            // read by none; a change an older reader would misread raises
            // the version instead.
            _ => {}
        }
    }
    Ok(s)
}

/// The set a file holds, its records taken as [`RecordSet::restore`] takes
/// them (marked ones unverified under local), its notices and arrivals
/// taken back. With local, a file whose pin does not hold, or that has
/// none, is refused; without it the pin is not read and every record is
/// verified.
pub fn load(b: &[u8], local: Option<&[u8; 32]>) -> Result<RecordSet> {
    let s = read(b)?;
    if let Some(l) = local {
        let pin = s.pin.ok_or_else(|| Error::msg("the set file has no pin for this device"))?;
        if RecordSet::pinned(s.root.clone(), s.recovery.clone(), l, &pin).is_none() {
            return Err(Error::msg("the set file's keys were changed: its pin does not hold"));
        }
    }
    let mut set = match local {
        Some(l) => {
            // Marked records first, round after round as restore does, so
            // that a record that waits for another or for a list is taken.
            let mut set = RecordSet::new(s.root, s.recovery);
            let rounds = s.records.len().saturating_add(s.lists.len()).saturating_add(2);
            let mut last = None;
            for _ in 0..rounds {
                for list in &s.lists {
                    let _ = set.insert_list(list);
                }
                set.load_marked(l, s.records.iter().cloned());
                let now = (set.digest(), set.lists().count(), set.state());
                if last.as_ref() == Some(&now) {
                    break;
                }
                last = Some(now);
            }
            set
        }
        None => {
            let records: Vec<Record> = s.records.into_iter().map(|(r, _)| r).collect();
            RecordSet::restore(s.root, s.recovery, &records, &s.lists)
        }
    };
    set.keep_notices(&s.notices, &s.dismissed);
    set.keep_arrivals(&s.arrivals, s.base);
    Ok(set)
}
