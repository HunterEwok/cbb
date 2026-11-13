// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The messages wave 3 numbers (format sections 9 and 11): pairing, the
//! hub's offer, `hubs`, `guest`, `tunnel`, the request that waits for an
//! admin, and the forwarder's and the relay's messages. Each is a map of
//! numbered fields; a table here gives each field's number, type and
//! bounds, and [`check`] reads a message against its table. The tables are
//! the layout: the format document's section is written from them, and the
//! vectors (`testdata/format/messages3.json`) are checked against them.
//!
//! Messages are not signed and have no zones: a receiver skips a field its
//! table does not list, so a later version adds fields freely. A field that
//! is listed must have its type and bounds, a needed field must be there,
//! and a field at its default is left out (`form/default`).

pub mod later;
pub mod tables;
pub mod wave4;

#[cfg(test)]
mod mutants;
#[cfg(test)]
mod tests;

pub use later::Later;

use crate::format::{Alg, Rule, Value, cbor, frame};

/// A field's type.
#[derive(Clone, Copy, Debug)]
pub enum Ty {
    /// An unsigned integer from `min` to `max`.
    Uint { min: u64, max: u64 },
    /// A flag: the integer 1, present only when set.
    Flag,
    /// Bytes of exactly this length.
    Bytes(usize),
    /// An ID: bytes of exactly this length, not all zero (the zero ID is
    /// "none", which a message says by leaving the field out).
    Id(usize),
    /// Bytes of 1 to this many.
    BytesUpTo(usize),
    /// Text of 1 to this many bytes, no control character.
    Text(usize),
    /// `ip:port` or `[ipv6]:port`.
    Addr,
    /// A Key of this algorithm.
    Key(Alg),
    /// A signed envelope, kept as bytes for its own reader.
    Envelope,
    /// An array of 1 to `max` elements of one type, in the writer's order.
    Array { of: &'static Ty, max: usize },
    /// The same, each element once (by its encoding), in the writer's order
    /// (a preference, such as endpoints).
    Once { of: &'static Ty, max: usize },
    /// The same, sorted by the elements' encodings, each once: a set whose
    /// order says nothing.
    Set { of: &'static Ty, max: usize },
    /// A map of its own table.
    Map(&'static Table),
}

/// One field of a table.
#[derive(Clone, Copy, Debug)]
pub struct Field {
    pub n: u16,
    /// The rule a bad value breaks, `<table>/<field>`.
    pub rule: &'static str,
    pub ty: Ty,
    pub needed: bool,
}

/// A message's or a map's table.
#[derive(Clone, Copy, Debug)]
pub struct Table {
    /// The rule of a value that is not a map: `<table>/shape`.
    pub shape: &'static str,
    pub fields: &'static [Field],
}

fn check_ty(f: &Field, v: &Value<'_>) -> Result<(), Rule> {
    let bad = || Rule::field(f.rule);
    match f.ty {
        Ty::Uint { min, max } => {
            let n = v.as_uint().ok_or_else(bad)?;
            if n < min || n > max {
                return Err(bad());
            }
        }
        Ty::Flag => {
            if v.as_uint() != Some(1) {
                return Err(bad());
            }
        }
        Ty::Bytes(n) => {
            if v.as_bytes().map(<[u8]>::len) != Some(n) {
                return Err(bad());
            }
        }
        Ty::Id(n) => {
            if v.as_bytes().is_none_or(|b| b.len() != n || b.iter().all(|&x| x == 0)) {
                return Err(bad());
            }
        }
        Ty::BytesUpTo(n) => {
            let b = v.as_bytes().ok_or_else(bad)?;
            if b.is_empty() || b.len() > n {
                return Err(bad());
            }
        }
        Ty::Text(n) => {
            let t = v.as_text().ok_or_else(bad)?;
            if t.is_empty() || t.len() > n || t.chars().any(char::is_control) {
                return Err(bad());
            }
        }
        Ty::Addr => {
            let t = v.as_text().ok_or_else(bad)?;
            if !valid_addr(t) {
                return Err(bad());
            }
        }
        Ty::Key(alg) => {
            let k = crate::format::Key::from_value(v).map_err(|_| bad())?;
            if k.alg != alg || k.check().is_err() {
                return Err(bad());
            }
        }
        Ty::Envelope => {
            crate::format::Envelope::from_value(v).map_err(|_| bad())?;
        }
        Ty::Array { of, max } | Ty::Once { of, max } | Ty::Set { of, max } => {
            let a = v.as_array().ok_or_else(bad)?;
            if a.is_empty() || a.len() > max {
                return Err(bad());
            }
            match f.ty {
                Ty::Once { .. } if !each_once(a) => return Err(bad()),
                Ty::Set { .. } if !sorted(a) => return Err(bad()),
                _ => {}
            }
            let inner = Field { n: f.n, rule: f.rule, ty: *of, needed: true };
            for x in a {
                check_ty(&inner, x)?;
            }
        }
        // A bad field inside breaks the field that holds the map.
        Ty::Map(t) => check_map(t, v).map_err(|_| bad())?,
    }
    Ok(())
}

impl Ty {
    /// The type as the vectors' tables and the format document write it:
    /// `uint 0..65535`, `flag`, `bytes 32`, `id 16`, `bytes 1..64`, `text 1..64`,
    /// `addr`, `key 3`, `envelope`, `array 1..8 of addr`, `once …`,
    /// `set …`, `map offer`.
    pub fn describe(&self) -> alloc::string::String {
        use alloc::format;
        match self {
            Ty::Uint { min, max } => format!("uint {min}..{max}"),
            Ty::Flag => "flag".into(),
            Ty::Bytes(n) => format!("bytes {n}"),
            Ty::Id(n) => format!("id {n}"),
            Ty::BytesUpTo(n) => format!("bytes 1..{n}"),
            Ty::Text(n) => format!("text 1..{n}"),
            Ty::Addr => "addr".into(),
            Ty::Key(a) => format!("key {}", a.number()),
            Ty::Envelope => "envelope".into(),
            Ty::Array { of, max } => format!("array 1..{max} of {}", of.describe()),
            Ty::Once { of, max } => format!("once 1..{max} of {}", of.describe()),
            Ty::Set { of, max } => format!("set 1..{max} of {}", of.describe()),
            Ty::Map(t) => format!("map {}", t.name()),
        }
    }
}

impl Table {
    /// The table's name: its shape rule without `/shape`.
    pub fn name(&self) -> &'static str {
        self.shape.strip_suffix("/shape").unwrap_or(self.shape)
    }
}

/// Reports whether t is an `addr`: `ip:port` or `[ipv6]:port` in its one
/// canonical text (RFC 5952 for IPv6: lower case, the longest run of zero
/// groups shortened, no leading zeros; the port in its shortest digits), no
/// scope (zone), no IPv4-mapped IPv6 address, not the unspecified address,
/// not port 0. So one address has one spelling, and a `once` list cannot
/// hold it twice.
pub fn valid_addr(t: &str) -> bool {
    let Ok(a) = t.parse::<core::net::SocketAddr>() else { return false };
    let canonical = match a {
        core::net::SocketAddr::V4(_) => true,
        core::net::SocketAddr::V6(v6) => v6.scope_id() == 0 && v6.flowinfo() == 0 && v6.ip().to_ipv4_mapped().is_none(),
    };
    canonical && a.port() != 0 && !a.ip().is_unspecified() && alloc::format!("{a}") == t
}

/// Reports whether no two elements have one encoding.
pub fn each_once(items: &[Value<'_>]) -> bool {
    let mut e: alloc::vec::Vec<alloc::vec::Vec<u8>> = items.iter().map(Value::encode).collect();
    e.sort();
    e.windows(2).all(|w| w.first() != w.last())
}

/// Reports whether the elements are in strictly rising order of their
/// encodings (bytewise), so each is there once.
pub fn sorted(items: &[Value<'_>]) -> bool {
    items.windows(2).all(|w| match w {
        [a, b] => a.encode() < b.encode(),
        _ => true,
    })
}

/// Reads a map against its table.
pub fn check_map(table: &Table, v: &Value<'_>) -> Result<(), Rule> {
    if v.as_map().is_none() {
        return Err(Rule::field(table.shape));
    }
    for f in table.fields {
        match v.get(f.n) {
            None if f.needed => return Err(Rule::field(f.rule)),
            None => {}
            Some(x) => check_ty(f, x)?,
        }
    }
    between(table, v)
}

/// The rules between fields of a map.
fn between(table: &Table, v: &Value<'_>) -> Result<(), Rule> {
    // The rules between fields of a map: AmneziaWG's junk sizes and an
    // offer's endpoint keys.
    if core::ptr::eq(table, &tables::OBFUSCATION)
        && v.get(2).and_then(Value::as_uint) > v.get(3).and_then(Value::as_uint)
    {
        return Err(Rule::field("obfuscation/jmax"));
    }
    // An offer's endpoint keys each name one of its endpoints, once.
    if core::ptr::eq(table, &tables::OFFER)
        && let Some(keys) = v.get(9).and_then(Value::as_array)
    {
        let eps = v.get(2).and_then(Value::as_array).unwrap_or(&[]);
        let named: alloc::vec::Vec<Option<&Value<'_>>> = keys.iter().map(|k| k.get(1)).collect();
        let mut seen: alloc::vec::Vec<alloc::vec::Vec<u8>> = alloc::vec::Vec::new();
        for n in named {
            let Some(n) = n else { return Err(Rule::field("offer/endpoint-keys")) };
            let e = n.encode();
            if !eps.iter().any(|x| x.encode() == e) || seen.contains(&e) {
                return Err(Rule::field("offer/endpoint-keys"));
            }
            seen.push(e);
        }
    }
    // A root's fork is two records.
    if core::ptr::eq(table, &wave4::ROOTS) && v.get(3).and_then(Value::as_array).is_some_and(|a| a.len() != 2) {
        return Err(Rule::field("roots/fork"));
    }
    // Fields 3 (claim ages) and 8 (counted claims) of earlier drafts are
    // refused (rule 33).
    if core::ptr::eq(table, &tables::WELCOME) && (v.get(3).is_some() || v.get(8).is_some()) {
        return Err(Rule::field("welcome/retired"));
    }
    // A Welcome's records ride in it or in parts; a leaf's has neither
    // digest nor parts.
    if core::ptr::eq(table, &tables::WELCOME) {
        crate::join::welcome::between(v)?;
    }
    // A records message carries records, lists, or both.
    if core::ptr::eq(table, &tables::RECORDS) && v.get(2).is_none() && v.get(3).is_none() {
        return Err(Rule::field("records/shape"));
    }
    Ok(())
}

/// What a field's value reads as for a reader of this version (format
/// 20.5, "one rule for a value from a later version").
enum Got<'a> {
    /// In range: the value, its lists cleaned.
    Keep(Value<'a>),
    /// Outside this version's range, in a field whose row reads it as
    /// absent ([`later`]).
    Absent,
}

/// Reads one value as a reader of this version does. A wrong shape (the
/// CBOR type, the length of a fixed-size key or ID, a key off its curve,
/// an envelope that does not parse, a list out of its order) refuses. A
/// value outside this version's range does what `l` says ([`Later`]): a
/// needed field's is always [`Later::Refuse`].
fn read_ty<'a>(f: &Field, l: Later, v: &Value<'a>, dropped: &mut alloc::vec::Vec<Dropped>) -> Result<Got<'a>, Rule> {
    use Got::{Absent, Keep};
    let bad = || Rule::field(f.rule);
    // Out of range: refused, or read as absent and noted.
    let out = |dropped: &mut alloc::vec::Vec<Dropped>| {
        if l == Later::Absent {
            dropped.push(Dropped { rule: f.rule, n: f.n, bytes: v.encode().len() });
            Ok(Absent)
        } else {
            Err(bad())
        }
    };
    Ok(match f.ty {
        Ty::Uint { min, max } => {
            let n = v.as_uint().ok_or_else(bad)?;
            if let Later::Bits(mask) = l {
                if n & !mask != 0 {
                    dropped.push(Dropped { rule: f.rule, n: f.n, bytes: v.encode().len() });
                }
                return Ok(if n & mask == 0 { Absent } else { Keep(Value::Uint(n & mask)) });
            }
            if n < min || n > max {
                return out(dropped);
            }
            Keep(v.clone())
        }
        Ty::Flag => {
            if v.as_uint().ok_or_else(bad)? != 1 {
                return out(dropped);
            }
            Keep(v.clone())
        }
        Ty::Bytes(n) => {
            if v.as_bytes().map(<[u8]>::len) != Some(n) {
                return Err(bad());
            }
            Keep(v.clone())
        }
        Ty::Id(n) => {
            let b = v.as_bytes().filter(|b| b.len() == n).ok_or_else(bad)?;
            if b.iter().all(|&x| x == 0) {
                return out(dropped);
            }
            Keep(v.clone())
        }
        Ty::BytesUpTo(n) => {
            let b = v.as_bytes().ok_or_else(bad)?;
            if b.is_empty() || b.len() > n {
                return out(dropped);
            }
            Keep(v.clone())
        }
        Ty::Text(n) => {
            let t = v.as_text().ok_or_else(bad)?;
            if t.is_empty() || t.len() > n || t.chars().any(char::is_control) {
                return out(dropped);
            }
            Keep(v.clone())
        }
        Ty::Addr => {
            if !valid_addr(v.as_text().ok_or_else(bad)?) {
                return out(dropped);
            }
            Keep(v.clone())
        }
        Ty::Key(alg) => {
            let k = crate::format::Key::from_value(v).map_err(|_| bad())?;
            if k.alg != alg {
                return out(dropped);
            }
            k.check().map_err(|_| bad())?;
            Keep(v.clone())
        }
        Ty::Envelope => {
            crate::format::Envelope::from_value(v).map_err(|_| bad())?;
            Keep(v.clone())
        }
        Ty::Array { of, max } | Ty::Once { of, max } | Ty::Set { of, max } => {
            let a = v.as_array().ok_or_else(bad)?;
            match f.ty {
                Ty::Once { .. } if !each_once(a) => return Err(bad()),
                Ty::Set { .. } if !sorted(a) => return Err(bad()),
                _ => {}
            }
            if a.len() > max {
                return out(dropped);
            }
            // An entry out of range is skipped only where the field may
            // read as absent; elsewhere it refuses.
            let inner = Field { n: f.n, rule: f.rule, ty: *of, needed: false };
            let el = if l == Later::Absent { Later::Absent } else { Later::Refuse };
            let mut kept = alloc::vec::Vec::new();
            for x in a {
                if let Keep(c) = read_ty(&inner, el, x, dropped)? {
                    kept.push(c);
                }
            }
            if kept.is_empty() {
                return out(dropped);
            }
            Keep(Value::Array(kept))
        }
        Ty::Map(t) if l == Later::Unusable => {
            let m = v.as_map().ok_or_else(bad)?;
            let known = m.iter().all(|(k, _)| t.fields.iter().any(|f| f.n == *k));
            match read_map_into(t, v, later::of, dropped) {
                Ok(c) if known => Keep(c),
                _ => {
                    dropped.push(Dropped { rule: f.rule, n: f.n, bytes: v.encode().len() });
                    Keep(Value::Map(alloc::vec::Vec::new()))
                }
            }
        }
        Ty::Map(t) => Keep(read_map_into(t, v, later::of, dropped).map_err(|_| bad())?),
    })
}

/// Reads a map against its table as a reader of this version does
/// ([`read_ty`], [`later`]): the map with each field outside this
/// version's range read as its row says (left out, its unknown bits
/// cleared, or a transport made unusable) and each list cleaned; a field
/// that cannot be read so refuses, and so does a rule between fields.
/// Fields the table does not list are kept as they are. [`check_map`] is
/// the writer's strict form of the same table.
pub fn read_map<'a>(table: &Table, v: &Value<'a>) -> Result<Value<'a>, Rule> {
    read_map_noted(table, v).map(|(r, _)| r)
}

/// A field a reader of this version did not read as written: left out, its
/// unknown bits cleared, or its transport made unusable. For the log: "a
/// reason this version could not read" is not "no reason sent".
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Dropped {
    /// The field's rule, `<table>/<field>`.
    pub rule: &'static str,
    pub n: u16,
    /// The size of its value as written.
    pub bytes: usize,
}

/// [`read_map`], and the fields it did not read as written, nested maps'
/// among them.
pub fn read_map_noted<'a>(table: &Table, v: &Value<'a>) -> Result<(Value<'a>, alloc::vec::Vec<Dropped>), Rule> {
    let mut dropped = alloc::vec::Vec::new();
    let r = read_map_into(table, v, later::of, &mut dropped)?;
    Ok((r, dropped))
}

/// [`read_map`] with the rows of the table's optional fields from `rows`.
#[cfg(test)]
fn read_map_by<'a>(table: &Table, v: &Value<'a>, rows: fn(&Table, u16) -> Later) -> Result<Value<'a>, Rule> {
    read_map_into(table, v, rows, &mut alloc::vec::Vec::new())
}

fn read_map_into<'a>(
    table: &Table,
    v: &Value<'a>,
    rows: fn(&Table, u16) -> Later,
    dropped: &mut alloc::vec::Vec<Dropped>,
) -> Result<Value<'a>, Rule> {
    let entries = v.as_map().ok_or_else(|| Rule::field(table.shape))?;
    let mut out: alloc::vec::Vec<(u16, Value<'a>)> = alloc::vec::Vec::with_capacity(entries.len());
    for (k, x) in entries {
        match table.fields.iter().find(|f| f.n == *k) {
            None => out.push((*k, x.clone())),
            Some(f) => {
                let l = if f.needed { Later::Refuse } else { rows(table, f.n) };
                if let Got::Keep(c) = read_ty(f, l, x, dropped)? {
                    out.push((*k, c));
                }
            }
        }
    }
    let read = Value::Map(out);
    for f in table.fields.iter().filter(|f| f.needed) {
        if read.get(f.n).is_none() {
            return Err(Rule::field(f.rule));
        }
    }
    between(table, &read)?;
    Ok(read)
}

/// Reads a message as a reader of this version does: its type, and the
/// message read against the table of its type ([`read_map`]), or as it is
/// when this version does not number the type (the receiver ignores it).
pub fn read(msg: &[u8]) -> Result<(u64, Value<'_>), Rule> {
    read_noted(msg).map(|(t, v, _)| (t, v))
}

/// [`read`], and the fields it did not read as written ([`Dropped`]).
pub fn read_noted(msg: &[u8]) -> Result<(u64, Value<'_>, alloc::vec::Vec<Dropped>), Rule> {
    let v = cbor::decode(msg)?;
    let t = v.get(frame::FIELD_T).and_then(Value::as_uint).ok_or(Rule::FRAME_MESSAGE)?;
    match tables::of(t).or_else(|| wave4::of(t)) {
        Some(table) => {
            let (r, d) = read_map_noted(table, &v)?;
            Ok((t, r, d))
        }
        None => Ok((t, v, alloc::vec::Vec::new())),
    }
}

/// A group's AmneziaWG settings ([`tables::OBFUSCATION`]), kept as their
/// encoding: the core passes them on and the tunnel reads them.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Obfuscation(alloc::vec::Vec<u8>);

impl Obfuscation {
    /// Reads them from a value, checked against their table; `rule` is the
    /// rule of the field that carries them.
    pub fn read(v: &Value<'_>, rule: &'static str) -> Result<Obfuscation, Rule> {
        check_map(&tables::OBFUSCATION, v).map_err(|_| Rule::field(rule))?;
        Ok(Obfuscation(v.encode()))
    }

    /// From their encoding.
    pub fn decode(b: &[u8], rule: &'static str) -> Result<Obfuscation, Rule> {
        Obfuscation::read(&cbor::decode(b).map_err(|_| Rule::field(rule))?, rule)
    }

    pub fn encoding(&self) -> &[u8] {
        &self.0
    }

    /// As a value, to put in a message.
    pub fn value(&self) -> Option<Value<'_>> {
        cbor::decode(&self.0).ok()
    }
}

/// Reads a message (a map with its type in field 0, and `pad` in field 1
/// when it came in a frame) against the table of its type. Returns the
/// type. A type this version does not number is no error of its form: the
/// receiver ignores it.
pub fn check(msg: &[u8]) -> Result<u64, Rule> {
    let v = cbor::decode(msg)?;
    let t = v.get(frame::FIELD_T).and_then(Value::as_uint).ok_or(Rule::FRAME_MESSAGE)?;
    if let Some(table) = tables::of(t).or_else(|| wave4::of(t)) {
        check_map(table, &v)?;
    }
    Ok(t)
}
