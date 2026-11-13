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

pub mod tables;
pub mod wave4;

#[cfg(test)]
mod mutants;
#[cfg(test)]
mod tests;

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
    Ok(())
}

/// What a field's value reads as for a reader of this version (format
/// 20.5, "one rule for a value from a later version").
enum Got<'a> {
    /// In range: the value, its lists cleaned.
    Keep(Value<'a>),
    /// Outside this version's range: read as absent.
    Absent,
}

/// The maps whose problems make only that map unusable (a transport's
/// table), never the message that carries it.
fn transport(t: &Table) -> bool {
    core::ptr::eq(t, &tables::OBFUSCATION)
}

/// Reads one value as a reader of this version does: a wrong shape (the
/// CBOR type, the length of a fixed-size key or ID, a key off its curve,
/// an envelope that does not parse, a list out of its order) refuses; a
/// value outside this version's range reads as absent; a list keeps the
/// elements it understands.
fn read_ty<'a>(f: &Field, v: &Value<'a>) -> Result<Got<'a>, Rule> {
    use Got::{Absent, Keep};
    let bad = || Rule::field(f.rule);
    Ok(match f.ty {
        Ty::Uint { min, max } => {
            let n = v.as_uint().ok_or_else(bad)?;
            if n < min || n > max { Absent } else { Keep(v.clone()) }
        }
        Ty::Flag => {
            v.as_uint().ok_or_else(bad)?;
            if v.as_uint() == Some(1) { Keep(v.clone()) } else { Absent }
        }
        Ty::Bytes(n) => {
            if v.as_bytes().map(<[u8]>::len) != Some(n) {
                return Err(bad());
            }
            Keep(v.clone())
        }
        Ty::Id(n) => {
            let b = v.as_bytes().filter(|b| b.len() == n).ok_or_else(bad)?;
            if b.iter().all(|&x| x == 0) { Absent } else { Keep(v.clone()) }
        }
        Ty::BytesUpTo(n) => {
            let b = v.as_bytes().ok_or_else(bad)?;
            if b.is_empty() || b.len() > n { Absent } else { Keep(v.clone()) }
        }
        Ty::Text(n) => {
            let t = v.as_text().ok_or_else(bad)?;
            if t.is_empty() || t.len() > n || t.chars().any(char::is_control) { Absent } else { Keep(v.clone()) }
        }
        Ty::Addr => {
            let t = v.as_text().ok_or_else(bad)?;
            if valid_addr(t) { Keep(v.clone()) } else { Absent }
        }
        Ty::Key(alg) => {
            let k = crate::format::Key::from_value(v).map_err(|_| bad())?;
            if k.alg != alg {
                Absent
            } else if k.check().is_err() {
                return Err(bad());
            } else {
                Keep(v.clone())
            }
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
                return Ok(Absent);
            }
            let inner = Field { n: f.n, rule: f.rule, ty: *of, needed: true };
            let mut kept = alloc::vec::Vec::new();
            for x in a {
                if let Keep(c) = read_ty(&inner, x)? {
                    kept.push(c);
                }
            }
            if kept.is_empty() { Absent } else { Keep(Value::Array(kept)) }
        }
        Ty::Map(t) if transport(t) => match read_map(t, v) {
            Ok(c) => Keep(c),
            Err(_) => Absent,
        },
        Ty::Map(t) => Keep(read_map(t, v).map_err(|_| bad())?),
    })
}

/// Reads a map against its table as a reader of this version does
/// ([`read_ty`]): the map with every field outside this version's range
/// left out and every list cleaned. A needed field that is wrong or left
/// out refuses, and so does a rule between fields. [`check_map`] is the
/// writer's strict form of the same table.
pub fn read_map<'a>(table: &Table, v: &Value<'a>) -> Result<Value<'a>, Rule> {
    let entries = v.as_map().ok_or_else(|| Rule::field(table.shape))?;
    let mut out: alloc::vec::Vec<(u16, Value<'a>)> = alloc::vec::Vec::with_capacity(entries.len());
    for (k, x) in entries {
        match table.fields.iter().find(|f| f.n == *k) {
            None => out.push((*k, x.clone())),
            Some(f) => match read_ty(f, x)? {
                Got::Keep(c) => out.push((*k, c)),
                Got::Absent if f.needed => return Err(Rule::field(f.rule)),
                Got::Absent => {}
            },
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
