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
    /// A claim's age in a Welcome: `[record ID (bytes 32), held_ms]`.
    Age,
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
        Ty::Age => match v.as_array() {
            Some([Value::Bytes(id), Value::Uint(ms)]) if id.len() == 32 && *ms < (1 << 63) => {}
            _ => return Err(bad()),
        },
        // A bad field inside breaks the field that holds the map.
        Ty::Map(t) => check_map(t, v).map_err(|_| bad())?,
    }
    Ok(())
}

impl Ty {
    /// The type as the vectors' tables and the format document write it:
    /// `uint 0..65535`, `flag`, `bytes 32`, `bytes 1..64`, `text 1..64`,
    /// `addr`, `key 3`, `envelope`, `array 1..8 of addr`, `once …`,
    /// `set …`, `map offer`.
    pub fn describe(&self) -> alloc::string::String {
        use alloc::format;
        match self {
            Ty::Uint { min, max } => format!("uint {min}..{max}"),
            Ty::Flag => "flag".into(),
            Ty::Bytes(n) => format!("bytes {n}"),
            Ty::BytesUpTo(n) => format!("bytes 1..{n}"),
            Ty::Text(n) => format!("text 1..{n}"),
            Ty::Addr => "addr".into(),
            Ty::Key(a) => format!("key {}", a.number()),
            Ty::Envelope => "envelope".into(),
            Ty::Array { of, max } => format!("array 1..{max} of {}", of.describe()),
            Ty::Once { of, max } => format!("once 1..{max} of {}", of.describe()),
            Ty::Set { of, max } => format!("set 1..{max} of {}", of.describe()),
            Ty::Map(t) => format!("map {}", t.name()),
            Ty::Age => "age".into(),
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
    // The rules between fields of a map: AmneziaWG's junk sizes, an
    // offer's endpoint keys, and one age per claim in a Welcome (the
    // claims' IDs rise).
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
    if core::ptr::eq(table, &tables::WELCOME)
        && let Some(a) = v.get(3).and_then(Value::as_array)
    {
        fn id<'a>(x: &Value<'a>) -> Option<&'a [u8]> {
            x.as_array().and_then(|p| p.first()).and_then(Value::as_bytes)
        }
        if a.windows(2).any(|w| w.first().and_then(id) >= w.last().and_then(id)) {
            return Err(Rule::field("welcome/claim-ages"));
        }
    }
    Ok(())
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
