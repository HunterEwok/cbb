// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The strict CBOR profile (format section 1): unsigned integers below
//! 2^63, bytes, UTF-8 text, arrays and maps with unsigned keys up to 65535
//! in increasing order; definite lengths in their shortest form; at most 8
//! containers deep and 4096 elements each. Every value has exactly one
//! encoding, so a reader that checks these rules knows that encoding what it
//! read gives back the bytes it got.

use alloc::vec::Vec;

use super::Rule;

/// How deeply containers nest: an item inside 8 containers is the deepest.
pub const MAX_DEPTH: usize = 8;
/// The most elements of one array or map.
pub const MAX_COUNT: usize = 4096;
/// The largest integer of the profile, 2^63 − 1.
pub const MAX_INT: u64 = i64::MAX as u64;

/// One item of the profile, borrowing its bytes and text from the input.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Value<'a> {
    /// An unsigned integer up to 2^63 − 1.
    Uint(u64),
    /// A byte string.
    Bytes(&'a [u8]),
    /// A UTF-8 text string.
    Text(&'a str),
    /// An array.
    Array(Vec<Value<'a>>),
    /// A map, its keys strictly increasing.
    Map(Vec<(u16, Value<'a>)>),
}

impl<'a> Value<'a> {
    /// The integer, if this is one.
    pub fn as_uint(&self) -> Option<u64> {
        match self {
            Value::Uint(n) => Some(*n),
            _ => None,
        }
    }

    /// The bytes, if these are bytes.
    pub fn as_bytes(&self) -> Option<&'a [u8]> {
        match self {
            Value::Bytes(b) => Some(b),
            _ => None,
        }
    }

    /// The text, if this is text.
    pub fn as_text(&self) -> Option<&'a str> {
        match self {
            Value::Text(t) => Some(t),
            _ => None,
        }
    }

    /// The elements, if this is an array.
    pub fn as_array(&self) -> Option<&[Value<'a>]> {
        match self {
            Value::Array(a) => Some(a),
            _ => None,
        }
    }

    /// The entries, if this is a map.
    pub fn as_map(&self) -> Option<&[(u16, Value<'a>)]> {
        match self {
            Value::Map(m) => Some(m),
            _ => None,
        }
    }

    /// The value of key in a map; None when this is no map or has no such
    /// key.
    pub fn get(&self, key: u16) -> Option<&Value<'a>> {
        let m = self.as_map()?;
        let i = m.binary_search_by_key(&key, |(k, _)| *k).ok()?;
        m.get(i).map(|(_, v)| v)
    }

    /// The value's encoding in the profile. A map is written with its keys
    /// in increasing order whatever order it holds them in; one that holds a
    /// key twice has no encoding in the profile, and its later entries are
    /// dropped.
    pub fn encode(&self) -> Vec<u8> {
        let mut e = Encoder::new();
        e.value(self);
        e.finish()
    }
}

/// Reads b as exactly one item of the profile.
pub fn decode(b: &[u8]) -> Result<Value<'_>, Rule> {
    let mut r = Reader { b, pos: 0 };
    let v = r.item(0)?;
    if r.pos != b.len() {
        return Err(Rule::TRAILING);
    }
    Ok(v)
}

/// Checks that b is exactly one item of the profile, without keeping it.
pub fn check(b: &[u8]) -> Result<(), Rule> {
    decode(b).map(|_| ())
}

struct Reader<'a> {
    b: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: u64) -> Result<&'a [u8], Rule> {
        let n = usize::try_from(n).map_err(|_| Rule::TRUNCATED)?;
        let end = self.pos.checked_add(n).ok_or(Rule::TRUNCATED)?;
        let s = self.b.get(self.pos..end).ok_or(Rule::TRUNCATED)?;
        self.pos = end;
        Ok(s)
    }

    fn peek(&self) -> Result<u8, Rule> {
        self.b.get(self.pos).copied().ok_or(Rule::TRUNCATED)
    }

    /// The argument of a head with additional information ai, refusing a
    /// longer form than its value needs.
    fn arg(&mut self, ai: u8) -> Result<u64, Rule> {
        let size: u64 = match ai {
            0..=23 => return Ok(u64::from(ai)),
            24 => 1,
            25 => 2,
            26 => 4,
            27 => 8,
            31 => return Err(Rule::INDEFINITE),
            _ => return Err(Rule::RESERVED),
        };
        let mut v: u64 = 0;
        for &c in self.take(size)? {
            v = v << 8 | u64::from(c);
        }
        let min = match size {
            1 => 24,
            2 => 0x100,
            4 => 0x1_0000,
            _ => 0x1_0000_0000,
        };
        if v < min {
            return Err(Rule::SHORTEST);
        }
        Ok(v)
    }

    fn item(&mut self, depth: usize) -> Result<Value<'a>, Rule> {
        let ib = self.peek()?;
        self.pos = self.pos.checked_add(1).ok_or(Rule::TRUNCATED)?;
        let (major, ai) = (ib >> 5, ib & 31);
        match major {
            1 => return Err(Rule::NEGATIVE),
            6 => return Err(Rule::TAG),
            7 => return Err(Rule::SIMPLE),
            _ => {}
        }
        let n = self.arg(ai)?;
        match major {
            0 => {
                if n > MAX_INT {
                    return Err(Rule::INT_RANGE);
                }
                Ok(Value::Uint(n))
            }
            2 => Ok(Value::Bytes(self.take(n)?)),
            3 => {
                let s = self.take(n)?;
                core::str::from_utf8(s).map(Value::Text).map_err(|_| Rule::UTF8)
            }
            _ => {
                if depth >= MAX_DEPTH {
                    return Err(Rule::DEPTH);
                }
                let count = usize::try_from(n).map_err(|_| Rule::COUNT)?;
                if count > MAX_COUNT {
                    return Err(Rule::COUNT);
                }
                // Each element takes at least one byte: never reserve more
                // than the input can hold.
                let room = self.b.len().saturating_sub(self.pos);
                let inner = depth.saturating_add(1);
                if major == 4 {
                    let mut a = Vec::with_capacity(count.min(room));
                    for _ in 0..count {
                        a.push(self.item(inner)?);
                    }
                    return Ok(Value::Array(a));
                }
                let mut m: Vec<(u16, Value<'a>)> = Vec::with_capacity(count.min(room / 2));
                for _ in 0..count {
                    if self.peek()? >> 5 != 0 {
                        return Err(Rule::MAP_KEY);
                    }
                    let k = match self.item(inner)? {
                        Value::Uint(k) => u16::try_from(k).map_err(|_| Rule::MAP_KEY)?,
                        _ => return Err(Rule::MAP_KEY),
                    };
                    if m.last().is_some_and(|(last, _)| k <= *last) {
                        return Err(Rule::MAP_ORDER);
                    }
                    let v = self.item(inner)?;
                    m.push((k, v));
                }
                Ok(Value::Map(m))
            }
        }
    }
}

/// Writes items of the profile. The caller writes a container's head with
/// its count, then its elements; map keys in increasing order.
#[derive(Default)]
pub struct Encoder {
    out: Vec<u8>,
}

/// The bytes a head with argument n takes.
pub const fn head_len(n: u64) -> usize {
    if n < 24 {
        1
    } else if n < 0x100 {
        2
    } else if n < 0x1_0000 {
        3
    } else if n < 0x1_0000_0000 {
        5
    } else {
        9
    }
}

impl Encoder {
    /// An empty encoder.
    pub fn new() -> Self {
        Encoder { out: Vec::new() }
    }

    fn head(&mut self, major: u8, n: u64) {
        let m = major << 5;
        let be = n.to_be_bytes();
        match head_len(n) {
            // The match arms make each cast lossless.
            1 => self.out.push(m | be[7]),
            2 => self.out.extend_from_slice(&[m | 24, be[7]]),
            3 => {
                self.out.push(m | 25);
                self.out.extend_from_slice(&be[6..]);
            }
            5 => {
                self.out.push(m | 26);
                self.out.extend_from_slice(&be[4..]);
            }
            _ => {
                self.out.push(m | 27);
                self.out.extend_from_slice(&be);
            }
        }
    }

    /// An unsigned integer; n must be at most 2^63 − 1.
    pub fn uint(&mut self, n: u64) -> &mut Self {
        debug_assert!(n <= MAX_INT, "an integer over the profile's range");
        self.head(0, n);
        self
    }

    /// A byte string.
    pub fn bytes(&mut self, b: &[u8]) -> &mut Self {
        self.head(2, b.len() as u64);
        self.out.extend_from_slice(b);
        self
    }

    /// A text string.
    pub fn text(&mut self, t: &str) -> &mut Self {
        self.head(3, t.len() as u64);
        self.out.extend_from_slice(t.as_bytes());
        self
    }

    /// The head of an array of n elements.
    pub fn array(&mut self, n: usize) -> &mut Self {
        self.head(4, n as u64);
        self
    }

    /// The head of a map of n entries.
    pub fn map(&mut self, n: usize) -> &mut Self {
        self.head(5, n as u64);
        self
    }

    /// An item already encoded in the profile, as it is.
    pub fn raw(&mut self, item: &[u8]) -> &mut Self {
        self.out.extend_from_slice(item);
        self
    }

    /// A whole value.
    pub fn value(&mut self, v: &Value<'_>) -> &mut Self {
        match v {
            Value::Uint(n) => {
                self.uint(*n);
            }
            Value::Bytes(b) => {
                self.bytes(b);
            }
            Value::Text(t) => {
                self.text(t);
            }
            Value::Array(a) => {
                self.array(a.len());
                for x in a {
                    self.value(x);
                }
            }
            Value::Map(m) => {
                let mut order: Vec<&(u16, Value<'_>)> = m.iter().collect();
                order.sort_by_key(|(k, _)| *k);
                order.dedup_by_key(|(k, _)| *k);
                self.map(order.len());
                for (k, x) in order {
                    self.uint(u64::from(*k));
                    self.value(x);
                }
            }
        }
        self
    }

    /// The bytes written so far.
    pub fn as_slice(&self) -> &[u8] {
        &self.out
    }

    /// The bytes written.
    pub fn finish(self) -> Vec<u8> {
        self.out
    }
}
