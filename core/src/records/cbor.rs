// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! A writer for the strict CBOR profile of the 0.6 format (unsigned
//! integers, bytes, text, arrays and maps with integer keys in increasing
//! order, every head in its shortest form), just enough to give a record's
//! body its bytes. The format's own codec (`crate::format`) takes its place
//! once it is in the tree; nothing outside this module uses it.

use alloc::vec::Vec;

// Major types, already in the head's top three bits.
const UINT: u8 = 0x00;
const BYTES: u8 = 0x40;
const TEXT: u8 = 0x60;
const ARRAY: u8 = 0x80;
const MAP: u8 = 0xa0;

/// Writes a head: major type and argument, in the shortest form.
fn head(out: &mut Vec<u8>, major: u8, n: u64) {
    let m = major;
    if n < 24 {
        out.push(m | n as u8);
    } else if n <= 0xff {
        out.push(m | 24);
        out.push(n as u8);
    } else if n <= 0xffff {
        out.push(m | 25);
        out.extend_from_slice(&(n as u16).to_be_bytes());
    } else if n <= 0xffff_ffff {
        out.push(m | 26);
        out.extend_from_slice(&(n as u32).to_be_bytes());
    } else {
        out.push(m | 27);
        out.extend_from_slice(&n.to_be_bytes());
    }
}

pub fn uint(n: u64) -> Vec<u8> {
    let mut out = Vec::new();
    head(&mut out, UINT, n);
    out
}

pub fn bytes(b: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(b.len().saturating_add(9));
    head(&mut out, BYTES, b.len() as u64);
    out.extend_from_slice(b);
    out
}

pub fn text(s: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(s.len().saturating_add(9));
    head(&mut out, TEXT, s.len() as u64);
    out.extend_from_slice(s.as_bytes());
    out
}

/// An array of items already encoded.
pub fn array(items: impl IntoIterator<Item = Vec<u8>>) -> Vec<u8> {
    let items: Vec<Vec<u8>> = items.into_iter().collect();
    let mut out = Vec::new();
    head(&mut out, ARRAY, items.len() as u64);
    for i in items {
        out.extend_from_slice(&i);
    }
    out
}

/// A map from field numbers to items already encoded, written in
/// increasing key order whatever the order given.
#[derive(Default)]
pub struct Map(Vec<(u16, Vec<u8>)>);

impl Map {
    pub fn new() -> Map {
        Map(Vec::new())
    }

    pub fn put(&mut self, key: u16, value: Vec<u8>) -> &mut Map {
        self.0.push((key, value));
        self
    }

    pub fn finish(&mut self) -> Vec<u8> {
        self.0.sort_by_key(|(k, _)| *k);
        let mut out = Vec::new();
        head(&mut out, MAP, self.0.len() as u64);
        for (k, v) in &self.0 {
            head(&mut out, UINT, u64::from(*k));
            out.extend_from_slice(v);
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shortest_heads() {
        assert_eq!(uint(0), [0x00]);
        assert_eq!(uint(23), [0x17]);
        assert_eq!(uint(24), [0x18, 24]);
        assert_eq!(uint(256), [0x19, 1, 0]);
        assert_eq!(uint(1 << 32), [0x1b, 0, 0, 0, 1, 0, 0, 0, 0]);
        assert_eq!(text("a"), [0x61, b'a']);
        assert_eq!(bytes(&[1, 2]), [0x42, 1, 2]);
        assert_eq!(Map::new().put(300, uint(1)).put(2, uint(3)).finish(), [0xa2, 0x02, 0x03, 0x19, 0x01, 0x2c, 0x01]);
    }
}
