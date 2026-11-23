// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The group's AmneziaWG settings as the hub's JSON keeps them
//! (docs/protocol.md, section 11, "Obfuscation"), read and checked as Go's
//! tunnel.Obfuscation.Check, before the forwarder's registration writes
//! them in the format's table `obfuscation`.

use alloc::string::ToString;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde_json::{Map, Value};
use zeroize::Zeroize;

/// A range of a message's type field, inclusive.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Range {
    pub min: u32,
    pub max: u32,
}

impl Range {
    fn overlaps(self, o: Range) -> bool {
        self.min <= o.max && o.min <= self.max
    }
}

/// The hub's AmneziaWG settings.
#[derive(Clone, PartialEq, Eq)]
pub struct Obfuscation {
    pub jc: u32,
    pub jmin: u32,
    pub jmax: u32,
    pub s: [u32; 4],
    pub h: [Range; 4],
    pub header_protection_key: [u8; 32],
}

impl core::fmt::Debug for Obfuscation {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Obfuscation")
            .field("jc", &self.jc)
            .field("jmin", &self.jmin)
            .field("jmax", &self.jmax)
            .field("s", &self.s)
            .field("h", &self.h)
            .field("header_protection_key", &crate::secret::Redacted(self.header_protection_key.len()))
            .finish()
    }
}

impl Drop for Obfuscation {
    fn drop(&mut self) {
        self.header_protection_key.zeroize();
    }
}

impl Obfuscation {
    /// The settings as the hub's JSON keeps them.
    pub fn to_json(&self) -> Value {
        let r = |r: Range| Value::from(alloc::format!("{}-{}", r.min, r.max));
        let mut m = Map::new();
        for (k, v) in [("jc", self.jc), ("jmin", self.jmin), ("jmax", self.jmax)] {
            m.insert(k.into(), Value::from(v));
        }
        for (i, (s, h)) in self.s.iter().zip(self.h.iter()).enumerate() {
            let n = i.saturating_add(1);
            m.insert(alloc::format!("s{n}"), Value::from(*s));
            m.insert(alloc::format!("h{n}"), r(*h));
        }
        m.insert("header_protection_key".into(), Value::from(STANDARD.encode(self.header_protection_key)));
        Value::Object(m)
    }

    fn check(&self) -> bool {
        if self.jc > MAX_JUNK_COUNT || self.jmin > self.jmax || self.jmax > MAX_JUNK_SIZE {
            return false;
        }
        // The three handshake messages keep three sizes once padded. The
        // paddings are at most 64 here, so the sums cannot overflow.
        let [s1, s2, s3, _] = self.s;
        if self.s.iter().any(|s| !(MIN_PADDING..=MAX_PADDING).contains(s)) {
            return false;
        }
        let (a, b, c) = (148u32.saturating_add(s1), 92u32.saturating_add(s2), 64u32.saturating_add(s3));
        if a == b || a == c || b == c {
            return false;
        }
        for (i, h) in self.h.iter().enumerate() {
            if h.min > h.max || h.min <= MSG_DATA {
                return false;
            }
            if self.h.iter().skip(i.saturating_add(1)).any(|o| h.overlaps(*o)) {
                return false;
            }
        }
        true
    }
}

const INTS: [&str; 7] = ["jc", "jmin", "jmax", "s1", "s2", "s3", "s4"];
const STRS: [&str; 5] = ["h1", "h2", "h3", "h4", "header_protection_key"];

// The bounds of Go's tunnel.Obfuscation.Check.
const MAX_JUNK_COUNT: u32 = 16;
const MAX_JUNK_SIZE: u32 = 1000;
const MIN_PADDING: u32 = 16;
const MAX_PADDING: u32 = 64;
/// WireGuard's highest message type; the headers stay above it.
const MSG_DATA: u32 = 4;

/// Reads the settings from the hub's JSON: every field, of its type, and
/// none other, within Go's bounds; None otherwise.
pub fn from_json(v: &Value) -> Option<Obfuscation> {
    let o = v.as_object()?;
    if o.len() != INTS.len().saturating_add(STRS.len())
        || o.keys().any(|k| !INTS.contains(&k.as_str()) && !STRS.contains(&k.as_str()))
    {
        return None;
    }
    let mut n = [0u32; 7];
    for (dst, name) in n.iter_mut().zip(INTS) {
        *dst = u32::try_from(o.get(name)?.as_i64()?).ok()?;
    }
    let text = |name: &str| o.get(name).and_then(Value::as_str).map(ToString::to_string);
    let h = [
        parse_range(&text("h1")?)?,
        parse_range(&text("h2")?)?,
        parse_range(&text("h3")?)?,
        parse_range(&text("h4")?)?,
    ];
    let header_protection_key = key(&text("header_protection_key")?)?;
    let [jc, jmin, jmax, s1, s2, s3, s4] = n;
    let o = Obfuscation { jc, jmin, jmax, s: [s1, s2, s3, s4], h, header_protection_key };
    o.check().then_some(o)
}

/// Reads "min-max": two decimal numbers of 32 bits, without a sign or a
/// leading zero, the first not above the second.
pub fn parse_range(s: &str) -> Option<Range> {
    let (lo, hi) = s.split_once('-')?;
    let (min, max) = (parse_u32(lo)?, parse_u32(hi)?);
    (min <= max).then_some(Range { min, max })
}

fn parse_u32(s: &str) -> Option<u32> {
    if s.is_empty() || s.len() > 10 || (s.len() > 1 && s.starts_with('0')) || !s.bytes().all(|c| c.is_ascii_digit()) {
        return None;
    }
    s.parse().ok()
}

/// 32 bytes, not all zeros, in standard base64's one form: padded, no
/// stray bits.
fn key(s: &str) -> Option<[u8; 32]> {
    let b = STANDARD.decode(s).ok()?;
    if STANDARD.encode(&b) != s {
        return None;
    }
    let k: [u8; 32] = b.try_into().ok()?;
    (k != [0u8; 32]).then_some(k)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn good() -> Value {
        json!({"jc": 4, "jmin": 40, "jmax": 300, "s1": 20, "s2": 30, "s3": 16, "s4": 24,
            "h1": "100-200", "h2": "1073741840-1073807375", "h3": "2147483664-2147483664", "h4": "3221225488-4294967295",
            "header_protection_key": "BQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQU="})
    }

    #[test]
    fn reads_and_writes_the_settings() {
        let o = from_json(&good()).unwrap();
        assert_eq!(o.jc, 4);
        assert_eq!(o.h[1], Range { min: 1073741840, max: 1073807375 });
        assert_eq!(o.header_protection_key, [5; 32]);
        assert_eq!(o.to_json(), good());
        assert_eq!(from_json(&o.to_json()).as_ref(), Some(&o));
        let shown = format!("{o:?}");
        assert!(!shown.contains("[5, 5"), "{shown}");
    }

    #[test]
    fn refuses_what_go_refuses() {
        let with = |k: &str, v: Value| {
            let mut g = good();
            g[k] = v;
            g
        };
        let mut missing = good();
        missing.as_object_mut().unwrap().remove("s4");
        let cases = [
            ("not an object", json!([])),
            ("a field missing", missing),
            ("a field unknown", with("x", json!(1))),
            ("jc as text", with("jc", json!("4"))),
            ("negative", with("jmin", json!(-1))),
            ("too many junk packets", with("jc", json!(17))),
            ("jmin above jmax", with("jmin", json!(301))),
            ("junk too large", with("jmax", json!(1001))),
            ("padding too small", with("s1", json!(15))),
            ("padding too large", with("s4", json!(65))),
            ("two handshakes of one size", with("s2", json!(76))),
            ("a header at a message type", with("h1", json!("4-200"))),
            ("headers that overlap", with("h2", json!("150-1073807375"))),
            ("a range turned round", with("h1", json!("200-100"))),
            ("a leading zero", with("h1", json!("0100-200"))),
            ("a sign", with("h1", json!("+100-200"))),
            ("no dash", with("h1", json!("100"))),
            ("above 32 bits", with("h4", json!("3221225488-4294967296"))),
            ("an empty number", with("h1", json!("-200"))),
            ("a key of zeros", with("header_protection_key", json!("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="))),
            ("a short key", with("header_protection_key", json!("BQUF"))),
            ("a key unpadded", with("header_protection_key", json!("BQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQU"))),
            ("a key not base64", with("header_protection_key", json!("!"))),
        ];
        for (name, v) in cases {
            assert!(from_json(&v).is_none(), "{name}");
        }
    }
}
