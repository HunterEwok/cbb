// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! What a copy carries, inside its sealed payload (format section 10.3):
//! one envelope "type, flags, data" for every kind of content (A-2), and a
//! secret flag that any type may carry (A-3).
//!
//! The content is a map in the format's profile, padded to one of the
//! content steps. Field 0 is its type: 1 text, 2 clipboard media, 3 files,
//! 4 a device's state (A-17). A reader that meets a type, a flag or a
//! critical field (below 256) it does not know reads the content as
//! [`Content::unknown`]: it keeps the copy and passes it on, and never
//! writes it to a clipboard. So a later version adds kinds of content
//! without an older device writing what it does not understand.

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::format::Rule;
use crate::format::cbor::{self, Value};
use crate::format::copy::{read_content, write_content};
use crate::media;

mod nfc;

/// Text.
pub const TYPE_TEXT: u64 = 1;
/// Clipboard media: images, formatted text.
pub const TYPE_MEDIA: u64 = 2;
/// Files and folders.
pub const TYPE_FILES: u64 = 3;
/// A device's state (A-17): a CBOR item its firmware defines.
pub const TYPE_STATE: u64 = 4;
/// The highest type 0.6 knows.
pub const MAX_TYPE: u64 = TYPE_STATE;

/// The content is a secret (A-3): any type may be one.
pub const FLAG_SECRET: u64 = 1;
/// The flags 0.6 knows.
pub const KNOWN_FLAGS: u64 = FLAG_SECRET;

/// The fixed lifetimes of `ttl`: one minute, ten minutes, one hour, one day.
pub const TTLS_MS: [u64; 4] = [60_000, 600_000, 3_600_000, 86_400_000];

/// The largest device state.
pub const MAX_STATE: usize = 4 << 10;

/// A content field's type or value out of its row.
pub const RULE_TYPE: Rule = Rule::field("content/type");
pub const RULE_FLAGS: Rule = Rule::field("content/flags");
pub const RULE_TTL: Rule = Rule::field("content/ttl");
pub const RULE_VIA: Rule = Rule::field("content/via");
/// Text missing where its type needs it, or not text.
pub const RULE_TEXT: Rule = Rule::field("content/text");
/// A manifest missing on media or files, present on another type, or one
/// the rules of manifests refuse.
pub const RULE_MANIFEST: Rule = Rule::field("content/manifest");
/// A state missing on type 4, present on another type, larger than 4 KiB
/// or not one item of the profile.
pub const RULE_DATA: Rule = Rule::field("content/data");

const F_TYPE: u16 = 0;
const F_PAD: u16 = 1;
const F_FLAGS: u16 = 2;
const F_TTL: u16 = 3;
const F_VIA: u16 = 4;
const F_TEXT: u16 = 5;
const F_MANIFEST: u16 = 6;
const F_DATA: u16 = 7;
/// The fields below 256 that 0.6 defines.
const FIELDS: [u16; 8] = [F_TYPE, F_PAD, F_FLAGS, F_TTL, F_VIA, F_TEXT, F_MANIFEST, F_DATA];

/// A copy's content, read or to write.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct Content {
    /// The type (field 0).
    pub kind: u64,
    /// The flags (field 2), bits.
    pub flags: u64,
    /// The lifetime, 1 to 4 (field 3); 0 for the group's `incoming_ms`.
    pub ttl: u64,
    /// 1 phone, 2 universal clipboard (field 4); 0 for a copy.
    pub via: u64,
    /// The text, or a plain-text alternative (field 5).
    pub text: Option<String>,
    /// The manifest of media or files (field 6).
    pub manifest: Option<media::Manifest>,
    /// A device's state (field 7).
    pub data: Option<Vec<u8>>,
    /// A type, flag or critical field this version does not know: the copy
    /// is kept and passed on, never written.
    pub unknown: bool,
}

impl Content {
    /// A text, secret or not.
    pub fn text(text: &str, secret: bool) -> Content {
        Content {
            kind: TYPE_TEXT,
            flags: if secret { FLAG_SECRET } else { 0 },
            text: Some(text.to_string()),
            ..Content::default()
        }
    }

    /// A device's state, a CBOR item its firmware defines.
    pub fn state(data: &[u8]) -> Content {
        Content { kind: TYPE_STATE, data: Some(data.to_vec()), ..Content::default() }
    }

    /// Reports whether the content is a secret.
    pub fn is_secret(&self) -> bool {
        self.flags & FLAG_SECRET != 0
    }

    /// Reports whether a reader may write the content to its clipboard:
    /// a type it knows, with nothing in it it does not understand, and not
    /// a device's state (which an app shows, never pastes).
    pub fn writable(&self) -> bool {
        !self.unknown && matches!(self.kind, TYPE_TEXT | TYPE_MEDIA | TYPE_FILES)
    }

    /// The lifetime its `ttl` names, or None for the group's.
    pub fn ttl_ms(&self) -> Option<u64> {
        let i = usize::try_from(self.ttl.checked_sub(1)?).ok()?;
        TTLS_MS.get(i).copied()
    }

    /// Checks the rows between fields: what [`Content::read`] refuses.
    pub fn check(&self) -> Result<(), Rule> {
        if self.kind == 0 || self.kind > cbor::MAX_INT {
            return Err(RULE_TYPE);
        }
        if self.ttl > TTLS_MS.len() as u64 {
            return Err(RULE_TTL);
        }
        if self.via > 2 {
            return Err(RULE_VIA);
        }
        if self.text.as_deref() == Some("") {
            return Err(Rule::FORM_DEFAULT);
        }
        match self.kind {
            TYPE_TEXT if self.text.is_none() => return Err(RULE_TEXT),
            TYPE_MEDIA | TYPE_FILES => {
                let files = self.kind == TYPE_FILES;
                let m = self.manifest.as_ref().ok_or(RULE_MANIFEST)?;
                if m.files() != files || m.validate().is_err() || (files && !names_ok(m)) {
                    return Err(RULE_MANIFEST);
                }
                if self.text.as_ref().is_some_and(|t| t.len() > media::MAX_ALT_TEXT) {
                    return Err(RULE_TEXT);
                }
            }
            TYPE_STATE => {
                let d = self.data.as_ref().ok_or(RULE_DATA)?;
                if d.is_empty() || d.len() > MAX_STATE || cbor::check(d).is_err() {
                    return Err(RULE_DATA);
                }
            }
            _ => {}
        }
        let known = self.kind <= MAX_TYPE;
        if known && self.manifest.is_some() && !matches!(self.kind, TYPE_MEDIA | TYPE_FILES) {
            return Err(RULE_MANIFEST);
        }
        if known && self.data.is_some() && self.kind != TYPE_STATE {
            return Err(RULE_DATA);
        }
        if known && self.kind == TYPE_STATE && self.text.is_some() {
            return Err(RULE_TEXT);
        }
        Ok(())
    }

    /// Encodes the content padded to its step; None when it breaks a row,
    /// says it is unknown, or is larger than 4 MiB.
    pub fn write(&self) -> Option<Vec<u8>> {
        if self.unknown || self.check().is_err() {
            return None;
        }
        let manifest = self.manifest.as_ref().map(encode_manifest);
        let manifest = match &manifest {
            Some(Some(b)) => Some(cbor::decode(b).ok()?),
            Some(None) => return None,
            None => None,
        };
        let nz = |n: u64| (n != 0).then_some(Value::Uint(n));
        let fields: [(u16, Option<Value<'_>>); 7] = [
            (F_TYPE, Some(Value::Uint(self.kind))),
            (F_FLAGS, nz(self.flags)),
            (F_TTL, nz(self.ttl)),
            (F_VIA, nz(self.via)),
            (F_TEXT, self.text.as_deref().map(Value::Text)),
            (F_MANIFEST, manifest),
            (F_DATA, self.data.as_deref().map(Value::Bytes)),
        ];
        let m: Vec<(u16, Value<'_>)> = fields.into_iter().filter_map(|(k, v)| v.map(|v| (k, v))).collect();
        write_content(&Value::Map(m))
    }

    /// Reads a content opened from a payload: the profile, the one padding
    /// of its step, each known field's row and the rows between them.
    /// What this version does not know marks it [`Content::unknown`].
    pub fn read(b: &[u8]) -> Result<Content, Rule> {
        let v = read_content(b)?;
        let entries = v.as_map().unwrap_or(&[]);
        let uint = |f, rule| match v.get(f) {
            None => Ok(0),
            Some(Value::Uint(0)) => Err(Rule::FORM_DEFAULT),
            Some(x) => x.as_uint().ok_or(rule),
        };
        let kind = v.get(F_TYPE).and_then(Value::as_uint).filter(|k| *k > 0).ok_or(RULE_TYPE)?;
        let flags = uint(F_FLAGS, RULE_FLAGS)?;
        let ttl = uint(F_TTL, RULE_TTL)?;
        let via = uint(F_VIA, RULE_VIA)?;
        let text = match v.get(F_TEXT) {
            None => None,
            Some(t) => Some(t.as_text().ok_or(RULE_TEXT)?.to_string()),
        };
        let manifest = match v.get(F_MANIFEST) {
            None => None,
            Some(m) => Some(read_manifest(m)?),
        };
        let data = match v.get(F_DATA) {
            None => None,
            Some(d) => Some(d.as_bytes().ok_or(RULE_DATA)?.to_vec()),
        };
        let unknown = kind > MAX_TYPE
            || flags & !KNOWN_FLAGS != 0
            || entries.iter().any(|(k, _)| *k < 256 && !FIELDS.contains(k));
        let c = Content { kind, flags, ttl, via, text, manifest, data, unknown };
        c.check()?;
        Ok(c)
    }
}

/// Whether a character is a bidirectional control (Unicode's Bidi_Control:
/// U+061C, U+200E, U+200F, U+202A to U+202E, U+2066 to U+2069).
fn bidi(c: char) -> bool {
    matches!(c, '\u{61c}' | '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
}

/// Whether NFC would leave a path as it is: no code point NFC changes
/// alone (NFC_Quick_Check No), and none that composes with the one before
/// it. A sender writes names in NFC; marks with nothing to compose with
/// (Hindi vowel signs, Arabic harakat, Hebrew niqqud) stay.
fn nfc(path: &str) -> bool {
    use core::cmp::Ordering;
    let changed = |c: u32| {
        nfc::NO
            .binary_search_by(|(lo, hi)| {
                if *hi < c {
                    Ordering::Less
                } else if *lo > c {
                    Ordering::Greater
                } else {
                    Ordering::Equal
                }
            })
            .is_ok()
    };
    let composes = |a: u32, b: u32| {
        let lv = (0x1100..=0x1112).contains(&a) && (0x1161..=0x1175).contains(&b);
        let lvt = (0xac00..=0xd7a3).contains(&a)
            && a.wrapping_sub(0xac00).is_multiple_of(28)
            && (0x11a8..=0x11c2).contains(&b);
        lv || lvt || nfc::PAIRS.binary_search(&(a, b)).is_ok()
    };
    let mut prev = None;
    for c in path.chars().map(u32::from) {
        if changed(c) || prev.is_some_and(|p| composes(p, c)) {
            return false;
        }
        prev = Some(c);
    }
    true
}

/// A path as systems that ignore case compare it: each character in lower
/// case (the first of its lower case when that is longer).
fn fold(path: &str) -> String {
    path.chars().map(|c| c.to_lowercase().next().unwrap_or(c)).collect()
}

/// The rules of 0.6 on the names of files, over today's: no device name of
/// Windows (`media::device`: CON, PRN, AUX, NUL, CONIN$, CONOUT$, COM and
/// LPT with a digit or a superscript, with or without an extension), no
/// bidirectional control, nothing NFC would change, and no two
/// paths that are one when case is ignored, nor a path inside a file so.
fn names_ok(m: &media::Manifest) -> bool {
    let mut seen = alloc::collections::BTreeMap::new();
    for p in &m.parts {
        if p.path.split('/').any(media::device) || p.path.chars().any(bidi) || !nfc(&p.path) {
            return false;
        }
        if seen.insert(fold(&p.path), p.dir).is_some() {
            return false;
        }
    }
    seen.keys().all(|path| path.match_indices('/').all(|(i, _)| seen.get(&path[..i]) != Some(&false)))
}

/// The manifest's CBOR form: 1 `size`; 2 `parts`, 1 to 10 000 maps of
/// 1 `type` (1 png, 2 jpeg, 3 gif, 4 html), 2 `path`, 3 `dir` (1),
/// 4 `size`, 5 `sha256` bytes 32. Today's rules on manifests apply.
const MEDIA_TYPES: [&str; 4] = ["image/png", "image/jpeg", "image/gif", "text/html"];

fn read_manifest(v: &Value<'_>) -> Result<media::Manifest, Rule> {
    let m = v.as_map().ok_or(RULE_MANIFEST)?;
    if m.iter().any(|(k, _)| *k < 256 && !matches!(k, 1 | 2)) {
        return Err(RULE_MANIFEST);
    }
    let size = match v.get(1) {
        None => 0,
        Some(Value::Uint(0)) => return Err(Rule::FORM_DEFAULT),
        Some(s) => s.as_uint().and_then(|s| i64::try_from(s).ok()).ok_or(RULE_MANIFEST)?,
    };
    let list = v.get(2).and_then(Value::as_array).ok_or(RULE_MANIFEST)?;
    if list.is_empty() || list.len() > media::MAX_PARTS {
        return Err(RULE_MANIFEST);
    }
    let mut parts = Vec::with_capacity(list.len());
    for p in list {
        let pm = p.as_map().ok_or(RULE_MANIFEST)?;
        if pm.iter().any(|(k, _)| *k < 256 && !(1..=5).contains(k)) {
            return Err(RULE_MANIFEST);
        }
        let kind = match p.get(1) {
            None => String::new(),
            Some(t) => {
                let i = t.as_uint().and_then(|n| usize::try_from(n).ok()).and_then(|n| n.checked_sub(1));
                MEDIA_TYPES.get(i.ok_or(RULE_MANIFEST)?).ok_or(RULE_MANIFEST)?.to_string()
            }
        };
        let path = match p.get(2) {
            None => String::new(),
            Some(t) => t.as_text().filter(|t| !t.is_empty()).ok_or(RULE_MANIFEST)?.to_string(),
        };
        let dir = match p.get(3) {
            None => false,
            Some(Value::Uint(1)) => true,
            Some(_) => return Err(RULE_MANIFEST),
        };
        let size = match p.get(4) {
            None => 0,
            Some(Value::Uint(0)) => return Err(Rule::FORM_DEFAULT),
            Some(s) => s.as_uint().and_then(|s| i64::try_from(s).ok()).ok_or(RULE_MANIFEST)?,
        };
        let sha256 = match p.get(5) {
            None => None,
            Some(h) => Some(h.as_bytes().filter(|h| h.len() == 32).ok_or(RULE_MANIFEST)?.to_vec()),
        };
        parts.push(media::Part { kind, path, dir, size, sha256 });
    }
    Ok(media::Manifest { size, parts })
}

fn encode_manifest(m: &media::Manifest) -> Option<Vec<u8>> {
    let mut parts = Vec::with_capacity(m.parts.len());
    for p in &m.parts {
        let mut e: Vec<(u16, Value<'_>)> = Vec::new();
        if !p.kind.is_empty() {
            let i = MEDIA_TYPES.iter().position(|t| *t == p.kind)?;
            e.push((1, Value::Uint(u64::try_from(i).ok()?.checked_add(1)?)));
        }
        if !p.path.is_empty() {
            e.push((2, Value::Text(&p.path)));
        }
        if p.dir {
            e.push((3, Value::Uint(1)));
        }
        if p.size != 0 {
            e.push((4, Value::Uint(u64::try_from(p.size).ok()?)));
        }
        if let Some(h) = &p.sha256 {
            e.push((5, Value::Bytes(h)));
        }
        parts.push(Value::Map(e));
    }
    let mut top: Vec<(u16, Value<'_>)> = Vec::new();
    if m.size != 0 {
        top.push((1, Value::Uint(u64::try_from(m.size).ok()?)));
    }
    top.push((2, Value::Array(parts)));
    Some(Value::Map(top).encode())
}

#[cfg(test)]
mod tests;
