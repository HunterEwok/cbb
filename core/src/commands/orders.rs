// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The orders of each command type (format section 6), the map inside
//! `sealed`. A field below 256 that a type does not define refuses the
//! orders (a command is never held); fields from 256 up are skipped.

use crate::format::Rule;
use crate::format::cbor::{self, Value};

use super::{COMMAND_ACTION, COMMAND_DEVICE, COMMAND_HUB, COMMAND_MODE, COMMAND_MUTE, COMMAND_PASTE};

pub const RULE_MODE: Rule = Rule::field("orders/mode");
pub const RULE_HUB: Rule = Rule::field("orders/hub");
pub const RULE_PASTE: Rule = Rule::field("orders/paste");
pub const RULE_ACTION: Rule = Rule::field("orders/action");
pub const RULE_MUTE: Rule = Rule::field("orders/mute");
pub const RULE_DEVICE: Rule = Rule::field("orders/device");

/// The longest text of a paste, and of one typed out (format 20.6: 16 KiB
/// for a member; a leaf takes what its 16 KiB frame holds beside the
/// command's envelope).
pub const MAX_PASTE_TEXT: usize = 1 << 20;
pub const MAX_TYPED_TEXT: usize = 16 << 10;
/// The longest mute.
pub const MAX_MUTE_MS: u64 = 2_592_000_000;
/// A device command's arguments.
pub const MAX_ARGS: usize = 4 << 10;

fn only(m: &Value<'_>, fields: &[u16]) -> Result<(), Rule> {
    let entries = m.as_map().ok_or(Rule::FORM_CRITICAL)?;
    if entries.iter().any(|(k, _)| *k < 256 && !fields.contains(k)) {
        return Err(Rule::FORM_CRITICAL);
    }
    Ok(())
}

fn flag(v: Option<&Value<'_>>, rule: Rule) -> Result<bool, Rule> {
    match v {
        None => Ok(false),
        Some(Value::Uint(1)) => Ok(true),
        Some(_) => Err(rule),
    }
}

/// A hidden character (format 20.1): C0, DEL, C1, U+2028 to U+202E and
/// U+2066 to U+2069.
fn hidden(c: char) -> bool {
    matches!(c, '\u{0}'..='\u{1f}' | '\u{7f}'..='\u{9f}' | '\u{2028}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
}

/// A name of 1 to 32 bytes of `a-z 0-9 -`, starting with a letter.
/// A hub's endpoint or forwarder: 1 to 255 bytes, nothing hidden.
fn plain_text(t: &str) -> bool {
    (1..=255).contains(&t.len()) && !t.chars().any(hidden)
}

fn action_name(t: &str) -> bool {
    (1..=32).contains(&t.len())
        && t.starts_with(|c: char| c.is_ascii_lowercase())
        && t.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// Checks opened orders of type t against the type's rows.
pub fn check(t: u64, b: &[u8]) -> Result<(), Rule> {
    let m = cbor::decode(b)?;
    match t {
        COMMAND_MODE => {
            only(&m, &[10])?;
            if !matches!(m.get(10), Some(Value::Uint(1 | 2))) {
                return Err(RULE_MODE);
            }
        }
        COMMAND_HUB => {
            only(&m, &[10, 11, 12, 13])?;
            if flag(m.get(13), RULE_HUB)? {
                if m.as_map().is_some_and(|e| e.iter().any(|(k, _)| *k < 256 && *k != 13)) {
                    return Err(RULE_HUB);
                }
                return Ok(());
            }
            match m.get(10).and_then(Value::as_array) {
                Some([Value::Text(e), Value::Bytes(k)]) if plain_text(e) && k.len() == 32 => {}
                None if m.get(10).is_none() => {}
                _ => return Err(RULE_HUB),
            }
            if let Some(v) = m.get(11) {
                let a = v.as_array().ok_or(RULE_HUB)?;
                let distinct = a.iter().enumerate().all(|(i, x)| a.get(..i).is_some_and(|p| !p.contains(x)));
                if a.is_empty() || a.len() > 8 || !distinct || !a.iter().all(|x| x.as_text().is_some_and(plain_text)) {
                    return Err(RULE_HUB);
                }
            }
            if let Some(v) = m.get(12) {
                let a = v.as_array().ok_or(RULE_HUB)?;
                let ok = |c: &Value<'_>| {
                    matches!(c.as_array(), Some([Value::Bytes(id), Value::Bytes(k), Value::Bytes(p)])
                        if id.len() == 16 && k.len() == 32 && p.len() == 32)
                };
                if a.is_empty() || a.len() > 256 || !cbor::is_set(a) || !a.iter().all(ok) {
                    return Err(RULE_HUB);
                }
            }
            if m.as_map().is_some_and(|e| e.iter().all(|(k, _)| *k >= 256)) {
                return Err(RULE_HUB);
            }
        }
        COMMAND_PASTE => {
            only(&m, &[10, 11, 12, 13, 14])?;
            let way = m.get(10).and_then(Value::as_uint).filter(|w| matches!(w, 1 | 2)).ok_or(RULE_PASTE)?;
            flag(m.get(11), RULE_PASTE)?;
            let kind = m.get(12).and_then(Value::as_uint).filter(|k| (1..=3).contains(k)).ok_or(RULE_PASTE)?;
            match (kind, m.get(13), m.get(14)) {
                (1 | 2, Some(Value::Text(t)), None) => {
                    let max = if way == 2 { MAX_TYPED_TEXT } else { MAX_PASTE_TEXT };
                    if t.is_empty() || t.len() > max {
                        return Err(RULE_PASTE);
                    }
                }
                (3, None, Some(Value::Bytes(id))) if id.len() == 16 && way == 1 => {}
                _ => return Err(RULE_PASTE),
            }
        }
        COMMAND_ACTION => {
            only(&m, &[10])?;
            if !m.get(10).and_then(Value::as_text).is_some_and(action_name) {
                return Err(RULE_ACTION);
            }
        }
        COMMAND_MUTE => {
            only(&m, &[10])?;
            match m.get(10) {
                None => {}
                Some(Value::Uint(n)) if (1..=MAX_MUTE_MS).contains(n) => {}
                Some(_) => return Err(RULE_MUTE),
            }
        }
        COMMAND_DEVICE => {
            only(&m, &[10, 11])?;
            let name = m.get(10).and_then(Value::as_text).ok_or(RULE_DEVICE)?;
            if name.is_empty() || name.len() > 32 || name.chars().any(hidden) {
                return Err(RULE_DEVICE);
            }
            if let Some(a) = m.get(11) {
                let a = a.as_bytes().ok_or(RULE_DEVICE)?;
                if a.is_empty() || a.len() > MAX_ARGS || cbor::check(a).is_err() {
                    return Err(RULE_DEVICE);
                }
            }
        }
        _ => return Err(super::RULE_TYPE),
    }
    Ok(())
}
