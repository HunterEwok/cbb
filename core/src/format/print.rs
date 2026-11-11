// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! Items printed as text: [`diag`] in CBOR's diagnostic notation (as the
//! vectors write it), and [`describe`] with the field names of the format's
//! tables, for `cbb inspect` and for logs in debug builds.

use alloc::format;
use alloc::string::String;

use super::cbor::{self, Value};
use super::envelope::Envelope;

/// The value in diagnostic notation: integers in decimal, bytes as
/// `h'…'`, text as a JSON string, `[…]` and `{k: v, …}`.
pub fn diag(v: &Value<'_>) -> String {
    let mut s = String::new();
    write_diag(&mut s, v);
    s
}

fn write_diag(s: &mut String, v: &Value<'_>) {
    match v {
        Value::Uint(n) => s.push_str(&format!("{n}")),
        Value::Bytes(b) => {
            s.push_str("h'");
            hex(s, b);
            s.push('\'');
        }
        Value::Text(t) => json_string(s, t),
        Value::Array(a) => {
            s.push('[');
            for (i, x) in a.iter().enumerate() {
                if i > 0 {
                    s.push_str(", ");
                }
                write_diag(s, x);
            }
            s.push(']');
        }
        Value::Map(m) => {
            s.push('{');
            for (i, (k, x)) in m.iter().enumerate() {
                if i > 0 {
                    s.push_str(", ");
                }
                s.push_str(&format!("{k}: "));
                write_diag(s, x);
            }
            s.push('}');
        }
    }
}

fn hex(s: &mut String, b: &[u8]) {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    for c in b {
        for d in [c >> 4, c & 15] {
            s.push(char::from(DIGITS.get(usize::from(d)).copied().unwrap_or(b'0')));
        }
    }
}

fn json_string(s: &mut String, t: &str) {
    s.push('"');
    for c in t.chars() {
        match c {
            '"' => s.push_str("\\\""),
            '\\' => s.push_str("\\\\"),
            '\n' => s.push_str("\\n"),
            '\r' => s.push_str("\\r"),
            '\t' => s.push_str("\\t"),
            '\u{8}' => s.push_str("\\b"),
            '\u{c}' => s.push_str("\\f"),
            c if u32::from(c) < 0x20 => s.push_str(&format!("\\u{:04x}", u32::from(c))),
            c => s.push(c),
        }
    }
    s.push('"');
}

/// What an item is, for its field names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// A record's body (section 4).
    Record,
    /// A keys statement's body (section 5).
    Statement,
    /// A command's body (section 6).
    Command,
    /// A grant's body (section 7).
    Grant,
    /// A server credential's body (section 8).
    Credential,
    /// A message of a frame (section 9).
    Message,
    /// A copy's wire form (section 10.1).
    Copy,
    /// A copy's header (section 10.2).
    CopyHeader,
    /// A copy's content (section 10.3).
    Content,
}

const COMMON: [&str; 9] = ["", "type", "group", "signer", "number", "prev", "time_ms", "expires_ms", "signer2"];

const RECORD_TYPES: [&str; 13] = [
    "",
    "device",
    "revoke",
    "freeze",
    "thaw",
    "claim",
    "resolve",
    "settings",
    "copies",
    "checkpoint",
    "hubs",
    "recovery",
    "handover",
];

const MESSAGES: [&str; 26] = [
    "",
    "hello",
    "copy",
    "ping",
    "bye",
    "records",
    "have",
    "keys",
    "intro",
    "command",
    "result",
    "credentials",
    "release",
    "get",
    "missing",
    "tunnel",
    "hubs",
    "guest",
    "reach",
    "evidence",
    "grant",
    "nonce",
    "beacon",
    "reseal",
    "roots",
    "entries",
];

/// The names of the `os` numbers (device record field 17, `hello` field 3,
/// the joiner's info): a number this version does not name is kept as it
/// is and shown as unknown.
const OS: [&str; 12] =
    ["", "linux", "windows", "macos", "ios", "android", "aurora", "sailfish", "watchos", "wearos", "none", "harmonyos"];

/// The name of an `os` number, or "unknown" for one this version does not
/// name (a later version's system).
pub fn os_name(n: u64) -> &'static str {
    usize::try_from(n).ok().and_then(|i| OS.get(i)).copied().filter(|n| !n.is_empty()).unwrap_or("unknown")
}

fn record_field(typ: u64, k: u16) -> Option<&'static str> {
    let device = [
        "key",
        "name",
        "role",
        "rights",
        "skip",
        "",
        "caps",
        "os",
        "store",
        "proof",
        "admin",
        "powers",
        "commands",
        "holds_root",
        "replaces",
        "guarded",
    ];
    let i = usize::from(k.checked_sub(10)?);
    match typ {
        1 => device.get(i).copied().filter(|n| !n.is_empty()),
        2 | 3 => ["keys", "seen"].get(i).copied(),
        4 | 6 => ["records"].get(i).copied(),
        5 => ["root", "seen"].get(i).copied(),
        7 => ["takeover_delay_ms", "key_level", "min_rules", "", "shared", "servers"]
            .get(i)
            .copied()
            .filter(|n| !n.is_empty()),
        8 => ["incoming_ms"].get(i).copied(),
        9 => ["heads", "keep"].get(i).copied(),
        10 => ["hubs"].get(i).copied(),
        11 | 12 => ["admin"].get(i).copied(),
        _ => None,
    }
}

/// The name of field k of an item of kind, whose `type` (or message `t`)
/// is typ.
pub fn field_name(kind: Kind, typ: u64, k: u16) -> Option<&'static str> {
    let ki = usize::from(k);
    let common = || COMMON.get(ki).copied().filter(|n| !n.is_empty());
    match kind {
        Kind::Record => {
            if k == 4 {
                return Some("seq");
            }
            common().or_else(|| record_field(typ, k))
        }
        Kind::Statement => match k {
            4 => Some("epoch"),
            10 => Some("seal"),
            _ => common(),
        },
        Kind::Command => match k {
            4 => Some("n"),
            10 | 11 | 13..=15 => ["to", "id", "", "nonce", "epoch", "sealed"].get(ki.wrapping_sub(10)).copied(),
            _ => common(),
        },
        Kind::Grant => match k {
            1 => Some("type"),
            2 => Some("group"),
            3 => Some("signer"),
            4 => Some("counter"),
            10..=15 => {
                ["leaf", "life_ms", "commanders", "readers", "neighbors", "guarded"].get(ki.wrapping_sub(10)).copied()
            }
            16 => Some("time_ms"),
            17 => Some("root_counter"),
            _ => None,
        },
        Kind::Credential => match k {
            4 => Some("version"),
            10..=14 => ["tag", "key", "hubs", "admins", "members"].get(ki.wrapping_sub(10)).copied(),
            _ => common(),
        },
        Kind::Message => match (k, typ) {
            (0, _) => Some("t"),
            (1, _) => Some("pad"),
            (2..=21, 1) => [
                "caps",
                "os",
                "name",
                "wall_ms",
                "current",
                "records",
                "count",
                "",
                "mode",
                "muted",
                "muted_for_ms",
                "device",
                "key_store",
                "actions",
                "release_seq",
                "release_keys_seq",
                "entries_seq",
                "entries_keys_seq",
                "features",
                "keys_epoch",
            ]
            .get(ki.wrapping_sub(2))
            .copied()
            .filter(|n| !n.is_empty()),
            (2, 2) => Some("copy"),
            (2, 5 | 24) => Some("records"),
            (2, 6) => Some("ids"),
            (2, 7) => Some("keys"),
            (2, 8) => Some("records"),
            (3, 8) => Some("keys"),
            (2, 9) => Some("command"),
            (2, 20) => Some("grant"),
            (3, 20) => Some("admin"),
            _ => None,
        },
        Kind::Copy => {
            ["", "hdr", "age_ms", "wraps", "payload", "payload_hash", "sig"].get(ki).copied().filter(|n| !n.is_empty())
        }
        Kind::CopyHeader => ["", "id", "origin", "time", "readers", "blob", "commit", "reuse"]
            .get(ki)
            .copied()
            .filter(|n| !n.is_empty()),
        Kind::Content => ["type", "pad", "flags", "ttl", "via", "text", "manifest", "data"].get(ki).copied(),
    }
}

/// The value as diagnostic notation with the field names of its kind:
/// `{type(1): 1 device, group(2): h'…', …}`. A record's type and a
/// message's type carry their names too. Unknown fields print by number.
pub fn describe(kind: Kind, v: &Value<'_>) -> String {
    let Some(m) = v.as_map() else {
        return diag(v);
    };
    let typ_key = if kind == Kind::Message || kind == Kind::Content { 0 } else { 1 };
    let typ = v.get(typ_key).and_then(Value::as_uint).unwrap_or(0);
    let mut s = String::from("{");
    for (i, (k, x)) in m.iter().enumerate() {
        if i > 0 {
            s.push_str(", ");
        }
        match field_name(kind, typ, *k) {
            Some(name) => s.push_str(&format!("{name}({k}): ")),
            None => s.push_str(&format!("{k}: ")),
        }
        write_diag(&mut s, x);
        if let (Some("os"), Some(n)) = (field_name(kind, typ, *k), x.as_uint()) {
            s.push(' ');
            s.push_str(os_name(n));
        }
        if *k == typ_key {
            let label = match kind {
                Kind::Record => usize::try_from(typ).ok().and_then(|t| RECORD_TYPES.get(t)),
                Kind::Message => usize::try_from(typ).ok().and_then(|t| MESSAGES.get(t)),
                _ => None,
            };
            if let Some(l) = label.filter(|l| !l.is_empty()) {
                s.push(' ');
                s.push_str(l);
            }
        }
    }
    s.push('}');
    s
}

/// An envelope's encoding printed with its body's field names, or the
/// rule it breaks.
pub fn describe_envelope(kind: Kind, b: &[u8]) -> String {
    match cbor::decode(b).and_then(|v| Envelope::from_value(&v).map(|e| (e.map.clone(), e.sig.len(), e.sig2.is_some())))
    {
        Ok((map, sig_len, two)) => {
            let mut s = format!("envelope {{body: {}, sig: {sig_len} bytes", describe(kind, &map));
            if two {
                s.push_str(", sig2");
            }
            s.push('}');
            s
        }
        Err(rule) => format!("refused: {rule}"),
    }
}
