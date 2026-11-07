// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The lite member's verdicts on a corpus of tools/difffuzz
//! (docs/differential.md): one line per case, which the comparison checks
//! against the other implementations' lines. A child of `command`, so that
//! it reads a command's fields; records are of version 2 (`crate::group`). It runs on the corpus that
//! CBB_VERDICTS names and writes to CBB_VERDICTS_OUT; without them, on a
//! corpus of its own.

use std::fmt::Write as _;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use serde_json::Value;

use super::Command;
use crate::authority::{Hash, Record};
use crate::certs::{Cert, KeyHash, sha256};
use crate::group::Records;

fn hex(b: &[u8]) -> String {
    b.iter().fold(String::new(), |mut s, x| {
        let _ = write!(s, "{x:02x}");
        s
    })
}

fn hashes(l: &[KeyHash]) -> String {
    l.iter().map(|k| hex(k)).collect::<Vec<_>>().join(".")
}

fn opt(k: &Option<KeyHash>) -> String {
    k.as_ref().map(|k| hex(k)).unwrap_or_default()
}

fn bit(b: bool) -> &'static str {
    if b { "1" } else { "0" }
}

fn bytes(v: &Value) -> Vec<u8> {
    v.as_str().map(|s| STANDARD.decode(s).unwrap()).unwrap_or_default()
}

fn taken(pairs: &[(&str, String)]) -> String {
    let mut s = String::from("taken");
    for (k, v) in pairs {
        let _ = write!(s, " {k}={v}");
    }
    s
}

fn verdict(c: &Value) -> String {
    let kind = c["kind"].as_str().unwrap();
    let body = bytes(&c["body"]);
    match kind {
        "record" => match crate::authority::Body::parse(&body) {
            Err(_) => "refused".into(),
            Ok(b) => {
                let h = |k: &Option<Hash>| k.map(|k| hex(&k.0)).unwrap_or_default();
                let l = |ks: &[Hash]| ks.iter().map(|k| hex(&k.0)).collect::<Vec<_>>().join(".");
                taken(&[
                    ("type", hex(b.kind.as_bytes())),
                    ("group", hex(b.group.as_bytes())),
                    ("signer", hex(&b.signer.0)),
                    ("seq", b.seq.to_string()),
                    ("prev", h(&b.prev)),
                    ("time_ms", b.time_ms.to_string()),
                    ("device", hex(b.device.as_bytes())),
                    ("name", hex(b.name.as_bytes())),
                    ("role", hex(b.role.as_bytes())),
                    ("os", hex(b.os.as_bytes())),
                    ("store", hex(b.store.as_bytes())),
                    ("key", h(&b.key)),
                    ("admin", h(&b.admin)),
                    ("powers", b.powers.join(".")),
                    ("commands", b.commands.join(".")),
                    ("holds_root", bit(b.holds_root).into()),
                    ("keys", l(&b.keys)),
                    ("root", hex(&b.root)),
                    ("records", l(&b.records)),
                ])
            }
        },
        "command" => match Command::parse(&body) {
            Err(_) => "refused".into(),
            Ok(b) => taken(&[
                ("type", hex(b.kind.as_bytes())),
                ("group", hex(b.group.as_bytes())),
                ("by", hex(b.by.as_bytes())),
                ("to", hex(b.to.as_bytes())),
                ("id", hex(b.id.as_bytes())),
                ("time_ms", b.time_ms.to_string()),
                ("expires_ms", b.expires_ms.to_string()),
                ("mode", hex(b.mode.as_bytes())),
                ("enter", bit(b.enter).into()),
                ("kind", hex(b.paste_kind.as_bytes())),
                ("text", hex(&sha256(b.text.as_bytes()))),
                ("action", hex(b.action.as_bytes())),
            ]),
        },
        "credential" => match crate::credential::Body::parse(&body) {
            Err(_) => "refused".into(),
            Ok(b) => taken(&[
                ("type", hex(b.kind.as_bytes())),
                ("group", hex(b.group.as_bytes())),
                ("version", b.version.to_string()),
                ("expires_ms", b.expires_ms.to_string()),
                ("tag", hex(b.tag.as_bytes())),
                ("key", hex(&b.key)),
                ("hubs", hashes(&b.hubs)),
                ("admins", hashes(&b.admins)),
                ("members", hashes(&b.members)),
            ]),
        },
        "manifest" => {
            let ok = crate::media::Manifest::parse(&body).is_ok();
            if ok { "taken" } else { "refused" }.into()
        }
        "keys" | "release" | "channel" => {
            let ok = body.len() <= crate::release::MAX_BODY
                && match kind {
                    "keys" => crate::release::decode_keys(&body).is_ok(),
                    "release" => crate::release::decode_release(&body).is_ok(),
                    _ => crate::release::decode_channel(&body).is_ok(),
                };
            if ok { "taken" } else { "refused" }.into()
        }
        // The lite member reads no attest-status.json.
        "attest-status" => "skip".into(),
        "set" => set(c),
        _ => panic!("unknown kind {kind}"),
    }
}

fn set(c: &Value) -> String {
    let mut s = Records::new(&Cert::parse(&bytes(&c["ca"])).unwrap());
    let rs: Vec<Record> = serde_json::from_value(c.get("records").cloned().unwrap_or(Value::Array(vec![]))).unwrap();
    let (fresh, _) = s.add_all(&rs);
    let roots: Vec<String> = s.roots().iter().map(|r| hex(&sha256(&r.der))).collect();
    let devices: Vec<String> = s
        .devices()
        .iter()
        .map(|d| {
            [
                hex(d.id.as_bytes()),
                hex(d.name.as_bytes()),
                hex(d.role.as_bytes()),
                hex(d.store.as_bytes()),
                bit(d.admin).into(),
                opt(&d.admin_key),
                bit(d.frozen).into(),
            ]
            .join(":")
        })
        .collect();
    let (mut revoked, mut frozen) = (String::new(), String::new());
    for k in c.get("keys").and_then(Value::as_array).into_iter().flatten() {
        let k: KeyHash = bytes(k).try_into().unwrap();
        revoked.push_str(bit(s.revoked(&k)));
        frozen.push_str(bit(s.frozen(&k)));
    }
    format!(
        "set taken={} roots={} devices={} revoked={revoked} frozen={frozen} digest={}",
        fresh.len(),
        roots.join("."),
        devices.join("."),
        s.digest()
    )
}

#[test]
fn verdicts() {
    let (input, out) = match (std::env::var("CBB_VERDICTS"), std::env::var("CBB_VERDICTS_OUT")) {
        (Ok(i), Ok(o)) if !i.is_empty() => (std::fs::read_to_string(i).unwrap(), Some(o)),
        _ => (
            "{\"kind\":\"record\",\"body\":\"e30=\"}\n{\"kind\":\"attest-status\",\"body\":\"e30=\"}\n".to_string(),
            None,
        ),
    };
    let mut lines = String::new();
    for line in input.lines() {
        let c: Value = serde_json::from_str(line).unwrap();
        lines.push_str(&verdict(&c));
        lines.push('\n');
    }
    match out {
        Some(o) => std::fs::write(o, lines).unwrap(),
        None => assert_eq!(lines, "refused\nskip\n"),
    }
}
