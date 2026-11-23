// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The core's verdicts on a corpus of tools/difffuzz
//! (docs/differential.md): one line per case, which the comparison checks
//! against the other implementations' lines. A child of `command`, so that
//! it reads a command's fields. It runs on the corpus that
//! CBB_VERDICTS names and writes to CBB_VERDICTS_OUT; without them, on a
//! corpus of its own.

use std::fmt::Write as _;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use serde_json::Value;

use super::Command;
use crate::certs::sha256;

fn hex(b: &[u8]) -> String {
    b.iter().fold(String::new(), |mut s, x| {
        let _ = write!(s, "{x:02x}");
        s
    })
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
        "manifest" => {
            let ok = crate::media::Manifest::parse(&body).is_ok();
            if ok { "taken" } else { "refused" }.into()
        }
        "keys" | "release" | "channel" | "attest-status" => {
            let ok = body.len() <= crate::release::MAX_BODY
                && match kind {
                    "keys" => crate::release::decode_keys(&body).is_ok(),
                    "release" => crate::release::decode_release(&body).is_ok(),
                    "channel" => crate::release::decode_channel(&body).is_ok(),
                    _ => crate::release::decode_status(&body).is_ok(),
                };
            if ok { "taken" } else { "refused" }.into()
        }
        _ => panic!("unknown kind {kind}"),
    }
}

#[test]
fn verdicts() {
    let (input, out) = match (std::env::var("CBB_VERDICTS"), std::env::var("CBB_VERDICTS_OUT")) {
        (Ok(i), Ok(o)) if !i.is_empty() => (std::fs::read_to_string(i).unwrap(), Some(o)),
        _ => (
            "{\"kind\":\"command\",\"body\":\"e30=\"}\n{\"kind\":\"attest-status\",\"body\":\"e30=\"}\n".to_string(),
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
        None => assert_eq!(lines, "refused\nrefused\n"),
    }
}
