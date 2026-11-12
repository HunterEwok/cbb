// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The format's vectors in testdata/format, which a second reader in Go
//! (testdata/format/check) checks the same way.

use std::collections::HashMap;
use std::path::PathBuf;
use std::string::String;
use std::vec::Vec;

use serde_json::Value as Json;

use super::cbor::{self, Value};
use super::envelope::{self, Envelope};
use super::frame;
use super::key::{Alg, DeviceId, Key};
use super::print::{self, Kind};
use super::{Rule, container, copy, grant, sig};

fn load(name: &str) -> Json {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../testdata/format").join(name);
    serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap()
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|c| format!("{c:02x}")).collect()
}

fn s<'a>(v: &'a Json, k: &str) -> &'a str {
    v[k].as_str().unwrap_or_else(|| panic!("no {k} in {v}"))
}

/// The test keys by key hash: their points.
fn keys() -> HashMap<String, Vec<u8>> {
    let k = load("keys.json");
    let mut out = HashMap::new();
    for row in k["keys"].as_array().unwrap() {
        let enc = unhex(s(row, "key"));
        let v = cbor::decode(&enc).unwrap();
        let key = Key::from_value(&v).unwrap();
        key.check().unwrap();
        assert_eq!(key.encode(), enc);
        assert_eq!(hex(&key.hash().0), s(row, "key_hash"), "{}", s(row, "name"));
        assert_eq!(hex(&key.device_id().0), s(row, "id16"));
        if s(row, "name") == "root" {
            assert_eq!(hex(&key.device_id().0), s(&k, "group_id"));
        }
        out.insert(s(row, "key_hash").to_string(), key.public.to_vec());
    }
    out
}

#[test]
fn profile() {
    let p = load("profile.json");
    for t in p["vectors"].as_array().unwrap() {
        let b = unhex(s(t, "hex"));
        let got = cbor::decode(&b);
        if t["valid"].as_bool().unwrap() {
            let v = got.unwrap_or_else(|r| panic!("{}: refused by {r}", s(t, "name")));
            assert_eq!(v.encode(), b, "{}: one encoding", s(t, "name"));
            assert_eq!(print::diag(&v), s(t, "diag"), "{}", s(t, "name"));
        } else {
            assert_eq!(got.err().map(Rule::name), Some(s(t, "rule")), "{}", s(t, "name"));
        }
    }
}

#[test]
fn deep_and_wide_inputs_are_refused_quickly() {
    // A count over the limit is refused before any element is read.
    assert_eq!(cbor::decode(&[0x9a, 0, 1, 0, 0]), Err(Rule::COUNT));
    assert_eq!(cbor::decode(&[0xb9, 0x10, 0x01]), Err(Rule::COUNT));
    assert_eq!(cbor::decode(&[0x5b, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]), Err(Rule::TRUNCATED));
    // Map key 65535 is the last one allowed.
    assert!(cbor::decode(&[0xa1, 0x19, 0xff, 0xff, 0x00]).is_ok());
    // 4096 elements are allowed.
    let mut a = vec![0x99, 0x10, 0x00];
    a.extend(std::iter::repeat_n(0u8, 4096));
    assert!(cbor::decode(&a).is_ok());
}

/// Reads the signed vectors of a file: takes and holds read and verify;
/// refusals at the format level are refused with their rule.
fn signed(file: &str, by_key: bool) {
    let keys = keys();
    let f = load(file);
    let label = s(&f, "label");
    // A signer the test keys do not have (a field-level refusal) gets an
    // empty point, which verifies nothing.
    let signer_point = |e: &Envelope<'_>| -> Vec<u8> {
        let v = e.signer().unwrap();
        if by_key {
            let k = Key::from_value(v).unwrap();
            k.check().unwrap();
            k.public.to_vec()
        } else {
            keys.get(&hex(v.as_bytes().unwrap())).cloned().unwrap_or_default()
        }
    };
    for t in f["take"].as_array().unwrap() {
        let name = s(t, "name");
        let b = unhex(s(t, "envelope"));
        let e = Envelope::parse(&b).unwrap_or_else(|r| panic!("{name}: {r}"));
        e.verify(&signer_point(&e), label).unwrap_or_else(|r| panic!("{name}: {r}"));
        assert_eq!(hex(e.body), s(t, "body"), "{name}");
        if let Some(id) = t["id"].as_str() {
            assert_eq!(hex(&e.id()), id, "{name}");
        }
        assert_eq!(print::diag(&e.map), s(t, "diag"), "{name}");
        assert_eq!(e.map.encode(), e.body, "{name}: one encoding");
        assert_eq!(envelope::write(e.body, e.sig, e.sig2), b, "{name}: the envelope written again");
        if let Some(ad) = t["seal_ad"].as_str() {
            let rest: Vec<(u16, Value<'_>)> =
                e.map.as_map().unwrap().iter().filter(|(k, _)| *k != 15).cloned().collect();
            assert_eq!(hex(&sig::message(label, &Value::Map(rest).encode())), ad, "{name}");
        }
        if let Some(o) = t["orders"].as_str() {
            cbor::check(&unhex(o)).unwrap();
        }
        // Every body prints with its names without trouble.
        let kind = match file {
            "records.json" => Kind::Record,
            "statements.json" => Kind::Statement,
            "commands.json" => Kind::Command,
            _ => Kind::Credential,
        };
        assert!(print::describe(kind, &e.map).starts_with('{'));
        if let Some(os) = t["os_name"].as_str() {
            let n = t["os"].as_u64().unwrap();
            assert_eq!(print::os_name(n), os, "{name}");
            assert!(print::describe(kind, &e.map).contains(&format!("os(17): {n} {os}")), "{name}");
        }
        assert!(print::describe_envelope(kind, &b).starts_with("envelope"));
    }
    for t in f["refuse"].as_array().unwrap() {
        let name = s(t, "name");
        let rule = s(t, "rule");
        let b = unhex(s(t, "envelope"));
        let got = Envelope::parse(&b).and_then(|e| e.verify(&signer_point(&e), label));
        let format_level = ["cbor/", "env/", "sig/"].iter().any(|p| rule.starts_with(p));
        if format_level {
            assert_eq!(got.err().map(Rule::name), Some(rule), "{name}");
        } else if rule.starts_with("keys/") {
            // The form and the signature are good; the key in the body is not.
            got.unwrap_or_else(|r| panic!("{name}: {r}"));
        }
    }
}

#[test]
fn records() {
    signed("records.json", false);
}

#[test]
fn statements() {
    signed("statements.json", false);
}

#[test]
fn commands() {
    signed("commands.json", false);
}

#[test]
fn credentials() {
    signed("credentials.json", true);
}

#[test]
fn device_fields_are_the_ones_the_printer_names() {
    // One list of a device record's fields: the printer names each, and
    // names no other below 256 but expires_ms (7) and signer2 (8).
    let named: Vec<u16> =
        (0..256).filter(|&k| print::field_name(Kind::Record, 1, k).is_some() && k != 7 && k != 8).collect();
    assert_eq!(named, super::DEVICE_FIELDS);
}

#[test]
fn names_refuse_what_a_list_cannot_show() {
    let r = load("records.json");
    let mut refused = 0;
    for t in r["refuse"].as_array().unwrap() {
        if s(t, "rule") != "records/device/name" {
            continue;
        }
        let b = unhex(s(t, "envelope"));
        let e = Envelope::parse(&b).unwrap();
        assert!(!super::name_ok(e.map.get(11).and_then(Value::as_text).unwrap_or("")), "{}", s(t, "name"));
        refused += 1;
    }
    assert_eq!(refused, 7);
    for t in r["take"].as_array().unwrap() {
        let b = unhex(s(t, "envelope"));
        let e = Envelope::parse(&b).unwrap();
        if let Some(n) = e.map.get(11).and_then(Value::as_text).filter(|_| e.map.get(1) == Some(&Value::Uint(1))) {
            assert!(super::name_ok(n), "{}", s(t, "name"));
        }
    }
    let shown = print::diag(&Value::Text("a\u{9b}b\u{2028}c\u{202e}d\u{2069}e\u{7f}"));
    assert_eq!(shown, "\"a\\u009bb\\u2028c\\u202ed\\u2069e\\u007f\"");
    assert!(super::name_ok("Laptop \u{1F4BB}"));
}

#[test]
fn keys_of_the_wrong_size_or_off_the_curve() {
    let r = load("records.json");
    let st = load("statements.json");
    let mut seen = 0;
    for t in r["refuse"].as_array().unwrap().iter().chain(st["refuse"].as_array().unwrap()) {
        let rule = s(t, "rule");
        if !rule.starts_with("keys/") {
            continue;
        }
        let b = unhex(s(t, "envelope"));
        let e = Envelope::parse(&b).unwrap();
        let field = e.map.get(10).unwrap();
        let k = Key::from_value(field).unwrap();
        assert_eq!(k.check().err().map(Rule::name), Some(rule), "{}", s(t, "name"));
        seen += 1;
    }
    assert_eq!(seen, 3);
    assert_eq!(Key::new(Alg::X25519, &[0; 31]).check(), Err(Rule::KEYS_X25519));
    assert_eq!(Key::new(Alg::Unknown(4), &[1]).check(), Ok(()));
    assert_eq!(Key::from_value(&Value::Array(vec![Value::Uint(1)])), Err(Rule::KEYS_SHAPE));
}

#[test]
fn signatures_have_one_form() {
    let key = p256::ecdsa::SigningKey::from_slice(&[7u8; 32]).unwrap();
    let point = sig::public_point(&key);
    for i in 0..32u8 {
        let data = [i; 5];
        let sg = sig::sign_es256(&key, sig::LABEL_RECORD, &data);
        sig::verify_es256(&point, sig::LABEL_RECORD, &data, &sg).unwrap();
        assert_eq!(sig::verify_es256(&point, sig::LABEL_COMMAND, &data, &sg), Err(Rule::SIG_VERIFY));
    }
    assert_eq!(sig::check_form(&[1; 63]), Err(Rule::SIG_SIZE));
    assert_eq!(sig::check_form(&[1; 65]), Err(Rule::SIG_SIZE));
    let mut high = [0u8; 64];
    high[0] = 1;
    high[32] = 0x80;
    assert_eq!(sig::check_form(&high), Err(Rule::SIG_LOW_S));
    let mut big_r = [0xffu8; 64];
    big_r[32..].fill(1);
    assert_eq!(sig::check_form(&big_r), Err(Rule::SIG_RANGE));
}

#[test]
fn grants() {
    let keys = keys();
    let root = keys[&hex(&{
        let k = load("keys.json");
        let row = k["keys"].as_array().unwrap().iter().find(|r| s(r, "name") == "root").unwrap().clone();
        unhex(s(&row, "key_hash"))
    })]
        .clone();
    let g = load("grants.json");
    let group = DeviceId(unhex(s(&g, "group")).try_into().unwrap());
    let leaf_of = |t: &Json| DeviceId(unhex(s(t, "leaf")).try_into().unwrap());
    for t in g["take"].as_array().unwrap() {
        let msg = unhex(s(t, "message"));
        let v = cbor::decode(&msg).unwrap();
        let got = grant::read(&v, &root, &leaf_of(t), &group, None).unwrap_or_else(|r| panic!("{}: {r}", s(t, "name")));
        assert_eq!(got.guarded, s(t, "name").contains("guarded"));
        assert_eq!(got.admin.is_some(), s(t, "name").contains("admin"));
        assert_eq!(hex(got.grant.body), s(t, "grant"));
        assert_eq!(print::diag(&got.grant.map), s(t, "grant_diag"));
        assert!(print::describe(Kind::Grant, &got.grant.map).contains("signer(3)"));
        let fb = unhex(s(t, "frame"));
        let f = frame::read(&fb, frame::LIMIT_LEAF).unwrap();
        assert_eq!(f.t, 20);
        grant::read(&f.map, &root, &leaf_of(t), &group, None).unwrap();
    }
    for t in g["refuse"].as_array().unwrap() {
        let mb = unhex(s(t, "message"));
        let v = cbor::decode(&mb).unwrap();
        let got = grant::read(&v, &root, &leaf_of(t), &group, None);
        assert_eq!(got.err().map(Rule::name), Some(s(t, "rule")), "{}", s(t, "name"));
    }
    for q in g["sequences"].as_array().unwrap() {
        let mut kept: Option<grant::Kept> = None;
        for t in q["steps"].as_array().unwrap() {
            let name = format!("{}: {}", s(q, "name"), s(t, "name"));
            let mb = unhex(s(t, "message"));
            let v = cbor::decode(&mb).unwrap();
            match grant::read(&v, &root, &leaf_of(q), &group, kept.as_ref()) {
                Ok(got) => {
                    assert_eq!(s(t, "verdict"), "take", "{name}");
                    kept = Some(got.keep(kept.as_ref()));
                }
                Err(r) => assert_eq!(Some(r.name()), t["rule"].as_str(), "{name}"),
            }
        }
    }
    for t in g["copy_senders"].as_array().unwrap() {
        let gb = unhex(s(t, "grant"));
        let map = cbor::decode(&gb).unwrap();
        let origin = DeviceId(unhex(s(t, "origin")).try_into().unwrap());
        let got = grant::copy_sender(&map, &origin).err().map(Rule::name);
        let want = (s(t, "verdict") == "refuse").then(|| s(t, "rule"));
        assert_eq!(got, want, "{}", s(t, "name"));
    }
}

/// The set fields of a record type (section 1 "Sets"): sorted fields, and
/// `hubs`, each device once in the user's order.
fn record_sets(typ: u64) -> (&'static [u16], &'static [u16]) {
    match typ {
        1 => (&[26], &[]),
        2 | 3 | 4 | 9 => (&[10, 11], &[]),
        6 => (&[10], &[]),
        5 | 8 => (&[11], &[]),
        10 => (&[11], &[10]),
        _ => (&[], &[]),
    }
}

/// The field of a record type's `seen`, and whether it is required.
fn seen_field(typ: u64) -> Option<(u16, bool)> {
    match typ {
        1 => Some((26, false)),
        2 | 3 | 5 => Some((11, false)),
        4 | 8 | 10 => Some((11, true)),
        _ => None,
    }
}

/// Whether the sets of a record body keep their order and hold each value
/// once.
fn record_sets_hold(m: &Value<'_>) -> bool {
    let typ = m.get(1).and_then(Value::as_uint).unwrap_or(0);
    let (sorted, once) = record_sets(typ);
    let arr = |f: u16| m.get(f).and_then(Value::as_array).unwrap_or(&[]);
    // seen: [key hash, seq >= 1, record ID]
    let seen_ok = |e: &Value<'_>| matches!(e.as_array(), Some([Value::Bytes(k), Value::Uint(s), Value::Bytes(id)]) if k.len() == 32 && *s >= 1 && id.len() == 32);
    if let Some((f, required)) = seen_field(typ)
        && ((required && m.get(f).is_none()) || !arr(f).iter().all(seen_ok))
    {
        return false;
    }
    sorted.iter().all(|f| cbor::is_set(arr(*f)))
        && once.iter().all(|f| {
            let a = arr(*f);
            a.iter().enumerate().all(|(i, x)| !a[..i].contains(x))
        })
}

#[test]
fn sets_keep_their_order() {
    let r = load("records.json");
    let mut sorted_twice = 0;
    for t in r["take"].as_array().unwrap() {
        let eb = unhex(s(t, "envelope"));
        let e = Envelope::parse(&eb).unwrap();
        assert!(record_sets_hold(&e.map), "{}", s(t, "name"));
        let (sorted, once) = record_sets(e.map.get(1).and_then(Value::as_uint).unwrap_or(0));
        for f in sorted.iter().chain(once) {
            if e.map.get(*f).and_then(Value::as_array).is_some_and(|a| a.len() >= 2) {
                sorted_twice += 1;
            }
        }
    }
    assert!(sorted_twice >= 6, "sets of two or more in the take vectors: {sorted_twice}");
    let mut refused = 0;
    for t in r["refuse"].as_array().unwrap() {
        let rule = s(t, "rule");
        let eb = unhex(s(t, "envelope"));
        let Ok(e) = Envelope::parse(&eb) else { continue };
        let typ = e.map.get(1).and_then(Value::as_uint).unwrap_or(0);
        let field = rule.rsplit('/').next().unwrap();
        let is_set_rule = ["keys", "seen", "records", "heads", "keep", "hubs"].contains(&field)
            && matches!(typ, 1 | 2 | 4 | 8 | 9 | 10);
        if is_set_rule {
            assert!(!record_sets_hold(&e.map), "{}", s(t, "name"));
            refused += 1;
        }
    }
    assert_eq!(refused, 17);
    let fr = load("frames.json");
    for t in fr["refuse_fields"].as_array().unwrap() {
        let b = unhex(s(t, "message"));
        let mut v = cbor::decode(&b).unwrap();
        for k in t["path"].as_array().unwrap() {
            v = v.get(k.as_u64().unwrap() as u16).unwrap().clone();
        }
        assert!(!cbor::is_set(v.as_array().unwrap()), "{}", s(t, "name"));
    }
    for t in fr["take"].as_array().unwrap() {
        let fb = unhex(s(t, "frame"));
        let f = frame::read(&fb, frame::LIMIT_MEMBER).unwrap();
        let set = match f.t {
            6 | 18 => f.map.get(2),
            67 => f.map.get(3).and_then(|w| w.get(3)),
            _ => None,
        };
        if let Some(a) = set {
            let a = a.as_array().unwrap();
            assert!(a.len() >= 2 && cbor::is_set(a), "{}", s(t, "name"));
        }
    }
    let c = load("copy.json");
    for t in c["refuse_copies"].as_array().unwrap().iter().chain(c["refuse_readers"].as_array().unwrap()) {
        let b = unhex(s(t, "copy"));
        let v = cbor::decode(&b).unwrap();
        assert_eq!(copy::Copy::from_value(&v).err().map(Rule::name), Some(s(t, "rule")), "{}", s(t, "name"));
    }
}

#[test]
fn frames() {
    let f = load("frames.json");
    for t in f["take"].as_array().unwrap() {
        let b = unhex(s(t, "frame"));
        let m = frame::read(&b, frame::LIMIT_MEMBER).unwrap_or_else(|r| panic!("{}: {r}", s(t, "name")));
        let without: Vec<(u16, Value<'_>)> =
            m.map.as_map().unwrap().iter().filter(|(k, _)| *k != frame::FIELD_PAD).cloned().collect();
        assert_eq!(frame::write(&Value::Map(without)), b, "{}: the one frame", s(t, "name"));
        assert!(print::describe(Kind::Message, &m.map).contains("t(0)"));
    }
    for t in f["refuse"].as_array().unwrap() {
        let fb = unhex(s(t, "frame"));
        let got = frame::read(&fb, frame::LIMIT_MEMBER);
        assert_eq!(got.err().map(Rule::name), Some(s(t, "rule")), "{}", s(t, "name"));
    }
    // The set digest: SHA-256 over the label, a zero byte and the sorted IDs
    // of the records taken.
    let r = load("records.json");
    let mut ids: Vec<Vec<u8>> =
        r["take"].as_array().unwrap().iter().filter(|t| s(t, "verdict") == "take").map(|t| unhex(s(t, "id"))).collect();
    ids.sort();
    let mut parts: Vec<&[u8]> = vec![sig::LABEL_SET.as_bytes(), &[0]];
    parts.extend(ids.iter().map(|i| i.as_slice()));
    assert_eq!(hex(&super::sha256(&parts)), s(&f, "set_digest_of_records_take"));
}

#[test]
fn every_message_size_pads_to_one_frame() {
    // Messages of every size from 2 bytes to past 16 KiB: written frames are
    // on the grid and read back; the same message with one zero more or
    // less in `pad` is refused.
    for n in 0..17_000usize {
        let filler = vec![7u8; n];
        let msg = Value::Map(vec![(0, Value::Uint(3)), (2, Value::Bytes(&filler))]);
        let f = frame::write(&msg);
        assert!(frame::on_grid(f.len() - 4), "{n}");
        let m = frame::read(&f, frame::LIMIT_MEMBER).unwrap_or_else(|r| panic!("{n}: {r}"));
        if let Some(pad) = m.get(frame::FIELD_PAD).and_then(Value::as_bytes) {
            for other in [pad.len().wrapping_sub(1), pad.len() + 1] {
                if other > pad.len() + 1 {
                    continue;
                }
                let zeros = vec![0u8; other];
                let mut entries = m.map.as_map().unwrap().to_vec();
                entries[1].1 = Value::Bytes(&zeros);
                let body = Value::Map(entries).encode();
                let mut wrong = (body.len() as u32).to_be_bytes().to_vec();
                wrong.extend_from_slice(&body);
                assert!(frame::read(&wrong, frame::LIMIT_MEMBER).is_err(), "{n} {other}");
            }
        }
    }
    // A message on the grid with an empty `pad` is refused.
    let msg = frame::write(&Value::Map(vec![(0, Value::Uint(3))]));
    let m = frame::read(&msg, frame::LIMIT_MEMBER).unwrap();
    assert_eq!(m.t, 3);
    assert_eq!(frame::length([0, 0, 0x40, 0], frame::LIMIT_LEAF), Ok(16384));
    assert_eq!(frame::length([0, 0, 0x80, 0], frame::LIMIT_LEAF), Err(Rule::FRAME_GRID));
    assert_eq!(frame::length([0, 0x70, 0, 0], frame::LIMIT_MEMBER), Ok(7 * 1024 * 1024));
    assert_eq!(frame::length([0, 0x70, 0x40, 0], frame::LIMIT_MEMBER), Err(Rule::FRAME_GRID));
}

#[test]
fn copies() {
    let c = load("copy.json");
    let keys = keys();
    let laptop = keys
        .iter()
        .find(|(_, p)| {
            let k = load("keys.json");
            k["keys"]
                .as_array()
                .unwrap()
                .iter()
                .any(|r| s(r, "name") == "laptop member key" && unhex(s(r, "key")).ends_with(p))
        })
        .map(|(_, p)| p.clone())
        .unwrap();
    let k: [u8; 32] = unhex(s(&c, "K")).try_into().unwrap();
    let h: [u8; 32] = unhex(s(&c, "h")).try_into().unwrap();
    assert_eq!(hex(&copy::header_hash(&unhex(s(&c, "hdr")))), s(&c, "h"));
    assert_eq!(hex(&copy::commit(&k)), s(&c, "commit"));
    assert_eq!(hex(&copy::payload_key(&k, &h)), s(&c, "payload_key"));
    assert_eq!(hex(&copy::blob_key(&k, &h)), s(&c, "blob_key"));
    for form in ["copy", "reduced_copy_for_board"] {
        let b = unhex(s(&c, form));
        let v = cbor::decode(&b).unwrap();
        let cp = copy::Copy::from_value(&v).unwrap();
        assert_eq!(hex(&cp.w), s(&c, "W"), "{form}");
        assert_eq!(hex(&cp.p), s(&c, "P"), "{form}");
        assert_eq!(print::diag(&cp.header), s(&c, "hdr_diag"));
        cp.verify(&laptop).unwrap();
        cp.check_commit(&k).unwrap();
        assert_eq!(cp.check_commit(&[0; 32]), Err(copy::RULE_COMMIT));
        assert!(print::describe(Kind::Copy, &v).contains("hdr(1)"));
        assert!(print::describe(Kind::CopyHeader, &cp.header).contains("origin(2)"));
    }
    let twin = unhex(s(&c, "copy_high_s_twin"));
    let tv = cbor::decode(&twin).unwrap();
    assert_eq!(copy::Copy::from_value(&tv).unwrap().verify(&laptop), Err(Rule::SIG_LOW_S));
    for r in c["refuse_commit"].as_array().unwrap() {
        let other: [u8; 32] = unhex(s(r, "K")).try_into().unwrap();
        let b = unhex(s(&c, "copy"));
        let v = cbor::decode(&b).unwrap();
        let got = copy::Copy::from_value(&v).unwrap().check_commit(&other).err().map(Rule::name);
        assert_eq!(got, Some(s(r, "rule")), "{}", s(r, "name"));
    }
    for r in c["refuse_contents"].as_array().unwrap() {
        let b = unhex(s(r, "content"));
        assert_eq!(copy::read_content(&b).err().map(Rule::name), Some(s(r, "rule")), "{}", s(r, "name"));
    }
    let content = unhex(s(&c, "content_plaintext"));
    let v = copy::read_content(&content).unwrap();
    let without: Vec<(u16, Value<'_>)> = v.as_map().unwrap().iter().filter(|(k, _)| *k != 1).cloned().collect();
    assert_eq!(copy::write_content(&Value::Map(without)).unwrap(), content);
    // The edges of a step: an empty pad, the next step, no pad.
    for e in c["content_edges"].as_array().unwrap() {
        let b = unhex(s(e, "content"));
        assert_eq!(b.len() as u64, e["size"].as_u64().unwrap());
        copy::read_content(&b).unwrap_or_else(|r| panic!("{}: {r}", s(e, "name")));
        let text = "a".repeat(e["text_bytes"].as_u64().unwrap() as usize);
        let written = copy::write_content(&Value::Map(vec![(0, Value::Uint(1)), (5, Value::Text(&text))])).unwrap();
        assert_eq!(written, b, "{}", s(e, "name"));
    }
    let fb = unhex(s(&c, "frame"));
    let f = frame::read(&fb, frame::LIMIT_MEMBER).unwrap();
    assert_eq!(f.t, 2);
    copy::Copy::from_value(f.get(2).unwrap()).unwrap().verify(&laptop).unwrap();
}

#[test]
fn contents_of_every_size_pad_to_one_step() {
    for n in (0..20_000usize).step_by(7) {
        let text = "a".repeat(n);
        let c = Value::Map(vec![(0, Value::Uint(1)), (5, Value::Text(&text))]);
        let b = copy::write_content(&c).unwrap();
        assert!(copy::CONTENT_STEPS.contains(&b.len()), "{n}");
        copy::read_content(&b).unwrap_or_else(|r| panic!("{n}: {r}"));
    }
}

#[test]
fn key_container() {
    let c = load("container.json");
    let cert = unhex(s(&c, "example_cert"));
    let point = container::read(&cert).unwrap();
    assert_eq!(container::build(&point).as_slice(), cert.as_slice());
    assert_eq!(hex(&Key::new(Alg::Es256, &point).hash().0), s(&c, "example_key_hash"));
    assert_eq!(hex(&container::serial(&point)), s(&c, "example_serial"));
    assert_eq!(c["key_offset_in_tbs"].as_u64(), Some(container::KEY_AT as u64));
    assert_eq!(c["tbs_length"].as_u64(), Some(container::TBS_LEN as u64));
    for r in c["refuse"].as_array().unwrap() {
        if let Some(b) = r["cert"].as_str() {
            assert_eq!(container::read(&unhex(b)), Err(Rule::CONTAINER), "{}", s(r, "name"));
        }
    }
    // The tolerant reader: any signature value in its form, the constant
    // one, a real self-signature, the longest integers.
    for t in c["take"].as_array().unwrap() {
        let got = container::read(&unhex(s(t, "cert"))).unwrap_or_else(|r| panic!("{}: {r}", s(t, "name")));
        assert_eq!(hex(&got), s(t, "point"), "{}", s(t, "name"));
    }
    let mut trailing = cert.clone();
    trailing.push(0);
    assert!(container::read(&trailing).is_err());
}

/// Every vector's bytes, for the mutations below.
fn corpus() -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    for t in load("profile.json")["vectors"].as_array().unwrap() {
        out.push(unhex(s(t, "hex")));
    }
    for file in ["records.json", "statements.json", "commands.json", "credentials.json"] {
        let f = load(file);
        for t in f["take"].as_array().unwrap().iter().chain(f["refuse"].as_array().unwrap()) {
            let e = unhex(s(t, "envelope"));
            if let Ok(env) = Envelope::parse(&e) {
                out.push(env.body.to_vec());
            }
            out.push(e);
        }
    }
    for t in load("frames.json")["take"].as_array().unwrap() {
        let f = unhex(s(t, "frame"));
        out.push(f[4..].to_vec());
        out.push(f);
    }
    let c = load("copy.json");
    for k in ["copy", "reduced_copy_for_board", "content_plaintext", "hdr"] {
        out.push(unhex(s(&c, k)));
    }
    out.push(unhex(s(&load("container.json"), "example_cert")));
    for t in load("grants.json")["take"].as_array().unwrap() {
        out.push(unhex(s(t, "message")));
    }
    out
}

#[test]
fn the_vectors_keep_their_one_form() {
    for b in corpus() {
        super::fuzz::one_form(&b);
    }
}

/// An owned value for the property tests.
#[derive(Clone, Debug)]
enum Tree {
    Uint(u64),
    Bytes(Vec<u8>),
    Text(String),
    Array(Vec<Tree>),
    Map(std::collections::BTreeMap<u16, Tree>),
}

impl Tree {
    fn value(&self) -> Value<'_> {
        match self {
            Tree::Uint(n) => Value::Uint(*n),
            Tree::Bytes(b) => Value::Bytes(b),
            Tree::Text(t) => Value::Text(t),
            Tree::Array(a) => Value::Array(a.iter().map(Tree::value).collect()),
            Tree::Map(m) => Value::Map(m.iter().map(|(k, v)| (*k, v.value())).collect()),
        }
    }
}

fn tree() -> impl proptest::strategy::Strategy<Value = Tree> {
    use proptest::prelude::*;
    let leaf = prop_oneof![
        prop_oneof![0..30u64, 0..70_000u64, 0..=super::cbor::MAX_INT].prop_map(Tree::Uint),
        proptest::collection::vec(any::<u8>(), 0..300).prop_map(Tree::Bytes),
        ".{0,40}".prop_map(Tree::Text),
    ];
    leaf.prop_recursive(7, 64, 8, |inner| {
        prop_oneof![
            proptest::collection::vec(inner.clone(), 0..30).prop_map(Tree::Array),
            proptest::collection::btree_map(prop_oneof![0..30u16, any::<u16>()], inner, 0..30).prop_map(Tree::Map),
        ]
    })
}

proptest::proptest! {
    #![proptest_config(proptest::prelude::ProptestConfig::with_cases(2000))]

    /// Any value of the profile written and read back is itself, and its
    /// encoding is the only one taken.
    #[test]
    fn values_round_trip(t in tree()) {
        let v = t.value();
        let b = v.encode();
        let back = cbor::decode(&b).unwrap();
        proptest::prop_assert_eq!(&back, &v);
        super::fuzz::one_form(&b);
    }

    /// Random bytes never panic a reader, and whatever is taken has one form.
    #[test]
    fn random_bytes(b in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..512)) {
        super::fuzz::one_form(&b);
    }

    /// The vectors with a byte changed, cut or added: whatever a reader
    /// still takes has one form.
    #[test]
    fn mutated_vectors(i in 0usize..1000, at in 0usize..100_000, byte in proptest::prelude::any::<u8>(), how in 0u8..4) {
        let c = corpus();
        let mut b = c[i % c.len()].clone();
        if b.is_empty() { return Ok(()); }
        let at = at % b.len();
        match how {
            0 => b[at] = byte,
            1 => b[at] ^= 1 << (byte % 8),
            2 => b.truncate(at),
            _ => b.insert(at, byte),
        }
        super::fuzz::one_form(&b);
    }
}

/// The high-S twin of a signature: the same r with n − s.
fn high_s_twin(sig: &[u8]) -> Vec<u8> {
    const N: [u8; 32] = [
        0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xbc, 0xe6,
        0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51,
    ];
    let mut out = sig[..32].to_vec();
    let mut borrow = 0i16;
    let mut low = [0u8; 32];
    for i in (0..32).rev() {
        let d = i16::from(N[i]) - i16::from(sig[32 + i]) - borrow;
        borrow = i16::from(d < 0);
        low[i] = (d + 256 * borrow) as u8;
    }
    out.extend_from_slice(&low);
    out
}

#[test]
fn every_signature_has_one_form() {
    // For every signed vector taken, the twin (r, n − s) of its signature
    // also verifies mathematically, and is refused for its high s.
    let keys = keys();
    for (file, by_key) in
        [("records.json", false), ("statements.json", false), ("commands.json", false), ("credentials.json", true)]
    {
        let f = load(file);
        let label = s(&f, "label");
        for t in f["take"].as_array().unwrap() {
            let b = unhex(s(t, "envelope"));
            let e = Envelope::parse(&b).unwrap();
            let point = if by_key {
                Key::from_value(e.signer().unwrap()).unwrap().public.to_vec()
            } else {
                keys[&hex(e.signer().unwrap().as_bytes().unwrap())].clone()
            };
            let twin = high_s_twin(e.sig);
            assert_eq!(
                sig::verify_es256(&point, label, e.body, &twin),
                Err(Rule::SIG_LOW_S),
                "{file} {}",
                s(t, "name")
            );
            // The twin is the signature p256 itself would also accept.
            let full = p256::ecdsa::Signature::from_slice(&twin).unwrap();
            use p256::ecdsa::signature::Verifier;
            assert!(
                p256::ecdsa::VerifyingKey::from_sec1_bytes(&point)
                    .unwrap()
                    .verify(&sig::message(label, e.body), &full)
                    .is_ok()
            );
        }
    }
}

/// The root's record of the admin that signs a first grant is read by the
/// record reader itself: a body that reader refuses is no admin's record
/// for a grant either.
#[test]
fn the_admins_record_of_a_grant_is_read_as_a_record() {
    use p256::ecdsa::SigningKey;
    let sk = |name: &str| SigningKey::from_slice(&super::sha256(&[name.as_bytes()])).unwrap();
    let point = |name: &str| sig::public_point(&sk(name));
    let (root, admin_p, member_p) = (point("root"), point("admin"), point("member"));
    let root_hash = Key::new(Alg::Es256, &root).hash().0;
    let group = Key::new(Alg::Es256, &root).device_id().0;
    let leaf = Key::new(Alg::Es256, &point("lamp")).device_id().0;
    let (admin, member) = (Key::new(Alg::Es256, &admin_p), Key::new(Alg::Es256, &member_p));
    let admin_hash = admin.hash().0;
    let record = |change: Option<(u16, Value<'static>)>| {
        let mut m: Vec<(u16, Value)> = vec![
            (1, Value::Uint(1)),
            (2, Value::Bytes(&group)),
            (3, Value::Bytes(&root_hash)),
            (4, Value::Uint(1)),
            (6, Value::Uint(1)),
            (10, member.to_value()),
            (11, Value::Text("phone")),
            (12, Value::Uint(1)),
            (13, Value::Uint(3)),
            (20, admin.to_value()),
            (21, Value::Uint(1)),
        ];
        if let Some((k, v)) = change {
            m.retain(|(f, _)| *f != k);
            m.push((k, v));
            m.sort_by_key(|(f, _)| *f);
        }
        envelope::sign(&sk("root"), sig::LABEL_RECORD, &Value::Map(m).encode())
    };
    let grant_of = |rec: &[u8]| {
        let body = Value::Map(vec![
            (1, Value::Uint(1)),
            (2, Value::Bytes(&group)),
            (3, Value::Bytes(&admin_hash)),
            (4, Value::Uint(1)),
            (10, Value::Bytes(&leaf)),
            (12, Value::Array(vec![admin.to_value()])),
        ])
        .encode();
        let env = envelope::sign(&sk("admin"), sig::LABEL_GRANT, &body);
        let mut e = cbor::Encoder::new();
        e.map(2).uint(2).raw(&env).uint(3).raw(rec);
        let msg = e.finish();
        let v = cbor::decode(&msg).unwrap();
        grant::read(&v, &root, &DeviceId(leaf), &DeviceId(group), None).map(|_| ()).map_err(Rule::name)
    };
    assert_eq!(grant_of(&record(None)), Ok(()));
    for change in
        [(13, Value::Text("all")), (21, Value::Uint(1 | 1 << 40)), (22, Value::Text("x")), (26, Value::Uint(7))]
    {
        let rec = record(Some(change.clone()));
        assert!(crate::records::Record::decode(&rec).is_err(), "{change:?}");
        assert_eq!(grant_of(&rec), Err("grants/admin"), "{change:?}");
    }
}
