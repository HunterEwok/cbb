// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

#![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use alloc::vec;

use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey};

use super::*;
use crate::certs::DeviceId;
use crate::media::Part;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use serde_json::{Value, json};

struct Device {
    id: DeviceId,
    key: SigningKey,
    cert: Vec<u8>,
    secret: [u8; 32],
    public: Vec<u8>,
}

fn device(n: u8) -> Device {
    let id = DeviceId::parse(&format!("{:032x}", u128::from(n) * 0x1111)).unwrap();
    let key = SigningKey::from_slice(&[n.max(1); 32]).unwrap();
    let cert = certs::self_signed(&id, &key).unwrap();
    let secret = [n; 32];
    let public = seal::public_key(&secret).unwrap();
    Device { id, key, cert, secret, public }
}

fn readers(ds: &[&Device]) -> Vec<(String, Vec<u8>)> {
    ds.iter().map(|d| (d.id.as_str().to_string(), d.public.clone())).collect()
}

fn text(t: &str) -> Content {
    Content { kind: Kind::Text, via: Via::Copy, text: t.to_string(), media: None }
}

fn sealed(from: &Device, to: &[&Device], c: &Content, blob: Option<Blob>, key: &[u8; 32]) -> Sealed {
    let d = seal(
        &"ab".repeat(16),
        from.id.as_str(),
        Timestamp::parse("1761024000000.3").unwrap(),
        &from.cert,
        &[],
        &readers(to),
        c,
        blob,
        key,
    )
    .unwrap();
    let mut s = d.sealed;
    let sig: Signature = from.key.sign(&d.to_sign);
    s.sig = sig.to_der().as_bytes().to_vec();
    s
}

fn verifies(s: &Sealed, d: &Device) -> bool {
    Cert::parse(&d.cert).unwrap().verifies(&s.to_sign(), &s.sig)
}

#[test]
fn every_reader_opens_its_own() {
    let (a, b, c) = (device(1), device(2), device(3));
    let s = sealed(&a, &[&c, &a, &b], &text("hello"), None, &new_key());
    s.validate().unwrap();
    assert!(verifies(&s, &a));
    let ids: Vec<&str> = s.wraps.iter().map(|w| w.to.as_str()).collect();
    assert_eq!(ids, vec![a.id.as_str(), b.id.as_str(), c.id.as_str()], "sorted by device ID");
    for d in [&a, &b, &c] {
        let (got, _) = s.open(d.id.as_str(), &d.secret).unwrap();
        assert_eq!(got, text("hello"));
    }
    // A device that is no reader, and a reader with another's secret.
    let x = device(9);
    assert!(s.open(x.id.as_str(), &x.secret).is_err());
    assert!(s.open(b.id.as_str(), &c.secret).is_err());
}

#[test]
fn the_wire_form_round_trips() {
    let (a, b) = (device(1), device(2));
    let s = sealed(&a, &[&a, &b], &text("hello"), None, &new_key());
    let json = serde_json::to_string(&s).unwrap();
    for field in ["\"kind\"", "\"text\"", "\"via\"", "\"media\"", "hello"] {
        assert!(!json.contains(field), "{field} is outside the seal: {json}");
    }
    let back: Sealed = serde_json::from_str(&json).unwrap();
    assert_eq!(back, s);
    back.validate().unwrap();
    assert!(verifies(&back, &a));
}

#[test]
fn a_copy_in_the_open_is_refused() {
    let (a, b) = (device(1), device(2));
    let s = sealed(&a, &[&a, &b], &text("hello"), None, &new_key());
    let mut v: serde_json::Value = serde_json::to_value(&s).unwrap();
    for (k, x) in [("kind", "text"), ("text", "hi"), ("via", "phone"), ("media", "{}")] {
        let mut w = v.clone();
        w[k] = serde_json::Value::from(x);
        let back: Sealed = serde_json::from_value(w).unwrap();
        assert!(back.validate().is_err(), "{k}");
    }
    v["payload"] = serde_json::Value::from("");
    let back: Sealed = serde_json::from_value(v).unwrap();
    assert!(back.validate().is_err(), "neither payload nor its hash");
}

#[test]
fn nothing_in_it_can_change() {
    let (a, b) = (device(1), device(2));
    let s = sealed(&a, &[&a, &b], &text("hello"), None, &new_key());
    let mut changes: Vec<Sealed> = Vec::new();
    let mut t = s.clone();
    t.id = "cd".repeat(16);
    changes.push(t);
    let mut t = s.clone();
    t.time = Timestamp::parse("1761024000000.4").unwrap();
    changes.push(t);
    let mut t = s.clone();
    t.payload[5] ^= 1;
    changes.push(t);
    let mut t = s.clone();
    t.wraps[0].key[2000 % WRAP_SIZE] ^= 1;
    changes.push(t);
    let mut t = s.clone();
    t.wraps.remove(0);
    changes.push(t);
    for t in changes {
        assert!(!verifies(&t, &a), "the signature covers it");
    }
    // A reader moved to another header no longer opens it, even signed again.
    let mut t = s.clone();
    t.time = Timestamp::parse("1761024000000.4").unwrap();
    assert!(t.open(b.id.as_str(), &b.secret).is_err());
    // The age changes on the way and is no part of it.
    let mut t = s.clone();
    t.age = 9000;
    assert!(verifies(&t, &a));
    assert!(t.open(b.id.as_str(), &b.secret).is_ok());
}

#[test]
fn a_mark_still_verifies() {
    let (a, b) = (device(1), device(2));
    let secret = Content { kind: Kind::Secret, ..text("hunter2") };
    let s = sealed(&a, &[&a, &b], &secret, None, &new_key());
    let m = s.mark();
    assert!(m.is_mark());
    m.validate().unwrap();
    assert!(verifies(&m, &a));
    assert!(m.open(b.id.as_str(), &b.secret).is_err());
    assert_eq!(m.payload_hash(), certs::sha256(&s.payload));
    assert!(!serde_json::to_string(&m).unwrap().contains("\"payload\""));
}

#[test]
fn padding_hides_the_size() {
    let (a, b) = (device(1), device(2));
    let short = sealed(&a, &[&a, &b], &text("a"), None, &new_key());
    let longer = sealed(&a, &[&a, &b], &text(&"b".repeat(900)), None, &new_key());
    assert_eq!(short.payload.len(), longer.payload.len());
    assert_eq!(short.payload.len(), 1024 + TAG);
    let big = sealed(&a, &[&a, &b], &text(&"c".repeat(5000)), None, &new_key());
    assert_eq!(big.payload.len(), (16 << 10) + TAG);
    let max = sealed(&a, &[&a, &b], &text(&"d".repeat(MAX_TEXT)), None, &new_key());
    assert_eq!(max.payload.len(), (2 << 20) + TAG);
    assert_eq!(max.open(b.id.as_str(), &b.secret).unwrap().0.text.len(), MAX_TEXT);
}

#[test]
fn content_is_read_strictly() {
    let c = Content { kind: Kind::Secret, via: Via::Phone, text: "x".into(), media: None };
    let b = c.encode().unwrap();
    assert_eq!(Content::decode(&b).unwrap(), c);
    let mut bad = b.clone();
    bad[1000] = 1;
    assert!(Content::decode(&bad).is_err(), "padding that is not zeros");
    let mut bad = b.clone();
    bad[0] = 2;
    assert!(Content::decode(&bad).is_err(), "another version");
    let mut bad = b.clone();
    bad[1] = 9;
    assert!(Content::decode(&bad).is_err(), "an unknown kind");
    assert!(Content::decode(&b[..1000]).is_err(), "not a step");
    let mut wide = b.clone();
    wide.resize(4 << 10, 0);
    assert!(Content::decode(&wide).is_err(), "padded past its step");
    assert!(text("").encode().is_err(), "an empty text");
    assert!(Content { kind: Kind::Media, ..text("x") }.encode().is_err(), "media without a manifest");
}

fn image(size: i64) -> Content {
    let part = Part { kind: "image/png".into(), size, sha256: Some(vec![7; 32]), ..Part::default() };
    Content {
        kind: Kind::Media,
        via: Via::Copy,
        text: String::new(),
        media: Some(Manifest { size, parts: vec![part] }),
    }
}

#[test]
fn a_blob_opens_segment_by_segment() {
    let (a, b) = (device(1), device(2));
    let key = new_key();
    let bytes: Vec<u8> = (0..(SEGMENT + 100)).map(|i| i as u8).collect();
    let n = bytes.len().div_ceil(SEGMENT) as u64;
    let mut blob = Vec::new();
    for (i, chunk) in bytes.chunks(SEGMENT).enumerate() {
        blob.extend(seal_segment(&key, i as u64, i as u64 == n - 1, chunk).unwrap());
    }
    assert_eq!(blob.len() as u64, blob_size(bytes.len() as u64));
    let meta = Blob { size: blob.len() as i64, sha256: certs::sha256(&blob).to_vec() };
    let s = sealed(&a, &[&a, &b], &image(bytes.len() as i64), Some(meta), &key);
    s.validate().unwrap();
    let (c, k) = s.open(b.id.as_str(), &b.secret).unwrap();
    assert!(c.media.is_some());
    let mut got = Vec::new();
    for (i, seg) in blob.chunks(SEALED_SEGMENT).enumerate() {
        got.extend(open_segment(&k, i as u64, i as u64 == n - 1, seg).unwrap());
    }
    assert_eq!(&got[..bytes.len()], &bytes[..]);
    assert!(got[bytes.len()..].iter().all(|&x| x == 0));
    // Cut short, moved or changed, a segment does not open.
    assert!(open_segment(&k, 0, true, &blob[..SEALED_SEGMENT]).is_err(), "the first as the last");
    assert!(open_segment(&k, 1, true, &blob[..SEALED_SEGMENT]).is_err(), "at another place");
    let mut bad = blob[SEALED_SEGMENT..].to_vec();
    bad[3] ^= 1;
    assert!(open_segment(&k, 1, true, &bad).is_err(), "changed");
    assert!(open_segment(&new_key(), 1, true, &blob[SEALED_SEGMENT..]).is_err(), "another copy's key");
}

#[test]
fn a_blob_must_fit_its_manifest() {
    let (a, b) = (device(1), device(2));
    let key = new_key();
    let wrong = Blob { size: (3 * SEALED_SEGMENT) as i64, sha256: vec![1; 32] };
    let s = sealed(&a, &[&a, &b], &image(10), Some(wrong), &key);
    assert!(s.open(b.id.as_str(), &b.secret).is_err());
    let s = sealed(&a, &[&a, &b], &image(10), None, &key);
    assert!(s.open(b.id.as_str(), &b.secret).is_err(), "bytes without a blob");
    let mut v = serde_json::to_value(&s).unwrap();
    v["blob"] = serde_json::json!({"size": 100, "sha256": "AQ=="});
    let back: Sealed = serde_json::from_value(v).unwrap();
    assert!(back.validate().is_err(), "a blob of no whole segment");
}

#[test]
fn readers_are_checked_and_counted() {
    let a = device(1);
    let mut bad = readers(&[&a]);
    bad[0].1 = vec![0; 10];
    assert!(
        seal(
            &"ab".repeat(16),
            a.id.as_str(),
            Timestamp::parse("1.0").unwrap(),
            &a.cert,
            &[],
            &bad,
            &text("x"),
            None,
            &new_key()
        )
        .is_err()
    );
    assert!(
        seal(
            &"ab".repeat(16),
            a.id.as_str(),
            Timestamp::parse("1.0").unwrap(),
            &a.cert,
            &[],
            &[],
            &text("x"),
            None,
            &new_key()
        )
        .is_err()
    );
}

fn dir() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../testdata/interop")
}

fn content_json(c: &Content) -> Value {
    let mut v = json!({"kind": c.kind, "via": c.via, "text": c.text});
    if let Some(m) = &c.media {
        v["media"] = serde_json::to_value(m).unwrap();
    }
    v
}

/// Seals parts as a blob under key: the blob and its name.
fn seal_blob(key: &[u8; 32], parts: &[u8]) -> (Vec<u8>, Blob) {
    let n = parts.len().div_ceil(SEGMENT);
    let mut blob = Vec::new();
    for (i, chunk) in parts.chunks(SEGMENT).enumerate() {
        blob.extend(seal_segment(key, i as u64, i == n - 1, chunk).unwrap());
    }
    let meta = Blob { size: blob.len() as i64, sha256: certs::sha256(&blob).to_vec() };
    (blob, meta)
}

/// The copies the Rust core seals for testdata/interop/copies-rust.json,
/// in the form of Go's copies-go.json (internal/clip's TestCopyVectors).
fn rust_vectors() -> Value {
    let (a, b, c, x) = (device(1), device(2), device(3), device(4));
    let reader = |d: &Device| json!({"id": d.id.as_str(), "secret": STANDARD.encode(d.secret)});
    let mut cases = Vec::new();
    let mut add = |name: &str, ct: Content, parts: Option<Vec<u8>>, to: &[&Device]| -> Sealed {
        let key = new_key();
        let (blob, meta) = match &parts {
            Some(p) => {
                let (b, m) = seal_blob(&key, p);
                (Some(b), Some(m))
            }
            None => (None, None),
        };
        let s = sealed(&a, to, &ct, meta, &key);
        let mut case = json!({"name": name, "event": s, "readers": to.iter().map(|d| reader(d)).collect::<Vec<_>>(),
            "outsider": reader(&x), "content": content_json(&ct)});
        if let (Some(b), Some(p)) = (blob, parts) {
            case["blob"] = Value::from(STANDARD.encode(b));
            case["parts"] = Value::from(STANDARD.encode(p));
        }
        cases.push(case);
        s
    };
    let text = add("a text to three", text("Hello from Rust"), None, &[&a, &b, &c]);
    add(
        "a secret from a phone",
        Content { kind: Kind::Secret, via: Via::Phone, ..text_of("hunter2") },
        None,
        &[&a, &b],
    );
    add("a long text", Content { via: Via::Universal, ..text_of(&"\u{fc}".repeat(3000)) }, None, &[&a, &c]);
    let parts: Vec<u8> = (0..(SEGMENT + 1234)).map(|i| (i * 7) as u8).collect();
    let mut img = image(parts.len() as i64);
    img.text = "an image".into();
    img.media.as_mut().unwrap().parts[0].sha256 = Some(certs::sha256(&parts).to_vec());
    add("an image of two segments", img, Some(parts), &[&a, &b]);

    let mut refused = Vec::new();
    let mut refuse = |name: &str, stage: &str, s: Value| {
        refused.push(json!({"name": name, "stage": stage, "event": s, "reader": reader(&b)}));
    };
    let mut open = serde_json::to_value(&text).unwrap();
    open["text"] = Value::from("Hello from Rust");
    refuse("a copy in the open", "validate", open);
    let mut unsorted = text.clone();
    unsorted.wraps.reverse();
    refuse("wraps not sorted", "validate", serde_json::to_value(&unsorted).unwrap());
    let mut changed = text.clone();
    changed.payload[7] ^= 1;
    refuse("a changed payload", "verify", serde_json::to_value(&changed).unwrap());
    let mut moved = text.clone();
    moved.time = Timestamp::parse("1761024000000.4").unwrap();
    refuse("moved to another time", "verify", serde_json::to_value(&moved).unwrap());
    let mut off = text.clone();
    off.wraps.retain(|w| w.to != c.id.as_str());
    refuse("a reader taken off", "verify", serde_json::to_value(&off).unwrap());
    let mut resigned = moved.clone();
    let sig: Signature = a.key.sign(&resigned.to_sign());
    resigned.sig = sig.to_der().as_bytes().to_vec();
    refuse("moved and signed again", "open", serde_json::to_value(&resigned).unwrap());
    json!({"comment": "Written by the Rust core's copy tests with CBB_UPDATE_VECTORS=1. Each reader opens each case's event to its content, and the outsider does not; each refused event fails at its stage (docs/protocol.md, section 4, \"Event\").", "cases": cases, "refused": refused})
}

fn text_of(t: &str) -> Content {
    text(t)
}

fn b64(v: &Value) -> Vec<u8> {
    STANDARD.decode(v.as_str().unwrap()).unwrap()
}

/// Where a refused copy fails: validate, verify (the origin's signature)
/// or open, by the reader.
fn refused_at(r: &Value) -> &'static str {
    let Ok(s) = serde_json::from_value::<Sealed>(r["event"].clone()) else { return "validate" };
    if s.validate().is_err() {
        return "validate";
    }
    if !Cert::parse(&s.cert).unwrap().verifies(&s.to_sign(), &s.sig) {
        return "verify";
    }
    if s.open(r["reader"]["id"].as_str().unwrap(), &b64(&r["reader"]["secret"])).is_err() {
        return "open";
    }
    ""
}

/// testdata/interop/copies-go.json, which Go's TestCopyVectors writes, and
/// copies-rust.json, which this writes with CBB_UPDATE_VECTORS=1: every
/// reader opens each copy to its content and blob, the outsider does not,
/// and each refused copy fails at its stage.
#[test]
fn vectors() {
    if std::env::var("CBB_UPDATE_VECTORS").as_deref() == Ok("1") {
        let mut s = serde_json::to_string_pretty(&rust_vectors()).unwrap();
        s.push('\n');
        std::fs::write(dir().join("copies-rust.json"), s).unwrap();
    }
    for file in ["copies-go.json", "copies-rust.json"] {
        let v: Value = serde_json::from_str(&std::fs::read_to_string(dir().join(file)).unwrap()).unwrap();
        let cases = v["cases"].as_array().unwrap();
        let refused = v["refused"].as_array().unwrap();
        assert!(cases.len() >= 4 && refused.len() >= 4, "{file}");
        for c in cases {
            let name = format!("{file} {}", c["name"]);
            let s: Sealed = serde_json::from_value(c["event"].clone()).unwrap();
            s.validate().unwrap_or_else(|e| panic!("{name}: {e}"));
            assert!(Cert::parse(&s.cert).unwrap().verifies(&s.to_sign(), &s.sig), "{name}");
            for r in c["readers"].as_array().unwrap() {
                let (got, key) =
                    s.open(r["id"].as_str().unwrap(), &b64(&r["secret"])).unwrap_or_else(|e| panic!("{name}: {e}"));
                assert_eq!(content_json(&got), c["content"], "{name}");
                if let Some(blob) = c.get("blob") {
                    let blob = b64(blob);
                    let parts = b64(&c["parts"]);
                    assert_eq!(s.blob.as_ref().unwrap().sha256, certs::sha256(&blob).to_vec(), "{name}");
                    let n = blob.len() / SEALED_SEGMENT;
                    let mut got = Vec::new();
                    for (i, seg) in blob.chunks(SEALED_SEGMENT).enumerate() {
                        got.extend(open_segment(&key, i as u64, i == n - 1, seg).unwrap());
                    }
                    assert_eq!(&got[..parts.len()], &parts[..], "{name}");
                    assert!(got[parts.len()..].iter().all(|&b| b == 0), "{name}");
                }
            }
            let o = &c["outsider"];
            assert!(s.open(o["id"].as_str().unwrap(), &b64(&o["secret"])).is_err(), "{name}: the outsider opens it");
        }
        for r in refused {
            assert_eq!(refused_at(r), r["stage"].as_str().unwrap(), "{file} {}", r["name"]);
        }
    }
}

/// testdata/interop/go-copy-checks.json, which Go's TestCopyCheckVectors
/// writes: the copies a member takes by the group's records, the readers
/// the records give, and the order of the hubs, a hub that only passes
/// copies on last.
#[test]
fn go_copy_checks() {
    let v: Value = serde_json::from_str(&std::fs::read_to_string(dir().join("go-copy-checks.json")).unwrap()).unwrap();
    let ca = Cert::parse(&b64(&v["group_ca"])).unwrap();
    let now = v["now_ms"].as_i64().unwrap();
    let mut s = Records::new(&ca);
    s.set_clock(move || now);
    let rs: Vec<crate::authority::Record> = serde_json::from_value(v["records"].clone()).unwrap();
    s.add_all(&rs);
    let copies = v["copies"].as_array().unwrap();
    assert!(copies.len() >= 8);
    for c in copies {
        let e: Sealed = serde_json::from_value(c["event"].clone()).unwrap();
        let got = e.check(&s, now / 1000);
        assert_eq!(got.is_ok(), c["ok"].as_bool().unwrap(), "{}: {got:?}", c["name"]);
    }
    let ids = |secret: bool| -> Vec<Value> {
        crate::copy::readers(&s, secret).into_iter().map(|(id, _)| Value::from(id)).collect()
    };
    assert_eq!(Value::from(ids(false)), v["readers"]);
    assert_eq!(Value::from(ids(true)), v["secret_readers"]);
    assert_eq!(serde_json::to_value(s.hub_order()).unwrap(), v["hub_order"]);
}
