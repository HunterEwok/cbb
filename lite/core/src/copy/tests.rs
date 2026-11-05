// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

#![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use alloc::vec;

use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey};

use super::*;
use crate::certs::DeviceId;
use crate::media::Part;

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
