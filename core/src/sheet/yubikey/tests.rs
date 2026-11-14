// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The recovery secret on a YubiKey: sealed and opened, every refusal with
//! the reason a person is shown, and the vectors of sheet.json.

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use super::*;

fn scalar(n: u8) -> p256::SecretKey {
    let mut b = [0x11u8; 32];
    b[31] = n.max(1);
    p256::SecretKey::from_bytes(&b.into()).unwrap()
}

fn point(k: &p256::SecretKey) -> Vec<u8> {
    k.public_key().to_sec1_point(false).as_bytes().to_vec()
}

fn secret(n: u8) -> [u8; 32] {
    core::array::from_fn(|i| n.wrapping_mul(13).wrapping_add(i as u8))
}

#[test]
fn a_sealed_secret_opens_with_the_cards_answer() {
    for n in 1..8 {
        let (card, e) = (scalar(n), scalar(n + 100));
        let s = secret(n);
        let obj = seal(&s, &point(&card), &e).unwrap();
        assert_eq!(obj.len(), LEN);
        assert!(obj.starts_with(b"CBBR\x01"));
        assert!(is_ours(&obj));
        // The card does ECDH with its key and the object's E.
        let r = read(&obj).unwrap();
        let z = ecdh(&card, r.e).unwrap();
        assert_eq!(*z, *ecdh(&e, &point(&card)).unwrap());
        assert_eq!(*open(&z, &point(&card), &obj).unwrap(), s);
        // Another card's answer, or the card's point changed, do not open.
        let other = scalar(n + 50);
        let z2 = ecdh(&other, r.e).unwrap();
        assert_eq!(open(&z2, &point(&card), &obj).err(), Some(Reason::OtherKey));
        assert_eq!(open(&z, &point(&other), &obj).err(), Some(Reason::OtherKey));
    }
}

#[test]
fn every_change_of_the_object_is_refused() {
    let card = scalar(3);
    let obj = seal(&secret(3), &point(&card), &scalar(4)).unwrap();
    let z = ecdh(&card, read(&obj).unwrap().e).unwrap();
    for i in 0..LEN {
        let mut b = obj;
        b[i] ^= 0x01;
        let want = match i {
            0..4 => Reason::NotCbb,
            4 => Reason::Newer,
            // The point's first byte, or a coordinate off the curve, does
            // not read; a coordinate still on it opens to nothing.
            _ => match read(&b) {
                Err(r) => {
                    assert!(i < 5 + POINT, "byte {i}");
                    assert_eq!(r, Reason::Damaged, "byte {i}");
                    continue;
                }
                Ok(_) => Reason::OtherKey,
            },
        };
        assert_eq!(open(&z, &point(&card), &b).err(), Some(want), "byte {i}");
    }
    assert_eq!(read(&obj[..LEN - 1]).err(), Some(Reason::Damaged));
    assert_eq!(read(b"").err(), Some(Reason::NotCbb));
    assert!(!is_ours(b"CBBR\x02"));
    assert!(!is_ours(b"CBBR"));
    assert!(!is_ours(&[0u8; LEN]));
}

#[test]
fn an_opened_secret_is_checked_against_the_group() {
    use crate::records::key::{Key, Recovery};
    let s = secret(9);
    let (k1, k2) = crate::records::pq::recovery_keys(&s).unwrap();
    let rec = Recovery::new(Key::es256(k1.public_key().to_sec1_point(false).as_bytes().to_vec()), k2.key()).unwrap();
    assert_eq!(check(&s, &rec), Ok(()));
    assert_eq!(check(&secret(10), &rec), Err(Reason::OtherKey));
}

#[test]
fn a_card_key_that_is_not_a_point_seals_nothing() {
    let e = scalar(5);
    assert_eq!(seal(&secret(1), &[4u8; 65], &e).err(), Some(Reason::CardKey));
    let mut compressed =
        p256::SecretKey::from_bytes(&[7u8; 32].into()).unwrap().public_key().to_sec1_point(true).as_bytes().to_vec();
    assert_eq!(seal(&secret(1), &compressed, &e).err(), Some(Reason::CardKey));
    compressed.clear();
    assert_eq!(seal(&secret(1), &compressed, &e).err(), Some(Reason::CardKey));
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

fn reason_name(r: Reason) -> &'static str {
    match r {
        Reason::NotCbb => "not_cbb",
        Reason::Newer => "newer",
        Reason::Damaged => "damaged",
        Reason::OtherKey => "other_key",
        Reason::CardKey => "card_key",
    }
}

#[test]
fn the_yubikey_vectors() {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../testdata/format/sheet.json");
    let v: serde_json::Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    let v = &v["yubikey"];
    let s = |x: &serde_json::Value, k: &str| -> String { x[k].as_str().unwrap().to_string() };
    let key = |h: String| p256::SecretKey::from_slice(&unhex(&h)).unwrap();
    for t in v["take"].as_array().unwrap() {
        let name = s(t, "name");
        let secret: [u8; 32] = unhex(&s(t, "secret")).try_into().unwrap();
        let card = key(s(t, "card_scalar"));
        assert_eq!(point(&card), unhex(&s(t, "card")), "{name}");
        let obj = seal(&secret, &point(&card), &key(s(t, "e_scalar"))).unwrap();
        assert_eq!(obj.to_vec(), unhex(&s(t, "object")), "{name}");
        let z = ecdh(&card, read(&obj).unwrap().e).unwrap();
        assert_eq!(z.to_vec(), unhex(&s(t, "z")), "{name}");
        assert_eq!(*open(&z, &point(&card), &obj).unwrap(), secret, "{name}");
    }
    for t in v["refuse"].as_array().unwrap() {
        let z: [u8; 32] = unhex(&s(t, "z")).try_into().unwrap();
        let got = open(&z, &unhex(&s(t, "card")), &unhex(&s(t, "object"))).err().map(reason_name);
        assert_eq!(got, Some(s(t, "reason").as_str()), "{}", s(t, "name"));
    }
}
