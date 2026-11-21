// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

use cbb_core::commands::{COMMAND_MODE, COMMAND_UNMUTE};
use cbb_core::keystore::{MemoryStore, rotate};
use cbb_core::records::body::{self, Device};
use cbb_core::records::{Key, Kind, RecordSet, Recovery, key::ALG_SLH_DSA, pq};
use p256::ecdsa::SigningKey;
use p256::ecdsa::signature::hazmat::PrehashSigner as _;

use super::*;

struct K(SigningKey);

impl K {
    fn new(n: u8) -> K {
        K(SigningKey::from_slice(&[n; 32]).unwrap())
    }
    fn key(&self) -> Key {
        Key::es256(self.public())
    }
}

impl ExternalKey for K {
    fn public(&self) -> Vec<u8> {
        self.0.verifying_key().to_sec1_point(false).as_bytes().to_vec()
    }
    fn sign_digest(&self, digest: &[u8; 32]) -> cbb_core::error::Result<Vec<u8>> {
        let sig: p256::ecdsa::Signature = self.0.sign_prehash(digest).unwrap();
        Ok(sig.to_der().as_bytes().to_vec())
    }
}

const NOW: u64 = 1_793_000_000_000;

/// A group whose root (key 1) commands device b (key 3).
fn group() -> RecordSet {
    let root = K::new(1);
    let (k1, k2) = pq::recovery_keys(&[1; 32]).unwrap();
    let k1 = SigningKey::from(&k1).verifying_key().to_sec1_point(false).as_bytes().to_vec();
    let mut set =
        RecordSet::new(root.key(), Recovery::new(Key::es256(k1), Key::new(ALG_SLH_DSA, k2.public())).unwrap());
    for (n, name) in [(2, "a"), (3, "b")] {
        let mut d = Device::new(K::new(n).key(), name, body::ROLE_MEMBER);
        d.rights = body::RIGHT_READ | body::RIGHT_SEND;
        let st = set.state();
        set.write_record(&st, &root, Kind::device(d), NOW - 1000).unwrap();
    }
    set
}

fn temp(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("cbb-commands-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// b's key store and the statements the root's device holds of it.
fn b_keys(state: &State, dir: &Path) -> (MemoryStore<K>, Statements) {
    let mut s = MemoryStore::new(K::new(3));
    let made = rotate(&mut s, &state.group, NOW - 500, Some(NOW - 500)).unwrap().made.unwrap();
    let mut st = Statements::load(dir).unwrap();
    st.add(&made).unwrap();
    (s, st)
}

#[test]
fn the_root_commands_a_member_once() {
    let set = group();
    let state = set.state();
    let keys = Keys::of(&set);
    let b = K::new(3).key().device_id();
    let (store, statements) = b_keys(&state, &temp("once-st"));
    let mut root_book = Book::load(&temp("once-root")).unwrap();
    let orders = Value::Map(vec![(10, Value::Uint(2))]).encode();
    let f = root_book.send(&K::new(1), &state, &statements, b, COMMAND_MODE, Some(&orders), NOW).unwrap();
    // The orders are sealed: not in the open.
    assert!(!f.windows(orders.len()).any(|w| w == orders.as_slice()));

    let dir = temp("once-b");
    let mut book = Book::load(&dir).unwrap();
    let t = book.take(&f[4..], b, &state, &keys, &store, Some(NOW + 5)).unwrap();
    assert_eq!(t.kind, COMMAND_MODE);
    assert_eq!(t.orders.as_deref(), Some(orders.as_slice()));
    assert_eq!(t.signer, K::new(1).key().hash());
    // Taken once, across a restart too; the refusal is answered.
    let mut book = Book::load(&dir).unwrap();
    let r = book.take(&f[4..], b, &state, &keys, &store, Some(NOW + 6)).unwrap_err();
    assert!(r.refusal.answer && r.answer.is_some());
    // The next command goes on; one without orders needs no statement.
    let f2 = root_book.send(&K::new(1), &state, &statements, b, COMMAND_UNMUTE, None, NOW).unwrap();
    let t2 = book.take(&f2[4..], b, &state, &keys, &store, Some(NOW + 7)).unwrap();
    assert!(t2.orders.is_none());
    // The commander's counter survives its restart.
    assert_eq!(Book::load(&temp_keep(&root_book)).unwrap().sent, root_book.sent);
}

fn temp_keep(b: &Book) -> std::path::PathBuf {
    b.path.parent().unwrap().to_path_buf()
}

#[test]
fn a_command_from_no_commander_or_to_another_device_is_refused() {
    let set = group();
    let state = set.state();
    let keys = Keys::of(&set);
    let b = K::new(3).key().device_id();
    let (store, statements) = b_keys(&state, &temp("refused-st"));
    let mut book = Book::load(&temp("refused-b")).unwrap();
    // A stranger: silent, no answer.
    let f = Book::load(&temp("refused-x"))
        .unwrap()
        .send(&K::new(9), &state, &statements, b, COMMAND_UNMUTE, None, NOW)
        .unwrap();
    let r = book.take(&f[4..], b, &state, &keys, &store, Some(NOW)).unwrap_err();
    assert!(!r.refusal.answer && r.answer.is_none());
    // A member that is no admin: signed, answered.
    let f = Book::load(&temp("refused-a"))
        .unwrap()
        .send(&K::new(2), &state, &statements, b, COMMAND_UNMUTE, None, NOW)
        .unwrap();
    let r = book.take(&f[4..], b, &state, &keys, &store, Some(NOW)).unwrap_err();
    assert!(r.refusal.answer && r.answer.is_some());
    // To device a, taken at b.
    let a = K::new(2).key().device_id();
    let f = Book::load(&temp("refused-r"))
        .unwrap()
        .send(&K::new(1), &state, &statements, a, COMMAND_UNMUTE, None, NOW)
        .unwrap();
    let r = book.take(&f[4..], b, &state, &keys, &store, Some(NOW)).unwrap_err();
    assert_eq!(r.refusal.rule, cbb_core::commands::RULE_TO);
    // Late.
    let f = Book::load(&temp("refused-late"))
        .unwrap()
        .send(&K::new(1), &state, &statements, b, COMMAND_UNMUTE, None, NOW)
        .unwrap();
    assert!(book.take(&f[4..], b, &state, &keys, &store, Some(NOW + 700_000)).is_err());
    // Orders to a device without a statement here cannot be written.
    let orders = Value::Map(vec![(10, Value::Uint(1))]).encode();
    let none = Statements::load(&temp("refused-none")).unwrap();
    assert!(
        Book::load(&temp("refused-o"))
            .unwrap()
            .send(&K::new(1), &state, &none, b, COMMAND_MODE, Some(&orders), NOW)
            .is_err()
    );
}
