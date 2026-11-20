// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

use cbb_core::keystore::{MemoryStore, rotate};
use cbb_core::records::body::{self, Device};
use cbb_core::records::{Key, Kind, RecordSet, Recovery, key::ALG_SLH_DSA, pq};
use p256::ecdsa::SigningKey;
use p256::ecdsa::signature::hazmat::PrehashSigner as _;

use super::*;

#[derive(Clone)]
struct K(SigningKey);

impl K {
    fn new(n: u8) -> K {
        K(SigningKey::from_slice(&[n; 32]).unwrap())
    }
    fn key(&self) -> Key {
        Key::es256(self.public())
    }
    fn id(&self) -> DeviceId {
        self.key().device_id()
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
const LIFE: Lifetimes = Lifetimes { secret_ms: 60_000, incoming_ms: 600_000 };

/// A group of devices a (key 2) and b (key 3) that read, send and take
/// secrets, and the state.
fn group() -> State {
    let root = K::new(1);
    let (k1, k2) = pq::recovery_keys(&[1; 32]).unwrap();
    let k1 = SigningKey::from(&k1).verifying_key().to_sec1_point(false).as_bytes().to_vec();
    let mut set =
        RecordSet::new(root.key(), Recovery::new(Key::es256(k1), Key::new(ALG_SLH_DSA, k2.public())).unwrap());
    for (n, name) in [(2, "a"), (3, "b")] {
        let mut d = Device::new(K::new(n).key(), name, body::ROLE_MEMBER);
        d.rights = body::RIGHT_READ | body::RIGHT_SEND | body::RIGHT_SECRETS;
        let st = set.state();
        set.write_record(&st, &root, Kind::device(d), NOW - 1000).unwrap();
    }
    set.state()
}

/// A device's key store with its first epoch, and its statement.
fn store(n: u8, state: &State) -> (MemoryStore<K>, Vec<u8>) {
    let mut s = MemoryStore::new(K::new(n));
    let made = rotate(&mut s, &state.group, NOW - 500, Some(NOW - 500)).unwrap().made.unwrap();
    (s, made)
}

fn temp(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("cbb-sealed-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn at(ms: u64) -> Timestamp {
    Timestamp { wall: ms as i64, logical: 0 }
}

#[test]
fn a_copy_reaches_the_other_reader_once() {
    let state = group();
    let (_sa, ea) = store(2, &state);
    let (sb, eb) = store(3, &state);
    let mut st = Statements::load(&temp("once")).unwrap();
    assert!(st.add(&ea).unwrap() && st.add(&eb).unwrap());
    assert!(!st.add(&eb).unwrap(), "a statement once");
    assert_eq!(st.sealing(&state).len(), 2);

    let content = Content::text("hello", false);
    let (frame, kept) = make(&K::new(2), &state, &st, &content, at(NOW), Some(NOW)).unwrap().unwrap();
    assert_eq!(kept.content, content);
    let mut marks = fresh::Marks::default();
    let taken = take(&frame[4..], &K::new(3).id(), &state, &sb, &mut marks, LIFE, Some(NOW + 10)).unwrap();
    let Taken::New { content: got, origin, signed, .. } = taken else { panic!("{taken:?}") };
    assert_eq!(*got, content);
    assert_eq!(origin, K::new(2).id());
    marks.wrote(&origin, signed);
    // The same copy again is not newer.
    let again = take(&frame[4..], &K::new(3).id(), &state, &sb, &mut marks, LIFE, Some(NOW + 20)).unwrap();
    assert!(matches!(again, Taken::Old(fresh::Fresh::Behind)), "{again:?}");
    // The origin is no reader of its own copy: it passes it on.
    let (sa, _) = store(2, &state);
    let own = take(&frame[4..], &K::new(2).id(), &state, &sa, &mut fresh::Marks::default(), LIFE, Some(NOW)).unwrap();
    assert!(matches!(own, Taken::PassedOn));
}

#[test]
fn a_copy_from_outside_the_group_is_refused() {
    let state = group();
    let (_, ea) = store(2, &state);
    let (sb, eb) = store(3, &state);
    let mut st = Statements::load(&temp("outside")).unwrap();
    st.add(&ea).unwrap();
    st.add(&eb).unwrap();
    // A stranger seals to b with b's statement, and signs with its own key.
    let (frame, _) = make(&K::new(9), &state, &st, &Content::text("x", false), at(NOW), Some(NOW)).unwrap().unwrap();
    let r = take(&frame[4..], &K::new(3).id(), &state, &sb, &mut fresh::Marks::default(), LIFE, Some(NOW));
    assert!(r.is_err());
    // A flipped byte breaks the signature.
    let (mut frame, _) =
        make(&K::new(2), &state, &st, &Content::text("x", false), at(NOW), Some(NOW)).unwrap().unwrap();
    let n = frame.len() - 40;
    frame[n] ^= 1;
    assert!(take(&frame[4..], &K::new(3).id(), &state, &sb, &mut fresh::Marks::default(), LIFE, Some(NOW)).is_err());
}

#[test]
fn no_reader_no_copy_and_an_old_epoch_asks_again() {
    let state = group();
    let (_, ea) = store(2, &state);
    let mut st = Statements::load(&temp("noreader")).unwrap();
    st.add(&ea).unwrap();
    // b has no statement: nobody to seal to.
    assert!(make(&K::new(2), &state, &st, &Content::text("x", false), at(NOW), Some(NOW)).unwrap().is_none());

    // b's epoch 1 is sealed to, then b moves on two weeks and erases it.
    let (mut sb, eb) = store(3, &state);
    st.add(&eb).unwrap();
    let (frame, _) = make(&K::new(2), &state, &st, &Content::text("x", false), at(NOW), Some(NOW)).unwrap().unwrap();
    let week = cbb_core::keystore::WEEK_MS;
    rotate(&mut sb, &state.group, NOW + week, Some(NOW + week)).unwrap();
    rotate(&mut sb, &state.group, NOW + 2 * week + 1, Some(NOW + 2 * week + 1)).unwrap();
    assert!(sb.sealing(1).is_none());
    let r = take(&frame[4..], &K::new(3).id(), &state, &sb, &mut fresh::Marks::default(), LIFE, Some(NOW)).unwrap();
    let Taken::Reseal(f) = r else { panic!("{r:?}") };
    assert_eq!(cbb_core::msg::check(&f[4..]), Ok(copies::T_RESEAL));
}

#[test]
fn statements_travel_and_are_kept() {
    let state = group();
    let (_, ea) = store(2, &state);
    let (_, eb) = store(3, &state);
    let dir = temp("kept");
    let mut st = Statements::load(&dir).unwrap();
    st.add(&ea).unwrap();
    st.add(&eb).unwrap();
    st.save().unwrap();
    let back = Statements::load(&dir).unwrap();
    assert_eq!(back.sealing(&state).len(), 2);
    // Message keys carries them to a peer.
    let mut peer = Statements::load(&temp("peer")).unwrap();
    let msgs = st.messages();
    assert_eq!(msgs.len(), 1);
    assert_eq!(peer.take_message(&msgs[0][4..]).unwrap(), 2);
    assert_eq!(peer.take_message(&msgs[0][4..]).unwrap(), 0);
    // Garbage is no statement.
    assert!(peer.add(b"not a statement").is_err());
    let _ = std::fs::remove_dir_all(&dir);
}
