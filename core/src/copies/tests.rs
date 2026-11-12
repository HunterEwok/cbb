// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! Copies sealed end to end: who they are sealed to, the key bound to the
//! header, checking on the way, opening, the leaf's reduced copy, the mark,
//! sealing again after a key change, and freshness from signed fields.

use alloc::vec;

use super::fresh::{self, Fresh, Marks};
use super::*;
use crate::content::{Content, TYPE_STATE};
use crate::format::copy::write_content;
use crate::keystore::{self, WEEK_MS};
use crate::records::body::*;
use crate::testkit::{self, G, K, T0, k, sealing, store};

const DAY: u64 = 86_400_000;

fn made(n: u8) -> Made {
    Made { id: [n; 16], time: Timestamp { wall: (T0 + u64::from(n)) as i64, logical: 0 }, blob: None }
}

/// A group of a root phone, a laptop, a desktop that does not read secrets,
/// a watch, a forward-only hub and a kettle; each with its first epoch.
struct World {
    g: G,
    phone: K,
    laptop: K,
    desktop: K,
    stores: BTreeMap<&'static str, keystore::MemoryStore<K>>,
    statements: Vec<crate::records::statement::Statement>,
}

impl World {
    fn new() -> World {
        let mut g = G::new();
        let phone = g.device("phone", ROLE_PHONE, RIGHT_READ | RIGHT_SEND | RIGHT_SECRETS, |_| {});
        let laptop = g.device("laptop", ROLE_MEMBER, RIGHT_READ | RIGHT_SEND | RIGHT_SECRETS, |_| {});
        let desktop = g.device("desktop", ROLE_MEMBER, RIGHT_READ | RIGHT_SEND, |_| {});
        g.device("watch", ROLE_WATCH, RIGHT_READ | RIGHT_SEND, |_| {});
        g.device("hub", ROLE_MEMBER, RIGHT_HUB, |_| {});
        g.device("kettle", ROLE_LEAF, RIGHT_READ | RIGHT_SEND, |_| {});
        let mut stores = BTreeMap::new();
        let mut statements = Vec::new();
        for name in ["phone", "laptop", "desktop", "watch", "hub", "kettle"] {
            let (s, st) = store(name, &g.gid);
            stores.insert(name, s);
            statements.push(st);
        }
        World { g, phone, laptop, desktop, stores, statements }
    }

    fn sealing(&self) -> BTreeMap<DeviceId, Sealing> {
        let refs: Vec<&_> = self.statements.iter().collect();
        sealing(&self.g.state(), &refs)
    }

    fn id(&self, name: &str) -> DeviceId {
        k(name).key.device_id()
    }
}

fn opened(o: Opened) -> Content {
    match o {
        Opened::Content { content, .. } => content,
        other => panic!("not opened: {other:?}"),
    }
}

#[test]
fn a_copy_is_sealed_to_the_devices_that_read_it() {
    let w = World::new();
    let state = w.g.state();
    let s = w.sealing();
    let ids = |rs: Vec<Reader>| rs.into_iter().map(|r| r.id).collect::<Vec<_>>();
    let mut want = vec![w.id("laptop"), w.id("desktop")];
    want.sort();
    // Not the origin, not the watch (it reads through its phone), not the
    // forward-only hub, not a leaf it is not a reader of.
    assert_eq!(ids(readers(&state, &s, &Content::text("x", false), &w.id("phone"), &[])), want);
    // A secret only to devices that take secrets.
    assert_eq!(ids(readers(&state, &s, &Content::text("x", true), &w.id("phone"), &[])), vec![w.id("laptop")]);
    // The kettle when the phone is a reader of its grant.
    let with_leaf = ids(readers(&state, &s, &Content::text("x", false), &w.id("phone"), &[w.id("kettle")]));
    assert!(with_leaf.contains(&w.id("kettle")));
    // A device that skips the type.
    let mut g = World::new();
    g.g.device("laptop", ROLE_MEMBER, RIGHT_READ | RIGHT_SEND, |d| d.skip = 1 << (TYPE_STATE - 1));
    let st = g.g.state();
    let refs: Vec<&_> = g.statements.iter().collect();
    let s2 = sealing(&st, &refs);
    assert!(!ids(readers(&st, &s2, &Content::state(&[1]), &g.id("phone"), &[])).contains(&g.id("laptop")));
    // No statement, no copy: root and admin keys open nothing.
    let none = readers(&state, &BTreeMap::new(), &Content::text("x", false), &w.id("phone"), &[]);
    assert!(none.is_empty());
}

#[test]
fn every_reader_opens_its_own_wrap_and_nobody_else_reads() {
    let w = World::new();
    let state = w.g.state();
    let rs = readers(&state, &w.sealing(), &Content::text("hello", false), &w.id("phone"), &[]);
    let copy = seal(&w.phone, &rs, &made(1), &Content::text("hello", false)).unwrap();
    let v = cbor::decode(&copy).unwrap();
    let c = check(&v, &state).unwrap();
    assert_eq!(c.origin, w.id("phone"));
    for name in ["laptop", "desktop"] {
        let got = opened(open(&c, &w.id(name), &w.stores[name]).unwrap());
        assert_eq!(got.text.as_deref(), Some("hello"));
    }
    // The hub passes it on unread; so does the watch.
    assert_eq!(open(&c, &w.id("hub"), &w.stores["hub"]).unwrap(), Opened::NotForMe);
    assert_eq!(open(&c, &w.id("watch"), &w.stores["watch"]).unwrap(), Opened::NotForMe);
    // Another device's key does not open a wrap.
    let laptop_wrap_for_desktop =
        Checked { readers: c.readers.iter().map(|(_, e)| (w.id("desktop"), *e)).collect(), ..c.clone() };
    let i = c.readers.iter().position(|(d, _)| *d == w.id("laptop")).unwrap();
    let only = Checked {
        readers: vec![laptop_wrap_for_desktop.readers[i]],
        copy: Copy { wraps: vec![c.copy.wraps[i]], ..c.copy.clone() },
        ..c.clone()
    };
    assert_eq!(open(&only, &w.id("desktop"), &w.stores["desktop"]), Err(RULE_WRAP));
}

#[test]
fn every_member_checks_the_origin_before_passing_a_copy_on() {
    let w = World::new();
    let state = w.g.state();
    let rs = readers(&state, &w.sealing(), &Content::text("x", false), &w.id("phone"), &[]);
    // From a stranger: it waits for the records.
    let stranger = k("stranger");
    let copy = seal(&stranger, &rs, &made(1), &Content::text("x", false)).unwrap();
    assert_eq!(check(&cbor::decode(&copy).unwrap(), &state).err(), Some(RULE_ORIGIN));
    // From the forward-only hub, which may not send.
    let hub = k("hub");
    let copy = seal(&hub, &rs, &made(1), &Content::text("x", false)).unwrap();
    assert_eq!(check(&cbor::decode(&copy).unwrap(), &state).err(), Some(RULE_SEND));
    // A copy whose header names the phone but another key signed.
    let copy = seal(&w.phone, &rs, &made(1), &Content::text("x", false)).unwrap();
    let v = cbor::decode(&copy).unwrap();
    let forged = fcopy::Copy::from_value(&v).unwrap();
    let sig =
        rkey::sign_es256(&w.laptop, sig::LABEL_COPY_SIG, &fcopy::signed(&forged.h, &forged.w, &forged.p)).unwrap();
    let swapped = Value::Map(
        v.as_map()
            .unwrap()
            .iter()
            .map(|(n, x)| if *n == fcopy::FIELD_SIG { (*n, Value::Bytes(&sig)) } else { (*n, x.clone()) })
            .collect(),
    );
    assert_eq!(check(&swapped, &state).err(), Some(Rule::SIG_VERIFY));
    // A payload changed on the way.
    let changed: Vec<(u16, Value<'_>)> = v
        .as_map()
        .unwrap()
        .iter()
        .map(|(n, x)| if *n == fcopy::FIELD_PAYLOAD { (*n, Value::Bytes(&[0u8; 1040])) } else { (*n, x.clone()) })
        .collect();
    assert_eq!(check(&Value::Map(changed), &state).err(), Some(Rule::SIG_VERIFY));
    // A removed origin's copies stop.
    let mut g = World::new();
    g.g.revoke(&[g.laptop.hash]);
    let copy = seal(&g.laptop, &rs, &made(2), &Content::text("x", false)).unwrap();
    assert!(check(&cbor::decode(&copy).unwrap(), &g.g.state()).is_err());
    let _ = &w.desktop;
}

/// A copy whose header commits to another key than the one its wraps
/// carry: signed by the origin, so only the reader's check finds it.
#[test]
fn the_copy_key_is_bound_to_its_header() {
    let w = World::new();
    let state = w.g.state();
    let rs = readers(&state, &w.sealing(), &Content::text("x", false), &w.id("phone"), &[]);
    let (k1, k2) = ([1u8; 32], [2u8; 32]);
    let plain = Content::text("x", false).write().unwrap();
    let entries: Vec<Value<'_>> =
        rs.iter().map(|r| Value::Array(vec![Value::Bytes(&r.id.0), Value::Uint(r.epoch)])).collect();
    let origin = w.id("phone");
    let commit = fcopy::commit(&k2);
    let hdr = Value::Map(vec![
        (1, Value::Bytes(&[9; 16])),
        (2, Value::Bytes(&origin.0)),
        (3, Value::Array(vec![Value::Uint(T0), Value::Uint(0)])),
        (4, Value::Array(entries)),
        (6, Value::Bytes(&commit)),
    ])
    .encode();
    let h = fcopy::header_hash(&hdr);
    let payload =
        aead(&fcopy::payload_key(&k1, &h)).encrypt(&Nonce::default(), Payload { msg: &plain, aad: &h }).unwrap();
    let wraps: Vec<Vec<u8>> = rs.iter().map(|r| crate::seal::seal(&r.seal, &h, &k1).unwrap()).collect();
    let hashes: Vec<[u8; 32]> = wraps.iter().map(|x| sha256(&[x])).collect();
    let s = rkey::sign_es256(
        &w.phone,
        sig::LABEL_COPY_SIG,
        &fcopy::signed(&h, &fcopy::wraps_digest(&hashes), &sha256(&[&payload])),
    )
    .unwrap();
    let v = Value::Map(vec![
        (1, Value::Bytes(&hdr)),
        (3, Value::Array(wraps.iter().map(|x| Value::Bytes(x)).collect())),
        (4, Value::Bytes(&payload)),
        (6, Value::Bytes(&s)),
    ]);
    let c = check(&v, &state).unwrap();
    assert_eq!(open(&c, &w.id("laptop"), &w.stores["laptop"]), Err(fcopy::RULE_COMMIT));
    // One K under two headers gives two payload keys (A-75).
    let h2 = fcopy::header_hash(b"another header");
    assert_ne!(fcopy::payload_key(&k1, &h), fcopy::payload_key(&k1, &h2));
    assert_ne!(fcopy::blob_key(&k1, &h), fcopy::blob_key(&k1, &h2));
}

#[test]
fn an_older_device_passes_an_unknown_type_on_and_does_not_write_it() {
    let w = World::new();
    let state = w.g.state();
    let rs = readers(&state, &w.sealing(), &Content::text("x", false), &w.id("phone"), &[]);
    let later =
        write_content(&Value::Map(vec![(0, Value::Uint(9)), (5, Value::Text("from a later version"))])).unwrap();
    let seeds = vec![[3u8; 32]; rs.len()];
    let copy = seal_bytes(&w.phone, &rs, &made(1), &later, &[5; 32], &seeds).unwrap();
    let v = cbor::decode(&copy).unwrap();
    // It checks, so it is passed on.
    let c = check(&v, &state).unwrap();
    let got = opened(open(&c, &w.id("laptop"), &w.stores["laptop"]).unwrap());
    assert!(got.unknown && !got.writable(), "{got:?}");
}

#[test]
fn a_leaf_gets_a_reduced_copy_within_its_frame() {
    let w = World::new();
    let state = w.g.state();
    let kettle = w.id("kettle");
    let rs = readers(&state, &w.sealing(), &Content::text("tea", false), &w.id("phone"), &[kettle]);
    assert!(rs.len() >= 3);
    let copy = seal(&w.phone, &rs, &made(1), &Content::text("tea", false)).unwrap();
    let v = cbor::decode(&copy).unwrap();
    let c = check(&v, &state).unwrap();
    let reduced = reduce(&c.copy, &c.readers, &kettle).unwrap();
    let msg = message(&reduced).unwrap();
    assert!(msg.len() <= frame::LIMIT_LEAF, "{} bytes", msg.len());
    assert!(frame::read(&msg, frame::LIMIT_LEAF).is_ok());
    // The leaf checks the signature from the reduced copy alone and opens
    // its own wrap.
    let rv = cbor::decode(&reduced).unwrap();
    let rc = check(&rv, &state).unwrap();
    assert_eq!(opened(open(&rc, &kettle, &w.stores["kettle"]).unwrap()).text.as_deref(), Some("tea"));
    assert!(rc.copy.wraps.iter().filter(|x| x.len() == fcopy::WRAP_SIZE).count() == 1);
    // A payload too large for the frame goes as its hash.
    let big = Content::text(&"x".repeat(20_000), false);
    let copy = seal(&w.phone, &rs, &made(2), &big).unwrap();
    let v = cbor::decode(&copy).unwrap();
    let c = check(&v, &state).unwrap();
    let reduced = reduce(&c.copy, &c.readers, &kettle).unwrap();
    assert!(message(&reduced).unwrap().len() <= frame::LIMIT_LEAF);
    let rv = cbor::decode(&reduced).unwrap();
    let rc = check(&rv, &state).unwrap();
    assert_eq!(open(&rc, &kettle, &w.stores["kettle"]).unwrap(), Opened::NoPayload);
    // Not sealed to the leaf: nothing to send it.
    assert_eq!(reduce(&c.copy, &c.readers, &k("stranger").key.device_id()).err(), Some(RULE_LEAF_FRAME));
    // A peer learns the leaf's limit from its record.
    assert_eq!(frame_limit(state.device(&kettle).unwrap()), frame::LIMIT_LEAF);
    assert_eq!(frame_limit(state.device(&w.id("laptop")).unwrap()), frame::LIMIT_MEMBER);
}

#[test]
fn a_secret_mark_verifies_and_holds_no_payload() {
    let w = World::new();
    let state = w.g.state();
    let rs = readers(&state, &w.sealing(), &Content::text("pw", true), &w.id("phone"), &[]);
    let copy = seal(&w.phone, &rs, &made(1), &Content::text("pw", true)).unwrap();
    let v = cbor::decode(&copy).unwrap();
    let c = check(&v, &state).unwrap();
    let m = mark(&c.copy);
    let mv = cbor::decode(&m).unwrap();
    let mc = check(&mv, &state).unwrap();
    assert!(mc.copy.payload.is_none());
    assert_eq!(open(&mc, &w.id("laptop"), &w.stores["laptop"]).unwrap(), Opened::NoPayload);
}

/// The wave's promise: a device that slept through a key change gets the
/// copy after it asks to have it sealed again.
#[test]
fn a_device_that_slept_through_a_key_change_gets_the_copy_sealed_again() {
    let mut w = World::new();
    let state = w.g.state();
    let content = Content::text("while you slept", false);
    let rs = readers(&state, &w.sealing(), &content, &w.id("phone"), &[]);
    let m = made(1);
    let copy = seal(&w.phone, &rs, &m, &content).unwrap();
    let kept = Kept { made: m, content: content.clone(), readers: rs.iter().map(|r| r.id).collect() };
    // The laptop sleeps three weeks: two epochs later its epoch 1 is gone.
    let laptop = w.stores.get_mut("laptop").unwrap();
    keystore::rotate(laptop, &w.g.gid, T0 + 2 * WEEK_MS).unwrap();
    let r = keystore::rotate(laptop, &w.g.gid, T0 + 3 * WEEK_MS).unwrap();
    assert!(r.erased.contains(&1));
    let now = testkit::statement_of(r.made.as_ref().unwrap());
    let v = cbor::decode(&copy).unwrap();
    let c = check(&v, &state).unwrap();
    let Opened::Reseal { epoch } = open(&c, &w.id("laptop"), &w.stores["laptop"]).unwrap() else { panic!() };
    assert_eq!(epoch, 1);
    // It asks at its current epoch; the origin learns its new statement.
    let ask = reseal_request(&c.id, now.body().epoch);
    let msg = frame::read(&ask, frame::LIMIT_MEMBER).unwrap();
    assert_eq!(msg.t, T_RESEAL);
    w.statements.push(now.clone());
    let s = w.sealing();
    assert_eq!(s[&w.id("laptop")].statement.body().epoch, 3);
    // Not to a device that was no reader, nor to another epoch.
    assert_eq!(reseal(&w.phone, &kept, &state, &s, &w.id("watch"), 1, &[]).err(), Some(RULE_RESEAL_READER));
    assert_eq!(reseal(&w.phone, &kept, &state, &s, &w.id("laptop"), 2, &[]).err(), Some(RULE_RESEAL_EPOCH));
    let again = reseal(&w.phone, &kept, &state, &s, &w.id("laptop"), 3, &[]).unwrap();
    let v = cbor::decode(&again).unwrap();
    let c2 = check(&v, &state).unwrap();
    assert_eq!((c2.id, c2.time), (c.id, c.time), "the same copy, at its own time");
    assert_eq!(opened(open(&c2, &w.id("laptop"), &w.stores["laptop"]).unwrap()), content);
    // A device that lost the right to read since is not sealed it again.
    let mut g2 = World::new();
    g2.g.device("laptop", ROLE_MEMBER, RIGHT_SEND, |_| {});
    let st2 = g2.g.state();
    let refs: Vec<&_> = w.statements.iter().collect();
    let s2 = sealing(&st2, &refs);
    assert_eq!(reseal(&w.phone, &kept, &st2, &s2, &w.id("laptop"), 3, &[]).err(), Some(RULE_RESEAL_READER));
}

#[test]
fn freshness_is_decided_from_signed_fields() {
    let t = |wall: u64, l: u32| Timestamp { wall: wall as i64, logical: l };
    let mut m = Marks::default();
    // A secret made a day ago, replayed with age 0: its age is a day.
    let old = t(T0, 0);
    assert_eq!(m.judge(&[1; 16], old, 0, true, Some(T0 + DAY)), Fresh::New { age_ms: DAY - fresh::ALLOWANCE_MS });
    // Seen once, never again, even after a restart.
    let saved = m.encode();
    let mut back = Marks::decode(&saved).unwrap();
    assert_eq!(back, m);
    assert_eq!(back.judge(&[1; 16], old, 0, true, Some(T0 + 1)), Fresh::SeenSecret);
    // A copy not after the newest written is behind (A-61), with or
    // without a clock.
    back.wrote(t(T0 + 5000, 0));
    assert_eq!(back.judge(&[2; 16], t(T0 + 5000, 0), 0, false, None), Fresh::Behind);
    assert_eq!(back.judge(&[3; 16], t(T0 + 5000, 1), 7, false, None), Fresh::New { age_ms: 7 });
    // An origin's clock a little ahead is allowed.
    assert_eq!(fresh::effective_age(0, t(T0 + 60_000, 0), Some(T0)), 0);
    // Past the list's length the floor still holds.
    let mut f = Marks::default();
    for i in 0..(fresh::MAX_SECRETS as u64 + 10) {
        let mut id = [0u8; 16];
        id[..8].copy_from_slice(&i.to_be_bytes());
        f.judge(&id, t(T0 + i, 0), 0, true, None);
    }
    assert_eq!(f.secrets.len(), fresh::MAX_SECRETS);
    assert_eq!(f.judge(&[0; 16], t(T0, 0), 0, true, None), Fresh::SeenSecret);
    assert!(Marks::decode(&[0xa0]).is_err());
}
