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
    assert_eq!(ids(readers(&state, &s, &Content::text("x", false), &w.id("phone"), &[], None)), want);
    // A secret only to devices that take secrets.
    assert_eq!(ids(readers(&state, &s, &Content::text("x", true), &w.id("phone"), &[], None)), vec![w.id("laptop")]);
    // The kettle when the phone is a reader of its grant.
    let with_leaf = ids(readers(&state, &s, &Content::text("x", false), &w.id("phone"), &[w.id("kettle")], None));
    assert!(with_leaf.contains(&w.id("kettle")));
    // A device that skips the type.
    let mut g = World::new();
    g.g.device("laptop", ROLE_MEMBER, RIGHT_READ | RIGHT_SEND, |d| d.skip = 1 << (TYPE_STATE - 1));
    let st = g.g.state();
    let refs: Vec<&_> = g.statements.iter().collect();
    let s2 = sealing(&st, &refs);
    assert!(!ids(readers(&st, &s2, &Content::state(&[1]), &g.id("phone"), &[], None)).contains(&g.id("laptop")));
    // No statement, no copy: root and admin keys open nothing.
    let none = readers(&state, &BTreeMap::new(), &Content::text("x", false), &w.id("phone"), &[], None);
    assert!(none.is_empty());
}

#[test]
fn every_reader_opens_its_own_wrap_and_nobody_else_reads() {
    let w = World::new();
    let state = w.g.state();
    let rs = readers(&state, &w.sealing(), &Content::text("hello", false), &w.id("phone"), &[], None);
    let copy = seal(&w.phone, &rs, &made(1), &Content::text("hello", false)).unwrap();
    let v = cbor::decode(&copy).unwrap();
    let c = check(&v, &state).unwrap();
    assert_eq!(c.origin, w.id("phone"));
    for name in ["laptop", "desktop"] {
        let got = opened(open(&c, &w.id(name), &w.stores[name], &state).unwrap());
        assert_eq!(got.text.as_deref(), Some("hello"));
    }
    // The hub passes it on unread; so does the watch.
    assert_eq!(open(&c, &w.id("hub"), &w.stores["hub"], &state).unwrap(), Opened::NotForMe);
    assert_eq!(open(&c, &w.id("watch"), &w.stores["watch"], &state).unwrap(), Opened::NotForMe);
    // Another device's key does not open a wrap.
    let laptop_wrap_for_desktop =
        Checked { readers: c.readers.iter().map(|(_, e)| (w.id("desktop"), *e)).collect(), ..c.clone() };
    let i = c.readers.iter().position(|(d, _)| *d == w.id("laptop")).unwrap();
    let only = Checked {
        readers: vec![laptop_wrap_for_desktop.readers[i]],
        copy: Copy { wraps: vec![c.copy.wraps[i]], ..c.copy.clone() },
        ..c.clone()
    };
    assert_eq!(open(&only, &w.id("desktop"), &w.stores["desktop"], &state), Err(RULE_WRAP));
}

#[test]
fn every_member_checks_the_origin_before_passing_a_copy_on() {
    let w = World::new();
    let state = w.g.state();
    let rs = readers(&state, &w.sealing(), &Content::text("x", false), &w.id("phone"), &[], None);
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
    let rs = readers(&state, &w.sealing(), &Content::text("x", false), &w.id("phone"), &[], None);
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
    assert_eq!(open(&c, &w.id("laptop"), &w.stores["laptop"], &state), Err(fcopy::RULE_COMMIT));
    // One K under two headers gives two payload keys (A-75).
    let h2 = fcopy::header_hash(b"another header");
    assert_ne!(fcopy::payload_key(&k1, &h), fcopy::payload_key(&k1, &h2));
    assert_ne!(fcopy::blob_key(&k1, &h), fcopy::blob_key(&k1, &h2));
}

#[test]
fn an_older_device_passes_an_unknown_type_on_and_does_not_write_it() {
    let w = World::new();
    let state = w.g.state();
    let rs = readers(&state, &w.sealing(), &Content::text("x", false), &w.id("phone"), &[], None);
    let later =
        write_content(&Value::Map(vec![(0, Value::Uint(9)), (5, Value::Text("from a later version"))])).unwrap();
    let seeds = vec![[3u8; 32]; rs.len()];
    let copy = seal_bytes(&w.phone, &rs, &made(1), &later, &[5; 32], &seeds).unwrap();
    let v = cbor::decode(&copy).unwrap();
    // It checks, so it is passed on.
    let c = check(&v, &state).unwrap();
    let got = opened(open(&c, &w.id("laptop"), &w.stores["laptop"], &state).unwrap());
    assert!(got.unknown && !got.writable(), "{got:?}");
}

#[test]
fn a_leaf_gets_a_reduced_copy_within_its_frame() {
    let w = World::new();
    let state = w.g.state();
    let kettle = w.id("kettle");
    let rs = readers(&state, &w.sealing(), &Content::text("tea", false), &w.id("phone"), &[kettle], None);
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
    assert_eq!(opened(open(&rc, &kettle, &w.stores["kettle"], &state).unwrap()).text.as_deref(), Some("tea"));
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
    assert_eq!(open(&rc, &kettle, &w.stores["kettle"], &state).unwrap(), Opened::NoPayload);
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
    let rs = readers(&state, &w.sealing(), &Content::text("pw", true), &w.id("phone"), &[], None);
    let copy = seal(&w.phone, &rs, &made(1), &Content::text("pw", true)).unwrap();
    let v = cbor::decode(&copy).unwrap();
    let c = check(&v, &state).unwrap();
    let m = mark(&c.copy);
    let mv = cbor::decode(&m).unwrap();
    let mc = check(&mv, &state).unwrap();
    assert!(mc.copy.payload.is_none());
    assert_eq!(open(&mc, &w.id("laptop"), &w.stores["laptop"], &state).unwrap(), Opened::NoPayload);
}

/// The wave's promise: a device that slept through a key change gets the
/// copy after it asks to have it sealed again.
#[test]
fn a_device_that_slept_through_a_key_change_gets_the_copy_sealed_again() {
    let mut w = World::new();
    let state = w.g.state();
    let content = Content::text("while you slept", false);
    let rs = readers(&state, &w.sealing(), &content, &w.id("phone"), &[], None);
    let m = made(1);
    let copy = seal(&w.phone, &rs, &m, &content).unwrap();
    let mut kept = Kept::new(m, content.clone(), &rs);
    // The laptop sleeps three weeks: two epochs later its epoch 1 is gone.
    let laptop = w.stores.get_mut("laptop").unwrap();
    keystore::rotate(laptop, &w.g.gid, T0 + 2 * WEEK_MS, Some(T0 + 2 * WEEK_MS)).unwrap();
    let r = keystore::rotate(laptop, &w.g.gid, T0 + 3 * WEEK_MS, Some(T0 + 3 * WEEK_MS)).unwrap();
    assert!(r.erased.contains(&1));
    let now = testkit::statement_of(r.made.as_ref().unwrap());
    let v = cbor::decode(&copy).unwrap();
    let c = check(&v, &state).unwrap();
    let Opened::Reseal { epoch } = open(&c, &w.id("laptop"), &w.stores["laptop"], &state).unwrap() else { panic!() };
    assert_eq!(epoch, 1);
    // It asks at its current epoch; the origin learns its new statement.
    let ask = reseal_request(&c.id, now.body().epoch);
    let msg = frame::read(&ask, frame::LIMIT_MEMBER).unwrap();
    assert_eq!(msg.t, T_RESEAL);
    w.statements.push(now.clone());
    let s = w.sealing();
    assert_eq!(s[&w.id("laptop")].statement.body().epoch, 3);
    // Not to a device that was no reader, nor to another epoch.
    let ask = |who: &str, epoch| Ask { asker: w.id(who), epoch, leaves: &[], now_ms: Some(T0), group_ttl_ms: DAY };
    assert_eq!(reseal(&w.phone, &mut kept, &state, &s, &ask("watch", 1)).err(), Some(RULE_RESEAL_READER));
    assert_eq!(reseal(&w.phone, &mut kept, &state, &s, &ask("laptop", 2)).err(), Some(RULE_RESEAL_EPOCH));
    // A halted group (a recovery record this device cannot read, as for
    // a fork) seals nothing again, seals to nobody and opens nothing.
    let mut halted = state.clone();
    halted.update_needed = true;
    assert_eq!(reseal(&w.phone, &mut kept, &halted, &s, &ask("laptop", 3)).err(), Some(RULE_RESEAL_HALTED));
    assert!(readers(&halted, &s, &content, &w.id("phone"), &[], None).is_empty());
    assert_eq!(open(&c, &w.id("laptop"), &w.stores["laptop"], &halted).unwrap(), Opened::Halted);
    let again = reseal(&w.phone, &mut kept, &state, &s, &ask("laptop", 3)).unwrap();
    let v = cbor::decode(&again).unwrap();
    let c2 = check(&v, &state).unwrap();
    assert_eq!((c2.id, c2.time), (c.id, c.time), "the same copy, at its own time");
    assert_eq!(opened(open(&c2, &w.id("laptop"), &w.stores["laptop"], &state).unwrap()), content);
    // A device that lost the right to read since is not sealed it again.
    let mut g2 = World::new();
    g2.g.device("laptop", ROLE_MEMBER, RIGHT_SEND, |_| {});
    let st2 = g2.g.state();
    let refs: Vec<&_> = w.statements.iter().collect();
    let s2 = sealing(&st2, &refs);
    assert_eq!(reseal(&w.phone, &mut kept, &st2, &s2, &ask("laptop", 3)).err(), Some(RULE_RESEAL_READER));
}

#[test]
fn a_copy_sealed_again_is_passed_to_the_asker_and_limited() {
    let w = World::new();
    let state = w.g.state();
    let s = w.sealing();
    let content = Content::text("again", false);
    let rs = readers(&state, &s, &content, &w.id("phone"), &[], None);
    assert!(rs.len() >= 2, "the laptop and another reader");
    let m = made(1);
    let first_bytes = seal(&w.phone, &rs, &m, &content).unwrap();
    let mut kept = Kept::new(m, content.clone(), &rs);
    let ask = Ask { asker: w.id("laptop"), epoch: 1, leaves: &[], now_ms: None, group_ttl_ms: DAY };
    // A copy without a lifetime is sealed again without a clock.
    let again_bytes = reseal(&w.phone, &mut kept, &state, &s, &ask).unwrap();
    let (v1, v2) = (cbor::decode(&first_bytes).unwrap(), cbor::decode(&again_bytes).unwrap());
    let (first, again) = (check(&v1, &state).unwrap(), check(&v2, &state).unwrap());
    // A member holding the first keeps it and passes the second to the
    // asker alone; the same copy twice is dropped.
    assert_eq!(second(&first, &again), Second::Pass { to: vec![w.id("laptop")] });
    assert_eq!(second(&first, &first), Second::Drop);
    let other = seal(&w.phone, &rs, &made(2), &content).unwrap();
    let v3 = cbor::decode(&other).unwrap();
    assert_eq!(second(&first, &check(&v3, &state).unwrap()), Second::Another, "another copy");
    // The first still opens for its other readers.
    assert_eq!(opened(open(&first, &w.id("desktop"), &w.stores["desktop"], &state).unwrap()), content);
    // At most MAX_RESEALS times for one asker.
    reseal(&w.phone, &mut kept, &state, &s, &ask).unwrap();
    assert_eq!(reseal(&w.phone, &mut kept, &state, &s, &ask).err(), Some(RULE_RESEAL_LIMIT));
    assert_eq!(kept.resealed[&w.id("laptop")], MAX_RESEALS);
}

#[test]
fn a_secret_past_its_lifetime_is_not_sealed_again() {
    let w = World::new();
    let state = w.g.state();
    let s = w.sealing();
    let mut secret = Content::text("pin", true);
    secret.ttl = 2; // ten minutes
    let rs = readers(&state, &s, &secret, &w.id("phone"), &[], None);
    let mut kept = Kept::new(made(1), secret.clone(), &rs);
    let wall = u64::try_from(kept.made.time.wall).unwrap();
    let at = |now_ms| Ask { asker: w.id("laptop"), epoch: 1, leaves: &[], now_ms, group_ttl_ms: DAY };
    assert!(reseal(&w.phone, &mut kept, &state, &s, &at(Some(wall + 599_999))).is_ok());
    assert_eq!(reseal(&w.phone, &mut kept, &state, &s, &at(Some(wall + 600_000))).err(), Some(RULE_RESEAL_EXPIRED));
    // An origin without a clock cannot tell: a secret is not sealed again.
    assert_eq!(reseal(&w.phone, &mut kept, &state, &s, &at(None)).err(), Some(RULE_RESEAL_EXPIRED));
    // A secret without its own ttl lives the group's lifetime.
    let plain = Content::text("pin", true);
    let mut k2 = Kept::new(made(2), plain, &rs);
    let wall2 = u64::try_from(k2.made.time.wall).unwrap();
    assert_eq!(k2.life_ms(DAY), Some(DAY));
    let late = Ask { now_ms: Some(wall2 + DAY), ..at(None) };
    assert_eq!(reseal(&w.phone, &mut k2, &state, &s, &late).err(), Some(RULE_RESEAL_EXPIRED));
}

fn seen(w: &World, who: &str, id: u8, wall: u64, secret: bool) -> fresh::Seen {
    fresh::Seen {
        origin: w.id(who),
        id: [id; 16],
        signed: Timestamp { wall: wall as i64, logical: 0 },
        age_ms: 0,
        secret,
        ttl_ms: None,
    }
}

/// The marks are saved before a copy is written. A restart from the marks
/// one step old (saved before this copy) means it was not written yet: it
/// is written once more, and then never again; a secret seen before the
/// step stays seen.
#[test]
fn freshness_survives_a_restart_from_a_state_one_step_old() {
    let w = World::new();
    let st = w.g.state();
    let (a, b) = (seen(&w, "phone", 1, T0, true), seen(&w, "phone", 2, T0 + 1, false));
    let mut m = Marks::default();
    assert!(matches!(m.judge(&a, Some(T0), &st), Fresh::New { .. }));
    m.wrote(&a.origin, a.signed);
    let one_step_old = m.encode();
    assert!(matches!(m.judge(&b, Some(T0), &st), Fresh::New { .. }));
    m.wrote(&b.origin, b.signed);
    let mut back = Marks::decode(&one_step_old).unwrap();
    assert_eq!(back.judge(&a, Some(T0), &st), Fresh::SeenSecret);
    assert!(matches!(back.judge(&b, Some(T0), &st), Fresh::New { .. }));
    back.wrote(&b.origin, b.signed);
    let mut again = Marks::decode(&back.encode()).unwrap();
    assert_eq!(again.judge(&b, Some(T0), &st), Fresh::Behind);
}

#[test]
fn freshness_is_decided_from_signed_fields() {
    let w = World::new();
    let st = w.g.state();
    let mut m = Marks::default();
    // A secret made a day ago, replayed with age 0: its age is a day.
    let old = seen(&w, "phone", 1, T0, true);
    assert_eq!(m.judge(&old, Some(T0 + DAY), &st), Fresh::New { age_ms: DAY - fresh::ALLOWANCE_MS });
    // Seen once, never again, even after a restart.
    let saved = m.encode();
    let mut back = Marks::decode(&saved).unwrap();
    assert_eq!(back, m);
    assert_eq!(back.judge(&old, Some(T0 + 1), &st), Fresh::SeenSecret);
    // A copy not after the newest written is behind (A-61), with or
    // without a clock, whichever origin it comes from.
    back.wrote(&w.id("phone"), Timestamp { wall: (T0 + 5000) as i64, logical: 0 });
    assert_eq!(back.judge(&seen(&w, "laptop", 2, T0 + 5000, false), None, &st), Fresh::Behind);
    let mut later = seen(&w, "laptop", 3, T0 + 5000, false);
    later.signed.logical = 1;
    later.age_ms = 7;
    assert_eq!(back.judge(&later, None, &st), Fresh::New { age_ms: 7 });
    // An origin's clock a little ahead is allowed.
    assert_eq!(fresh::effective_age(0, Timestamp { wall: (T0 + 60_000) as i64, logical: 0 }, None, Some(T0)), 0);
    // Past the list's length the floor still holds.
    let mut f = Marks::default();
    for i in 0..(fresh::MAX_SECRETS as u64 + 10) {
        let mut s = seen(&w, "phone", 0, T0 + i, true);
        s.id[..8].copy_from_slice(&i.to_be_bytes());
        f.judge(&s, None, &st);
    }
    assert_eq!(f.secrets.len(), fresh::MAX_SECRETS);
    assert_eq!(f.judge(&seen(&w, "phone", 0, T0, true), None, &st), Fresh::SeenSecret);
    assert!(Marks::decode(&[0xa0]).is_err());
}

/// A copy dated far ahead of a reader's clock is not written and does not
/// become the newest; one dated ahead that a clockless reader wrote stops
/// nothing once its origin is removed or frozen.
#[test]
fn a_copy_dated_ahead_stops_no_reader() {
    let mut w = World::new();
    let st = w.g.state();
    let mut m = Marks::default();
    let far = seen(&w, "laptop", 1, T0 + fresh::ALLOWANCE_MS + 1, true);
    assert_eq!(m.judge(&far, Some(T0), &st), Fresh::Ahead);
    assert!(m.secrets.is_empty(), "not remembered");
    let near = seen(&w, "laptop", 2, T0 + fresh::ALLOWANCE_MS, false);
    assert!(matches!(m.judge(&near, Some(T0), &st), Fresh::New { .. }));
    let mut beyond = seen(&w, "laptop", 3, 0, false);
    beyond.signed.wall = crate::hlc::MAX_WALL + 1;
    assert_eq!(m.judge(&beyond, None, &st), Fresh::Ahead, "no clock reaches it");
    // A reader without a clock writes the laptop's copy dated a year ahead;
    // the phone's copies are behind it until the laptop is removed.
    let year = seen(&w, "laptop", 4, T0 + 365 * DAY, false);
    assert!(matches!(m.judge(&year, None, &st), Fresh::New { .. }));
    m.wrote(&year.origin, year.signed);
    let honest = seen(&w, "phone", 5, T0 + DAY, false);
    assert_eq!(m.judge(&honest, None, &st), Fresh::Behind);
    let saved = m.encode();
    w.g.revoke(&[w.laptop.hash]);
    let frozen = w.g.state();
    assert!(frozen.device(&w.id("laptop")).is_none());
    let mut back = Marks::decode(&saved).unwrap();
    assert_eq!(back, m);
    // Once the laptop is removed, a newer copy of the phone is new; the
    // one already judged stays behind.
    assert_eq!(back.judge(&honest, None, &frozen), Fresh::Behind);
    let next = seen(&w, "phone", 6, T0 + DAY + 1, false);
    assert!(matches!(back.judge(&next, None, &frozen), Fresh::New { .. }));
    back.wrote(&next.origin, next.signed);
    assert_eq!(back.newest(&frozen), next.signed);
}

/// Without a clock, a removal lets no copy older than what the reader
/// already judged be written.
#[test]
fn a_removal_lets_no_older_copy_in_without_a_clock() {
    let mut w = World::new();
    let st = w.g.state();
    let mut m = Marks::default();
    let x = seen(&w, "laptop", 1, T0 + 600_000, false);
    assert!(matches!(m.judge(&x, None, &st), Fresh::New { .. }));
    m.wrote(&x.origin, x.signed);
    let old = seen(&w, "phone", 2, T0, false);
    assert_eq!(m.judge(&old, None, &st), Fresh::Behind);
    w.g.revoke(&[w.laptop.hash]);
    let after = w.g.state();
    let mut back = Marks::decode(&m.encode()).unwrap();
    assert_eq!(back.judge(&old, None, &after), Fresh::Behind);
    // A copy of the phone newer than the one it saw is written.
    let newer = seen(&w, "phone", 3, T0 + 1, false);
    assert!(matches!(back.judge(&newer, None, &after), Fresh::New { .. }));
}

/// The allowance for a copy with a lifetime is at most a quarter of it.
#[test]
fn the_allowance_is_within_a_quarter_of_the_lifetime() {
    let w = World::new();
    let st = w.g.state();
    let mut s = seen(&w, "phone", 1, T0, true);
    s.ttl_ms = Some(60_000);
    assert_eq!(fresh::allowance(Some(60_000)), 15_000);
    assert_eq!(fresh::allowance(None), fresh::ALLOWANCE_MS);
    assert_eq!(Marks::default().judge(&s, Some(T0 + 299_000), &st), Fresh::New { age_ms: 284_000 });
    s.ttl_ms = Some(86_400_000);
    assert_eq!(Marks::default().judge(&s, Some(T0 + 299_000), &st), Fresh::New { age_ms: 0 });
}

/// A copy is known by its origin and ID: another origin's copy with a seen
/// ID hides nothing.
#[test]
fn a_copy_is_known_by_its_origin_and_id() {
    let w = World::new();
    let state = w.g.state();
    let s = w.sealing();
    let content = Content::text("mine", true);
    let real_rs = readers(&state, &s, &content, &w.id("phone"), &[], None);
    let real = seal(&w.phone, &real_rs, &made(9), &content).unwrap();
    let decoy_rs = readers(&state, &s, &content, &w.id("laptop"), &[], None);
    let decoy = seal(&w.laptop, &decoy_rs, &made(9), &content).unwrap();
    let (vr, vd) = (cbor::decode(&real).unwrap(), cbor::decode(&decoy).unwrap());
    let (cr, cd) = (check(&vr, &state).unwrap(), check(&vd, &state).unwrap());
    assert_eq!(cr.id, cd.id);
    assert_eq!(second(&cd, &cr), Second::Another);
    let mut m = Marks::default();
    let as_seen = |c: &Checked<'_>| fresh::Seen {
        origin: c.origin,
        id: c.id,
        signed: c.time,
        age_ms: 0,
        secret: true,
        ttl_ms: None,
    };
    let mut d = as_seen(&cd);
    d.signed.logical = 1;
    assert!(matches!(m.judge(&d, Some(T0), &state), Fresh::New { .. }));
    let mut r = as_seen(&cr);
    r.signed.logical = 2;
    assert!(matches!(m.judge(&r, Some(T0), &state), Fresh::New { .. }), "not taken for seen");
}

/// A device whose rules are too old for the group opens no secret.
#[test]
fn rules_too_old_open_no_secret() {
    let w = World::new();
    let mut state = w.g.state();
    let s = w.sealing();
    let secret = Content::text("pin", true);
    let rs = readers(&state, &s, &secret, &w.id("phone"), &[], None);
    let copy = seal(&w.phone, &rs, &made(3), &secret).unwrap();
    let v = cbor::decode(&copy).unwrap();
    let c = check(&v, &state).unwrap();
    state.too_old = true;
    assert_eq!(open(&c, &w.id("laptop"), &w.stores["laptop"], &state).unwrap(), Opened::TooOld);
    let plain = Content::text("hi", false);
    let rs = readers(&w.g.state(), &s, &plain, &w.id("phone"), &[], None);
    let copy = seal(&w.phone, &rs, &made(4), &plain).unwrap();
    let v = cbor::decode(&copy).unwrap();
    let c = check(&v, &state).unwrap();
    assert_eq!(opened(open(&c, &w.id("laptop"), &w.stores["laptop"], &state).unwrap()), plain);
}

/// A keys statement older than 35 days on a sender with a clock is not
/// sealed to: the device is asleep and asks for the copy when back.
#[test]
fn an_old_statement_is_not_sealed_to() {
    let w = World::new();
    let state = w.g.state();
    let s = w.sealing();
    let content = Content::text("x", false);
    let made_at = s[&w.id("laptop")].statement.body().time_ms;
    assert_ne!(made_at, 0);
    let ids = |now| readers(&state, &s, &content, &w.id("phone"), &[], now).iter().map(|r| r.id).collect::<Vec<_>>();
    assert!(ids(Some(made_at + STATEMENT_MAX_AGE_MS)).contains(&w.id("laptop")));
    assert!(!ids(Some(made_at + STATEMENT_MAX_AGE_MS + 1)).contains(&w.id("laptop")));
    assert!(ids(None).contains(&w.id("laptop")), "no clock, no age");
}

/// A leaf counts its weeks on its running time and writes no time into its
/// statement: a sender with a clock seals to it all the same.
#[test]
fn a_leaf_on_running_time_is_sealed_to() {
    let mut w = World::new();
    let state = w.g.state();
    let mut s = keystore::MemoryStore::new(k("kettle"));
    let made = keystore::rotate(&mut s, &w.g.gid, 7_200_000, None).unwrap().made.unwrap();
    let st = testkit::statement_of(&made);
    assert_eq!(st.body().time_ms, 0, "no wall clock, no time");
    w.statements.retain(|x| x.body().signer != k("kettle").hash);
    w.statements.push(st);
    let sealing = w.sealing();
    let content = Content::text("tea", false);
    let kettle = w.id("kettle");
    let rs = readers(&state, &sealing, &content, &w.id("phone"), &[kettle], Some(T0 + 400 * DAY));
    assert!(rs.iter().any(|r| r.id == kettle));
}

/// A secret without its own ttl lives the group's lifetime, and the
/// allowance is a quarter of that too.
#[test]
fn a_default_secret_gets_a_quarter_of_the_groups_lifetime() {
    let w = World::new();
    let state = w.g.state();
    let s = w.sealing();
    let secret = Content::text("pw", true);
    let rs = readers(&state, &s, &secret, &w.id("phone"), &[], None);
    let copy = seal(&w.phone, &rs, &made(5), &secret).unwrap();
    let v = cbor::decode(&copy).unwrap();
    let c = check(&v, &state).unwrap();
    let seen = fresh::Seen::of(&c, &secret, 60_000, 120_000);
    assert_eq!(seen.ttl_ms, Some(60_000));
    let wall = c.time.wall as u64;
    assert_eq!(Marks::default().judge(&seen, Some(wall + 299_000), &state), Fresh::New { age_ms: 284_000 });
    // Not a secret, no ttl: the group's window for incoming copies.
    let plain = Content::text("hi", false);
    assert_eq!(fresh::Seen::of(&c, &plain, 60_000, 120_000).ttl_ms, Some(120_000));
}

/// An ordinary copy without a ttl is bounded by the group's window for
/// incoming copies: a quarter of it is the allowance.
#[test]
fn an_ordinary_copy_gets_a_quarter_of_the_incoming_window() {
    let w = World::new();
    let state = w.g.state();
    let plain = Content::text("hi", false);
    let rs = readers(&state, &w.sealing(), &plain, &w.id("phone"), &[], None);
    let copy = seal(&w.phone, &rs, &made(6), &plain).unwrap();
    let v = cbor::decode(&copy).unwrap();
    let c = check(&v, &state).unwrap();
    let seen = fresh::Seen::of(&c, &plain, 60_000, 60_000);
    let wall = c.time.wall as u64;
    assert_eq!(Marks::default().judge(&seen, Some(wall + 299_000), &state), Fresh::New { age_ms: 284_000 });
}

/// A leaf checks a copy against the origins its grant names, with no
/// state, and reaches the state's verdicts.
#[test]
fn a_leaf_checks_a_copy_by_the_origins_it_knows() {
    let w = World::new();
    let state = w.g.state();
    let content = Content::text("kettle on", false);
    let rs = readers(&state, &w.sealing(), &content, &w.id("phone"), &[], None);
    let copy = seal(&w.phone, &rs, &made(1), &content).unwrap();
    let v = cbor::decode(&copy).unwrap();
    let mut known = OriginMap::default();
    assert_eq!(check(&v, &known).err(), Some(RULE_ORIGIN));
    known.insert(w.phone.key.clone(), RIGHT_READ, false);
    assert_eq!(check(&v, &known).err(), Some(RULE_SEND));
    known.insert(w.phone.key.clone(), RIGHT_SEND, true);
    assert_eq!(check(&v, &known).err(), Some(RULE_SEND));
    known.insert(w.phone.key.clone(), RIGHT_READ | RIGHT_SEND, false);
    let (a, b) = (check(&v, &known).unwrap(), check(&v, &state).unwrap());
    assert_eq!((a.id, a.origin, a.time, a.readers), (b.id, b.origin, b.time, b.readers));
    // Another device's key under the phone's ID is not the phone.
    let mut wrong = OriginMap::default();
    wrong.insert(w.laptop.key.clone(), RIGHT_SEND, false);
    assert_eq!(check(&v, &wrong).err(), Some(RULE_ORIGIN));
}
