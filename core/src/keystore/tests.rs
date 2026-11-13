// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! A device's own keys: the weekly epoch, the previous one kept a week, the
//! statement only its own member key signs, and reading statements.

use alloc::string::String;

use serde_json::Value as Json;

use super::*;
use crate::format::cbor::Encoder;
use crate::records::body::{RIGHT_READ, ROLE_MEMBER};
use crate::testkit::{G, T0, k, sealing};

fn held(r: &MemoryStore<crate::testkit::K>) -> Vec<u64> {
    let mut e: Vec<u64> = r.epochs().iter().map(|e| e.epoch).collect();
    e.sort();
    e
}

#[test]
fn the_sealing_key_changes_once_a_week_and_the_old_one_stays_a_week() {
    let group = k("root").key.device_id();
    let mut s = MemoryStore::new(k("laptop"));
    let r = rotate(&mut s, &group, T0, Some(T0)).unwrap();
    assert!(r.made.is_some());
    assert_eq!(held(&s), [1]);
    // Within the week nothing changes.
    assert_eq!(rotate(&mut s, &group, T0 + WEEK_MS - 1, Some(T0 + WEEK_MS - 1)).unwrap(), Rotated::default());
    // A week on: epoch 2, and epoch 1 still opens late copies.
    let r = rotate(&mut s, &group, T0 + WEEK_MS, Some(T0 + WEEK_MS)).unwrap();
    assert!(r.made.is_some() && r.erased.is_empty());
    assert_eq!(held(&s), [1, 2]);
    assert!(s.sealing(1).is_some());
    // Another week: epoch 3, epoch 1 erased.
    let r = rotate(&mut s, &group, T0 + 2 * WEEK_MS, Some(T0 + 2 * WEEK_MS)).unwrap();
    assert_eq!(r.erased, [1]);
    assert_eq!(held(&s), [2, 3]);
    assert!(s.sealing(1).is_none());
    // A clock gone back a little makes nothing and erases nothing.
    assert_eq!(
        rotate(&mut s, &group, T0 + 2 * WEEK_MS - AHEAD_MS, Some(T0 + 2 * WEEK_MS - AHEAD_MS)).unwrap(),
        Rotated::default()
    );
    assert_eq!(held(&s), [2, 3]);
    // After a long sleep: one new epoch, the previous one kept, older ones
    // gone.
    let r = rotate(&mut s, &group, T0 + 10 * WEEK_MS, Some(T0 + 10 * WEEK_MS)).unwrap();
    assert_eq!(r.erased, [2]);
    assert_eq!(held(&s), [3, 4]);
    let r = rotate(&mut s, &group, T0 + 11 * WEEK_MS, Some(T0 + 11 * WEEK_MS)).unwrap();
    assert_eq!(r.erased, [3]);
    assert_eq!(held(&s), [4, 5]);
}

#[test]
fn the_device_itself_signs_its_statement() {
    let mut g = G::new();
    let laptop = g.device("laptop", ROLE_MEMBER, RIGHT_READ, |_| {});
    let mut s = MemoryStore::new(k("laptop"));
    let env = rotate(&mut s, &g.gid, T0, Some(T0)).unwrap().made.unwrap();
    let ReadStatement::Take(st) = read_statement(&env).unwrap() else { panic!("held") };
    assert_eq!(st.body().signer, laptop.hash);
    assert_eq!(st.envelope(), env);
    assert!(st.verify(&laptop.key).is_ok());
    let state = g.state();
    let chosen = sealing(&state, &[&st]);
    assert_eq!(chosen[&laptop.key.device_id()].statement.body().epoch, 1);
    // The root signing a statement for the laptop: nobody takes it.
    let body = st.body().clone();
    let forged = crate::format::envelope::sign(&k("root").sk, crate::records::statement::LABEL_KEYS, &body.encode());
    let ReadStatement::Take(f) = read_statement(&forged).unwrap() else { panic!("held") };
    assert!(f.verify(&laptop.key).is_err());
    assert!(sealing(&state, &[&f]).is_empty());
    // A store refuses to sign a statement for another key.
    let other = Body { signer: k("phone").hash, ..body };
    assert!(Statement::sign(other, &k("laptop")).is_err());
}

fn statement(fields: &[(u16, Value<'_>)]) -> Vec<u8> {
    let body = Value::Map(fields.to_vec()).encode();
    crate::format::envelope::sign(&k("laptop").sk, crate::records::statement::LABEL_KEYS, &body)
}

#[test]
fn statements_are_read_row_by_row() {
    let group = [7u8; 16];
    let signer = k("laptop").hash.0;
    let seal = crate::seal::public_key(&[5; 32]).unwrap();
    let key = |p: &[u8]| {
        let mut e = Encoder::new();
        e.array(2).uint(2).bytes(p);
        e.finish()
    };
    let good_key = key(&seal);
    let gk = crate::format::cbor::decode(&good_key).unwrap();
    let mk = |epoch: u64, k10: Value<'_>, more: Option<(u16, Value<'_>)>| {
        let mut f: Vec<(u16, Value<'_>)> = alloc::vec![
            (1, Value::Uint(1)),
            (2, Value::Bytes(&group)),
            (3, Value::Bytes(&signer)),
            (4, Value::Uint(epoch))
        ];
        f.push((10, k10));
        if let Some(m) = more {
            f.push(m);
            f.sort_by_key(|(n, _)| *n);
        }
        statement(&f)
    };
    assert!(matches!(read_statement(&mk(1, gk.clone(), None)), Ok(ReadStatement::Take(_))));
    assert_eq!(read_statement(&mk(0, gk.clone(), None)), Err(Rule::field("statements/epoch")));
    let short = key(&seal[1..]);
    assert_eq!(read_statement(&mk(1, crate::format::cbor::decode(&short).unwrap(), None)), Err(Rule::KEYS_XWING));
    // A later version's critical field, type or algorithm: held.
    assert!(matches!(read_statement(&mk(1, gk.clone(), Some((99, Value::Uint(1))))), Ok(ReadStatement::Held { .. })));
    let mut e = Encoder::new();
    e.array(2).uint(9).bytes(&[1; 40]);
    let later_alg = e.finish();
    assert!(matches!(
        read_statement(&mk(1, crate::format::cbor::decode(&later_alg).unwrap(), None)),
        Ok(ReadStatement::Held { .. })
    ));
    // An optional field is skipped.
    assert!(matches!(read_statement(&mk(1, gk.clone(), Some((300, Value::Uint(1))))), Ok(ReadStatement::Take(_))));
    // Over 2 KiB of body.
    let pad = alloc::vec![0u8; 1000];
    assert_eq!(read_statement(&mk(1, gk.clone(), Some((300, Value::Bytes(&pad))))).err(), Some(Rule::ENV_SIZE));
    // time 0 written.
    assert_eq!(read_statement(&mk(1, gk, Some((6, Value::Uint(0))))).err(), Some(Rule::FORM_DEFAULT));
}

fn load(name: &str) -> Json {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../testdata/format").join(name);
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

/// statements.json: every take reads; every refusal is refused by its
/// rule, the signature's by the device's member key.
#[test]
fn statement_vectors() {
    let v = load("statements.json");
    let keys = load("keys.json");
    let laptop = keys["keys"].as_array().unwrap().iter().find(|k| k["name"] == "laptop member key").unwrap();
    let laptop =
        crate::records::Key::read(&crate::format::cbor::decode(&unhex(laptop["key"].as_str().unwrap())).unwrap())
            .unwrap();
    for t in v["take"].as_array().unwrap() {
        let env = unhex(t["envelope"].as_str().unwrap());
        assert!(matches!(read_statement(&env), Ok(ReadStatement::Take(_))), "{}", t["name"]);
    }
    for r in v["refuse"].as_array().unwrap() {
        let env = unhex(r["envelope"].as_str().unwrap());
        let rule: String = r["rule"].as_str().unwrap().into();
        let got = match read_statement(&env) {
            Err(e) => e.name().into(),
            Ok(ReadStatement::Take(st)) => st.verify(&laptop).err().map(|e| alloc::format!("{e}")).unwrap_or_default(),
            Ok(ReadStatement::Held { .. }) => "held".into(),
        };
        assert_eq!(got, rule, "{}", r["name"]);
    }
}

/// A clock that was once far ahead does not stop the weekly change: once
/// the clock has been behind that epoch for a week of its own, a new epoch
/// is made, and the one made ahead is kept a week after it.
#[test]
fn a_clock_once_far_ahead_does_not_stop_the_change() {
    let group = k("root").key.device_id();
    let mut s = MemoryStore::new(k("laptop"));
    rotate(&mut s, &group, T0, Some(T0)).unwrap();
    rotate(&mut s, &group, T0 + 520 * WEEK_MS, Some(T0 + 520 * WEEK_MS)).unwrap();
    assert_eq!(held(&s), [1, 2]);
    let at = |t: u64| T0 + 1000 + t;
    assert_eq!(rotate(&mut s, &group, at(0), Some(at(0))).unwrap(), Rotated::default());
    assert_eq!(rotate(&mut s, &group, at(WEEK_MS - 1), Some(at(WEEK_MS - 1))).unwrap(), Rotated::default());
    assert_eq!(held(&s), [1, 2]);
    let r = rotate(&mut s, &group, at(WEEK_MS), Some(at(WEEK_MS))).unwrap();
    assert!(r.made.is_some());
    assert_eq!(held(&s), [2, 3]);
    assert_eq!(rotate(&mut s, &group, at(WEEK_MS + 1), Some(at(WEEK_MS + 1))).unwrap(), Rotated::default());
    let r = rotate(&mut s, &group, at(2 * WEEK_MS), Some(at(2 * WEEK_MS))).unwrap();
    assert!(r.made.is_some());
    assert_eq!(held(&s), [3, 4]);
}

/// A restart with the clock at a default date and the clock set right an
/// hour later: the epochs of before the restart still open.
#[test]
fn a_restart_at_a_default_date_keeps_the_epochs() {
    let group = k("root").key.device_id();
    let mut s = MemoryStore::new(k("laptop"));
    let real = T0 + 100 * WEEK_MS;
    rotate(&mut s, &group, real, Some(real)).unwrap();
    rotate(&mut s, &group, real + WEEK_MS, Some(real + WEEK_MS)).unwrap();
    assert_eq!(held(&s), [1, 2]);
    let now = real + WEEK_MS + 3 * AHEAD_MS;
    // The default date, then the right time an hour later, then a restart
    // at the default date again.
    for t in [T0, now + 3_600_000, T0, now + 7_200_000] {
        assert_eq!(rotate(&mut s, &group, t, Some(t)).unwrap(), Rotated::default(), "at {t}");
    }
    assert_eq!(held(&s), [1, 2]);
    assert!(s.sealing(1).is_some() && s.sealing(2).is_some());
    // The week of epoch 2 ends on the real clock as before.
    let r = rotate(&mut s, &group, real + 2 * WEEK_MS, Some(real + 2 * WEEK_MS)).unwrap();
    assert!(r.made.is_some());
    assert_eq!(held(&s), [2, 3]);
}

/// A clock moved back and forth by days makes no epoch within the week,
/// however many calls.
#[test]
fn a_clock_moved_back_and_forth_makes_one_epoch_a_week() {
    let group = k("root").key.device_id();
    let mut s = MemoryStore::new(k("laptop"));
    rotate(&mut s, &group, T0 + WEEK_MS, Some(T0 + WEEK_MS)).unwrap();
    let mut made = 0;
    for i in 0..20u64 {
        let t = if i % 2 == 0 { T0 + WEEK_MS - 2 * AHEAD_MS } else { T0 + WEEK_MS + 6 * AHEAD_MS };
        made += usize::from(rotate(&mut s, &group, t, Some(t)).unwrap().made.is_some());
    }
    assert_eq!(made, 0);
    assert_eq!(held(&s), [1]);
}

/// A leaf on its running time makes its new epoch at a restart at once, made
/// at the start of the run, and the next restarts do not rotate.
#[test]
fn a_leaf_rotates_at_most_once_at_a_restart() {
    let group = k("root").key.device_id();
    let mut s = MemoryStore::new(k("kettle"));
    rotate(&mut s, &group, 3 * AHEAD_MS, None).unwrap();
    // A restart: running time starts again.
    assert!(rotate(&mut s, &group, 1000, None).unwrap().made.is_some());
    assert_eq!(held(&s), [1, 2]);
    for t in [1000, 2000, 500] {
        assert_eq!(rotate(&mut s, &group, t, None).unwrap(), Rotated::default());
    }
    assert_eq!(held(&s), [1, 2]);
}

/// A statement of a later type is held whatever its other fields are; a
/// sealing key of an algorithm this version knows that is not a sealing
/// key is refused.
#[test]
fn a_later_statement_is_held_with_or_without_its_key() {
    let group = [7u8; 16];
    let signer = k("laptop").hash.0;
    let base = |t: u64| {
        alloc::vec![(1, Value::Uint(t)), (2, Value::Bytes(&group)), (3, Value::Bytes(&signer)), (4, Value::Uint(3))]
    };
    assert!(matches!(read_statement(&statement(&base(2))), Ok(ReadStatement::Held { .. })));
    let mut other = base(2);
    other.push((10, Value::Text("another form")));
    assert!(matches!(read_statement(&statement(&other)), Ok(ReadStatement::Held { .. })));
    let mut f = base(1);
    let es = k("laptop").key.public.clone();
    let mut e = Encoder::new();
    e.array(2).uint(1).bytes(&es);
    let es_key = e.finish();
    f.push((10, crate::format::cbor::decode(&es_key).unwrap()));
    assert_eq!(read_statement(&statement(&f)).err(), Some(Rule::KEYS_XWING));
    // Type 1 still needs its fields.
    assert_eq!(read_statement(&statement(&base(1))).err(), Some(Rule::field("statements/seal")));
    let mut no_type = base(1);
    no_type.remove(0);
    assert_eq!(read_statement(&statement(&no_type)).err(), Some(Rule::field("statements/type")));
}
