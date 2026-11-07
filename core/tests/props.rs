// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! Property tests: random inputs against the core's parsers, which must
//! refuse what they cannot read and never panic, and against promises of
//! the rules of records v:2 (docs/records-v2.md), such as the state not
//! depending on the order in which a member got the records.

use std::collections::BTreeMap;

use cbb_core::authority::{self, Body, Hash, Input, Record};
use cbb_core::certs::{Cert, b64};
use cbb_core::{store, strict, wire};
use proptest::prelude::*;
use serde::Deserialize;

/// A case of testdata/interop/v2-records.json.
#[derive(Deserialize)]
struct Case {
    name: String,
    #[serde(with = "b64")]
    group_ca: Vec<u8>,
    group: String,
    now_ms: i64,
    #[serde(default)]
    time_unknown: bool,
    #[serde(default)]
    first_seen: Vec<FirstSeen>,
    records: Vec<Record>,
    state: String,
}

#[derive(Deserialize)]
struct FirstSeen {
    record: Hash,
    ms: i64,
}

fn cases() -> Vec<Case> {
    #[derive(Deserialize)]
    struct File {
        cases: Vec<Case>,
    }
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../testdata/interop/v2-records.json");
    let file: File = serde_json::from_slice(&std::fs::read(path).expect("the vectors")).expect("the vectors' JSON");
    file.cases
}

fn evaluate(c: &Case, records: &[Record]) -> String {
    let ca = Cert::parse(&c.group_ca).expect("the group CA");
    let first_seen: BTreeMap<Hash, i64> = c.first_seen.iter().map(|f| (f.record, f.ms)).collect();
    let state = authority::evaluate(&Input {
        group_ca: &ca,
        group: &c.group,
        records,
        now_ms: c.now_ms,
        first_seen: &first_seen,
        time_unknown: c.time_unknown,
        sigs: None,
    });
    String::from_utf8(state.encode()).expect("the state is UTF-8")
}

/// A JSON value with the shapes a signed body may hold.
fn json() -> impl Strategy<Value = serde_json::Value> {
    let leaf = prop_oneof![
        any::<bool>().prop_map(serde_json::Value::from),
        any::<i64>().prop_map(serde_json::Value::from),
        "[ -~]{0,12}".prop_map(serde_json::Value::from),
        "\\PC{0,6}".prop_map(serde_json::Value::from),
    ];
    leaf.prop_recursive(4, 32, 6, |inner| {
        prop_oneof![
            prop::collection::vec(inner.clone(), 0..5).prop_map(serde_json::Value::from),
            prop::collection::btree_map("[a-z_][a-z0-9_]{0,8}", inner, 0..5)
                .prop_map(|m| serde_json::Value::Object(m.into_iter().collect())),
        ]
    })
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 512, ..ProptestConfig::default() })]

    // The strict reader refuses or takes any bytes without panicking.
    #[test]
    fn strict_never_panics(b in prop::collection::vec(any::<u8>(), 0..256)) {
        let _ = strict::check(&b, &["v"]);
        let _ = strict::check_canonical(&b, &["v"]);
        let _ = strict::integers_only(&b);
        let _ = strict::canonicalize(&b);
    }

    // Whatever the canonical form of a body is, it is canonical, and
    // canonicalizing it again changes nothing.
    #[test]
    fn canonical_is_stable(v in json()) {
        let b = serde_json::to_vec(&v).expect("a JSON value encodes");
        if let Ok(c) = strict::canonicalize(&b) {
            prop_assert_eq!(strict::canonicalize(&c).ok(), Some(c.clone()));
            if v.is_object() {
                prop_assert!(strict::check_canonical(&c, &[]).is_ok(), "{}", String::from_utf8_lossy(&c));
            }
        }
    }

    // A record body is read or refused, never a panic; one that is read
    // encodes to the same bytes, since bodies are canonical.
    #[test]
    fn body_parse_round_trips(b in prop::collection::vec(any::<u8>(), 0..512)) {
        if let Ok(body) = Body::parse(&b) {
            prop_assert_eq!(body.encode().ok(), Some(b));
        }
    }

    // The saved state's frames: what frame writes, read gives back, and
    // read takes any bytes without panicking.
    #[test]
    fn store_frames(seq in any::<u32>(), payload in prop::collection::vec(any::<u8>(), 0..128),
                    junk in prop::collection::vec(any::<u8>(), 0..128)) {
        let f = store::frame(seq, &payload);
        prop_assert_eq!(store::read(&f), Some((seq, &payload[..])));
        let _ = store::read(&junk);
        let _ = store::frame_len_in(&junk);
        let _ = store::Fields::decode(&junk);
    }

    // The saved fields come back as they were written.
    #[test]
    fn store_fields(m in prop::collection::btree_map(any::<u8>(), prop::collection::vec(any::<u8>(), 0..32), 0..8)) {
        let mut f = store::Fields::default();
        for (t, v) in &m {
            f.set(*t, v.clone());
        }
        let back = store::Fields::decode(&f.encode()).expect("its own encoding");
        for (t, v) in &m {
            prop_assert_eq!(back.get(*t), Some(&v[..]));
        }
    }

    // A frame of the member protocol is read or refused, never a panic.
    #[test]
    fn wire_never_panics(b in prop::collection::vec(any::<u8>(), 0..256), head in any::<[u8; 4]>()) {
        let _ = wire::decode(&b);
        let _ = wire::frame_len(head, 1 << 20);
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 16, ..ProptestConfig::default() })]

    // The state does not depend on the order in which the records came
    // (docs/records-v2.md: evaluation is order-independent).
    #[test]
    fn order_does_not_matter(seed in any::<u64>()) {
        for c in cases() {
            let mut records = c.records.clone();
            shuffle(&mut records, seed);
            prop_assert_eq!(evaluate(&c, &records), c.state.clone(), "{} in another order", c.name);
        }
    }

    // A record held twice counts once.
    #[test]
    fn duplicates_do_not_matter(seed in any::<u64>()) {
        for c in cases() {
            let mut s = seed;
            let mut records = c.records.clone();
            records.extend(c.records.iter().filter(|_| next(&mut s).is_multiple_of(2)).cloned());
            shuffle(&mut records, seed);
            prop_assert_eq!(evaluate(&c, &records), c.state.clone(), "{} with duplicates", c.name);
        }
    }

    // Any subset of a case's records, and any record with a byte changed,
    // evaluates to some state without panicking.
    #[test]
    fn damaged_sets_never_panic(seed in any::<u64>(), flip in any::<(usize, u8)>()) {
        for c in cases() {
            let mut s = seed;
            let mut records: Vec<Record> = c.records.iter().filter(|_| !next(&mut s).is_multiple_of(3)).cloned().collect();
            if let Some(r) = records.first_mut() {
                if !r.body.is_empty() {
                    let i = flip.0 % r.body.len();
                    r.body[i] ^= flip.1 | 1;
                }
            }
            let _ = evaluate(&c, &records);
        }
    }
}

/// A small generator (splitmix64), so a failing seed replays exactly.
fn next(s: &mut u64) -> u64 {
    *s = s.wrapping_add(0x9e37_79b9_7f4a_7c15);
    let mut z = *s;
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^ (z >> 31)
}

fn shuffle<T>(v: &mut [T], seed: u64) {
    let mut s = seed;
    for i in (1..v.len()).rev() {
        let j = (next(&mut s) % (i as u64 + 1)) as usize;
        v.swap(i, j);
    }
}
