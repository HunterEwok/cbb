// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! Property tests: random inputs against the core's parsers, which must
//! refuse what they cannot read and never panic. The order independence of
//! the records' rules is tested in core/src/records.

use cbb_core::{store, strict, wire};
use proptest::prelude::*;

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
