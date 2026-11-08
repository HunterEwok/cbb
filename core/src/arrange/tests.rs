// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The arrangement against the shared vectors.

use super::*;

const VECTORS: &str = include_str!("../../../testdata/arrangement/vectors.json");

#[test]
fn passes_the_vectors() {
    let v: serde_json::Value = serde_json::from_str(VECTORS).unwrap();
    let cases = v["cases"].as_array().unwrap();
    assert!(!cases.is_empty());
    for c in cases {
        let name = c["name"].as_str().unwrap();
        let group = c["group"].as_str().unwrap();
        let me = c["self"].as_str();
        let devices: Vec<String> = serde_json::from_value(c["devices"].clone()).unwrap();
        let stored = Some(&c["stored"]).filter(|s| !s.is_null());
        let mut a = Arrangement::decode(stored, group);
        if c["prune"].as_bool().unwrap_or(false) {
            a.prune(&devices);
        }
        let ops = c["ops"].as_array().unwrap();
        let mut failed = false;
        for (i, o) in ops.iter().enumerate() {
            let before = a.clone();
            let r =
                serde_json::from_value::<Op>(o.clone()).map_err(|_| refuse()).and_then(|op| a.apply(&op, &devices, me));
            if r.is_err() {
                assert_eq!(a, before, "{name}: a refused change changed the arrangement");
                assert_eq!(i + 1, ops.len(), "{name}: op {i} failed");
                failed = true;
            }
        }
        assert_eq!(failed, c["error"].as_bool().unwrap(), "{name}: error");
        let items: Vec<Item> = serde_json::from_value(c["items"].clone()).unwrap();
        assert_eq!(a.items, items, "{name}: items");
        let view: Vec<Item> = serde_json::from_value(c["view"].clone()).unwrap();
        assert_eq!(a.view(&devices, me), view, "{name}: view");
    }
}
