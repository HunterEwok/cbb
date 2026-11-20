// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

use std::path::{Path, PathBuf};

use cbb_core::records::body::{self, ROLE_MEMBER};
use cbb_core::records::{Recovery, key::ALG_SLH_DSA, pq};
use p256::ecdsa::SigningKey;

use super::*;
use crate::own::Which;

fn temp(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("cbb-writers-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn own(dir: &Path) -> Own {
    Own::load_with(dir, &|_| Err(Error::msg("no hardware")), &|| None).unwrap()
}

const T: u64 = 1_800_000_000_000;

/// A group whose root this device holds, with itself and two laptops.
fn group(name: &str) -> (Own, RecordSet) {
    let dir = temp(name);
    let mut o = own(&dir);
    let root = o.make(&dir, Which::Root).unwrap();
    let (k1, k2) = pq::recovery_keys(&[1; 32]).unwrap();
    let k1 = SigningKey::from(&k1).verifying_key().to_sec1_point(false).as_bytes().to_vec();
    let mut set = RecordSet::new(
        Key::es256(root.public()),
        Recovery::new(Key::es256(k1), Key::new(ALG_SLH_DSA, k2.public())).unwrap(),
    );
    let mut me = Device::new(o.member_key(), "desk", ROLE_MEMBER);
    me.holds_root = true;
    me.rights = body::RIGHT_READ | body::RIGHT_SEND;
    let st = set.state();
    set.write_record(&st, &*root, Kind::device(me), T).unwrap();
    for (n, seed) in [("laptop", 7u8), ("old laptop", 8)] {
        let k = SigningKey::from_slice(&[seed; 32]).unwrap();
        let mut d = Device::new(Key::es256(k.verifying_key().to_sec1_point(false).as_bytes().to_vec()), n, ROLE_MEMBER);
        d.rights = body::RIGHT_READ | body::RIGHT_SEND | if seed == 7 { body::RIGHT_HUB } else { 0 };
        let st = set.state();
        set.write_record(&st, &*root, Kind::device(d), T + 1).unwrap();
    }
    (o, set)
}

#[test]
fn the_root_signs_and_a_device_without_keys_does_not() {
    let (o, set) = group("signer");
    let st = set.state();
    assert!(signer(&o, &st).is_some());
    let plain = own(&temp("signer-plain"));
    assert!(signer(&plain, &st).is_none());
}

#[test]
fn a_device_is_found_by_name_or_id() {
    let (_, set) = group("find");
    let st = set.state();
    let laptop = find(&st, "laptop").unwrap();
    assert_eq!(find(&st, &hex(&laptop.id.0[..3])).unwrap().id, laptop.id);
    assert!(find(&st, "lap").is_err(), "a prefix of a name is no name");
    assert!(find(&st, "nobody").is_err());
}

#[test]
fn the_root_removes_freezes_thaws_and_renames() {
    let (o, mut set) = group("write");
    let root = o.root.clone().unwrap();
    let (d, recs) = rename(&mut set, &*root, "laptop", "work laptop", T + 10).unwrap();
    assert_eq!(recs.len(), 1);
    assert_eq!(set.state().device(&d.id).unwrap().name, "work laptop");
    assert!(rename(&mut set, &*root, "work laptop", "desk", T + 11).is_err(), "a name another device has");

    freeze(&mut set, &*root, "work laptop", true, T + 12).unwrap();
    assert!(set.state().device(&d.id).unwrap().frozen);
    freeze(&mut set, &*root, "work laptop", false, T + 13).unwrap();
    assert!(!set.state().device(&d.id).unwrap().frozen);

    let (gone, _) = remove(&mut set, &*root, "old laptop", T + 14).unwrap();
    assert!(set.state().device(&gone.id).is_none());
    assert!(remove(&mut set, &*root, "desk", T + 15).is_err(), "the root's own device");
}

#[test]
fn the_root_sets_the_window_hubs_and_settings() {
    let (o, mut set) = group("group");
    let root = o.root.clone().unwrap();
    set_incoming(&mut set, &*root, 30_000, T + 10).unwrap();
    assert_eq!(set.state().incoming_ms, Some(30_000));
    set_hubs(&mut set, &*root, &["laptop".to_string()], T + 11).unwrap();
    let st = set.state();
    assert_eq!(st.hubs, vec![find(&st, "laptop").unwrap().id]);
    assert!(set_hubs(&mut set, &*root, &["old laptop".to_string()], T + 12).is_err(), "no right to be a hub");
    assert!(set_settings(&mut set, &*root, |_| {}, T + 12).unwrap().is_empty(), "nothing changed");
    set_settings(&mut set, &*root, |s| s.shared = !s.shared, T + 13).unwrap();
    assert_ne!(set.state().settings.shared, st.settings.shared);
}
