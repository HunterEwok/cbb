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

/// A member with the cap hub that an admin admitted gets only base rights;
/// the root lets it be a hub when it names it one, and an admin cannot.
#[test]
fn the_root_lets_an_admitted_member_with_the_cap_hub_be_a_hub() {
    let (o, mut set) = group("admitted-hub");
    let root = o.root.clone().unwrap();
    let dir = temp("admitted-hub-admin");
    let admin = own(&dir).make(&dir, Which::Admin).unwrap();
    make_admin(&mut set, &*root, "laptop", &admin.public(), T + 2).unwrap();
    let k = SigningKey::from_slice(&[9; 32]).unwrap();
    let mut pi = Device::new(Key::es256(k.verifying_key().to_sec1_point(false).as_bytes().to_vec()), "pi", ROLE_MEMBER);
    pi.rights = body::RIGHT_READ | body::RIGHT_SEND;
    pi.caps = body::CAP_HUB;
    let st = set.state();
    set.write_record(&st, &*admin, Kind::device(pi), T + 3).unwrap();
    let st = set.state();
    let id = find(&st, "pi").unwrap().id;
    assert_eq!(find(&st, "pi").unwrap().rights & RIGHT_HUB, 0);

    let e = set_hubs(&mut set, &*admin, &["pi".to_string()], T + 4).unwrap_err();
    assert!(e.message().contains("may not be a hub"), "{e:?}");

    set_hubs(&mut set, &*root, &["pi".to_string(), "laptop".to_string()], T + 5).unwrap();
    let st = set.state();
    assert_ne!(find(&st, "pi").unwrap().rights & RIGHT_HUB, 0);
    assert!(st.hubs.contains(&id), "{:?}", st.hubs);
}

#[test]
fn the_root_makes_a_hub_that_only_passes_copies_on() {
    let (o, mut set) = group("forward-only");
    let root = o.root.clone().unwrap();
    let k = SigningKey::from_slice(&[9; 32]).unwrap();
    let mut pi = Device::new(Key::es256(k.verifying_key().to_sec1_point(false).as_bytes().to_vec()), "pi", ROLE_MEMBER);
    pi.rights = body::RIGHT_READ | body::RIGHT_SEND | body::RIGHT_SECRETS;
    pi.caps = body::CAP_HUB;
    let st = set.state();
    set.write_record(&st, &*root, Kind::device(pi), T + 2).unwrap();
    set_hubs(&mut set, &*root, &["laptop".to_string()], T + 3).unwrap();
    assert!(set_forward_only(&mut set, &*root, "desk", T + 4).is_err(), "the root's own device");
    assert!(set_forward_only(&mut set, &*root, "old laptop", T + 4).is_err(), "no cap hub");

    set_forward_only(&mut set, &*root, "pi", T + 5).unwrap();
    let st = set.state();
    let pi = find(&st, "pi").unwrap();
    assert!(is_forward_only(pi.rights) && pi.rights & body::RIGHT_SECRETS == 0, "{:b}", pi.rights);
    let laptop = find(&st, "laptop").unwrap().id;
    assert_eq!(st.hubs, vec![laptop, pi.id], "after the hubs named already");
    // Again: nothing more to write.
    assert!(set_forward_only(&mut set, &*root, "pi", T + 6).unwrap().is_empty());
    assert!(!is_forward_only(find(&st, "laptop").unwrap().rights));
}
