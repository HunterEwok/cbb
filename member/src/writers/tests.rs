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

/// The root records where a member's keys live as its hello says: `file`
/// moves to `hardware`, and `rootless` takes the admin key away; nothing
/// else signs, nor does an admin.
#[test]
fn the_root_records_the_store_a_hello_says() {
    use body::{STORE_FILE, STORE_HARDWARE, STORE_ROOTLESS};
    let (o, mut set) = group("store");
    let root = o.root.clone().unwrap();
    let dir = temp("store-admin");
    let admin = own(&dir).make(&dir, Which::Admin).unwrap();
    make_admin(&mut set, &*root, "laptop", &admin.public(), T + 2).unwrap();
    let st = set.state();
    let (laptop, old, desk) =
        (find(&st, "laptop").unwrap().id, find(&st, "old laptop").unwrap().id, find(&st, "desk").unwrap().id);

    assert!(store_from_hello(&mut set, &*admin, &old, STORE_HARDWARE, T + 3).unwrap().is_none(), "an admin");
    assert!(store_from_hello(&mut set, &*root, &old, STORE_FILE, T + 3).unwrap().is_none(), "the same");
    assert!(store_from_hello(&mut set, &*root, &desk, STORE_ROOTLESS, T + 3).unwrap().is_none(), "the root's own");
    assert!(store_from_hello(&mut set, &*root, &old, STORE_HARDWARE, T + 4).unwrap().is_some());
    assert_eq!(set.state().device(&old).unwrap().store, STORE_HARDWARE);
    assert!(store_from_hello(&mut set, &*root, &old, STORE_HARDWARE, T + 5).unwrap().is_none(), "said already");
    assert!(store_from_hello(&mut set, &*root, &old, STORE_FILE, T + 5).unwrap().is_none(), "never back to a file");

    assert!(store_from_hello(&mut set, &*root, &laptop, STORE_ROOTLESS, T + 6).unwrap().is_some());
    let d = set.state().device(&laptop).unwrap().clone();
    assert_eq!((d.store, d.admin, d.powers, d.commands), (STORE_ROOTLESS, None, 0, 0));
    assert_eq!(d.name, "laptop", "the rest stays");
}

/// An admin key that signed two histories (a computer brought back from a
/// backup): the root voids both, the key signs again below the fork, and
/// an admin cannot resolve, nor can anyone when no key forked.
#[test]
fn the_root_voids_both_histories_of_an_admin_key() {
    let (o, mut set) = group("resolve");
    let root = o.root.clone().unwrap();
    let dir = temp("resolve-admin");
    let admin = own(&dir).make(&dir, Which::Admin).unwrap();
    make_admin(&mut set, &*root, "laptop", &admin.public(), T + 2).unwrap();
    assert!(resolve(&mut set, &*root, T + 3).unwrap_err().message().contains("no key"));
    // The admin admits attic; brought back from a backup, it signs another
    // record with the same seq.
    let device = |name: &str, seed: u8| {
        let k = SigningKey::from_slice(&[seed; 32]).unwrap();
        let mut d =
            Device::new(Key::es256(k.verifying_key().to_sec1_point(false).as_bytes().to_vec()), name, ROLE_MEMBER);
        d.rights = body::RIGHT_READ | body::RIGHT_SEND;
        d
    };
    let st = set.state();
    let first = set.write_record(&st, &*admin, Kind::device(device("attic", 20)), T + 4).unwrap();
    let b = first[0].body().clone();
    let twin = Record::sign(
        cbb_core::records::Body { kind: Kind::device(device("cellar", 21)), time_ms: T + 5, ..b },
        &*admin,
    )
    .unwrap();
    set.insert_all([twin]);
    let st = set.state();
    assert_eq!(two_histories(&st), vec!["laptop".to_string()]);

    let e = resolve(&mut set, &*admin, T + 6).unwrap_err();
    assert!(e.message().contains("only the group's root"), "{e:?}");
    let (who, recs) = resolve(&mut set, &*root, T + 6).unwrap();
    assert_eq!((who, recs.len()), (vec!["laptop".to_string()], 1));
    let st = set.state();
    assert!(two_histories(&st).is_empty(), "{:?}", st.conflicts);
    assert!(find(&st, "attic").is_err() && find(&st, "cellar").is_err(), "both sides are void");
    let st = set.state();
    set.write_record(&st, &*admin, Kind::device(device("shed", 22)), T + 7).unwrap();
    assert!(find(&set.state(), "shed").is_ok(), "the admin goes on below the fork");
}

/// The key the tests' watches make, as a SEC1 point.
fn point_of(seed: u8) -> Vec<u8> {
    SigningKey::from_slice(&[seed; 32]).unwrap().verifying_key().to_sec1_point(false).as_bytes().to_vec()
}

/// The root adds a watch with the key the watch made as its admin key and
/// a watch's grants; each watch gets a member key of its own, and what
/// another key of the group holds, another device's name, a system that is
/// no watch's or a key that is not the root's is refused (D-124).
#[test]
fn the_root_adds_a_watch_whose_member_key_nobody_keeps() {
    use cbb_core::records::body::{AdminKind, RIGHT_READ, ROLE_WATCH};
    let (o, mut set) = group("watch");
    let root = o.root.clone().unwrap();
    let (id, recs) = add_watch(&mut set, &*root, " Wrist ", "harmonyos", &point_of(9), T + 10).unwrap();
    assert_eq!(recs.len(), 1);
    let st = set.state();
    let w = st.device(&id).unwrap();
    assert_eq!((w.role, w.rights, w.name.as_str()), (ROLE_WATCH, RIGHT_READ, "Wrist"));
    assert_eq!(w.admin, Some(Key::es256(point_of(9)).hash()));
    assert_eq!((w.powers, w.commands), AdminKind::Watch.grants());
    let (id2, _) = add_watch(&mut set, &*root, "Second", "wearos", &point_of(10), T + 11).unwrap();
    assert_ne!(id, id2, "one member key for both watches");
    assert!(add_watch(&mut set, &*root, "Third", "harmonyos", &point_of(9), T + 12).is_err(), "an admin key taken");
    assert!(add_watch(&mut set, &*root, "Wrist", "watchos", &point_of(11), T + 12).is_err(), "a name taken");
    assert!(add_watch(&mut set, &*root, "Third", "linux", &point_of(11), T + 12).is_err(), "no watch's system");
    let other = cbb_core::identity::FileKey::new(&cbb_core::identity::new_key().unwrap()).unwrap();
    assert!(add_watch(&mut set, &other, "Third", "harmonyos", &point_of(11), T + 12).is_err(), "not the root");
}

/// Even someone holding a watch's member key signs nothing that counts:
/// its keys statement verifies, yet no copy is sealed to a watch, and a
/// copy it signed is refused, since a watch sends nothing (D-124).
#[test]
fn a_watchs_member_key_signs_nothing_that_counts() {
    use cbb_core::content::Content;
    use cbb_core::copies::{self, Made, Reader};
    use cbb_core::hlc::Timestamp;
    use cbb_core::records::key::{ALG_XWING, XWING_PUBLIC};
    use cbb_core::records::statement::{self, Statement};
    let (o, mut set) = group("watch-key");
    let root = o.root.clone().unwrap();
    // The key add_watch drops at once, kept here for the test alone.
    let member = cbb_core::identity::FileKey::new(&cbb_core::identity::new_key().unwrap()).unwrap();
    let (id, _) =
        add_watch_with(&mut set, &*root, &member.public(), "Wrist", "harmonyos", &point_of(9), T + 10).unwrap();
    let st = set.state();
    let body = statement::Body {
        group: st.group,
        signer: Key::es256(member.public()).hash(),
        epoch: 1,
        time_ms: T + 11,
        seal: Key::new(ALG_XWING, vec![3; XWING_PUBLIC]),
        held: false,
    };
    let s = Statement::sign(body, &member).unwrap();
    let sealing = statement::choose(&st, [&s]);
    assert!(sealing.contains_key(&id), "the watch's statement verifies");
    let content = Content::text("for the group", false);
    let desk = o.member_key().device_id();
    assert!(copies::readers(&st, &sealing, &content, &desk, &[], None).iter().all(|r| r.id != id));

    let laptop = find(&st, "laptop").unwrap().id;
    let seal = cbb_core::seal::public_key(&cbb_core::seal::generate_secret().unwrap()).unwrap();
    let made = Made { id: [1; 16], time: Timestamp { wall: (T + 12) as i64, logical: 0 }, blob: None };
    let copy = copies::seal(&member, &[Reader { id: laptop, epoch: 1, seal }], &made, &content).unwrap();
    let v = cbb_core::format::cbor::decode(&copy).unwrap();
    assert_eq!(copies::check(&v, &st).err(), Some(copies::RULE_SEND));
}
