// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The cap of MAX_DEVICES: taken last, among the devices that count, so
//! that a removed device holds no place and no signer's power depends on
//! it; a writer never makes a 257th device.

use super::*;

fn ids_of(s: &State) -> Vec<DeviceId> {
    s.devices.iter().map(|d| d.id).collect()
}

/// 1536 devices admitted and removed, 256 that count, and the 16th
/// admin's own record the last in order: it counts, what it admits
/// counts, and its removals hold.
#[test]
fn removed_devices_hold_no_place() {
    let mut g = G::new();
    let early = ADMIN_KEYS_MAX - 1;
    let per = 103;
    let mut admitted = Vec::new();
    for a in 0..early {
        let admin = k(&format!("admin {a}"));
        g.admin(&k(&format!("admin phone {a}")), &admin, POWER_ADMIT);
        for i in 0..per {
            let m = k(&format!("a{a} d{i}"));
            g.device(&admin, &m, "d", |_| {});
            admitted.push(m.hash);
        }
    }
    let gone = MAX_ROOT_RECORDS - early - 1;
    for x in &admitted[..gone] {
        g.root_rec(Kind::Revoke(Removal { keys: vec![*x], seen: Vec::new() }));
    }
    let last = k(&format!("admin {early}"));
    let last_phone = k(&format!("admin phone {early}"));
    g.admin(&last_phone, &last, POWER_ADMIT | POWER_REMOVE);
    let live_before = early + (admitted.len() - gone) + 1;
    let mut own = Vec::new();
    for i in 0..MAX_DEVICES - live_before {
        let m = k(&format!("last d{i}"));
        g.device(&last, &m, "d", |_| {});
        own.push(m.hash);
    }
    let s = g.state();
    assert_eq!(s.devices.len(), MAX_DEVICES);
    assert!(s.device_by_key(&last_phone.hash).is_some_and(|d| d.admin == Some(last.hash)));
    for x in &own {
        assert!(s.device_by_key(x).is_some());
    }
    for x in &admitted[..gone] {
        assert!(s.device_by_key(x).is_none());
    }
    let set = set_with(&g.root.key, &g.recs, &g.lists);
    assert_eq!(set.state(), s);
    // The 16th admin removes one of its own: it holds.
    let seen = vec![g.seen_at(&last.hash, g.heads[&last.hash].0)];
    g.rec(&last, Kind::Revoke(Removal { keys: vec![own[0]], seen }));
    let s = g.state();
    assert!(s.device_by_key(&own[0]).is_none());
    assert_eq!(s.devices.len(), MAX_DEVICES - 1);
}

/// Two admins admit a device each at once, past 256: exactly one device is
/// past the cap, every member places it alike in any order the records
/// come, and a removal lets it count.
#[test]
fn two_admissions_at_once_past_the_cap() {
    let mut g = G::new();
    let root = k("root");
    let (a, b) = (k("admin a"), k("admin b"));
    g.admin(&k("phone a"), &a, POWER_ADMIT);
    g.admin(&k("phone b"), &b, POWER_ADMIT);
    for i in 0..MAX_DEVICES - 3 {
        g.device(&root, &k(&format!("d{i}")), "d", |_| {});
    }
    assert_eq!(g.state().devices.len(), MAX_DEVICES - 1);
    let xa = g.device(&a, &k("xa"), "xa", |_| {});
    let xb = g.device(&b, &k("xb"), "xb", |_| {});
    let s = g.state();
    assert_eq!(s.devices.len(), MAX_DEVICES);
    // Exactly one device is past the cap, the same on every member.
    let all: Vec<K> = (0..MAX_DEVICES - 3).map(|i| k(&format!("d{i}"))).chain([k("xa"), k("xb")]).collect();
    let out: Vec<&K> = all.iter().filter(|m| s.device_by_key(&m.hash).is_none()).collect();
    assert_eq!(out.len(), 1);
    let out = out[0].clone();
    assert!(xa.id() != xb.id());
    for order in 0..3 {
        let mut recs = g.recs.clone();
        let n = recs.len();
        match order {
            0 => recs.reverse(),
            1 => recs.rotate_left(n / 2),
            _ => recs.swap(n - 1, n - 2),
        }
        let mut set = set_of(&g.root.key);
        set.insert_all(recs);
        assert_eq!(ids_of(&set.state()), ids_of(&s), "order {order}");
    }
    // A removal makes room: the one past the cap counts.
    let gone = if out.hash == k("d0").hash { k("d1") } else { k("d0") };
    g.root_rec(Kind::Revoke(Removal { keys: vec![gone.hash], seen: Vec::new() }));
    let s = g.state();
    assert!(s.device_by_key(&out.hash).is_some());
    assert_eq!(s.devices.len(), MAX_DEVICES);
}

/// At 256 devices the writer refuses a new admission, by the root or an
/// admin, and no device that counted stops counting.
#[test]
fn the_writer_refuses_a_257th_device() {
    let mut g = G::new();
    let root = k("root");
    let a = k("admin a");
    g.admin(&k("phone a"), &a, POWER_ADMIT);
    for i in 0..MAX_DEVICES - 1 {
        g.device(&root, &k(&format!("d{i}")), "d", |_| {});
    }
    let mut set = set_with(&g.root.key, &g.recs, &g.lists);
    let st = set.state();
    assert_eq!(st.devices.len(), MAX_DEVICES);
    for by in [&root, &a] {
        let d = Device::new(k("one more").key, "one more", ROLE_MEMBER);
        let e = set.write_record(&st, by, Kind::device(d), 0).unwrap_err();
        assert!(e.to_string().contains("256 devices"), "{e}");
    }
    assert_eq!(set.state(), st);
    // A device that counts may still be written again (a new name).
    let d = Device::new(k("d5").key, "renamed", ROLE_MEMBER);
    set.write_record(&st, &root, Kind::device(d), 0).unwrap();
    assert_eq!(set.state().devices.len(), MAX_DEVICES);
}
