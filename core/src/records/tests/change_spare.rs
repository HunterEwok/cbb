// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! S as tests, the writer's side: an admin's ack publishes a spare admin
//! key; a change of root names an admin on the spare of its newest ack
//! that counts under the root being replaced, with the powers it had; an
//! admin asleep through two changes keeps nothing.

use super::*;
use crate::records::set::{Outcome, SPARE_USED, Written};

fn phone(member: &K) -> Device {
    let mut d = Device::new(member.key.clone(), "new phone", ROLE_PHONE);
    d.rights = RIGHT_READ | RIGHT_SEND | RIGHT_SECRETS;
    d
}

/// The change written on a set of g's records, making new_root the root
/// on the device of member; g takes its records and its list.
fn write(g: &mut G, new_root: &K, member: &K, out: &[KeyHash]) -> Written {
    let mut set = set_with(&g.root.key, &g.recs, &g.lists);
    let st = set.state();
    let w =
        set.write_change(&st, &k("recovery"), crate::testkit::rk2(), new_root, phone(member), out, false, 0).unwrap();
    for r in &w.first {
        g.push(r.clone());
    }
    g.push(w.record.clone());
    g.lists.push(w.list.encode());
    w
}

/// The re-issued device record of m.
fn reissue_of(w: &Written, m: &K) -> Device {
    w.first
        .iter()
        .find_map(|r| match &r.body().kind {
            Kind::Device(d) if d.key == m.key && !d.holds_root => Some((**d).clone()),
            _ => None,
        })
        .expect("re-issued")
}

const POWERS: u64 = POWER_ADMIT | POWER_REMOVE;

/// The first root's group: a laptop, and admin a on phone a.
fn group() -> G {
    let mut g = G::new();
    g.device(&k("root"), &k("laptop"), "laptop", |_| {});
    g.admin(&k("phone a"), &k("admin a"), POWERS);
    g
}

/// The admin's ack, written by the core's writer on a set of g's records
/// and taken into g: it publishes spare.
fn ack_with_spare(g: &mut G, admin: &K, spare: &K) -> Record {
    let mut set = set_with(&g.root.key, &g.recs, &g.lists);
    let st = set.state();
    let r = set.write_ack_spare(&st, admin, &spare.key, 0).unwrap();
    g.push(r.clone());
    r
}

/// The record by key `by` whose seen names the newest record of `root`:
/// a key named by the new root acknowledges its grant first.
fn ack_seeing(g: &mut G, by: &K, root: &K) -> Record {
    let (seq, id) = g.heads[&root.hash];
    g.rec_as_is(by, Kind::Ack { seen: vec![Seen { key: root.hash, seq, id }], spare: None })
}

/// The new root names the admin on its spare, with the powers it had;
/// after the change the spare commands and the old admin key does not, and
/// the spare's records count once it has seen its grant.
#[test]
fn a_change_names_an_admin_on_its_spare() {
    let mut g = group();
    ack_with_spare(&mut g, &k("admin a"), &k("spare a"));
    let set = set_with(&g.root.key, &g.recs, &g.lists);
    let st = set.state();
    assert_eq!(set.spare_of(&st, &k("admin a").hash), Some(k("spare a").key.clone()));
    let p = set.change_preview(&st, &[]);
    let of = |m: &str| p.iter().find(|x| x.device == k(m).key.device_id()).map(|x| x.outcome);
    assert_eq!(of("phone a"), Some(Outcome::AdminKeptWithSpare));
    assert_eq!(of("laptop"), Some(Outcome::Stays));
    let w = write(&mut g, &k("n1"), &k("p1"), &[]);
    let d = reissue_of(&w, &k("phone a"));
    assert_eq!(d.admin, Some(k("spare a").key.clone()));
    assert_eq!(d.powers, POWERS);
    let s = g.state();
    assert_eq!(s.roots.last(), Some(&k("n1").hash));
    assert!(s.may_command(&k("spare a").hash) && !s.may_command(&k("admin a").hash));
    // The device switches to the spare: its first record sees the grant,
    // then it admits a device, which counts.
    ack_seeing(&mut g, &k("spare a"), &k("n1"));
    let tv = g.device(&k("spare a"), &k("tv"), "tv", |_| {});
    let s = g.state();
    assert!(s.counting.contains(&tv.id()) && s.device_by_key(&k("tv").hash).is_some());
    // Every member agrees.
    let mut m = set_of(&g.root.key);
    sync_all(&mut m, &g.recs, &g.lists);
    assert_eq!(m.state().devices, s.devices);
}

/// Of two acks the newest that counts names the spare: a spare the device
/// rotated past is not named.
#[test]
fn the_newest_counting_ack_names_the_spare() {
    let mut g = group();
    ack_with_spare(&mut g, &k("admin a"), &k("spare 1"));
    g.device(&k("root"), &k("tv"), "tv", |_| {});
    ack_with_spare(&mut g, &k("admin a"), &k("spare 2"));
    let w = write(&mut g, &k("n1"), &k("p1"), &[]);
    assert_eq!(reissue_of(&w, &k("phone a")).admin, Some(k("spare 2").key.clone()));
}

/// An admin asleep through two changes keeps nothing: the first names its
/// spare, the second finds no ack of that spare under the root it
/// replaces, so the admin's device is carried plain (rights survive one
/// change asleep, not two).
#[test]
fn an_admin_asleep_through_two_changes_loses_its_rights() {
    let mut g = group();
    ack_with_spare(&mut g, &k("admin a"), &k("spare a"));
    write(&mut g, &k("n1"), &k("p1"), &[]);
    let set = set_with(&g.root.key, &g.recs, &g.lists);
    let st = set.state();
    let p = set.change_preview(&st, &[]);
    let phone_a = p.iter().find(|x| x.device == k("phone a").key.device_id()).unwrap();
    assert_eq!(phone_a.outcome, Outcome::AdminRightsLost);
    let w = write(&mut g, &k("n2"), &k("p2"), &[]);
    let d = reissue_of(&w, &k("phone a"));
    assert!(d.admin.is_none() && d.powers == 0);
    let s = g.state();
    assert!(!s.may_command(&k("spare a").hash) && !s.may_command(&k("admin a").hash));
    assert!(s.device_by_key(&k("phone a").hash).is_some());
}

/// The awake admin keeps its rights across two changes: under the first
/// new root its spare's ack publishes the next spare, which the second
/// change names.
#[test]
fn an_awake_admin_keeps_its_rights_across_two_changes() {
    let mut g = group();
    ack_with_spare(&mut g, &k("admin a"), &k("spare 1"));
    write(&mut g, &k("n1"), &k("p1"), &[]);
    // The device takes the change, switches to spare 1 and publishes the
    // next spare in its first ack, which sees the grant.
    let mut set = set_with(&g.root.key, &g.recs, &g.lists);
    let st = set.state();
    let r = set.write_ack_spare(&st, &k("spare 1"), &k("spare 2").key, 0).unwrap();
    g.push(r);
    let w = write(&mut g, &k("n2"), &k("p2"), &[]);
    assert_eq!(reissue_of(&w, &k("phone a")).admin, Some(k("spare 2").key.clone()));
    let s = g.state();
    assert!(s.may_command(&k("spare 2").hash));
}

/// An admin without a spare, and one whose spare is a key the group used,
/// lose their rights; a left-out admin is not carried at all.
#[test]
fn no_usable_spare_no_rights() {
    let mut g = group();
    g.admin(&k("phone b"), &k("admin b"), POWERS);
    g.admin(&k("phone c"), &k("admin c"), POWERS);
    // b acks without a spare; c's ack names the laptop's key, which only
    // a deviant writer signs (the honest one refuses it below).
    let seen = g.seen();
    g.rec(&k("admin b"), Kind::Ack { seen: seen.clone(), spare: None });
    g.rec(&k("admin c"), Kind::Ack { seen, spare: Some(k("laptop").key.clone()) });
    ack_with_spare(&mut g, &k("admin a"), &k("spare a"));
    let w = write(&mut g, &k("n1"), &k("p1"), &[k("phone a").hash]);
    assert!(!w.first.iter().any(|r| matches!(&r.body().kind, Kind::Device(d) if d.key == k("phone a").key)));
    for m in ["phone b", "phone c"] {
        let d = reissue_of(&w, &k(m));
        assert!(d.admin.is_none() && d.powers == 0, "{m}");
    }
    assert!(!g.state().may_command(&k("spare a").hash));
}

/// The writer of an ack refuses a spare the group has used: a device's
/// key, an admin key, the signer's own key, the root.
#[test]
fn the_writer_refuses_a_used_spare() {
    let g = group();
    let mut set = set_with(&g.root.key, &g.recs, &g.lists);
    let st = set.state();
    for used in ["laptop", "admin a", "phone a", "root"] {
        let e = set.write_ack_spare(&st, &k("admin a"), &k(used).key, 0).unwrap_err();
        assert_eq!(e.to_string(), SPARE_USED, "{used}");
    }
    assert!(set.write_ack_spare(&st, &k("admin a"), &k("fresh").key, 0).is_ok());
}

/// A newer counting ack without a spare withdraws the spare an older one
/// published: the change names no spare, and the admin's device is carried
/// plain.
#[test]
fn a_newer_ack_without_a_spare_withdraws_it() {
    let mut g = group();
    ack_with_spare(&mut g, &k("admin a"), &k("spare a"));
    g.device(&k("root"), &k("tv"), "tv", |_| {});
    let mut set = set_with(&g.root.key, &g.recs, &g.lists);
    let st = set.state();
    let r = set.write_ack(&st, &k("admin a"), 0).unwrap();
    g.push(r);
    let set = set_with(&g.root.key, &g.recs, &g.lists);
    assert_eq!(set.spare_of(&set.state(), &k("admin a").hash), None);
    let w = write(&mut g, &k("n1"), &k("p1"), &[]);
    let d = reissue_of(&w, &k("phone a"));
    assert!(d.admin.is_none() && d.powers == 0);
}
