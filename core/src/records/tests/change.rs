// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! L + B as tests: after a change of root only the last root, the admin
//! keys it names and the recovery chain count; the new root re-issues what
//! counts at its device as its own records, leaving out what the person
//! names; a sleeper takes the change from a peer it does not know.

use super::*;
use crate::records::set::{CHANGE_FORMER_ADMIN, CHANGE_WAITING, Outcome, Written};

/// The device record of a new phone of the root.
fn phone(member: &K) -> Device {
    let mut d = Device::new(member.key.clone(), "new phone", ROLE_PHONE);
    d.rights = RIGHT_READ | RIGHT_SEND | RIGHT_SECRETS;
    d
}

/// The change written on a set of `from`, making new_root the root on the
/// device of member, leaving out `out`; g takes its records and its list.
fn write(g: &mut G, from: &[Record], new_root: &K, member: &K, out: &[KeyHash]) -> Written {
    let mut set = set_with(&g.root.key, from, &g.lists);
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

/// The new root's re-issued device record of m, if any.
fn reissue_of<'w>(w: &'w Written, m: &K) -> Option<&'w Device> {
    w.first.iter().find_map(|r| match &r.body().kind {
        Kind::Device(d) if d.key == m.key && !d.holds_root => Some(&**d),
        _ => None,
    })
}

fn has(s: &State, m: &K) -> bool {
    s.device_by_key(&m.hash).is_some()
}

/// Every member ends in one state: evaluate, and sets filled in both
/// orders.
fn agreed(g: &G) -> State {
    let s = g.state();
    for order in 0..2 {
        let mut recs = g.recs.clone();
        if order == 1 {
            recs.reverse();
        }
        let mut m = set_of(&g.root.key);
        sync_all(&mut m, &recs, &g.lists);
        let t = m.state();
        assert_eq!((&t.roots, &t.devices, &t.revoked), (&s.roots, &s.devices, &s.revoked), "order {order}");
    }
    s
}

/// The first root's group: its phone, a laptop, and an admin with a phone.
fn group() -> G {
    let mut g = G::new();
    let root = k("root");
    g.device(&root, &k("old phone"), "old phone", |d| {
        d.role = ROLE_PHONE;
        d.holds_root = true;
    });
    g.device(&root, &k("laptop"), "laptop", |_| {});
    g.admin(&k("phone a"), &k("admin a"), POWER_ADMIT | POWER_REMOVE | POWER_FREEZE);
    g
}

/// oldRootResolveStays, first pin: a device whose only counting admission
/// an admin signed is re-issued as the new root's own record, from its
/// newest counting record, and counts after the change.
#[test]
fn a_device_an_admin_admitted_is_reissued_by_the_new_root() {
    let mut g = group();
    g.device(&k("admin a"), &k("lamp"), "lamp", |d| d.name = "lamp".into());
    let seen = g.seen();
    g.device(&k("admin a"), &k("lamp"), "lamp", |d| {
        d.name = "lamp 2".into();
        d.seen = seen;
    });
    let name = g.state().device_by_key(&k("lamp").hash).expect("counts before").name.clone();
    let all = g.recs.clone();
    let w = write(&mut g, &all, &k("n1"), &k("p1"), &[]);
    let d = reissue_of(&w, &k("lamp")).expect("re-issued");
    assert_eq!(d.name, name, "from its newest counting record");
    let s = agreed(&g);
    assert_eq!(s.roots.last(), Some(&k("n1").hash));
    let lamp = s.device_by_key(&k("lamp").hash).expect("counts after the change");
    assert!(lamp.by_root);
}

/// Second pin: a device that counted only through a record that does not
/// count at the writer (an admin key's record off its grant line) is not
/// re-issued, and is no device after the change.
#[test]
fn a_device_that_does_not_count_at_the_writer_is_not_reissued() {
    let mut g = group();
    // The admin key's first record names no root record: off its line.
    let mut d = Device::new(k("ghost").key.clone(), "ghost", ROLE_MEMBER);
    d.rights = RIGHT_READ;
    g.rec_as_is(&k("admin a"), Kind::device(d));
    assert!(!has(&g.state(), &k("ghost")));
    let all = g.recs.clone();
    let w = write(&mut g, &all, &k("n1"), &k("p1"), &[]);
    assert!(reissue_of(&w, &k("ghost")).is_none());
    assert!(!has(&agreed(&g), &k("ghost")));
}

/// The mirror: an admin's own device stays, as a plain device, and its
/// admin key commands nothing after the change.
#[test]
fn an_admins_device_stays_as_a_plain_device() {
    let mut g = group();
    let all = g.recs.clone();
    let w = write(&mut g, &all, &k("n1"), &k("p1"), &[]);
    let d = reissue_of(&w, &k("phone a")).expect("re-issued");
    assert!(d.admin.is_none() && d.powers == 0);
    let s = agreed(&g);
    assert!(s.device_by_key(&k("phone a").hash).is_some_and(|d| d.admin.is_none()));
    assert!(!s.may_command(&k("admin a").hash));
}

/// A device removed before the first change stays out after the second,
/// however the records reach a member, and the old removal is not needed
/// for it.
#[test]
fn a_device_removed_before_a_change_stays_out_after_the_next() {
    let mut g = group();
    g.device(&k("root"), &k("tv"), "tv", |_| {});
    g.root_rec(Kind::Revoke(removal(&[k("tv").hash], g.seen())));
    let all = g.recs.clone();
    let w = write(&mut g, &all, &k("n1"), &k("p1"), &[]);
    assert!(reissue_of(&w, &k("tv")).is_none());
    assert!(!has(&agreed(&g), &k("tv")));
    let all = g.recs.clone();
    let w = write(&mut g, &all, &k("n2"), &k("p2"), &[]);
    assert!(reissue_of(&w, &k("tv")).is_none());
    let s = agreed(&g);
    assert_eq!(s.roots.last(), Some(&k("n2").hash));
    assert!(!has(&s, &k("tv")) && has(&s, &k("laptop")) && has(&s, &k("p1")));
}

/// Freezes are carried: a device the root froze and an admin's device
/// another admin froze (by its admin key) are re-issued frozen, each with
/// the new root's own freeze of its member key, and only the new root's
/// thaw takes it off.
#[test]
fn freezes_are_carried_as_the_new_roots_own() {
    let mut g = group();
    g.admin(&k("phone b"), &k("admin b"), POWER_ADMIT);
    g.root_rec(Kind::Freeze(removal(&[k("laptop").hash], g.seen())));
    let seen = g.seen();
    g.rec(&k("admin a"), Kind::Freeze(removal(&[k("admin b").hash], seen)));
    let before = g.state();
    assert!(before.device_by_key(&k("laptop").hash).is_some_and(|d| d.frozen));
    assert!(before.device_by_key(&k("phone b").hash).is_some_and(|d| d.frozen));
    let all = g.recs.clone();
    let w = write(&mut g, &all, &k("n1"), &k("p1"), &[]);
    let freezes: Vec<&Record> = w.first.iter().filter(|r| matches!(r.body().kind, Kind::Freeze(_))).collect();
    assert_eq!(freezes.len(), 2);
    let s = agreed(&g);
    for m in ["laptop", "phone b"] {
        assert!(s.device_by_key(&k(m).hash).is_some_and(|d| d.frozen), "{m} frozen after the change");
    }
    assert!(s.device_by_key(&k("phone a").hash).is_some_and(|d| !d.frozen));
    // The new root thaws the laptop.
    let laptop_freeze = freezes
        .iter()
        .find(|r| matches!(&r.body().kind, Kind::Freeze(rm) if rm.keys == vec![k("laptop").hash]))
        .unwrap()
        .id();
    let seen = g.seen();
    g.rec(&k("n1"), Kind::Thaw { ids: vec![laptop_freeze], seen });
    let s = agreed(&g);
    assert!(s.device_by_key(&k("laptop").hash).is_some_and(|d| !d.frozen));
    assert!(s.device_by_key(&k("phone b").hash).is_some_and(|d| d.frozen));
}

/// The query before a change lists every device but the writer's own with
/// what the change does to it, and write_change carries exactly those not
/// out.
#[test]
fn the_preview_names_every_outcome_and_the_writer_follows_it() {
    let mut g = group();
    g.device(&k("root"), &k("tv"), "tv", |_| {});
    g.device(&k("root"), &k("radio"), "radio", |_| {});
    g.root_rec(Kind::Freeze(removal(&[k("tv").hash], g.seen())));
    let set = set_with(&g.root.key, &g.recs, &g.lists);
    let st = set.state();
    let out = [k("radio").hash];
    let preview = set.change_preview(&st, &out);
    let of = |m: &str| preview.iter().find(|p| p.device == k(m).key.device_id()).map(|p| p.outcome);
    assert_eq!(of("laptop"), Some(Outcome::Stays));
    assert_eq!(of("radio"), Some(Outcome::Out));
    assert_eq!(of("tv"), Some(Outcome::Frozen));
    assert_eq!(of("phone a"), Some(Outcome::AdminRightsLost));
    let all = g.recs.clone();
    let w = write(&mut g, &all, &k("n1"), &k("p1"), &out);
    for p in &preview {
        let carried =
            w.first.iter().any(|r| matches!(&r.body().kind, Kind::Device(d) if d.key.device_id() == p.device));
        assert_eq!(carried, p.outcome != Outcome::Out, "{:?}", p);
    }
}

/// A device the person leaves out counts at no member after the change,
/// even when an old-root or old-admin record about it arrives later.
#[test]
fn a_left_out_device_stays_out_whatever_comes_later() {
    let mut g = group();
    g.device(&k("root"), &k("tv"), "tv", |_| {});
    let all = g.recs.clone();
    write(&mut g, &all, &k("n1"), &k("p1"), &[k("tv").hash]);
    assert!(!has(&agreed(&g), &k("tv")));
    // Late records of the old era about the TV.
    let seen = g.seen();
    g.device(&k("root"), &k("tv"), "tv again", |d| d.seen = seen.clone());
    g.device(&k("admin a"), &k("tv"), "tv by admin", |d| d.seen = seen);
    let s = agreed(&g);
    assert!(!has(&s, &k("tv")) && s.roots.last() == Some(&k("n1").hash));
}

/// A new root is always a fresh key: a key that was an admin key is
/// refused with its own message.
#[test]
fn the_writer_refuses_a_former_admin_key_as_the_new_root() {
    let g = group();
    let mut set = set_with(&g.root.key, &g.recs, &g.lists);
    let st = set.state();
    let e = set
        .write_change(&st, &k("recovery"), crate::testkit::rk2(), &k("admin a"), phone(&k("p1")), &[], false, 0)
        .unwrap_err();
    assert_eq!(e.to_string(), CHANGE_FORMER_ADMIN);
}

/// A writer holding a head without the new root's re-issue waits: it
/// writes no second change while that one is pending.
#[test]
fn a_head_without_its_reissue_keeps_the_writer_waiting() {
    let mut g = group();
    let all = g.recs.clone();
    let w = write(&mut g, &all, &k("n1"), &k("p1"), &[]);
    let mut held = all.clone();
    held.push(w.record.clone());
    let mut set = set_with(&g.root.key, &held, &g.lists);
    let st = set.state();
    assert_eq!(st.roots.last(), Some(&k("root").hash), "the change does not apply without its records");
    let e = set
        .write_change(&st, &k("recovery"), crate::testkit::rk2(), &k("n2"), phone(&k("p2")), &[], false, 0)
        .unwrap_err();
    assert_eq!(e.to_string(), CHANGE_WAITING);
}

/// A sleeper whose only peer is the new root's phone, a key it does not
/// know, takes the change from it: the recovery record, its list and the
/// new root's records; then the new root's later records. What else that
/// peer offers (records of other keys, of the old root, more recovery
/// records than a fork's proof at a seq) is not kept.
#[test]
fn a_sleeper_takes_the_change_from_a_peer_it_does_not_know() {
    let mut g = group();
    let mut sleeper = set_with(&g.root.key, &g.recs, &g.lists);
    let all = g.recs.clone();
    let w = write(&mut g, &all, &k("n1"), &k("p1"), &[]);
    let later = g.device(&k("n1"), &k("watch"), "watch", |_| {});
    // Junk beside it: a stranger's records, the old root's and the old
    // admin's after the change.
    let stranger = k("stranger");
    let gid = g.gid;
    let junk_body = |by: &K, seq: u64| Body {
        group: gid,
        signer: by.hash,
        seq,
        prev: None,
        time_ms: 0,
        kind: Kind::Copies { incoming_ms: MIN_INCOMING_MS, seen: vec![] },
        held: false,
    };
    let junk: Vec<Record> = vec![
        crate::testkit::sign_by(junk_body(&stranger, 1), &stranger),
        g.device(&k("root"), &k("intruder"), "intruder", |_| {}),
        g.device(&k("admin a"), &k("intruder 2"), "intruder", |_| {}),
    ];
    let st = sleeper.state();
    assert!(
        crate::peer::standing(&st, &k("laptop").hash, k("p1").key.public().try_into().unwrap())
            == crate::peer::Standing::Unknown
    );
    let mut offered: Vec<Record> = junk.clone();
    offered.extend(w.first.iter().cloned());
    offered.push(w.record.clone());
    offered.push(later.clone());
    let list = w.list.encode();
    let (bytes_before, _) = (sleeper.bytes(), ());
    let n = sleeper.insert_from_unknown(&offered, &[list.as_slice()]);
    assert!(n > 0 && sleeper.bytes() > bytes_before);
    let s = sleeper.state();
    assert_eq!(s.roots.last(), Some(&k("n1").hash));
    assert!(has(&s, &k("p1")) && has(&s, &k("laptop")) && has(&s, &k("watch")));
    assert!(junk.iter().all(|r| !sleeper.contains(&r.id())));
    assert!(!has(&s, &k("intruder")) && !has(&s, &k("intruder 2")));
}

/// Of a peer it does not know a set takes no recovery records but the
/// recovery key's, at most two of a seq, and none of a root no held
/// recovery record names.
#[test]
fn a_peer_it_does_not_know_brings_nothing_else() {
    let g = group();
    let mut set = set_with(&g.root.key, &g.recs, &g.lists);
    let (bytes, digest) = (set.bytes(), set.digest());
    let other = k("other root");
    let mut h = G { root: g.root.clone(), gid: g.gid, heads: BTreeMap::new(), recs: Vec::new(), lists: Vec::new() };
    let offered: Vec<Record> = (0..8).map(|i| h.device(&other, &k(&format!("o{i}")), "o", |_| {})).collect();
    assert_eq!(set.insert_from_unknown(&offered, &[]), 0);
    assert_eq!((set.bytes(), set.digest()), (bytes, digest));
}
