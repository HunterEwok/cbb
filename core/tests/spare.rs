// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The spare key (S), read from its rule only (S-note, the owner's
//! decisions): each admin's acknowledgement may carry a one-time spare
//! key its device made; at a change of root the new root names, in its
//! re-issue, the spare of each admin's newest counting acknowledgement,
//! so an admin survives one change asleep, not two. Within one root no
//! writer call reads a spare: granting a key that happens to be a
//! published spare is an ordinary grant. No key is named as admin by two
//! roots. A spare counts only from when its device saw the record that
//! named it (the seen line). Cases the code before S does not meet are
//! marked to wait for it.

mod pieces;

use cbb_core::records::Kind;
use cbb_core::records::set::ADMIN_SILENCE_MS;
use pieces::*;

/// A's acknowledgement carrying spare `spare`.
fn ack_with_spare(g: &mut Group, by: &K, spare: &K) {
    g.t += 1_000;
    let seen = vec![head_of(&g.set, &g.r1.hash).unwrap()];
    let r = g.chain.sign(&g.set, by, Kind::Ack { seen, spare: Some(spare.key.clone()) }, g.t);
    g.set.insert(r).unwrap();
}

/// S1.1, and the spare's first acts: A acks with spare SA; at the change
/// the new root names SA on PA; A is void. PA wakes, sees the record that
/// named SA, and SA's removal counts.
#[test]
#[ignore = "waits for S"]
fn the_spare_carries_an_admin_through_one_change() {
    let mut g = group("s1");
    let (a, sa) = (k("A"), k("SA"));
    ack_with_spare(&mut g, &a, &sa);
    g.t += 1_000;
    change(&mut g.set, &k("s1 root 2"), &k("P2"), &[], g.t);
    let st = g.set.state();
    assert_eq!(admin_of(&st, &k("PA")), Some(sa.hash), "named through its spare");
    assert!(!is_admin(&st, &a), "the old key is void");
    let mut chain = Chain::new();
    g.t += 1_000;
    let seen = vec![head_of(&g.set, &k("s1 root 2").hash).unwrap()];
    let rm = chain.sign(&g.set, &sa, Kind::Revoke(removal(&[&k("E")], seen)), g.t);
    g.set.insert(rm.clone()).unwrap();
    let st = g.set.state();
    assert!(st.counting.contains(&rm.id()));
    assert!(!has(&st, &k("E")));
    same_in_every_order(&g.set, "spare named");
}

/// Only the newest counting acknowledgement's spare is named.
#[test]
#[ignore = "waits for S"]
fn the_newest_ack_s_spare_is_named() {
    let mut g = group("s2");
    let a = k("A");
    ack_with_spare(&mut g, &a, &k("SA1"));
    ack_with_spare(&mut g, &a, &k("SA2"));
    g.t += 1_000;
    change(&mut g.set, &k("s2 root 2"), &k("P2"), &[], g.t);
    let st = g.set.state();
    assert_eq!(admin_of(&st, &k("PA")), Some(k("SA2").hash));
    assert!(!is_admin(&st, &k("SA1")));
}

/// Records' §6, pinned: within one root, granting a key that happens to
/// be a published spare is an ordinary grant and counts.
#[test]
fn within_one_root_a_published_spare_is_an_ordinary_grant() {
    let mut g = group("s3");
    let (a, sa) = (k("A"), k("SA"));
    ack_with_spare(&mut g, &a, &sa);
    let st = g.set.state();
    g.t += 1_000;
    g.set.write_record(&st, &g.r1, Kind::device(admin_device(&k("PX"), "PX", &sa)), g.t).unwrap();
    assert_eq!(admin_of(&g.set.state(), &k("PX")), Some(sa.hash));
}

/// No key is named as admin by two roots: a spare that the replaced root
/// had already named as an admin key is not named again at the change
/// (that admin's rights are lost; the person makes it an admin again).
#[test]
#[ignore = "waits for S"]
fn a_spare_the_old_root_already_named_is_not_named_again() {
    let mut g = group("s4");
    let (a, sa) = (k("A"), k("SA"));
    ack_with_spare(&mut g, &a, &sa);
    let st = g.set.state();
    g.t += 1_000;
    g.set.write_record(&st, &g.r1, Kind::device(admin_device(&k("PX"), "PX", &sa)), g.t).unwrap();
    g.t += 1_000;
    change(&mut g.set, &k("s4 root 2"), &k("P2"), &[], g.t);
    let st = g.set.state();
    assert!(!is_admin(&st, &sa), "named by the old root: not named by the new one");
    assert!(has(&st, &k("PA")) && admin_of(&st, &k("PA")).is_none(), "PA stays, a plain device");
}

/// S1.3: a spare that collides with a key the group knows (PA's own
/// member key, another device's, another admin key, the old root, the
/// recovery key) is never named; the change still goes through.
#[test]
#[ignore = "waits for S"]
fn a_colliding_spare_is_never_named() {
    for (i, collide) in ["PA", "D", "B", "s5 root 1", "recovery"].into_iter().enumerate() {
        let mut g = group("s5");
        let st = g.set.state();
        g.t += 1_000;
        g.set.write_record(&st, &g.r1, Kind::device(admin_device(&k("PB"), "PB", &k("B"))), g.t).unwrap();
        g.t += 1_000;
        let seen = vec![head_of(&g.set, &g.r1.hash).unwrap()];
        let r = g.chain.sign(&g.set, &k("A"), Kind::Ack { seen, spare: Some(k(collide).key.clone()) }, g.t);
        let _ = g.set.insert(r);
        g.t += 1_000;
        let root2 = k(&format!("s5 root 2 {i}"));
        change(&mut g.set, &root2, &k("P2"), &[], g.t);
        let st = g.set.state();
        assert!(!is_admin(&st, &k(collide)), "{collide}: a colliding spare is not named");
        assert!(has(&st, &k("PA")), "{collide}");
    }
}

/// S1.4: two devices publish the same spare: it is named for at most one.
#[test]
fn a_spare_two_devices_published_is_named_at_most_once() {
    let mut g = group("s6");
    let st = g.set.state();
    g.t += 1_000;
    g.set.write_record(&st, &g.r1, Kind::device(admin_device(&k("PB"), "PB", &k("B"))), g.t).unwrap();
    let s = k("S shared");
    ack_with_spare(&mut g, &k("A"), &s);
    ack_with_spare(&mut g, &k("B"), &s);
    g.t += 1_000;
    change(&mut g.set, &k("s6 root 2"), &k("P2"), &[], g.t);
    let st = g.set.state();
    assert!(st.devices.iter().filter(|d| d.admin == Some(s.hash)).count() <= 1);
}

/// S1.5: a spare that is not an ES256 public key: such an
/// acknowledgement cannot even be written.
#[test]
fn a_spare_that_is_not_a_key_is_refused() {
    let g = group("s7");
    let seen = vec![head_of(&g.set, &g.r1.hash).unwrap()];
    let bad = cbb_core::records::Key::es256(vec![4u8; 65]);
    let a = k("A");
    let head = head_of(&g.set, &a.hash).unwrap();
    let body = cbb_core::records::Body {
        group: g.set.group(),
        signer: a.hash,
        seq: head.seq + 1,
        prev: Some(head.id),
        time_ms: g.t + 1_000,
        kind: Kind::Ack { seen, spare: Some(bad) },
        held: false,
    };
    assert!(cbb_core::records::Record::sign(body, &a).is_err());
}

/// S2.1: the spare pre-signs (a removal of D, its seen holding only the
/// old root) before the new root names it: void after the naming.
#[test]
#[ignore = "waits for S and the seen line"]
fn what_a_spare_signed_before_its_naming_is_void() {
    let mut g = group("s8");
    let (a, sa) = (k("A"), k("SA"));
    ack_with_spare(&mut g, &a, &sa);
    let mut chain = Chain::new();
    g.t += 1_000;
    let seen = vec![head_of(&g.set, &g.r1.hash).unwrap()];
    let early = chain.sign(&g.set, &sa, Kind::Revoke(removal(&[&k("D")], seen)), g.t);
    g.t += 1_000;
    change(&mut g.set, &k("s8 root 2"), &k("P2"), &[], g.t);
    let _ = g.set.insert(early.clone());
    let st = g.set.state();
    assert_eq!(admin_of(&st, &k("PA")), Some(sa.hash));
    assert!(!st.counting.contains(&early.id()));
    assert!(has(&st, &k("D")));
}

/// S3.1: a named spare that never signs is taken back for its silence,
/// counted from the record that named it, on the root's clock.
#[test]
#[ignore = "waits for S"]
fn a_spare_that_never_signs_falls_to_the_silence() {
    let mut g = group("s9");
    let (a, sa) = (k("A"), k("SA"));
    ack_with_spare(&mut g, &a, &sa);
    g.t += 1_000;
    let named = g.t;
    change(&mut g.set, &k("s9 root 2"), &k("P2"), &[], g.t);
    let r2 = k("s9 root 2");
    let heard = std::collections::BTreeMap::new();
    let st = g.set.state();
    let early = g.set.take_back_lagging(&st, &r2, &heard, named + ADMIN_SILENCE_MS - 1).unwrap();
    assert!(early.is_empty(), "not before its silence");
    let due = g.set.take_back_lagging(&st, &r2, &heard, named + ADMIN_SILENCE_MS + 1).unwrap();
    assert!(
        due.iter().any(|(_, r)| matches!(&r.body().kind, Kind::Device(d) if d.key.hash() == k("PA").hash)),
        "the silent spare is taken back"
    );
}

/// S3.3: two changes before the device wakes: root 3 does not name the
/// spare root 2 named (an admin key under an earlier root); PA stays a
/// plain device.
#[test]
#[ignore = "waits for S"]
fn an_admin_survives_one_change_asleep_not_two() {
    let mut g = group("s10");
    let (a, sa) = (k("A"), k("SA"));
    ack_with_spare(&mut g, &a, &sa);
    g.t += 1_000;
    change(&mut g.set, &k("s10 root 2"), &k("P2"), &[], g.t);
    assert_eq!(admin_of(&g.set.state(), &k("PA")), Some(sa.hash));
    g.t += 1_000;
    change(&mut g.set, &k("s10 root 3"), &k("P3"), &[], g.t);
    let st = g.set.state();
    assert!(has(&st, &k("PA")));
    assert_eq!(admin_of(&st, &k("PA")), None, "two changes asleep: the rights are lost");
}
