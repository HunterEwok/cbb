// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! Two members with the same records count the same, also when the new
//! root signs a checkpoint whose head for an admin key is one of that
//! key's records from before the change of root: such an anchor names
//! nothing, at a member that held the old record all along and at a fresh
//! one given every record ever written. The change removes the key, so
//! here the root names it again by hand, against the writer.

use super::*;

fn phone(member: &K) -> Device {
    let mut d = Device::new(member.key.clone(), "new phone", ROLE_PHONE);
    d.rights = RIGHT_READ | RIGHT_SEND | RIGHT_SECRETS;
    d
}

fn feed(set: &mut RecordSet, recs: &[Record], lists: &[Vec<u8>]) {
    for _ in 0..3 {
        set.insert_all(recs.to_vec());
        for l in lists {
            let _ = set.insert_list(l);
        }
    }
}

/// The newest record of signer in set: its seq and ID.
fn head(set: &RecordSet, signer: &KeyHash) -> (u64, RecordId) {
    set.ids()
        .filter_map(|i| set.get(i))
        .filter(|r| r.body().signer == *signer)
        .max_by_key(|r| r.body().seq)
        .map_or((0, RecordId::default()), |r| (r.body().seq, r.id()))
}

/// A record of by on its newest record in set, signed as given.
fn by_hand(set: &RecordSet, by: &K, kind: Kind, time_ms: u64) -> Record {
    let (seq, id) = head(set, &by.hash);
    let body = crate::records::body::Body {
        group: set.group(),
        signer: by.hash,
        seq: seq + 1,
        prev: (seq > 0).then_some(id),
        time_ms,
        kind,
        held: false,
    };
    crate::testkit::sign_by(body, by)
}

/// What two members must agree on.
fn meaning(s: &State) -> impl PartialEq + core::fmt::Debug {
    (s.roots.clone(), s.devices.clone(), s.revoked.clone(), s.stop, s.counting.clone())
}

/// Admin a of the first root admits d and d2 and removes dw, which k
/// holds all along; the change to nk is written by a member without the
/// removal (leaving d2 out when `leave_d2`); nk names a's key as an admin
/// again, a acks and admits d3, nk checkpoints; then nk signs a checkpoint
/// whose head for a is a's pre-change record number `bent_at` (0 to 2),
/// or (3) a record a signs after the change, before its grant, with a seen
/// that names the new root below the record that names a again.
fn check(leave_d2: bool, bent_at: usize) {
    let mut g = G::new();
    let root = k("root");
    g.device(&root, &k("k phone"), "k phone", |_| {});
    let dw = k("dw");
    g.device(&root, &dw, "dw", |_| {});
    g.admin(&k("phone a"), &k("admin a"), POWER_ADMIT | POWER_REMOVE | POWER_FREEZE);
    let a = k("admin a");
    let d = g.device(&a, &k("d"), "d", |_| {});
    let d2 = g.device(&a, &k("d2"), "d2", |_| {});
    let seen = g.seen();
    let rm = g.rec(&a, Kind::Revoke(removal(&[dw.hash], seen)));
    let pre = [d, d2, rm.clone()];
    let all = g.recs.clone();
    let without: Vec<Record> = all.iter().filter(|r| r.id() != rm.id()).cloned().collect();
    let mut kset = set_with(&g.root.key, &all, &g.lists);
    let mut aset = set_with(&g.root.key, &all, &g.lists);
    let mut w = set_with(&g.root.key, &without, &g.lists);
    let st = w.state();
    let out: Vec<KeyHash> = if leave_d2 { vec![k("d2").hash] } else { vec![] };
    let nk = k("nk");
    let wr = w
        .write_change(&st, &k("recovery"), crate::testkit::rk2(), &nk, phone(&k("nk phone")), &out, false, 1_000)
        .unwrap();
    let mut sent: Vec<Record> = wr.first.clone();
    sent.push(wr.record.clone());
    let mut lists = g.lists.clone();
    lists.push(wr.list.encode());
    let step = |sets: &mut [&mut RecordSet], sent: &[Record]| {
        for s in sets.iter_mut() {
            feed(s, sent, &lists);
        }
    };
    step(&mut [&mut w, &mut kset, &mut aset], &sent);
    // a heard the change, not its grant: void on the seen line.
    let newest = w.ids().filter_map(|i| w.get(i)).filter(|r| r.body().signer == nk.hash).max_by_key(|r| r.body().seq);
    let (seq, id) = newest.map(|r| (r.body().seq, r.id())).unwrap();
    let mut d4 = Device::new(k("d4").key.clone(), "d4", ROLE_MEMBER);
    d4.rights = RIGHT_READ | RIGHT_SEND;
    d4.seen = vec![Seen { key: nk.hash, seq, id }];
    let early = crate::testkit::sign_by(
        crate::records::body::Body {
            group: g.gid,
            signer: a.hash,
            seq: 1,
            prev: None,
            time_ms: 1_500,
            kind: Kind::device(d4),
            held: false,
        },
        &a,
    );
    if bent_at == 3 {
        sent.push(early.clone());
        step(&mut [&mut w, &mut kset, &mut aset], &sent);
    }
    let pre = [pre[0].clone(), pre[1].clone(), pre[2].clone(), early];
    let st = w.state();
    let mut dev = Device::new(k("phone a").key.clone(), "admin again", ROLE_MEMBER);
    dev.rights = RIGHT_READ | RIGHT_SEND;
    dev.admin = Some(a.key.clone());
    dev.powers = POWER_ADMIT | POWER_REMOVE | POWER_FREEZE;
    // The writer refuses the old key (the change removed it); a root that
    // names it anyway signs by hand.
    assert!(w.write_record(&st, &nk, Kind::device(dev.clone()), 2_000).is_err());
    let _ = st;
    sent.push(by_hand(&w, &nk, Kind::device(dev), 2_000));
    step(&mut [&mut w, &mut kset, &mut aset], &sent);
    let st = w.state();
    sent.push(w.write_checkpoint(&st, &nk, 3_000).unwrap());
    step(&mut [&mut w, &mut kset, &mut aset], &sent);
    // The void record bent at stands before a's ack: the root bends the
    // checkpoint while every member still holds it.
    if bent_at != 3 {
        let (seq, id) = head(&aset, &nk.hash);
        sent.push(by_hand(&aset, &a, Kind::Ack { seen: vec![Seen { key: nk.hash, seq, id }], spare: None }, 4_000));
        step(&mut [&mut aset], &sent);
        sent.push(by_hand(&aset, &a, Kind::device(Device::new(k("d3").key.clone(), "d3", ROLE_MEMBER)), 5_000));
        step(&mut [&mut w, &mut kset, &mut aset], &sent);
        let st = w.state();
        sent.push(w.write_checkpoint(&st, &nk, 6_000).unwrap());
        step(&mut [&mut w, &mut kset, &mut aset], &sent);
    }
    // The bent checkpoint: an honest one with a's head moved below the grant.
    let st = kset.state();
    let honest = kset.write_checkpoint(&st, &nk, 7_000).unwrap();
    let Kind::Checkpoint { mut heads, keep } = honest.body().kind.clone() else { unreachable!() };
    let at = &pre[bent_at];
    heads.retain(|h| h.key != a.hash);
    heads.push(Head { key: a.hash, seq: at.body().seq, id: at.id() });
    heads.sort_by_key(|h| h.key);
    let mut body = honest.body().clone();
    body.kind = Kind::Checkpoint { heads, keep };
    let bent = crate::testkit::sign_by(body, &nk);
    sent.push(bent);
    feed(&mut kset, &sent, &lists);
    // Offered again, with every record ever written.
    let every: Vec<Record> = all.iter().chain(sent.iter()).cloned().collect();
    feed(&mut kset, &every, &lists);
    let sk = kset.state();
    assert!(pre.iter().all(|r| !sk.counting.contains(&r.id())), "nothing a signed before its grant counts at k");
    assert!(sk.device_by_key(&dw.hash).is_some(), "the change left the removal out");
    let mut reversed = every.clone();
    reversed.reverse();
    for recs in [every, reversed] {
        let mut f = set_of(&g.root.key);
        feed(&mut f, &recs, &lists);
        assert_eq!(meaning(&f.state()), meaning(&sk), "a fresh member given every record counts as k does");
    }
    crate::testkit::closed(&kset);
}

#[test]
fn a_bent_anchor_below_the_admins_grant_names_nothing() {
    for bent_at in 0..4 {
        check(false, bent_at);
    }
}

#[test]
fn a_bent_anchor_with_a_device_left_out_names_nothing() {
    for bent_at in 0..4 {
        check(true, bent_at);
    }
}
