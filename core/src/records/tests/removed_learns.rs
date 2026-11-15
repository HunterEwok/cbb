// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! A member an admin removes while it is away must learn its removal
//! from what a member of the group hands it (for_peer and
//! lists_for_peer), whatever root records it missed while away.

use super::*;

fn feed(set: &mut RecordSet, recs: &[Record], lists: &[Vec<u8>]) {
    for _ in 0..3 {
        set.insert_all(recs.to_vec());
        for l in lists {
            let _ = set.insert_list(l);
        }
    }
}

/// away_before_grant: the member left before the root named the admin.
/// more_root: the root signs two more records before its checkpoint.
fn case(away_before_grant: bool, more_root: bool) -> bool {
    case_with(away_before_grant, more_root, false)
}

/// ack_first: the admin acknowledges its grant before the root's
/// checkpoint, so no record of the admin's sees the checkpoint.
fn case_with(away_before_grant: bool, more_root: bool, ack_first: bool) -> bool {
    let mut g = G::new();
    let root = k("root");
    g.device(&root, &k("rl phone"), "phone", |d| {
        d.role = ROLE_PHONE;
        d.holds_root = true;
    });
    let x = k("rl x");
    g.device(&root, &x, "x", |_| {});
    g.device(&root, &k("rl y"), "y", |_| {});
    let all: Vec<Record> = g.recs.clone();
    let refs: Vec<&Record> = all.iter().collect();
    checkpoint_keeping(&mut g, &refs);
    let mut x_recs = g.recs.clone();
    let a = k("rl admin a");
    g.admin(&k("rl phone a"), &a, POWER_ADMIT | POWER_REMOVE | POWER_FREEZE);
    if !away_before_grant {
        x_recs = g.recs.clone();
    }
    if more_root {
        g.device(&root, &k("rl z"), "z", |_| {});
        g.device(&root, &k("rl w"), "w", |_| {});
    }
    if ack_first {
        let set = set_with(&g.root.key, &g.recs, &g.lists);
        let st = set.state();
        let mut set = set;
        let ack = set.write_ack(&st, &a, 500).unwrap();
        g.push(ack);
    }
    // The root checkpoints, the admin removes x: both through the writers.
    let mut r = set_with(&g.root.key, &g.recs, &g.lists);
    let st = r.state();
    let cp = r.write_checkpoint(&st, &root, 1_000).unwrap();
    r.insert(cp).unwrap();
    let mut aset = r.clone();
    let st = aset.state();
    let rm = aset.write_record(&st, &a, Kind::Revoke(removal(&[x.hash], vec![])), 2_000).unwrap();
    feed(&mut r, &rm, &g.lists);
    let st = r.state();
    let at_root = st.revoked.contains(&x.hash);
    // x comes back and takes what the root's member hands it.
    let mut xs = set_with(&g.root.key, &x_recs, &g.lists);
    for _ in 0..3 {
        let st = r.state();
        let given: Vec<Record> = r.for_peer(&st, &x.hash).into_iter().cloned().collect();
        let lists: Vec<Vec<u8>> = r.lists_for_peer(&st, &x.hash).into_iter().map(<[u8]>::to_vec).collect();
        // Within the root's room: only root records the set keeps go.
        let units: u64 = given
            .iter()
            .filter(|r| r.body().signer == root.hash)
            .map(|r| crate::records::eval::item(r, crate::records::eval::Role::Root).units)
            .sum();
        assert!(units <= crate::records::keep::ceiling(true), "{units} units of root records");
        feed(&mut xs, &given, &lists);
    }
    let xst = xs.state();
    let learned = xst.revoked.contains(&x.hash);
    let ignored: Vec<_> = xst.ignored.iter().map(|i| (i.record, i.why.name())).collect();
    std::eprintln!(
        "away before grant {away_before_grant} more root {more_root}: removal counts at the root {at_root}; x learned {learned}; x still a device {}; x ignored {ignored:?}",
        xst.device_by_key(&x.hash).is_some()
    );
    at_root && learned
}

#[test]
fn a_member_an_admin_removes_while_away_learns_it() {
    let mut ok = true;
    for away in [false, true] {
        for more in [false, true] {
            ok &= case(away, more);
        }
    }
    assert!(ok, "a removed member does not learn an admin's removal from what the group hands it");
}

/// The admin's records saw the root only below its newest checkpoint: the
/// checkpoint is not on the line any seen names, and x still learns.
#[test]
fn a_removal_whose_admin_never_saw_the_checkpoint_is_learned() {
    let mut ok = true;
    for away in [false, true] {
        for more in [false, true] {
            ok &= case_with(away, more, true);
        }
    }
    assert!(ok, "a removed member does not learn the removal of an admin that never saw the checkpoint");
}
