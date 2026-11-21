// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

use super::*;

/// Sim seed 1321 (238004d + whole sessions): an admin admits x, then the
/// root signs two records at one seq; the admin's side holds one head.
/// A member holding both heads must hand x the pair (x counts itself in).
fn fork_after_admin_admission(before: bool) -> (State, State, RecordSet, Record, K2) {
    let mut g = G::new();
    g.device(&k("root"), &k("f laptop"), "laptop", |_| {});
    g.admin(&k("f phone a"), &k("f admin a"), POWER_ADMIT | POWER_REMOVE);
    let mut adm_recs: Vec<Record> = Vec::new();
    let admit = |g: &G, extra: &[Record]| -> Vec<Record> {
        let mut recs = g.recs.clone();
        recs.extend(extra.iter().cloned());
        let mut a = set_with(&g.root.key, &recs, &g.lists);
        let st = a.state();
        let w = a
            .write_record(
                &st,
                &k("f admin a"),
                Kind::device(Device::new(k("f x").key.clone(), "x", ROLE_MEMBER)),
                70_000,
            )
            .unwrap();
        let _ = w;
        let have: alloc::collections::BTreeSet<RecordId> = recs.iter().map(Record::id).collect();
        a.in_dependency_order().into_iter().filter(|r| !have.contains(&r.id())).cloned().collect()
    };
    if before {
        adm_recs = admit(&g, &[]);
        for r in &adm_recs {
            g.push(r.clone());
        }
    }
    let r = g.root_rec(Kind::Copies { incoming_ms: 50_000, seen: vec![] });
    let twin = root_twin(&g, &r, Kind::Copies { incoming_ms: 60_000, seen: vec![] });
    // The admin's side: everything but r, and the twin.
    let mut side: Vec<Record> = g.recs.iter().filter(|q| q.id() != r.id()).cloned().collect();
    side.push(twin.clone());
    if !before {
        adm_recs = admit(&G { recs: side.clone(), ..g.clone() }, &[]);
        side.extend(adm_recs.iter().cloned());
    }
    let xset = set_with(&g.root.key, &side, &g.lists);
    let mut all = g.recs.clone();
    all.push(twin.clone());
    all.extend(adm_recs.iter().cloned());
    let m = set_with(&g.root.key, &all, &g.lists);
    (xset.state(), m.state(), m, r, K2(twin))
}

struct K2(Record);

fn check_fork_after_admission(before: bool) {
    let (xs, ms, m, r, K2(twin)) = fork_after_admin_admission(before);
    let x = k("f x");
    let pt: [u8; 65] = x.key.public().to_vec().try_into().unwrap();
    let s = crate::peer::standing(&ms, &k("f laptop").hash, &pt);
    let given: Vec<RecordId> = m.for_peer(&ms, &x.hash).into_iter().map(Record::id).collect();
    std::eprintln!(
        "before {before}: x counts itself {}, x stop {:?}; member stop {:?} halted {} x in its devices {} proof_to has x {} standing {s:?}; for_peer gives r {} twin {}",
        xs.device_by_key(&x.hash).is_some(),
        xs.stop,
        ms.stop,
        ms.halted(),
        ms.device_by_key(&x.hash).is_some(),
        ms.proof_to.contains(&x.hash),
        given.contains(&r.id()),
        given.contains(&twin.id())
    );
    assert!(xs.device_by_key(&x.hash).is_some(), "x counts itself in on its side");
    assert!(
        given.contains(&r.id()) && given.contains(&twin.id()),
        "a member holding both heads hands x the pair: {s:?}"
    );
}

#[test]
fn sim1321_admitted_before_the_root_fork_gets_the_pair() {
    check_fork_after_admission(true);
}

#[test]
fn sim1321_admitted_past_one_root_head_gets_the_pair() {
    check_fork_after_admission(false);
}
