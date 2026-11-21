// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The seen line (section 10, "Admin keys"): what an admin key signed
//! before it saw its own grant is void. A void record is held, links prev,
//! does not count, and is charged to its signer like any held record.

use super::*;
use crate::records::set::ADMIN_SILENCE_MS;

/// Admin key a signs n records before the root names it: void, each
/// charged to a's room only.
fn presigned(n: usize) -> (G, Vec<Record>) {
    let mut g = G::new();
    let (pa, a) = (k("phone a"), k("admin a"));
    g.device(&k("root"), &k("m"), "m", |_| {});
    let void: Vec<Record> = (0..n).map(|i| g.device(&a, &k(&alloc::format!("pre {i}")), "pre", |_| {})).collect();
    g.admin(&pa, &a, POWER_ADMIT);
    (g, void)
}

/// An admin room made only of void records leaves no room for the key's
/// first counting record, its acknowledgement: the writer refuses it with
/// the room's message, and the key has locked itself out. The silence
/// takes it back, as any silent key.
#[test]
fn a_room_full_of_void_records_locks_its_key_out_until_the_silence() {
    let _small = crate::records::keep::small::Small::new(64, 16, 4);
    let (g, void) = presigned(4);
    let (root, a) = (k("root"), k("admin a"));
    let mut set = set_with(&g.root.key, &g.recs, &g.lists);
    let st = set.state();
    assert!(st.device_by_key(&k("phone a").hash).is_some_and(|d| d.admin == Some(a.hash)));
    for r in &void {
        assert!(set.contains(&r.id()) && !st.counting.contains(&r.id()), "held, void");
    }
    assert_eq!(set.room_of(&a.hash).map(|r| r.used), Some(4), "charged to its signer");
    let err = set.write_ack(&st, &a, 0).unwrap_err();
    assert!(alloc::format!("{err}").contains("pass its room"), "{err}");
    let back = set.take_back_lagging(&st, &root, &BTreeMap::new(), ADMIN_SILENCE_MS).unwrap();
    assert_eq!(back.len(), 1, "the silence takes it back");
}

/// Void records never reach past their signer's ceiling, nor the root's
/// room or the set's: more of them than the key's room holds are kept out
/// as any record over a ceiling, and the root's room is as before.
#[test]
fn void_records_touch_no_room_but_their_signer_s() {
    let _small = crate::records::keep::small::Small::new(64, 16, 4);
    let (g, void) = presigned(9);
    let root = k("root");
    let a = k("admin a");
    let without: Vec<Record> = g.recs.iter().filter(|r| r.body().signer != a.hash).cloned().collect();
    let base = set_with(&g.root.key, &without, &g.lists);
    let set = set_with(&g.root.key, &g.recs, &g.lists);
    assert_eq!(
        set.room_of(&root.hash).map(|r| r.used),
        base.room_of(&root.hash).map(|r| r.used),
        "the root's room is as before"
    );
    let used = set.room_of(&a.hash).map(|r| r.used).unwrap_or(0);
    assert!(used <= 4, "within its own ceiling: {used}");
    assert!(void.iter().filter(|r| set.contains(&r.id())).count() <= 4);
    let total: u64 = [root.hash, a.hash].iter().filter_map(|h| set.room_of(h)).map(|r| r.used).sum();
    let base_total: u64 = base.room_of(&root.hash).map(|r| r.used).unwrap_or(0);
    assert_eq!(total, base_total + used);
}

/// The model's break in branch (b): the checkpoint names, as an admin
/// key's head, only its newest record that counts at the writer. A key
/// with only void records gets no head, and its void records stay void
/// before and after the checkpoint.
#[test]
fn a_checkpoint_never_heads_an_admin_key_at_a_void_record() {
    let (mut g, void) = presigned(2);
    let a = k("admin a");
    let recs = g.recs.clone();
    let cp = root_checkpoint(&mut g, &recs);
    let Kind::Checkpoint { heads, keep } = &cp.body().kind else { panic!() };
    assert!(heads.iter().all(|h| h.key != a.hash), "no head for a key with only void records");
    assert!(void.iter().all(|r| !keep.contains(&r.id())));
    let set = set_with(&g.root.key, &g.recs, &g.lists);
    let st = set.state();
    assert_eq!(st.checkpoint, Some(cp.id()));
    assert!(void.iter().all(|r| !st.counting.contains(&r.id())), "still void");
    assert!(!has_key(&st, "pre 0") && !has_key(&st, "pre 1"));
}

fn has_key(st: &State, name: &str) -> bool {
    st.device_by_key(&k(name).hash).is_some()
}
