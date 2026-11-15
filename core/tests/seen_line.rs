// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The seen line (GRANT_ABOVE), read from its rule only: an admin key's
//! record counts only if (a) it, or a record below it on the key's chain,
//! has a `seen` that holds the current root at a seq at or above the
//! oldest root record that names the key as admin, or (b) it is at or
//! above a record the counting checkpoint names for the key. A
//! record below that line is void: it links the chain, it does not count,
//! it is not charged, and it does not block the records above it. And the
//! root's removals signed before the grant wait for no acknowledgement of
//! the key. Cases that the code before the seen line does not meet are
//! marked to wait for it.

mod pieces;

use cbb_core::records::Kind;
use cbb_core::records::body::Removal;
use pieces::*;

/// The root R admits D, E, G and admin B on PB; then (seq s = 5) names
/// admin key A on PA.
/// Before that, A's device signed `pre` (records of A whose seen holds
/// only R's records below s). Returns the set, R, A's chain and the clock.
fn granted_after(pre: &[fn(&cbb_core::records::RecordSet) -> Kind]) -> (cbb_core::records::RecordSet, K, Chain, u64) {
    let r = k("seen root");
    let mut set = cbb_core::records::RecordSet::new(r.key.clone(), recovery());
    let mut t = 1_000;
    for (m, n) in [("D", "D"), ("E", "E"), ("G", "G")] {
        t += 1_000;
        let st = set.state();
        set.write_record(&st, &r, Kind::device(plain(&k(m), n)), t).unwrap();
    }
    // B, an admin A may freeze (it may not remove admins).
    let mut pb = admin_device(&k("PB"), "PB", &k("B"));
    pb.powers &= !cbb_core::records::body::POWER_REMOVE_ADMINS;
    t += 1_000;
    let st = set.state();
    set.write_record(&st, &r, Kind::device(pb), t).unwrap();
    let a = k("A");
    let mut chain = Chain::new();
    let mut early = Vec::new();
    for make in pre {
        t += 1_000;
        let kind = make(&set);
        early.push(chain.sign(&set, &a, kind, t));
    }
    t += 1_000;
    let st = set.state();
    set.write_record(&st, &r, Kind::device(admin_device(&k("PA"), "PA", &a)), t).unwrap();
    for e in early {
        let _ = set.insert(e);
    }
    (set, r, chain, t)
}

fn removal_of_d(set: &cbb_core::records::RecordSet) -> Kind {
    Kind::Revoke(removal(&[&k("D")], vec![head_of(set, &k("seen root").hash).unwrap()]))
}

fn freeze_of_b(set: &cbb_core::records::RecordSet) -> Kind {
    Kind::Freeze(removal(&[&k("B")], vec![head_of(set, &k("seen root").hash).unwrap()]))
}

fn admission_of_x(set: &cbb_core::records::RecordSet) -> Kind {
    let mut d = plain(&k("X"), "X");
    d.seen = vec![head_of(set, &k("seen root").hash).unwrap()];
    Kind::device(d)
}

/// A's acknowledgement of everything it holds of the root.
fn ack(set: &cbb_core::records::RecordSet, r: &K) -> Kind {
    Kind::Ack { seen: vec![head_of(set, &r.hash).unwrap()], spare: None }
}

/// Pre-signed records below the line (a removal, a freeze, an admission,
/// signed before the root named the key, their seen holding only the root
/// below the grant) count for nothing once the key is named and
/// acknowledges above: D stays, B is not frozen, X is not a device.
#[test]
#[ignore = "waits for the seen line"]
fn records_signed_before_the_grant_are_void() {
    let (mut set, r, mut chain, mut t) = granted_after(&[removal_of_d, freeze_of_b, admission_of_x]);
    t += 1_000;
    let a = k("A");
    let r_ack = chain.sign(&set, &a, ack(&set, &r), t);
    set.insert(r_ack.clone()).unwrap();
    let st = set.state();
    assert!(is_admin(&st, &a));
    assert!(st.counting.contains(&r_ack.id()), "the acknowledgement above the line counts");
    assert!(has(&st, &k("D")), "a removal signed before the grant is void");
    assert!(!frozen(&st, &k("PB")), "a freeze signed before the grant is void");
    assert!(!has(&st, &k("X")), "an admission signed before the grant is void");
    same_in_every_order(&set, "pre-signed");
}

/// The void records still link the chain: what A signs above its
/// acknowledgement counts (G removed), and the void ones do not count.
/// Void records are charged like any held record, to their signer's room
/// only (architecture 00:57Z): the root's room and B's are what they are
/// without them.
#[test]
#[ignore = "waits for the seen line"]
fn void_records_do_not_block_the_records_above() {
    let (mut set, r, mut chain, mut t) = granted_after(&[removal_of_d, freeze_of_b]);
    let a = k("A");
    let void: Vec<_> =
        set.in_dependency_order().into_iter().filter(|x| x.body().signer == a.hash).map(|x| x.id()).collect();
    assert_eq!(void.len(), 2);
    t += 1_000;
    let x = chain.sign(&set, &a, ack(&set, &r), t);
    set.insert(x).unwrap();
    t += 1_000;
    let rm = chain.sign(&set, &a, Kind::Revoke(removal(&[&k("G")], vec![head_of(&set, &r.hash).unwrap()])), t);
    set.insert(rm.clone()).unwrap();
    let st = set.state();
    assert!(st.counting.contains(&rm.id()), "the removal above the line counts");
    assert!(!has(&st, &k("G")));
    assert!(has(&st, &k("D")) && !frozen(&st, &k("PB")));
    for id in &void {
        assert!(!st.counting.contains(id), "a void record does not count");
    }
    let (twin, _, _, _) = granted_after(&[]);
    let room = |s: &cbb_core::records::RecordSet, key: &K| s.room_of(&key.hash).map(|x| x.used).unwrap_or(0);
    let (root_before, b_before) = (room(&twin, &r), room(&twin, &k("B")));
    assert_eq!(room(&set, &r), root_before, "the root's room carries none of A's void records");
    assert_eq!(room(&set, &k("B")), b_before, "nor does B's");
    assert!(room(&set, &a) >= 4, "A pays for its own records, the void ones too: {}", room(&set, &a));
    same_in_every_order(&set, "void below, counting above");
}

/// A record whose seen holds the root, but at a seq below the grant (an
/// older root record), is below the line even when signed after the grant.
#[test]
#[ignore = "waits for the seen line"]
fn a_seen_below_the_grant_is_below_the_line() {
    let (mut set, r, mut chain, mut t) = granted_after(&[]);
    let a = k("A");
    t += 1_000;
    let old = seen_at(&set, &r.hash, 2);
    let rm = chain.sign(&set, &a, Kind::Revoke(removal(&[&k("D")], vec![old])), t);
    set.insert(rm.clone()).unwrap();
    let st = set.state();
    assert!(!st.counting.contains(&rm.id()));
    assert!(has(&st, &k("D")));
}

/// The honest order: grant, an acknowledgement whose seen holds the grant,
/// then a removal: the removal counts. Also a removal whose own seen holds
/// the grant, with nothing below it.
#[test]
fn the_honest_order_counts() {
    for direct in [false, true] {
        let (mut set, r, mut chain, mut t) = granted_after(&[]);
        let a = k("A");
        if !direct {
            t += 1_000;
            let x = chain.sign(&set, &a, ack(&set, &r), t);
            set.insert(x).unwrap();
        }
        t += 1_000;
        let rm = chain.sign(&set, &a, removal_of_d(&set), t);
        set.insert(rm.clone()).unwrap();
        let st = set.state();
        assert!(st.counting.contains(&rm.id()), "direct={direct}");
        assert!(!has(&st, &k("D")), "direct={direct}");
        same_in_every_order(&set, "honest");
    }
}

/// The root updates PA's device later (a new name, still naming A): the
/// line does not move. A's records whose seen holds only the first grant,
/// and records above them, still count.
#[test]
fn a_root_update_of_the_device_does_not_move_the_line() {
    let (mut set, r, mut chain, mut t) = granted_after(&[]);
    let a = k("A");
    t += 1_000;
    let x = chain.sign(&set, &a, ack(&set, &r), t);
    set.insert(x.clone()).unwrap();
    for name in ["PA renamed", "PA again"] {
        t += 1_000;
        let st = set.state();
        set.write_record(&st, &r, Kind::device(admin_device(&k("PA"), name, &a)), t).unwrap();
    }
    // Seen still names only the grant, not the updates.
    let grant = seen_at(&set, &r.hash, 5);
    t += 1_000;
    let rm = chain.sign(&set, &a, Kind::Revoke(removal(&[&k("D")], vec![grant])), t);
    set.insert(rm.clone()).unwrap();
    let st = set.state();
    assert!(st.counting.contains(&x.id()) && st.counting.contains(&rm.id()));
    assert!(!has(&st, &k("D")));
    same_in_every_order(&set, "updates");
}

/// A checkpoint between the anchor and later records: what counted keeps
/// counting, at the root and at a member restored from what it saves; and
/// A's records above the checkpoint count (b).
#[test]
fn a_checkpoint_between_keeps_what_counted() {
    let (mut set, r, mut chain, mut t) = granted_after(&[]);
    let a = k("A");
    t += 1_000;
    let x = chain.sign(&set, &a, ack(&set, &r), t);
    set.insert(x.clone()).unwrap();
    t += 1_000;
    let st = set.state();
    set.write_record(&st, &r, Kind::device(admin_device(&k("PA"), "PA renamed", &a)), t).unwrap();
    t += 1_000;
    let st = set.state();
    let cp = set.write_checkpoint(&st, &r, t).unwrap();
    set.insert(cp).unwrap();
    t += 1_000;
    // No seen at all: above a record the checkpoint names for A.
    let rm = chain.sign(&set, &a, Kind::Revoke(Removal { keys: vec![k("E").hash], seen: vec![] }), t);
    set.insert(rm.clone()).unwrap();
    let st = set.state();
    assert!(st.counting.contains(&rm.id()), "above the checkpoint's head of A");
    assert!(!has(&st, &k("E")));
    let saved: Vec<_> = set.in_dependency_order().into_iter().cloned().collect();
    let lists: Vec<Vec<u8>> = set.lists().map(<[u8]>::to_vec).collect();
    let restored = cbb_core::records::RecordSet::restore(set.root().clone(), set.recovery().clone(), &saved, &lists);
    assert_eq!(view(&restored.state()), view(&st));
}

/// A's record names a root record the member does not hold yet: it waits,
/// it is not void for good, and it counts when that root record arrives.
/// (My reading: the line is judged on a root record the member holds, else
/// a made-up head would pass it; see the next case. Open question.)
#[test]
#[ignore = "waits for the seen line; open question: is the line judged on a held root record"]
fn a_seen_on_a_root_record_not_held_waits() {
    let (mut set, r, mut chain, mut t) = granted_after(&[]);
    let a = k("A");
    t += 1_000;
    let st = set.state();
    set.write_record(&st, &r, Kind::device(admin_device(&k("PA"), "PA renamed", &a)), t).unwrap();
    let update = head_of(&set, &r.hash).unwrap();
    t += 1_000;
    let rm = chain.sign(&set, &a, Kind::Revoke(removal(&[&k("D")], vec![update])), t);
    set.insert(rm.clone()).unwrap();
    let all: Vec<_> = set.in_dependency_order().into_iter().cloned().collect();
    let mut m = cbb_core::records::RecordSet::new(set.root().clone(), set.recovery().clone());
    let without: Vec<_> = all.iter().filter(|x| x.id() != update.id).cloned().collect();
    offer(&mut m, &[], &without);
    assert!(has(&m.state(), &k("D")), "waits for the root record it names");
    offer(&mut m, &[], &all);
    assert!(!has(&m.state(), &k("D")), "counts once it arrives");
    assert_eq!(view(&m.state()), view(&set.state()));
}

/// GRANT_ABOVE with acknowledgements: a removal the root signed before it
/// named A waits for no acknowledgement of A (A could sign nothing then);
/// a removal signed after the grant waits for A.
#[test]
#[ignore = "waits for the seen line (GRANT_ABOVE)"]
fn a_root_removal_before_the_grant_waits_for_no_ack_of_that_key() {
    let r = k("seen root");
    let mut set = cbb_core::records::RecordSet::new(r.key.clone(), recovery());
    let mut t = 1_000;
    for m in ["D", "E"] {
        t += 1_000;
        let st = set.state();
        set.write_record(&st, &r, Kind::device(plain(&k(m), m)), t).unwrap();
    }
    t += 1_000;
    let st = set.state();
    let before = set.write_removal(&st, &r, &[k("D").hash], t).unwrap();
    let before_id = before.last().unwrap().id();
    for x in before {
        let _ = set.insert(x);
    }
    t += 1_000;
    let st = set.state();
    set.write_record(&st, &r, Kind::device(admin_device(&k("PA"), "PA", &k("A"))), t).unwrap();
    t += 1_000;
    let st = set.state();
    let after = set.write_removal(&st, &r, &[k("E").hash], t).unwrap();
    let after_id = after.last().unwrap().id();
    for x in after {
        let _ = set.insert(x);
    }
    let st = set.state();
    let waiting: Vec<_> = set.removals_waiting(&st).into_iter().map(|w| w.removal).collect();
    assert!(!waiting.contains(&before_id), "signed before the grant: waits for nobody");
    assert!(waiting.contains(&after_id), "signed after the grant: waits for A");
    t += 1_000;
    let cp = set.write_checkpoint(&st, &r, t).unwrap();
    let Kind::Checkpoint { keep, .. } = &cp.body().kind else { panic!() };
    assert!(!keep.contains(&before_id), "the early removal settles");
}

/// A deviant device pre-signs with a seen that claims a root head far
/// above the grant (seq 999, an ID no root record has). If the line were
/// judged on the seq alone, this would pass it; it must not count, at a
/// member holding every real root record.
#[test]
#[ignore = "waits for the seen line; open question: is the line judged on a held root record"]
fn a_made_up_root_head_does_not_lift_a_record_above_the_line() {
    let made_up = |_: &cbb_core::records::RecordSet| {
        let fake = cbb_core::records::body::Seen {
            key: k("seen root").hash,
            seq: 999,
            id: cbb_core::records::RecordId::from_slice(&[7u8; 32]).unwrap(),
        };
        Kind::Revoke(removal(&[&k("D")], vec![fake]))
    };
    let (set, _, _, _) = granted_after(&[made_up]);
    let st = set.state();
    assert!(has(&st, &k("D")), "a pre-signed removal with a made-up root head is void");
}

/// posBranchBBreakTest's shape (model, PR #552): X pre-signs v1 and v2
/// before its grant (void by (a)), then acknowledges above the grant and
/// signs r3. The honest checkpoint heads X at a record that counts at the
/// writer, never at v1 or v2, so (b) never lifts them: they stay void
/// before and after the checkpoint, at every member, and r3 counts.
#[test]
#[ignore = "waits for the seen line"]
fn a_checkpoint_never_heads_an_admin_at_a_void_record() {
    let (mut set, r, mut chain, mut t) = granted_after(&[removal_of_d, freeze_of_b]);
    let x = k("A");
    let void: Vec<_> =
        set.in_dependency_order().into_iter().filter(|y| y.body().signer == x.hash).map(|y| y.id()).collect();
    t += 1_000;
    let a = chain.sign(&set, &x, ack(&set, &r), t);
    set.insert(a).unwrap();
    t += 1_000;
    let r3 = chain.sign(&set, &x, Kind::Revoke(removal(&[&k("G")], vec![head_of(&set, &r.hash).unwrap()])), t);
    set.insert(r3.clone()).unwrap();
    let st = set.state();
    t += 1_000;
    let cp = set.write_checkpoint(&st, &r, t).unwrap();
    let Kind::Checkpoint { heads, .. } = &cp.body().kind else { panic!() };
    if let Some(h) = heads.iter().find(|h| h.key == x.hash) {
        assert!(!void.contains(&h.id), "the checkpoint heads X at a void record");
        assert!(h.seq >= 3, "X's head is a record that counts: seq {}", h.seq);
    }
    set.insert(cp).unwrap();
    let st = set.state();
    for id in &void {
        assert!(!st.counting.contains(id), "void after the checkpoint too");
    }
    assert!(st.counting.contains(&r3.id()));
    assert!(has(&st, &k("D")) && !frozen(&st, &k("PB")) && !has(&st, &k("G")));
    same_in_every_order(&set, "posBranchBBreak");
}

/// The root record an admin's seen named was later pruned by the root's
/// checkpoint (a settled removal): the admin's later records still count,
/// through (b), the checkpoint's head for that key; also at a member
/// restored from what the root saves.
#[test]
fn a_seen_on_a_pruned_root_record_still_counts_through_the_checkpoint() {
    let (mut set, r, mut chain, mut t) = granted_after(&[]);
    let a = k("A");
    let st = set.state();
    t += 1_000;
    for x in set.write_removal(&st, &r, &[k("D").hash], t).unwrap() {
        set.insert(x).unwrap();
    }
    let named = head_of(&set, &r.hash).unwrap();
    t += 1_000;
    let x = chain.sign(&set, &a, ack(&set, &r), t);
    set.insert(x).unwrap();
    for _ in 0..2 {
        let st = set.state();
        t += 1_000;
        let cp = set.write_checkpoint(&st, &r, t).unwrap();
        set.insert(cp).unwrap();
    }
    println!("the removal named by A's seen is held after the checkpoints: {}", set.contains(&named.id));
    t += 1_000;
    let rm = chain.sign(&set, &a, Kind::Revoke(removal(&[&k("E")], vec![named])), t);
    set.insert(rm.clone()).unwrap();
    let st = set.state();
    assert!(st.counting.contains(&rm.id()), "through the checkpoint's head of A");
    assert!(!has(&st, &k("E")));
    let saved: Vec<_> = set.in_dependency_order().into_iter().cloned().collect();
    let restored = cbb_core::records::RecordSet::restore(set.root().clone(), set.recovery().clone(), &saved, &[]);
    assert_eq!(view(&restored.state()), view(&st));
}

/// An admin key whose room is filled with its own void records (signed
/// after the grant, their seen below it) locks itself out: its first
/// acknowledgement finds no room (decided, no rule for it: only a deviant
/// device pre-signs). The root's removal waits for it; the person takes A
/// back, the other admin acknowledges, and the next checkpoint settles
/// the removal. None of the void removals ever counts.
#[test]
#[ignore = "waits for the seen line"]
fn an_admin_that_fills_its_room_with_void_records_is_taken_back_by_the_person() {
    let (mut set, r, mut chain, mut t) = granted_after(&[]);
    let a = k("A");
    let below = seen_at(&set, &r.hash, 2);
    for i in 0..400u32 {
        t += 10;
        let x = chain.sign(&set, &a, Kind::Revoke(removal(&[&k("D")], vec![below])), t + u64::from(i));
        let _ = set.insert(x);
    }
    assert!(has(&set.state(), &k("D")), "none of the void removals counts");
    let st = set.state();
    t += 10_000;
    let rm = set.write_removal(&st, &r, &[k("E").hash], t).unwrap();
    let rm_id = rm.last().unwrap().id();
    for x in rm {
        set.insert(x).unwrap();
    }
    t += 1_000;
    let x = chain.sign(&set, &a, ack(&set, &r), t);
    let id = x.id();
    assert_eq!(set.insert(x), Ok(cbb_core::records::set::Added::NoRoom), "the first ack finds no room");
    assert!(!set.state().counting.contains(&id));
    t += 1_000;
    let b_ack = chain.sign(&set, &k("B"), ack(&set, &r), t);
    set.insert(b_ack).unwrap();
    let st = set.state();
    assert!(set.removals_waiting(&st).iter().any(|w| w.removal == rm_id && w.waits_for == vec![a.hash]));
    t += 1_000;
    set.take_back(&st, &r, &a.hash, t).unwrap();
    let st = set.state();
    t += 1_000;
    let cp = set.write_checkpoint(&st, &r, t).unwrap();
    let Kind::Checkpoint { keep, .. } = &cp.body().kind else { panic!() };
    assert!(!keep.contains(&rm_id), "settled once A is taken back and B acknowledged");
    set.insert(cp).unwrap();
    let st = set.state();
    assert!(!has(&st, &k("E")) && has(&st, &k("D")));
}
