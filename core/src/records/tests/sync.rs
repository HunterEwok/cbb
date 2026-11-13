// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! Sync by parts: at the widest a set with its lists does not fit one
//! frame, so a sender splits it by count and by bytes, and a receiver that
//! takes the parts in order ends where one message of everything would.

use super::*;
use crate::records::sync::{self, HAVE_IDS, PART_BYTES, PART_RECORDS, Part};

/// A list of the most IDs a list holds: listed, then IDs nobody holds.
fn full_list(listed: &[RecordId], salt: u64) -> Vec<RecordId> {
    let mut ids = listed.to_vec();
    let mut i = 0u64;
    while ids.len() < LIST_MAX {
        let mut b = [0u8; 32];
        b[..8].copy_from_slice(&salt.to_be_bytes());
        b[8..16].copy_from_slice(&i.to_be_bytes());
        ids.push(RecordId(sha256(&b)));
        i += 1;
    }
    ids.truncate(LIST_MAX);
    ids
}

/// Takes the parts in order into an empty set of the group.
fn take_all(root: &Key, parts: &[Part<'_>]) -> RecordSet {
    let mut set = set_of(root);
    for p in parts {
        let recs: Vec<Record> = p.records.iter().map(|r| Record::decode(&r.envelope()).unwrap()).collect();
        set.take_part(&recs, &p.lists);
    }
    set
}

fn assert_fits(parts: &[Part<'_>], max_records: usize, max_bytes: usize) {
    for p in parts {
        assert!(p.records.len() <= max_records, "{} records in a part", p.records.len());
        assert!(p.bytes() <= max_bytes, "{} bytes in a part", p.bytes());
    }
}

/// The widest case: the recovery key changed the root 64 times, each with
/// a full list and a first checkpoint that keeps it, and the last root's
/// room and its 16 admins' rooms are full. It passes the count of one
/// `records` message; split by count, and by bytes at 2 MiB a part, the
/// parts each fit, and a receiver that takes them ends with the sender's
/// set.
#[test]
fn the_widest_set_syncs_in_parts_that_each_fit_a_frame() {
    let mut g = G::new();
    let root = k("root");
    g.device(&root, &k("laptop"), "laptop", |_| {});
    // The first root's room nearly full: its records ride in every list.
    for i in 0..LIST_MAX - 64 {
        g.device(&root, &k(&format!("r{i}")), "a device of the first root", |_| {});
    }
    let max = crate::records::body::MAX_RECOVERY;
    let mut last = root.clone();
    for i in 1..=max {
        let listed = g.listing();
        let next = k(&format!("n{i}"));
        g.change(&next, &full_list(&listed, i));
        last = next;
    }
    // The last root's 16 admins, each room full, and the root's own room.
    for a in 0..ADMIN_KEYS_MAX {
        let admin = k(&format!("admin {a}"));
        g.device(&last, &k(&format!("admin phone {a}")), "admin", |d| {
            d.admin = Some(admin.key.clone());
            d.powers = POWER_ADMIT;
        });
        for i in 0..MAX_ADMIN_RECORDS {
            g.device(&admin, &k(&format!("a{a} d{i}")), "a device of an admin", |_| {});
        }
    }
    for i in 0..MAX_ROOT_RECORDS {
        g.device(&last, &k(&format!("d{i}")), "a device of the last root", |_| {});
    }
    let sender = set_with(&g.root.key, &g.recs, &g.lists);
    let st = sender.state();
    let laptop = k("laptop").hash;
    assert!(st.device_by_key(&laptop).is_some());
    let parts = sender.parts_for_peer(&st, &laptop);
    assert_fits(&parts, PART_RECORDS, PART_BYTES);
    let total: usize = parts.iter().map(Part::bytes).sum();
    let listed: usize = sender.lists().map(<[u8]>::len).sum();
    std::eprintln!(
        "widest: {} records, set {} B, lists {listed} B, parts {}, total {total} B",
        sender.len(),
        sender.bytes(),
        parts.len()
    );
    // Split by count here (5953 records); by bytes, the same records twice
    // over with every list pass the frame, and each part still fits.
    assert!(parts.len() >= 2);
    let records = sender.for_peer(&st, &laptop);
    let lists = sender.lists_for_peer(&st, &laptop);
    let small = 2 << 20;
    let by_bytes = sync::split(&records, &lists, usize::MAX, small);
    assert!(by_bytes.len() >= 3);
    assert_fits(&by_bytes, usize::MAX, small);
    let receiver = take_all(&g.root.key, &by_bytes);
    assert_eq!(receiver.digest(), sender.digest());
    let lists: usize = parts.iter().map(|p| p.lists.len()).sum();
    assert_eq!(lists, sender.lists().count());
    let receiver = take_all(&g.root.key, &parts);
    assert_eq!(receiver.digest(), sender.digest());
    assert_eq!(receiver.state(), st);
    for h in sender.have() {
        assert!(h.len() <= HAVE_IDS);
        assert!(h.windows(2).all(|w| w[0] < w[1]));
    }
}

/// Small parts, many of them: a change of root's list rides with its head,
/// the records it keeps are taken once it is, and the receiver ends equal
/// whatever the cut between parts.
#[test]
fn any_cut_between_parts_ends_equal() {
    let mut g = changed_group();
    let nr = k("new root");
    for i in 0..30 {
        g.device(&nr, &k(&format!("t{i}")), "t", |_| {});
    }
    let list = g.listing();
    g.change(&k("third root"), &list);
    g.device(&k("third root"), &k("watch"), "watch", |_| {});
    let sender = set_with(&g.root.key, &g.recs, &g.lists);
    let st = sender.state();
    let peer = k("laptop").hash;
    let records = sender.for_peer(&st, &peer);
    let lists = sender.lists_for_peer(&st, &peer);
    assert_eq!(lists.len(), 2);
    for (n, bytes) in [(1, PART_BYTES), (3, PART_BYTES), (PART_RECORDS, 4096), (7, 20_000)] {
        let parts = sync::split(&records, &lists, n, bytes);
        assert!(parts.len() > 1);
        for p in &parts {
            for l in &p.lists {
                let h = crate::records::body::list_hash(l);
                assert!(p.records.iter().any(|r| matches!(&r.body().kind, Kind::Recovery { list, .. } if *list == h)));
            }
            // A change of root travels whole: its first records with it.
            let head = p.records.iter().find_map(|r| match &r.body().kind {
                Kind::Recovery { root, first, .. } => Some((root.hash(), *first)),
                _ => None,
            });
            if let Some((root, first)) = head
                && let Some(cp) = records.iter().find(|r| r.id() == first).map(|r| r.body().seq)
            {
                assert!(p.records.iter().any(|r| r.id() == first), "a head without its first checkpoint");
                let firsts = records.iter().filter(|r| r.body().signer == root && r.body().seq <= cp);
                for r in firsts {
                    assert!(p.records.iter().any(|x| x.id() == r.id()));
                }
            } else {
                assert!(p.records.len() <= n);
                assert!(p.records.len() == 1 || p.bytes() <= bytes);
            }
        }
        let receiver = take_all(&g.root.key, &parts);
        assert_eq!(receiver.digest(), sender.digest(), "cut by {n} records, {bytes} bytes");
        assert_eq!(receiver.state(), st);
    }
}

/// A list no record among the parts names goes after the records, by
/// the same bytes; nothing is dropped and no part is empty.
#[test]
fn a_list_no_head_names_goes_last() {
    let g = changed_group();
    let set = set_with(&g.root.key, &g.recs, &g.lists);
    let records: Vec<&Record> = set.in_dependency_order().into_iter().filter(|r| r.body().seq > 100).collect();
    assert!(records.is_empty());
    let lists: Vec<&[u8]> = set.lists().collect();
    let parts = sync::split(&records, &lists, PART_RECORDS, PART_BYTES);
    assert_eq!(parts.len(), 1);
    assert_eq!(parts[0].lists.len(), lists.len());
    assert!(sync::split(&[], &[], PART_RECORDS, PART_BYTES).is_empty());
    let ids: Vec<RecordId> = (0..HAVE_IDS as u64 * 2 + 1).map(|i| RecordId(sha256(&i.to_be_bytes()))).collect();
    let mut sorted = ids.clone();
    sorted.sort();
    let have = sync::have_parts(&sorted);
    assert_eq!(have.iter().map(Vec::len).collect::<Vec<_>>(), [HAVE_IDS, HAVE_IDS, 1]);
}
