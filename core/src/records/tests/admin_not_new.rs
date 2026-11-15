// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! After a change of root an admin key is always a new key: the new root's
//! first records remove every admin key that loses its rights (with those
//! an earlier change removed), the writer refuses to name one again, and a
//! spare the change carries stays an admin.

use super::*;
use crate::records::set::{ADMIN_KEY_NOT_NEW, Written};

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

fn admin_again(member: &K, admin: &K) -> Kind {
    let mut dev = Device::new(member.key.clone(), "admin again", ROLE_MEMBER);
    dev.rights = RIGHT_READ | RIGHT_SEND;
    dev.admin = Some(admin.key.clone());
    dev.powers = POWER_ADMIT | POWER_REMOVE | POWER_FREEZE;
    Kind::device(dev)
}

fn refused(err: crate::error::Error) {
    assert!(alloc::format!("{err}").contains(ADMIN_KEY_NOT_NEW), "{err}");
}

/// The change to new_root written on w, given to w: the records sent.
fn change(w: &mut RecordSet, new_root: &K, lists: &mut Vec<Vec<u8>>) -> Vec<Record> {
    let st = w.state();
    let name = alloc::format!("{} phone", new_root_name(new_root));
    let wr: Written = w
        .write_change(&st, &k("recovery"), crate::testkit::rk2(), new_root, phone(&k(&name)), &[], false, 1_000)
        .unwrap();
    let mut sent: Vec<Record> = wr.first.clone();
    sent.push(wr.record.clone());
    lists.push(wr.list.encode());
    feed(w, &sent, lists);
    assert_eq!(w.state().roots.last(), Some(&new_root.hash));
    sent
}

fn new_root_name(r: &K) -> &'static str {
    if r.hash == k("nk").hash { "nk" } else { "nk2" }
}

/// A group whose admin a admitted pre devices: its records, and a's.
fn group(pre: usize) -> (G, Vec<Record>) {
    let mut g = G::new();
    let root = k("root");
    g.device(&root, &k("old phone"), "old phone", |d| {
        d.role = ROLE_PHONE;
        d.holds_root = true;
    });
    g.admin(&k("phone a"), &k("admin a"), POWER_ADMIT | POWER_REMOVE | POWER_FREEZE);
    for i in 0..pre {
        g.device(&k("admin a"), &k(&format!("d{i}")), "d", |_| {});
    }
    let old_a = g.recs.iter().filter(|r| r.body().signer == k("admin a").hash).cloned().collect();
    (g, old_a)
}

/// The finding this rule closes (model ok33ST, at 30dcfafc): a's device
/// holds none of a's old records once it is no longer named, so its ack of
/// a new grant of the same key would be written at seq 1, prev none, the
/// seq of a's first old record. Where a sleeper still offers those, the
/// ack and what follows collide with them and do not count; without them
/// they count: the history, not the records, would decide. The change
/// removes the key, and the writer never names it again.
#[test]
fn the_new_root_does_not_name_an_old_admin_key_again() {
    for pre in [1, 100] {
        let (mut g, old_a) = group(pre);
        let mut w = set_with(&g.root.key, &g.recs, &g.lists);
        let sent = change(&mut w, &k("nk"), &mut g.lists);
        let st = w.state();
        assert!(st.revoked.contains(&k("admin a").hash), "the change removes the old admin key");
        assert!(st.device_by_key(&k("phone a").hash).is_some(), "its device stays, plain");
        refused(w.write_record(&st, &k("nk"), admin_again(&k("phone a"), &k("admin a")), 2_000).unwrap_err());
        // A new admin key for the same device is named.
        let st = w.state();
        w.write_record(&st, &k("nk"), admin_again(&k("phone a"), &k("admin a2")), 2_000).unwrap();
        // Hand-signed, the naming counts for nothing, nor does what the
        // old key signs on it, with the sleeper's old records or without.
        let mut h = G { root: g.root.clone(), gid: g.gid, heads: BTreeMap::new(), recs: Vec::new(), lists: Vec::new() };
        for r in w.in_dependency_order() {
            h.heads.insert(r.body().signer, (r.body().seq, r.id()));
        }
        let naming = h.rec(&k("nk"), admin_again(&k("phone a"), &k("admin a")));
        let (seq, id) = (naming.body().seq, naming.id());
        let ack = crate::testkit::sign_by(
            crate::records::body::Body {
                group: g.gid,
                signer: k("admin a").hash,
                seq: 1,
                prev: None,
                time_ms: 3_000,
                kind: Kind::Ack { seen: alloc::vec![Seen { key: k("nk").hash, seq, id }], spare: None },
                held: false,
            },
            &k("admin a"),
        );
        let mut all: Vec<Record> = g.recs.iter().chain(sent.iter()).cloned().collect();
        all.extend([naming.clone(), ack.clone()]);
        let mut without: Vec<Record> = all.iter().filter(|r| !old_a.contains(r)).cloned().collect();
        for recs in [&mut all, &mut without] {
            for order in 0..2 {
                if order == 1 {
                    recs.reverse();
                }
                let mut m = set_of(&g.root.key);
                feed(&mut m, recs, &g.lists);
                let s = m.state();
                assert!(s.revoked.contains(&k("admin a").hash));
                assert!(!s.devices.iter().any(|d| d.admin == Some(k("admin a").hash)), "the old key is no admin");
                assert!(!s.counting.contains(&ack.id()), "nothing the old key signs counts");
            }
        }
    }
}

/// A spare a's ack published is an admin under the new root, not removed;
/// a's own key is.
#[test]
fn the_spare_a_change_carries_stays_an_admin() {
    let (mut g, _) = group(1);
    let mut w = set_with(&g.root.key, &g.recs, &g.lists);
    let st = w.state();
    let r = w.write_ack_spare(&st, &k("admin a"), &k("spare a").key, 500).unwrap();
    g.push(r);
    let mut w = set_with(&g.root.key, &g.recs, &g.lists);
    change(&mut w, &k("nk"), &mut g.lists);
    let st = w.state();
    assert!(st.revoked.contains(&k("admin a").hash));
    assert!(!st.revoked.contains(&k("spare a").hash));
    assert!(st.devices.iter().any(|d| d.admin == Some(k("spare a").hash)), "the spare is the device's admin key");
    // The root may write the device again on its spare.
    w.write_record(&st, &k("nk"), admin_again(&k("phone a"), &k("spare a")), 2_000).unwrap();
}

/// Two changes in a row: the second root's first records remove the key
/// again, though the first root's records are cut.
#[test]
fn two_changes_keep_the_old_key_out() {
    let (mut g, _) = group(1);
    let mut w = set_with(&g.root.key, &g.recs, &g.lists);
    change(&mut w, &k("nk"), &mut g.lists);
    change(&mut w, &k("nk2"), &mut g.lists);
    let st = w.state();
    assert!(st.revoked.contains(&k("admin a").hash), "removed again by the second change");
    refused(w.write_record(&st, &k("nk2"), admin_again(&k("phone a"), &k("admin a")), 3_000).unwrap_err());
}

/// The removal of 16 admin keys fits the change.
#[test]
fn a_change_with_sixteen_admins_fits() {
    let mut g = G::new();
    let root = k("root");
    g.device(&root, &k("old phone"), "old phone", |d| {
        d.role = ROLE_PHONE;
        d.holds_root = true;
    });
    for i in 0..16 {
        g.admin(&k(&format!("phone {i}")), &k(&format!("admin {i}")), POWER_ADMIT | POWER_REMOVE);
    }
    let mut w = set_with(&g.root.key, &g.recs, &g.lists);
    let sent = change(&mut w, &k("nk"), &mut g.lists);
    let removed: Vec<KeyHash> = sent
        .iter()
        .filter_map(|r| match &r.body().kind {
            Kind::Revoke(rm) => Some(rm.keys.clone()),
            _ => None,
        })
        .flatten()
        .collect();
    assert_eq!(removed.len(), 16);
    let st = w.state();
    assert!((0..16).all(|i| st.revoked.contains(&k(&format!("admin {i}")).hash)));
    assert_eq!(st.devices.len(), 18, "every device is carried, with the new root's own");
    crate::testkit::closed(&w);
}
