// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! An independent reading of the record set's rooms at real sizes: a root
//! whose own checkpoints never count (each keeps IDs nobody holds) and fill
//! its room, then makes devices, then writes an honest checkpoint. The
//! honest checkpoint should be written and should count, so that the
//! devices count again.

use std::collections::BTreeMap;

use cbb_core::identity::ExternalKey;
use cbb_core::records::body::{Device, Head, MIN_INCOMING_MS, RIGHT_READ, RIGHT_SEND, ROLE_MEMBER, ROLE_PHONE};
use cbb_core::records::key::group_id;
use cbb_core::records::{Body, Key, KeyHash, Kind, Record, RecordId, RecordSet};
use p256::ecdsa::SigningKey;
use p256::ecdsa::signature::hazmat::PrehashSigner as _;

struct K {
    sk: SigningKey,
    key: Key,
    hash: KeyHash,
}

impl ExternalKey for K {
    fn public(&self) -> Vec<u8> {
        self.key.public().to_vec()
    }
    fn sign_digest(&self, digest: &[u8; 32]) -> cbb_core::error::Result<Vec<u8>> {
        let sig: p256::ecdsa::Signature = self.sk.sign_prehash(digest).unwrap();
        Ok(sig.to_der().as_bytes().to_vec())
    }
}

fn k(name: &str) -> K {
    let sk = SigningKey::from_slice(&cbb_core::certs::sha256(name.as_bytes())).unwrap();
    let key = Key::es256(sk.verifying_key().to_sec1_point(false).as_bytes().to_vec());
    let hash = key.hash();
    K { sk, key, hash }
}

struct G {
    gid: cbb_core::records::GroupId,
    heads: BTreeMap<KeyHash, (u64, RecordId)>,
    t: u64,
}

impl G {
    fn sign(&mut self, by: &K, kind: Kind) -> Record {
        let (seq, prev) = self.heads.get(&by.hash).map_or((1, None), |(s, id)| (s + 1, Some(*id)));
        self.t += 1000;
        let body = Body { group: self.gid, signer: by.hash, seq, prev, time_ms: self.t, kind, held: false };
        let r = Record::sign(body, by).unwrap();
        self.heads.insert(by.hash, (seq, r.id()));
        r
    }
}

/// A root with `n` checkpoints of `ids` IDs nobody holds, then 100 devices;
/// returns the set, the root and the device records.
fn root_with_dead_checkpoints(n: usize, ids: usize) -> (RecordSet, K, G) {
    let root = k("root");
    let admin = k("admin a");
    let phone = k("phone a");
    let recovery = cbb_core::records::Recovery {
        k1: k("recovery").key,
        k2: cbb_core::records::pq::PqKey::from_seeds(&[0x31; 16], &[0x32; 16], &[0x33; 16]).key(),
    };
    let mut g = G { gid: group_id(&root.key, &recovery), heads: BTreeMap::new(), t: 0 };
    let mut set = RecordSet::new(root.key.clone(), recovery);
    let mut d = Device::new(phone.key.clone(), "admin", ROLE_PHONE);
    d.rights = RIGHT_READ | RIGHT_SEND;
    d.admin = Some(admin.key.clone());
    d.powers = 0x1ff & !64;
    let r = g.sign(&root, Kind::device(d));
    set.insert(r).unwrap();
    let r = g.sign(&root, Kind::Copies { incoming_ms: MIN_INCOMING_MS, seen: vec![] });
    set.insert(r).unwrap();
    for c in 0..n {
        let (seq, id) = g.heads[&root.hash];
        let keep: Vec<RecordId> = {
            let mut v: Vec<RecordId> = (0..ids)
                .map(|i| {
                    RecordId(cbb_core::certs::sha256(
                        &[&(c as u32).to_le_bytes()[..], &(i as u32).to_le_bytes()[..]].concat(),
                    ))
                })
                .collect();
            v.sort();
            v
        };
        let r = g.sign(&root, Kind::Checkpoint { heads: vec![Head { key: root.hash, seq, id }], keep });
        let _ = set.insert(r);
    }
    for i in 0..100u32 {
        let dk = k(&format!("bench dev {i}"));
        let r = g.sign(&root, Kind::device(Device::new(dk.key.clone(), "dev", ROLE_MEMBER)));
        let _ = set.insert(r);
    }
    (set, root, g)
}

/// After its own checkpoints that never count, the current root can still
/// write an honest checkpoint, and it counts.
#[test]
#[ignore = "fails at 7d9fa7f1: write_checkpoint keeps the root's own dead checkpoints and refuses for room"]
fn an_honest_checkpoint_after_dead_ones_is_written_and_counts() {
    for n in [9, 10, 16] {
        let (mut set, root, _) = root_with_dead_checkpoints(n, 2385);
        let st = set.state();
        let cp = set.write_checkpoint(&st, &root, 10_000_000).unwrap_or_else(|e| panic!("n={n}: {e:?}"));
        set.insert(cp.clone()).unwrap();
        let st = set.state();
        assert_eq!(st.checkpoint, Some(cp.id()), "n={n}");
        assert!(st.devices.len() > 100, "n={n}: devices {}", st.devices.len());
    }
}

/// What the honest checkpoint would name: how many of the root's own
/// earlier checkpoints, and their bytes. Printed, for the reading.
#[test]
#[ignore = "information for the reading; run with --ignored --nocapture"]
fn what_the_honest_checkpoint_names() {
    for n in [9, 10, 16] {
        let (set, root, _) = root_with_dead_checkpoints(n, 2385);
        let st = set.state();
        println!(
            "n={n}: devices {}, checkpoint counts {}, aside {}, write_checkpoint: {:?}",
            st.devices.len(),
            st.checkpoint.is_some(),
            set.aside().count(),
            set.write_checkpoint(&st, &root, 10_000_000).map(|c| c.body().encode().len())
        );
    }
}

/// What a restarted member has: its records saved by `marked()` and its
/// lists, restored.
fn restarted(set: &RecordSet) -> RecordSet {
    let records: Vec<Record> = set.marked(&[7; 32]).into_iter().map(|(r, _)| r.clone()).collect();
    let lists: Vec<Vec<u8>> = set.lists().map(<[u8]>::to_vec).collect();
    RecordSet::restore(set.root().clone(), set.recovery().clone(), &records, &lists)
}

/// Where a restarted set differs from the live one: state, digest or the
/// records kept aside.
fn differs(live: &RecordSet) -> Option<String> {
    let back = restarted(live);
    let mut out = Vec::new();
    if live.state() != back.state() {
        let (a, b) = (live.state(), back.state());
        out.push(format!(
            "state (devices {} vs {}, checkpoint {:?} vs {:?}, stop {:?} vs {:?}, counting {} vs {})",
            a.devices.len(),
            b.devices.len(),
            a.checkpoint.is_some(),
            b.checkpoint.is_some(),
            a.stop,
            b.stop,
            a.counting.len(),
            b.counting.len()
        ));
    }
    if live.digest() != back.digest() {
        out.push(format!("digest ({} vs {} records)", live.len(), back.len()));
    }
    let aside = |s: &RecordSet| s.aside().copied().collect::<std::collections::BTreeSet<RecordId>>();
    if aside(live) != aside(&back) {
        out.push(format!("aside ({} vs {})", aside(live).len(), aside(&back).len()));
    }
    (!out.is_empty()).then(|| out.join(", "))
}

/// Steps through one scenario, checking a restart after each.
/// One step of a scenario: its name and what it gives the member.
type Step = (String, Box<dyn Fn(&mut RecordSet)>);

struct Run {
    steps: usize,
    found: Vec<String>,
}

impl Run {
    fn check(&mut self, scenario: &str, step: &str, live: &RecordSet) {
        self.steps += 1;
        if let Some(d) = differs(live) {
            self.found.push(format!("{scenario}, after {step}: {d}"));
        }
    }
}

fn sign_at(g: &G, by: &K, seq: u64, prev: Option<RecordId>, kind: Kind, time_ms: u64) -> Record {
    Record::sign(Body { group: g.gid, signer: by.hash, seq, prev, time_ms, kind, held: false }, by).unwrap()
}

/// After every insert of the scenarios this file can build through the
/// public API, a set restored from `marked()` and `lists()` is the live
/// set: the same state, digest and records aside. The scenarios: a root
/// with an admin, devices, removals and honest checkpoints; a root whose
/// own checkpoints never count; a root's twin at a seq an honest
/// checkpoint pruned (given to the live set and to one restarted before
/// it came) in four shapes, one of them in two orders (they differ
/// before sync and are equal and halted after); a change of root in two
/// orders; admin keys made and unmade until the set is near its bytes.
/// It covers 692 steps (116 with READ_RECORDS_QUICK, which skips the
/// last scenario).
#[test]
#[ignore = "slow (a restore per step); run with --ignored --release"]
fn a_restored_set_is_the_live_set_after_every_insert() {
    let mut run = Run { steps: 0, found: Vec::new() };

    // 1. Admin, devices, removals, honest checkpoints.
    {
        let (mut set, root, mut g) = root_with_dead_checkpoints(0, 0);
        run.check("plain", "the admin and copies", &set);
        let mut devs = Vec::new();
        for i in 0..40u32 {
            let dk = k(&format!("plain dev {i}"));
            devs.push(dk.hash);
            let r = g.sign(&root, Kind::device(Device::new(dk.key.clone(), "dev", ROLE_MEMBER)));
            let _ = set.insert(r);
            run.check("plain", &format!("device {i}"), &set);
            if i % 10 == 9 {
                let gone = devs[i as usize - 5];
                let r = g
                    .sign(&root, Kind::Revoke(cbb_core::records::body::Removal { keys: vec![gone], seen: Vec::new() }));
                let _ = set.insert(r);
                run.check("plain", &format!("removal after device {i}"), &set);
                let st = set.state();
                if let Ok(cp) = set.write_checkpoint(&st, &root, g.t + 1) {
                    g.heads.insert(root.hash, (cp.body().seq, cp.id()));
                    g.t += 1000;
                    let _ = set.insert(cp);
                    run.check("plain", &format!("checkpoint after device {i}"), &set);
                } else {
                    run.found.push(format!("plain: no honest checkpoint after device {i}"));
                }
            }
        }
    }

    // 2. A root whose own checkpoints never count, then devices.
    {
        let (set, _, _) = root_with_dead_checkpoints(10, 2385);
        run.check("dead checkpoints", "setup", &set);
    }
    {
        let root = k("root");
        let recovery = cbb_core::records::Recovery {
            k1: k("recovery").key,
            k2: cbb_core::records::pq::PqKey::from_seeds(&[0x31; 16], &[0x32; 16], &[0x33; 16]).key(),
        };
        let mut g = G { gid: group_id(&root.key, &recovery), heads: BTreeMap::new(), t: 0 };
        let mut set = RecordSet::new(root.key.clone(), recovery);
        let r = g.sign(&root, Kind::Copies { incoming_ms: MIN_INCOMING_MS, seen: vec![] });
        set.insert(r).unwrap();
        for c in 0..10usize {
            let (seq, id) = g.heads[&root.hash];
            let mut keep: Vec<RecordId> = (0..2385u32)
                .map(|i| {
                    RecordId(cbb_core::certs::sha256(&[&(c as u32).to_le_bytes()[..], &i.to_le_bytes()[..]].concat()))
                })
                .collect();
            keep.sort();
            let r = g.sign(&root, Kind::Checkpoint { heads: vec![Head { key: root.hash, seq, id }], keep });
            let _ = set.insert(r);
            run.check("dead checkpoints", &format!("checkpoint {c}"), &set);
        }
        for i in 0..20u32 {
            let dk = k(&format!("dead dev {i}"));
            let r = g.sign(&root, Kind::device(Device::new(dk.key.clone(), "dev", ROLE_MEMBER)));
            let _ = set.insert(r);
            run.check("dead checkpoints", &format!("device {i}"), &set);
        }
    }

    // 3. A root's twin at a seq an honest checkpoint already pruned: the
    // live set may still make the pair from what it remembers.
    {
        let (mut set, root, mut g) = root_with_dead_checkpoints(0, 0);
        let mut at3: Option<(u64, Option<RecordId>)> = None;
        for i in 0..6u32 {
            let before = g.heads.get(&root.hash).copied();
            let dk = k(&format!("twin dev {i}"));
            let r = g.sign(&root, Kind::device(Device::new(dk.key.clone(), "dev", ROLE_MEMBER)));
            if i == 0 {
                at3 = Some((r.body().seq, before.map(|(_, id)| id)));
            }
            let _ = set.insert(r);
            run.check("twin", &format!("device {i}"), &set);
        }
        let r = g.sign(
            &root,
            Kind::Revoke(cbb_core::records::body::Removal { keys: vec![k("twin dev 0").hash], seen: Vec::new() }),
        );
        let _ = set.insert(r);
        run.check("twin", "removal of device 0", &set);
        let st = set.state();
        match set.write_checkpoint(&st, &root, g.t + 1) {
            Ok(cp) => {
                g.heads.insert(root.hash, (cp.body().seq, cp.id()));
                let _ = set.insert(cp);
                run.check("twin", "checkpoint", &set);
            }
            Err(e) => run.found.push(format!("twin: no honest checkpoint: {e:?}")),
        }
        let (seq, prev) = at3.unwrap();
        let other = k("twin other");
        let twin = sign_at(&g, &root, seq, prev, Kind::device(Device::new(other.key.clone(), "other", ROLE_MEMBER)), 1);
        // A member restarted before the twin comes, and given it later.
        let mut back = restarted(&set);
        let _ = back.insert(twin.clone());
        let _ = set.insert(twin);
        run.steps += 1;
        if back.state() != set.state() || back.digest() != set.digest() {
            run.found.push(format!(
                "twin, restarted before the twin came: stop {:?} live vs {:?} restarted",
                set.state().stop,
                back.state().stop
            ));
        }
        run.check("twin", "the twin of device 0's pruned admission", &set);
    }

    // 4. A root's twin of a record below every head a held checkpoint
    // names, in three shapes: of a pruned removal, of a kept admission,
    // and of a record whose prev the checkpoint pruned. Each given to the
    // live set, which settled the original, and to a member restarted
    // before the twin came.
    for shape in ["pruned removal", "kept admission", "prev pruned"] {
        let (mut set, root, mut g) = root_with_dead_checkpoints(0, 0);
        let mut at: BTreeMap<&str, (u64, Option<RecordId>)> = BTreeMap::new();
        for i in 0..4u32 {
            let before = g.heads.get(&root.hash).map(|(_, id)| *id);
            let dk = k(&format!("narrow dev {i}"));
            let r = g.sign(&root, Kind::device(Device::new(dk.key.clone(), "dev", ROLE_MEMBER)));
            if i == 2 {
                at.insert("kept admission", (r.body().seq, before));
            }
            let _ = set.insert(r);
        }
        let before = g.heads.get(&root.hash).map(|(_, id)| *id);
        let rm = g.sign(
            &root,
            Kind::Revoke(cbb_core::records::body::Removal { keys: vec![k("narrow dev 0").hash], seen: Vec::new() }),
        );
        at.insert("pruned removal", (rm.body().seq, before));
        let rm_id = rm.id();
        let _ = set.insert(rm);
        let r = g.sign(&root, Kind::Copies { incoming_ms: MIN_INCOMING_MS + 1, seen: vec![] });
        at.insert("prev pruned", (r.body().seq, Some(rm_id)));
        let _ = set.insert(r);
        for i in 4..6u32 {
            let dk = k(&format!("narrow dev {i}"));
            let r = g.sign(&root, Kind::device(Device::new(dk.key.clone(), "dev", ROLE_MEMBER)));
            let _ = set.insert(r);
        }
        let st = set.state();
        match set.write_checkpoint(&st, &root, g.t + 1) {
            Ok(cp) => {
                g.heads.insert(root.hash, (cp.body().seq, cp.id()));
                let _ = set.insert(cp);
            }
            Err(e) => {
                run.found.push(format!("narrow twin ({shape}): no honest checkpoint: {e:?}"));
                continue;
            }
        }
        run.check("narrow twin", &format!("{shape}: checkpoint"), &set);
        let held_original = set.contains(&rm_id);
        let (seq, prev) = at[shape];
        let other = k(&format!("narrow other {shape}"));
        let twin = sign_at(&g, &root, seq, prev, Kind::device(Device::new(other.key.clone(), "other", ROLE_MEMBER)), 2);
        let mut back = restarted(&set);
        let got_back = back.insert(twin.clone()).map(|a| format!("{a:?}"));
        let got = set.insert(twin).map(|a| format!("{a:?}"));
        run.steps += 1;
        println!(
            "narrow twin ({shape}): removal held {held_original}; live {got:?} stop {:?}; restarted {got_back:?} stop {:?}",
            set.state().stop,
            back.state().stop
        );
        if back.state() != set.state() || back.digest() != set.digest() {
            run.found.push(format!(
                "step {}: narrow twin ({shape}), restarted before the twin came: stop {:?} live vs {:?} restarted",
                run.steps,
                set.state().stop,
                back.state().stop
            ));
        }
        run.check("narrow twin", &format!("{shape}: after the twin"), &set);
    }

    // 4b. The same records in two orders: A takes the root's records, the
    // checkpoint, then the twin of the pruned removal; B takes the twin
    // before the checkpoint. Then each gives the other all it holds.
    {
        let (mut a, root, mut g) = root_with_dead_checkpoints(0, 0);
        let mut b = a.clone();
        let mut recs: Vec<Record> = Vec::new();
        for i in 0..4u32 {
            let dk = k(&format!("order dev {i}"));
            recs.push(g.sign(&root, Kind::device(Device::new(dk.key.clone(), "dev", ROLE_MEMBER))));
        }
        let before = g.heads.get(&root.hash).map(|(_, id)| *id);
        let rm = g.sign(
            &root,
            Kind::Revoke(cbb_core::records::body::Removal { keys: vec![k("order dev 0").hash], seen: Vec::new() }),
        );
        let (rm_seq, rm_prev) = (rm.body().seq, before);
        recs.push(rm);
        recs.push(g.sign(&root, Kind::Copies { incoming_ms: MIN_INCOMING_MS + 1, seen: vec![] }));
        for i in 4..6u32 {
            let dk = k(&format!("order dev {i}"));
            recs.push(g.sign(&root, Kind::device(Device::new(dk.key.clone(), "dev", ROLE_MEMBER))));
        }
        for r in &recs {
            let _ = a.insert(r.clone());
            let _ = b.insert(r.clone());
        }
        let st = a.state();
        let cp = a.write_checkpoint(&st, &root, g.t + 1).expect("honest checkpoint");
        let other = k("order other");
        let twin =
            sign_at(&g, &root, rm_seq, rm_prev, Kind::device(Device::new(other.key.clone(), "other", ROLE_MEMBER)), 2);
        let a1 = a.insert(cp.clone()).map(|x| format!("{x:?}"));
        let a2 = a.insert(twin.clone()).map(|x| format!("{x:?}"));
        let b1 = b.insert(twin.clone()).map(|x| format!("{x:?}"));
        let b2 = b.insert(cp.clone()).map(|x| format!("{x:?}"));
        let show = |s: &RecordSet| {
            let st = s.state();
            format!(
                "stop {:?}, checkpoint {}, devices {}, counting {}, records {}, digest {:02x?}",
                st.stop,
                st.checkpoint.is_some(),
                st.devices.len(),
                st.counting.len(),
                s.len(),
                &s.digest()[..4]
            )
        };
        println!("order A (checkpoint, then twin): {a1:?}, {a2:?}; {}", show(&a));
        println!("order B (twin, then checkpoint): {b1:?}, {b2:?}; {}", show(&b));
        // What holds: a twin below A's counting checkpoint counts for no
        // one there, so before they sync A and B differ (B halted, A not).
        run.steps += 1;
        if a.state() == b.state() || b.state().stop != cbb_core::records::eval::Stop::Full {
            run.found.push(format!(
                "step {}: the same records in two orders, before sync: expected A not halted and B halted; A {} / B {}",
                run.steps,
                show(&a),
                show(&b)
            ));
        }
        // Sync both ways: each gives the other every record it holds.
        let from_b: Vec<Record> = b.in_dependency_order().into_iter().cloned().collect();
        let from_a: Vec<Record> = a.in_dependency_order().into_iter().cloned().collect();
        a.insert_all(from_b);
        b.insert_all(from_a);
        println!("after sync both ways: A {}; B {}", show(&a), show(&b));
        run.steps += 1;
        // After they sync both ways they are equal, and halted for good.
        if a.state() != b.state() || a.digest() != b.digest() || a.state().stop != cbb_core::records::eval::Stop::Full {
            run.found.push(format!("step {}: after sync both ways: A {} / B {}", run.steps, show(&a), show(&b)));
        }
    }

    // 6. A change of root by the recovery key (ES256 and SLH-DSA), taken
    // by a member in two orders with a restart checked after each step:
    // head, list, first records; and first records, head, list. Then the
    // new root admits a device.
    {
        let (mut set, root, mut g) = root_with_dead_checkpoints(0, 0);
        for i in 0..8u32 {
            let dk = k(&format!("change dev {i}"));
            let r = g.sign(&root, Kind::device(Device::new(dk.key.clone(), "dev", ROLE_MEMBER)));
            let _ = set.insert(r);
        }
        let r = g.sign(
            &root,
            Kind::Revoke(cbb_core::records::body::Removal { keys: vec![k("change dev 1").hash], seen: Vec::new() }),
        );
        let _ = set.insert(r);
        let st = set.state();
        if let Ok(cp) = set.write_checkpoint(&st, &root, g.t + 1) {
            g.heads.insert(root.hash, (cp.body().seq, cp.id()));
            let _ = set.insert(cp);
        }
        let member = set.clone();
        let rk = k("recovery");
        let rk2 = cbb_core::records::pq::PqKey::from_seeds(&[0x31; 16], &[0x32; 16], &[0x33; 16]);
        let new_root = k("change new root");
        let phone = k("change new phone");
        let st = set.state();
        let mut writer = set.clone();
        match writer.write_change(
            &st,
            &rk,
            &rk2,
            &new_root,
            Device::new(phone.key.clone(), "phone", ROLE_PHONE),
            &[],
            false,
            g.t + 1,
        ) {
            Err(e) => run.found.push(format!("change: write_change refused: {e:?}")),
            Ok(w) => {
                let list = w.list.encode();
                for order in ["head, list, first", "first, head, list, first again"] {
                    let mut m = member.clone();
                    let mut steps: Vec<Step> = Vec::new();
                    let head = w.record.clone();
                    let l = list.clone();
                    let firsts = w.first.clone();
                    let head_step: Step = (
                        "the head".into(),
                        Box::new(move |m: &mut RecordSet| {
                            let _ = m.insert(head.clone());
                        }),
                    );
                    let list_step: Step = (
                        "the list".into(),
                        Box::new(move |m: &mut RecordSet| {
                            let _ = m.insert_list(&l);
                        }),
                    );
                    let first_steps: Vec<Step> = firsts
                        .into_iter()
                        .enumerate()
                        .map(|(i, r)| {
                            let s: Step = (
                                format!("first record {i}"),
                                Box::new(move |m: &mut RecordSet| {
                                    let _ = m.insert(r.clone());
                                }),
                            );
                            s
                        })
                        .collect();
                    if order == "head, list, first" {
                        steps.push(head_step);
                        steps.push(list_step);
                        steps.extend(first_steps);
                    } else {
                        // The first records before their head are refused
                        // (no known signer); sync offers them again after.
                        let again: Vec<Step> = w
                            .first
                            .iter()
                            .cloned()
                            .enumerate()
                            .map(|(i, r)| {
                                let s: Step = (
                                    format!("first record {i} offered again"),
                                    Box::new(move |m: &mut RecordSet| {
                                        let _ = m.insert(r.clone());
                                    }),
                                );
                                s
                            })
                            .collect();
                        steps.extend(first_steps);
                        steps.push(head_step);
                        steps.push(list_step);
                        steps.extend(again);
                    }
                    for (name, f) in &steps {
                        f(&mut m);
                        run.check(&format!("change ({order})"), name, &m);
                    }
                    let st = m.state();
                    println!(
                        "change ({order}): roots {}, stop {:?}, devices {}, waiting {}",
                        st.roots.len(),
                        st.stop,
                        st.devices.len(),
                        m.missing_list().is_some()
                    );
                    let dk = k(&format!("change after {order}"));
                    match m.write_record(
                        &st,
                        &new_root,
                        Kind::device(Device::new(dk.key.clone(), "dev", ROLE_MEMBER)),
                        g.t + 5,
                    ) {
                        Ok(_) => run.check(&format!("change ({order})"), "the new root's device", &m),
                        Err(e) => run.found.push(format!("change ({order}): the new root cannot admit: {e:?}")),
                    }
                }
            }
        }
    }

    // 5. Admin keys made and unmade one after another, each filling its
    // room with removals of 256 keys (about 17 units each), until the
    // keys that keep a room ask for more than the set's room and the
    // level binds.
    if std::env::var_os("READ_RECORDS_QUICK").is_none() {
        let (mut set, root, mut g) = root_with_dead_checkpoints(0, 0);
        let mut steps_here = 0usize;
        let mut first_drop: Option<usize> = None;
        'admins: for a in 0..32u32 {
            let ak = k(&format!("ex admin {a}"));
            let pk = k(&format!("ex admin phone {a}"));
            let mut d = Device::new(pk.key.clone(), "admin", ROLE_PHONE);
            d.rights = RIGHT_READ | RIGHT_SEND;
            d.admin = Some(ak.key.clone());
            d.powers = 0x1ff & !64;
            let r = g.sign(&root, Kind::device(d));
            let _ = set.insert(r);
            steps_here += 1;
            run.check("ex-admins", &format!("admin {a} made"), &set);
            for n in 0..16u32 {
                let mut keys: Vec<KeyHash> = (0..256u32)
                    .map(|i| {
                        KeyHash(cbb_core::certs::sha256(
                            &[&a.to_le_bytes()[..], &n.to_le_bytes()[..], &i.to_le_bytes()[..]].concat(),
                        ))
                    })
                    .collect();
                keys.sort();
                let r = g.sign(&ak, Kind::Revoke(cbb_core::records::body::Removal { keys, seen: Vec::new() }));
                let id = r.id();
                let _ = set.insert(r);
                steps_here += 1;
                if first_drop.is_none() && n < 15 && !set.contains(&id) {
                    first_drop = Some(run.steps + 1);
                }
                run.check("ex-admins", &format!("admin {a} removal {n}"), &set);
                if run.found.len() > 5 {
                    break 'admins;
                }
            }
            let r = g.sign(&root, Kind::device(Device::new(pk.key.clone(), "was admin", ROLE_PHONE)));
            let _ = set.insert(r);
            steps_here += 1;
            run.check("ex-admins", &format!("admin {a} unmade"), &set);
        }
        println!(
            "ex-admins: {steps_here} steps, first removal turned away at step {first_drop:?}, set {} records, {} of {} set bytes",
            set.len(),
            set.bytes(),
            cbb_core::records::MAX_SET_BYTES
        );
    }

    println!("{} steps checked; {} differ", run.steps, run.found.len());
    for f in &run.found {
        println!("  {f}");
    }
    assert!(
        run.found.is_empty(),
        "{} of {} steps differ after a restart:\n{}",
        run.found.len(),
        run.steps,
        run.found.join("\n")
    );
}
