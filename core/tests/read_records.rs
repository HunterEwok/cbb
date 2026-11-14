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

/// An honest checkpoint keeps none of its root's older checkpoints, the
/// counting one neither: it carries their heads and takes their place.
/// Were each to keep those before it, after some 70 a root's own
/// checkpoint would no longer fit its room (`honest_checkpoints_in_a_row`).
#[test]
fn an_honest_checkpoint_keeps_none_of_its_root_s_older_checkpoints() {
    let (mut set, root, mut g) = root_with_dead_checkpoints(0, 0);
    let mut cps = Vec::new();
    for round in 0..3u32 {
        for i in 0..3u32 {
            let dk = k(&format!("keep dev {round} {i}"));
            let r = g.sign(&root, Kind::device(Device::new(dk.key.clone(), "dev", ROLE_MEMBER)));
            set.insert(r).unwrap();
        }
        let st = set.state();
        let cp = set.write_checkpoint(&st, &root, g.t + 1).unwrap();
        g.heads.insert(root.hash, (cp.body().seq, cp.id()));
        g.t += 1000;
        if let Kind::Checkpoint { keep, .. } = &cp.body().kind {
            for (i, old) in cps.iter().enumerate() {
                assert!(!keep.contains(old), "round {round}, checkpoint {i}");
            }
        }
        cps.push(cp.id());
        set.insert(cp.clone()).unwrap();
        assert_eq!(set.state().checkpoint, Some(cp.id()), "round {round}");
    }
}

/// An honest root writes checkpoints in a row, a few devices admitted
/// between each, and the writer never refuses one.
#[test]
fn honest_checkpoints_in_a_row() {
    let (mut set, root, mut g) = root_with_dead_checkpoints(0, 0);
    for round in 0..700u32 {
        for i in 0..3u32 {
            let dk = k(&format!("row dev {round} {i}"));
            let r = g.sign(&root, Kind::device(Device::new(dk.key.clone(), "dev", ROLE_MEMBER)));
            let _ = set.insert(r);
        }
        let st = set.state();
        match set.write_checkpoint(&st, &root, g.t + 1) {
            Ok(cp) => {
                let kept = match &cp.body().kind {
                    Kind::Checkpoint { keep, .. } => keep.len(),
                    _ => 0,
                };
                if round % 25 == 0 {
                    println!(
                        "round {round}: checkpoint {} bytes, keeps {kept}, devices {}",
                        cp.body().encode().len(),
                        st.devices.len()
                    );
                }
                g.heads.insert(root.hash, (cp.body().seq, cp.id()));
                g.t += 1000;
                let _ = set.insert(cp);
            }
            Err(e) => panic!("round {round}: an honest checkpoint refused: {e:?}; devices {}", st.devices.len()),
        }
    }
}

/// The recovery key `root_with_dead_checkpoints` gives its group.
fn bench_recovery() -> cbb_core::records::Recovery {
    cbb_core::records::Recovery {
        k1: k("recovery").key,
        k2: cbb_core::records::pq::PqKey::from_seeds(&[0x31; 16], &[0x32; 16], &[0x33; 16]).key(),
    }
}

/// Five hundred honest checkpoints in a row, each after a device comes and
/// the oldest goes: every one is written and counts, what each keeps stays
/// as large as the group, the set's bytes stay flat, and a member that
/// takes what the root's set gives it ends on each checkpoint too. With
/// `restart`, the root's set is rebuilt from its records halfway.
fn checkpoints_in_a_row(rounds: u32, restart: bool) {
    let (mut set, root, mut g) = root_with_dead_checkpoints(0, 0);
    let phone = k("phone a").hash;
    let mut other = RecordSet::new(root.key.clone(), bench_recovery());
    let mut live: std::collections::VecDeque<KeyHash> = std::collections::VecDeque::new();
    let (mut first_keep, mut first_bytes) = (0usize, 0usize);
    for round in 0..rounds {
        let dk = k(&format!("flat dev {round}"));
        set.insert(g.sign(&root, Kind::device(Device::new(dk.key.clone(), "dev", ROLE_MEMBER)))).unwrap();
        live.push_back(dk.hash);
        if live.len() > 20 {
            let gone = live.pop_front().unwrap();
            let rm = cbb_core::records::body::Removal { keys: vec![gone], seen: Vec::new() };
            set.insert(g.sign(&root, Kind::Revoke(rm))).unwrap();
        }
        if restart && round == rounds / 2 {
            let records: Vec<Record> = set.in_dependency_order().into_iter().cloned().collect();
            let lists: Vec<Vec<u8>> = set.lists().map(<[u8]>::to_vec).collect();
            let before = set.state();
            set = RecordSet::restore(root.key.clone(), bench_recovery(), &records, &lists);
            assert_eq!(set.state(), before, "round {round}: the restored set");
        }
        let st = set.state();
        let cp = set.write_checkpoint(&st, &root, g.t + 1).unwrap_or_else(|e| panic!("round {round}: {e:?}"));
        g.heads.insert(root.hash, (cp.body().seq, cp.id()));
        g.t += 1000;
        let Kind::Checkpoint { keep, .. } = &cp.body().kind else { unreachable!() };
        let kept = keep.len();
        set.insert(cp.clone()).unwrap();
        let st = set.state();
        assert_eq!(st.checkpoint, Some(cp.id()), "round {round}");
        let sent: Vec<Record> = set.for_peer(&st, &phone).into_iter().cloned().collect();
        other.insert_all(sent);
        assert_eq!(other.state().checkpoint, Some(cp.id()), "round {round}: the other member");
        if round == 30 {
            (first_keep, first_bytes) = (kept, set.bytes());
        }
        if round > 30 {
            assert!(kept <= first_keep, "round {round}: keeps {kept}, at round 30 {first_keep}");
            assert!(
                set.bytes() <= first_bytes + 4096,
                "round {round}: {} bytes, at round 30 {first_bytes}",
                set.bytes()
            );
        }
    }
}

#[test]
fn five_hundred_checkpoints_in_a_row_stay_flat() {
    checkpoints_in_a_row(500, false);
}

#[test]
fn five_hundred_checkpoints_in_a_row_with_a_restart() {
    checkpoints_in_a_row(500, true);
}

/// A member that holds a root's checkpoints each keeping all before it, as
/// a writer did before, lets them all go once a checkpoint that keeps none
/// of them counts, but the one just below it; so does a member that takes
/// what the first one gives.
#[test]
fn a_pile_of_older_checkpoints_goes_when_a_new_one_counts() {
    let (mut set, root, mut g) = root_with_dead_checkpoints(0, 0);
    let phone = k("phone a").hash;
    let mut other = RecordSet::new(root.key.clone(), bench_recovery());
    let mut pile: Vec<RecordId> = Vec::new();
    for round in 0..20u32 {
        let dk = k(&format!("pile dev {round}"));
        set.insert(g.sign(&root, Kind::device(Device::new(dk.key.clone(), "dev", ROLE_MEMBER)))).unwrap();
        let st = set.state();
        let cp = set.write_checkpoint(&st, &root, g.t + 1).unwrap();
        let mut body = cp.body().clone();
        if let Kind::Checkpoint { keep, .. } = &mut body.kind {
            keep.extend(pile.iter().copied());
            keep.sort();
            keep.dedup();
        }
        let cp = Record::sign(body, &root).unwrap();
        g.heads.insert(root.hash, (cp.body().seq, cp.id()));
        g.t += 1000;
        set.insert(cp.clone()).unwrap();
        assert_eq!(set.state().checkpoint, Some(cp.id()), "round {round}");
        pile.push(cp.id());
    }
    let st = set.state();
    other.insert_all(set.for_peer(&st, &phone).into_iter().cloned());
    assert!(pile.iter().all(|id| set.contains(id) && other.contains(id)));
    let cp = set.write_checkpoint(&st, &root, g.t + 1).unwrap();
    set.insert(cp.clone()).unwrap();
    let st = set.state();
    assert_eq!(st.checkpoint, Some(cp.id()));
    other.insert_all(set.for_peer(&st, &phone).into_iter().cloned());
    assert_eq!(other.state().checkpoint, Some(cp.id()));
    // The last of them is the new one's prev, the record its chain
    // follows, and stays with it; the others go.
    assert_eq!(cp.body().prev.as_ref(), pile.last());
    for (i, id) in pile[..pile.len() - 1].iter().enumerate() {
        assert!(!set.contains(id), "the writer still holds checkpoint {i}");
        assert!(!other.contains(id), "the other member still holds checkpoint {i}");
    }
}

/// The root's admin device in a test of the floor: a phone with admin key
/// `admin`.
fn admin_device(phone: &K, admin: &K) -> Device {
    let mut d = Device::new(phone.key.clone(), "admin", ROLE_PHONE);
    d.rights = RIGHT_READ | RIGHT_SEND;
    d.admin = Some(admin.key.clone());
    d.powers = 0x1ff & !64;
    d
}

/// Fills the root's room with devices that come and go, through the
/// writer, until the writer refuses a device for the floor; returns how
/// many came and went. With `admins`, each device has an admin key, so its
/// admission and its removal stay for good; without, a checkpoint lets
/// both go.
fn fill_to_the_floor(set: &mut RecordSet, root: &K, t: &mut u64, admins: bool) -> usize {
    for i in 0.. {
        let (dk, ak) = (k(&format!("floor dev {i}")), k(&format!("floor admin {i}")));
        let d = if admins { admin_device(&dk, &ak) } else { Device::new(dk.key.clone(), "dev", ROLE_MEMBER) };
        let st = set.state();
        *t += 1000;
        if let Err(e) = set.write_record(&st, root, Kind::device(d), *t) {
            let e = format!("{e:?}");
            assert!(e.contains("no room for its next checkpoint"), "device {i}: {e}");
            return i;
        }
        let mut keys = if admins { vec![dk.hash, ak.hash] } else { vec![dk.hash] };
        keys.sort();
        let st = set.state();
        *t += 1000;
        let rm = cbb_core::records::body::Removal { keys, seen: Vec::new() };
        set.write_record(&st, root, Kind::Revoke(rm), *t).unwrap_or_else(|e| panic!("removal {i}: {e:?}"));
    }
    unreachable!()
}

/// The root writes its checkpoint; it counts, and so does every record it
/// keeps.
fn checkpoint_counts(set: &mut RecordSet, root: &K, t: &mut u64, what: &str) {
    let st = set.state();
    *t += 1000;
    let cp = set.write_checkpoint(&st, root, *t).unwrap_or_else(|e| panic!("{what}: {e:?}"));
    set.insert(cp.clone()).unwrap();
    let st = set.state();
    assert_eq!(st.checkpoint, Some(cp.id()), "{what}");
    let Kind::Checkpoint { keep, .. } = &cp.body().kind else { unreachable!() };
    for id in keep {
        assert!(st.counting.contains(id), "{what}: a kept record does not count");
    }
}

/// The root at its floor: the writer refuses its next ordinary record and
/// says so, the set says a checkpoint is due, and the checkpoint the root
/// then writes counts with everything it keeps; after it the root writes
/// again. With `restart`, the root's set is rebuilt from its records at
/// the floor first; with `admins`, what fills the room stays for good.
fn at_the_floor_a_checkpoint_counts(restart: bool, admins: bool) {
    let (mut set, root, g) = root_with_dead_checkpoints(0, 0);
    let mut t = g.t;
    let n = fill_to_the_floor(&mut set, &root, &mut t, admins);
    assert!(n > 100, "only {n} devices came and went");
    let st = set.state();
    assert!(set.checkpoint_due(&st, t));
    if restart {
        let records: Vec<Record> = set.in_dependency_order().into_iter().cloned().collect();
        let lists: Vec<Vec<u8>> = set.lists().map(<[u8]>::to_vec).collect();
        set = RecordSet::restore(root.key.clone(), bench_recovery(), &records, &lists);
        assert_eq!(set.state(), st);
        assert!(set.checkpoint_due(&st, t));
    }
    checkpoint_counts(&mut set, &root, &mut t, "at the floor");
    if !admins {
        let st = set.state();
        assert!(!set.checkpoint_due(&st, t));
        let dk = k("after the floor");
        t += 1000;
        set.write_record(&st, &root, Kind::device(Device::new(dk.key.clone(), "dev", ROLE_MEMBER)), t).unwrap();
    }
}

#[test]
fn at_the_floor_the_root_s_checkpoint_counts() {
    at_the_floor_a_checkpoint_counts(false, false);
}

#[test]
fn at_the_floor_the_root_s_checkpoint_counts_after_a_restart() {
    at_the_floor_a_checkpoint_counts(true, false);
}

#[test]
fn at_the_floor_of_records_that_stay_the_root_s_checkpoint_counts() {
    at_the_floor_a_checkpoint_counts(false, true);
}

#[test]
fn at_the_floor_of_records_that_stay_the_root_s_checkpoint_counts_after_a_restart() {
    at_the_floor_a_checkpoint_counts(true, true);
}

/// Removals pass the floor: at it the root removes its admin and twenty
/// devices, and its checkpoint still counts with everything it keeps.
#[test]
fn removals_at_the_floor_leave_room_for_the_checkpoint() {
    let (mut set, root, g) = root_with_dead_checkpoints(0, 0);
    let mut t = g.t;
    fill_to_the_floor(&mut set, &root, &mut t, true);
    let st = set.state();
    t += 1000;
    let mut keys = vec![k("phone a").hash, k("admin a").hash];
    keys.sort();
    let rm = cbb_core::records::body::Removal { keys, seen: Vec::new() };
    set.write_record(&st, &root, Kind::Revoke(rm), t).unwrap();
    for i in 0..20u32 {
        let st = set.state();
        t += 1000;
        let rm = cbb_core::records::body::Removal { keys: vec![k(&format!("bench dev {i}")).hash], seen: Vec::new() };
        set.write_record(&st, &root, Kind::Revoke(rm), t).unwrap_or_else(|e| panic!("removal {i}: {e:?}"));
    }
    let st = set.state();
    assert!(st.devices.iter().all(|d| d.admin.is_none()));
    checkpoint_counts(&mut set, &root, &mut t, "after removals at the floor");
}

/// The end of the road: each admin key the root makes and removes leaves
/// its admission and its removal for good, with a checkpoint after each.
/// Printed: how many before the writer refuses the next admin, and what
/// the set says then. A change of root then frees the room: the new root
/// makes an admin again.
#[test]
#[ignore = "slow (hundreds of checkpoints); run with --ignored --release --nocapture"]
fn admin_keys_made_and_removed_until_the_floor() {
    let (mut set, root, g) = root_with_dead_checkpoints(0, 0);
    let mut t = g.t;
    let mut n = 0usize;
    loop {
        let (phone, admin) = (k(&format!("road phone {n}")), k(&format!("road admin {n}")));
        let st = set.state();
        t += 1000;
        if let Err(e) = set.write_record(&st, &root, Kind::device(admin_device(&phone, &admin)), t) {
            let e = format!("{e:?}");
            assert!(e.contains("write a checkpoint first"), "admin {n}: {e}");
            break;
        }
        let st = set.state();
        t += 1000;
        let mut keys = vec![phone.hash, admin.hash];
        keys.sort();
        let rm = cbb_core::records::body::Removal { keys, seen: Vec::new() };
        set.write_record(&st, &root, Kind::Revoke(rm), t).unwrap_or_else(|e| panic!("removal {n}: {e:?}"));
        checkpoint_counts(&mut set, &root, &mut t, &format!("after admin {n}"));
        n += 1;
    }
    let st = set.state();
    println!(
        "{n} admin keys made and removed; then the writer refuses; checkpoint due {}; devices {}; set {} bytes",
        set.checkpoint_due(&st, t),
        st.devices.len(),
        set.bytes()
    );
    // At the end of the road a checkpoint still counts.
    checkpoint_counts(&mut set, &root, &mut t, "at the end of the road");
    // The way out: a change of root.
    let st = set.state();
    let pq = cbb_core::records::pq::PqKey::from_seeds(&[0x31; 16], &[0x32; 16], &[0x33; 16]);
    let root2 = k("road root 2");
    let phone2 = Device::new(k("road root 2 phone").key.clone(), "root2 phone", ROLE_PHONE);
    t += 1000;
    set.write_change(&st, &k("recovery"), &pq, &root2, phone2, &[], false, t).unwrap();
    let st = set.state();
    assert_eq!(st.roots.last(), Some(&root2.hash));
    for i in 0..4u32 {
        let (phone, admin) = (k(&format!("road2 phone {i}")), k(&format!("road2 admin {i}")));
        let st = set.state();
        t += 1000;
        set.write_record(&st, &root2, Kind::device(admin_device(&phone, &admin)), t)
            .unwrap_or_else(|e| panic!("new root, admin {i}: {e:?}"));
    }
    println!("after the change of root: devices {}, set {} bytes", set.state().devices.len(), set.bytes());
}

/// Devices a root signs past the cap of devices do not count, and its
/// checkpoints do not keep them: 700 rounds of three devices and a
/// checkpoint, each written and counting, keep no more than the devices
/// the group may have and the root's first records.
#[test]
fn checkpoints_keep_no_more_than_the_devices_the_group_may_have() {
    let (mut set, root, mut g) = root_with_dead_checkpoints(0, 0);
    for round in 0..700u32 {
        for i in 0..3u32 {
            let dk = k(&format!("cap dev {round} {i}"));
            let _ = set.insert(g.sign(&root, Kind::device(Device::new(dk.key.clone(), "dev", ROLE_MEMBER))));
        }
        let st = set.state();
        let cp = set.write_checkpoint(&st, &root, g.t + 1).unwrap_or_else(|e| panic!("round {round}: {e:?}"));
        let Kind::Checkpoint { keep, .. } = &cp.body().kind else { unreachable!() };
        assert!(keep.len() <= 256 + 2, "round {round}: keeps {}", keep.len());
        g.heads.insert(root.hash, (cp.body().seq, cp.id()));
        g.t += 1000;
        set.insert(cp.clone()).unwrap();
        assert_eq!(set.state().checkpoint, Some(cp.id()), "round {round}");
    }
}

/// A removal of 256 random keys by `by`, about 17 units.
fn wide_removal(g: &mut G, by: &K, tag: &str, n: u32) -> Record {
    let mut keys: Vec<KeyHash> = (0..256u32)
        .map(|i| {
            KeyHash(cbb_core::certs::sha256(&[tag.as_bytes(), &n.to_le_bytes()[..], &i.to_le_bytes()[..]].concat()))
        })
        .collect();
    keys.sort();
    g.sign(by, Kind::Revoke(cbb_core::records::body::Removal { keys, seen: Vec::new() }))
}

/// Keys that are no longer admins against a full honest group: 16 live
/// admin keys and the root each fill their room, then 12 admin keys made
/// and unmade fill theirs. The live admins keep every record they kept before (no squeeze
/// from the second tier), and after every insert a restored set is the
/// live one.
#[test]
#[ignore = "slow (a restore per step); run with --ignored --release"]
fn keys_no_longer_admins_squeeze_no_live_admin() {
    let (mut set, root, mut g) = root_with_dead_checkpoints(0, 0);
    let mut run = Run { steps: 0, found: Vec::new() };
    let mut live: Vec<(K, Vec<RecordId>)> = Vec::new();
    for a in 0..15u32 {
        // The phone of root_with_dead_checkpoints is admin 16.
        let ak = k(&format!("live admin {a}"));
        let pk = k(&format!("live admin phone {a}"));
        let mut d = Device::new(pk.key.clone(), "admin", ROLE_PHONE);
        d.rights = RIGHT_READ | RIGHT_SEND;
        d.admin = Some(ak.key.clone());
        d.powers = 0x1ff & !64;
        let r = g.sign(&root, Kind::device(d));
        let _ = set.insert(r);
        let mut mine = Vec::new();
        for n in 0..16u32 {
            let r = wide_removal(&mut g, &ak, &format!("live {a}"), n);
            let id = r.id();
            let _ = set.insert(r);
            if set.contains(&id) {
                mine.push(id);
            }
        }
        live.push((ak, mine));
    }
    // The root fills its room too, so that the first tier asks for all of
    // ROOM but the reserve, and the second tier gets only the reserve's
    // unused part.
    // About 19 units each: 72 leave room for the root's own 118 or so
    // records (100 devices, the admissions), which come after its
    // removals in its room.
    for n in 0..72u32 {
        let r = wide_removal(&mut g, &root, "root", n);
        let _ = set.insert(r);
    }
    run.check("full group", "16 live admins and the root filled", &set);
    {
        let st = set.state();
        let still: usize = live.iter().map(|(_, m)| m.iter().filter(|id| set.contains(id)).count()).sum();
        println!(
            "after the root filled: set {} records, live admins keep {still}, devices {}, admins in state {}",
            set.len(),
            st.devices.len(),
            st.devices.iter().filter(|d| d.admin.is_some()).count()
        );
    }
    let kept_before: usize = live.iter().map(|(_, m)| m.len()).sum();
    for a in 0..12u32 {
        let ak = k(&format!("gone admin {a}"));
        let pk = k(&format!("gone admin phone {a}"));
        let mut d = Device::new(pk.key.clone(), "admin", ROLE_PHONE);
        d.rights = RIGHT_READ | RIGHT_SEND;
        d.admin = Some(ak.key.clone());
        d.powers = 0x1ff & !64;
        // Made an admin in place of nobody: the 17th admin key counts as
        // no longer an admin from the start (ADMIN_KEYS_MAX).
        let r = g.sign(&root, Kind::device(d));
        let _ = set.insert(r);
        if a == 0 {
            let still: usize = live.iter().map(|(_, m)| m.iter().filter(|id| set.contains(id)).count()).sum();
            println!("after the 17th admin key made: set {} records, live admins keep {still}", set.len());
        }
        run.check("full group", &format!("admin {a} made"), &set);
        for n in 0..16u32 {
            let r = wide_removal(&mut g, &ak, &format!("gone {a}"), n);
            let _ = set.insert(r);
            run.check("full group", &format!("admin {a} removal {n}"), &set);
        }
        let r = g.sign(&root, Kind::device(Device::new(pk.key.clone(), "was admin", ROLE_PHONE)));
        let _ = set.insert(r);
        run.check("full group", &format!("admin {a} unmade"), &set);
        let still: usize = live.iter().map(|(_, m)| m.iter().filter(|id| set.contains(id)).count()).sum();
        if still != kept_before {
            run.found.push(format!(
                "step {}: after admin {a} unmade, the live admins keep {still} of the {kept_before} records they kept",
                run.steps
            ));
        }
    }
    println!(
        "full group: {} steps, live admins kept {kept_before} records, set {} records, {} of {} bytes",
        run.steps,
        set.len(),
        set.bytes(),
        cbb_core::records::MAX_SET_BYTES
    );
    for f in &run.found {
        println!("  {f}");
    }
    assert!(run.found.is_empty(), "{} of {} steps:\n{}", run.found.len(), run.steps, run.found.join("\n"));
}

/// Admits an admin key with its phone by the root: the key, the record.
fn admit_admin(g: &mut G, root: &K, name: &str) -> (K, Record) {
    let ak = k(&format!("{name} key"));
    let pk = k(&format!("{name} phone"));
    let mut d = Device::new(pk.key.clone(), "admin", ROLE_PHONE);
    d.rights = RIGHT_READ | RIGHT_SEND;
    d.admin = Some(ak.key.clone());
    d.powers = 0x1ff & !64;
    let r = g.sign(root, Kind::device(d));
    (ak, r)
}

/// A group whose root and 16 admin keys fill their rooms, then `ex` admin
/// keys made and unmade fill theirs (the second tier, which shares the
/// 1536 units the first tier leaves while no change of root fills the
/// reserve): the records, in order, the root, the admin keys and G. Admin
/// key 0 leaves its room empty and admin key 1 has no power to remove
/// admins, so that admin key 0 may still remove it.
fn full_group(tag: &str, ex: u32) -> (Vec<Record>, K, Vec<K>, G) {
    let root = k("root");
    let recovery = cbb_core::records::Recovery {
        k1: k("recovery").key,
        k2: cbb_core::records::pq::PqKey::from_seeds(&[0x31; 16], &[0x32; 16], &[0x33; 16]).key(),
    };
    let mut g = G { gid: group_id(&root.key, &recovery), heads: BTreeMap::new(), t: 0 };
    let mut recs = Vec::new();
    let mut admins = Vec::new();
    for a in 0..16u32 {
        let (ak, mut r) = admit_admin(&mut g, &root, &format!("{tag} admin {a}"));
        if a == 1 {
            // Signed again without the power to remove admins.
            let Kind::Device(mut d) = r.body().kind.clone() else { unreachable!() };
            d.powers &= !cbb_core::records::body::POWER_REMOVE_ADMINS;
            let b = r.body();
            r = sign_at(&g, &root, b.seq, b.prev, Kind::device(*d), b.time_ms);
            g.heads.insert(root.hash, (r.body().seq, r.id()));
        }
        recs.push(r);
        admins.push(ak);
    }
    // Admin key 0 keeps its room empty, so that it can still remove.
    for (a, ak) in admins.iter().enumerate().skip(1) {
        for n in 0..16u32 {
            recs.push(wide_removal(&mut g, ak, &format!("{tag} {a}"), n));
        }
    }
    for n in 0..76u32 {
        recs.push(wide_removal(&mut g, &root, &format!("{tag} root"), n));
    }
    for e in 0..ex {
        let (ak, r) = admit_admin(&mut g, &root, &format!("{tag} ex admin {e}"));
        recs.push(r);
        for n in 0..16u32 {
            recs.push(wide_removal(&mut g, &ak, &format!("{tag} ex {e}"), n));
        }
        let pk = k(&format!("{tag} ex admin {e} phone"));
        recs.push(g.sign(&root, Kind::device(Device::new(pk.key.clone(), "was admin", ROLE_PHONE))));
    }
    (recs, root, admins, g)
}

fn new_set() -> RecordSet {
    let recovery = cbb_core::records::Recovery {
        k1: k("recovery").key,
        k2: cbb_core::records::pq::PqKey::from_seeds(&[0x31; 16], &[0x32; 16], &[0x33; 16]).key(),
    };
    RecordSet::new(k("root").key, recovery)
}

/// Being settled: a key an admin removed. Admin A removes admin B (an
/// admin removal, not the root's), then the root admits C, the 17th key it
/// names; C fills its room. Wanted: C is in the first tier and keeps what
/// a live admin keeps.
#[test]
#[ignore = "being settled at records: a key an admin removed still takes a live admin's place in the tiers"]
fn an_admin_admitted_after_an_admin_removal_is_in_the_first_tier() {
    let (recs, root, admins, mut g) = full_group("b", 8);
    let mut set = new_set();
    set.insert_all(recs);
    let rm = g.sign(
        &admins[0],
        Kind::Revoke(cbb_core::records::body::Removal { keys: vec![admins[1].hash], seen: Vec::new() }),
    );
    let _ = set.insert(rm);
    let (c, r) = admit_admin(&mut g, &root, "b admin C");
    let _ = set.insert(r);
    let mut ids = Vec::new();
    for n in 0..16u32 {
        let r = wide_removal(&mut g, &c, "b C", n);
        ids.push(r.id());
        let _ = set.insert(r);
    }
    let live_keeps = 14usize;
    let kept = ids.iter().filter(|id| set.contains(id)).count();
    println!(
        "C keeps {kept} of 16 (a live admin keeps {live_keeps}); B removed: {}",
        set.state().revoked.contains(&admins[1].hash)
    );
    assert_eq!(kept, live_keeps, "C is squeezed as if no longer an admin");
}

/// Two members holding different subsets of the root's records: X holds
/// the root's record that takes admin key 3 back, Y does not. A 17th admin
/// key D the root admits after it is live for X and past the first 16 for
/// Y, so the tiers differ while they hold different records. After they
/// give each other all they hold, they are equal.
#[test]
fn members_with_different_root_records_agree_after_sync() {
    let (recs, root, _admins, mut g) = full_group("a", 8);
    // The root takes admin key 3 back: its phone's newest record names none.
    let back = g.sign(&root, Kind::device(Device::new(k("a admin 3 phone").key.clone(), "was admin", ROLE_PHONE)));
    let (d, rd) = admit_admin(&mut g, &root, "a admin D");
    let mut d_recs = Vec::new();
    for n in 0..16u32 {
        d_recs.push(wide_removal(&mut g, &d, "a D", n));
    }
    let mut x = new_set();
    let mut y = new_set();
    x.insert_all(recs.clone());
    y.insert_all(recs);
    let _ = x.insert(back.clone());
    for r in std::iter::once(rd).chain(d_recs.iter().cloned()) {
        let _ = x.insert(r.clone());
        let _ = y.insert(r);
    }
    let d_kept = |s: &RecordSet| d_recs.iter().filter(|r| s.contains(&r.id())).count();
    println!(
        "before sync: X keeps {} of D's 16, Y keeps {}; equal {}",
        d_kept(&x),
        d_kept(&y),
        x.state() == y.state() && x.digest() == y.digest()
    );
    for _ in 0..3 {
        let from_x: Vec<Record> = x.in_dependency_order().into_iter().cloned().collect();
        let from_y: Vec<Record> = y.in_dependency_order().into_iter().cloned().collect();
        x.insert_all(from_y);
        y.insert_all(from_x);
    }
    println!("after sync: X keeps {} of D's 16, Y keeps {}", d_kept(&x), d_kept(&y));
    let ids = |s: &RecordSet| {
        s.in_dependency_order()
            .into_iter()
            .map(|r| (r.id(), r.body().signer, r.body().seq))
            .collect::<std::collections::BTreeSet<_>>()
    };
    let (ix, iy) = (ids(&x), ids(&y));
    let name = |h: &KeyHash| {
        (0..16)
            .map(|a| format!("a admin {a}"))
            .chain((0..8).map(|e| format!("a ex admin {e}")))
            .chain(["a admin D".to_string()])
            .find(|n| k(&format!("{n} key")).hash == *h)
            .unwrap_or_else(|| if *h == root.hash { "root".into() } else { "?".into() })
    };
    for (id, sg, seq) in ix.difference(&iy) {
        println!("  only X: {} seq {seq} {:02x?}", name(sg), &id.0[..3]);
    }
    for (id, sg, seq) in iy.difference(&ix) {
        println!("  only Y: {} seq {seq} {:02x?}", name(sg), &id.0[..3]);
        if let Some(r) = y.in_dependency_order().into_iter().find(|r| r.id() == *id).cloned() {
            let mut x2 = x.clone();
            println!("    offered to X again: {:?}", x2.insert(r).map(|a| format!("{a:?}")));
        }
    }
    assert_eq!(x.digest(), y.digest(), "different records after sync");
    assert_eq!(x.state(), y.state(), "different states after sync");
    // A member given every record at once holds the same.
    let mut all = new_set();
    let every: Vec<Record> = y
        .in_dependency_order()
        .into_iter()
        .cloned()
        .chain(std::iter::once(back.clone()))
        .chain(d_recs.iter().cloned())
        .collect();
    all.insert_all(every);
    assert_eq!(all.digest(), x.digest(), "sync ends elsewhere than all at once");
    assert_eq!(all.state(), x.state(), "sync ends in another state than all at once");
}

/// The records of the take-back case: `full_group(tag, ex)`, the root's
/// record that takes admin key 3 back, a 17th admin key D the root admits
/// after it, and D's 16 removals. Ex-admins 7 and 8 squeeze the second
/// tier; up to 6 they do not.
struct TakeBack {
    recs: Vec<Record>,
    back: Record,
    rd: Record,
    d_recs: Vec<Record>,
}

fn take_back(tag: &str, ex: u32) -> TakeBack {
    let (recs, root, _admins, mut g) = full_group(tag, ex);
    let back = g.sign(
        &root,
        Kind::device(Device::new(k(&format!("{tag} admin 3 phone")).key.clone(), "was admin", ROLE_PHONE)),
    );
    let (d, rd) = admit_admin(&mut g, &root, &format!("{tag} admin D"));
    let d_recs = (0..16u32).map(|n| wide_removal(&mut g, &d, &format!("{tag} D"), n)).collect();
    TakeBack { recs, back, rd, d_recs }
}

impl TakeBack {
    /// Every record, the take-back before D's admission.
    fn back_first(&self) -> Vec<Record> {
        let mut v = self.recs.clone();
        v.push(self.back.clone());
        v.push(self.rd.clone());
        v.extend(self.d_recs.iter().cloned());
        v
    }

    /// Members X and Y after three rounds of sync: X took every record,
    /// the take-back before D's admission; Y took them without it.
    fn synced(&self) -> (RecordSet, RecordSet) {
        let (mut x, mut y) = (new_set(), new_set());
        x.insert_all(self.back_first());
        y.insert_all(self.recs.clone());
        y.insert_all(core::iter::once(self.rd.clone()).chain(self.d_recs.iter().cloned()));
        for _ in 0..3 {
            let from_x: Vec<Record> = x.in_dependency_order().into_iter().cloned().collect();
            let from_y: Vec<Record> = y.in_dependency_order().into_iter().cloned().collect();
            x.insert_all(from_y);
            y.insert_all(from_x);
        }
        (x, y)
    }

    /// Every record, the take-back last.
    fn back_last(&self) -> Vec<Record> {
        let mut v = self.recs.clone();
        v.push(self.rd.clone());
        v.extend(self.d_recs.iter().cloned());
        v.push(self.back.clone());
        v
    }
}

fn same(a: &RecordSet, b: &RecordSet) -> bool {
    a.digest() == b.digest() && a.state() == b.state()
}

/// One member given the same records in other orders (the take-back
/// before or after D's admission, or shuffled with eight seeds and offered
/// three times) ends with the same set and state.
#[test]
fn one_member_ends_equal_whatever_the_order() {
    for ex in [0u32, 6, 7, 8] {
        let c = take_back("o", ex);
        let (mut first, mut last) = (new_set(), new_set());
        first.insert_all(c.back_first());
        last.insert_all(c.back_last());
        assert!(same(&first, &last), "ex {ex}: {} records against {}", first.len(), last.len());
        let mut seed = 0x9e37_79b9_7f4a_7c15u64;
        for s in 0..8 {
            let mut v = c.back_first();
            for i in (1..v.len()).rev() {
                seed ^= seed << 13;
                seed ^= seed >> 7;
                seed ^= seed << 17;
                v.swap(i, (seed % (i as u64 + 1)) as usize);
            }
            let mut shuffled = new_set();
            for _ in 0..3 {
                shuffled.insert_all(v.clone());
            }
            assert!(same(&shuffled, &last), "ex {ex}, seed {s}: {} records against {}", shuffled.len(), last.len());
        }
    }
}

/// A restore from a member's records in any order (here shuffled, eight
/// seeds) equals the member; what the member holds, offered again to the
/// restored set, is taken.
#[test]
#[ignore = "slow; run with --ignored --release"]
fn a_restore_in_any_order_equals_the_member() {
    for ex in [0u32, 6, 7, 8] {
        let c = take_back("s", ex);
        let (_, member) = c.synced();
        let every: Vec<Record> = member.in_dependency_order().into_iter().cloned().collect();
        let lists: Vec<Vec<u8>> = member.lists().map(<[u8]>::to_vec).collect();
        let mut seed = 0x9e37_79b9_7f4a_7c15u64;
        for s in 0..8 {
            let mut v = every.clone();
            for i in (1..v.len()).rev() {
                seed ^= seed << 13;
                seed ^= seed >> 7;
                seed ^= seed << 17;
                v.swap(i, (seed % (i as u64 + 1)) as usize);
            }
            let mut back = RecordSet::restore(member.root().clone(), member.recovery().clone(), &v, &lists);
            for r in &every {
                if !back.contains(&r.id()) {
                    let got = back.insert(r.clone());
                    assert!(
                        !format!("{got:?}").contains("NoRoom"),
                        "ex {ex}, seed {s}: a record the member holds turned away"
                    );
                }
            }
            assert!(same(&back, &member), "ex {ex}, seed {s}: {} records against {}", back.len(), member.len());
        }
    }
}

/// A live member that held the take-back first takes, offered again, the
/// records it turned away while it was the only one to hold it.
#[test]
fn a_live_member_takes_what_it_turned_away_when_offered_again() {
    for ex in [0u32, 6, 7, 8] {
        let c = take_back("l", ex);
        let mut x = new_set();
        x.insert_all(c.back_first());
        let mut whole = new_set();
        whole.insert_all(c.back_last());
        for r in whole.in_dependency_order() {
            if !x.contains(&r.id()) {
                let got = x.insert(r.clone());
                assert!(!format!("{got:?}").contains("NoRoom"), "ex {ex}: turned away again");
            }
        }
        assert!(same(&x, &whole), "ex {ex}: {} records against {}", x.len(), whole.len());
    }
}

/// The records of `full_group(tag, 8)` with records that move the tiers
/// and the order in the rooms among them, both tiers squeezed: the root
/// takes admin key 3 back, admits D (16 removals), removes admin key 5,
/// writes a checkpoint and admits E (16 removals); then the recovery key
/// changes the root, and the new root admits F (16 removals). In signing
/// order, with the change's list, and the index of the take-back.
struct Moving {
    records: Vec<Record>,
    lists: Vec<Vec<u8>>,
    back: usize,
    /// Where each stage ends: after D's removals, after the checkpoint,
    /// after E's removals, and after the change and F.
    stages: Vec<(&'static str, usize)>,
}

fn moving_records(tag: &str) -> Moving {
    let (recs, root, _admins, mut g) = full_group(tag, 8);
    let mut all = recs;
    let back = all.len();
    all.push(g.sign(
        &root,
        Kind::device(Device::new(k(&format!("{tag} admin 3 phone")).key.clone(), "was admin", ROLE_PHONE)),
    ));
    let admit = |g: &mut G, all: &mut Vec<Record>, by: &K, name: &str| {
        let (key, r) = admit_admin(g, by, &format!("{tag} admin {name}"));
        all.push(r);
        for n in 0..16u32 {
            all.push(wide_removal(g, &key, &format!("{tag} {name}"), n));
        }
    };
    admit(&mut g, &mut all, &root, "D");
    let mut stages = vec![("after D", all.len())];
    all.push(g.sign(
        &root,
        Kind::Revoke(cbb_core::records::body::Removal {
            keys: vec![k(&format!("{tag} admin 5 key")).hash],
            seen: Vec::new(),
        }),
    ));
    let mut held = new_set();
    held.insert_all(all.clone());
    let st = held.state();
    let cp = held.write_checkpoint(&st, &root, g.t + 1).expect("an honest checkpoint");
    g.heads.insert(root.hash, (cp.body().seq, cp.id()));
    g.t += 1000;
    all.push(cp);
    stages.push(("after the checkpoint", all.len()));
    admit(&mut g, &mut all, &root, "E");
    stages.push(("after E", all.len()));
    let mut held = new_set();
    held.insert_all(all.clone());
    let st = held.state();
    let rk = k("recovery");
    let rk2 = cbb_core::records::pq::PqKey::from_seeds(&[0x31; 16], &[0x32; 16], &[0x33; 16]);
    let new_root = k(&format!("{tag} new root"));
    let phone = k(&format!("{tag} new phone"));
    let w = held
        .write_change(
            &st,
            &rk,
            &rk2,
            &new_root,
            Device::new(phone.key.clone(), "phone", ROLE_PHONE),
            &[],
            false,
            g.t + 1,
        )
        .expect("a change of root");
    let last = w.first.last().expect("the new root's first records");
    g.heads.insert(new_root.hash, (last.body().seq, last.id()));
    g.t += 1000;
    all.extend(w.first.iter().cloned());
    all.push(w.record.clone());
    admit(&mut g, &mut all, &new_root, "F");
    stages.push(("after the change and F", all.len()));
    Moving { records: all, lists: vec![w.list.encode()], back, stages }
}

/// One offer, as sync gives it: the records, then the lists; when a list
/// is new, the records again, which a record that waited for it takes.
fn offer(set: &mut RecordSet, records: &[Record], lists: &[Vec<u8>]) {
    set.insert_all(records.to_vec());
    let mut new = false;
    for l in lists {
        new |= set.insert_list(l).unwrap_or(false);
    }
    if new {
        set.insert_all(records.to_vec());
    }
}

/// Offers the records again until the set changes no more: the offers it
/// took.
fn until_stable(set: &mut RecordSet, records: &[Record], lists: &[Vec<u8>]) -> u32 {
    let mut rounds = 0;
    loop {
        let before = (set.digest(), set.state());
        offer(set, records, lists);
        rounds += 1;
        if (set.digest(), set.state()) == before || rounds == 10 {
            return rounds;
        }
    }
}

/// Records that move the tiers or the order in the rooms (a take-back, a
/// removal, a newer root checkpoint, a change of root), both tiers
/// squeezed: at each stage, whatever the order of what was signed so far
/// (signing order, the take-back last, eight shuffles), one offer ends
/// with the set the signing order settles at, and offering again changes
/// nothing.
#[test]
#[ignore = "slow (about five minutes in release); run with --ignored --release --nocapture"]
fn records_that_move_the_tiers_end_equal_whatever_the_order() {
    let m = moving_records("m");
    let mut bad = Vec::new();
    for (stage, end) in &m.stages {
        let records = &m.records[..*end];
        let lists: &[Vec<u8>] = if *end == m.records.len() { &m.lists } else { &[] };
        let mut reference = new_set();
        let rounds = until_stable(&mut reference, records, lists);
        println!("{stage}: signing order {} of {} records, stable after {rounds} offers", reference.len(), end);
        let mut orders: Vec<(String, Vec<Record>)> = vec![("signing order".into(), records.to_vec())];
        let mut last = records.to_vec();
        let b = last.remove(m.back);
        last.push(b);
        orders.push(("the take-back last".into(), last));
        let mut seed = 0x9e37_79b9_7f4a_7c15u64;
        for s in 0..8 {
            let mut v = records.to_vec();
            for i in (1..v.len()).rev() {
                seed ^= seed << 13;
                seed ^= seed >> 7;
                seed ^= seed << 17;
                v.swap(i, (seed % (i as u64 + 1)) as usize);
            }
            orders.push((format!("seed {s}"), v));
        }
        for (name, v) in &orders {
            let mut set = new_set();
            offer(&mut set, v, lists);
            let once = same(&set, &reference);
            let n = set.len();
            let more = until_stable(&mut set, v, lists);
            println!(
                "  {name}: one offer {n} records, equal {once}; stable after {more} more, equal {}",
                same(&set, &reference)
            );
            if !once || more > 1 || !same(&set, &reference) {
                bad.push(format!("{stage}, {name}"));
            }
        }
    }
    assert!(bad.is_empty(), "{bad:?} end elsewhere or late");
}

/// A root that writes checkpoints in a row (an admin's records between
/// them, so that each prunes) and a member given every record it signed
/// shuffled, offered three times: equal to the root's own set.
#[test]
fn checkpoints_in_a_row_shuffled_end_equal() {
    let (mut set, root, mut g) = root_with_dead_checkpoints(0, 0);
    let mut all: Vec<Record> = set.in_dependency_order().into_iter().cloned().collect();
    let admin = k("admin a");
    for round in 0..30u32 {
        for i in 0..3u32 {
            let dk = k(&format!("cpo dev {round} {i}"));
            let r = g.sign(&root, Kind::device(Device::new(dk.key.clone(), "dev", ROLE_MEMBER)));
            all.push(r.clone());
            let _ = set.insert(r);
        }
        if round % 3 == 0 {
            let r = wide_removal(&mut g, &admin, &format!("cpo adm {round}"), 0);
            all.push(r.clone());
            let _ = set.insert(r);
        }
        let st = set.state();
        let cp = set.write_checkpoint(&st, &root, g.t + 1).expect("an honest checkpoint");
        g.heads.insert(root.hash, (cp.body().seq, cp.id()));
        g.t += 1000;
        all.push(cp.clone());
        let _ = set.insert(cp);
    }
    assert!(set.len() < all.len(), "the checkpoints pruned nothing");
    let mut seed = 0x9e37_79b9_7f4a_7c15u64;
    for s in 0..4 {
        let mut v = all.clone();
        for i in (1..v.len()).rev() {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            v.swap(i, (seed % (i as u64 + 1)) as usize);
        }
        let mut m = new_set();
        for _ in 0..3 {
            m.insert_all(v.clone());
        }
        assert!(same(&m, &set), "seed {s}: {} records against {}", m.len(), set.len());
    }
    let mut rev = all.clone();
    rev.reverse();
    let mut m = new_set();
    for _ in 0..3 {
        m.insert_all(rev.clone());
    }
    assert!(same(&m, &set), "reversed: {} records against {}", m.len(), set.len());
}

/// A change of root whose new root's first checkpoint has not come: the
/// member holds the old root's records and is given the recovery record
/// with its list, then the new root's device record, its later checkpoint
/// and a device it admits, in every order. The path never grows to the new
/// root without a checkpoint of it held, nor shrinks; a restore after
/// every step is the live set; every order ends alike, still on the old
/// root and asking for the first checkpoint; a second offer of everything
/// changes nothing; an honest member that took the change still holds the
/// first checkpoint to give; and once it comes the change completes.
#[test]
fn a_change_whose_first_checkpoint_never_comes_completes_alike_in_any_order() {
    let (set, _root, mut g) = root_with_dead_checkpoints(0, 0);
    let rk = k("recovery");
    let rk2 = cbb_core::records::pq::PqKey::from_seeds(&[0x31; 16], &[0x32; 16], &[0x33; 16]);
    let nk = k("unfirst new root");
    let phone = k("unfirst new phone");
    let st = set.state();
    let mut writer = set.clone();
    let w = writer
        .write_change(&st, &rk, &rk2, &nk, Device::new(phone.key.clone(), "phone", ROLE_PHONE), &[], false, g.t + 1)
        .expect("a change of root");
    let list = w.list.encode();
    let _ = writer.insert(w.record.clone());
    let _ = writer.insert_list(&list);
    writer.insert_all(w.first.clone());
    assert_eq!(writer.state().roots.len(), 2, "the writer is on the new root");
    let first_cp = w.first.last().expect("the new root's first checkpoint").clone();
    assert!(matches!(first_cp.body().kind, Kind::Checkpoint { .. }), "the last first record is a checkpoint");
    let device = w.first.iter().find(|r| matches!(r.body().kind, Kind::Device(_))).expect("its device record").clone();
    g.heads.insert(nk.hash, (first_cp.body().seq, first_cp.id()));
    g.t += 1000;
    let six = g.sign(&nk, Kind::device(Device::new(k("unfirst dev 6").key.clone(), "dev", ROLE_MEMBER)));
    let _ = writer.insert(six.clone());
    let st = writer.state();
    let seven = writer.write_checkpoint(&st, &nk, g.t + 1).expect("the new root's later checkpoint");
    let _ = writer.insert(seven.clone());
    println!(
        "writer after 7: path {}, holds the first checkpoint {}, holds the device record {}, checkpoint counting is 7 {}",
        writer.state().roots.len(),
        writer.contains(&first_cp.id()),
        writer.contains(&device.id()),
        writer.state().checkpoint == Some(seven.id())
    );
    let items = [("device", device.clone()), ("7", seven.clone()), ("6", six.clone())];
    let orders: [[usize; 3]; 6] = [[0, 1, 2], [0, 2, 1], [1, 0, 2], [1, 2, 0], [2, 0, 1], [2, 1, 0]];
    let mut ends: Vec<RecordSet> = Vec::new();
    for order in orders {
        let name: Vec<&str> = order.iter().map(|i| items[*i].0).collect();
        let mut m = set.clone();
        let mut path = m.state().roots.len();
        let mut steps: Vec<(String, Record)> = vec![("the recovery record".into(), w.record.clone())];
        steps.extend(order.iter().map(|i| (items[*i].0.to_string(), items[*i].1.clone())));
        for (n, (step, r)) in steps.into_iter().enumerate() {
            let got = m.insert(r).map(|a| format!("{a:?}"));
            if n == 0 {
                let _ = m.insert_list(&list);
            }
            let now = m.state().roots.len();
            let asks: Vec<String> = m.missing(&m.state()).iter().map(|i| format!("{:02x?}", &i.0[..2])).collect();
            println!("{name:?} {step}: {got:?}; path {now}, holds 7 {}; asks {asks:?}", m.contains(&seven.id()));
            assert!(now >= path, "{name:?} after {step}: the path shrank");
            if now == 2 {
                assert!(
                    m.contains(&seven.id()),
                    "{name:?} after {step}: on the new root without the checkpoint that settles it"
                );
            }
            let back = restarted(&m);
            assert!(back.state().roots.len() >= now, "{name:?} after {step}: a restore shortened the path");
            assert!(same(&back, &m), "{name:?} after {step}: a restore is not the live set");
            path = now;
        }
        let before = (m.digest(), m.state());
        let _ = m.insert(w.record.clone());
        let _ = m.insert_list(&list);
        m.insert_all(vec![device.clone(), seven.clone(), six.clone()]);
        assert!((m.digest(), m.state()) == before, "{name:?}: a second offer changed the set");
        ends.push(m);
    }
    for (i, e) in ends.iter().enumerate() {
        assert!(same(e, &ends[0]), "order {:?} ends elsewhere", orders[i]);
    }
    println!(
        "end: path {}, holds the first checkpoint {}",
        ends[0].state().roots.len(),
        ends[0].contains(&first_cp.id())
    );
    // An honest member that took the change keeps the new root's first
    // checkpoint (outside the rooms) after a later one counts: a peer
    // always has it to give.
    assert!(writer.contains(&first_cp.id()), "the writer dropped the new root's first checkpoint");
    let mut m = ends[0].clone();
    for round in 0..40 {
        let st = m.state();
        let asks = m.missing(&st);
        println!("round {round}: asks {}, stuck {}", asks.len(), m.stuck_checkpoints().len());
        if asks.is_empty() {
            break;
        }
    }
    println!("after asking: path {}", m.state().roots.len());
    assert_eq!(ends[0].state().roots.len(), 1, "the change completed without its first checkpoint");
    let st = ends[0].state();
    let arriving = ends[0].change_arriving(&st).expect("the set tells that a change of root is arriving");
    assert_eq!(arriving.first_missing, Some(first_cp.id()));
    // The state still tells the app the change is arriving after the
    // asking gave up.
    assert_eq!(m.state().first_missing, Some(first_cp.id()), "the state does not tell the change is arriving");
    // After a restart the member asks again: what it asked is not saved.
    let mut again = restarted(&m);
    let st = again.state();
    let asks_again = again.missing(&st);
    println!("restarted after giving up: asks {}", asks_again.len());
    assert_eq!(asks_again, vec![first_cp.id()], "a restarted member does not ask for the first checkpoint again");
    // A peer that took the change gives it in sync whatever was asked: what
    // a device of the group gets holds the new root's first checkpoint.
    let peer = k("bench dev 0").hash;
    let st = writer.state();
    let given: Vec<Record> = writer.for_peer(&st, &peer).into_iter().cloned().collect();
    println!(
        "for_peer gives {} records, the first checkpoint among them {}",
        given.len(),
        given.iter().any(|r| r.id() == first_cp.id())
    );
    assert!(given.iter().any(|r| r.id() == first_cp.id()), "sync does not give the first checkpoint");
    let mut synced = m.clone();
    synced.insert_all(given);
    println!("after sync with that peer: path {}", synced.state().roots.len());
    assert_eq!(synced.state().roots.len(), 2, "sync with a peer that took the change does not complete it");
    let got = m.insert(first_cp.clone()).map(|a| format!("{a:?}"));
    println!("the first checkpoint at last: {got:?}; path {}", m.state().roots.len());
    assert_eq!(m.state().roots.len(), 2, "the first checkpoint did not complete the change");
    assert!(same(&restarted(&m), &m), "a restore after the change is not the live set");
}

/// What the state shows of a set, the parts a checkpoint must leave as
/// they were. Not the removed keys: a removal a checkpoint settles goes,
/// with the admissions of the keys it names, as the fold always did.
fn shown(set: &RecordSet) -> String {
    let s = set.state();
    format!("{:?} {:?} {:?} {:?} {:?} {:?}", s.devices, s.settings, s.incoming_ms, s.hubs, s.stop, s.conflicts)
}

/// The root renames one device thirty times and sets how long copies stay
/// ten times. Its checkpoint keeps the device's oldest and newest records
/// and the newest of the copies records, the state shows the same, and
/// what it left out never comes back: offered again one by one, in
/// reverse after a restart, or held before by a member that then takes
/// what the root's set gives it.
#[test]
fn a_checkpoint_keeps_the_newest_of_what_the_root_set_again() {
    let (mut set, root, g) = root_with_dead_checkpoints(0, 0);
    let mut t = g.t;
    let phone = k("phone a").hash;
    let dk = k("renamed dev");
    let mut write = |set: &mut RecordSet, kind: Kind| {
        let st = set.state();
        t += 1000;
        set.write_record(&st, &root, kind, t).unwrap()
    };
    let names: Vec<Record> = (0..30)
        .map(|i| write(&mut set, Kind::device(Device::new(dk.key.clone(), &format!("name {i}"), ROLE_MEMBER))))
        .collect();
    let copies: Vec<Record> =
        (0..10).map(|i| write(&mut set, Kind::Copies { incoming_ms: MIN_INCOMING_MS + i, seen: vec![] })).collect();
    // The root's newest record is its head; one more puts these below it.
    write(&mut set, Kind::device(Device::new(k("one more").key.clone(), "dev", ROLE_MEMBER)));
    let before = shown(&set);
    let mut other = RecordSet::new(root.key.clone(), bench_recovery());
    let st = set.state();
    other.insert_all(set.for_peer(&st, &phone).into_iter().cloned());
    assert_eq!(shown(&other), before);
    let mut t2 = t;
    checkpoint_counts(&mut set, &root, &mut t2, "after the renames");
    assert_eq!(shown(&set), before);
    let gone: Vec<&Record> = names[1..29].iter().chain(&copies[..9]).collect();
    for r in [&names[0], &names[29], &copies[9]] {
        assert!(set.contains(&r.id()), "a record that stands for the rest");
    }
    for r in &gone {
        assert!(!set.contains(&r.id()), "a record set again later stays");
    }
    let after_bytes = set.bytes();
    for r in &gone {
        let _ = set.insert((*r).clone());
        assert!(!set.contains(&r.id()), "offered again, it came back");
    }
    assert_eq!(shown(&set), before);
    assert_eq!(set.bytes(), after_bytes);
    let mut back = restarted(&set);
    assert_eq!(shown(&back), before);
    for r in gone.iter().rev() {
        let _ = back.insert((*r).clone());
    }
    back.insert_all(gone.iter().map(|r| (*r).clone()));
    assert!(gone.iter().all(|r| !back.contains(&r.id())), "after a restart, it came back");
    assert_eq!(shown(&back), before);
    let st = set.state();
    other.insert_all(set.for_peer(&st, &phone).into_iter().cloned());
    assert_eq!(other.state().checkpoint, st.checkpoint);
    assert!(gone.iter().all(|r| !other.contains(&r.id())), "the other member still holds it");
    assert_eq!(shown(&other), before);
}

/// The admin admits plain devices and removes them while the root is
/// away, until its writer refuses for its room. The root's checkpoint
/// then leaves out the admin's admissions and removals below its head:
/// the state shows the same, the admin writes again, and none of them
/// comes back when offered again, before or after a restart.
#[test]
fn an_admin_s_removals_go_at_the_root_s_checkpoint() {
    let (mut set, root, g) = root_with_dead_checkpoints(0, 0);
    let mut t = g.t;
    let admin = k("admin a");
    let mut written: Vec<Record> = Vec::new();
    let mut refused = String::new();
    'fill: for i in 0.. {
        let dk = k(&format!("admin's dev {i}"));
        for kind in [
            Kind::device(Device::new(dk.key.clone(), "dev", ROLE_MEMBER)),
            Kind::Revoke(cbb_core::records::body::Removal { keys: vec![dk.hash], seen: Vec::new() }),
        ] {
            let st = set.state();
            t += 1000;
            match set.write_record(&st, &admin, kind, t) {
                Ok(r) => written.push(r),
                Err(e) => {
                    refused = format!("{e:?}");
                    break 'fill;
                }
            }
        }
    }
    assert!(written.len() > 20, "only {} records", written.len());
    assert!(refused.contains("ceiling") || refused.contains("room"), "{refused}");
    let before = shown(&set);
    checkpoint_counts(&mut set, &root, &mut t, "after the admin's removals");
    assert_eq!(shown(&set), before);
    // The admin's head stays as an anchor, with what it names.
    let gone: Vec<&Record> = written[..written.len() - 2].iter().collect();
    for r in &gone {
        assert!(!set.contains(&r.id()), "an admin's settled record stays");
    }
    for r in &gone {
        let _ = set.insert((*r).clone());
    }
    assert!(gone.iter().all(|r| !set.contains(&r.id())), "offered again, it came back");
    let mut back = restarted(&set);
    back.insert_all(gone.iter().map(|r| (*r).clone()));
    assert!(gone.iter().all(|r| !back.contains(&r.id())), "after a restart, it came back");
    assert_eq!(shown(&back), before);
    let st = set.state();
    t += 1000;
    let dk = k("admin's dev after");
    set.write_record(&st, &admin, Kind::device(Device::new(dk.key.clone(), "dev", ROLE_MEMBER)), t)
        .expect("the admin writes again");
}

/// Removals past the floor: the root's room holds records that stay for
/// good up to its floor, then the root removes its hundred plain devices
/// one by one. Each removal is written; where one more would leave no room
/// for the root's checkpoint, the writer writes that checkpoint first,
/// which settles the removals before it, and at the end a checkpoint
/// still counts.
#[test]
fn removals_past_the_floor_write_the_checkpoint_first() {
    let (mut set, root, g) = root_with_dead_checkpoints(0, 0);
    let mut t = g.t;
    fill_to_the_floor(&mut set, &root, &mut t, true);
    let first = set.state().checkpoint;
    let mut checkpoints = std::collections::BTreeSet::new();
    for i in 0..100u32 {
        let st = set.state();
        t += 1000;
        let rm = cbb_core::records::body::Removal { keys: vec![k(&format!("bench dev {i}")).hash], seen: Vec::new() };
        set.write_record(&st, &root, Kind::Revoke(rm), t).unwrap_or_else(|e| panic!("removal {i}: {e:?}"));
        let st = set.state();
        assert!(st.revoked.contains(&k(&format!("bench dev {i}")).hash) || st.checkpoint != first);
        assert!(st.device(&k(&format!("bench dev {i}")).key.device_id()).is_none(), "removal {i}");
        checkpoints.extend(st.checkpoint);
    }
    assert!(!checkpoints.is_empty(), "no checkpoint was written first");
    let st = set.state();
    assert!(st.devices.iter().all(|d| !d.name.starts_with("bench")));
    checkpoint_counts(&mut set, &root, &mut t, "after the removals");
}

/// The take-back case with sixteen keys no longer admins squeezing the
/// second tier, taken in two offers (the group, then the tail): what the
/// member holds is what the rooms keep of it (checked after every insert
/// in debug builds), and offered everything again it comes to rest: a
/// third offer changes nothing. Where it rests may differ from a member
/// that took everything at once (the first offer turned records away by
/// what it held then), only in records of keys no longer admins past
/// their share.
#[test]
fn a_member_comes_to_rest_when_offered_everything_again() {
    let tb = take_back("s", 16);
    let mut x = new_set();
    x.insert_all(tb.recs.clone());
    x.insert_all(tb.back_first()[tb.recs.len()..].iter().cloned());
    x.insert_all(tb.back_first());
    let (digest, state, n) = (x.digest(), x.state(), x.len());
    x.insert_all(tb.back_first());
    assert_eq!(x.len(), n, "held {n}, then {}", x.len());
    assert!(x.digest() == digest && x.state() == state, "a third offer changed the set");
    let mut once = new_set();
    once.insert_all(tb.back_first());
    assert_eq!(once.state().devices, x.state().devices, "the devices differ from a member that took all at once");
    let ex: Vec<KeyHash> =
        (0..16).map(|e| k(&format!("s ex admin {e} key")).hash).chain([k("s admin 3 key").hash]).collect();
    let ids = |s: &RecordSet| {
        s.in_dependency_order().iter().map(|r| (r.id(), r.body().signer)).collect::<std::collections::BTreeSet<_>>()
    };
    for (_, signer) in ids(&once).symmetric_difference(&ids(&x)) {
        assert!(ex.contains(signer), "a record of a live key differs");
    }
}

/// Two members that read different rosters (one holds the root's record
/// that takes admin key 3 back, the other does not) hold the same after
/// one exchange of what they hold: the root records settle the roster,
/// and every key's cap with it, in the same exchange.
#[test]
fn members_reading_different_rosters_agree_after_one_exchange() {
    let tb = take_back("o", 8);
    let (mut x, mut y) = (new_set(), new_set());
    x.insert_all(tb.back_first());
    y.insert_all(tb.recs.clone());
    y.insert_all(std::iter::once(tb.rd.clone()).chain(tb.d_recs.iter().cloned()));
    assert!(!same(&x, &y), "the two read the same roster before");
    let from_x: Vec<Record> = x.in_dependency_order().into_iter().cloned().collect();
    let from_y: Vec<Record> = y.in_dependency_order().into_iter().cloned().collect();
    x.insert_all(from_y);
    y.insert_all(from_x);
    assert!(same(&x, &y), "not equal after one exchange");
    let mut all = new_set();
    all.insert_all(tb.back_first());
    assert!(same(&all, &x), "the exchange ends elsewhere than all at once");
}

/// What a taken-back admin key signed that the root never held. The 16
/// admin keys are live; admin key 0 removes a device the root admitted,
/// and the root does not hear of it. The root takes admin key 0 back (15
/// live: the key's cap is a whole admin room), its set says a checkpoint
/// is due, and the root writes it; offered then, the removal is held, but counts
/// no more than any record of a key that is no longer an admin: the device
/// stays (`fifteen`). Or the root first makes a new admin key D, 16 live again,
/// and the cap of a key no longer an admin is 0: offered after that, the
/// removal is lost and the device stays until someone removes it again.
fn a_taken_back_admin_s_removal(fifteen: bool) -> (bool, bool) {
    let (recs, root, admins, mut g) = full_group("z", 0);
    let mut set = new_set();
    set.insert_all(recs);
    let mut t = g.t;
    let dev = k("z dev");
    let st = set.state();
    t += 1000;
    set.write_record(&st, &root, Kind::device(Device::new(dev.key.clone(), "dev", ROLE_MEMBER)), t).unwrap();
    let rm =
        g.sign(&admins[0], Kind::Revoke(cbb_core::records::body::Removal { keys: vec![dev.hash], seen: Vec::new() }));
    let st = set.state();
    t += 1000;
    let back = Device::new(k("z admin 0 phone").key.clone(), "was admin", ROLE_PHONE);
    set.write_record(&st, &root, Kind::device(back), t).unwrap();
    assert!(set.checkpoint_due(&set.state(), t), "no checkpoint due after the take-back");
    checkpoint_counts(&mut set, &root, &mut t, "after the take-back");
    assert!(!set.checkpoint_due(&set.state(), t));
    if !fifteen {
        let (dk, ak) = (k("z admin D phone"), k("z admin D key"));
        let mut d = Device::new(dk.key.clone(), "admin", ROLE_PHONE);
        d.rights = RIGHT_READ | RIGHT_SEND;
        d.admin = Some(ak.key.clone());
        d.powers = 0x1ff & !64;
        let st = set.state();
        t += 1000;
        set.write_record(&st, &root, Kind::device(d), t).unwrap();
        assert!(set.checkpoint_due(&set.state(), t), "no checkpoint due after the admission");
        checkpoint_counts(&mut set, &root, &mut t, "after the admission");
    }
    let _ = set.insert(rm.clone());
    let st = set.state();
    (set.contains(&rm.id()), st.device(&dev.key.device_id()).is_some())
}

#[test]
fn a_taken_back_admin_s_removal_is_held_while_its_cap_has_room() {
    let (held, stays) = a_taken_back_admin_s_removal(true);
    assert!(held, "the removal is not held");
    assert!(stays, "a removal of a key no longer an admin counts");
}

#[test]
fn a_taken_back_admin_s_removal_is_lost_while_its_cap_is_0() {
    let (held, stays) = a_taken_back_admin_s_removal(false);
    assert!(!held, "the removal is held");
    assert!(stays, "the device left");
}

/// Members that take the records one by one, each in its own order, may
/// end with different sets (an insert holds what the rooms keep of what
/// is held and the record); after they sync, each giving the others what
/// it holds in one batch, they all hold the same, at every stage.
#[test]
#[ignore = "slow; run with --ignored --release --nocapture"]
fn members_taking_records_one_by_one_agree_after_sync() {
    let m = moving_records("m");
    for (stage, end) in m.stages.clone() {
        let records = &m.records[..end];
        let lists: &[Vec<u8>] = if end == m.records.len() { &m.lists } else { &[] };
        let mut seed = 0x1234_5678_9abc_def1u64 ^ (end as u64);
        let mut members = Vec::new();
        for _ in 0..4 {
            let mut v = records.to_vec();
            for i in (1..v.len()).rev() {
                seed ^= seed << 13;
                seed ^= seed >> 7;
                seed ^= seed << 17;
                v.swap(i, (seed % (i as u64 + 1)) as usize);
            }
            let mut one = new_set();
            for _ in 0..5 {
                for r in &v {
                    let _ = one.insert(r.clone());
                }
                for l in lists {
                    let _ = one.insert_list(l);
                }
            }
            members.push(one);
        }
        let mut batch = new_set();
        offer(&mut batch, records, lists);
        members.push(batch);
        let lens: Vec<usize> = members.iter().map(RecordSet::len).collect();
        let mut rounds = 0;
        loop {
            let before: Vec<[u8; 32]> = members.iter().map(RecordSet::digest).collect();
            for i in 0..members.len() {
                for j in 0..members.len() {
                    if i != j {
                        let give: Vec<Record> = members[j].in_dependency_order().into_iter().cloned().collect();
                        let lists: Vec<Vec<u8>> = members[j].lists().map(<[u8]>::to_vec).collect();
                        offer(&mut members[i], &give, &lists);
                    }
                }
            }
            rounds += 1;
            if members.iter().map(RecordSet::digest).collect::<Vec<_>>() == before || rounds == 6 {
                break;
            }
        }
        println!("{stage}: before sync {lens:?}, after {rounds} rounds {}", members[0].len());
        assert!(members.iter().all(|x| same(x, &members[0])), "{stage}: members differ after sync");
        assert!(rounds <= 3, "{stage}: {rounds} rounds of sync");
    }
}

/// The writer's warning before an admin removal tells exactly what the
/// removal, once written, takes from the group: the devices that leave
/// and those that no longer hold an admin key.
#[test]
fn the_warning_before_an_admin_removal_tells_what_it_takes() {
    let (mut set, root, mut g) = root_with_dead_checkpoints(0, 0);
    let admin = k("admin a");
    let mut admitted = Vec::new();
    for i in 0..3u32 {
        let dk = k(&format!("warn dev {i}"));
        let r = g.sign(&admin, Kind::device(Device::new(dk.key.clone(), "dev", ROLE_MEMBER)));
        admitted.push(r.id());
        set.insert(r).expect("an admin's admission");
    }
    let st = set.state();
    let warning = set.removal_warning(&st, &root.hash, &[admin.hash], g.t + 1);
    let removal =
        g.sign(&root, Kind::Revoke(cbb_core::records::body::Removal { keys: vec![admin.hash], seen: Vec::new() }));
    let mut after = set.clone();
    after.insert(removal).expect("the root's removal");
    let now = after.state();
    let out: Vec<_> = st.devices.iter().filter(|d| now.device(&d.id).is_none()).map(|d| d.id).collect();
    let no_admin: Vec<_> = st
        .devices
        .iter()
        .filter(|d| d.admin.is_some() && now.device(&d.id).is_some_and(|a| a.admin.is_none()))
        .map(|d| d.id)
        .collect();
    println!("warning {warning:?}; written: out {out:?}, no longer admin {no_admin:?}");
    assert_eq!(warning.out, out, "the warning and the written removal differ on who leaves");
    assert_eq!(warning.no_longer_admin, no_admin, "the warning and the written removal differ on admin keys");
    assert!(!warning.out.is_empty() || !warning.no_longer_admin.is_empty(), "the removal takes nothing");
    assert_eq!(set.state(), st, "the warning changed the set");
}

/// A live set and the same set restarted (equal records, state and
/// digest) answer every insert alike: what the rooms keep hangs on what is
/// held alone. After a batch the live set must not judge by the levels of
/// the batch it turned records away from.
#[test]
fn a_live_set_and_its_restart_answer_inserts_alike() {
    let (recs, ..) = full_group("w", 16);
    let mut live = new_set();
    live.insert_all(recs.clone());
    let mut back = restarted(&live);
    assert!(same(&back, &live), "the restart is not the live set");
    let dropped: Vec<Record> = recs.iter().filter(|r| !live.contains(&r.id())).cloned().collect();
    for r in &dropped {
        let a = live.insert(r.clone()).map(|x| format!("{x:?}"));
        let b = back.insert(r.clone()).map(|x| format!("{x:?}"));
        assert_eq!(a, b, "live and restarted answer differently");
        assert!(same(&back, &live), "live and restarted differ after an insert");
    }
}

/// What one member holds that another does not, before they sync, is only
/// records of second-tier keys past their share: never a removal, a
/// freeze, a resolve, a record of a root on the path, or a checkpoint that
/// counts for either.
fn only_second_tier_differs(a: &RecordSet, b: &RecordSet) -> Result<(), String> {
    let (sa, sb) = (a.state(), b.state());
    for (x, y, sx, sy) in [(a, b, &sa, &sb), (b, a, &sb, &sa)] {
        for r in x.in_dependency_order() {
            if y.contains(&r.id()) {
                continue;
            }
            let body = r.body();
            let what = match &body.kind {
                Kind::Revoke(_) => Some("a removal"),
                Kind::Freeze(_) => Some("a freeze"),
                Kind::Resolve(_) => Some("a resolve"),
                Kind::Checkpoint { .. } if sx.checkpoints.contains(&r.id()) || sy.checkpoints.contains(&r.id()) => {
                    Some("a counted checkpoint")
                }
                _ if sx.roots.contains(&body.signer) || sy.roots.contains(&body.signer) => Some("a root's record"),
                _ => None,
            };
            // A removal of a key no longer an admin is a second-tier
            // record past its share: that difference is allowed.
            let second = x.room_of(&body.signer).is_some_and(|r| r.tier == cbb_core::records::set::Tier::Second);
            if let Some(what) = what
                && !(second && matches!(body.kind, Kind::Revoke(_)))
            {
                return Err(format!("{what} (seq {}) held by one member only", body.seq));
            }
        }
    }
    Ok(())
}

/// Three members, each given the records one by one in its own order,
/// sync in a fuzzed order of pairs: before sync they differ only in
/// second-tier records past their share; the sync reaches one common set
/// and stops, and syncing more changes nothing.
#[test]
#[ignore = "slow; run with --ignored --release --nocapture"]
fn three_members_syncing_in_any_order_reach_one_set_and_stop() {
    let m = moving_records("p");
    let mut seed = 0x0bad_c0de_1234_5678u64;
    let mut next = |n: u64| {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed % n
    };
    let trials: Vec<(u32, (&str, usize))> = (0..3).flat_map(|t| m.stages.iter().map(move |s| (t, *s))).collect();
    for (trial, (stage, end)) in trials {
        let stage = format!("{stage}, trial {trial}");
        let records = &m.records[..end];
        let lists: &[Vec<u8>] = if end == m.records.len() { &m.lists } else { &[] };
        let mut members: Vec<RecordSet> = Vec::new();
        for _ in 0..3 {
            let mut v = records.to_vec();
            for i in (1..v.len()).rev() {
                v.swap(i, next(i as u64 + 1) as usize);
            }
            let mut one = new_set();
            for _ in 0..5 {
                for r in &v {
                    let _ = one.insert(r.clone());
                }
                for l in lists {
                    let _ = one.insert_list(l);
                }
            }
            members.push(one);
        }
        for i in 0..3 {
            for j in i + 1..3 {
                if let Err(e) = only_second_tier_differs(&members[i], &members[j]) {
                    panic!("{stage}: members {i} and {j} before sync: {e}");
                }
            }
        }
        let lens: Vec<usize> = members.iter().map(RecordSet::len).collect();
        let mut steps = 0u32;
        while !(same(&members[0], &members[1]) && same(&members[1], &members[2])) {
            let i = next(3) as usize;
            let j = (i + 1 + next(2) as usize) % 3;
            let give: Vec<Record> = members[j].in_dependency_order().into_iter().cloned().collect();
            let gl: Vec<Vec<u8>> = members[j].lists().map(<[u8]>::to_vec).collect();
            offer(&mut members[i], &give, &gl);
            steps += 1;
            assert!(steps <= 60, "{stage}: no common set after 60 pairwise syncs");
        }
        // It stops: every pair syncs again and nothing changes.
        let end_set = members[0].clone();
        for i in 0..3 {
            for j in 0..3 {
                if i != j {
                    let give: Vec<Record> = members[j].in_dependency_order().into_iter().cloned().collect();
                    let gl: Vec<Vec<u8>> = members[j].lists().map(<[u8]>::to_vec).collect();
                    offer(&mut members[i], &give, &gl);
                }
            }
        }
        assert!(members.iter().all(|x| same(x, &end_set)), "{stage}: syncing again changed a member");
        println!("{stage}: before {lens:?}, one set of {} after {steps} pairwise syncs", end_set.len());
    }
}
