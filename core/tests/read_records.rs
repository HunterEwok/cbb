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
/// checkpoint already pruned, given to the live set and to one restarted
/// before it came. It covers 90 steps.
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
