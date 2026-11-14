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
