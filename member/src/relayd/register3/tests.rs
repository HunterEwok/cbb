// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

use cbb_core::records::key::{ALG_SLH_DSA, Key};
use cbb_core::records::{Recovery, group_id, pq};
use p256::ecdsa::SigningKey;

use super::*;
use crate::faces::ServerKey;
use crate::identity::ExternalKey;

fn key(b: u8) -> ServerKey {
    ServerKey::from_scalar(&[b; 32]).unwrap()
}

fn hash(k: &ServerKey) -> [u8; 32] {
    Key::es256(k.public()).hash().0
}

fn blank(kind: u64, group: [u8; 16], version: u64) -> Credential {
    Credential {
        kind,
        group,
        signer: Vec::new(),
        version,
        expires_ms: 4_000_000_000_000,
        tag: None,
        key: None,
        hubs: Vec::new(),
        admins: Vec::new(),
        members: Vec::new(),
        id: [0; 32],
    }
}

struct Group {
    listed: Listed,
    period: Vec<u8>,
    hubs: Vec<u8>,
    members: Vec<u8>,
    device: ServerKey,
    admin: ServerKey,
}

/// A group of root key 1: its period with period key 2, the hubs'
/// credential naming admin key 4, and a members' credential by the period
/// key listing device key 3.
fn group() -> Group {
    let root = key(1);
    let (k1, k2) = pq::recovery_keys(&[1; 32]).unwrap();
    let k1 = SigningKey::from(&k1).verifying_key().to_sec1_point(false).as_bytes().to_vec();
    let rec = Recovery::new(Key::es256(k1.clone()), Key::new(ALG_SLH_DSA, k2.public())).unwrap();
    let gid = group_id(&Key::es256(root.public()), &rec);
    let listed = Listed { root: root.public(), recovery: k1, recovery2: k2.public() };
    let (pk, device, admin) = (key(2), key(3), key(4));
    let tag = [7; 16];
    let mut p = blank(TYPE_PERIOD, gid.0, 10);
    p.tag = Some(tag);
    p.key = Some(pk.public());
    let period = p.sign(&root).unwrap();
    let mut h = blank(TYPE_HUBS, tag, 11);
    h.admins = vec![hash(&admin)];
    let hubs = h.sign(&pk).unwrap();
    let mut m = blank(TYPE_MEMBERS, tag, 12);
    m.members = vec![hash(&device)];
    let members = m.sign(&pk).unwrap();
    Group { listed, period, hubs, members, device, admin }
}

#[test]
fn an_open_relay_takes_a_listed_member() {
    let g = group();
    let leaf = hash(&g.device);
    let shows = check(&[g.hubs.clone(), g.members.clone()], &leaf, None, None, 1).unwrap();
    assert_eq!(shows.members.version, 12);
    // Not listed, no members' credential, two hubs' credentials, expired.
    let other = hash(&key(9));
    let both = [g.hubs.clone(), g.members.clone()];
    assert!(check(&both, &other, None, None, 1).unwrap_err().contains("does not list"));
    assert!(check(std::slice::from_ref(&g.hubs), &leaf, None, None, 1).is_err());
    assert!(check(&[g.hubs.clone(), g.hubs.clone(), g.members.clone()], &leaf, None, None, 1).is_err());
    assert!(check(&both, &leaf, None, None, 4_000_000_000_000).unwrap_err().contains("expired"));
}

#[test]
fn the_members_credential_is_the_period_keys_or_a_listed_admins() {
    let g = group();
    let leaf = hash(&g.device);
    let mut m = blank(TYPE_MEMBERS, [7; 16], 13);
    m.members = vec![leaf];
    let by_admin = m.clone().sign(&g.admin).unwrap();
    assert!(check(&[g.hubs.clone(), by_admin], &leaf, None, None, 1).is_ok());
    let by_other = m.sign(&key(5)).unwrap();
    assert!(check(&[g.hubs.clone(), by_other], &leaf, None, None, 1).is_err());
}

#[test]
fn a_relay_with_a_list_takes_only_its_groups_from_their_root() {
    let g = group();
    let leaf = hash(&g.device);
    let all = [g.period.clone(), g.hubs.clone(), g.members.clone()];
    let root = g.listed.root.clone();
    let listed = [g.listed.clone()];
    assert!(check(&all, &leaf, Some(&root), Some(&listed), 1).is_ok());
    // Without the period, without naming the root, or a group not listed.
    assert!(check(&all[1..], &leaf, Some(&root), Some(&listed), 1).is_err());
    assert!(check(&all, &leaf, None, Some(&listed), 1).is_err());
    let mut other = g.listed.clone();
    other.recovery2[0] ^= 1;
    assert!(check(&all, &leaf, Some(&root), Some(&[other]), 1).is_err(), "the recovery key is in the Group ID");
    // A period whose key did not sign the hubs' credential.
    let mut p = Credential::read(&g.period).unwrap();
    p.key = Some(key(6).public());
    let wrong = p.sign(&key(1)).unwrap();
    assert!(check(&[wrong, g.hubs.clone(), g.members.clone()], &leaf, Some(&root), Some(&listed), 1).is_err());
}

#[test]
fn groups_are_named_by_their_keys() {
    let g = group();
    let h = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
    let s = format!("{}:{}:{}", h(&g.listed.root), h(&g.listed.recovery), h(&g.listed.recovery2));
    let l = Listed::parse(&s).unwrap();
    assert_eq!(l.root, g.listed.root);
    assert!(Listed::parse("aa:bb").is_err());
    assert!(Listed::parse(&format!("{}:zz:{}", h(&g.listed.root), h(&g.listed.recovery2))).is_err());
}
