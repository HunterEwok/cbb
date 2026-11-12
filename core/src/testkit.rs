// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! What the tests of copies, keys, commands and beacons share: keys made
//! from names, a group's records built up in a set, and devices with key
//! stores and statements.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use p256::ecdsa::SigningKey;
use p256::ecdsa::signature::hazmat::PrehashSigner as _;

use crate::certs::sha256;
use crate::identity::ExternalKey;
use crate::keystore::{self, MemoryStore, ReadStatement};
use crate::records::body::*;
use crate::records::eval::State;
use crate::records::statement::{self, Sealing, Statement};
use crate::records::{Body, GroupId, Key, KeyHash, Record, RecordId, RecordSet};

/// The time the tests start at.
pub const T0: u64 = 1_793_000_000_000;

/// A key made from a name, so that a test replays exactly.
pub struct K {
    pub sk: SigningKey,
    pub key: Key,
    pub hash: KeyHash,
}

impl ExternalKey for K {
    fn public(&self) -> Vec<u8> {
        self.key.public.clone()
    }
    fn sign_digest(&self, digest: &[u8; 32]) -> crate::error::Result<Vec<u8>> {
        let sig: p256::ecdsa::Signature = self.sk.sign_prehash(digest).unwrap();
        Ok(sig.to_der().as_bytes().to_vec())
    }
}

pub fn k(name: &str) -> K {
    let sk = SigningKey::from_slice(&sha256(name.as_bytes())).unwrap();
    let key = Key::es256(sk.verifying_key().to_sec1_point(false).as_bytes().to_vec());
    let hash = key.hash();
    K { sk, key, hash }
}

/// A group's records in a set, signed by keys made from names: "root" is
/// the root.
pub struct G {
    pub gid: GroupId,
    pub set: RecordSet,
    heads: BTreeMap<KeyHash, (u64, RecordId)>,
}

impl G {
    pub fn new() -> G {
        let (root, recovery) = (k("root"), k("recovery"));
        G {
            gid: crate::records::group_id(&root.key, &recovery.key),
            set: RecordSet::new(root.key.clone(), recovery.key.clone()),
            heads: BTreeMap::new(),
        }
    }

    pub fn rec(&mut self, by: &K, kind: Kind) -> Record {
        self.rec_at(by, kind, 0)
    }

    /// A record signed at time_ms.
    pub fn rec_at(&mut self, by: &K, kind: Kind, time_ms: u64) -> Record {
        let (seq, prev) = match self.heads.get(&by.hash) {
            Some((s, id)) => (s + 1, Some(*id)),
            None => (1, None),
        };
        let body = Body { group: self.gid, signer: by.hash, seq, prev, time_ms, kind, held: false };
        let r = Record::sign(body, by).unwrap();
        self.heads.insert(by.hash, (seq, r.id()));
        self.set.insert(r.clone()).unwrap();
        r
    }

    /// The root records a device of member, named name, of role, with
    /// rights; f changes the record further.
    pub fn device(&mut self, member: &str, role: u64, rights: u64, f: impl FnOnce(&mut Device)) -> K {
        let m = k(member);
        let mut d = Device::new(m.key.clone(), member, role);
        d.rights = rights;
        f(&mut d);
        self.rec(&k("root"), Kind::device(d));
        m
    }

    /// The root makes member's device an admin of kind with the admin key
    /// named admin.
    pub fn admin(&mut self, member: &str, admin: &str, kind: AdminKind) -> (K, K) {
        let a = k(admin);
        let (powers, commands) = kind.grants();
        let m = self.device(member, ROLE_PHONE, RIGHT_READ | RIGHT_SEND | RIGHT_SECRETS, |d| {
            d.admin = Some(a.key.clone());
            d.powers = powers;
            d.commands = commands;
        });
        (m, a)
    }

    /// The root freezes keys (a device's member key freezes its admin key
    /// with it).
    pub fn freeze(&mut self, keys: &[KeyHash]) {
        let mut keys = keys.to_vec();
        keys.sort();
        let seen = self.heads.iter().map(|(k, (s, id))| Seen { key: *k, seq: *s, id: *id }).collect();
        self.rec(&k("root"), Kind::Freeze(Removal { keys, seen }));
    }

    /// The root removes keys.
    pub fn revoke(&mut self, keys: &[KeyHash]) {
        let mut keys = keys.to_vec();
        keys.sort();
        let seen = self.heads.iter().map(|(k, (s, id))| Seen { key: *k, seq: *s, id: *id }).collect();
        self.rec(&k("root"), Kind::Revoke(Removal { keys, seen }));
    }

    /// The root's checkpoint at time_ms, keeping every other signer's
    /// record.
    pub fn checkpoint(&mut self, time_ms: u64) -> Record {
        let root = k("root");
        let mut keep: Vec<RecordId> = self
            .set
            .ids()
            .filter(|id| self.set.get(id).is_some_and(|r| r.body().signer != root.hash))
            .copied()
            .collect();
        keep.sort();
        let heads =
            self.heads.get(&root.hash).map(|(s, id)| Head { key: root.hash, seq: *s, id: *id }).into_iter().collect();
        self.rec_at(&root, Kind::Checkpoint { heads, keep }, time_ms)
    }

    pub fn state(&self) -> State {
        self.set.state()
    }

    /// Each signer's head, as a removal or a claim names them.
    pub fn seen(&self) -> Vec<Seen> {
        self.heads.iter().map(|(k, (s, id))| Seen { key: *k, seq: *s, id: *id }).collect()
    }

    /// The set's records in the order a sender sends them.
    pub fn records(&self) -> Vec<Record> {
        self.set.in_dependency_order().into_iter().cloned().collect()
    }
}

/// A device's key store with its first epoch made at T0.
pub fn store(member: &str, group: &GroupId) -> (MemoryStore<K>, Statement) {
    let mut s = MemoryStore::new(k(member));
    let made = keystore::rotate(&mut s, group, T0, Some(T0)).unwrap().made.unwrap();
    (s, statement_of(&made))
}

pub fn statement_of(env: &[u8]) -> Statement {
    match keystore::read_statement(env).unwrap() {
        ReadStatement::Take(st) => st,
        ReadStatement::Held { .. } => panic!("held"),
    }
}

/// The statements that count for the state's devices.
pub fn sealing(state: &State, statements: &[&Statement]) -> BTreeMap<crate::records::DeviceId, Sealing> {
    statement::choose(state, statements.iter().copied())
}
