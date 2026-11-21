// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! A group of 0.6 as its servers see it, made in memory for the tests of
//! the relay and the forwarder: a root and recovery key (its Group ID), a period of the root
//! with its period key, a server key per device, and the period's hubs'
//! and members' credentials (`cbb_core::blind::credential`), with what a
//! device registers with (`relay::Credentialed`) and what a hub registers
//! with at a forwarder (`forward::HubCredential`).

use std::collections::HashMap;
use std::sync::Arc;

use cbb_core::blind::credential::{Credential, TYPE_HUBS, TYPE_MEMBERS, TYPE_PERIOD};
use cbb_core::records::key::{ALG_SLH_DSA, Key};
use cbb_core::records::{Recovery, group_id, pq};
use p256::ecdsa::SigningKey;

use crate::faces::ServerKey;
use crate::identity::ExternalKey;
use crate::relay::Credentialed;

/// A group of 0.6: device i has server key `servers[i]` and device ID
/// `ids[i]`; the devices are in the order of their pseudonyms, so device
/// 0 dials the others.
pub struct Blind {
    root: ServerKey,
    recovery: Vec<u8>,
    recovery2: Vec<u8>,
    gid: [u8; 16],
    tag: [u8; 16],
    period_key: ServerKey,
    pub servers: Vec<Arc<ServerKey>>,
    pub ids: Vec<String>,
}

fn random_key() -> ServerKey {
    loop {
        if let Ok(k) = ServerKey::from_scalar(&cbb_core::certs::random_bytes()) {
            return k;
        }
    }
}

fn b64(b: &[u8]) -> String {
    base64::Engine::encode(&base64::engine::general_purpose::STANDARD, b)
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn blank(kind: u64, group: [u8; 16], version: u64) -> Credential {
    Credential {
        kind,
        group,
        signer: Vec::new(),
        version,
        expires_ms: u64::try_from(crate::uptime::wall_ms()).unwrap() + 24 * 3600 * 1000,
        tag: None,
        key: None,
        hubs: Vec::new(),
        admins: Vec::new(),
        members: Vec::new(),
        id: [0; 32],
    }
}

impl Blind {
    pub fn new(n: usize) -> Blind {
        let root = random_key();
        let (k1, k2) = pq::recovery_keys(&cbb_core::certs::random_bytes()).unwrap();
        let k1 = SigningKey::from(&k1).verifying_key().to_sec1_point(false).as_bytes().to_vec();
        let rec = Recovery::new(Key::es256(k1.clone()), Key::new(ALG_SLH_DSA, k2.public())).unwrap();
        let gid = group_id(&Key::es256(root.public()), &rec).0;
        let mut servers: Vec<Arc<ServerKey>> = (0..n).map(|_| Arc::new(random_key())).collect();
        servers.sort_by_key(|k| Blind::pseudonym(&**k));
        Blind {
            root,
            recovery: k1,
            recovery2: k2.public(),
            gid,
            tag: cbb_core::certs::random_bytes(),
            period_key: random_key(),
            servers,
            ids: (0..n).map(|_| cbb_core::certs::random_id()).collect(),
        }
    }

    /// A device's name at the relay: the hash of its server key, in base64.
    pub fn pseudonym(k: &dyn ExternalKey) -> String {
        b64(&Key::es256(k.public()).hash().0)
    }

    pub fn name(&self, i: usize) -> String {
        Blind::pseudonym(&*self.servers[i])
    }

    /// The group as a relay's `-group` names it: its root key and the two
    /// halves of its recovery key, in hex.
    pub fn listed(&self) -> String {
        format!("{}:{}:{}", hex(&self.root.public()), hex(&self.recovery), hex(&self.recovery2))
    }

    /// The period, hubs' and members' credentials of version `version`,
    /// the members' listing the devices `listed`.
    pub fn credentials(&self, version: u64, listed: &[usize]) -> [Vec<u8>; 3] {
        let mut p = blank(TYPE_PERIOD, self.gid, version);
        p.tag = Some(self.tag);
        p.key = Some(self.period_key.public());
        let h = blank(TYPE_HUBS, self.tag, version);
        let mut m = blank(TYPE_MEMBERS, self.tag, version);
        m.members = listed.iter().map(|&i| Key::es256(self.servers[i].public()).hash().0).collect();
        [p.sign(&self.root).unwrap(), h.sign(&self.period_key).unwrap(), m.sign(&self.period_key).unwrap()]
    }

    /// What hub i registers with at a forwarder, at version `version`: the
    /// hubs' credential alone, listing the hubs `listed`, with the
    /// certificate of its server key. The forwarder never sees the period
    /// credential, which names the group and its root.
    pub fn hub_credential(&self, i: usize, version: u64, listed: &[usize]) -> crate::forward::HubCredential {
        let mut h = blank(TYPE_HUBS, self.tag, version);
        h.hubs = listed.iter().map(|&j| Key::es256(self.servers[j].public()).hash().0).collect();
        crate::forward::HubCredential {
            credentials: vec![h.sign(&self.period_key).unwrap()],
            cert: self.servers[i].cert().unwrap(),
            key: self.servers[i].clone(),
        }
    }

    /// What device i registers with, at version `version`, with every
    /// device listed.
    pub fn credentialed(&self, i: usize, version: u64) -> Arc<Credentialed> {
        let all: Vec<usize> = (0..self.servers.len()).collect();
        self.credentialed_by(i, &self.credentials(version, &all))
    }

    /// What device i registers with, from credentials made here.
    pub fn credentialed_by(&self, i: usize, [period, hubs, members]: &[Vec<u8>; 3]) -> Arc<Credentialed> {
        let names: HashMap<String, String> =
            (0..self.servers.len()).filter(|&j| j != i).map(|j| (self.name(j), self.ids[j].clone())).collect();
        let now = u64::try_from(crate::uptime::wall_ms()).unwrap();
        Arc::new(
            Credentialed::new(
                self.servers[i].clone(),
                vec![hubs.clone(), members.clone()],
                period.clone(),
                self.root.public(),
                names,
                now,
            )
            .unwrap(),
        )
    }

    /// The root's key, which signs the period.
    pub fn root(&self) -> Vec<u8> {
        self.root.public()
    }
}
