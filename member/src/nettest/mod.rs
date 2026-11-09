// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! What the tests of the service's network part share: a group of devices
//! with their member certificates and records, made in memory, and a way to
//! wait for a condition. The tests themselves live beside it, each a child
//! of the module it tests, so that they reach its private parts.

use std::sync::Arc;
use std::time::{Duration, Instant};

use cbb_core::admit::{OwnDevice, new_group};
use cbb_core::authority::{self, Body, Hash, Record};
use cbb_core::certs::{self, Cert, DeviceId};
use cbb_core::credential::{self, Credential};
use cbb_core::group::Records;
use cbb_core::identity::{self, ExternalKey, FileKey};
use cbb_core::issue;
use serde_json::Value;

pub mod forwarder;
pub mod xhttp;

pub fn now_ms() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as i64
}

pub fn new_key() -> Arc<FileKey> {
    Arc::new(FileKey::new(&identity::new_key().unwrap()).unwrap())
}

/// A device of a test group: its ID, member key and member certificate.
pub struct Dev {
    pub id: DeviceId,
    pub key: Arc<FileKey>,
    pub pkcs8: Vec<u8>,
    pub cert: Vec<u8>,
}

/// A new key and its PKCS #8.
fn new_key_der() -> (Arc<FileKey>, Vec<u8>) {
    let der = identity::new_key().unwrap();
    (Arc::new(FileKey::new(&der).unwrap()), der)
}

/// A group made in memory: its root, the devices with member
/// certificates, the first one the root's own, and their records.
pub struct Group {
    pub root_key: Arc<FileKey>,
    pub root_pkcs8: Vec<u8>,
    pub root: Cert,
    pub records: Records,
    pub devs: Vec<Dev>,
}

impl Group {
    /// A group of n devices.
    pub fn new(n: usize) -> Group {
        let (root_key, root_pkcs8) = new_key_der();
        let (key, pkcs8) = new_key_der();
        let now = now_ms();
        let point = key.public();
        let own = OwnDevice {
            name: "computer",
            os: "linux",
            role: authority::ROLE_MEMBER,
            caps: &authority::CAPS,
            member_point: &point,
            store: "file",
            seal: Vec::new(),
        };
        let g = new_group(&*root_key, &own, now).unwrap();
        let group = Group {
            root_key,
            root_pkcs8,
            root: g.root,
            records: g.records,
            devs: vec![Dev { id: g.device, key, pkcs8, cert: g.cert.der }],
        };
        let mut group = group;
        for _ in 1..n {
            group.add();
        }
        group
    }

    /// Adds a device with its certificate and record.
    pub fn add(&mut self) -> usize {
        self.add_with(|_| {})
    }

    /// Adds a device that only passes copies on, which may be a hub.
    pub fn add_forwarder(&mut self) -> usize {
        self.add_with(|b| {
            b.forward_only = true;
            b.caps = vec![authority::CAP_HUB.into()];
        })
    }

    /// Adds a device whose record f changes first, such as a device that
    /// only passes copies on and may be a hub.
    pub fn add_with(&mut self, f: impl FnOnce(&mut Body)) -> usize {
        let (key, pkcs8) = new_key_der();
        let id = DeviceId::random();
        let now = now_ms();
        let rk = self.root_key.clone();
        let cert = issue::member(&id, &key.public(), &self.root, now / 1000, &mut |b| identity::sign_external(&*rk, b))
            .unwrap();
        let b = Body {
            v: 2,
            alg: authority::ALG_ES256.into(),
            kind: authority::TYPE_DEVICE.into(),
            signer: Hash(self.root.key_hash()),
            time_ms: now,
            device: id.to_string(),
            name: format!("device {}", self.devs.len()),
            role: authority::ROLE_MEMBER.into(),
            os: "linux".into(),
            key: Some(Hash(Cert::parse(&cert).unwrap().key_hash())),
            store: "file".into(),
            ..Default::default()
        };
        let mut b = b;
        f(&mut b);
        self.sign(b);
        self.devs.push(Dev { id, key, pkcs8, cert });
        self.devs.len() - 1
    }

    /// Signs a record by the root and adds it.
    pub fn sign(&mut self, b: Body) -> Record {
        let body = self.records.next_body(b).unwrap();
        let sig = identity::sign_external(&*self.root_key, &body).unwrap();
        let r = Record::new(body, sig, None);
        assert!(self.records.add(&r).unwrap(), "a record of the test group");
        r
    }

    /// Removes device i by a revocation record.
    pub fn revoke(&mut self, i: usize) -> Record {
        let b = Body {
            v: 2,
            alg: authority::ALG_ES256.into(),
            kind: authority::TYPE_REVOKE.into(),
            signer: Hash(self.root.key_hash()),
            time_ms: now_ms(),
            keys: vec![Hash(Cert::parse(&self.devs[i].cert).unwrap().key_hash())],
            ..Default::default()
        };
        self.sign(b)
    }

    /// Device i's chain as TLS presents it: its certificate and the root.
    pub fn chain(&self, i: usize) -> Vec<Vec<u8>> {
        vec![self.devs[i].cert.clone(), self.root.der.clone()]
    }

    pub fn key(&self, i: usize) -> Arc<dyn ExternalKey> {
        self.devs[i].key.clone()
    }

    pub fn id(&self, i: usize) -> String {
        self.devs[i].id.to_string()
    }

    /// A period of the group's credentials (docs/protocol.md, section 18)
    /// whose hubs' and members' credentials list the server keys given:
    /// the period, hubs' and members' credentials, the last two signed by
    /// the period key, of the given version.
    pub fn period(&self, servers: &[Arc<FileKey>], version: u64) -> [Credential; 3] {
        let period_key = new_key();
        let spki = |k: &FileKey| certs::p256_spki_of(&k.public());
        let tag = credential::new_period_tag().unwrap();
        let pb = credential::period_body(&certs::tag(&self.root), &tag, &spki(&period_key), version, now_ms());
        let rk = self.root_key.clone();
        let period = credential::sign(pb.clone(), &spki(&rk), &mut |b| identity::sign_external(&*rk, b)).unwrap();
        let hashes: Vec<certs::KeyHash> = servers.iter().map(|k| certs::sha256(&spki(k))).collect();
        let pk = period_key.clone();
        let by_period = |b| credential::sign(b, &spki(&pk), &mut |x| identity::sign_external(&*pk, x)).unwrap();
        let hubs = by_period(credential::hubs_body(&pb, &hashes, &[], version).unwrap());
        let members = by_period(credential::members_body(&pb, &hashes, version).unwrap());
        [period, hubs, members]
    }

    pub fn records_json(&self) -> Vec<Value> {
        self.records.all().iter().map(|r| serde_json::to_value(r).unwrap()).collect()
    }
}

/// Waits up to d for f, polling; whether it came.
pub fn wait_for(d: Duration, mut f: impl FnMut() -> bool) -> bool {
    let until = Instant::now() + d;
    loop {
        if f() {
            return true;
        }
        if Instant::now() >= until {
            return false;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// A folder of its own for a test, removed when dropped.
pub struct TempDir(pub std::path::PathBuf);

impl TempDir {
    pub fn new(what: &str) -> TempDir {
        let p = std::env::temp_dir().join(format!("cbb-{what}-{}", crate::vless::random_uuid()));
        std::fs::create_dir_all(&p).unwrap();
        TempDir(p)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Device i of the group as a node in a folder of its own, with the
/// group's records as they are now; its log goes to logs.
pub struct NodeAt {
    pub dir: TempDir,
    pub node: Arc<crate::node::Node>,
    pub logs: Arc<std::sync::Mutex<Vec<String>>>,
}

impl NodeAt {
    pub fn logged(&self, s: &str) -> bool {
        self.logs.lock().unwrap().iter().any(|l| l.contains(s))
    }

    pub fn log(&self) -> Arc<dyn Fn(&str) + Send + Sync> {
        let l = self.logs.clone();
        Arc::new(move |s: &str| l.lock().unwrap().push(s.to_string()))
    }
}

impl Group {
    pub fn identity(&self, i: usize) -> crate::identity::Identity {
        crate::identity::Identity {
            id: self.devs[i].id.clone(),
            key: self.devs[i].pkcs8.clone(),
            external: None,
            cert: Cert::parse(&self.devs[i].cert).unwrap(),
            issuer: None,
            group_ca: self.root.clone(),
            roots: Vec::new(),
        }
    }

    pub fn node(&self, i: usize) -> NodeAt {
        let dir = TempDir::new("node");
        let mut rs = crate::records::new(&self.root);
        let (_, errs) = rs.add_all(&self.records.all());
        assert!(errs.is_empty(), "{errs:?}");
        let ident = self.identity(i);
        // The root's device keeps the root's key, as admin::new_group
        // leaves it, so that it signs records and commands.
        let mut fields = serde_json::Map::new();
        if i == 0 {
            use base64::Engine;
            fields.insert(
                "group_ca_key".into(),
                base64::engine::general_purpose::STANDARD.encode(&self.root_pkcs8).into(),
            );
        }
        crate::identity::save_with(&ident, &dir.0, fields).unwrap();
        crate::records::Stored::save(&rs, &dir.0).unwrap();
        let engine = Arc::new(crate::clip::Engine::new(
            ident.id.as_str(),
            crate::service::clock(&dir.0),
            Box::new(crate::uptime::wall_ms),
            Box::new(crate::uptime::now),
        ));
        let logs = Arc::new(std::sync::Mutex::new(Vec::new()));
        let l = logs.clone();
        let log: Arc<dyn Fn(&str) + Send + Sync> = Arc::new(move |s: &str| l.lock().unwrap().push(s.to_string()));
        let node = Arc::new(crate::node::Node::new(
            ident,
            &format!("device {i}"),
            engine,
            rs,
            dir.0.clone(),
            Box::new(|_| {}),
            log,
        ));
        NodeAt { dir, node, logs }
    }
}
