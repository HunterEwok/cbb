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
use cbb_core::certs::{Cert, DeviceId};
use cbb_core::group::Records;
use cbb_core::identity::{self, ExternalKey, FileKey};
use cbb_core::issue;

pub mod blind;
pub mod forwarder;
mod ipv6;
mod props;
mod races;
mod toward;
pub mod xhttp;

pub fn now_ms() -> i64 {
    crate::uptime::wall_ms()
}

pub fn new_key() -> Arc<FileKey> {
    Arc::new(FileKey::new(&identity::new_key().unwrap()).unwrap())
}

/// A device of a test group: its ID.
pub struct Dev {
    pub id: DeviceId,
}

/// A group made in memory: its root, the devices with member
/// certificates, the first one the root's own, and their records.
pub struct Group {
    pub root_key: Arc<FileKey>,
    pub root: Cert,
    pub records: Records,
    pub devs: Vec<Dev>,
}

impl Group {
    /// A group of n devices.
    pub fn new(n: usize) -> Group {
        let (root_key, key) = (new_key(), new_key());
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
        let group = Group { root_key, root: g.root, records: g.records, devs: vec![Dev { id: g.device }] };
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

    /// Adds a device whose record f changes first, such as a device that
    /// only passes copies on and may be a hub.
    pub fn add_with(&mut self, f: impl FnOnce(&mut Body)) -> usize {
        let key = new_key();
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
        self.devs.push(Dev { id });
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

    pub fn id(&self, i: usize) -> String {
        self.devs[i].id.to_string()
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

impl Group {}
