// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! What the tests of the service's network part share: the devices of a
//! group by their IDs, made in memory, and a way to wait for a condition. The tests themselves live beside it, each a child
//! of the module it tests, so that they reach its private parts.

use std::sync::Arc;
use std::time::{Duration, Instant};

use cbb_core::certs::{Cert, DeviceId};
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

/// The devices of a test group, by their IDs, and a root CA, whose
/// certificate a test shows where only a server key's own is taken.
pub struct Group {
    pub root_key: Arc<FileKey>,
    pub root: Cert,
    pub devs: Vec<Dev>,
}

impl Group {
    /// A group of n devices.
    pub fn new(n: usize) -> Group {
        let root_key = new_key();
        let der = issue::root_ca(&root_key.public(), now_ms() / 1000, &mut |b| identity::sign_external(&*root_key, b))
            .unwrap();
        let root = Cert::parse(&der).unwrap();
        Group { root_key, root, devs: (0..n).map(|_| Dev { id: DeviceId::random() }).collect() }
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
