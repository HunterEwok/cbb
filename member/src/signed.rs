// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The log of the records this device signed (`signed.json`, as Go's
//! service keeps it), and signing them again once the group's root voided
//! both histories of this device's key (docs/protocol.md, section 10,
//! "Going on after two histories"). A device brought back from a backup has
//! the log of the backup, so the records it signed before the backup was
//! restored, which it cannot tell from a thief's, are not in it.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Mutex;

use cbb_core::authority::{self, Body, Hash};
use serde::{Deserialize, Serialize};

use crate::admin::{Admin, signer};
use crate::node::Node;
use crate::records::Record;

/// The log's file in the state directory.
pub const FILE_NAME: &str = "signed.json";
/// How many record IDs the log keeps, the newest: as many as a set keeps of
/// one signer.
const MAX_SIGNED: usize = 1024;

/// One writer of the log at a time.
static LOCK: Mutex<()> = Mutex::new(());

/// What signed.json holds: the IDs of the records this device signed, and
/// for each of them a root's resolve voided, the record it signed again.
#[derive(Default, Serialize, Deserialize)]
struct Log {
    #[serde(default)]
    signed: Vec<Hash>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    again: BTreeMap<String, Hash>,
}

fn load(dir: &Path, log: &dyn Fn(&str)) -> Log {
    match std::fs::read(dir.join(FILE_NAME)) {
        Ok(data) => serde_json::from_slice(&data).unwrap_or_else(|e| {
            log(&format!("cbb: reading the log of the records this device signed: {e}"));
            Log::default()
        }),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Log::default(),
        Err(e) => {
            log(&format!("cbb: reading the log of the records this device signed: {e}"));
            Log::default()
        }
    }
}

fn save(dir: &Path, mut l: Log, log: &dyn Fn(&str)) {
    if l.signed.len() > MAX_SIGNED {
        l.signed.drain(..l.signed.len() - MAX_SIGNED);
    }
    let res = serde_json::to_vec(&l)
        .map_err(|e| crate::error::Error::with("cannot encode the log", e))
        .and_then(|data| crate::files::write_atomic(&dir.join(FILE_NAME), &data, 0o600));
    if let Err(e) = res {
        log(&format!("cbb: saving the log of the records this device signed: {}", e.for_log()));
    }
}

/// Adds the records this device signed to the log.
pub fn note(dir: &Path, rs: &[Record], log: &dyn Fn(&str)) {
    let _one = LOCK.lock().unwrap();
    let mut l = load(dir, log);
    l.signed.extend(rs.iter().map(Record::id));
    save(dir, l, log);
}

/// The types of record a device signs again after the root voided both
/// histories of its key: what admits, removes, freezes and sets. A claim is
/// made again by its user, and the apps sign checkpoints by themselves.
const RESIGNABLE: &[&str] = &[
    authority::TYPE_DEVICE,
    authority::TYPE_REVOKE,
    authority::TYPE_FREEZE,
    authority::TYPE_THAW,
    authority::TYPE_HUBS,
    authority::TYPE_SETTINGS,
    authority::TYPE_COPIES,
];

/// Signs again, once the group's root voided both histories of this
/// device's key, each voided record the log says this device signed, in
/// their order, as Go's resignVoided. The voided records it did not sign,
/// as a thief's or its own from before a backup was restored, it only
/// counts in the log, for the user to do again what was theirs.
pub fn resign_voided(dir: &Path, node: &Node) {
    let log = |s: &str| node.logf(s);
    let Ok(Some(s)) = signer(dir, &node.identity()) else { return };
    let me = s.hash();
    let voided = {
        let records = node.records();
        let rs = records.lock().unwrap();
        if rs.two_histories(&me) {
            return;
        }
        rs.voided(&me)
    };
    if voided.is_empty() {
        return;
    }
    let l = {
        let _one = LOCK.lock().unwrap();
        load(dir, &log)
    };
    let admin = Admin { node, dir };
    let (mut again, mut others) = (BTreeMap::new(), 0usize);
    for r in &voided {
        let old = r.id();
        if l.again.contains_key(&old.text()) {
            continue;
        }
        if !l.signed.contains(&old) {
            others += 1;
            continue;
        }
        let Ok(mut b) = Body::parse(&r.body) else { continue };
        if !RESIGNABLE.contains(&b.kind.as_str()) {
            continue;
        }
        (b.seq, b.prev, b.seen) = (0, None, Vec::new());
        match admin.sign_body(&s, b) {
            Ok(nr) => {
                again.insert(old.text(), nr.id());
            }
            Err(e) => {
                log(&format!("cbb: signing a voided record again: {}", e.for_log()));
                break;
            }
        }
    }
    let n = again.len();
    if n > 0 {
        let _one = LOCK.lock().unwrap();
        let mut cur = load(dir, &log);
        cur.again.extend(again);
        save(dir, cur, &log);
        log(&format!(
            "cbb: the group's root voided both histories of this device's key; signed {n} of its records again"
        ));
    }
    if others > 0 {
        log(&format!(
            "cbb: {others} voided records of this device's key were not signed on this device since its last backup, or were a thief's; they stay void, so do again what was yours (cbb status lists the devices)"
        ));
    }
}
