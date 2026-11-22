// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The log of the records this device signed on the records of 0.6
//! (`signed-records.json`), and signing them again once the group's root
//! voided both histories of this device's key (docs/protocol.md, section
//! 10, "Going on after two histories"). A device brought back from a backup
//! has the log of the backup, so the records it signed before the backup
//! was restored, which it cannot tell from a thief's, are not in it and
//! stay void.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::Mutex;

use cbb_core::records::body::Kind;
use cbb_core::records::{Key, KeyHash, Record, RecordId, RecordSet};
use serde::{Deserialize, Serialize};

use super::Mesh;

/// The log's file in the state directory.
pub const FILE_NAME: &str = "signed-records.json";
/// How many record IDs the log keeps, the newest.
const MAX_SIGNED: usize = 1024;

/// One writer of the log at a time.
static LOCK: Mutex<()> = Mutex::new(());

/// What the log holds: the IDs of the records this device signed, in hex,
/// for each that it signed again after a resolve the new record's, and the
/// voided records it did not sign that it told of.
#[derive(Default, Serialize, Deserialize)]
struct Log {
    #[serde(default)]
    signed: Vec<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    again: BTreeMap<String, String>,
    /// The voided records it did not sign, once told.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    told: BTreeSet<String>,
}

fn id_text(id: &RecordId) -> String {
    crate::certs::hex(&id.0)
}

fn load(dir: &Path, log: &dyn Fn(&str)) -> Log {
    match std::fs::read(dir.join(FILE_NAME)) {
        Ok(data) => serde_json::from_slice(&data).unwrap_or_else(|e| {
            log(&format!("the log of the records this device signed does not read: {e}"));
            Log::default()
        }),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Log::default(),
        Err(e) => {
            log(&format!("cannot read the log of the records this device signed: {e}"));
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
        log(&format!("cannot save the log of the records this device signed: {}", e.for_log()));
    }
}

/// The IDs of the records key `h` signed that the set holds.
pub(super) fn ids_of(set: &RecordSet, h: &KeyHash) -> BTreeSet<RecordId> {
    set.ids().filter(|id| set.get(id).is_some_and(|r| r.body().signer == *h)).copied().collect()
}

/// Adds to the log the records key `h` signed that the set holds now and
/// did not before.
pub(super) fn note(dir: &Path, set: &RecordSet, h: &KeyHash, before: &BTreeSet<RecordId>, log: &dyn Fn(&str)) {
    let mut new: Vec<&Record> = ids_of(set, h).difference(before).filter_map(|id| set.get(id)).collect();
    if new.is_empty() {
        return;
    }
    new.sort_by_key(|r| r.body().seq);
    let _one = LOCK.lock().unwrap();
    let mut l = load(dir, log);
    l.signed.extend(new.iter().map(|r| id_text(&r.id())));
    save(dir, l, log);
}

/// What a device signs again: what admits, removes, freezes, thaws and
/// sets, with what it saw left for the writer to fill.
fn again(kind: &Kind) -> Option<Kind> {
    let mut k = kind.clone();
    match &mut k {
        Kind::Device(d) => d.seen = Vec::new(),
        Kind::Revoke(rm) | Kind::Freeze(rm) => rm.seen = Vec::new(),
        Kind::Thaw { seen, .. } | Kind::Copies { seen, .. } | Kind::Hubs { seen, .. } => *seen = Vec::new(),
        Kind::Settings(_) => {}
        _ => return None,
    }
    Some(k)
}

impl Mesh {
    /// Signs again, once the group's root voided both histories of this
    /// device's admin key, each voided record the log says this device
    /// signed, in their order; the voided records it did not sign, as a
    /// thief's or its own from before a backup was restored, it only counts
    /// in the log, for the user to do again what was theirs. Gives how many
    /// it signed again.
    pub fn resign_voided(&self) -> usize {
        let Some(admin) = self.own.admin.clone() else { return 0 };
        let h = Key::es256(admin.public()).hash();
        let log = |s: &str| self.logf(s);
        let voided = {
            let set = self.set.lock().unwrap();
            let st = set.state();
            if st.two_histories(&h) {
                return 0;
            }
            set.voided_of(&st, &h)
        };
        if voided.is_empty() {
            return 0;
        }
        let l = {
            let _one = LOCK.lock().unwrap();
            load(&self.dir, &log)
        };
        let (mut signed, mut others) = (BTreeMap::new(), BTreeSet::new());
        for r in &voided {
            let old = id_text(&r.id());
            if l.again.contains_key(&old) {
                continue;
            }
            if !l.signed.contains(&old) {
                if !l.told.contains(&old) {
                    others.insert(old);
                }
                continue;
            }
            let Some(kind) = again(&r.body().kind) else { continue };
            let now = crate::uptime::wall_ms().max(0) as u64;
            match self.write_by(&*admin, |set, k| {
                let st = set.state();
                set.write_record(&st, k, kind, now).map_err(|e| crate::error::Error::msg(e.to_string()))
            }) {
                Ok(out) => {
                    if let Some(n) = out.last() {
                        signed.insert(old, id_text(&n.id()));
                    }
                }
                Err(e) => {
                    log(&format!("cbb: signing a voided record again: {}", e.for_log()));
                    break;
                }
            }
        }
        let n = signed.len();
        if n > 0 || !others.is_empty() {
            let _one = LOCK.lock().unwrap();
            let mut cur = load(&self.dir, &log);
            cur.again.extend(signed);
            cur.told.extend(others.iter().cloned());
            save(&self.dir, cur, &log);
        }
        if n > 0 {
            log(&format!(
                "cbb: the group's root voided both histories of this device's key; signed {n} of its records again"
            ));
        }
        if !others.is_empty() {
            log(&format!(
                "cbb: {} voided records of this device's key were not signed on this device since its last backup, or were a thief's; they stay void, so do again what was yours (cbb status lists the devices)",
                others.len()
            ));
        }
        n
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use cbb_core::identity::ExternalKey as _;
    use cbb_core::records::body::{self, Device, Kind, ROLE_MEMBER};
    use cbb_core::records::{Body, Key, Record, RecordSet, Recovery, key::ALG_SLH_DSA, pq};
    use p256::ecdsa::SigningKey;

    use super::super::tests::{own, root};
    use super::super::*;
    use crate::own::Which;

    fn device(name: &str, seed: u8) -> Device {
        let k = SigningKey::from_slice(&[seed; 32]).unwrap();
        let mut d =
            Device::new(Key::es256(k.verifying_key().to_sec1_point(false).as_bytes().to_vec()), name, ROLE_MEMBER);
        d.rights = body::RIGHT_READ | body::RIGHT_SEND;
        d
    }

    /// An admin computer brought back from a backup signs again at a seq
    /// it had signed: once the root voids both histories, it signs again
    /// what its log says it signed, and leaves void the record it did not
    /// sign since the backup, telling of it once.
    #[test]
    fn an_admin_signs_again_what_a_resolve_voided() {
        let dir = std::env::temp_dir().join(format!("cbb-mesh-resign-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let mut o = own(&dir);
        let admin = o.make(&dir, Which::Admin).unwrap();
        let root = root();
        let (k1, k2) = pq::recovery_keys(&[1; 32]).unwrap();
        let k1 = SigningKey::from(&k1).verifying_key().to_sec1_point(false).as_bytes().to_vec();
        let mut set = RecordSet::new(
            Key::es256(root.public()),
            Recovery::new(Key::es256(k1), Key::new(ALG_SLH_DSA, k2.public())).unwrap(),
        );
        let now = crate::uptime::wall_ms() as u64;
        let mut me = Device::new(o.member_key(), "desk", ROLE_MEMBER);
        me.rights = body::RIGHT_READ | body::RIGHT_SEND;
        let st = set.state();
        set.write_record(&st, &root, Kind::device(me), now - 3000).unwrap();
        crate::writers::make_admin(&mut set, &root, "desk", &admin.public(), now - 2900).unwrap();
        let local = crate::set::local_key(&dir).unwrap();
        crate::set::save(&dir, &set, &local).unwrap();
        let lines = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
        let l2 = lines.clone();
        let m = Mesh::open(&dir, o, Arc::new(move |s: &str| l2.lock().unwrap().push(s.to_string()))).unwrap();

        // The admin admits attic, which the log keeps; the old copy of the
        // computer signed cellar at the same seq.
        let attic = m.write(|set, k| {
            let st = set.state();
            Ok(set.write_record(&st, k, Kind::device(device("attic", 20)), now - 2000).unwrap())
        });
        let first = attic.unwrap().pop().unwrap();
        let twin =
            Record::sign(Body { kind: Kind::device(device("cellar", 21)), ..first.body().clone() }, &*admin).unwrap();
        m.set.lock().unwrap().insert_all([twin.clone()]);
        assert!(m.state().two_histories(&Key::es256(admin.public()).hash()));
        assert_eq!(m.resign_voided(), 0, "nothing while the two histories last");

        // The root voids both.
        m.write_by(&root, |set, k| crate::writers::resolve(set, k, now - 1000)).unwrap();
        let st = m.state();
        assert!(crate::writers::find(&st, "attic").is_err() && crate::writers::find(&st, "cellar").is_err());
        assert_eq!(m.resign_voided(), 1);
        let st = m.state();
        assert!(crate::writers::find(&st, "attic").is_ok(), "signed again");
        assert!(crate::writers::find(&st, "cellar").is_err(), "not signed here since the backup");
        assert_eq!(m.resign_voided(), 0, "once");
        let told = lines.lock().unwrap().iter().filter(|l| l.contains("stay void")).count();
        assert_eq!(told, 1, "{:?}", lines.lock().unwrap());
        m.close();
    }
}
