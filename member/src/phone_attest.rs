// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The Android attestations a root phone checks when its app signs through
//! the core (docs/protocol.md, section 17, "Evidence" and "Revoked
//! attestations"), as the iPhone app does with its kit: the member keeps
//! the last evidence each Android peer sent and the revocation list the app
//! fetched, and when the app hands it the root key it checks them with the
//! core (cbb_core::attest) and records what they show in the peers' device
//! records. A computer's root has cbb-helper check them (src/evidence.rs).

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use cbb_core::attest::{self, Policy};
use cbb_core::certs::{Cert, DeviceId, b64};
use cbb_core::manage::{self, Attested, Signer};
use cbb_core::release::{self, File, Seen};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::{Context, Error, Result};
use crate::files::write_atomic;
use crate::node::Node;

/// The list kept in the state directory, as src/evidence.rs keeps it.
#[derive(Serialize, Deserialize)]
struct Kept {
    keys: File,
    status: File,
    seen: Seen,
}

/// An Android phone's evidence of its member key (src/evidence.rs).
#[derive(Deserialize)]
struct Evidence {
    #[serde(default)]
    format: String,
    #[serde(default)]
    key: String,
    #[serde(default)]
    group_tag: String,
    #[serde(with = "b64", default)]
    salt: Vec<u8>,
    #[serde(with = "b64::list", default)]
    chain: Vec<Vec<u8>>,
}

struct Last {
    leaf: Cert,
    evidence: Value,
    /// Checked with the list taken since.
    done: bool,
}

pub struct Attestations {
    dir: PathBuf,
    revoked: Mutex<Vec<String>>,
    last: Mutex<HashMap<DeviceId, Last>>,
}

impl Attestations {
    pub fn new(dir: &Path) -> Attestations {
        let a = Attestations { dir: dir.to_path_buf(), revoked: Mutex::default(), last: Mutex::default() };
        if let Some(k) = a.kept()
            && let Ok((st, _)) = Self::check_status(&k.keys, &k.status, &Seen::default())
        {
            *a.revoked.lock().unwrap() = st.android_revoked;
        }
        a
    }

    fn kept(&self) -> Option<Kept> {
        let data = std::fs::read(self.dir.join(crate::evidence::STATUS_FILE)).ok()?;
        serde_json::from_slice(&data).ok()
    }

    fn check_status(keys: &File, status: &File, seen: &Seen) -> Result<(release::Status, Seen)> {
        let roots = crate::update::release_roots();
        let roots: Vec<&[u8]> = roots.iter().map(Vec::as_slice).collect();
        release::check_status(keys, status, &roots, crate::update::now_ms(), seen)
    }

    /// Keeps the evidence a peer whose member certificate is leaf sent.
    pub fn received(&self, from: &DeviceId, leaf: Cert, e: &Value) {
        if e["format"] != "android-key" || e["key"] != "member" {
            return;
        }
        self.last.lock().unwrap().insert(from.clone(), Last { leaf, evidence: e.clone(), done: false });
    }

    /// Takes the revocation list's files the app fetched from the mirror,
    /// when they check out and are not older than the list kept; the
    /// evidence kept is checked again with it. It answers how many
    /// certificates the list revokes.
    pub fn take_status(&self, keys: File, status: File, log: &dyn Fn(&str)) -> Result<usize> {
        let kept_seen = self.kept().map(|k| k.seen).unwrap_or_default();
        let (st, seen) = Self::check_status(&keys, &status, &kept_seen)?;
        let n = st.android_revoked.len();
        if seen == kept_seen {
            return Ok(n); // the same list
        }
        let data = serde_json::to_vec(&Kept { keys, status, seen }).context("cannot encode the list")?;
        write_atomic(&self.dir.join(crate::evidence::STATUS_FILE), &data, 0o600)?;
        *self.revoked.lock().unwrap() = st.android_revoked;
        for l in self.last.lock().unwrap().values_mut() {
            l.done = false;
        }
        log(&format!(
            "cbb: took the revocation list of Android attestations of {}, {n} certificates",
            crate::node::date(st.time_ms / 1000)
        ));
        Ok(n)
    }

    /// How many peers' evidence waits for the root key.
    pub fn pending(&self) -> usize {
        self.last.lock().unwrap().values().filter(|l| !l.done).count()
    }

    /// Checks, as the root that s signs for, the evidence that waits and
    /// records what it shows; it answers how many records it signed. An
    /// evidence that proves nothing is logged and not checked again until
    /// the list changes or the peer sends another.
    pub fn record(&self, node: &Node, s: &Signer) -> Result<usize> {
        let tag = cbb_core::certs::tag(&node.identity().group_ca);
        let revoked = self.revoked.lock().unwrap().clone();
        let waiting: Vec<(DeviceId, Cert, Value)> = self
            .last
            .lock()
            .unwrap()
            .iter()
            .filter(|(_, l)| !l.done)
            .map(|(id, l)| (id.clone(), l.leaf.clone(), l.evidence.clone()))
            .collect();
        let mut signed = 0;
        for (id, leaf, e) in waiting {
            match self.one(node, s, &tag, &revoked, &id, &leaf, &e) {
                Ok(Some(line)) => {
                    signed += 1;
                    node.logf(&line);
                }
                Ok(None) => {}
                Err(err) if err.to_string().contains("only the group's root") => return Err(err),
                Err(err) => node.logf(&format!("cbb: the attestation from {id}: {}", err.for_log())),
            }
            if let Some(l) = self.last.lock().unwrap().get_mut(&id) {
                l.done = true;
            }
        }
        Ok(signed)
    }

    #[allow(clippy::too_many_arguments)]
    fn one(
        &self,
        node: &Node,
        s: &Signer,
        tag: &str,
        revoked: &[String],
        id: &DeviceId,
        leaf: &Cert,
        e: &Value,
    ) -> Result<Option<String>> {
        let e: Evidence =
            serde_json::from_value(e.clone()).map_err(|_| Error::msg("an attestation that is not understood"))?;
        if e.format != "android-key" || e.key != "member" {
            return Ok(None);
        }
        if !e.group_tag.is_empty() && e.group_tag != tag {
            return Err(Error::msg("invalid attestation: an attestation made for another group"));
        }
        let challenge = attest::challenge(&e.group_tag, &[], &e.salt).map_err(|i| Error::msg(i.to_string()))?;
        let test_roots = test_roots();
        let policy = Policy { strict: false, revoked, roots: test_roots.as_deref() };
        let (store, kind, proof, why) = match attest::check(&e.chain, &leaf.spki, &challenge, &policy) {
            Ok(shown) => {
                let proof = match (shown.store.as_str(), e.chain.first()) {
                    (attest::STORE_PROVEN, Some(first)) => attest::proof(first),
                    _ => String::new(),
                };
                (shown.store, shown.kind, proof, shown.why)
            }
            // Revoked: the keys may still be in hardware, as the hello says,
            // but Google no longer vouches for the chain.
            Err(i) if i.revoked => (attest::STORE_HARDWARE.to_string(), String::new(), String::new(), i.reason),
            Err(i) => return Err(Error::msg(i.to_string())),
        };
        // One record per evidence, whichever connections bring it at once.
        let _one = node.signing.lock().unwrap_or_else(|e| e.into_inner());
        let records = node.records();
        let shown = Attested { store: &store, kind: &kind, proof: &proof };
        let Some(r) = manage::evidence(
            &records.lock().unwrap(),
            s,
            id.as_str(),
            &leaf.key_hash(),
            &shown,
            crate::uptime::wall_ms(),
        )?
        else {
            return Ok(None);
        };
        node.add_own_records(std::slice::from_ref(&r));
        if !records.lock().unwrap().has(&r) {
            return Err(Error::msg("the group's records did not take the attestation's record; the log says why"));
        }
        let name = node.devices().into_iter().find(|d| d.id == id.as_str()).map(|d| d.name).unwrap_or_default();
        let why = if why.is_empty() { String::new() } else { format!(": {why}") };
        Ok(Some(format!("cbb: the attestation of {name} ({id}) shows its keys {store} ({kind}){why}")))
    }
}

/// The attestation roots a test names in CBB_TEST_ATTEST_ROOTS (a PEM file
/// of public keys), in place of Google's, as cbb-helper reads them.
fn test_roots() -> Option<Vec<Vec<u8>>> {
    let f = std::env::var_os("CBB_TEST_ATTEST_ROOTS")?;
    crate::update::read_roots(Path::new(&f)).ok()
}
