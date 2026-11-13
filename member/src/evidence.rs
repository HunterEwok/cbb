// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! Attestations of member keys (docs/protocol.md, section 17, "Evidence",
//! "TPM evidence" and "Revoked attestations"). The group's root checks the
//! evidence its peers send and records what it proves in their device
//! records; a computer whose member key is in a TPM sends its own and opens
//! the root's credential. The checks of Android's Key Attestation and of
//! the TPM's structures, the TPM itself and the fetching of the revocation
//! list are cbb-helper's (internal/helper/attest.go); without a helper a
//! member neither checks nor sends evidence.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;

use cbb_core::certs::{self, Cert, DeviceId, b64};
use cbb_core::identity::HeldKey;
use cbb_core::release::{self, File, Seen};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::control::Header;
use crate::error::{Context, Error, Result};
use crate::files::write_atomic;
use crate::node::Node;

/// How long the helper may take for an attestation: a TPM is slow.
const HELPER_TIME: Duration = Duration::from_secs(60);

/// The file in the state directory that keeps the last revocation list
/// taken, as Go's statusFile.
pub const STATUS_FILE: &str = "attest-status.json";

/// What an attestation shows of a key: its store and kind, why it is not
/// proven, and the proof the device record keeps.
#[derive(Deserialize, Default, Debug, Clone)]
pub struct Proven {
    #[serde(default)]
    pub store: String,
    #[serde(default)]
    pub kind: String,
    #[serde(default)]
    pub why: String,
    #[serde(default)]
    pub proof: String,
}

/// The credential the root sent a device, and what it expects back.
#[derive(Deserialize)]
struct Challenge {
    evidence: Value,
    #[serde(with = "b64")]
    value: Vec<u8>,
    proof: String,
}

struct Pending {
    value: Vec<u8>,
    cert: Vec<u8>,
    proof: String,
}

#[derive(Serialize, Deserialize)]
struct Kept {
    keys: File,
    status: File,
    seen: Seen,
}

#[derive(Deserialize)]
struct Secret {
    #[serde(with = "b64::opt", default)]
    secret: Option<Vec<u8>>,
}

/// The attestations a member checks and sends.
pub struct Attestations {
    dir: PathBuf,
    /// The serial numbers the revocation list taken last revokes.
    revoked: Mutex<Vec<String>>,
    /// The last Android evidence of each peer, checked again when the list
    /// changes.
    last: Mutex<HashMap<DeviceId, (Vec<Cert>, Value)>>,
    /// The credentials sent, by the device they went to.
    pending: Mutex<HashMap<DeviceId, Pending>>,
    /// Whether the TPM opens a credential now.
    opening: AtomicBool,
}

/// Bytes as a JSON string in base64, as Go's []byte.
fn b64_value(b: &[u8]) -> Value {
    #[derive(Serialize)]
    struct W<'a>(#[serde(with = "b64")] &'a [u8]);
    serde_json::to_value(W(b)).unwrap_or_default()
}

fn call(op: &str, req: &impl Serialize) -> Result<Vec<u8>> {
    let helper = crate::helper::shared().ok_or_else(|| Error::msg("attestations need cbb-helper beside cbb"))?;
    let payload = serde_json::to_vec(req).context("cannot encode an attestation request")?;
    Ok(helper.call(Header { op: op.into(), ..Default::default() }, payload, HELPER_TIME)?.payload)
}

/// The TPM's one opening of a credential, until dropped.
struct Opening<'a>(&'a AtomicBool);

impl<'a> Opening<'a> {
    fn start(flag: &'a AtomicBool) -> Option<Opening<'a>> {
        flag.compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst).ok().map(|_| Opening(flag))
    }
}

impl Drop for Opening<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::SeqCst);
    }
}

impl Attestations {
    /// The attestations of the member whose state is in dir, with the list
    /// kept there.
    pub fn new(dir: &Path) -> Arc<Attestations> {
        let a = Attestations {
            dir: dir.to_path_buf(),
            revoked: Mutex::new(Vec::new()),
            last: Mutex::new(HashMap::new()),
            pending: Mutex::new(HashMap::new()),
            opening: AtomicBool::new(false),
        };
        a.load_status();
        Arc::new(a)
    }

    /// Whether this member holds the group's root.
    fn is_root(&self, node: &Node) -> bool {
        matches!(crate::admin::signer(&self.dir, &node.identity()), Ok(Some(s)) if s.root)
    }

    /// Takes an evidence message from the peer from, away from the
    /// connection's thread, and logs what fails.
    pub fn received(self: &Arc<Self>, node: &Arc<Node>, from: &DeviceId, e: &Value) {
        let (a, n, from, e) = (self.clone(), Arc::downgrade(node), from.clone(), e.clone());
        std::thread::spawn(move || {
            let Some(node) = n.upgrade() else { return };
            let chain = node.chain_of(&from);
            if let Err(err) = a.check(&node, &from, &chain, &e) {
                node.logf(&format!("cbb: the attestation from {from}: {}", err.for_log()));
            }
        });
    }

    fn check(&self, node: &Node, from: &DeviceId, chain: &[Cert], e: &Value) -> Result<()> {
        let Some(leaf) = chain.first() else { return Ok(()) };
        if e["key"] != "member" {
            return Ok(()); // from a newer version
        }
        match e["format"].as_str().unwrap_or_default() {
            "android-key" => {
                if !self.is_root(node) {
                    return Ok(());
                }
                self.last.lock().unwrap().insert(from.clone(), (chain.to_vec(), e.clone()));
                self.android(node, from, leaf, e)
            }
            "tpm" => self.tpm(node, from, leaf, e),
            "tpm-credential" => self.credential(node, from, leaf, e),
            "tpm-activated" => self.activated(node, from, leaf, e),
            _ => Ok(()),
        }
    }

    fn android(&self, node: &Node, from: &DeviceId, leaf: &Cert, e: &Value) -> Result<()> {
        let revoked = self.revoked.lock().unwrap().clone();
        let req = serde_json::json!({
            "evidence": e,
            "spki": b64_value(&leaf.spki),
            "tag": certs::tag(&node.identity().group_ca),
            "revoked": revoked,
        });
        let p: Proven = serde_json::from_slice(&call("attest-android", &req)?)
            .context("the helper's answer about an attestation is not understood")?;
        self.record(node, from, leaf, &p)
    }

    fn record(&self, node: &Node, from: &DeviceId, leaf: &Cert, p: &Proven) -> Result<()> {
        let admin = crate::admin::Admin { node, dir: &self.dir };
        if let Some(line) = admin.record_evidence(from.as_str(), &leaf.key_hash(), p)? {
            node.logf(&line);
        }
        Ok(())
    }

    /// Checks, on the root, the TPM attestation a peer sent and sends it the
    /// credential.
    fn tpm(&self, node: &Node, from: &DeviceId, leaf: &Cert, e: &Value) -> Result<()> {
        if !self.is_root(node) {
            return Ok(());
        }
        let req = serde_json::json!({
            "evidence": e,
            "spki": b64_value(&leaf.spki),
            "tag": certs::tag(&node.identity().group_ca),
        });
        let c: Challenge = serde_json::from_slice(&call("attest-tpm", &req)?)
            .context("the helper's answer about an attestation is not understood")?;
        self.pending
            .lock()
            .unwrap()
            .insert(from.clone(), Pending { value: c.value, cert: leaf.der.clone(), proof: c.proof });
        node.send_to(from, cbb_core::wire::evidence(&c.evidence));
        Ok(())
    }

    /// Opens, with this device's TPM, the credential the group's root sent,
    /// and sends back what it held. Only the root sends one.
    fn credential(&self, node: &Node, from: &DeviceId, leaf: &Cert, e: &Value) -> Result<()> {
        if !node.records().lock().unwrap().is_root_member(from.as_str(), &leaf.key_hash()) {
            return Err(Error::msg("a TPM credential from a device that is not the group's root"));
        }
        // One at a time: the TPM opens a credential in a few steps.
        let Some(_opening) = Opening::start(&self.opening) else {
            return Err(Error::msg("a TPM credential while the TPM opens another"));
        };
        let back: Value = serde_json::from_slice(&call("tpm-activate", e)?)
            .context("the helper's answer about a TPM credential is not understood")?;
        node.send_to(from, cbb_core::wire::evidence(&back));
        Ok(())
    }

    /// Records, on the root, a peer's member key as proven in a TPM when it
    /// sent back the credential's value.
    fn activated(&self, node: &Node, from: &DeviceId, leaf: &Cert, e: &Value) -> Result<()> {
        let Some(p) = self.pending.lock().unwrap().remove(from) else {
            return Err(Error::msg("an activated TPM credential that this device did not send"));
        };
        let got: Secret =
            serde_json::from_value(e.clone()).map_err(|_| Error::msg("a TPM answer that is not understood"))?;
        let same =
            |a: &[u8], b: &[u8]| a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0;
        if !same(&p.value, got.secret.as_deref().unwrap_or_default()) || !same(&p.cert, &leaf.der) {
            return Err(Error::msg("invalid attestation: the TPM did not open the credential"));
        }
        self.record(
            node,
            from,
            leaf,
            &Proven { store: "proven".into(), kind: "tpm".into(), proof: p.proof, ..Proven::default() },
        )
    }

    /// Hands the node this device's TPM evidence of its member key, which it
    /// sends each peer after the hellos, when the key is in a TPM whose
    /// maker put an EK certificate in it.
    pub fn send_own(&self, node: &Node) {
        let ident = node.identity();
        let Some(HeldKey::Tpm(blob)) = ident.external.as_ref().and_then(|k| k.held()) else { return };
        let req = serde_json::json!({"held": {"key_tpm": blob}, "tag": certs::tag(&ident.group_ca)});
        let e: Result<Value> = call("tpm-evidence", &req)
            .and_then(|b| serde_json::from_slice(&b).context("the helper's TPM evidence is not understood"));
        match e {
            Ok(e) if e["format"].as_str().is_some_and(|f| !f.is_empty()) => node.set_evidence(vec![e]),
            Ok(_) => {}
            Err(err) => node.logf(&format!("cbb: the TPM's attestation of the member key: {}", err.for_log())),
        }
    }

    /// Takes the list kept in the state directory, when it still checks
    /// out: it is checked again from scratch, as the one seen last.
    fn load_status(&self) {
        let Ok(data) = std::fs::read(self.dir.join(STATUS_FILE)) else { return };
        let Ok(k) = serde_json::from_slice::<Kept>(&data) else { return };
        let roots = crate::update::release_roots();
        if let Ok((st, _)) =
            release::check_status(&k.keys, &k.status, &roots, crate::update::now_ms(), &Seen::default())
        {
            *self.revoked.lock().unwrap() = st.android_revoked;
        }
    }

    /// Fetches the mirror's list, takes it when it checks out and is not
    /// older than the kept one, and checks the peers' evidence again when
    /// it changed.
    fn fetch_status(&self, node: &Node) -> Result<()> {
        let path = self.dir.join(STATUS_FILE);
        let kept_seen = std::fs::read(&path)
            .ok()
            .and_then(|d| serde_json::from_slice::<Kept>(&d).ok())
            .map(|k| k.seen)
            .unwrap_or_default();
        #[derive(Deserialize)]
        struct Files {
            keys: File,
            status: File,
        }
        let f: Files = serde_json::from_slice(&call("attest-status", &serde_json::json!({}))?)
            .context("the revocation list's files do not decode")?;
        let roots = crate::update::release_roots();
        let (st, seen) = release::check_status(&f.keys, &f.status, &roots, crate::update::now_ms(), &kept_seen)?;
        if seen == kept_seen {
            return Ok(()); // the same list
        }
        let data =
            serde_json::to_vec(&Kept { keys: f.keys, status: f.status, seen }).context("cannot encode the list")?;
        write_atomic(&path, &data, 0o600)?;
        let n = st.android_revoked.len();
        *self.revoked.lock().unwrap() = st.android_revoked;
        node.logf(&format!(
            "cbb: took the revocation list of Android attestations of {}, {n} certificates",
            crate::node::date(st.time_ms / 1000)
        ));
        let peers: Vec<(DeviceId, (Vec<Cert>, Value))> =
            self.last.lock().unwrap().iter().map(|(k, v)| (k.clone(), v.clone())).collect();
        for (id, (chain, e)) in peers {
            if let Some(leaf) = chain.first()
                && let Err(err) = self.android(node, &id, leaf, &e)
            {
                node.logf(&format!("cbb: checking the attestation of {id} again: {}", err.for_log()));
            }
        }
        Ok(())
    }

    /// Keeps the revocation list current on the group's root: it fetches
    /// the mirror's when the service starts and every day after
    /// (CBB_TEST_STATUS_EVERY milliseconds in tests), until the node is
    /// gone. It does nothing while no root keys are pinned or there is no
    /// helper.
    pub fn status_loop(self: &Arc<Self>, node: Weak<Node>) {
        if crate::update::release_roots().is_empty() || crate::helper::shared().is_none() {
            return;
        }
        let every = std::env::var("CBB_TEST_STATUS_EVERY")
            .ok()
            .and_then(|v| v.parse().ok())
            .map_or(Duration::from_secs(24 * 3600), Duration::from_millis);
        let a = self.clone();
        std::thread::spawn(move || {
            loop {
                let Some(n) = node.upgrade() else { return };
                if a.is_root(&n)
                    && let Err(e) = a.fetch_status(&n)
                {
                    n.logf(&format!("cbb: fetching the revocation list of Android attestations: {}", e.for_log()));
                }
                let end = crate::uptime::now() + every;
                while !n.is_closed() && crate::uptime::now() < end {
                    n.records_nap(end - crate::uptime::now());
                }
                if n.is_closed() {
                    return;
                }
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicBool;

    use super::Opening;

    /// The TPM opens one credential at a time: a second waits for none,
    /// and the next starts once the first ends.
    #[test]
    fn one_opening_at_a_time() {
        let flag = AtomicBool::new(false);
        let first = Opening::start(&flag).expect("the first opening");
        assert!(Opening::start(&flag).is_none(), "a second opening while the first runs");
        drop(first);
        assert!(Opening::start(&flag).is_some(), "no opening after the first ended");
    }
}
