// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! Attestations of member keys on the records of 0.6 (docs/protocol.md,
//! section 17, "Evidence on the records of 0.6"). Each evidence is one
//! `evidence` message (t 19) whose `data` is a map of its format's table
//! (`msg::member::evidence_data`); the checks of Android's Key Attestation
//! and of the TPM's structures, the TPM itself and the revocation list are
//! cbb-helper's (`crate::evidence`), which takes and gives the
//! evidence in its JSON form. The group's root records what an attestation
//! proves in the device's record (`writers::record_proven`); a computer
//! whose member key is in a TPM sends its own evidence on each connection
//! and opens the root's credential. Without a helper a member neither
//! checks nor sends evidence, but a phone that is the group's root
//! (`with_phone_attestations`) checks its peers' Android evidence itself,
//! with the core's checks and the revocation list its app hands it, when
//! its app hands it the root key: it signs no record by itself.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use cbb_core::format::cbor::Value;
use cbb_core::format::frame;
use cbb_core::identity::HeldKey;
use cbb_core::msg::member::{
    self as m, EVIDENCE_ANDROID, EVIDENCE_TPM, EVIDENCE_TPM_ACTIVATED, EVIDENCE_TPM_CREDENTIAL,
};
use cbb_core::records::KeyHash;
use cbb_core::records::body::{STORE_FILE, STORE_HARDWARE, STORE_PROVEN};
use cbb_core::records::key::DeviceId;
use serde_json::{Value as Json, json};

use super::{Live, id_text4};
use crate::discovery::Peers as _;
use crate::error::{Context, Error, Result};
use crate::evidence::{Attestations, Challenge, Proven, b64_value, call};
use crate::writers::{self, Shown};

/// The credential the root sent a device, and what it expects back.
struct Pending {
    value: Vec<u8>,
    key: KeyHash,
}

/// The attestations of the member of 0.6.
pub(super) struct Attest {
    list: Arc<Attestations>,
    /// This device's TPM evidence of its member key, as the message's
    /// format and data, once the helper made it.
    own: Mutex<Vec<(u64, Vec<u8>)>>,
    /// The credentials sent, by the device they went to.
    pending: Mutex<HashMap<DeviceId, Pending>>,
    /// The last Android evidence of each peer, checked again when the
    /// revocation list changes.
    last: Mutex<HashMap<DeviceId, Vec<u8>>>,
    /// Whether the TPM opens a credential now: one at a time.
    opening: AtomicBool,
    /// A phone's, with no helper: it keeps Android evidence until its app
    /// hands it the root key, and takes no other.
    phone: bool,
    /// On a phone, the peers whose last evidence was checked under the
    /// list held.
    checked: Mutex<HashSet<DeviceId>>,
}

/// The `evidence` message of format, attesting the key `key`, with data.
fn message(format: u64, key: &KeyHash, data: &[u8]) -> Vec<u8> {
    frame::write(&Value::Map(vec![
        (frame::FIELD_T, Value::Uint(m::T_EVIDENCE)),
        (2, Value::Uint(format)),
        (3, Value::Bytes(&key.0)),
        (4, Value::Bytes(data)),
    ]))
}

fn bytes_of(j: &Json) -> Option<Vec<u8>> {
    STANDARD.decode(j.as_str()?).ok()
}

/// A group tag as the helper writes it, 16 lowercase hex characters.
fn tag_bytes(t: &str) -> Option<Vec<u8>> {
    if t.len() != 16 {
        return None;
    }
    (0..16).step_by(2).map(|i| u8::from_str_radix(t.get(i..i + 2)?, 16).ok()).collect()
}

/// The helper's JSON evidence as the message's format and data; None for
/// a format of the helper's that 0.6 does not carry or a field that does
/// not decode.
pub(super) fn to_wire(e: &Json) -> Option<(u64, Vec<u8>)> {
    let tag = match e.get("group_tag").and_then(Json::as_str) {
        Some(t) if !t.is_empty() => Some(tag_bytes(t)?),
        _ => None,
    };
    let salt = || bytes_of(e.get("salt")?);
    let chain = || e.get("chain")?.as_array()?.iter().map(bytes_of).collect::<Option<Vec<_>>>();
    let field = |k: &str| bytes_of(e.get(k)?);
    let (format, data) = match e.get("format").and_then(Json::as_str)? {
        "android-key" => (EVIDENCE_ANDROID, encode(&tag, &salt()?, &chain()?, None)),
        "tpm" => {
            let t = e.get("tpm")?;
            let s: Vec<Vec<u8>> = ["ek", "ak", "key", "attest", "signature"]
                .iter()
                .map(|k| bytes_of(t.get(*k)?))
                .collect::<Option<_>>()?;
            (EVIDENCE_TPM, encode(&tag, &salt()?, &chain()?, Some(&s)))
        }
        "tpm-credential" => {
            let (c, s) = (field("credential")?, field("secret")?);
            (EVIDENCE_TPM_CREDENTIAL, Value::Map(vec![(1, Value::Bytes(&c)), (2, Value::Bytes(&s))]).encode())
        }
        "tpm-activated" => {
            let s = field("secret")?;
            (EVIDENCE_TPM_ACTIVATED, Value::Map(vec![(1, Value::Bytes(&s))]).encode())
        }
        _ => return None,
    };
    m::evidence_data(format, &data).ok()?;
    Some((format, data))
}

/// The data of format 1 or 2: the group tag, salt and chain, and a TPM's
/// structures.
fn encode(tag: &Option<Vec<u8>>, salt: &[u8], chain: &[Vec<u8>], tpm: Option<&[Vec<u8>]>) -> Vec<u8> {
    let mut f = Vec::new();
    if let Some(t) = tag {
        f.push((1, Value::Bytes(t)));
    }
    f.push((2, Value::Bytes(salt)));
    f.push((3, Value::Array(chain.iter().map(|c| Value::Bytes(c)).collect())));
    for (n, s) in (4u16..).zip(tpm.unwrap_or_default()) {
        f.push((n, Value::Bytes(s)));
    }
    Value::Map(f).encode()
}

/// The message's data of format as the helper's JSON evidence of the
/// member key.
pub(super) fn to_json(format: u64, v: &Value<'_>) -> Option<Json> {
    let b = |n: u16| v.get(n).and_then(Value::as_bytes).map(b64_value);
    let mut e = json!({"key": "member"});
    let tag = v.get(1).and_then(Value::as_bytes).map(cbb_core::certs::hex);
    let chain = |n: u16| -> Option<Json> {
        Some(Json::Array(v.get(n)?.as_array()?.iter().filter_map(Value::as_bytes).map(b64_value).collect()))
    };
    match format {
        EVIDENCE_ANDROID | EVIDENCE_TPM => {
            e["format"] = json!(if format == EVIDENCE_ANDROID { "android-key" } else { "tpm" });
            if let Some(t) = tag {
                e["group_tag"] = json!(t);
            }
            e["salt"] = b(2)?;
            e["chain"] = chain(3)?;
            if format == EVIDENCE_TPM {
                e["tpm"] = json!({"ek": b(4)?, "ak": b(5)?, "key": b(6)?, "attest": b(7)?, "signature": b(8)?});
            }
        }
        EVIDENCE_TPM_CREDENTIAL => {
            e["format"] = json!("tpm-credential");
            (e["credential"], e["secret"]) = (b(1)?, b(2)?);
        }
        EVIDENCE_TPM_ACTIVATED => {
            e["format"] = json!("tpm-activated");
            e["secret"] = b(1)?;
        }
        _ => return None,
    }
    Some(e)
}

/// The store and proof an attestation shows, as the device record says
/// them.
fn shown(p: &Proven) -> Shown {
    match (p.store.as_str(), p.kind.as_str()) {
        ("proven", "android-tee") => Shown::Store { store: STORE_PROVEN, proof: 1 },
        ("proven", "android-strongbox") => Shown::Store { store: STORE_PROVEN, proof: 2 },
        ("proven", "tpm") => Shown::Store { store: STORE_PROVEN, proof: 3 },
        ("hardware", "") => Shown::NotProven,
        ("hardware", _) => Shown::Store { store: STORE_HARDWARE, proof: 0 },
        _ => Shown::Store { store: STORE_FILE, proof: 0 },
    }
}

/// Equal bytes, in time that does not depend on where they differ.
fn same(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
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

impl Live {
    /// Starts the attestations: the evidence the peers send goes to them,
    /// this device's own TPM evidence goes to each peer that connects, and
    /// the group's root keeps the revocation list of Android attestations
    /// current. Nothing without cbb-helper.
    pub fn with_attestations(self: &Arc<Self>) {
        if crate::helper::shared().is_none() {
            return;
        }
        if !self.start_attest(false) {
            return;
        }
        let w: Weak<Live> = Arc::downgrade(self);
        self.mesh.on_connected(Box::new(move |peer| {
            if let Some(l) = w.upgrade() {
                l.send_own_evidence(Some(peer));
            }
        }));
        let w: Weak<Live> = Arc::downgrade(self);
        std::thread::spawn(move || {
            if let Some(l) = w.upgrade() {
                l.make_own_evidence();
            }
        });
        let w: Weak<Live> = Arc::downgrade(self);
        std::thread::spawn(move || status_loop(&w));
    }

    /// Starts the attestations of a phone, which has no helper: it keeps
    /// the Android evidence its peers send while it is the group's root
    /// and checks it when its app hands it the root key (`attest_record`),
    /// under the revocation list its app fetched (`attest_status`). It
    /// takes no TPM's; the evidence of its own key its app made
    /// ([`Live::set_own_evidence`]) goes to each peer that connects.
    pub fn with_phone_attestations(self: &Arc<Self>) {
        if !self.start_attest(true) {
            return;
        }
        let w: Weak<Live> = Arc::downgrade(self);
        self.mesh.on_connected(Box::new(move |peer| {
            if let Some(l) = w.upgrade() {
                l.send_own_evidence(Some(peer));
            }
        }));
    }

    /// The evidence of this phone's member key its app made (Android Key
    /// Attestation), as the helper's JSON gives a computer's: kept and
    /// sent in `evidence` messages (t 19) to every peer connected now and
    /// to each one that connects later; an empty list sends none.
    pub fn set_own_evidence(&self, list: &[Json]) -> Result<()> {
        let a = self.attest.get().ok_or_else(|| Error::msg("this member takes no attestations"))?;
        let wire = list
            .iter()
            .map(|e| to_wire(e).ok_or_else(|| Error::msg("an attestation does not fit the format")))
            .collect::<Result<Vec<_>>>()?;
        *a.own.lock().unwrap() = wire;
        self.send_own_evidence(None);
        Ok(())
    }

    /// Sets the attestations up and takes the peers' evidence; false when
    /// they were already.
    fn start_attest(self: &Arc<Self>, phone: bool) -> bool {
        let a = Attest {
            list: Attestations::new(self.mesh.dir()),
            own: Mutex::new(Vec::new()),
            pending: Mutex::new(HashMap::new()),
            last: Mutex::new(HashMap::new()),
            opening: AtomicBool::new(false),
            phone,
            checked: Mutex::new(HashSet::new()),
        };
        if self.attest.set(a).is_err() {
            return false;
        }
        let w: Weak<Live> = Arc::downgrade(self);
        self.mesh.on_evidence(Box::new(move |peer, _, msg| {
            let (w, peer, msg) = (w.clone(), *peer, msg.to_vec());
            // The helper may take a while (a TPM is slow): off the
            // connection's thread.
            std::thread::spawn(move || {
                if let Some(l) = w.upgrade()
                    && let Err(e) = l.evidence_from(&peer, &msg)
                {
                    l.logf(&format!("cbb: the attestation from {}: {}", id_text4(&peer), e.for_log()));
                }
            });
        }));
        true
    }

    /// Asks the helper for this device's TPM evidence of its member key,
    /// when the key is in a TPM whose maker put an EK certificate in it,
    /// and sends it to the peers connected.
    fn make_own_evidence(&self) {
        let Some(a) = self.attest.get() else { return };
        // A build for tests sends the evidence a file names (a JSON array
        // of the helper's evidence), as a phone would: the tests' Android
        // chains (internal/service, TestEvidence).
        if let Some(path) = crate::testbuild::env("CBB_TEST_OWN_EVIDENCE") {
            let all: Vec<Json> =
                std::fs::read(&path).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default();
            *a.own.lock().unwrap() = all.iter().filter_map(to_wire).collect();
            self.send_own_evidence(None);
            return;
        }
        let Some(HeldKey::Tpm(blob)) = self.mesh.own().member.held() else { return };
        let req = json!({"held": {"key_tpm": blob}, "tag": self.tag()});
        let e: Result<Json> = call("tpm-evidence", &req)
            .and_then(|b| serde_json::from_slice(&b).context("the helper's TPM evidence is not understood"));
        match e {
            Ok(e) if e["format"].as_str().is_some_and(|f| !f.is_empty()) => match to_wire(&e) {
                Some(w) => {
                    *a.own.lock().unwrap() = vec![w];
                    self.send_own_evidence(None);
                }
                None => self.logf("cbb: the TPM's attestation of the member key does not fit the format"),
            },
            Ok(_) => {}
            Err(err) => self.logf(&format!("cbb: the TPM's attestation of the member key: {}", err.for_log())),
        }
    }

    /// Sends this device's own evidence to peer, or to every peer
    /// connected.
    fn send_own_evidence(&self, peer: Option<&DeviceId>) {
        let Some(a) = self.attest.get() else { return };
        let own = a.own.lock().unwrap().clone();
        let to = match peer {
            Some(p) => vec![*p],
            None => self.mesh.connected(),
        };
        for (format, data) in &own {
            let f = message(*format, &self.mesh.own().hash(), data);
            for p in &to {
                self.mesh.send(p, f.clone());
            }
        }
    }

    /// Takes an `evidence` message from the peer.
    fn evidence_from(&self, peer: &DeviceId, msg: &[u8]) -> Result<()> {
        let Some(a) = self.attest.get() else { return Ok(()) };
        let (_, v, _) = cbb_core::msg::read_noted(msg).map_err(|r| Error::msg(r.to_string()))?;
        let format = v.get(2).and_then(Value::as_uint).unwrap_or_default();
        let key = v.get(3).and_then(Value::as_bytes).and_then(|b| <[u8; 32]>::try_from(b).ok()).map(KeyHash);
        let (Some(key), Some(data)) = (key, v.get(4).and_then(Value::as_bytes)) else { return Ok(()) };
        let d = m::evidence_data(format, data).map_err(|r| Error::msg(format!("the evidence's data: {r}")))?;
        let Some(e) = to_json(format, &d) else { return Ok(()) };
        let st = self.mesh.state();
        let Some(dev) = st.devices.iter().find(|x| x.id == *peer) else { return Ok(()) };
        if a.phone {
            // A phone keeps its root's Android evidence for its app's root
            // key, and takes no TPM's.
            if format == EVIDENCE_ANDROID && key == dev.key.hash() && st.root_device == Some(self.mesh.device()) {
                // The same evidence again (a peer sends it on each
                // connection) waits no more than it did.
                if a.last.lock().unwrap().insert(*peer, msg.to_vec()).as_deref() != Some(msg) {
                    a.checked.lock().unwrap().remove(peer);
                }
            }
            return Ok(());
        }
        match format {
            EVIDENCE_ANDROID | EVIDENCE_TPM => {
                // Evidence of another key than the sender's member key, or
                // to a device that is not the root, changes nothing.
                if key != dev.key.hash() || !self.mesh.is_root() {
                    return Ok(());
                }
                let spki = cbb_core::certs::p256_spki_of(dev.key.public());
                if format == EVIDENCE_ANDROID {
                    a.last.lock().unwrap().insert(*peer, msg.to_vec());
                    return self.check_android(peer, &key, &spki, &e);
                }
                let req = json!({"evidence": e, "spki": b64_value(&spki), "tag": self.tag()});
                let c: Challenge = serde_json::from_slice(&call("attest-tpm", &req)?)
                    .context("the helper's answer about an attestation is not understood")?;
                let (format, data) = to_wire(&c.evidence)
                    .ok_or_else(|| Error::msg("the helper's TPM credential does not fit the format"))?;
                a.pending.lock().unwrap().insert(*peer, Pending { value: c.value, key });
                self.mesh.send(peer, message(format, &key, &data));
                Ok(())
            }
            EVIDENCE_TPM_CREDENTIAL => {
                // Only from the group's root, for this device's own key.
                if st.root_device != Some(*peer) || key != self.mesh.own().hash() {
                    return Err(Error::msg("a TPM credential that is not the group's root's for this device's key"));
                }
                let Some(_opening) = Opening::start(&a.opening) else {
                    return Err(Error::msg("a TPM credential while the TPM opens another"));
                };
                let back: Json = serde_json::from_slice(&call("tpm-activate", &e)?)
                    .context("the helper's answer about a TPM credential is not understood")?;
                let (format, data) =
                    to_wire(&back).ok_or_else(|| Error::msg("the TPM's answer does not fit the format"))?;
                self.mesh.send(peer, message(format, &key, &data));
                Ok(())
            }
            EVIDENCE_TPM_ACTIVATED => {
                let Some(p) = a.pending.lock().unwrap().remove(peer) else {
                    return Err(Error::msg("an activated TPM credential that this device did not send"));
                };
                let got = d.get(1).and_then(Value::as_bytes).unwrap_or_default();
                if key != p.key || !same(&p.value, got) {
                    return Err(Error::msg("invalid attestation: the TPM did not open the credential"));
                }
                self.record(peer, &key, Shown::Store { store: STORE_PROVEN, proof: 3 }, "")
            }
            _ => Ok(()),
        }
    }

    /// Checks, on the root, a peer's Android evidence under the revocation
    /// list held, and records what it proves.
    fn check_android(&self, peer: &DeviceId, key: &KeyHash, spki: &[u8], e: &Json) -> Result<()> {
        let Some(a) = self.attest.get() else { return Ok(()) };
        let req = json!({"evidence": e, "spki": b64_value(spki), "tag": self.tag(), "revoked": a.list.revoked()});
        let p: Proven = serde_json::from_slice(&call("attest-android", &req)?)
            .context("the helper's answer about an attestation is not understood")?;
        self.record(peer, key, shown(&p), &p.why)
    }

    fn record(&self, peer: &DeviceId, key: &KeyHash, s: Shown, why: &str) -> Result<()> {
        let now = crate::uptime::wall_ms().max(0) as u64;
        if let Some(d) = self.mesh.write(|set, k| writers::record_proven(set, k, peer, key, s, now))? {
            self.log_recorded(&d, why);
        }
        Ok(())
    }

    fn log_recorded(&self, (d, store, proof): &(cbb_core::records::eval::DeviceState, u64, u64), why: &str) {
        let why = if why.is_empty() { String::new() } else { format!(": {why}") };
        self.logf(&format!(
            "cbb: the attestation of {} ({}) shows its keys {}{}{why}",
            d.name,
            id_text4(&d.id),
            crate::roster::store_name(*store),
            match proof {
                1 => " (android-tee)",
                2 => " (android-strongbox)",
                3 => " (tpm)",
                _ => "",
            }
        ));
    }
}

impl Live {
    /// How many peers' Android evidence waits, on a phone that is the
    /// group's root, for its app to hand it the root key.
    pub fn attest_pending(&self) -> usize {
        let Some(a) = self.attest.get() else { return 0 };
        let st = self.mesh.state();
        // A phone holds no root key: its app does.
        if !a.phone || st.root_device != Some(self.mesh.device()) {
            return 0;
        }
        let checked = a.checked.lock().unwrap();
        a.last
            .lock()
            .unwrap()
            .keys()
            .filter(|p| !checked.contains(*p) && st.devices.iter().any(|d| d.id == **p))
            .count()
    }

    /// Takes the revocation list's files a phone's app fetched from the
    /// mirror (keys.json and attest-status.json), when they check out and
    /// are not older than the list kept; the evidence kept waits to be
    /// checked again with it. It answers how many certificates the list
    /// revokes.
    pub fn attest_status(&self, keys: cbb_core::release::File, status: cbb_core::release::File) -> Result<usize> {
        let a = self.attest.get().ok_or_else(|| Error::msg("this member keeps no attestations"))?;
        let (n, changed) = a.list.take_status(keys, status, &|s| self.logf(s))?;
        if changed {
            a.checked.lock().unwrap().clear();
        }
        Ok(n)
    }

    /// Checks, on a phone that is the group's root, the Android evidence
    /// that waits, with the root key its app hands it (signer), and
    /// records what each proves, as the root computer's helper does; it
    /// answers how many records it signed. An evidence that proves nothing
    /// is logged and not checked again until the list changes or the peer
    /// sends another.
    pub fn attest_record(&self, signer: &dyn cbb_core::identity::ExternalKey) -> Result<usize> {
        let Some(a) = self.attest.get().filter(|a| a.phone) else { return Ok(0) };
        let st = self.mesh.state();
        if st.roots.last() != Some(&cbb_core::records::Key::es256(signer.public()).hash()) {
            return Err(Error::msg("only the group's root records what an attestation proves"));
        }
        drop(st);
        let waiting: Vec<(DeviceId, Vec<u8>)> = {
            let checked = a.checked.lock().unwrap();
            a.last.lock().unwrap().iter().filter(|(p, _)| !checked.contains(*p)).map(|(p, m)| (*p, m.clone())).collect()
        };
        let mut signed = 0;
        for (peer, msg) in waiting {
            match self.check_here(&peer, &msg, signer, &a.list.revoked()) {
                Ok(true) => signed += 1,
                Ok(false) => {}
                Err(e) => self.logf(&format!("cbb: the attestation from {}: {}", id_text4(&peer), e.for_log())),
            }
            a.checked.lock().unwrap().insert(peer);
        }
        Ok(signed)
    }

    /// Checks a peer's Android evidence message with the core's checks and
    /// records what it proves with signer; whether it signed a record.
    #[cfg(feature = "tunnel")]
    fn check_here(
        &self,
        peer: &DeviceId,
        msg: &[u8],
        signer: &dyn cbb_core::identity::ExternalKey,
        revoked: &[String],
    ) -> Result<bool> {
        let (_, v, _) = cbb_core::msg::read_noted(msg).map_err(|r| Error::msg(r.to_string()))?;
        let data = v.get(4).and_then(Value::as_bytes).unwrap_or_default();
        let d =
            m::evidence_data(EVIDENCE_ANDROID, data).map_err(|r| Error::msg(format!("the evidence's data: {r}")))?;
        let e = to_json(EVIDENCE_ANDROID, &d).ok_or_else(|| Error::msg("an attestation that is not understood"))?;
        let Some(dev) = self.mesh.state().devices.iter().find(|x| x.id == *peer).cloned() else { return Ok(false) };
        let key = dev.key.hash();
        let spki = cbb_core::certs::p256_spki_of(dev.key.public());
        let p = crate::evidence::check_android_here(&e, &spki, &self.tag(), revoked)?;
        let now = crate::uptime::wall_ms().max(0) as u64;
        let done = self.mesh.write_by(signer, |set, k| writers::record_proven(set, k, peer, &key, shown(&p), now))?;
        if let Some(d) = &done {
            self.log_recorded(d, &p.why);
        }
        Ok(done.is_some())
    }

    #[cfg(not(feature = "tunnel"))]
    fn check_here(
        &self,
        _: &DeviceId,
        _: &[u8],
        _: &dyn cbb_core::identity::ExternalKey,
        _: &[String],
    ) -> Result<bool> {
        Err(Error::msg("this build checks no Android attestation by itself"))
    }
}

/// Keeps the revocation list current on the group's root: it fetches the
/// mirror's when the service starts and every day after
/// (CBB_TEST_STATUS_EVERY milliseconds in tests), and checks the peers'
/// Android evidence again when the list changed; nothing while no root
/// keys are pinned.
fn status_loop(w: &Weak<Live>) {
    if crate::update::release_roots().is_empty() {
        return;
    }
    let every = crate::testbuild::env("CBB_TEST_STATUS_EVERY")
        .and_then(|v| v.parse().ok())
        .map_or(Duration::from_secs(24 * 3600), Duration::from_millis);
    loop {
        {
            let Some(l) = w.upgrade() else { return };
            if l.is_closed() {
                return;
            }
            if l.mesh.is_root()
                && let Some(a) = l.attest.get()
            {
                match a.list.fetch_status_with(&|s| l.logf(s)) {
                    Ok(true) => {
                        let again: Vec<(DeviceId, Vec<u8>)> =
                            a.last.lock().unwrap().iter().map(|(k, v)| (*k, v.clone())).collect();
                        for (peer, msg) in again {
                            if let Err(e) = l.evidence_from(&peer, &msg) {
                                l.logf(&format!(
                                    "cbb: checking the attestation of {} again: {}",
                                    id_text4(&peer),
                                    e.for_log()
                                ));
                            }
                        }
                    }
                    Ok(false) => {}
                    Err(e) => {
                        l.logf(&format!("cbb: fetching the revocation list of Android attestations: {}", e.for_log()))
                    }
                }
            }
        }
        let end = crate::uptime::now() + every;
        while crate::uptime::now() < end {
            match w.upgrade() {
                Some(l) if !l.is_closed() => {}
                _ => return,
            }
            std::thread::sleep((end - crate::uptime::now()).min(Duration::from_millis(200)));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The helper's JSON evidence of each format goes into the message's
    /// data and comes back as it was, with `key` `member`.
    #[test]
    fn evidence_goes_into_the_format_and_back() {
        let b = |n: u8, len: usize| STANDARD.encode(vec![n; len]);
        let android = json!({"format": "android-key", "key": "member", "group_tag": "bb2fb52c6466f1ca",
            "salt": b(1, 16), "chain": [b(2, 300), b(3, 300)]});
        let tpm = json!({"format": "tpm", "key": "member", "salt": b(1, 16), "chain": [b(2, 600)],
            "tpm": {"ek": b(4, 314), "ak": b(5, 90), "key": b(6, 90), "attest": b(7, 150), "signature": b(8, 76)}});
        let credential =
            json!({"format": "tpm-credential", "key": "member", "credential": b(9, 68), "secret": b(10, 256)});
        let activated = json!({"format": "tpm-activated", "key": "member", "secret": b(11, 32)});
        for (e, want) in [
            (&android, EVIDENCE_ANDROID),
            (&tpm, EVIDENCE_TPM),
            (&credential, EVIDENCE_TPM_CREDENTIAL),
            (&activated, EVIDENCE_TPM_ACTIVATED),
        ] {
            let (format, data) = to_wire(e).unwrap();
            assert_eq!(format, want);
            let v = m::evidence_data(format, &data).unwrap();
            assert_eq!(&to_json(format, &v).unwrap(), e, "{e}");
        }
        // A group tag of another length, a salt that is not base64 and a
        // format 0.6 does not carry go nowhere.
        assert!(
            to_wire(&json!({"format": "android-key", "group_tag": "bb2f", "salt": b(1, 16), "chain": [b(2, 3)]}))
                .is_none()
        );
        assert!(to_wire(&json!({"format": "android-key", "salt": "!", "chain": [b(2, 3)]})).is_none());
        assert!(to_wire(&json!({"format": "later", "salt": b(1, 16)})).is_none());
        // What the helper's answers show, as the record says it.
        let p = |store: &str, kind: &str| Proven { store: store.into(), kind: kind.into(), ..Proven::default() };
        assert_eq!(shown(&p("proven", "android-strongbox")), Shown::Store { store: STORE_PROVEN, proof: 2 });
        assert_eq!(shown(&p("proven", "tpm")), Shown::Store { store: STORE_PROVEN, proof: 3 });
        assert_eq!(shown(&p("hardware", "")), Shown::NotProven);
        assert_eq!(shown(&p("file", "")), Shown::Store { store: STORE_FILE, proof: 0 });
    }

    /// The TPM opens one credential at a time.
    #[test]
    fn one_opening_at_a_time() {
        let flag = AtomicBool::new(false);
        let first = Opening::start(&flag).expect("the first opening");
        assert!(Opening::start(&flag).is_none());
        drop(first);
        assert!(Opening::start(&flag).is_some());
    }
}
