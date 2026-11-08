// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! Device keys that the machine's hardware holds, the TPM or a Mac's Secure
//! Enclave: the key never leaves the hardware, and the identity file keeps
//! the blob that loads it. A Mac's enclave cbb uses itself (sekey.rs); the
//! TPM through cbb-helper (docs/design.md, "The service and its helper"),
//! which makes the keys, loads them and signs with them.

use std::sync::Arc;
use std::time::Duration;

use cbb_core::certs::b64;
use serde::{Deserialize, Serialize};

use crate::control::Header;
use crate::error::{Context, Error, Result};
use crate::helper::Helper;
use crate::identity::{ExternalKey, HeldKey};

/// How long the helper may take for a key: a TPM is slow, and the first
/// use loads the key.
const KEY_TIME: Duration = Duration::from_secs(30);

/// What the helper answers about a key, and what it takes to name one, as
/// the identity file keeps it.
#[derive(Serialize, Deserialize, Default)]
struct Wire {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    key_tpm: Option<serde_json::Value>,
    #[serde(with = "b64::opt", default, skip_serializing_if = "Option::is_none")]
    key_se: Option<Vec<u8>>,
    #[serde(with = "b64::opt", default, skip_serializing_if = "Option::is_none")]
    public: Option<Vec<u8>>,
    #[serde(with = "b64::opt", default, skip_serializing_if = "Option::is_none")]
    digest: Option<Vec<u8>>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    why: String,
}

impl Wire {
    fn of(held: &HeldKey) -> Wire {
        match held {
            HeldKey::Tpm(b) => Wire { key_tpm: Some(b.clone()), ..Wire::default() },
            HeldKey::SecureEnclave(b) => Wire { key_se: Some(b.clone()), ..Wire::default() },
        }
    }

    fn held(&self) -> Result<Option<HeldKey>> {
        Ok(match (&self.key_tpm, &self.key_se) {
            (Some(b), None) => Some(HeldKey::Tpm(b.clone())),
            (None, Some(b)) => Some(HeldKey::SecureEnclave(b.clone())),
            (None, None) => None,
            _ => return Err(Error::msg("the helper named a key in two places")),
        })
    }
}

fn call(helper: &Helper, op: &str, req: &Wire) -> Result<Wire> {
    let payload = serde_json::to_vec(req).context("cannot encode a key request")?;
    let ans = helper.call(Header { op: op.into(), ..Default::default() }, payload, KEY_TIME)?;
    serde_json::from_slice(&ans.payload).context("the helper's answer about a key is not understood")
}

/// A secret sealed by the TPM or the Secure Enclave, as Go's state files
/// keep it (keyseal.Blob): the blob in tpm or se, or the secret itself
/// where secrets stay in files.
#[derive(Serialize, Deserialize, Default, Clone, PartialEq, Debug)]
pub struct Sealed {
    #[serde(with = "b64", default, skip_serializing_if = "Vec::is_empty")]
    pub secret: Vec<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tpm: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub se: Option<serde_json::Value>,
}

impl Sealed {
    /// Whether the hardware holds the secret.
    pub fn is_sealed(&self) -> bool {
        self.tpm.is_some() || self.se.is_some()
    }
}

/// Seals secret with the device's hardware through cbb-helper, as Go's
/// group.Sealer; None where secrets stay in files: no helper beside cbb,
/// or no TPM or Secure Enclave that seals.
pub fn seal(secret: &[u8]) -> Result<Option<Sealed>> {
    #[cfg(target_os = "macos")]
    {
        // As Go's group.Sealer: CBB_TPM=off keeps secrets in files, and an
        // enclave that cannot seal does too.
        if tpm_off() || !crate::sekey::available() {
            return Ok(None);
        }
        return Ok(crate::sekey::seal(secret)
            .ok()
            .map(|b| Sealed { se: Some(serde_json::Value::String(b64_std(&b))), ..Sealed::default() }));
    }
    #[allow(unreachable_code)]
    let Some(helper) = crate::helper::shared() else { return Ok(None) };
    let req = Sealed { secret: secret.to_vec(), ..Sealed::default() };
    let payload = serde_json::to_vec(&req).context("cannot encode a sealing request")?;
    let ans = helper.call(Header { op: "seal".into(), ..Default::default() }, payload, KEY_TIME)?;
    let b: Sealed = serde_json::from_slice(&ans.payload).context("the helper's sealed secret is not understood")?;
    Ok(b.is_sealed().then_some(Sealed { secret: Vec::new(), ..b }))
}

/// Opens what seal sealed, through cbb-helper.
pub fn unseal(b: &Sealed) -> Result<Vec<u8>> {
    if let Some(se) = &b.se {
        let raw = se
            .as_str()
            .and_then(base64_decode)
            .ok_or_else(|| Error::msg("the secret the Secure Enclave sealed is not understood"))?;
        #[cfg(target_os = "macos")]
        return crate::sekey::unseal(&raw);
        #[cfg(not(target_os = "macos"))]
        {
            let _ = raw;
            return Err(Error::msg("the secret is sealed by a Mac's Secure Enclave; was the state copied from a Mac?"));
        }
    }
    let helper = crate::helper::shared().ok_or_else(|| {
        Error::msg("the key is sealed by the TPM or the Secure Enclave, which cbb opens only through cbb-helper, and there is no cbb-helper beside cbb")
    })?;
    let req = Sealed { secret: Vec::new(), ..b.clone() };
    let payload = serde_json::to_vec(&req).context("cannot encode an unsealing request")?;
    let ans = helper.call(Header { op: "unseal".into(), ..Default::default() }, payload, KEY_TIME)?;
    let open: Sealed =
        serde_json::from_slice(&ans.payload).context("the helper's unsealed secret is not understood")?;
    if open.secret.is_empty() {
        return Err(Error::msg("the helper unsealed no secret"));
    }
    Ok(open.secret)
}

/// A key on a YubiKey, which cbb signs with itself after its PIN
/// (piv.rs): the recovery key a root phone put there. The key whose
/// certificate's public key has the hash key_hash signs; public is that
/// key, from the admin CA the records carry for it.
pub struct CardKey {
    key_hash: [u8; 32],
    pin: String,
    public: Vec<u8>,
}

impl CardKey {
    /// The card's key for key_hash, whose public key is public.
    pub fn new(key_hash: [u8; 32], pin: &str, public: Vec<u8>) -> Result<CardKey> {
        Ok(CardKey { key_hash, pin: pin.to_string(), public })
    }
}

impl ExternalKey for CardKey {
    fn public(&self) -> Vec<u8> {
        self.public.clone()
    }

    fn sign_digest(&self, digest: &[u8; 32]) -> Result<Vec<u8>> {
        crate::piv::sign_with_card(&self.key_hash, &self.pin, &self.public, digest)
    }
}

/// A device key in the hardware, which the helper signs with.
pub struct HardwareKey {
    helper: Arc<Helper>,
    held: HeldKey,
    public: Vec<u8>,
}

impl HardwareKey {
    fn from(helper: Arc<Helper>, ans: Wire) -> Result<Option<HardwareKey>> {
        let Some(held) = ans.held()? else { return Ok(None) };
        let public = ans.public.unwrap_or_default();
        if public.len() != 65 || public[0] != 4 {
            return Err(Error::msg("the helper's key is not a P-256 key"));
        }
        Ok(Some(HardwareKey { helper, held, public }))
    }
}

impl ExternalKey for HardwareKey {
    fn public(&self) -> Vec<u8> {
        self.public.clone()
    }

    fn sign_digest(&self, digest: &[u8; 32]) -> Result<Vec<u8>> {
        let req = Wire { digest: Some(digest.to_vec()), ..Wire::of(&self.held) };
        let payload = serde_json::to_vec(&req).context("cannot encode a key request")?;
        let ans = self.helper.call(Header { op: "key-sign".into(), ..Default::default() }, payload, KEY_TIME)?;
        Ok(ans.payload)
    }

    fn held(&self) -> Option<HeldKey> {
        Some(self.held.clone())
    }
}

/// A key in this Mac's Secure Enclave, which cbb signs with itself.
#[cfg(target_os = "macos")]
struct EnclaveKey(crate::sekey::Key);

#[cfg(target_os = "macos")]
impl ExternalKey for EnclaveKey {
    fn public(&self) -> Vec<u8> {
        self.0.public()
    }

    fn sign_digest(&self, digest: &[u8; 32]) -> Result<Vec<u8>> {
        self.0.sign_digest(digest)
    }

    fn held(&self) -> Option<HeldKey> {
        Some(HeldKey::SecureEnclave(self.0.blob()))
    }
}

/// Whether CBB_TPM=off keeps new keys and secrets out of the hardware, as
/// Go's group.TPMEnv.
#[cfg(target_os = "macos")]
fn tpm_off() -> bool {
    std::env::var("CBB_TPM").is_ok_and(|v| v == "off")
}

#[cfg(target_os = "macos")]
fn b64_std(b: &[u8]) -> String {
    #[derive(Serialize)]
    struct W<'a>(#[serde(with = "b64")] &'a [u8]);
    serde_json::to_value(W(b)).ok().and_then(|v| v.as_str().map(str::to_string)).unwrap_or_default()
}

fn base64_decode(s: &str) -> Option<Vec<u8>> {
    #[derive(Deserialize)]
    struct W(#[serde(with = "b64")] Vec<u8>);
    serde_json::from_value::<W>(serde_json::Value::String(s.to_string())).ok().map(|w| w.0)
}

/// Opens the key the identity file keeps as held: a Mac's enclave key
/// itself, a TPM key through this process's helper.
pub fn open(held: &HeldKey) -> Result<Arc<dyn ExternalKey>> {
    if let HeldKey::SecureEnclave(blob) = held {
        #[cfg(target_os = "macos")]
        return Ok(Arc::new(EnclaveKey(
            crate::sekey::Key::load(blob).map_err(|e| e.context("cannot open this device's key"))?,
        )));
        #[cfg(not(target_os = "macos"))]
        {
            let _ = blob;
            return Err(Error::msg(
                "this device's key is in a Mac's Secure Enclave; was the identity copied from a Mac?",
            ));
        }
    }
    let helper = crate::helper::shared().ok_or_else(|| {
        Error::msg("this device's key is in the TPM or the Secure Enclave, which only cbb-helper opens, and there is no cbb-helper beside cbb")
    })?;
    let ans = call(&helper, "key-public", &Wire::of(held)).map_err(|e| e.context("cannot open this device's key"))?;
    let key = HardwareKey::from(helper, ans)?.ok_or_else(|| Error::msg("the helper did not open this device's key"))?;
    Ok(Arc::new(key))
}

/// Makes a new device key in the hardware, where there is a helper and the
/// machine has a TPM or a Secure Enclave it may use; None otherwise, with
/// why when something failed, and the key then goes into the identity file.
pub fn new_device_key() -> (Option<Arc<dyn ExternalKey>>, String) {
    // A Mac has no TPM: its enclave, if it has one, takes the key.
    #[cfg(target_os = "macos")]
    {
        if tpm_off() {
            return (None, "CBB_TPM is off".into());
        }
        if !crate::sekey::available() {
            return (None, String::new());
        }
        return match crate::sekey::Key::new() {
            Ok(k) => (Some(Arc::new(EnclaveKey(k))), String::new()),
            Err(e) => (None, e.for_log()),
        };
    }
    #[allow(unreachable_code)]
    let Some(helper) = crate::helper::shared() else { return (None, String::new()) };
    match call(&helper, "key-new", &Wire::default()) {
        Ok(ans) => {
            let why = ans.why.clone();
            match HardwareKey::from(helper, ans) {
                Ok(Some(k)) => (Some(Arc::new(k)), String::new()),
                Ok(None) => (None, why),
                Err(e) => (None, e.for_log()),
            }
        }
        Err(e) => (None, e.for_log()),
    }
}
