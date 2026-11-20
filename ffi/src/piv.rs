// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The group's recovery key on a YubiKey over the phone's NFC (docs/protocol.md,
//! section 10, "On a hardware key"), for an app that has no PIV of its own
//! (the HarmonyOS app): the core speaks PIV (cbb_member::piv) and the app
//! only carries each APDU to the card through a callback, as the kits' Piv
//! does with Core NFC or Android's IsoDep.

use cbb_core::certs::{self, Cert, DeviceId};
use cbb_core::error::{Error, Result};
use cbb_member::piv::{self, Card};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::join::answer;

/// The app's card: sends apdu (len bytes) and writes the answer, its
/// status word last, to out (at most out_cap bytes) and its length to
/// out_len; returns 0, or another value when the card is gone.
pub type TransmitFn = unsafe extern "C" fn(
    ctx: *mut core::ffi::c_void,
    apdu: *const u8,
    len: usize,
    out: *mut u8,
    out_cap: usize,
    out_len: *mut usize,
) -> i32;

/// The most a card answers to one APDU: 256 bytes and the status word,
/// with room for an extended answer.
const OUT_CAP: usize = 4096;

struct AppCard {
    f: TransmitFn,
    ctx: usize,
}

impl Card for AppCard {
    fn transmit(&mut self, apdu: &[u8]) -> cbb_member::error::Result<Vec<u8>> {
        let mut out = vec![0u8; OUT_CAP];
        let mut n = 0usize;
        // SAFETY: the app's callback as TransmitFn says, with buffers that
        // live through the call.
        let rc = unsafe {
            (self.f)(self.ctx as *mut core::ffi::c_void, apdu.as_ptr(), apdu.len(), out.as_mut_ptr(), OUT_CAP, &mut n)
        };
        if rc != 0 || n > OUT_CAP {
            return Err(cbb_member::error::Error::msg(format!(
                "the YubiKey left the phone: hold it still until it is done (code {rc})"
            )));
        }
        out.truncate(n);
        Ok(out)
    }
}

#[derive(Deserialize)]
struct Args {
    op: String,
    #[serde(default)]
    pin: String,
    #[serde(default)]
    slot: u8,
    /// With put: the slot's certificate; with sign: the slot's key point.
    #[serde(with = "certs::b64", default)]
    cert: Vec<u8>,
    /// With issue: this phone's member key point; with sign: the slot's
    /// key point.
    #[serde(with = "certs::b64", default)]
    public: Vec<u8>,
    #[serde(with = "certs::b64", default)]
    digest: Vec<u8>,
}

/// A member certificate a slot's key issued this phone.
#[derive(Serialize)]
struct Issued {
    slot: u8,
    #[serde(with = "certs::b64")]
    admin_ca: Vec<u8>,
    device: String,
    #[serde(with = "certs::b64")]
    cert: Vec<u8>,
    /// The slot's key point, which `cbb_member_manage_card` takes as
    /// `public`.
    #[serde(with = "certs::b64")]
    public: Vec<u8>,
}

fn b64(b: &[u8]) -> Value {
    #[derive(Serialize)]
    struct B<'a>(#[serde(with = "certs::b64")] &'a [u8]);
    serde_json::to_value(B(b)).unwrap_or(Value::Null)
}

fn pin_check(card: &mut dyn Card, pin: &str) -> Result<()> {
    piv::verify(card, pin)?;
    Ok(())
}

/// Runs one PIV step (Args) on the app's card:
///
/// - `make` checks the PIN, authenticates with the factory management key
///   and makes a key in the first free retired slot: `{"slot","key"}`, key
///   its SubjectPublicKeyInfo for `cbb_member_manage`'s `recovery_for`;
/// - `put` stores the admin CA `cert` as `slot`'s certificate: `{}`;
/// - `issue` has each recovery key the card holds issue a member
///   certificate for `public` (the PIN before each signature):
///   `{"keys":[{slot, admin_ca, device, cert, public}]}`, which
///   `cbb_restore`'s `card` takes, public the slot's key point;
/// - `sign` signs `digest` with `slot`'s key, whose point is `public`:
///   `{"sig"}`, DER.
pub(crate) fn run(request: &[u8], f: TransmitFn, ctx: usize) -> Vec<u8> {
    answer((|| -> Result<Value> {
        let a: Args = serde_json::from_slice(request)
            .map_err(|e| Error::msg(format!("the YubiKey request does not decode: {e}")))?;
        let mut card = AppCard { f, ctx };
        piv::select(&mut card)?;
        match a.op.as_str() {
            "make" => {
                pin_check(&mut card, &a.pin)?;
                piv::authenticate(&mut card, &piv::DEFAULT_MANAGEMENT_KEY)?;
                let slot = piv::free_slot(&mut card)?;
                let point = piv::generate(&mut card, slot)?;
                Ok(json!({ "slot": slot, "key": b64(&certs::p256_spki_of(&point)) }))
            }
            "put" => {
                Cert::parse(&a.cert)?;
                piv::authenticate(&mut card, &piv::DEFAULT_MANAGEMENT_KEY)?;
                piv::put_certificate(&mut card, a.slot, &a.cert)?;
                Ok(json!({}))
            }
            "issue" => {
                let keys = piv::recovery_keys(&mut card)?;
                if keys.is_empty() {
                    return Err(Error::msg(piv::NO_KEY));
                }
                let now = cbb_member::uptime::wall_ms() / 1000;
                let mut out = Vec::new();
                for (slot, ca) in keys {
                    let device = DeviceId::random();
                    let public = ca.public_key().to_vec();
                    let cert = cbb_core::issue::member(&device, &a.public, &ca, now, &mut |tbs: &[u8]| {
                        pin_check(&mut card, &a.pin)?;
                        piv::sign(&mut card, slot, &public, &certs::sha256(tbs))
                    })?;
                    out.push(Issued { slot, admin_ca: ca.der.clone(), device: device.to_string(), cert, public });
                }
                Ok(json!({ "keys": out }))
            }
            "sign" => {
                let digest: [u8; 32] =
                    a.digest.as_slice().try_into().map_err(|_| Error::msg("a digest of 32 bytes to sign"))?;
                pin_check(&mut card, &a.pin)?;
                let sig = piv::sign(&mut card, a.slot, &a.public, &digest)?;
                Ok(json!({ "sig": b64(&sig) }))
            }
            other => Err(Error::msg(format!("there is no YubiKey step {other:?}"))),
        }
    })())
}

/// What signs a manage request with a slot's key on the app's card, and
/// the card's error when it did not.
struct CardSigner {
    f: TransmitFn,
    ctx: usize,
    pin: String,
    slot: u8,
    public: Vec<u8>,
    error: std::sync::Mutex<Option<Error>>,
}

/// The sign callback of CardSigner: selects the PIV application, checks
/// the PIN and signs with the slot's key.
unsafe extern "C" fn card_sign(
    ctx: *mut core::ffi::c_void,
    digest: *const u8,
    sig: *mut u8,
    sig_len: *mut usize,
) -> i32 {
    // SAFETY: ctx is the CardSigner manage keeps alive through the call,
    // digest 32 readable bytes, as the core's SignFn says.
    let (s, digest) = unsafe { (&*(ctx as *const CardSigner), core::slice::from_raw_parts(digest, 32)) };
    let mut card = AppCard { f: s.f, ctx: s.ctx };
    let signed = (|| -> Result<Vec<u8>> {
        let digest: [u8; 32] = digest.try_into().map_err(|_| Error::msg("a digest of 32 bytes to sign"))?;
        piv::select(&mut card)?;
        pin_check(&mut card, &s.pin)?;
        piv::sign(&mut card, s.slot, &s.public, &digest)
    })();
    match signed {
        Ok(der) if der.len() <= 72 => {
            // SAFETY: sig has 72 bytes of room and sig_len is writable.
            unsafe {
                core::ptr::copy_nonoverlapping(der.as_ptr(), sig, der.len());
                sig_len.write(der.len());
            }
            0
        }
        Ok(_) => 1,
        Err(e) => {
            if let Ok(mut err) = s.error.lock() {
                *err = Some(e);
            }
            1
        }
    }
}

/// Signs a manage request (`cbb_member_manage`) with a slot's key on the
/// app's card, as the recovery key claims the group: the request adds
/// `pin` and `slot` to manage's fields, `public` the slot's key point.
/// When the card refused, the answer is the card's error.
pub(crate) fn manage(m: &crate::member::Member, request: &[u8], f: TransmitFn, ctx: usize) -> Vec<u8> {
    #[derive(Deserialize)]
    struct Card {
        #[serde(default)]
        pin: String,
        #[serde(default)]
        slot: u8,
        #[serde(with = "certs::b64", default)]
        public: Vec<u8>,
    }
    let c: Card = match serde_json::from_slice(request) {
        Ok(c) => c,
        Err(e) => return answer::<Value>(Err(Error::msg(format!("the manage request does not decode: {e}")))),
    };
    let signer = CardSigner { f, ctx, pin: c.pin, slot: c.slot, public: c.public, error: std::sync::Mutex::new(None) };
    let got = m.manage(request, card_sign, &signer as *const CardSigner as usize);
    match signer.error.into_inner().ok().flatten() {
        Some(e) => answer::<Value>(Err(e)),
        None => got,
    }
}
