// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The group's recovery secret on a YubiKey over the phone's NFC
//! (docs/protocol.md, "The recovery key on a YubiKey (0.6)"): the core speaks
//! PIV (cbb_member::piv::recovery) and the app only carries each APDU to the
//! card through a callback, with Core NFC or Android's IsoDep; or, for a
//! YubiKey on USB-C, only moves the bytes of the card's CCID interface and
//! the core frames them (cbb_member::piv::ccid).

use cbb_core::certs;
use cbb_core::error::{Error, Result};
use cbb_core::secret::Zeroizing;
use cbb_member::piv::{Card, recovery};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::join::answer;

/// The app's card. With the transport `apdu` (NFC, or a card the system
/// already speaks to): sends apdu (len bytes) and writes the answer, its
/// status word last, to out (at most out_cap bytes) and its length to
/// out_len. With `ccid_bulk` (a YubiKey's CCID interface on USB): len > 0
/// writes those bytes to the bulk-out endpoint and sets out_len to 0; len
/// 0 reads one bulk-in transfer, at most out_cap bytes, into out, with
/// out_len 0 when nothing came within about a second. Either returns 0,
/// or another value when the card is gone.
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

impl AppCard {
    fn call(&mut self, data: &[u8], out: &mut [u8]) -> cbb_member::error::Result<usize> {
        let mut n = 0usize;
        // SAFETY: the app's callback as TransmitFn says, with buffers that
        // live through the call.
        let rc = unsafe {
            (self.f)(self.ctx as *mut core::ffi::c_void, data.as_ptr(), data.len(), out.as_mut_ptr(), out.len(), &mut n)
        };
        if rc != 0 || n > out.len() {
            return Err(cbb_member::error::Error::msg(format!(
                "the YubiKey left the phone: hold it still until it is done (code {rc})"
            )));
        }
        Ok(n)
    }
}

impl cbb_member::piv::ccid::Bulk for AppCard {
    fn write(&mut self, data: &[u8]) -> cbb_member::error::Result<()> {
        if data.is_empty() {
            return Ok(());
        }
        let mut none = [0u8; 0];
        self.call(data, &mut none).map(drop)
    }

    fn read(&mut self, max: usize) -> cbb_member::error::Result<Vec<u8>> {
        let mut out = vec![0u8; max];
        let n = self.call(&[], &mut out)?;
        out.truncate(n);
        Ok(out)
    }
}

impl Card for AppCard {
    fn transmit(&mut self, apdu: &[u8]) -> cbb_member::error::Result<Vec<u8>> {
        let mut out = vec![0u8; OUT_CAP];
        let n = self.call(apdu, &mut out)?;
        out.truncate(n);
        Ok(out)
    }
}

#[derive(Deserialize)]
struct Args {
    op: String,
    #[serde(default)]
    pin: String,
    /// With seal: the recovery key, as `change_root` takes it.
    #[serde(default)]
    recovery: Value,
    /// With seal and open: the group's ID in hex, or its first 16 hex
    /// digits, which name its slot on the card.
    #[serde(default)]
    group: String,
    /// With seal: the card's management key, when it is not the
    /// factory one and not PIN-protected.
    #[serde(with = "certs::b64", default)]
    management: Vec<u8>,
    /// How the app reaches the card: `apdu` (the default) or `ccid_bulk`.
    #[serde(default)]
    transport: String,
}

fn b64(b: &[u8]) -> Value {
    #[derive(Serialize)]
    struct B<'a>(#[serde(with = "certs::b64")] &'a [u8]);
    serde_json::to_value(B(b)).unwrap_or(Value::Null)
}

/// Runs one PIV step (Args) on the app's card, where the recovery secret of
/// a group of 0.6 goes (docs/protocol.md, "The recovery key on a YubiKey
/// (0.6)"):
///
/// - `seal` seals the `recovery` key's secret (the sheet's QR code or text,
///   as `change_root` takes it) onto the card for the `group`, in the
///   first empty retired slot from 95 down, with the management key as
///   the card keeps it: `{"slot","default_key"}`;
/// - `open` opens the `group`'s after the PIN and a touch: `{"secret"}`,
///   base64, which the app hands to `change_root` as `recovery`
///   `{"secret"}` and drops.
pub(crate) fn run(request: &[u8], f: TransmitFn, ctx: usize) -> Vec<u8> {
    answer((|| -> Result<Value> {
        let a: Args = serde_json::from_slice(request)
            .map_err(|e| Error::msg(format!("the YubiKey request does not decode: {e}")))?;
        let app = AppCard { f, ctx };
        if a.transport == "pcsc" {
            return pcsc(&a);
        }
        let mut ccid;
        let mut apdu;
        let card: &mut dyn Card = match a.transport.as_str() {
            "" | "apdu" => {
                apdu = app;
                &mut apdu
            }
            "ccid_bulk" => {
                ccid = cbb_member::piv::ccid::Ccid::new(app);
                &mut ccid
            }
            other => return Err(Error::msg(format!("there is no YubiKey transport {other:?}"))),
        };
        step(card, &a)
    })())
}

/// One step (Args' op) on card.
fn step(card: &mut dyn Card, a: &Args) -> Result<Value> {
    match a.op.as_str() {
        "seal" => {
            let read = crate::member::live::recovery_read(&a.recovery)?;
            let typed = Zeroizing::new(a.management.clone());
            let mut asked = false;
            let mut ask = |_alg: u8| {
                // The key the app was given, once: a wrong one is not
                // tried again.
                if typed.is_empty() || std::mem::replace(&mut asked, true) {
                    return None;
                }
                Some(Zeroizing::new(typed.to_vec()))
            };
            let s = recovery::seal(card, &a.pin, &read.secret, tag(a)?, &mut ask)?;
            Ok(json!({ "slot": s.slot, "default_key": s.default_key }))
        }
        "open" => {
            let secret = recovery::open(card, &a.pin, Some(tag(a)?))?;
            Ok(json!({ "secret": b64(secret.as_ref()) }))
        }
        other => Err(Error::msg(format!("there is no YubiKey step {other:?}"))),
    }
}

/// The group's tag from Args' `group`: its first 16 hex digits.
fn tag(a: &Args) -> Result<&str> {
    let t = a.group.get(..cbb_core::sheet::yubikey::TAG_LEN).unwrap_or("");
    if !cbb_core::sheet::yubikey::is_tag(t) || !a.group.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(Error::msg("the YubiKey request names no group"));
    }
    Ok(t)
}

/// A step on the card pcscd reaches (the transport `pcsc`, for a phone whose
/// system runs pcscd, as Aurora OS does): `open` takes the one card with
/// the group's recovery key, so that no other card is asked for the PIN;
/// `seal` the one card that answers SELECT PIV.
fn pcsc(a: &Args) -> Result<Value> {
    if a.op == "open" {
        let secret = recovery::open_one_of(&a.pin, Some(tag(a)?))?;
        return Ok(json!({ "secret": b64(secret.as_ref()) }));
    }
    let mut card = cbb_member::piv::one_piv_card()?;
    step(card.as_mut(), a)
}
