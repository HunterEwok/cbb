// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! What the C functions beside `cbb_call` share (include/cbb_core.h): the
//! app's signing and event callbacks, a key behind the signing callback,
//! the answers' JSON, a QR code's modules, and a group of 0.5 made with the
//! app's root key (`cbb_group_new` without a folder). A phone pairs on 0.6
//! through src/window.rs and src/joiner.rs.

use std::time::{SystemTime, UNIX_EPOCH};

use cbb_core::certs;
use cbb_core::error::{Error, Result};
use cbb_core::identity::ExternalKey;
use serde::{Deserialize, Serialize};

/// The app's signing callback: ECDSA P-256 over the 32-byte digest, DER,
/// written to sig (72 bytes of room) with its length in sig_len; 0 when it
/// signed.
pub type SignFn =
    unsafe extern "C" fn(ctx: *mut core::ffi::c_void, digest: *const u8, sig: *mut u8, sig_len: *mut usize) -> i32;

/// The app's events' callback: JSON at event, len bytes, on any thread.
pub type EventFn = unsafe extern "C" fn(ctx: *mut core::ffi::c_void, event: *const u8, len: usize);

/// The largest DER signature of P-256.
const MAX_SIG: usize = 72;

pub(crate) struct AppKey {
    pub(crate) public: Vec<u8>,
    pub(crate) sign: SignFn,
    pub(crate) ctx: usize,
}

impl ExternalKey for AppKey {
    fn public(&self) -> Vec<u8> {
        self.public.clone()
    }

    fn sign_digest(&self, digest: &[u8; 32]) -> Result<Vec<u8>> {
        let mut sig = [0u8; MAX_SIG];
        let mut n = 0usize;
        // SAFETY: the app gave a callback for the joiner's lifetime that
        // reads 32 bytes at digest and writes at most MAX_SIG at sig.
        let rc = unsafe { (self.sign)(self.ctx as *mut core::ffi::c_void, digest.as_ptr(), sig.as_mut_ptr(), &mut n) };
        match sig.get(..n) {
            Some(s) if rc == 0 && n > 0 => Ok(s.to_vec()),
            _ => Err(Error::msg(format!("the device key did not sign (code {rc})"))),
        }
    }
}

pub(crate) fn wall_ms() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| i64::try_from(d.as_millis()).unwrap_or(0)).unwrap_or(0)
}

#[derive(Serialize)]
struct JoinedAnswer {
    device: String,
    #[serde(with = "certs::b64")]
    cert: Vec<u8>,
    #[serde(with = "certs::b64::opt")]
    issuer: Option<Vec<u8>>,
    #[serde(with = "certs::b64")]
    group_ca: Vec<u8>,
    #[serde(with = "certs::b64::list")]
    roots: Vec<Vec<u8>>,
    /// The records file (docs/core-api.md, "The record set").
    #[serde(with = "certs::b64")]
    records: Vec<u8>,
    /// The admin CA for the admin key, when the member made the phone an
    /// admin.
    #[serde(with = "certs::b64::opt", skip_serializing_if = "Option::is_none")]
    admin_ca: Option<Vec<u8>>,
}

#[derive(Clone, Serialize)]
pub(crate) struct ErrorAnswer {
    message: String,
    details: String,
}

impl ErrorAnswer {
    pub(crate) fn of(e: &Error) -> ErrorAnswer {
        ErrorAnswer { message: e.to_string(), details: e.details() }
    }
}

pub(crate) fn answer<T: Serialize>(ok: Result<T>) -> Vec<u8> {
    let v = match ok {
        Ok(v) => serde_json::json!({ "ok": v }),
        Err(e) => serde_json::json!({ "error": ErrorAnswer::of(&e) }),
    };
    serde_json::to_vec(&v)
        .unwrap_or_else(|_| br#"{"error":{"message":"cannot encode the answer","details":""}}"#.to_vec())
}

#[derive(Deserialize)]
struct NewGroupArgs {
    /// The phone's name and system, as for a join.
    name: String,
    os: String,
    /// Where the member key lives: `hardware` or `file`.
    store: String,
    /// The root key's public point, SEC1 uncompressed: the key whose
    /// callback signs.
    #[serde(with = "certs::b64")]
    root_public: Vec<u8>,
    /// The member key's public point, SEC1 uncompressed.
    #[serde(with = "certs::b64")]
    public: Vec<u8>,
    #[serde(with = "certs::b64", default)]
    seal: Vec<u8>,
}

/// A group the phone makes with its root key (cbb_core::admit::new_group),
/// from the app's request (NewGroupArgs); the answer has a join's fields,
/// so the app keeps it as it keeps a join.
pub fn new_group(request: &[u8], sign: SignFn, ctx: usize) -> Vec<u8> {
    answer((|| -> Result<JoinedAnswer> {
        let a: NewGroupArgs = serde_json::from_slice(request)
            .map_err(|e| Error::msg(format!("the group request does not decode: {e}")))?;
        if a.store != "hardware" && a.store != "file" {
            return Err(Error::msg(format!("the key store is hardware or file, not {:?}", a.store)));
        }
        let root_key = AppKey { public: a.root_public, sign, ctx };
        let own = cbb_core::admit::OwnDevice {
            name: &a.name,
            os: &a.os,
            role: "phone",
            caps: &[],
            member_point: &a.public,
            store: &a.store,
            seal: a.seal,
        };
        let g = cbb_core::admit::new_group(&root_key, &own, wall_ms())?;
        Ok(JoinedAnswer {
            device: g.device.to_string(),
            cert: g.cert.der.clone(),
            issuer: None,
            group_ca: g.root.der.clone(),
            roots: Vec::new(),
            records: g.records.to_file()?,
            admin_ca: None,
        })
    })())
}

/// The QR code's modules for text, a string of '1' (dark) and '0' per row.
#[cfg(feature = "member")]
pub(crate) fn modules(text: &str) -> Result<Vec<String>> {
    let code = qrcode::QrCode::with_error_correction_level(text.as_bytes(), qrcode::EcLevel::M)
        .map_err(|e| Error::msg(format!("cannot make the QR code: {e}")))?;
    let width = code.width();
    let colors = code.to_colors();
    Ok(colors
        .chunks(width.max(1))
        .map(|row| row.iter().map(|c| if *c == qrcode::Color::Dark { '1' } else { '0' }).collect())
        .collect())
}
