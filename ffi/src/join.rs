// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! What the C functions beside `cbb_call` share (include/cbb_core.h): the
//! app's signing and event callbacks, a key behind the signing callback,
//! the answers' JSON and a QR code's modules. A phone makes a group in
//! src/found.rs and pairs through src/window.rs and src/joiner.rs.

use cbb_core::error::{Error, Result};
#[cfg(feature = "member")]
use cbb_core::identity::ExternalKey;
use serde::Serialize;

/// The app's signing callback: ECDSA P-256 over the 32-byte digest, DER,
/// written to sig (72 bytes of room) with its length in sig_len; 0 when it
/// signed.
pub type SignFn =
    unsafe extern "C" fn(ctx: *mut core::ffi::c_void, digest: *const u8, sig: *mut u8, sig_len: *mut usize) -> i32;

/// The app's events' callback: JSON at event, len bytes, on any thread.
pub type EventFn = unsafe extern "C" fn(ctx: *mut core::ffi::c_void, event: *const u8, len: usize);

/// The largest DER signature of P-256.
#[cfg(feature = "member")]
const MAX_SIG: usize = 72;

#[cfg(feature = "member")]
pub(crate) struct AppKey {
    pub(crate) public: Vec<u8>,
    pub(crate) sign: SignFn,
    pub(crate) ctx: usize,
}

#[cfg(feature = "member")]
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

/// The wall clock in milliseconds since 1970.
#[cfg(feature = "member")]
pub(crate) fn wall_ms() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| i64::try_from(d.as_millis()).unwrap_or(0)).unwrap_or(0)
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
