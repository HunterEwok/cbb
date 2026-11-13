// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The phone's watch as an admin of the group (docs/protocol.md, section
//! 10, "Watches"): the watch's admin key signs on the watch, which is shown
//! each record or command whole and checks it before it signs, so the
//! phone hands it the bytes, not a digest. The app carries them over its
//! link to the watch with the callback here.

use cbb_core::certs;
use cbb_core::error::{Error, Result};
use cbb_core::identity::ExternalKey;
use serde::Deserialize;

/// The app's link to its watch: sends the body (len bytes) to sign to the
/// watch and writes its ECDSA P-256 signature over the body's SHA-256,
/// DER, to sig (72 bytes of room) with its length in sig_len; 0 when the
/// watch signed, another value when it refused or went away.
pub type SignBodyFn = unsafe extern "C" fn(
    ctx: *mut core::ffi::c_void,
    body: *const u8,
    len: usize,
    sig: *mut u8,
    sig_len: *mut usize,
) -> i32;

/// The request of `cbb_member_manage_watch`.
#[derive(Deserialize)]
pub(crate) struct WatchArgs {
    pub(crate) action: String,
    #[serde(default)]
    pub(crate) device: String,
    /// The watch's own device ID, which its commands are by.
    pub(crate) watch: String,
    /// The watch's admin key point, SEC1 uncompressed.
    #[serde(with = "certs::b64")]
    pub(crate) public: Vec<u8>,
    /// The watch's admin CA, DER, as add_watch made it.
    #[serde(with = "certs::b64")]
    pub(crate) admin_ca: Vec<u8>,
    /// With action: the quick action's name.
    #[serde(default)]
    pub(crate) name: String,
    #[serde(default = "crate::member::ten_seconds")]
    pub(crate) timeout_ms: u64,
}

/// The watch's admin key behind the app's link: it signs what it sees, and
/// never a bare digest.
pub(crate) struct BodyKey {
    pub(crate) public: Vec<u8>,
    pub(crate) f: SignBodyFn,
    pub(crate) ctx: usize,
}

impl ExternalKey for BodyKey {
    fn public(&self) -> Vec<u8> {
        self.public.clone()
    }

    fn sign_digest(&self, _: &[u8; 32]) -> Result<Vec<u8>> {
        Err(Error::msg("the watch signs only a record or command it is shown"))
    }

    fn sign_data(&self, data: &[u8]) -> Result<Vec<u8>> {
        let mut sig = [0u8; 72];
        let mut n = 0usize;
        // SAFETY: the app gave a callback valid with ctx through the call
        // that reads len bytes at body and writes at most 72 at sig.
        let rc = unsafe {
            (self.f)(self.ctx as *mut core::ffi::c_void, data.as_ptr(), data.len(), sig.as_mut_ptr(), &mut n)
        };
        match sig.get(..n) {
            Some(s) if rc == 0 && n > 0 => Ok(s.to_vec()),
            _ => Err(Error::msg(format!("the watch did not sign (code {rc})"))),
        }
    }
}
