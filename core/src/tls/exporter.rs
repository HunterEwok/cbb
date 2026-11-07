// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The TLS exporter for the pairing (RFC 8446, section 7.5), which binds
//! the CPace exchange to the TLS connection. rustls offers the exporter
//! only on its buffered connections, which need the standard library; the
//! sans-I/O connections a microcontroller uses do not have it. So the
//! connection's key log hands this crate the exporter master secret, and
//! the exporter is derived here from it.

use alloc::vec::Vec;
use core::fmt;

use hmac::{KeyInit, Mac};
use rustls::KeyLog;
use sha2::{Digest, Sha256};

use crate::error::{Error, Result};
use crate::sync::Mutex;

/// Catches the exporter master secret of a connection. Give each pairing
/// connection its own configuration with its own Exporter as the key log:
/// it keeps the secret of the last handshake it saw.
pub struct Exporter {
    secret: Mutex<Option<Vec<u8>>>,
}

impl Default for Exporter {
    fn default() -> Exporter {
        Exporter { secret: Mutex::new(None) }
    }
}

impl fmt::Debug for Exporter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Exporter")
    }
}

const LABEL: &str = "EXPORTER_SECRET";

impl KeyLog for Exporter {
    fn log(&self, label: &str, _client_random: &[u8], secret: &[u8]) {
        if label == LABEL {
            *self.secret.lock() = Some(secret.to_vec());
        }
    }

    fn will_log(&self, label: &str) -> bool {
        label == LABEL
    }
}

impl Exporter {
    /// Fills out with keying material for label and context (none and
    /// empty are the same in TLS 1.3), as Go's ExportKeyingMaterial does.
    /// It fails before the handshake has made the secret.
    pub fn export(&self, label: &[u8], context: &[u8], out: &mut [u8]) -> Result<()> {
        let guard = self.secret.lock();
        let secret = guard.as_deref().ok_or_else(|| Error::msg("the TLS handshake is not over"))?;
        // Derive-Secret(Secret, label, "") with the hash of no messages.
        let derived = expand_label(secret, label, &Sha256::digest([]), 32)?;
        let out_len = out.len();
        let okm = expand_label(&derived, b"exporter", &Sha256::digest(context), out_len)?;
        out.copy_from_slice(&okm);
        Ok(())
    }
}

/// HKDF-Expand-Label with SHA-256 (RFC 8446, section 7.1).
#[allow(clippy::expect_used, reason = "HMAC takes a key of any length, so this never fails")]
fn expand_label(secret: &[u8], label: &[u8], context: &[u8], len: usize) -> Result<Vec<u8>> {
    let full = label.len().saturating_add(6);
    if len > 255 * 32 || full > 255 || context.len() > 255 {
        return Err(Error::msg("the exporter cannot make that much"));
    }
    // All three are checked small above.
    let mut info = Vec::with_capacity(full.saturating_add(context.len()).saturating_add(4));
    info.extend_from_slice(&(len as u16).to_be_bytes());
    info.push(full as u8);
    info.extend_from_slice(b"tls13 ");
    info.extend_from_slice(label);
    info.push(context.len() as u8);
    info.extend_from_slice(context);
    // HKDF-Expand (RFC 5869, section 2.3).
    let mut out = Vec::with_capacity(len.saturating_add(32));
    let mut prev: Vec<u8> = Vec::new();
    let mut i = 1u8;
    while out.len() < len {
        let mut mac = hmac::Hmac::<Sha256>::new_from_slice(secret).expect("HMAC takes any key");
        mac.update(&prev);
        mac.update(&info);
        mac.update(&[i]);
        prev = mac.finalize().into_bytes().to_vec();
        out.extend_from_slice(&prev);
        i = i.wrapping_add(1);
    }
    out.truncate(len);
    Ok(out)
}
