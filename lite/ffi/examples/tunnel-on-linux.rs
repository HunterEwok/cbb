// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The phones' tunnel (src/tunnel.rs) as a program, for the Go tests that
//! run it against a Go hub, Go clients and a Go forwarder (internal/tunnel,
//! TestRustPhone*): each line on stdin is a request, each answer a line on
//! stdout. At the end of stdin every tunnel stops with the process.
//!
//! `hub_register` goes to `cbb_tunnel_register`, `relay_start` to
//! `cbb_tunnel_relay` and `relay_credentials` to
//! `cbb_tunnel_relay_credentials`, with a software key in place of the
//! app's: `test_key`, its PKCS#8 DER. The relay's events wait for `test_events`,
//! which answers `{"events"}`.

use std::io::{BufRead, Write};

use base64::Engine;
use p256::ecdsa::SigningKey;
use p256::ecdsa::signature::hazmat::PrehashSigner;
use p256::pkcs8::DecodePrivateKey;

/// The key's signing callback, as the app's would be.
unsafe extern "C" fn sign(ctx: *mut core::ffi::c_void, digest: *const u8, sig: *mut u8, sig_len: *mut usize) -> i32 {
    // SAFETY: ctx is a key leaked for the process; digest is 32 bytes and
    // sig has 72 bytes of room, as cbb_core.h says.
    unsafe {
        let key = &*(ctx as *const SigningKey);
        let d = std::slice::from_raw_parts(digest, 32);
        let Ok(s): Result<p256::ecdsa::Signature, _> = key.sign_prehash(d) else { return 1 };
        let der = s.to_der();
        let b = der.as_bytes();
        std::ptr::copy_nonoverlapping(b.as_ptr(), sig, b.len());
        sig_len.write(b.len());
    }
    0
}

/// The relay links' events, until test_events takes them.
static EVENTS: std::sync::Mutex<Vec<serde_json::Value>> = std::sync::Mutex::new(Vec::new());

unsafe extern "C" fn event(_: *mut core::ffi::c_void, e: *const u8, len: usize) {
    // SAFETY: the library gives len bytes at e for the call.
    let b = unsafe { std::slice::from_raw_parts(e, len) };
    if let (Ok(v), Ok(mut q)) = (serde_json::from_slice(b), EVENTS.lock()) {
        q.push(v);
    }
}

fn signed(mut req: serde_json::Value) -> Vec<u8> {
    let der = req
        .as_object_mut()
        .and_then(|o| o.remove("test_key"))
        .and_then(|k| k.as_str().and_then(|k| base64::engine::general_purpose::STANDARD.decode(k).ok()))
        .unwrap_or_default();
    let Ok(key) = SigningKey::from_pkcs8_der(&der) else {
        return br#"{"error":{"message":"test_key is not a PKCS#8 P-256 key"}}"#.to_vec();
    };
    let ctx = Box::into_raw(Box::new(key)) as *mut core::ffi::c_void;
    let body = serde_json::to_vec(&req).unwrap_or_default();
    let mut n = 0usize;
    // SAFETY: body is readable, n writable; the key stays for the process.
    let p = unsafe {
        if req["op"] == "relay_start" {
            cbb_ffi::cbb_tunnel_relay(body.as_ptr(), body.len(), sign, event, ctx, &mut n)
        } else if req["op"] == "relay_credentials" {
            cbb_ffi::cbb_tunnel_relay_credentials(body.as_ptr(), body.len(), sign, ctx, &mut n)
        } else {
            cbb_ffi::cbb_tunnel_register(body.as_ptr(), body.len(), sign, ctx, &mut n)
        }
    };
    if p.is_null() {
        return b"{}".to_vec();
    }
    // SAFETY: the library gave n bytes at p, freed with cbb_free.
    let a = unsafe { std::slice::from_raw_parts(p, n).to_vec() };
    // SAFETY: as above.
    unsafe { cbb_ffi::cbb_free(p, n) };
    a
}

fn main() {
    let stdin = std::io::stdin();
    let mut out = std::io::stdout();
    for line in stdin.lock().lines() {
        let Ok(line) = line else { break };
        let req: serde_json::Value = serde_json::from_str(&line).unwrap_or_default();
        let answer = if req["op"] == "hub_register" || req["op"] == "relay_start" || req["op"] == "relay_credentials" {
            signed(req)
        } else if req["op"] == "test_events" {
            let events: Vec<serde_json::Value> = EVENTS.lock().map(|mut q| q.drain(..).collect()).unwrap_or_default();
            serde_json::to_vec(&serde_json::json!({ "ok": { "events": events } })).unwrap_or_default()
        } else {
            cbb_ffi::tunnel::call(line.as_bytes())
        };
        if out.write_all(&answer).and_then(|()| out.write_all(b"\n")).and_then(|()| out.flush()).is_err() {
            break;
        }
    }
}
