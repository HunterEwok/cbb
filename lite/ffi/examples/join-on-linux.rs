// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The Aurora app's joining through the C functions of src/join.rs, on
//! Linux with a software key, for internal/service's TestFFIJoiner: it
//! listens on -addr (host:port), prints the QR code's text after
//! "QR: ", takes connections until one joins, and prints
//! "Joined <device> <group tag>".
//!
//!   join-on-linux -addr 127.0.0.1:8764 -name phone

use std::io::{Read, Write};
use std::net::TcpListener;
use std::process::ExitCode;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use cbb_ffi::{cbb_free, cbb_join_accept, cbb_join_feed, cbb_join_finish, cbb_join_free, cbb_join_new};
use p256::ecdsa::SigningKey;
use p256::ecdsa::signature::hazmat::PrehashSigner;

/// The key's signing callback, as the app's KeyStore::sign is.
unsafe extern "C" fn sign(ctx: *mut core::ffi::c_void, digest: *const u8, sig: *mut u8, sig_len: *mut usize) -> i32 {
    // SAFETY: ctx is the key main keeps alive; digest is 32 bytes and sig
    // has 72 bytes of room, as cbb_core.h says.
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

/// Takes an answer of the library as JSON.
fn take(p: *mut u8, n: usize) -> serde_json::Value {
    // SAFETY: p and n are an answer of the library, given back once.
    let v = unsafe { serde_json::from_slice(std::slice::from_raw_parts(p, n)).unwrap_or_default() };
    // SAFETY: as above.
    unsafe { cbb_free(p, n) };
    v
}

fn b64(v: &serde_json::Value) -> Vec<u8> {
    STANDARD.decode(v.as_str().unwrap_or_default()).unwrap_or_default()
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let arg = |name: &str| args.iter().position(|a| a == name).and_then(|i| args.get(i + 1)).cloned();
    let addr = arg("-addr").unwrap_or_else(|| "127.0.0.1:8764".into());
    let name = arg("-name").unwrap_or_else(|| "phone".into());
    let key = SigningKey::from_slice(&[7u8; 32]).expect("a valid scalar");
    let public = key.verifying_key().to_sec1_point(false);
    let public_b64 = STANDARD.encode(public.as_bytes());
    let ln = TcpListener::bind(&addr).expect("listen");
    let req = serde_json::json!({"name": name, "os": "aurora", "public": public_b64, "addrs": [addr]}).to_string();
    let (mut ans, mut n) = (std::ptr::null_mut(), 0usize);
    // SAFETY: req, ans and n live for the call; the key outlives the joiner.
    let j =
        unsafe { cbb_join_new(req.as_ptr(), req.len(), sign, &key as *const SigningKey as *mut _, &mut ans, &mut n) };
    let created = take(ans, n);
    if j.is_null() {
        eprintln!("join-on-linux: {created}");
        return ExitCode::FAILURE;
    }
    println!("QR: {}", created["ok"]["qr"].as_str().unwrap_or_default());
    let mut code = ExitCode::FAILURE;
    'conns: for conn in ln.incoming() {
        let Ok(mut sock) = conn else { continue };
        // SAFETY: j is the joiner, used by this thread only.
        let a = take(unsafe { cbb_join_accept(j, &mut n) }, n);
        if a.get("error").is_some() {
            eprintln!("join-on-linux: {a}");
            break;
        }
        let mut buf = vec![0u8; 16 << 10];
        loop {
            let got = sock.read(&mut buf).unwrap_or(0);
            // SAFETY: buf holds got bytes; j as above.
            let step = take(unsafe { cbb_join_feed(j, buf.as_ptr(), got, 0, &mut n) }, n);
            let ok = &step["ok"];
            let _ = sock.write_all(&b64(&ok["send"]));
            match ok["state"].as_str() {
                Some("joined") => {
                    // SAFETY: j as above.
                    let last = take(unsafe { cbb_join_finish(j, 1, &mut n) }, n);
                    let _ = sock.write_all(&b64(&last["ok"]["send"]));
                    let joined = &ok["joined"];
                    let tag = cbb_core::certs::Cert::parse(&b64(&joined["group_ca"]))
                        .map(|ca| cbb_core::certs::tag(&ca))
                        .unwrap_or_default();
                    println!("Joined {} {tag}", joined["device"].as_str().unwrap_or_default());
                    code = ExitCode::SUCCESS;
                    break 'conns;
                }
                Some("failed") => {
                    eprintln!("join-on-linux: an attempt failed: {}", ok["error"]);
                    continue 'conns;
                }
                _ if got == 0 => continue 'conns,
                _ => {}
            }
        }
    }
    // SAFETY: j is freed once.
    unsafe { cbb_join_free(j) };
    code
}
