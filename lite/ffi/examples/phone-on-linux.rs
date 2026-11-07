// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The Aurora app through the C functions of src/join.rs and
//! src/member.rs, on Linux with a software key, for internal/service's
//! TestFFIJoiner. It listens on -addr (host:port), prints the QR code's
//! text after "QR: ", takes connections until one joins, and prints
//! "Joined <device> <group tag>"; with -admin it offers an admin key too,
//! and prints "Admin CA <base64>" when the member made it an admin. With
//! -dir, it then runs the member there,
//! dialing each -peer: it prints "WRITE <kind> <text>" for each text for
//! the clipboard, "IDENTITY <certificate in base64>" when an admin renewed
//! its certificate, "CHANGE <copy as JSON>" for each copy that became the
//! group's, "PEER <peer as JSON>" for each peer whose hello it took,
//! "COMMAND <token> <command as JSON>" for each command for the phone
//! itself, and "LOG <line>" for each log line, and takes "COPY <text>",
//! "PEERS" and "CALL <request as JSON>" on standard input, answering
//! "PEERS <count>" and "ANSWER <answer as JSON>" (cbb_member_call).
//!
//!   phone-on-linux -addr 127.0.0.1:8764 -name phone -dir /tmp/p -peer 127.0.0.1:8765

use std::io::{Read, Write};
use std::net::TcpListener;
use std::process::ExitCode;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use cbb_ffi::{
    cbb_free, cbb_join_accept, cbb_join_feed, cbb_join_finish, cbb_join_free, cbb_join_new, cbb_join_new_admin,
    cbb_member_call, cbb_member_start,
};
use p256::ecdsa::SigningKey;
use p256::ecdsa::signature::hazmat::PrehashSigner;

/// The key's signing callback, as the app's KeyStore::sign is.
/// The secret for sealed messages.
const SEAL: [u8; 32] = [9u8; 32];

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
    let admin = args.iter().any(|a| a == "-admin");
    let admin_key = SigningKey::from_slice(&[8u8; 32]).expect("a valid scalar");
    let admin_public = STANDARD.encode(admin_key.verifying_key().to_sec1_point(false).as_bytes());
    let ln = TcpListener::bind(&addr).expect("listen");
    // The secret for sealed messages, and its public key for the device
    // record, as the app has them.
    let seal_req =
        serde_json::json!({"abi": cbb_ffi::abi(), "op": "seal_public", "args": {"secret": STANDARD.encode(SEAL)}});
    let seal = serde_json::from_slice::<serde_json::Value>(&cbb_ffi::call(seal_req.to_string().into_bytes()))
        .map(|v| v["ok"]["key"].clone())
        .unwrap_or_default();
    let mut req =
        serde_json::json!({"name": name, "os": "aurora", "public": public_b64, "seal": seal, "addrs": [addr]});
    if admin {
        req["admin_public"] = admin_public.into();
    }
    let req = req.to_string();
    let (mut ans, mut n) = (std::ptr::null_mut(), 0usize);
    let ctx = &key as *const SigningKey as *mut _;
    let admin_ctx = &admin_key as *const SigningKey as *mut _;
    // SAFETY: req, ans and n live for the call; the keys outlive the joiner.
    let j = unsafe {
        if admin {
            cbb_join_new_admin(req.as_ptr(), req.len(), sign, ctx, sign, admin_ctx, &mut ans, &mut n)
        } else {
            cbb_join_new(req.as_ptr(), req.len(), sign, ctx, &mut ans, &mut n)
        }
    };
    let created = take(ans, n);
    if j.is_null() {
        eprintln!("phone-on-linux: {created}");
        return ExitCode::FAILURE;
    }
    println!("QR: {}", created["ok"]["qr"].as_str().unwrap_or_default());
    let mut joined = serde_json::Value::Null;
    'conns: for conn in ln.incoming() {
        let Ok(mut sock) = conn else { continue };
        // SAFETY: j is the joiner, used by this thread only.
        let a = take(unsafe { cbb_join_accept(j, &mut n) }, n);
        if a.get("error").is_some() {
            eprintln!("phone-on-linux: {a}");
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
                    joined = ok["joined"].clone();
                    let tag = cbb_core::certs::Cert::parse(&b64(&joined["group_ca"]))
                        .map(|ca| cbb_core::certs::tag(&ca))
                        .unwrap_or_default();
                    if let Some(ca) = joined["admin_ca"].as_str() {
                        println!("Admin CA {ca}");
                    }
                    println!("Joined {} {tag}", joined["device"].as_str().unwrap_or_default());
                    break 'conns;
                }
                Some("failed") => {
                    eprintln!("phone-on-linux: an attempt failed: {}", ok["error"]);
                    continue 'conns;
                }
                _ if got == 0 => continue 'conns,
                _ => {}
            }
        }
    }
    // SAFETY: j is freed once.
    unsafe { cbb_join_free(j) };
    if joined.is_null() {
        return ExitCode::FAILURE;
    }
    let Some(dir) = arg("-dir") else { return ExitCode::SUCCESS };
    let peers: Vec<String> =
        args.windows(2).filter(|w| w.first().is_some_and(|a| a == "-peer")).filter_map(|w| w.get(1).cloned()).collect();
    run_member(&key, &public_b64, &name, &dir, peers, &joined)
}

unsafe extern "C" fn event(_: *mut core::ffi::c_void, ev: *const u8, len: usize) {
    // SAFETY: the library gives len readable bytes at ev for the call.
    let v: serde_json::Value =
        unsafe { serde_json::from_slice(std::slice::from_raw_parts(ev, len)).unwrap_or_default() };
    let s = |k: &str| v[k].as_str().unwrap_or_default().replace('\n', "\\n");
    match v["type"].as_str() {
        Some("write") => println!("WRITE {} {}", s("kind"), s("text")),
        Some("log") => println!("LOG {}", s("line")),
        Some("identity") => println!("IDENTITY {}", s("cert")),
        Some("copy") => println!("CHANGE {}", v["copy"]),
        Some("peer") => println!("PEER {}", v["peer"]),
        Some("command") => println!("COMMAND {} {}", v["token"], v["command"]),
        _ => {}
    }
}

/// Runs the member as the app does once it joined, until standard input
/// ends.
fn run_member(
    key: &SigningKey,
    public_b64: &str,
    name: &str,
    dir: &str,
    peers: Vec<String>,
    joined: &serde_json::Value,
) -> ExitCode {
    let records = b64(&joined["records"]);
    if std::fs::create_dir_all(dir).is_err() || std::fs::write(format!("{dir}/records.json"), records).is_err() {
        eprintln!("phone-on-linux: cannot write the records in {dir}");
        return ExitCode::FAILURE;
    }
    let req = serde_json::json!({
        "dir": dir, "name": name, "os": "aurora", "os_version": "Aurora OS 5.1.5", "version": "0.5.0",
        "device": joined["device"], "public": public_b64,
        "seal": STANDARD.encode(SEAL), "cert": joined["cert"], "issuer": joined["issuer"],
        "group_ca": joined["group_ca"], "roots": joined["roots"], "peers": peers, "mdns": false,
    })
    .to_string();
    let (mut ans, mut n) = (std::ptr::null_mut(), 0usize);
    let ctx = key as *const SigningKey as *mut core::ffi::c_void;
    // SAFETY: req, ans and n live for the call; the key outlives the member,
    // which runs until the process ends.
    let m = unsafe { cbb_member_start(req.as_ptr(), req.len(), sign, event, ctx, &mut ans, &mut n) };
    let started = take(ans, n);
    if m.is_null() {
        eprintln!("phone-on-linux: {started}");
        return ExitCode::FAILURE;
    }
    let call = |req: String| -> serde_json::Value {
        let mut n = 0usize;
        // SAFETY: m runs; req and n live for the call.
        take(unsafe { cbb_member_call(m, req.as_ptr(), req.len(), &mut n) }, n)
    };
    for line in std::io::stdin().lines() {
        let Ok(line) = line else { break };
        if let Some(text) = line.strip_prefix("COPY ") {
            let a = call(serde_json::json!({ "op": "copy", "args": { "text": text } }).to_string());
            if a.get("error").is_some() {
                eprintln!("phone-on-linux: {a}");
            }
        } else if line == "PEERS" {
            let a = call(serde_json::json!({ "op": "peers" }).to_string());
            println!("PEERS {}", a["ok"]["peers"].as_array().map_or(0, Vec::len));
        } else if let Some(req) = line.strip_prefix("CALL ") {
            println!("ANSWER {}", call(req.to_string()));
        }
    }
    ExitCode::SUCCESS
}
