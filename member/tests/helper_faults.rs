// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! cbb-helper failing under a real service (docs/design.md, "The service
//! and its helper"): a helper that crashes, hangs, never says hello or
//! writes what is not a message. The service keeps answering, within the
//! helper's time limits, makes its group with the device key in a file
//! when the helper cannot hold it, and starts a helper that stopped again.

#![cfg(unix)]

mod common;

use std::io::Write as _;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use common::*;
use serde_json::{Value, json};

/// The environment variable that turns this test program into the fake
/// helper, and says how it misbehaves; the service passes every CBB_
/// variable to its helper.
const MODE: &str = "CBB_FAKE_HELPER_MODE";

/// This test program plays cbb-helper when MODE is set; it answers on
/// descriptor 3, which the script makes its standard output, as the test
/// harness writes its own lines to standard output.
///
/// - `crash`: exits at once.
/// - `silent`: reads its requests and never answers, hello included.
/// - `garbage`: writes a line that is not a message.
/// - `hang`: says hello, then never answers.
/// - `die-on-call`: says hello, then exits at its first request.
/// - `serve`: says hello and answers the keyboard's status; a key request
///   fails, as on a computer without a TPM.
/// - `tpm`: plays a TPM: makes P-256 keys, signs digests with them, seals
///   and unseals secrets; the "blob" it hands out is the key itself, which
///   a real TPM never does.
#[test]
fn fake_helper() {
    use std::os::fd::FromRawFd;
    let Ok(mode) = std::env::var(MODE) else { return };
    // SAFETY: the script opens descriptor 3 for this process alone.
    let mut out = unsafe { std::fs::File::from_raw_fd(3) };
    let mut r = std::io::BufReader::new(std::io::stdin());
    match mode.as_str() {
        "crash" => std::process::exit(3),
        "garbage" => {
            out.write_all(b"this is not a message\n").unwrap();
            std::thread::sleep(Duration::from_secs(60));
            std::process::exit(0);
        }
        _ => {}
    }
    let write = |out: &mut std::fs::File, h: Value, payload: &[u8]| {
        let mut h = h;
        h["op"] = json!("reply");
        h["done"] = json!(true);
        h["len"] = json!(payload.len());
        let mut buf = serde_json::to_vec(&h).unwrap();
        buf.push(b'\n');
        buf.extend_from_slice(payload);
        out.write_all(&buf).unwrap();
    };
    while let Some(m) = read_any(&mut r) {
        let seq = m.h["seq"].clone();
        let op = m.h["op"].as_str().unwrap_or("").to_string();
        match (mode.as_str(), op.as_str()) {
            ("silent", _) => continue,
            (_, "hello") => {
                write(&mut out, json!({"seq": seq}), br#"{"version":"cbb fake","ops":["hello"]}"#);
            }
            ("hang", _) => continue,
            ("die-on-call", _) => std::process::exit(4),
            ("tpm", op) => {
                let (ans, err) = fake_tpm(op, &m.payload);
                let h = if err.is_empty() { json!({"seq": seq}) } else { json!({"seq": seq, "error": err}) };
                write(&mut out, h, &ans);
            }
            ("serve", "peripheral-status") => write(&mut out, json!({"seq": seq}), br#"{"keyboard":{"layout":"de"}}"#),
            ("serve", _) => write(
                &mut out,
                json!({"seq": seq, "error": "no TPM here", "detail": "no TPM here: /dev/tpmrm0 is missing"}),
                b"",
            ),
            _ => continue,
        }
    }
    std::process::exit(0);
}

/// The fake TPM's answer to op, or its error.
fn fake_tpm(op: &str, payload: &[u8]) -> (Vec<u8>, String) {
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD as B64;
    use p256::ecdsa::signature::hazmat::PrehashSigner as _;
    use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
    let req: Value = serde_json::from_slice(payload).unwrap_or(Value::Null);
    let key_of = |req: &Value| -> Option<SigningKey> {
        let b = B64.decode(req["key_tpm"]["fake"].as_str()?).ok()?;
        SigningKey::from_slice(&b).ok()
    };
    let public = |k: &SigningKey| B64.encode(VerifyingKey::from(k).to_sec1_point(false).as_bytes());
    let ans = match op {
        "key-new" => {
            let mut raw = [0u8; 32];
            std::io::Read::read_exact(&mut std::fs::File::open("/dev/urandom").unwrap(), &mut raw).unwrap();
            let k = SigningKey::from_slice(&raw).unwrap();
            json!({"key_tpm": {"fake": B64.encode(k.to_bytes())}, "public": public(&k)})
        }
        "key-public" => match key_of(&req) {
            Some(k) => json!({"key_tpm": req["key_tpm"], "public": public(&k)}),
            None => return (Vec::new(), "no such key in this TPM".into()),
        },
        "key-sign" => {
            let (Some(k), Some(d)) = (key_of(&req), req["digest"].as_str().and_then(|d| B64.decode(d).ok())) else {
                return (Vec::new(), "a bad signing request".into());
            };
            let sig: Signature = k.sign_prehash(&d).unwrap();
            return (sig.to_der().as_bytes().to_vec(), String::new());
        }
        "seal" => json!({"tpm": {"fake": req["secret"]}}),
        "unseal" => json!({"secret": req["tpm"]["fake"]}),
        _ => return (Vec::new(), format!("the fake TPM does no {op}")),
    };
    (serde_json::to_vec(&ans).unwrap(), String::new())
}

/// Reads one message from any reader, as common::read does for sockets.
fn read_any(r: &mut impl std::io::BufRead) -> Option<Msg> {
    let mut line = Vec::new();
    if r.read_until(b'\n', &mut line).ok()? == 0 {
        return None;
    }
    let h: Value = serde_json::from_slice(&line).ok()?;
    let mut payload = vec![0; h["len"].as_u64().unwrap_or(0) as usize];
    r.read_exact(&mut payload).ok()?;
    Some(Msg { h, payload })
}

/// The script that starts fake_helper, in a folder only this user writes,
/// which the service checks before it starts a helper.
fn script() -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    static SCRIPT: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();
    SCRIPT
        .get_or_init(|| {
            let dir = std::env::temp_dir().join(format!("cbbh-{}", std::process::id()));
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
            let script = dir.join("cbb-helper");
            let exe = std::env::current_exe().unwrap();
            let tmp = dir.join("cbb-helper.tmp");
            std::fs::write(
                &tmp,
                format!(
                    "#!/bin/sh\nexec '{}' --exact fake_helper --nocapture --quiet --test-threads=1 3>&1 >/dev/null\n",
                    exe.display()
                ),
            )
            .unwrap();
            std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755)).unwrap();
            // Renamed into place, so no other test forks while it is open
            // for writing (ETXTBSY).
            std::fs::rename(&tmp, &script).unwrap();
            script
        })
        .clone()
}

/// A member whose helper misbehaves as mode says.
fn with_helper(mode: &str) -> Svc {
    let s = script();
    let helper = s.to_str().unwrap();
    Svc::start("desk", &[], &[("CBB_HELPER", helper), (MODE, mode)])
}

/// The status once the group started: while its start waits for the
/// helper, the service answers that it is still starting.
fn started(svc: &Svc) -> Value {
    wait_for(
        "the group starts",
        || {
            let m = svc.ask(false, json!({"op": "status"}), b"");
            if !m.error().is_empty() {
                assert!(m.error().contains("still starting"), "{:?}", m.h);
            }
            m.error().is_empty().then(|| m.h["status"].clone())
        },
        || svc.log(),
    )
}

fn timed<T>(f: impl FnOnce() -> T) -> (T, Duration) {
    let t = Instant::now();
    let v = f();
    (v, t.elapsed())
}

/// A helper that crashes, never says hello, or writes garbage: the group is
/// made with the device key in a file, saying why, and the operations that
/// need the helper fail with a reason instead of waiting.
#[test]
fn a_helper_that_never_starts() {
    for mode in ["crash", "garbage", "silent"] {
        let svc = with_helper(mode);
        let (st, took) = timed(|| svc.ok(true, json!({"op": "new"})).h["status"].clone());
        assert_eq!(st["key_level"], "files", "{mode}: {st}");
        assert!(!st["key_problem"].as_str().unwrap_or("").is_empty(), "{mode}: {st}");
        // No longer than the helper's hello may take for the device key and
        // again for the sealing key, and a moment.
        assert!(took < Duration::from_secs(35), "{mode}: cbb new took {took:?}");
        let (e, took) = timed(|| svc.err(true, json!({"op": "keyboard", "name": "status"})));
        assert!(e.contains("cbb-helper"), "{mode}: {e}");
        assert!(took < Duration::from_secs(15), "{mode}: keyboard took {took:?}");
        // The service runs on. (A copy is not tried here: with a helper that
        // fails, the key for sealed copies is not made yet, a known gap.)
        assert_eq!(started(&svc)["role"], "member");
        assert_eq!(svc.devices().len(), 1);
    }
}

/// A helper that says hello and then never answers: the status still comes
/// within its limit for the keyboard's status, and the group is made once
/// the key request runs out.
#[test]
fn a_helper_that_hangs() {
    let svc = with_helper("hang");
    write(&svc.state().join("keyboard"), "{}");
    let (st, took) = timed(|| svc.status());
    assert!(st["keyboard"].is_null(), "{st}");
    assert!(took < Duration::from_secs(12), "status took {took:?}");
    let (st, took) = timed(|| svc.ok(true, json!({"op": "new"})).h["status"].clone());
    assert_eq!(st["key_level"], "files", "{st}");
    assert!(st["key_problem"].as_str().unwrap_or("").contains("in time"), "{st}");
    // The device key's request and the sealing key's, each up to 30 s.
    assert!(took < Duration::from_secs(70), "cbb new took {took:?}");
    // The group starts, though each of its requests to the helper waits.
    let (st, took) = timed(|| started(&svc));
    assert_eq!(st["role"], "member");
    eprintln!("the group started {took:?} after cbb new");
}

/// A helper that dies at a request: that request fails at once, and the
/// next one after a moment finds it started again.
#[test]
fn a_helper_that_dies_is_started_again() {
    let svc = with_helper("die-on-call");
    let (e, took) = timed(|| svc.err(true, json!({"op": "keyboard", "name": "status"})));
    assert!(e.contains("cbb-helper") && e.contains("stopped"), "{e}");
    assert!(took < Duration::from_secs(12), "took {took:?}");
    std::thread::sleep(Duration::from_secs(3));
    let e = svc.err(true, json!({"op": "remote", "name": "status"}));
    assert!(e.contains("stopped"), "{e}");
    let log = svc.log();
    assert!(log.matches("cbb-helper runs").count() >= 2, "{log}");
    assert!(log.contains("cbb-helper stopped"), "{log}");
}

/// A helper that serves: the keyboard's status from it, and a key request
/// it refuses leaves the device key in a file with its reason.
#[test]
fn a_helper_that_serves() {
    let svc = with_helper("serve");
    write(&svc.state().join("keyboard"), "{}");
    assert_eq!(svc.status()["keyboard"]["layout"], "de");
    let st = svc.new_group();
    assert!(st["key_problem"].as_str().unwrap_or("").contains("no TPM here"), "{st}");
    assert_eq!(svc.status()["keyboard"]["layout"], "de");
}

/// A helper that holds the keys, as with a TPM: the group is made with the
/// device key in the hardware, which signs through the helper; after a
/// restart the key and the sealed secret are opened through it again; a
/// member with such a key becomes an admin without the user's consent to
/// a key in a file.
#[test]
fn keys_in_the_hardware() {
    let s = script();
    let mut svc = Svc::start("root", &[], &[("CBB_HELPER", s.to_str().unwrap()), (MODE, "tpm")]);
    let st = svc.new_group();
    assert!(st["key_problem"].is_null(), "{st}");
    svc.ok_with(false, json!({"op": "copy"}), b"sealed to the TPM's key");
    let me = svc.devices().into_iter().find(|d| d["self"] == true).unwrap();
    let helper = s.to_str().unwrap();
    let env = [("CBB_HELPER", helper), (MODE, "tpm")];
    svc.restart(&[], &env);
    assert_eq!(started(&svc)["device"], me["id"]);
    // The sealing key, unsealed through the helper, seals the next copy.
    svc.ok_with(false, json!({"op": "copy"}), b"after the restart");
    assert_eq!(svc.ok(false, json!({"op": "paste"})).payload, b"after the restart");
    // A member whose keys the hardware holds.
    let desk = Svc::start("desk", &["-peer", &svc.addr()], &env);
    assert_eq!(svc.admit(&desk, false), "desk");
    svc.wait_peer("desk");
    settle(std::slice::from_ref(&svc));
    let d = svc.find("desk").unwrap();
    assert_eq!(d["store"], "hardware", "{d}");
    wait_for(
        "the root makes desk an admin",
        || svc.ask(true, json!({"op": "make_admin", "device": "desk"}), b"").error().is_empty().then_some(()),
        || svc.log(),
    );
    wait_for(
        "desk signs as an admin with its key in the hardware",
        || desk.ask(true, json!({"op": "incoming", "value": "20s"}), b"").error().is_empty().then_some(()),
        || desk.log(),
    );
    svc.wait("the root takes desk's setting", |st| st["incoming_ms"] == 20_000);
    // The helper gone, the key cannot be opened: the service says why, and
    // takes only cbb leave.
    let mut desk = desk;
    desk.restart(&[], &[]);
    let m = desk.ask(false, json!({"op": "status"}), b"");
    assert!(m.s("detail").contains("cbb-helper"), "{:?}", m.h);
}
