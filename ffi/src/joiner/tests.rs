// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use std::sync::Arc;

use cbb_core::identity::{ExternalKey, FileKey};
use serde_json::{Value, json};

use super::*;
use crate::member::Member;

/// A key the test's callbacks sign with, as an app's would.
struct Signer(Arc<dyn ExternalKey>);

unsafe extern "C" fn sign(ctx: *mut core::ffi::c_void, digest: *const u8, sig: *mut u8, sig_len: *mut usize) -> i32 {
    // SAFETY: ctx is a Signer the test keeps for the process, digest 32
    // bytes and sig room for 72, as the callback's contract says.
    unsafe {
        let k = &*(ctx as *const Signer);
        let d: [u8; 32] = core::slice::from_raw_parts(digest, 32).try_into().unwrap();
        let Ok(s) = k.0.sign_digest(&d) else { return 1 };
        core::ptr::copy_nonoverlapping(s.as_ptr(), sig, s.len());
        *sig_len = s.len();
    }
    0
}

unsafe extern "C" fn events(_ctx: *mut core::ffi::c_void, _event: *const u8, _len: usize) {}

fn ok(answer: &[u8]) -> Value {
    let v: Value = serde_json::from_slice(answer).unwrap();
    v.get("ok").cloned().unwrap_or_else(|| panic!("an error: {v}"))
}

fn b64(b: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(b)
}

fn leak(k: Arc<dyn ExternalKey>) -> usize {
    Box::leak(Box::new(Signer(k))) as *const Signer as usize
}

/// Waits for a state named `want`, past `version`, from `next`.
fn wait(next: &dyn Fn(u64) -> Value, want: &str) -> Value {
    let mut v = 0;
    for _ in 0..200 {
        let st = next(v);
        if st["state"] == want {
            return st;
        }
        assert_ne!(st["state"], "failed", "{st}");
        v = st["version"].as_u64().unwrap();
    }
    panic!("no state {want}");
}

/// The phone's member of a group the phone made, its port open, with the
/// root key's callback context.
fn root_member(tmp: &std::path::Path) -> (Member, Arc<dyn ExternalKey>, usize) {
    let root_dir = tmp.join("root");
    let key = || -> Arc<dyn ExternalKey> { Arc::new(FileKey::new(&cbb_core::identity::new_key().unwrap()).unwrap()) };
    let (root_key, member_key) = (key(), key());
    let (root, member) = (leak(root_key.clone()), leak(member_key.clone()));
    let g = json!({
        "dir": root_dir.to_string_lossy(), "name": "phone", "os": "ios", "store": "hardware",
        "root_public": b64(&root_key.public()), "public": b64(&member_key.public()),
    })
    .to_string();
    let made = ok(&crate::found::new_group(g.as_bytes(), sign, root));
    let req = json!({
        "dir": root_dir.to_string_lossy(), "name": "phone", "os": "ios",
        "device": made["device"], "public": b64(&member_key.public()), "mdns": false,
    })
    .to_string();
    let (m, a) = Member::start(req.as_bytes(), sign, events, member);
    ok(&a);
    (m.unwrap(), root_key, root)
}

fn new_key() -> Arc<dyn ExternalKey> {
    Arc::new(FileKey::new(&cbb_core::identity::new_key().unwrap()).unwrap())
}

fn join_request(dir: &std::path::Path, qr: &str, digits: &str, key: &Arc<dyn ExternalKey>) -> String {
    json!({
        "dir": dir.to_string_lossy(), "qr": qr, "digits": digits, "name": "tablet", "os": "android",
        "public": b64(&key.public()),
    })
    .to_string()
}

#[test]
fn a_new_phone_joins_by_the_window_of_the_phone_that_made_the_group() {
    let tmp = std::env::temp_dir().join(format!("cbb-ffi-joiner-made-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    let (m, root_key, root) = root_member(&tmp);
    let w = json!({ "public": b64(&root_key.public()), "addrs": ["127.0.0.1"] }).to_string();
    // No window while the port is closed.
    let (none, a) = m.window(w.as_bytes(), sign, root);
    assert!(none.is_none() && String::from_utf8_lossy(&a).contains("listen first"));
    ok(&m.call(json!({ "op": "listen", "args": { "port": 0 } }).to_string().as_bytes()));
    let (win, a) = m.window(w.as_bytes(), sign, root);
    let opened = ok(&a);
    let win = win.unwrap();
    let qr = opened["qr"].as_str().unwrap().to_string();
    let digits = opened["digits"].as_str().unwrap();
    assert_eq!(digits.len(), 6);
    assert!(qr.starts_with("cbb://pair?addr=127.0.0.1:"), "{qr}");
    assert!(qr.contains(&format!("c={digits}")) && qr.contains(&format!("i={}", opened["id"].as_str().unwrap())));
    let t = read_code(&qr).unwrap();
    assert_eq!(Some(certs::hex(&t.fp.unwrap().0)), opened["fingerprint"].as_str().map(String::from));

    let new_dir = tmp.join("new");
    let k = new_key();
    let (joiner, a) = Joiner::new(join_request(&new_dir, &qr, "", &k).as_bytes(), sign, leak(k.clone()));
    assert_eq!(ok(&a)["state"], "dialing");
    let joiner = joiner.unwrap();
    let jnext = |v: u64| ok(&joiner.next(v, 100));
    let wnext = |v: u64| ok(&win.next(v, 100));
    let done = wait(&jnext, "done");
    let admitted = wait(&wnext, "done");
    assert_eq!(admitted["name"], "tablet");
    assert_eq!(done["name"], "phone", "the member that let it in");
    assert_eq!(done["device"], admitted["device"]);

    // The new phone keeps the group, and the root phone counts it.
    let local = cbb_member::set::local_key(&new_dir).unwrap();
    let kept = cbb_member::set::load(&new_dir, &local).unwrap().expect("the set is kept");
    assert!(kept.state().device_by_key(&Key::es256(k.public()).hash()).is_some());
    let devs = ok(&m.call(json!({ "op": "devices", "args": null }).to_string().as_bytes()));
    assert_eq!(devs["devices"].as_array().unwrap().len(), 2, "{devs}");

    // One device joined: the window is closed to the next.
    let other = tmp.join("other");
    let k2 = new_key();
    let (j2, _) = Joiner::new(join_request(&other, &qr, "", &k2).as_bytes(), sign, leak(k2));
    let j2 = j2.unwrap();
    let st = wait_end(&|v| ok(&j2.next(v, 100)));
    assert_eq!(st["state"], "failed", "{st}");
    // A phone in a group does not join again.
    let (again, _) = Joiner::new(join_request(&new_dir, &qr, "", &k).as_bytes(), sign, leak(k));
    assert!(again.is_none());
    drop(win);
    m.stop();
    let _ = std::fs::remove_dir_all(&tmp);
}

/// The first state that ends the joiner: done or failed.
fn wait_end(next: &dyn Fn(u64) -> Value) -> Value {
    let mut v = 0;
    for _ in 0..200 {
        let st = next(v);
        if st["state"] == "done" || st["state"] == "failed" {
            return st;
        }
        v = st["version"].as_u64().unwrap();
    }
    panic!("the joiner did not end");
}

#[test]
fn a_wrong_code_joins_no_one_and_writes_nothing() {
    let tmp = std::env::temp_dir().join(format!("cbb-ffi-joiner-wrong-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    let (m, root_key, root) = root_member(&tmp);
    ok(&m.call(json!({ "op": "listen", "args": { "port": 0 } }).to_string().as_bytes()));
    let w = json!({ "public": b64(&root_key.public()), "addrs": ["127.0.0.1"] }).to_string();
    let (win, a) = m.window(w.as_bytes(), sign, root);
    let opened = ok(&a);
    let win = win.unwrap();
    let digits = opened["digits"].as_str().unwrap().to_string();
    let wrong = if digits == "000000" { "000001" } else { "000000" };
    // The QR code with other digits: the session proves the wrong secret.
    let qr = opened["qr"].as_str().unwrap().replace(&format!("c={digits}"), &format!("c={wrong}"));
    let devices = || -> Vec<Value> {
        let d = ok(&m.call(json!({ "op": "devices", "args": null }).to_string().as_bytes()));
        d["devices"].as_array().unwrap().iter().map(|d| d["id"].clone()).collect()
    };
    let before = devices();
    let wnext = |v: u64| ok(&win.next(v, 100));
    for n in 1..=3 {
        let dir = tmp.join(format!("wrong{n}"));
        let k = new_key();
        let (j, _) = Joiner::new(join_request(&dir, &qr, "", &k).as_bytes(), sign, leak(k));
        let j = j.unwrap();
        let st = wait_end(&|v| ok(&j.next(v, 100)));
        assert_eq!(st["state"], "failed", "{st}");
        assert!(st["error"]["message"].as_str().unwrap().contains("not the window's"), "{st}");
        assert!(!dir.join("group.cbor").exists(), "the refused phone keeps no group");
        assert_eq!(devices(), before, "nothing reached the records");
        // The window says so too: open for the next attempt, closed after the third.
        let mut v = 0;
        let end = loop {
            let s = wnext(v);
            if (n < 3 && s["state"] == "failed") || s["state"] == "closed" {
                break s;
            }
            v = s["version"].as_u64().unwrap();
        };
        assert_eq!(end["state"], if n < 3 { "failed" } else { "closed" }, "{end}");
    }
    // Closed, the window takes not even the right digits.
    let dir = tmp.join("right");
    let k = new_key();
    let right = opened["qr"].as_str().unwrap();
    let (j, _) = Joiner::new(join_request(&dir, right, "", &k).as_bytes(), sign, leak(k));
    let st = wait_end(&|v| ok(&j.as_ref().unwrap().next(v, 100)));
    assert_eq!(st["state"], "failed", "{st}");
    assert_eq!(devices(), before);
    drop(win);
    m.stop();
    let _ = std::fs::remove_dir_all(&tmp);
}

#[test]
fn a_pairing_code_reads_as_the_window_writes_it() {
    use cbb_core::join::invitation::WindowLink;
    let link = WindowLink {
        addrs: vec!["192.168.1.20:8764".into(), "[fd00::20]:8764".into()],
        fp: cbb_core::format::KeyHash([0xab; 32]),
        id: [0x11; 16],
        digits: "123456".into(),
    };
    let t = link.text();
    let c = read_code(&t).unwrap();
    assert_eq!(c.addrs.len(), 2);
    assert_eq!(c.fp, Some(cbb_core::format::KeyHash([0xab; 32])));
    assert_eq!(c.invitation.id, [0x11; 16]);
    assert!(read_code("cbb://join?code=123456").is_err(), "a join code is not a window's");
    assert!(read_code("cbb://pair?addr=1.2.3.4:1").is_err(), "a window's code names its key, ID and digits");
}

#[test]
fn a_joiner_takes_six_digits_or_a_window_code() {
    let tmp = std::env::temp_dir().join(format!("cbb-ffi-joiner-digits-{}", std::process::id()));
    let k = new_key();
    for digits in ["", "12345", "1234567", "12a456"] {
        let (j, a) = Joiner::new(join_request(&tmp, "", digits, &k).as_bytes(), sign, leak(k.clone()));
        assert!(j.is_none(), "{digits:?}");
        assert!(String::from_utf8_lossy(&a).contains("six digits"), "{digits:?}");
    }
    let _ = std::fs::remove_dir_all(&tmp);
}
