// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use std::sync::Arc;

use cbb_core::identity::{ExternalKey, FileKey};
use cbb_member::own::Own;
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

#[test]
fn a_new_phone_joins_by_the_root_phones_window() {
    let tmp = std::env::temp_dir().join(format!("cbb-ffi-joiner-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    let (root_dir, new_dir) = (tmp.join("root"), tmp.join("new"));
    std::fs::create_dir_all(&root_dir).unwrap();
    let me = cbb_member::founding::Me { name: "phone", os: 0, caps: 0 };
    let now = cbb_member::uptime::wall_ms().max(0).unsigned_abs();
    cbb_member::founding::found_with(&root_dir, &me, now, &|| None).unwrap();
    let own = Own::load(&root_dir).unwrap();
    let (member, root) = (leak(own.member.clone()), leak(own.root.clone().unwrap()));
    let req = json!({
        "dir": root_dir.to_string_lossy(), "name": "phone", "os": "ios",
        "device": id_text(&own.device()), "public": b64(&own.member.public()), "mdns": false,
    })
    .to_string();
    let (m, a) = Member::start(req.as_bytes(), sign, events, member);
    ok(&a);
    let m = m.unwrap();
    let call = |op: &str, args: Value| m.call(json!({ "op": op, "args": args }).to_string().as_bytes());

    // No window while the port is closed.
    let w = json!({ "public": b64(&own.root.as_ref().unwrap().public()), "addrs": ["127.0.0.1"] }).to_string();
    let (none, a) = m.window(w.as_bytes(), sign, root);
    assert!(none.is_none() && String::from_utf8_lossy(&a).contains("listen first"));
    ok(&call("listen", json!({ "port": 0 })));
    let (win, a) = m.window(w.as_bytes(), sign, root);
    let qr = ok(&a)["qr"].as_str().unwrap().to_string();
    let win = win.unwrap();
    assert!(qr.starts_with("cbb://pair?addr=127.0.0.1%3A"), "{qr}");
    let code = read_code(&qr).unwrap();
    assert_eq!(code.fingerprint, certs::hex(&Key::es256(own.member.public()).hash().0));

    let new_key: Arc<dyn ExternalKey> = Arc::new(FileKey::new(&cbb_core::identity::new_key().unwrap()).unwrap());
    let j = json!({
        "dir": new_dir.to_string_lossy(), "qr": qr, "name": "tablet", "os": "android",
        "public": b64(&new_key.public()),
    })
    .to_string();
    let (joiner, a) = Joiner::new(j.as_bytes(), sign, leak(new_key.clone()));
    assert_eq!(ok(&a)["state"], "dialing");
    let joiner = joiner.unwrap();

    let wnext = |v: u64| ok(&win.next(v, 100));
    let jnext = |v: u64| ok(&joiner.next(v, 100));
    let at_window = wait(&wnext, "joining");
    let at_joiner = wait(&jnext, "joining");
    assert_eq!(at_window["joining"]["code"], at_joiner["shown"]["code"], "both screens show one code");
    assert_eq!(at_window["joining"]["name"], "tablet");
    assert_eq!(at_joiner["shown"]["name"], "phone");
    win.answer(true);
    joiner.answer(true);
    let done = wait(&jnext, "done");
    let admitted = wait(&wnext, "done");
    assert_eq!(admitted["name"], "tablet");
    assert_eq!(done["device"], admitted["device"]);

    // The new phone keeps the group, and the root phone counts it.
    let local = cbb_member::set::local_key(&new_dir).unwrap();
    let kept = cbb_member::set::load(&new_dir, &local).unwrap().expect("the set is kept");
    assert!(kept.state().device_by_key(&Key::es256(new_key.public()).hash()).is_some());
    let devs = ok(&call("devices", Value::Null));
    assert_eq!(devs["devices"].as_array().unwrap().len(), 2, "{devs}");

    // A phone in a group does not join again.
    let (again, _) = Joiner::new(j.as_bytes(), sign, leak(new_key));
    assert!(again.is_none());
    drop(win);
    m.stop();
    let _ = std::fs::remove_dir_all(&tmp);
}

#[test]
fn a_pairing_code_reads_as_the_window_writes_it() {
    let fp = "ab".repeat(32);
    let t = crate::window::qr_text_for_tests(&["192.168.1.20".into(), "fd00::20".into()], 8764, &fp);
    assert_eq!(t, format!("cbb://pair?addr=192.168.1.20%3A8764&addr=%5Bfd00%3A%3A20%5D%3A8764&fp={fp}"));
    let c = read_code(&t).unwrap();
    assert_eq!(c.addrs.len(), 2);
    assert_eq!(c.fingerprint, fp);
    assert!(read_code("CBB://PAIR?addr=1.2.3.4:1&fp=").is_err(), "a fingerprint is needed");
    assert!(read_code(&format!("cbb://join?code=123456&fp={fp}")).is_err(), "a join code is not a window's");
}

#[test]
fn a_phone_that_made_its_group_admits_a_new_phone_by_its_window() {
    let tmp = std::env::temp_dir().join(format!("cbb-ffi-joiner-made-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    let (root_dir, new_dir) = (tmp.join("root"), tmp.join("new"));
    let key = || -> Arc<dyn ExternalKey> { Arc::new(FileKey::new(&cbb_core::identity::new_key().unwrap()).unwrap()) };
    let (root_key, member_key, new_key) = (key(), key(), key());
    let (root, member) = (leak(root_key.clone()), leak(member_key.clone()));
    // As the app makes its group: the root key signs, the set is kept in dir.
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
    let m = m.unwrap();
    ok(&m.call(json!({ "op": "listen", "args": { "port": 0 } }).to_string().as_bytes()));
    let w = json!({ "public": b64(&root_key.public()), "addrs": ["127.0.0.1"] }).to_string();
    let (win, a) = m.window(w.as_bytes(), sign, root);
    let qr = ok(&a)["qr"].as_str().unwrap().to_string();
    let win = win.unwrap();

    let j = json!({
        "dir": new_dir.to_string_lossy(), "qr": qr, "name": "tablet", "os": "android",
        "public": b64(&new_key.public()),
    })
    .to_string();
    let (joiner, a) = Joiner::new(j.as_bytes(), sign, leak(new_key.clone()));
    ok(&a);
    let joiner = joiner.unwrap();
    let wnext = |v: u64| ok(&win.next(v, 100));
    let jnext = |v: u64| ok(&joiner.next(v, 100));
    let at_window = wait(&wnext, "joining");
    let at_joiner = wait(&jnext, "joining");
    assert_eq!(at_window["joining"]["code"], at_joiner["shown"]["code"]);
    win.answer(true);
    joiner.answer(true);
    let done = wait(&jnext, "done");
    assert_eq!(done["group"], made["group"], "the new phone is in the group the phone made");
    wait(&wnext, "done");
    let devs = ok(&m.call(json!({ "op": "devices", "args": null }).to_string().as_bytes()));
    assert_eq!(devs["devices"].as_array().unwrap().len(), 2, "{devs}");
    drop(win);
    m.stop();
    let _ = std::fs::remove_dir_all(&tmp);
}
