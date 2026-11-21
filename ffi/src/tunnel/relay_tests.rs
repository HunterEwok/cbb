// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! Two phones' relay links through the C functions, against the relay of
//! `cbb relay` in the same process, serving a list of groups: each gets
//! the period's server credentials (`cbb_tunnel_relay_credentials`) with
//! a callback that signs with its server key, both register and see each
//! other by device ID, the lower pseudonym dials, and the bytes pass to
//! the other's member listener.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{Ipv4Addr, TcpListener, TcpStream};

use cbb_core::blind::credential::{Credential, TYPE_HUBS, TYPE_MEMBERS, TYPE_PERIOD};
use cbb_core::identity::ExternalKey;
use cbb_core::records::key::{ALG_SLH_DSA, Key};
use cbb_core::records::{Recovery, group_id, pq};
use cbb_member::faces::ServerKey;
use cbb_member::relayd::keys::Keys;
use cbb_member::relayd::limits::Limits;
use cbb_member::relayd::server::{self, Relay as Server};
use p256::ecdsa::SigningKey;

use super::*;

fn key() -> ServerKey {
    loop {
        if let Ok(k) = ServerKey::from_scalar(&certs::random_bytes()) {
            return k;
        }
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn hash(k: &ServerKey) -> [u8; 32] {
    Key::es256(k.public()).hash().0
}

fn blank(kind: u64, group: [u8; 16]) -> Credential {
    Credential {
        kind,
        group,
        signer: Vec::new(),
        version: 1,
        expires_ms: u64::try_from(now_ms()).unwrap() + 3_600_000,
        tag: None,
        key: None,
        hubs: Vec::new(),
        admins: Vec::new(),
        members: Vec::new(),
        id: [0; 32],
    }
}

/// Signs with the ServerKey at ctx.
unsafe extern "C" fn sign_with(ctx: *mut core::ffi::c_void, digest: *const u8, sig: *mut u8, n: *mut usize) -> i32 {
    // SAFETY: the test passes a ServerKey that outlives the link, and the
    // caller 32 bytes at digest and 72 of room at sig.
    let (k, d) = unsafe { (&*(ctx as *const ServerKey), &*(digest as *const [u8; 32])) };
    match k.sign_digest(d) {
        Ok(s) if s.len() <= 72 => {
            // SAFETY: as above.
            unsafe {
                core::ptr::copy_nonoverlapping(s.as_ptr(), sig, s.len());
                *n = s.len();
            }
            0
        }
        _ => -1,
    }
}

/// Keeps the events in the Mutex at ctx.
unsafe extern "C" fn keep(ctx: *mut core::ffi::c_void, e: *const u8, len: usize) {
    // SAFETY: the test passes a Mutex that outlives the link, and the
    // caller len bytes at e.
    let (seen, b) = unsafe { (&*(ctx as *const Mutex<Vec<Value>>), core::slice::from_raw_parts(e, len)) };
    if let Ok(v) = serde_json::from_slice(b) {
        seen.lock().unwrap().push(v);
    }
}

fn c_answer(p: *mut u8, n: usize) -> Value {
    assert!(!p.is_null());
    // SAFETY: the C functions answer n bytes at p, freed with cbb_free.
    let v = serde_json::from_slice(unsafe { core::slice::from_raw_parts(p, n) }).unwrap();
    // SAFETY: as above.
    unsafe { crate::cbb_free(p, n) };
    v
}

fn wait(what: &str, mut f: impl FnMut() -> bool) {
    let until = Instant::now() + Duration::from_secs(30);
    while !f() {
        assert!(Instant::now() < until, "{what}");
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[test]
fn two_phones_meet_at_the_relay() {
    // A group of 0.6: its root and recovery key, a period, two server keys
    // in the order of their pseudonyms, the hubs' and members' credentials.
    let root = key();
    let (k1, k2) = pq::recovery_keys(&certs::random_bytes()).unwrap();
    let k1 = SigningKey::from(&k1).verifying_key().to_sec1_point(false).as_bytes().to_vec();
    let rec = Recovery::new(Key::es256(k1.clone()), Key::new(ALG_SLH_DSA, k2.public())).unwrap();
    let gid = group_id(&Key::es256(root.public()), &rec).0;
    let (tag, period_key) = (certs::random_bytes::<16>(), key());
    let mut servers = [key(), key()];
    servers.sort_by_key(hash);
    let ids = [DeviceId::random().to_string(), DeviceId::random().to_string()];
    let mut p = blank(TYPE_PERIOD, gid);
    p.tag = Some(tag);
    p.key = Some(period_key.public());
    let period = p.sign(&root).unwrap();
    let hubs = blank(TYPE_HUBS, tag).sign(&period_key).unwrap();
    let mut m = blank(TYPE_MEMBERS, tag);
    m.members = servers.iter().map(hash).collect();
    let members = m.sign(&period_key).unwrap();

    let keys = Keys::new().unwrap();
    let pin = cbb_core::certs::Cert::parse(&keys.cert).unwrap().key_hash();
    let s = Server::start(server::Config {
        listen: SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
        keys,
        groups: vec![format!("{}:{}:{}", hex(&root.public()), hex(&k1), hex(&k2.public()))],
        open: false,
        limits: Limits::default(),
        log: Arc::new(|_| {}),
        verbose: false,
        refused: None,
    })
    .unwrap();

    // The second phone's member listener echoes a line.
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let member_port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        if let Ok((c, _)) = listener.accept() {
            let mut line = String::new();
            let mut r = BufReader::new(c.try_clone().unwrap());
            if r.read_line(&mut line).is_ok() {
                let _ = (&c).write_all(line.as_bytes());
            }
        }
    });

    let seen = [Mutex::new(Vec::new()), Mutex::new(Vec::new())];
    let mut links = Vec::new();
    for i in 0..2 {
        let port = if i == 0 { 1 } else { member_port };
        let req =
            serde_json::to_vec(&json!({"endpoint": s.addr().to_string(), "pins": [b64(&pin)], "member_port": port}))
                .unwrap();
        let ctx = (&seen[i] as *const Mutex<Vec<Value>>).cast_mut().cast();
        let mut n = 0usize;
        // SAFETY: seen and the request outlive the call and the link.
        let p = unsafe { crate::cbb_tunnel_relay(req.as_ptr(), req.len(), sign_with, keep, ctx, &mut n) };
        let id = c_answer(p, n)["ok"]["id"].as_u64().unwrap();
        let creds = serde_json::to_vec(&json!({"id": id, "public": b64(&servers[i].public()),
            "credentials": [b64(&hubs), b64(&members)], "period": b64(&period), "root": b64(&root.public()),
            "names": {b64(&hash(&servers[1 - i])): ids[1 - i]}}))
        .unwrap();
        let kctx = (&servers[i] as *const ServerKey).cast_mut().cast();
        // SAFETY: the server key outlives the link.
        let p = unsafe { crate::cbb_tunnel_relay_credentials(creds.as_ptr(), creds.len(), sign_with, kctx, &mut n) };
        let a = c_answer(p, n);
        assert!(a.get("error").is_none(), "{a}");
        links.push(id);
    }
    let has = |i: usize, f: &dyn Fn(&Value) -> bool| seen[i].lock().unwrap().iter().any(f);
    for i in 0..2 {
        wait(&format!("phone {i} online: {:?}", seen[i].lock().unwrap()), || {
            has(i, &|e| e["type"] == "changed" && e["connected"] == true && e["online"] == json!([ids[1 - i]]))
        });
    }
    // The first dials the second: it is not connected another way.
    wait("no dial", || has(0, &|e| e["type"] == "dial"));
    let dial = seen[0].lock().unwrap().iter().find(|e| e["type"] == "dial").cloned().unwrap();
    assert_eq!(dial["peer"], json!(ids[1]));
    let mut c = TcpStream::connect(("127.0.0.1", u16::try_from(dial["port"].as_u64().unwrap()).unwrap())).unwrap();
    c.set_read_timeout(Some(Duration::from_secs(15))).unwrap();
    c.write_all(b"hello through the relay\n").unwrap();
    let mut got = [0u8; 24];
    c.read_exact(&mut got).unwrap();
    assert_eq!(&got, b"hello through the relay\n");
    wait("no call", || has(1, &|e| e["type"] == "calling" && e["peer"] == json!(ids[0])));
    for id in links {
        call(&serde_json::to_vec(&json!({"op": "relay_stop", "id": id})).unwrap());
    }
}
