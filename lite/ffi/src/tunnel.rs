// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The phones' tunnel to the group's hub, for sync away from home
//! (docs/protocol.md, section 11): the lite member's WireGuard on GotaTun,
//! with AmneziaWG and VLESS with XHTTP (`cbb_lite::tunnel`), in the app's
//! own process. A tunnel opens a TCP port on the loopback address that
//! leads to the hub's member port; the app's node dials it with its own
//! member TLS, so another app that connects to the port reaches only the
//! hub's member TLS.
//!
//! One C function, `cbb_tunnel`, takes a JSON request with its `op`:
//!
//! - `new_key`: `{"key"}`, a new private tunnel key for the device;
//! - `public_key` with `key`: `{"public"}`, the tunnel key its hellos offer;
//! - `start` with `key`, `device`, `hub` (the hub's device ID) and `offer`
//!   (the hub's tunnel offer as the member protocol carries it):
//!   `{"id", "port"}`;
//! - `status` with `id`: `{"answered", "log"}`, whether the hub answered
//!   and the log lines since the last status;
//! - `stop` with `id`: `{}`.
//!
//! The answer is `{"ok": ...}` or `{"error": {"message", "details"}}`.

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use cbb_core::certs::{self, DeviceId};
use cbb_core::error::{Error, Result};
use cbb_lite::tunnel::{self, Link, State};
use cbb_lite::wire::TunnelOffer;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::join::answer;

/// The log lines a tunnel keeps until the app asks for its status.
const MAX_LOG: usize = 200;

#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
enum Request {
    NewKey,
    PublicKey {
        #[serde(with = "certs::b64")]
        key: Vec<u8>,
    },
    Start {
        #[serde(with = "certs::b64")]
        key: Vec<u8>,
        device: String,
        hub: String,
        offer: Box<TunnelOffer>,
    },
    Status {
        id: u64,
    },
    Stop {
        id: u64,
    },
}

struct Running {
    link: Link,
    log: Arc<Mutex<VecDeque<String>>>,
}

static TUNNELS: Mutex<Option<HashMap<u64, Running>>> = Mutex::new(None);
static NEXT: AtomicU64 = AtomicU64::new(1);

/// Answers one request (the module's comment lists them).
pub fn call(request: &[u8]) -> Vec<u8> {
    answer(handle(request))
}

fn handle(request: &[u8]) -> Result<Value> {
    let req: Request =
        serde_json::from_slice(request).map_err(|e| Error::msg(format!("the tunnel request does not decode: {e}")))?;
    match req {
        Request::NewKey => Ok(json!({ "key": b64(&tunnel::new_key()?) })),
        Request::PublicKey { key } => Ok(json!({ "public": b64(&State::with_key(&key)?.public_key()) })),
        Request::Start { key, device, hub, offer } => start(&key, &device, &hub, &offer),
        Request::Status { id } => with(id, |r| {
            let log: Vec<String> = r.log.lock().map(|mut l| l.drain(..).collect()).unwrap_or_default();
            Ok(json!({ "answered": r.link.answered(), "log": log }))
        }),
        Request::Stop { id } => {
            // Dropping the link stops its thread and closes its port.
            let gone = tunnels(|t| Ok(t.remove(&id)))?;
            drop(gone);
            Ok(json!({}))
        }
    }
}

fn start(key: &[u8], device: &str, hub: &str, offer: &TunnelOffer) -> Result<Value> {
    let me = DeviceId::parse(device)?;
    let from = DeviceId::parse(hub)?;
    let st = State::with_key(key)?;
    let h = tunnel::hub_from_offer(&from, offer)?;
    let log = Arc::new(Mutex::new(VecDeque::new()));
    let sink = log.clone();
    let link = Link::start(
        &st,
        &h,
        &me,
        Arc::new(move |line: &str| {
            if let Ok(mut l) = sink.lock() {
                if l.len() >= MAX_LOG {
                    l.pop_front();
                }
                l.push_back(line.to_string());
            }
        }),
    )?;
    let port = link.local().port();
    let id = NEXT.fetch_add(1, Ordering::SeqCst);
    tunnels(|t| {
        t.insert(id, Running { link, log });
        Ok(())
    })?;
    Ok(json!({ "id": id, "port": port }))
}

fn tunnels<T>(f: impl FnOnce(&mut HashMap<u64, Running>) -> Result<T>) -> Result<T> {
    let mut g = TUNNELS.lock().map_err(|_| Error::msg("the tunnels' table is broken"))?;
    f(g.get_or_insert_with(HashMap::new))
}

fn with(id: u64, f: impl FnOnce(&Running) -> Result<Value>) -> Result<Value> {
    tunnels(|t| match t.get(&id) {
        Some(r) => f(r),
        None => Err(Error::msg(format!("there is no tunnel {id}"))),
    })
}

fn b64(b: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(b)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok(req: Value) -> Value {
        let a: Value = serde_json::from_slice(&call(&serde_json::to_vec(&req).unwrap())).unwrap();
        assert!(a.get("error").is_none(), "{a}");
        a["ok"].clone()
    }

    fn refused(req: Value) -> String {
        let a: Value = serde_json::from_slice(&call(&serde_json::to_vec(&req).unwrap())).unwrap();
        a["error"]["message"].as_str().unwrap().to_string()
    }

    #[test]
    fn keys() {
        let k = ok(json!({"op": "new_key"}))["key"].as_str().unwrap().to_string();
        let p = ok(json!({"op": "public_key", "key": k}));
        assert_eq!(p["public"].as_str().unwrap().len(), 44);
        assert!(!refused(json!({"op": "public_key", "key": b64(&[0; 32])})).is_empty());
        assert!(!refused(json!({"op": "public_key", "key": b64(&[1; 31])})).is_empty());
    }

    #[test]
    fn start_status_stop() {
        let key = ok(json!({"op": "new_key"}))["key"].clone();
        let device = DeviceId::random().to_string();
        let hub = DeviceId::random().to_string();
        let offer = json!({"hub_key": b64(&[1; 32]), "psk": b64(&[2; 32]), "endpoints": ["127.0.0.1:9"]});
        let t = ok(json!({"op": "start", "key": key, "device": device, "hub": hub, "offer": offer}));
        let id = t["id"].as_u64().unwrap();
        assert!(t["port"].as_u64().unwrap() > 0);
        let s = ok(json!({"op": "status", "id": id}));
        assert_eq!(s["answered"], false);
        ok(json!({"op": "stop", "id": id}));
        assert!(refused(json!({"op": "status", "id": id})).contains("no tunnel"));
        // An offer the member refuses: REALITY, which rustls cannot hide.
        let reality = json!({"hub_key": b64(&[1; 32]), "psk": b64(&[2; 32]),
            "vless": {"endpoint": "192.0.2.7:443", "public_key": "AAAA", "short_id": "ab",
                      "server_name": "cbb.example.org", "id": "6f1c2b9e-3d4a-4f5b-8c7d-0e1f2a3b4c5d"}});
        assert!(
            !refused(json!({"op": "start", "key": key, "device": device, "hub": hub, "offer": reality})).is_empty()
        );
        assert!(!refused(json!({"op": "start", "key": key, "device": "x", "hub": hub, "offer": offer})).is_empty());
    }
}
