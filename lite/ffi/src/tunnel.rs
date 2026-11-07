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
//! - `stop` with `id`: `{}`;
//! - `hub_start` with `key`, `device`, `obfuscation` (the group's AmneziaWG
//!   settings, or none), `clients` (`[{"device", "key", "psk"}]`) and
//!   `member_port` (the app's member listener on the loopback address):
//!   `{"id", "udp_port"}`, the phone as the group's hub;
//! - `hub_set_clients` with `id` and `clients`, `hub_status` with `id`
//!   (`{"udp_port", "log"}`) and `hub_stop` with `id`;
//! - `hub_invite` with `id`, `group` (the group's tag), `endpoints` (the
//!   hub's addresses away from home, "ip:port"), `lifetime` (seconds, at
//!   most a day) and `guest_port` (the app's pairing window):
//!   `{"guest", "text", "secret", "expires"}`, a remote invitation
//!   (docs/protocol.md, section 12) whose guest tunnel leads to the window;
//! - `guest_admitted` with `id` and `guest`: the window admitted the device,
//!   whose connections now go to the member port for 2 minutes;
//!   `guest_close` with `id` and `guest` drops the guest.
//!
//! The answer is `{"ok": ...}` or `{"error": {"message", "details"}}`.

use std::collections::{HashMap, VecDeque};
use std::net::{Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use cbb_core::certs::{self, DeviceId};
use cbb_core::error::{Error, Result};
use cbb_core::invite;
use cbb_lite::hub::{self, Hub, Peer};
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
    HubStart {
        #[serde(with = "certs::b64")]
        key: Vec<u8>,
        device: String,
        #[serde(default)]
        obfuscation: Option<Value>,
        #[serde(default)]
        clients: Vec<Client>,
        member_port: u16,
        /// Where WireGuard listens, "[::]:0" (any port) by default.
        #[serde(default)]
        listen: Option<String>,
    },
    HubSetClients {
        id: u64,
        clients: Vec<Client>,
    },
    HubStatus {
        id: u64,
    },
    HubInvite {
        id: u64,
        group: String,
        endpoints: Vec<String>,
        /// How long the invitation is valid, seconds, at most a day.
        lifetime: u64,
        /// The loopback port of the app's pairing window for it.
        guest_port: u16,
    },
    GuestAdmitted {
        id: u64,
        guest: u64,
    },
    GuestClose {
        id: u64,
        guest: u64,
    },
    HubStop {
        id: u64,
    },
}

/// One of the hub's clients: its device ID, its tunnel key and the
/// preshared key the hub's offer gave it.
#[derive(Deserialize)]
struct Client {
    device: String,
    #[serde(with = "certs::b64")]
    key: Vec<u8>,
    #[serde(with = "certs::b64")]
    psk: Vec<u8>,
}

struct RunningHub {
    hub: Hub,
    device: String,
    /// The hub's public key and AmneziaWG settings, which its invitations
    /// carry.
    public: [u8; 32],
    obfuscation: Option<Value>,
    clients: Vec<Peer>,
    guests: Arc<Mutex<HashMap<u64, Guest>>>,
    log: Arc<Mutex<VecDeque<String>>>,
}

/// The guest tunnel of a remote invitation (docs/protocol.md, section 12):
/// its connections go to the app's pairing window, and once the window
/// admitted the device, to the member port.
struct Guest {
    peer: Peer,
    port: u16,
    admitted: bool,
}

/// The longest an invitation is valid, and how long its guest stays after
/// the window admitted the device, as on a computer's hub.
const MAX_LIFETIME: u64 = 24 * 60 * 60;
const GUEST_GRACE: Duration = Duration::from_secs(120);
/// The pairing secret's length.
const SECRET: usize = 16;

impl RunningHub {
    /// Gives the hub its clients and the guests whose time is not up.
    fn set_peers(&self) -> Result<()> {
        let now = Instant::now();
        let mut peers = self.clients.clone();
        if let Ok(mut g) = self.guests.lock() {
            g.retain(|_, g| g.peer.until.is_none_or(|u| u > now));
            peers.extend(g.values().map(|g| g.peer.clone()));
        }
        self.hub.set_peers(peers, &self.device)
    }

    fn invite(&self, group: &str, endpoints: &[String], lifetime: u64, guest_port: u16) -> Result<Value> {
        if lifetime == 0 || lifetime > MAX_LIFETIME {
            return Err(Error::msg("an invitation is valid for a day at most"));
        }
        if guest_port == 0 {
            return Err(Error::msg("the pairing window's port is 0"));
        }
        let endpoints = endpoints
            .iter()
            .map(|e| invite::parse_endpoint(e).ok_or_else(|| Error::msg(format!("{e:?} is not an endpoint"))))
            .collect::<Result<Vec<_>>>()?;
        let guest_key: [u8; 32] = key32(&tunnel::new_key()?)?;
        let guest_psk: [u8; 32] = key32(&tunnel::new_key()?)?;
        let secret = tunnel::new_key()?.get(..SECRET).map(<[u8]>::to_vec).unwrap_or_default();
        let unix = SystemTime::now().duration_since(UNIX_EPOCH).map_err(|_| Error::msg("the clock is before 1970"))?;
        let expires = i64::try_from(unix.as_secs().saturating_add(lifetime)).unwrap_or(i64::MAX);
        let obfuscation = match &self.obfuscation {
            Some(v) => Some(
                invite::obfuscation_from_json(v)
                    .ok_or_else(|| Error::msg("the hub's obfuscation settings are damaged"))?,
            ),
            None => None,
        };
        let inv = invite::Invitation {
            group: group.to_string(),
            hub: self.device.clone(),
            hub_key: self.public,
            endpoints,
            guest_key,
            guest_psk,
            secret: secret.clone(),
            expires,
            obfuscation,
        };
        let text = inv.to_text();
        // Read back as the joiner will: the group's tag, 1 to 8 endpoints.
        invite::parse(&text).map_err(|r| Error::msg(format!("the invitation: {}", r.message())))?;
        let public = key32(&State::with_key(&guest_key)?.public_key())?;
        let peer = Peer {
            key: public,
            psk: guest_psk,
            addr: hub::guest_addr(&public),
            until: Instant::now().checked_add(Duration::from_secs(lifetime)),
        };
        let guest = NEXT.fetch_add(1, Ordering::SeqCst);
        self.guests
            .lock()
            .map_err(|_| Error::msg("the hub's guests are broken"))?
            .insert(guest, Guest { peer, port: guest_port, admitted: false });
        self.set_peers()?;
        Ok(json!({ "guest": guest, "text": text, "secret": b64(&secret), "expires": expires }))
    }

    /// Changes the guests, then gives the hub its peers again.
    fn guests_then(&self, f: impl FnOnce(&mut HashMap<u64, Guest>)) -> Result<Value> {
        {
            let mut g = self.guests.lock().map_err(|_| Error::msg("the hub's guests are broken"))?;
            f(&mut g);
        }
        self.set_peers()?;
        Ok(json!({}))
    }
}

fn key32(b: &[u8]) -> Result<[u8; 32]> {
    b.try_into().map_err(|_| Error::msg("a key is not 32 bytes"))
}

static HUBS: Mutex<Option<HashMap<u64, RunningHub>>> = Mutex::new(None);

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
        Request::HubStart { key, device, obfuscation, clients, member_port, listen } => {
            hub_start(&key, &device, obfuscation.as_ref(), &clients, member_port, listen.as_deref())
        }
        Request::HubSetClients { id, clients } => hubs(|t| {
            let r = t.get_mut(&id).ok_or_else(|| Error::msg(format!("there is no hub {id}")))?;
            r.clients = peers(&clients)?;
            r.set_peers()?;
            Ok(json!({}))
        }),
        Request::HubInvite { id, group, endpoints, lifetime, guest_port } => hubs(|t| {
            let r = t.get(&id).ok_or_else(|| Error::msg(format!("there is no hub {id}")))?;
            r.invite(&group, &endpoints, lifetime, guest_port)
        }),
        Request::GuestAdmitted { id, guest } => hubs(|t| {
            let r = t.get(&id).ok_or_else(|| Error::msg(format!("there is no hub {id}")))?;
            r.guests_then(|g| {
                if let Some(g) = g.get_mut(&guest) {
                    g.admitted = true;
                    g.peer.until = Instant::now().checked_add(GUEST_GRACE);
                }
            })
        }),
        Request::GuestClose { id, guest } => hubs(|t| {
            let r = t.get(&id).ok_or_else(|| Error::msg(format!("there is no hub {id}")))?;
            r.guests_then(|g| {
                g.remove(&guest);
            })
        }),
        Request::HubStatus { id } => hubs(|t| {
            let r = t.get(&id).ok_or_else(|| Error::msg(format!("there is no hub {id}")))?;
            let log: Vec<String> = r.log.lock().map(|mut l| l.drain(..).collect()).unwrap_or_default();
            Ok(json!({ "udp_port": r.hub.udp_port(), "log": log }))
        }),
        Request::HubStop { id } => {
            let gone = hubs(|t| Ok(t.remove(&id)))?;
            drop(gone);
            Ok(json!({}))
        }
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
    let link = Link::start(&st, &h, &me, logger(log.clone()))?;
    let port = link.local().port();
    let id = NEXT.fetch_add(1, Ordering::SeqCst);
    tunnels(|t| {
        t.insert(id, Running { link, log });
        Ok(())
    })?;
    Ok(json!({ "id": id, "port": port }))
}

fn hub_start(
    key: &[u8],
    device: &str,
    obfuscation: Option<&Value>,
    clients: &[Client],
    member_port: u16,
    listen: Option<&str>,
) -> Result<Value> {
    let key: [u8; 32] = key.try_into().map_err(|_| Error::msg("the hub's key is not 32 bytes"))?;
    if member_port == 0 {
        return Err(Error::msg("the member port is 0"));
    }
    let listen: SocketAddr =
        listen.unwrap_or("[::]:0").parse().map_err(|_| Error::msg("the hub's listening address is not ip:port"))?;
    let log = Arc::new(Mutex::new(VecDeque::new()));
    let guests: Arc<Mutex<HashMap<u64, Guest>>> = Arc::new(Mutex::new(HashMap::new()));
    let seen = guests.clone();
    // A client's connection goes to the app's member listener, a guest's to
    // its pairing window until the window admitted the device.
    let target = Arc::new(move |a: Ipv6Addr| -> Option<u16> {
        if !hub::is_guest(&a) {
            return Some(member_port);
        }
        let g = seen.lock().ok()?;
        let g = g.values().find(|g| g.peer.addr == a && g.peer.until.is_none_or(|u| u > Instant::now()))?;
        Some(if g.admitted { member_port } else { g.port })
    });
    let clients = peers(clients)?;
    let hub = Hub::start(&key, device, obfuscation, clients.clone(), listen, target, logger(log.clone()))?;
    let port = hub.udp_port();
    let public = key32(&State::with_key(&key)?.public_key())?;
    let id = NEXT.fetch_add(1, Ordering::SeqCst);
    hubs(|t| {
        t.insert(
            id,
            RunningHub {
                hub,
                device: device.to_string(),
                public,
                obfuscation: obfuscation.cloned(),
                clients,
                guests,
                log,
            },
        );
        Ok(())
    })?;
    Ok(json!({ "id": id, "udp_port": port }))
}

fn peers(clients: &[Client]) -> Result<Vec<Peer>> {
    clients
        .iter()
        .map(|c| {
            let key = c.key.as_slice().try_into().map_err(|_| Error::msg("a client's key is not 32 bytes"))?;
            let psk =
                c.psk.as_slice().try_into().map_err(|_| Error::msg("a client's preshared key is not 32 bytes"))?;
            let addr = tunnel::addr(&c.device).ok_or_else(|| Error::msg(format!("{} is not a device ID", c.device)))?;
            Ok(Peer { key, psk, addr, until: None })
        })
        .collect()
}

/// A log that keeps its last MAX_LOG lines for the next status.
fn logger(log: Arc<Mutex<VecDeque<String>>>) -> Arc<dyn Fn(&str) + Send + Sync> {
    Arc::new(move |line: &str| {
        if let Ok(mut l) = log.lock() {
            if l.len() >= MAX_LOG {
                l.pop_front();
            }
            l.push_back(line.to_string());
        }
    })
}

fn hubs<T>(f: impl FnOnce(&mut HashMap<u64, RunningHub>) -> Result<T>) -> Result<T> {
    let mut g = HUBS.lock().map_err(|_| Error::msg("the hubs' table is broken"))?;
    f(g.get_or_insert_with(HashMap::new))
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
