// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The lite member's end of the group's WireGuard tunnel (docs/protocol.md,
//! section 11): its key and the hub's offer in tunnel.json, and the link to
//! the hub. The link runs GotaTun's WireGuard over a UDP socket and
//! smoltcp's TCP inside it, in one thread, and opens a port on the loopback
//! address that leads to the hub's member port: the node dials that port
//! with member TLS, as the phone apps do (docs/design.md, "Members").

use std::collections::VecDeque;
use std::io::{self, Read, Write};
use std::net::{Ipv6Addr, Shutdown, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::os::fd::AsRawFd;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use bytes::BytesMut;
use gotatun::noise::index_table::IndexTable;
use gotatun::noise::rate_limiter::RateLimiter;
use gotatun::noise::{Tunn, TunnResult};
use gotatun::packet::Packet;
use gotatun::x25519::{PublicKey, StaticSecret};
use serde::{Deserialize, Serialize};
use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::tcp;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr};

use crate::certs::{DeviceId, b64};
use crate::error::{Context, Error, Result};
use crate::files;
use crate::wire::TunnelOffer;

/// The tunnel state's file in the state directory.
pub const FILE_NAME: &str = "tunnel.json";
/// Inside the tunnel the hub serves the member protocol on this port only.
pub(crate) const MEMBER_PORT: u16 = 8764;
pub(crate) const KEEPALIVE: u16 = 25;
/// The MTU inside the tunnel: IPv6's minimum, which fits in a UDP datagram
/// on any path, so nothing is fragmented.
pub(crate) const MTU: usize = 1280;
/// How long the link waits for the hub's answer at one endpoint before it
/// tries the next.
const ENDPOINT_WAIT: Duration = Duration::from_secs(10);
const MAX_ENDPOINTS: usize = 8;
pub(crate) const TCP_BUFFER: usize = 64 << 10;
/// The connections through the tunnel's local port at once; this member
/// makes one or two.
pub(crate) const MAX_BRIDGES: usize = 32;
pub(crate) const HANDSHAKE_RATE_LIMIT: u64 = 100;
pub(crate) const MAX_POLL: Duration = Duration::from_millis(250);

/// The tunnel state, kept while sync away from home is on: the device's own
/// key and preshared key, made on it, and the offers of the group's hubs.
#[derive(Serialize, Deserialize, Clone)]
pub struct State {
    #[serde(rename = "v")]
    pub version: u32,
    /// The group this state belongs to; a state of another group is dropped.
    #[serde(default)]
    pub group: String,
    #[serde(with = "b64", default, skip_serializing_if = "Vec::is_empty")]
    key: Vec<u8>,
    /// The preshared key every hub uses for this device (docs/protocol.md,
    /// section 11, "Several hubs").
    #[serde(with = "b64")]
    pub psk: Vec<u8>,
    /// The offers of the group's hubs, one per hub.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hubs: Vec<Hub>,
    /// The key sealed by the TPM or the Secure Enclave, as Go keeps it;
    /// key stays out of the file then.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    key_tpm: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    key_se: Option<serde_json::Value>,
    /// Whether this member is one of the group's hubs, which admit the
    /// other members' keys; endpoints are the addresses it gives its
    /// clients, listen_port its UDP port (0 for the member port).
    #[serde(default, skip_serializing_if = "is_false")]
    pub is_hub: bool,
    /// It stopped being a hub and tells the peers that keep its offer to
    /// forget it (docs/protocol.md, section 11, "Stopping a hub").
    #[serde(default, skip_serializing_if = "is_false")]
    pub retired: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub endpoints: Vec<SocketAddr>,
    #[serde(default, skip_serializing_if = "is_zero_u16")]
    pub listen_port: u16,
    /// On a hub, its clients.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub members: Vec<Member>,
    /// The user agreed to sync away from home with the keys in files.
    #[serde(default, skip_serializing_if = "is_false")]
    pub keys_in_file: bool,
    /// Where the hub registers for the clients that cannot reach it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub forwarder: Option<Forwarder>,
    /// The blind relay this device meets its group at, without a hub.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay: Option<Forwarder>,
    /// On the hub, the group's AmneziaWG settings, which it gives its
    /// clients (src/awg.rs reads them).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub obfuscation: Option<serde_json::Value>,
    /// On a hub, the key it serves its clients with in the period
    /// serving_for, and the next one, from next_at_ms on (docs/protocol.md,
    /// section 11, "The hub's key"); empty for none.
    #[serde(with = "b64", default, skip_serializing_if = "Vec::is_empty")]
    serving: Vec<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    serving_tpm: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    serving_se: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub serving_for: String,
    #[serde(with = "b64", default, skip_serializing_if = "Vec::is_empty")]
    next: Vec<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    next_tpm: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    next_se: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub next_for: String,
    #[serde(default, skip_serializing_if = "is_zero_i64")]
    pub next_at_ms: i64,
    /// The keys the sealed blobs hold: key, serving and next.
    #[serde(skip)]
    sealed_for: [Vec<u8>; 3],
}

/// A client as its hub keeps it: its WireGuard key, its own preshared key,
/// and the chain it presented with the key, so that the hub drops it when
/// the records revoke it; empty for one another hub handed over.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct Member {
    pub device: String,
    #[serde(with = "b64")]
    pub key: Vec<u8>,
    #[serde(with = "b64")]
    pub psk: Vec<u8>,
    #[serde(with = "b64_list", default)]
    pub chain: Vec<Vec<u8>>,
}

/// A hub's forwarder or a device's relay: its address, for UDP and TCP,
/// and the pin of its key; for a forwarder the group's VLESS user ID and
/// way once it registered, and whether it is the project's.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct Forwarder {
    pub endpoint: SocketAddr,
    #[serde(rename = "key")]
    pub pin: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub vless_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vless: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub project: bool,
}

fn is_false(b: &bool) -> bool {
    !*b
}

fn is_zero_u16(n: &u16) -> bool {
    *n == 0
}

fn is_zero_i64(n: &i64) -> bool {
    *n == 0
}

/// A list of byte strings in standard base64, as Go's [][]byte: null is
/// none, both ways.
mod b64_list {
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &[Vec<u8>], s: S) -> Result<S::Ok, S::Error> {
        if v.is_empty() {
            return s.serialize_none();
        }
        s.collect_seq(v.iter().map(|b| STANDARD.encode(b)))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<Vec<u8>>, D::Error> {
        let list: Option<Vec<String>> = Option::deserialize(d)?;
        list.unwrap_or_default().iter().map(|t| STANDARD.decode(t).map_err(serde::de::Error::custom)).collect()
    }
}

/// The offer of one of the group's hubs, as this member keeps it.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct Hub {
    pub device: String,
    #[serde(with = "b64")]
    pub key: Vec<u8>,
    #[serde(with = "b64")]
    pub psk: Vec<u8>,
    #[serde(default)]
    pub endpoints: Vec<SocketAddr>,
    /// The key the hub serves with in its next period, which this member
    /// tries after `key`; empty for none.
    #[serde(with = "b64", default, skip_serializing_if = "Vec::is_empty")]
    pub next: Vec<u8>,
    /// The group's AmneziaWG settings when the hub hides its tunnel, as its
    /// offer gave them (src/awg.rs reads them).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub obfuscation: Option<serde_json::Value>,
    /// The way to the hub's forwarder over VLESS with XHTTP, as the offer
    /// gave it (src/vless.rs reads it).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vless: Option<serde_json::Value>,
}

/// The hubs that VLESS reached last, which try it first the next time
/// (docs/protocol.md, section 11, "VLESS").
static VLESS_FIRST: Mutex<Vec<String>> = Mutex::new(Vec::new());

impl Hub {
    /// Reports whether the offer gives a way to the hub: an address, or
    /// VLESS.
    pub fn reachable(&self) -> bool {
        !self.endpoints.is_empty() || self.vless.is_some()
    }
}

impl State {
    /// A new state with a new key and preshared key.
    pub fn new(group: &str) -> Result<State> {
        Ok(State { version: 1, group: group.to_string(), key: random_key()?, psk: random_key()?, ..State::empty() })
    }

    /// A state with a key the app keeps itself, as a phone does (ffi/).
    pub fn with_key(key: &[u8]) -> Result<State> {
        if key.len() != 32 || key.iter().all(|&b| b == 0) {
            return Err(Error::msg("the tunnel key is not 32 bytes, or is zeros"));
        }
        Ok(State { version: 1, group: String::new(), key: key.to_vec(), psk: random_key()?, ..State::empty() })
    }

    fn empty() -> State {
        State {
            version: 1,
            group: String::new(),
            key: Vec::new(),
            psk: Vec::new(),
            hubs: Vec::new(),
            key_tpm: None,
            key_se: None,
            is_hub: false,
            retired: false,
            endpoints: Vec::new(),
            listen_port: 0,
            members: Vec::new(),
            keys_in_file: false,
            forwarder: None,
            relay: None,
            obfuscation: None,
            serving: Vec::new(),
            serving_tpm: None,
            serving_se: None,
            serving_for: String::new(),
            next: Vec::new(),
            next_tpm: None,
            next_se: None,
            next_for: String::new(),
            next_at_ms: 0,
            sealed_for: Default::default(),
        }
    }

    /// The key slots and their sealed blobs: key, serving and next.
    #[allow(clippy::type_complexity)]
    fn slots(
        &mut self,
    ) -> [(&mut Vec<u8>, &mut Option<serde_json::Value>, &mut Option<serde_json::Value>, &mut Vec<u8>); 3] {
        let [a, b, c] = &mut self.sealed_for;
        [
            (&mut self.key, &mut self.key_tpm, &mut self.key_se, a),
            (&mut self.serving, &mut self.serving_tpm, &mut self.serving_se, b),
            (&mut self.next, &mut self.next_tpm, &mut self.next_se, c),
        ]
    }

    /// Opens the keys the hardware sealed, through cbb-helper.
    fn unseal(&mut self) -> Result<()> {
        for (key, tpm, se, sealed_for) in self.slots() {
            if tpm.is_none() && se.is_none() {
                continue;
            }
            let b = crate::keys::Sealed { secret: Vec::new(), tpm: tpm.clone(), se: se.clone() };
            *key = crate::keys::unseal(&b)?;
            *sealed_for = key.clone();
        }
        Ok(())
    }

    /// Seals each key once, and again when it changed, where the hardware
    /// seals, as Go's State.seal; reports whether a blob changed.
    fn seal(&mut self) -> Result<bool> {
        let mut changed = false;
        for (key, tpm, se, sealed_for) in self.slots() {
            if (tpm.is_some() || se.is_some()) && *sealed_for == *key && !key.is_empty() {
                continue;
            }
            changed |= tpm.is_some() || se.is_some();
            (*tpm, *se, *sealed_for) = (None, None, Vec::new());
            if key.is_empty() {
                continue;
            }
            if let Some(b) = crate::keys::seal(key).map_err(|e| e.context("cannot seal the tunnel key"))? {
                (*tpm, *se, *sealed_for) = (b.tpm, b.se, key.clone());
                changed = true;
            }
        }
        Ok(changed)
    }

    /// Reads dir/tunnel.json; None if there is none.
    pub fn load(dir: &Path) -> Result<Option<State>> {
        let path = dir.join(FILE_NAME);
        let data = match std::fs::read(&path) {
            Ok(d) => d,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(Error::with(format!("cannot read {}", path.display()), e)),
        };
        let mut st: State = serde_json::from_slice(&data).context(format!("{} is damaged", path.display()))?;
        if st.version != 1 {
            return Err(Error::msg(format!("{} is of unknown version {}", path.display(), st.version)));
        }
        st.unseal().map_err(|e| e.context(path.display().to_string()))?;
        if st.key.len() != 32 {
            return Err(Error::msg(format!("{} is damaged: the key is not 32 bytes", path.display())));
        }
        if st.psk.len() != 32 {
            return Err(Error::msg(format!("{} is damaged: the preshared key is not 32 bytes", path.display())));
        }
        if [&st.serving, &st.next].iter().any(|k| !k.is_empty() && k.len() != 32) {
            return Err(Error::msg(format!("{} is damaged: a hub's key is not 32 bytes", path.display())));
        }
        // A key from the file is sealed when the device has the hardware.
        if st.key_tpm.is_none() && st.key_se.is_none() && st.seal()? {
            st.save(dir)?;
        }
        Ok(Some(st))
    }

    /// The offer of the hub `device`, if this member keeps one.
    pub fn hub(&self, device: &str) -> Option<&Hub> {
        self.hubs.iter().find(|h| h.device == device)
    }

    /// The offers this member tries, in the group's order of hubs `order`:
    /// those of hubs in the order, with an address, each hub that gave its
    /// key for the next period once more with that key, right after.
    pub fn hubs_to_try(&self, order: &[String]) -> Vec<Hub> {
        let mut hubs: Vec<&Hub> = self.hubs.iter().filter(|h| order.contains(&h.device) && h.reachable()).collect();
        hubs.sort_by_key(|h| order.iter().position(|d| *d == h.device));
        let mut out = Vec::new();
        for h in hubs {
            out.push(h.clone());
            if !h.next.is_empty() {
                out.push(Hub { key: h.next.clone(), next: Vec::new(), ..h.clone() });
            }
        }
        out
    }

    /// Writes dir/tunnel.json, readable only by its owner.
    pub fn save(&mut self, dir: &Path) -> Result<()> {
        self.seal()?;
        let mut f = self.clone();
        for (key, tpm, se, _) in f.slots() {
            if tpm.is_some() || se.is_some() {
                key.clear();
            }
        }
        let data = serde_json::to_vec_pretty(&f).context("cannot encode the tunnel state")?;
        files::write_atomic(&dir.join(FILE_NAME), &data, 0o600)
    }

    /// Removes dir/tunnel.json, if there is one.
    pub fn remove(dir: &Path) -> Result<()> {
        let path = dir.join(FILE_NAME);
        match std::fs::remove_file(&path) {
            Err(e) if e.kind() != io::ErrorKind::NotFound => {
                Err(Error::with(format!("cannot remove {}", path.display()), e))
            }
            _ => Ok(()),
        }
    }

    fn secret(&self) -> StaticSecret {
        let mut k = [0u8; 32];
        k.copy_from_slice(&self.key);
        StaticSecret::from(k)
    }

    /// The device's public key, which its hellos offer the hub.
    pub fn public_key(&self) -> Vec<u8> {
        PublicKey::from(&self.secret()).as_bytes().to_vec()
    }

    /// The key the hub serves its clients with: the period's, else its own.
    pub fn serving_key(&self) -> [u8; 32] {
        let k = if self.serving.len() == 32 { &self.serving } else { &self.key };
        k.as_slice().try_into().unwrap_or([0; 32])
    }

    /// The public key of the hub's next period, empty for none.
    pub fn next_public(&self) -> Vec<u8> {
        public_of(&self.next)
    }

    /// Whether pub is one of this device's public keys.
    fn own_key(&self, public: &[u8]) -> bool {
        [&self.key, &self.serving, &self.next].iter().any(|k| !k.is_empty() && public_of(k) == public)
    }

    /// The addresses the hub gives its clients: its own, then its
    /// forwarder's, which they try last.
    pub fn hub_endpoints(&self) -> Vec<SocketAddr> {
        let mut eps = self.endpoints.clone();
        if let Some(f) = &self.forwarder
            && !eps.contains(&f.endpoint)
        {
            eps.push(f.endpoint);
        }
        eps
    }

    /// The offers this member tries, as hubs_to_try, on a hub only those of
    /// the hubs above self in the group's order (Go's hubsToTry).
    pub fn hubs_above(&self, order: &[String], me: &str) -> Vec<Hub> {
        let limit = if self.is_hub { order.iter().position(|d| d == me).unwrap_or(order.len()) } else { order.len() };
        let above: Vec<String> = order.iter().take(limit).filter(|d| *d != me).cloned().collect();
        self.hubs_to_try(&above)
    }

    /// The hub's clients as the running hub takes them.
    pub fn peers(&self) -> Result<Vec<crate::hub::Peer>> {
        self.members
            .iter()
            .map(|m| {
                let addr = addr(&m.device).ok_or_else(|| Error::msg(format!("{} is not a device ID", m.device)))?;
                let key: [u8; 32] = m.key.as_slice().try_into().context("a client's key is not 32 bytes")?;
                let psk: [u8; 32] = m.psk.as_slice().try_into().context("a client's preshared key is not 32 bytes")?;
                if self.own_key(&key) {
                    return Err(Error::msg("a client has the hub's key"));
                }
                Ok(crate::hub::Peer { key, psk, addr, until: None })
            })
            .collect()
    }

    /// Adds or updates the client device with the key and preshared key it
    /// offered and the chain it presented, as Go's State.Admit, and returns
    /// the client as the hub keeps it and whether the state changed. An
    /// empty psk keeps the client's, or makes one for a new key.
    pub fn admit(&mut self, device: &str, public: &[u8], psk: &[u8], chain: Vec<Vec<u8>>) -> Result<(Member, bool)> {
        addr(device).ok_or_else(|| Error::msg(format!("{device} is not a device ID")))?;
        if chain.is_empty() {
            return Err(Error::msg("a client without a certificate"));
        }
        if public.len() != 32 || public.iter().all(|&b| b == 0) || self.own_key(public) {
            return Err(Error::msg("a client offered no key or the hub's own"));
        }
        if !psk.is_empty() && psk.len() != 32 {
            return Err(Error::msg("a client offered a preshared key that is not 32 bytes"));
        }
        let psk = if psk.iter().all(|&b| b == 0) { &[][..] } else { psk };
        let i = self.members.iter().position(|m| m.device == device);
        if let Some(o) = self.members.iter().enumerate().find(|(j, m)| Some(*j) != i && m.key == public) {
            return Err(Error::msg(format!("{device} offered the key of {}", o.1.device)));
        }
        if let Some(i) = i {
            let c = &mut self.members[i];
            if c.key == public && (psk.is_empty() || c.psk == psk) && c.chain == chain {
                return Ok((c.clone(), false));
            }
            if !psk.is_empty() {
                c.psk = psk.to_vec();
            } else if c.key != public {
                c.psk = random_key()?;
            }
            c.key = public.to_vec();
            c.chain = chain;
            return Ok((c.clone(), true));
        }
        if self.members.len() >= MAX_MEMBERS {
            return Err(Error::msg("the hub has too many clients"));
        }
        let psk = if psk.is_empty() { random_key()? } else { psk.to_vec() };
        let c = Member { device: device.to_string(), key: public.to_vec(), psk, chain };
        self.members.push(c.clone());
        Ok((c, true))
    }

    /// Adds a client another hub shared or handed over, with its key and
    /// preshared key and no chain yet, as Go's State.Take: a client this hub
    /// met itself stays as it is. Returns whether the state changed.
    pub fn take(&mut self, device: &str, public: &[u8], psk: &[u8]) -> Result<bool> {
        addr(device).ok_or_else(|| Error::msg(format!("{device} is not a device ID")))?;
        let zero = |k: &[u8]| k.len() != 32 || k.iter().all(|&b| b == 0);
        if zero(public) || zero(psk) {
            return Err(Error::msg("a client without a key"));
        }
        if self.own_key(public) {
            return Err(Error::msg(format!("{device} has the hub's own key")));
        }
        let mut i = None;
        for (j, o) in self.members.iter().enumerate() {
            if o.device == device {
                i = Some(j);
            } else if o.key == public {
                return Err(Error::msg(format!("{device} has the key of {}", o.device)));
            }
        }
        if let Some(i) = i {
            let c = &mut self.members[i];
            if !c.chain.is_empty() || c.key == public && c.psk == psk {
                return Ok(false);
            }
            (c.key, c.psk) = (public.to_vec(), psk.to_vec());
            return Ok(true);
        }
        if self.members.len() >= MAX_MEMBERS {
            return Err(Error::msg("the hub has too many clients"));
        }
        self.members.push(Member {
            device: device.to_string(),
            key: public.to_vec(),
            psk: psk.to_vec(),
            chain: Vec::new(),
        });
        Ok(true)
    }

    /// Keeps the offer of a hub in place of its earlier one, as Go's
    /// State.SetHub; returns whether the state changed.
    pub fn set_hub(&mut self, h: Hub) -> Result<bool> {
        if self.own_key(&h.key) || !h.next.is_empty() && self.own_key(&h.next) {
            return Err(Error::msg("the hub offered this device's own key"));
        }
        let full = self.hubs.len() >= MAX_MEMBERS;
        match self.hubs.iter_mut().find(|o| o.device == h.device) {
            Some(o) if *o == h => Ok(false),
            Some(o) => {
                *o = h;
                Ok(true)
            }
            None if full => Err(Error::msg("too many hubs")),
            None => {
                self.hubs.push(h);
                Ok(true)
            }
        }
    }

    /// Forgets the offers of the hubs keep refuses and returns their
    /// devices.
    pub fn forget_hubs(&mut self, keep: &dyn Fn(&Hub) -> bool) -> Vec<String> {
        let mut gone = Vec::new();
        self.hubs.retain(|h| {
            let k = keep(h);
            if !k {
                gone.push(h.device.clone());
            }
            k
        });
        gone
    }

    /// Forgets the hub's keys for the server credentials' periods, once
    /// it is no hub.
    pub fn clear_periods(&mut self) {
        for (key, tpm, se, sealed_for) in self.slots().into_iter().skip(1) {
            (*key, *tpm, *se, *sealed_for) = (Vec::new(), None, None, Vec::new());
        }
        self.serving_for.clear();
        self.next_for.clear();
        self.next_at_ms = 0;
    }

    /// Forgets the clients keep refuses and returns their devices.
    pub fn prune(&mut self, keep: &dyn Fn(&Member) -> bool) -> Vec<String> {
        let mut gone = Vec::new();
        self.members.retain(|m| {
            let k = keep(m);
            if !k {
                gone.push(m.device.clone());
            }
            k
        });
        gone
    }
}

/// The public key of a private key.
pub fn public_key_of(key: &[u8; 32]) -> Vec<u8> {
    public_of(key)
}

/// The public key of a private key, empty for none.
fn public_of(key: &[u8]) -> Vec<u8> {
    match <[u8; 32]>::try_from(key) {
        Ok(k) => PublicKey::from(&StaticSecret::from(k)).as_bytes().to_vec(),
        Err(_) => Vec::new(),
    }
}

/// The clients a hub keeps at most, as Go's.
const MAX_MEMBERS: usize = 256;

/// A new tunnel key, which a phone's app keeps (ffi/).
pub fn new_key() -> Result<Vec<u8>> {
    random_key()
}

/// 32 random bytes, for a key.
fn random_key() -> Result<Vec<u8>> {
    let mut key = vec![0u8; 32];
    getrandom::fill(&mut key).map_err(|_| Error::msg("cannot make a key: the system has no randomness"))?;
    Ok(key)
}

/// Checks the offer of the hub `from` and returns what this member keeps of
/// it: with AmneziaWG's settings (src/awg.rs) and the way over VLESS with
/// XHTTP (src/vless.rs), if it has them. REALITY is refused, as rustls
/// cannot make a browser's ClientHello.
pub fn hub_from_offer(from: &DeviceId, o: &TunnelOffer) -> Result<Hub> {
    if let Some(v) = &o.vless {
        cbb_core::vless::Link::from_offer(v)?;
    }
    if let Some(v) = &o.obfuscation {
        crate::awg::Obfuscation::from_offer(v)?;
    }
    if o.hub_key.len() != 32 || o.psk.len() != 32 || !o.next_key.is_empty() && o.next_key.len() != 32 {
        return Err(Error::msg("the hub's offer does not have 32-byte keys"));
    }
    // As in Go: a key of zeros is no key.
    if o.hub_key.iter().all(|&b| b == 0) || o.psk.iter().all(|&b| b == 0) {
        return Err(Error::msg("the hub's offer has a key of zeros"));
    }
    if o.endpoints.len() > MAX_ENDPOINTS {
        return Err(Error::msg(format!("the hub's offer has more than {MAX_ENDPOINTS} addresses")));
    }
    let endpoints = o
        .endpoints
        .iter()
        .map(|e| match e.parse::<SocketAddr>() {
            Ok(a) if a.port() != 0 => Ok(a),
            _ => Err(Error::msg(format!("the hub's offer has a bad address {e:?}"))),
        })
        .collect::<Result<Vec<_>>>()?;
    addr(from.as_str()).ok_or_else(|| Error::msg(format!("{from} is not a device ID")))?;
    Ok(Hub {
        device: from.to_string(),
        key: o.hub_key.clone(),
        psk: o.psk.clone(),
        endpoints,
        next: o.next_key.clone(),
        obfuscation: o.obfuscation.clone(),
        vless: o.vless.clone(),
    })
}

/// The tunnel address of a device: fd00:cbb::/32 followed by the first 96
/// bits of its ID (32 lowercase hex characters).
pub fn addr(id: &str) -> Option<Ipv6Addr> {
    crate::tunnel_addr(id)
}

/// The running link to the hub. Dropping it stops it.
pub struct Link {
    port: u16,
    /// The way over VLESS, which the pump's thread sends to; it stops
    /// after that thread.
    _vless: Option<crate::vless::Client>,
    stop: Arc<AtomicBool>,
    answered: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl Link {
    /// Starts the link of this device (me) to the hub.
    pub fn start(st: &State, hub: &Hub, me: &DeviceId, log: Arc<dyn Fn(&str) + Send + Sync>) -> Result<Link> {
        let own = addr(me.as_str()).ok_or_else(|| Error::msg(format!("{me} is not a device ID")))?;
        let peer = addr(&hub.device).ok_or_else(|| Error::msg(format!("{} is not a device ID", hub.device)))?;
        Link::start_at(st, hub, own, peer, log)
    }

    /// Starts a link with the tunnel addresses given: own, this device's,
    /// and peer, the hub's, as the blind relay gives them.
    pub fn start_at(
        st: &State,
        hub: &Hub,
        own: Ipv6Addr,
        peer: Ipv6Addr,
        log: Arc<dyn Fn(&str) + Send + Sync>,
    ) -> Result<Link> {
        if !hub.reachable() {
            return Err(Error::msg("the group's hub has no address away from home yet"));
        }
        // With VLESS, the hub's addresses are tried over UDP only when its
        // tunnel is hidden with AmneziaWG, and VLESS after them, or first
        // when it reached the hub the last time.
        let vless = match &hub.vless {
            Some(v) => Some(crate::vless::Client::start(v, log.clone())?),
            None => None,
        };
        let mut endpoints = match (&vless, &hub.obfuscation) {
            (Some(_), None) => Vec::new(),
            _ => hub.endpoints.clone(),
        };
        let vless_at = vless.as_ref().map(|v| v.addr());
        if let Some(at) = vless_at {
            if VLESS_FIRST.lock().unwrap().contains(&hub.device) {
                endpoints.insert(0, at);
            } else {
                endpoints.push(at);
            }
        }
        let ln = TcpListener::bind("127.0.0.1:0").context("cannot open the tunnel's local port")?;
        ln.set_nonblocking(true).context("cannot open the tunnel's local port")?;
        let port = ln.local_addr().context("cannot open the tunnel's local port")?.port();

        let secret = st.secret();
        let public = PublicKey::from(&secret);
        let hub_key: [u8; 32] = hub.key.as_slice().try_into().context("the hub's key is not 32 bytes")?;
        let psk: [u8; 32] = hub.psk.as_slice().try_into().context("the tunnel's preshared key is not 32 bytes")?;
        let awg = match &hub.obfuscation {
            Some(v) => Some(crate::awg::Awg::new(crate::awg::Obfuscation::from_offer(v)?, &hub_key, public.as_bytes())),
            None => None,
        };
        let limiter = Arc::new(RateLimiter::new(&public, HANDSHAKE_RATE_LIMIT));
        let tunn = Tunn::new(
            secret,
            PublicKey::from(hub_key),
            Some(psk),
            Some(KEEPALIVE),
            IndexTable::from_os_rng(),
            limiter.clone(),
        );
        let stop = Arc::new(AtomicBool::new(false));
        let answered = Arc::new(AtomicBool::new(false));
        let mut pump = Pump::new(tunn, limiter, endpoints, ln, own, peer, answered.clone(), log)?;
        pump.awg = awg;
        pump.vless = vless_at.map(|at| (hub.device.clone(), at));
        let thread = {
            let stop = stop.clone();
            std::thread::spawn(move || pump.run(&stop))
        };
        Ok(Link { port, _vless: vless, stop, answered, thread: Some(thread) })
    }

    /// The local port that leads to the hub's member port.
    pub fn local(&self) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], self.port))
    }

    /// Reports whether the hub has answered through the tunnel.
    pub fn answered(&self) -> bool {
        self.answered.load(Ordering::SeqCst)
    }
}

impl Drop for Link {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

/// The IP packets between smoltcp and the tunnel.
#[derive(Default)]
pub(crate) struct Queues {
    pub(crate) rx: VecDeque<Vec<u8>>,
    pub(crate) tx: VecDeque<Vec<u8>>,
}

pub(crate) struct Rx(Vec<u8>);
pub(crate) struct Tx<'a>(&'a mut VecDeque<Vec<u8>>);

impl RxToken for Rx {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(&self.0)
    }
}

impl TxToken for Tx<'_> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let mut buf = vec![0u8; len];
        let r = f(&mut buf);
        self.0.push_back(buf);
        r
    }
}

impl Device for Queues {
    type RxToken<'a> = Rx;
    type TxToken<'a> = Tx<'a>;

    fn receive(&mut self, _: smoltcp::time::Instant) -> Option<(Rx, Tx<'_>)> {
        let p = self.rx.pop_front()?;
        Some((Rx(p), Tx(&mut self.tx)))
    }

    fn transmit(&mut self, _: smoltcp::time::Instant) -> Option<Tx<'_>> {
        Some(Tx(&mut self.tx))
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut c = DeviceCapabilities::default();
        c.medium = Medium::Ip;
        c.max_transmission_unit = MTU;
        c
    }
}

/// One connection between a local TCP socket and one of smoltcp's.
pub(crate) struct Bridge {
    pub(crate) local: TcpStream,
    pub(crate) handle: SocketHandle,
    /// Read from the local side, not yet taken by smoltcp.
    pub(crate) up: Vec<u8>,
    /// From the tunnel, not yet written to the local side.
    pub(crate) down: Vec<u8>,
    pub(crate) local_eof: bool,
    pub(crate) done: bool,
}

struct Pump {
    tunn: Tunn,
    limiter: Arc<RateLimiter>,
    endpoints: Vec<SocketAddr>,
    current: usize,
    since: Instant,
    udp: UdpSocket,
    ln: TcpListener,
    iface: Interface,
    dev: Queues,
    sockets: SocketSet<'static>,
    bridges: Vec<Bridge>,
    peer: Ipv6Addr,
    next_port: u16,
    answered: Arc<AtomicBool>,
    log: Arc<dyn Fn(&str) + Send + Sync>,
    said: bool,
    /// AmneziaWG around the messages, for a hub that hides its tunnel.
    awg: Option<crate::awg::Awg>,
    /// The hub and the local address of its way over VLESS, if it has one.
    vless: Option<(String, SocketAddr)>,
}

/// A UDP socket of the endpoint's family.
fn udp_for(ep: &SocketAddr) -> Result<UdpSocket> {
    let any: SocketAddr = if ep.is_ipv4() { "0.0.0.0:0".parse().unwrap() } else { "[::]:0".parse().unwrap() };
    let s = UdpSocket::bind(any).context("cannot open the tunnel's UDP socket")?;
    s.set_nonblocking(true).context("cannot open the tunnel's UDP socket")?;
    Ok(s)
}

pub(crate) fn now() -> smoltcp::time::Instant {
    smoltcp::time::Instant::now()
}

impl Pump {
    #[allow(clippy::too_many_arguments)]
    fn new(
        tunn: Tunn,
        limiter: Arc<RateLimiter>,
        endpoints: Vec<SocketAddr>,
        ln: TcpListener,
        own: Ipv6Addr,
        peer: Ipv6Addr,
        answered: Arc<AtomicBool>,
        log: Arc<dyn Fn(&str) + Send + Sync>,
    ) -> Result<Pump> {
        let udp = udp_for(&endpoints[0])?;
        let mut dev = Queues::default();
        let mut iface = Interface::new(Config::new(HardwareAddress::Ip), &mut dev, now());
        // The hub's address is in the same /32, so it is reached directly.
        iface.update_ip_addrs(|a| {
            let _ = a.push(IpCidr::new(IpAddress::Ipv6(own), 32));
        });
        Ok(Pump {
            tunn,
            limiter,
            endpoints,
            current: 0,
            since: Instant::now(),
            udp,
            ln,
            iface,
            dev,
            sockets: SocketSet::new(Vec::new()),
            bridges: Vec::new(),
            peer,
            next_port: 49152,
            answered,
            log,
            said: false,
            awg: None,
            vless: None,
        })
    }

    fn run(&mut self, stop: &AtomicBool) {
        // Start the handshake at once, so the first dial does not wait for it.
        if let Some(p) = self.tunn.format_handshake_initiation(false) {
            self.send(Packet::from(gotatun::packet::WgKind::from(p)).as_ref());
        }
        while !stop.load(Ordering::SeqCst) {
            let busy = self.step();
            if !busy {
                self.wait();
            }
        }
        for b in &self.bridges {
            let _ = b.local.shutdown(Shutdown::Both);
        }
    }

    /// Does what can be done now; reports whether anything moved.
    fn step(&mut self) -> bool {
        let mut busy = false;
        self.accept();
        busy |= self.receive();
        if let Ok(Some(p)) = self.tunn.update_timers() {
            self.send(Packet::from(p).as_ref());
        }
        self.next_endpoint();
        busy |= self.bridge();
        self.iface.poll(now(), &mut self.dev, &mut self.sockets);
        busy |= self.bridge();
        busy |= self.transmit();
        busy
    }

    fn send(&mut self, data: &[u8]) {
        match self.awg.as_mut().map(|a| a.outgoing(data)) {
            Some(datagrams) => {
                for d in datagrams {
                    self.send_datagram(&d);
                }
            }
            None => self.send_datagram(data),
        }
    }

    fn send_datagram(&mut self, data: &[u8]) {
        let ep = self.endpoints[self.current];
        if let Err(e) = self.udp.send_to(data, ep)
            && !self.said
        {
            (self.log)(&format!("cbb: sending to the hub at {ep}: {e}"));
            self.said = true;
        }
    }

    /// Notes that the hub answered, and through which way.
    fn answer(&mut self) {
        if self.answered.swap(true, Ordering::SeqCst) {
            return;
        }
        if let Some((hub, at)) = &self.vless {
            let mut first = VLESS_FIRST.lock().unwrap();
            first.retain(|h| h != hub);
            if self.endpoints[self.current] == *at {
                first.push(hub.clone());
            }
        }
    }

    /// Tries the next endpoint while the hub does not answer at this one.
    fn next_endpoint(&mut self) {
        if self.tunn.has_active_session() || self.endpoints.len() < 2 || self.since.elapsed() < ENDPOINT_WAIT {
            return;
        }
        self.current = (self.current + 1) % self.endpoints.len();
        self.since = Instant::now();
        let ep = self.endpoints[self.current];
        if self.endpoints[(self.current + self.endpoints.len() - 1) % self.endpoints.len()].is_ipv4() != ep.is_ipv4() {
            match udp_for(&ep) {
                Ok(s) => self.udp = s,
                Err(e) => (self.log)(&format!("cbb: {}", e.for_log())),
            }
        }
        if let Some(p) = self.tunn.format_handshake_initiation(true) {
            self.send(Packet::from(gotatun::packet::WgKind::from(p)).as_ref());
        }
    }

    fn accept(&mut self) {
        while let Ok((s, from)) = self.ln.accept() {
            // The port is on the loopback, where every local user may
            // connect: only this member's own user is let through, and only
            // so many at once.
            if self.bridges.len() >= MAX_BRIDGES || !own_user(&tcp_table(), from, self.ln.local_addr().ok()) {
                let _ = s.shutdown(Shutdown::Both);
                continue;
            }
            if s.set_nonblocking(true).is_err() {
                continue;
            }
            let _ = s.set_nodelay(true);
            let mut sock = tcp::Socket::new(
                tcp::SocketBuffer::new(vec![0; TCP_BUFFER]),
                tcp::SocketBuffer::new(vec![0; TCP_BUFFER]),
            );
            sock.set_nagle_enabled(false);
            sock.set_timeout(Some(smoltcp::time::Duration::from_secs(30)));
            let port = self.next_port;
            self.next_port = if self.next_port == u16::MAX { 49152 } else { self.next_port + 1 };
            if sock.connect(self.iface.context(), (IpAddress::Ipv6(self.peer), MEMBER_PORT), port).is_err() {
                let _ = s.shutdown(Shutdown::Both);
                continue;
            }
            let handle = self.sockets.add(sock);
            self.bridges.push(Bridge {
                local: s,
                handle,
                up: Vec::new(),
                down: Vec::new(),
                local_eof: false,
                done: false,
            });
        }
    }

    /// Takes the datagrams from the hub through WireGuard.
    fn receive(&mut self) -> bool {
        let mut busy = false;
        let mut buf = BytesMut::zeroed(2048);
        loop {
            let (n, from) = match self.udp.recv_from(&mut buf) {
                Ok(r) => r,
                Err(_) => return busy,
            };
            busy = true;
            let packet = match self.awg.as_mut() {
                Some(a) => match a.incoming(&buf[..n]) {
                    Some(wg) => Packet::from_bytes(BytesMut::from(&wg[..])),
                    None => continue,
                },
                None => Packet::from_bytes(BytesMut::from(&buf[..n])),
            };
            let wg = match self.limiter.verify_packet(from, packet) {
                Ok(wg) => wg,
                Err(TunnResult::WriteToNetwork(p)) => {
                    self.send(Packet::from(p).as_ref());
                    continue;
                }
                Err(_) => continue,
            };
            match self.tunn.handle_incoming_packet(wg) {
                TunnResult::WriteToNetwork(p) => {
                    self.answer();
                    self.send(Packet::from(p).as_ref());
                    // A new session sends what waited for it.
                    let mut mtu = gotatun::tun::MtuWatcher::new(MTU as u16);
                    let queued: Vec<_> = self.tunn.get_queued_packets(&mut mtu).collect();
                    for p in queued {
                        self.send(Packet::from(p).as_ref());
                    }
                }
                TunnResult::WriteToTunnel(p) => {
                    self.answer();
                    let ip: &[u8] = p.as_ref();
                    // Only what comes from the hub's own address, as
                    // WireGuard's allowed IPs would have it.
                    if ip.len() >= 40 && ip[0] >> 4 == 6 && ip[8..24] == self.peer.octets() {
                        self.dev.rx.push_back(ip.to_vec());
                    }
                }
                TunnResult::Done | TunnResult::Err(_) => {}
            }
        }
    }

    /// Sends what smoltcp wrote through WireGuard.
    fn transmit(&mut self) -> bool {
        let mut busy = false;
        while let Some(ip) = self.dev.tx.pop_front() {
            busy = true;
            if let Some(p) = self.tunn.handle_outgoing_packet(Packet::from_bytes(BytesMut::from(&ip[..])), None) {
                self.send(Packet::from(p).as_ref());
            }
        }
        busy
    }

    /// Moves bytes between the local connections and smoltcp's sockets.
    fn bridge(&mut self) -> bool {
        let mut busy = false;
        let mut buf = [0u8; 16 << 10];
        for b in &mut self.bridges {
            busy |= move_bytes(b, self.sockets.get_mut::<tcp::Socket>(b.handle), &mut buf);
        }
        let sockets = &mut self.sockets;
        self.bridges.retain(|b| {
            if b.done {
                sockets.remove(b.handle);
            }
            !b.done
        });
        busy
    }

    /// Waits for a datagram, a local connection or byte, or smoltcp's next
    /// timer, at most MAX_POLL.
    fn wait(&mut self) {
        let delay = self.iface.poll_delay(now(), &self.sockets).map(|d| Duration::from_micros(d.total_micros()));
        let timeout = delay.map_or(MAX_POLL, |d| d.min(MAX_POLL));
        let mut fds = vec![
            libc::pollfd { fd: self.udp.as_raw_fd(), events: libc::POLLIN, revents: 0 },
            libc::pollfd { fd: self.ln.as_raw_fd(), events: libc::POLLIN, revents: 0 },
        ];
        for b in &self.bridges {
            let mut events = 0;
            if !b.local_eof && b.up.len() < TCP_BUFFER {
                events |= libc::POLLIN;
            }
            if !b.down.is_empty() {
                events |= libc::POLLOUT;
            }
            fds.push(libc::pollfd { fd: b.local.as_raw_fd(), events, revents: 0 });
        }
        // SAFETY: fds is a valid array of pollfd of the given length.
        unsafe {
            libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, timeout.as_millis() as libc::c_int);
        }
    }
}

/// Moves bytes between one local connection and its smoltcp socket, both
/// ways, and closes each side when the other ended; reports whether
/// anything moved.
pub(crate) fn move_bytes(b: &mut Bridge, s: &mut tcp::Socket, buf: &mut [u8]) -> bool {
    let mut busy = false;
    // Local to the hub.
    if !b.local_eof && b.up.len() < TCP_BUFFER {
        match b.local.read(buf) {
            Ok(0) => b.local_eof = true,
            Ok(n) => {
                b.up.extend_from_slice(&buf[..n]);
                busy = true;
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
            Err(_) => b.done = true,
        }
    }
    if !b.up.is_empty()
        && s.can_send()
        && let Ok(n) = s.send_slice(&b.up)
    {
        b.up.drain(..n);
        busy |= n > 0;
    }
    if b.local_eof && b.up.is_empty() && s.may_send() {
        s.close();
    }
    // The hub to local.
    if b.down.len() < TCP_BUFFER
        && s.can_recv()
        && let Ok(n) = s.recv_slice(buf)
    {
        b.down.extend_from_slice(&buf[..n]);
        busy |= n > 0;
    }
    if !b.down.is_empty() {
        match b.local.write(&b.down) {
            Ok(n) => {
                b.down.drain(..n);
                busy |= n > 0;
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
            Err(_) => b.done = true,
        }
    }
    if b.down.is_empty() && !s.may_recv() && !s.can_recv() && s.state() != tcp::State::SynSent {
        let _ = b.local.shutdown(Shutdown::Write);
        if !s.is_open() || b.local_eof {
            b.done = true;
        }
    }
    if b.done {
        s.abort();
        let _ = b.local.shutdown(Shutdown::Both);
    }
    busy
}

/// The kernel's table of IPv4 TCP sockets, or "" where there is none.
fn tcp_table() -> String {
    std::fs::read_to_string("/proc/net/tcp").unwrap_or_default()
}

/// Reports whether the socket at from, connected to the listener at to,
/// belongs to this process's user by table, the text of /proc/net/tcp.
/// Without the table (a system without /proc) it cannot tell and lets the
/// connection through.
fn own_user(table: &str, from: SocketAddr, to: Option<SocketAddr>) -> bool {
    let (SocketAddr::V4(from), Some(SocketAddr::V4(to))) = (from, to) else { return true };
    if table.is_empty() {
        return true;
    }
    // Addresses are written as the kernel holds them: the IPv4 address in
    // the host's byte order, the port in network order.
    let hex = |a: std::net::SocketAddrV4| format!("{:08X}:{:04X}", u32::from_ne_bytes(a.ip().octets()), a.port());
    let (local, remote) = (hex(from), hex(to));
    // SAFETY: geteuid has no preconditions.
    let me = unsafe { libc::geteuid() };
    table.lines().skip(1).any(|l| {
        let f: Vec<&str> = l.split_whitespace().collect();
        f.len() > 7 && f[1] == local && f[2] == remote && f[7].parse::<u32>().ok() == Some(me)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A Go hub's state (testdata/interop/tunnel-state.json, which
    /// internal/tunnel's TestStateVectors writes) reads and saves again
    /// the same.
    #[test]
    fn a_go_hubs_state_saves_the_same() {
        let want: serde_json::Value =
            serde_json::from_str(include_str!("../../testdata/interop/tunnel-state.json")).unwrap();
        let dir = std::env::temp_dir().join(format!("cbb-tunnel-go-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(FILE_NAME), want.to_string()).unwrap();
        let mut st = State::load(&dir).unwrap().unwrap();
        assert!(st.is_hub && st.members.len() == 2 && st.members[0].chain.len() == 2 && st.forwarder.is_some());
        assert_eq!((st.serving.len(), st.next_for.as_str(), st.listen_port), (32, "2026-12", 51820));
        st.save(&dir).unwrap();
        let got: serde_json::Value = serde_json::from_slice(&std::fs::read(dir.join(FILE_NAME)).unwrap()).unwrap();
        assert_eq!(got, want);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn local_port_takes_its_own_user() {
        let ln = TcpListener::bind("127.0.0.1:0").unwrap();
        let c = TcpStream::connect(ln.local_addr().unwrap()).unwrap();
        let (_s, from) = ln.accept().unwrap();
        assert_eq!(from, c.local_addr().unwrap());
        let to = ln.local_addr().ok();
        let table = tcp_table();
        if !table.is_empty() {
            assert!(own_user(&table, from, to), "this process's own connection");
        }
        // The same connection under another user's uid, and an unknown one.
        let hex = |a: SocketAddr| match a {
            SocketAddr::V4(a) => format!("{:08X}:{:04X}", u32::from_ne_bytes(a.ip().octets()), a.port()),
            _ => unreachable!(),
        };
        // SAFETY: geteuid has no preconditions.
        let other = unsafe { libc::geteuid() } + 1;
        let line = |uid: u32| {
            format!(
                "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n   0: {} {} 01 00000000:00000000 00:00000000 00000000 {uid:5} 0 1 1\n",
                hex(from),
                hex(to.unwrap())
            )
        };
        assert!(!own_user(&line(other), from, to));
        assert!(own_user(&line(other - 1), from, to));
        assert!(!own_user("header\n", from, to), "a connection the table does not show");
        assert!(own_user("", from, to), "no table");
    }

    #[test]
    fn addresses() {
        assert_eq!(
            addr("0123456789abcdef0123456789abcdef").unwrap().to_string(),
            "fd00:cbb:123:4567:89ab:cdef:123:4567"
        );
        assert!(addr("0123456789ABCDEF0123456789abcdef").is_none());
        assert!(addr("0123").is_none());
    }

    #[test]
    fn offers() {
        let id = DeviceId::parse("0123456789abcdef0123456789abcdef").unwrap();
        // As Go encodes node.TunnelOffer.
        let go = r#"{"hub_key":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=","psk":"AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=","endpoints":["192.0.2.1:8764","[2001:db8::1]:51820"]}"#;
        let o: TunnelOffer = serde_json::from_str(go).unwrap();
        let hub = hub_from_offer(&id, &o).unwrap();
        assert_eq!(hub.key, vec![1; 32]);
        assert_eq!(hub.psk, vec![2; 32]);
        assert_eq!(hub.endpoints, vec!["192.0.2.1:8764".parse().unwrap(), "[2001:db8::1]:51820".parse().unwrap()]);
        let hidden = r#"{"hub_key":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=","psk":"AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=","obfuscation":{"jc":4}}"#;
        let o: TunnelOffer = serde_json::from_str(hidden).unwrap();
        assert!(hub_from_offer(&id, &o).unwrap_err().message().contains("AmneziaWG"), "settings that do not read");
        let awg = r#"{"hub_key":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=","psk":"AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=","obfuscation":{"jc":5,"jmin":50,"jmax":300,"s1":20,"s2":33,"s3":17,"s4":25,"h1":"1000016-1065551","h2":"1073741840-1073807375","h3":"2147483664-2147549199","h4":"3221225488-3221291023","header_protection_key":"BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc="}}"#;
        let hub = hub_from_offer(&id, &serde_json::from_str(awg).unwrap()).unwrap();
        assert!(hub.obfuscation.is_some());
        let vless = r#"{"hub_key":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=","psk":"AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=","vless":{}}"#;
        assert!(hub_from_offer(&id, &serde_json::from_str(vless).unwrap()).is_err(), "empty VLESS settings");
        let xhttp = r#"{"hub_key":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=","psk":"AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=","vless":{"transport":"xhttp","endpoint":"192.0.2.7:443","server_name":"cbb.example.org","path":"/AbC-12_xyz0123456/a-group-of-its-own","id":"6f1c2b9e-3d4a-4f5b-8c7d-0e1f2a3b4c5d"}}"#;
        let hub = hub_from_offer(&id, &serde_json::from_str(xhttp).unwrap()).unwrap();
        assert!(hub.endpoints.is_empty() && hub.reachable(), "VLESS alone is a way");
        let reality = r#"{"hub_key":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=","psk":"AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=","vless":{"endpoint":"192.0.2.7:443","public_key":"AAAA","short_id":"ab","server_name":"cbb.example.org","id":"6f1c2b9e-3d4a-4f5b-8c7d-0e1f2a3b4c5d"}}"#;
        assert!(hub_from_offer(&id, &serde_json::from_str(reality).unwrap()).is_err(), "REALITY");
        let short = r#"{"hub_key":"AQE=","psk":"AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI="}"#;
        assert!(hub_from_offer(&id, &serde_json::from_str(short).unwrap()).is_err());

        // The key for the next period is tried right after the key now.
        let next = r#"{"hub_key":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=","psk":"AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=","endpoints":["192.0.2.1:8764"],"next_key":"AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM="}"#;
        let hub = hub_from_offer(&id, &serde_json::from_str(next).unwrap()).unwrap();
        assert_eq!(hub.next, vec![3; 32]);
        let mut st = State::new("abc").unwrap();
        st.hubs.push(hub);
        let tried = st.hubs_to_try(&[id.to_string()]);
        assert_eq!(tried.iter().map(|h| h.key[0]).collect::<Vec<_>>(), vec![1, 3]);
        assert!(tried[1].next.is_empty());
        let bad = r#"{"hub_key":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=","psk":"AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=","next_key":"AQE="}"#;
        assert!(hub_from_offer(&id, &serde_json::from_str(bad).unwrap()).is_err());
        // Keys of zeros and a port 0, which Go refuses too.
        let zero = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
        for bad in [
            format!(r#"{{"hub_key":"{zero}","psk":"AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI="}}"#),
            format!(r#"{{"hub_key":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=","psk":"{zero}"}}"#),
            r#"{"hub_key":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=","psk":"AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=","endpoints":["192.0.2.1:0"]}"#.to_string(),
        ] {
            assert!(hub_from_offer(&id, &serde_json::from_str(&bad).unwrap()).is_err(), "{bad}");
        }
    }

    #[test]
    fn state_keeps_its_key() {
        let dir = std::env::temp_dir().join(format!("cbb-tunnel-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let mut st = State::new("abc").unwrap();
        st.save(&dir).unwrap();
        let back = State::load(&dir).unwrap().unwrap();
        assert_eq!(back.public_key(), st.public_key());
        assert_eq!(back.group, "abc");
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(dir.join(FILE_NAME)).unwrap().permissions().mode() & 0o777, 0o600);
        State::remove(&dir).unwrap();
        assert!(State::load(&dir).unwrap().is_none());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The internet checksum over the IPv6 pseudo-header and the segment.
    fn checksum6(src: &Ipv6Addr, dst: &Ipv6Addr, proto: u8, seg: &[u8]) -> u16 {
        let mut sum: u32 = 0;
        let mut add = |b: &[u8]| {
            for c in b.chunks(2) {
                sum += u32::from(u16::from_be_bytes([c[0], *c.get(1).unwrap_or(&0)]));
            }
        };
        add(&src.octets());
        add(&dst.octets());
        add(&(seg.len() as u32).to_be_bytes());
        add(&[0, 0, 0, proto]);
        add(seg);
        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        !(sum as u16)
    }

    /// An IPv6 packet from src to dst carrying seg of protocol proto, its
    /// checksum filled in at sum_at.
    fn ip6(src: Ipv6Addr, dst: Ipv6Addr, proto: u8, mut seg: Vec<u8>, sum_at: usize) -> Vec<u8> {
        let c = checksum6(&src, &dst, proto, &seg);
        seg[sum_at..sum_at + 2].copy_from_slice(&c.to_be_bytes());
        let mut p = vec![0x60, 0, 0, 0];
        p.extend_from_slice(&(seg.len() as u16).to_be_bytes());
        p.extend_from_slice(&[proto, 64]);
        p.extend_from_slice(&src.octets());
        p.extend_from_slice(&dst.octets());
        p.extend_from_slice(&seg);
        p
    }

    fn syn(src: Ipv6Addr, dst: Ipv6Addr, port: u16) -> Vec<u8> {
        let mut t = vec![0u8; 20];
        t[0..2].copy_from_slice(&40000u16.to_be_bytes());
        t[2..4].copy_from_slice(&port.to_be_bytes());
        t[4..8].copy_from_slice(&1u32.to_be_bytes());
        t[12] = 5 << 4;
        t[13] = 0x02; // SYN
        t[14..16].copy_from_slice(&65535u16.to_be_bytes());
        ip6(src, dst, 6, t, 16)
    }

    fn udp(src: Ipv6Addr, dst: Ipv6Addr, port: u16) -> Vec<u8> {
        let mut u = vec![0u8; 8];
        u[0..2].copy_from_slice(&40000u16.to_be_bytes());
        u[2..4].copy_from_slice(&port.to_be_bytes());
        u.extend_from_slice(b"a packet");
        let n = u.len() as u16;
        u[4..6].copy_from_slice(&n.to_be_bytes());
        ip6(src, dst, 17, u, 6)
    }

    /// The hub, or anyone holding its key, sends TCP and UDP through the
    /// tunnel to the lite member's address on any port, to other addresses
    /// and as IPv4: nothing is accepted, nothing answered but a reset, and
    /// nothing reaches the computer the member runs on. The member's end
    /// only dials the hub's member port and forwards nothing.
    #[test]
    fn link_reaches_nothing_from_the_tunnel() {
        // The computer's own services.
        let host_tcp = TcpListener::bind("127.0.0.1:0").unwrap();
        host_tcp.set_nonblocking(true).unwrap();
        let host_udp = UdpSocket::bind("127.0.0.1:0").unwrap();
        host_udp.set_nonblocking(true).unwrap();
        let (tcp_port, udp_port) = (host_tcp.local_addr().unwrap().port(), host_udp.local_addr().unwrap().port());

        let st = State::new("g").unwrap();
        let me = DeviceId::parse("0123456789abcdef0123456789abcdef").unwrap();
        let hub_dev = "fedcba9876543210fedcba9876543210";
        let mut raw = [0u8; 32];
        raw.copy_from_slice(&random_key().unwrap());
        let hub_secret = StaticSecret::from(raw);
        let hub_public = PublicKey::from(&hub_secret);
        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        sock.set_read_timeout(Some(Duration::from_millis(200))).unwrap();
        let hub = Hub {
            device: hub_dev.into(),
            key: hub_public.as_bytes().to_vec(),
            psk: st.psk.clone(),
            endpoints: vec![sock.local_addr().unwrap()],
            next: vec![],
            obfuscation: None,
            vless: None,
        };
        let link = Link::start(&st, &hub, &me, Arc::new(|_: &str| {})).unwrap();
        let (own, peer) = (addr(me.as_str()).unwrap(), addr(hub_dev).unwrap());

        let mut psk = [0u8; 32];
        psk.copy_from_slice(&st.psk);
        let limiter = Arc::new(RateLimiter::new(&hub_public, HANDSHAKE_RATE_LIMIT));
        let mut tunn = Tunn::new(
            hub_secret,
            PublicKey::from(&st.secret()),
            Some(psk),
            None,
            IndexTable::from_os_rng(),
            limiter.clone(),
        );
        let mut lite: Option<SocketAddr> = None;
        // Takes what the member sends: answers the handshake and returns
        // the IP packets that came through the tunnel.
        let take = |tunn: &mut Tunn, lite: &mut Option<SocketAddr>, until: Instant| -> Vec<Vec<u8>> {
            let mut got = Vec::new();
            let mut buf = [0u8; 2048];
            while Instant::now() < until {
                let Ok((n, from)) = sock.recv_from(&mut buf) else { continue };
                *lite = Some(from);
                let Ok(wg) = limiter.verify_packet(from, Packet::from_bytes(BytesMut::from(&buf[..n]))) else {
                    continue;
                };
                match tunn.handle_incoming_packet(wg) {
                    TunnResult::WriteToNetwork(p) => {
                        let _ = sock.send_to(Packet::from(p).as_ref(), from);
                    }
                    TunnResult::WriteToTunnel(p) => got.push(AsRef::<[u8]>::as_ref(&p).to_vec()),
                    _ => {}
                }
            }
            got
        };
        // The handshake, and the member's first packet, which makes the
        // session the hub's to send in.
        let deadline = Instant::now() + Duration::from_secs(10);
        while !(tunn.has_active_session() && link.answered()) && Instant::now() < deadline {
            take(&mut tunn, &mut lite, Instant::now() + Duration::from_millis(300));
        }
        assert!(tunn.has_active_session(), "no session with the member");
        let to = lite.unwrap();

        let v4 = {
            // An IPv4 header to the computer's own TCP port.
            let mut p = vec![0x45, 0, 0, 40, 0, 0, 0, 0, 64, 6, 0, 0, 10, 0, 0, 1, 127, 0, 0, 1];
            p.extend_from_slice(&[0x9c, 0x40]);
            p.extend_from_slice(&tcp_port.to_be_bytes());
            p.extend_from_slice(&[0, 0, 0, 1, 0, 0, 0, 0, 0x50, 0x02, 0xff, 0xff, 0, 0, 0, 0]);
            p
        };
        let packets = vec![
            syn(peer, own, MEMBER_PORT),
            syn(peer, own, 22),
            syn(peer, own, tcp_port),
            syn(peer, Ipv6Addr::LOCALHOST, tcp_port),
            syn(peer, "2606:4700:4700::1111".parse().unwrap(), 443),
            udp(peer, own, udp_port),
            udp(peer, Ipv6Addr::LOCALHOST, udp_port),
            v4,
        ];
        for p in &packets {
            if let Some(w) = tunn.handle_outgoing_packet(Packet::from_bytes(BytesMut::from(&p[..])), None) {
                sock.send_to(Packet::from(w).as_ref(), to).unwrap();
            }
        }
        let mut resets = 0;
        for ip in take(&mut tunn, &mut lite, Instant::now() + Duration::from_secs(3)) {
            if ip.len() >= 54 && ip[6] == 6 {
                resets += usize::from(ip[40 + 13] & 0x04 != 0);
                // A reset may come back, never a SYN-ACK.
                assert_ne!(ip[40 + 13] & 0x12, 0x12, "the member accepted a stream through the tunnel");
            } else if ip.len() > 40 {
                assert_ne!(ip[6], 17, "the member answered a UDP packet through the tunnel");
            }
        }
        // The packets did arrive: the member's own ports answered with resets.
        assert!(resets > 0, "nothing came back through the tunnel");
        assert!(host_tcp.accept().is_err(), "a stream from the tunnel reached the computer");
        assert!(host_udp.recv_from(&mut [0u8; 64]).is_err(), "a packet from the tunnel reached the computer");
        drop(link);
    }
}
