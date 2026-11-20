// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The group's server credentials on the records of 0.6 (format section 8,
//! `cbb_core::blind`; docs/design.md, "What the servers learn"): what a
//! forwarder, a relay and the push service see of the group instead of its
//! records. The member keeps the current period's credentials in
//! `server-credentials.cbor`, takes those its peers send in message
//! `member-credentials` (t 11) and passes the new ones on, and brings them
//! up to date as far as it can:
//!
//! - on the root, a new period (a fresh tag and period key, signed by the
//!   root's key) when none counts, when the one kept is due, or when a
//!   device that sent its server key is no longer in the group;
//! - on every member, its server key for the period, derived from its own
//!   server secret and the period's tag (`blind::alias::server_key`), signed
//!   by its member key;
//! - on the root, which keeps the period key, the hubs' credential (the
//!   hubs' and the admins' server keys) and the members' credential when
//!   they list other keys than the records say; on an admin that the hubs'
//!   credential lists, the members' credential, signed by its server key.
//!
//! Each server gets a face of its own (A-55, `blind::alias::new_face`: a
//! random tag, a period key, versions from a random start, an expiry of its
//! own), kept by the server's pin, which every message names; the root
//! makes one for each server the group uses ([`project_servers`] for now).
//! The server secret and the root's period keys are files beside the set,
//! readable by the service alone.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use cbb_core::blind::alias;
use cbb_core::blind::credential::{self, Credential, TYPE_HUBS, TYPE_MEMBERS, TYPE_PERIOD, TYPE_SERVER};
use cbb_core::format::cbor::{self, Value};
use cbb_core::format::frame;
use cbb_core::msg::tables::T_CREDENTIALS;
use cbb_core::records::eval::State;
use cbb_core::records::key::{Key, KeyHash};
use p256::ecdsa::SigningKey;

use crate::error::{Error, Result};
use crate::files;
use crate::identity::ExternalKey;

/// The files beside the set.
pub const FILE: &str = "server-credentials.cbor";
pub const SECRET_FILE: &str = "server-secret";
pub const PERIOD_KEY_FILE: &str = "period-key";

/// How long a period lasts, and how long before its end the root starts
/// the next (as before 0.6: 35 days, renewed after 30).
pub const PERIOD_LIFETIME_MS: i64 = 35 * 24 * 3600 * 1000;
pub const PERIOD_RENEW_MS: i64 = 30 * 24 * 3600 * 1000;
/// The most credentials a message carries: the period, the hubs' and the
/// members' credentials and one server credential for each member.
pub const MAX_CREDENTIALS: usize = credential::LENGTHS_MEMBERS[credential::LENGTHS_MEMBERS.len() - 1] + 3;
/// The bytes of envelopes one message carries at most, as the keys
/// statements (`records::sync::PART_BYTES`).
const PART_BYTES: usize = cbb_core::records::sync::PART_BYTES;

/// A P-256 key from its scalar: a server key for a face
/// (`blind::alias::server_key`), or the root's period key.
pub struct ServerKey(SigningKey);

impl ServerKey {
    pub fn from_scalar(d: &[u8; 32]) -> Result<ServerKey> {
        SigningKey::from_slice(d).map(ServerKey).map_err(|_| Error::msg("not a P-256 scalar"))
    }

    /// Its self-signed certificate, which a server reads the key from.
    pub fn cert(&self) -> Result<Vec<u8>> {
        use p256::ecdsa::{Signature, signature::Signer};
        let point = self.public();
        cbb_core::certs::server_cert_by(&point, &mut |tbs| {
            let sig: Signature = self.0.sign(tbs);
            Ok(sig.to_der().as_bytes().to_vec())
        })
    }
}

impl ExternalKey for ServerKey {
    fn public(&self) -> Vec<u8> {
        self.0.verifying_key().to_sec1_point(false).as_bytes().to_vec()
    }

    fn sign_digest(&self, digest: &[u8; 32]) -> cbb_core::error::Result<Vec<u8>> {
        use p256::ecdsa::signature::hazmat::PrehashSigner as _;
        let sig: p256::ecdsa::Signature =
            self.0.sign_prehash(digest).map_err(|_| cbb_core::error::Error::msg("cannot sign with the server key"))?;
        Ok(sig.to_der().as_bytes().to_vec())
    }
}

/// A credential kept: its envelope and what it says.
#[derive(Clone)]
struct Held {
    env: Vec<u8>,
    c: Credential,
}

/// The current period's credentials, checked against the records.
#[derive(Clone, Default)]
pub struct Kept {
    period: Option<Held>,
    /// The members' server credentials, by the member key that signed.
    servers: BTreeMap<KeyHash, Held>,
    hubs: Option<Held>,
    members: Option<Held>,
    /// A device that sent its server key for this period left the group:
    /// the root starts the next period at once, since the device knows
    /// the tag.
    left: bool,
}

fn hash_of(point: &[u8]) -> KeyHash {
    Key::es256(point.to_vec()).hash()
}

/// A device of the state that counts for the credentials: in the group
/// and not frozen.
fn member_of<'a>(state: &'a State, k: &KeyHash) -> Option<&'a cbb_core::records::eval::DeviceState> {
    state.device_by_key(k).filter(|d| !d.frozen)
}

impl Kept {
    /// The period's tag, while a period counts.
    pub fn tag(&self) -> Option<[u8; 16]> {
        self.period.as_ref().and_then(|p| p.c.tag)
    }

    /// Takes one credential envelope against the state: whether it was new
    /// here. An error says why it was not taken.
    pub fn add(&mut self, state: &State, env: &[u8], now_ms: u64) -> Result<bool> {
        let c = Credential::read(env).map_err(|r| Error::msg(format!("a server credential breaks {r}")))?;
        if !c.live(now_ms) {
            return Err(Error::msg("a server credential that has expired"));
        }
        let held = Held { env: env.to_vec(), c };
        let c = &held.c;
        match c.kind {
            TYPE_PERIOD => {
                if Some(&c.signer_hash()) != state.roots.last() || c.group != state.group.0 {
                    return Err(Error::msg("a period not signed by the group's root"));
                }
                if self.period.as_ref().is_some_and(|p| p.c.version >= c.version) {
                    return Ok(false);
                }
                // A new period: what the old one listed goes with it.
                if self.tag() != c.tag {
                    self.servers.clear();
                    self.hubs = None;
                    self.members = None;
                    self.left = false;
                }
                self.period = Some(held);
                Ok(true)
            }
            TYPE_SERVER => {
                if self.tag().is_none() || c.tag != self.tag() || c.group != state.group.0 {
                    return Err(Error::msg("a server key of another period"));
                }
                let by = c.signer_hash();
                if member_of(state, &by).is_none() {
                    // One of a device the records show gone: the period it
                    // knows ends.
                    if state.device_by_key(&by).is_some() || state.revoked.contains(&by) {
                        self.left = true;
                    }
                    return Err(Error::msg("a server key signed by no member of the group"));
                }
                if self.servers.get(&by).is_some_and(|s| s.c.version >= c.version) {
                    return Ok(false);
                }
                self.servers.insert(by, held);
                Ok(true)
            }
            TYPE_HUBS => {
                let p = self.period.as_ref().ok_or_else(|| Error::msg("a hubs' credential before its period"))?;
                credential::check_chain(&p.c, c, None)
                    .map_err(|_| Error::msg("a hubs' credential not of the period's key"))?;
                if self.hubs.as_ref().is_some_and(|h| h.c.version >= c.version) {
                    return Ok(false);
                }
                self.hubs = Some(held);
                Ok(true)
            }
            TYPE_MEMBERS => {
                let (Some(p), Some(h)) = (&self.period, &self.hubs) else {
                    return Err(Error::msg("a members' credential before the hubs'"));
                };
                credential::check_chain(&p.c, &h.c, Some(c))
                    .map_err(|_| Error::msg("a members' credential signed by neither the period's key nor an admin"))?;
                if self.members.as_ref().is_some_and(|m| m.c.version >= c.version) {
                    return Ok(false);
                }
                self.members = Some(held);
                Ok(true)
            }
            _ => Err(Error::msg("a server credential of no known type")),
        }
    }

    /// Drops what the state no longer takes: a period of another root, and
    /// server keys of devices that left.
    pub fn prune(&mut self, state: &State) {
        if self
            .period
            .as_ref()
            .is_some_and(|p| Some(&p.c.signer_hash()) != state.roots.last() || p.c.group != state.group.0)
        {
            *self = Kept::default();
        }
        let n = self.servers.len();
        self.servers.retain(|k, _| member_of(state, k).is_some());
        self.left |= self.servers.len() != n;
    }

    /// Every credential kept, the period first, then the hubs', the
    /// members' and the server keys, in the order a receiver takes them.
    pub fn envelopes(&self) -> Vec<Vec<u8>> {
        let mut out: Vec<Vec<u8>> = self.period.iter().map(|h| h.env.clone()).collect();
        out.extend(self.servers.values().map(|h| h.env.clone()));
        out.extend(self.hubs.iter().chain(self.members.iter()).map(|h| h.env.clone()));
        out
    }

    /// Whether the members' credential lists the server key of the device
    /// with member key k.
    pub fn lists_member(&self, k: &KeyHash) -> bool {
        self.server_of(k).is_some_and(|h| self.members.as_ref().is_some_and(|m| m.c.members.contains(&h)))
    }

    /// The server key's hash of the member with member key k.
    fn server_of(&self, k: &KeyHash) -> Option<[u8; 32]> {
        self.servers.get(k).and_then(|s| s.c.key.as_deref()).map(|p| hash_of(p).0)
    }

    /// What the credentials must list, by the server keys kept: the hubs in
    /// their order (the first 16), the admins that are not frozen other
    /// than the root's own device, which holds the period key, and every
    /// device not frozen.
    fn lists(&self, state: &State) -> [Vec<[u8; 32]>; 3] {
        let root_dev = state.root_device.as_ref();
        let hubs: Vec<[u8; 32]> = state
            .hubs
            .iter()
            .filter_map(|id| state.device(id).filter(|d| !d.frozen))
            .filter_map(|d| self.server_of(&d.key.hash()))
            .take(credential::LENGTHS_HUBS[credential::LENGTHS_HUBS.len() - 1])
            .collect();
        let live = || state.devices.iter().filter(|d| !d.frozen);
        let admins: Vec<[u8; 32]> = live()
            .filter(|d| d.admin.is_some() && Some(&d.id) != root_dev)
            .filter_map(|d| self.server_of(&d.key.hash()))
            .collect();
        let members: Vec<[u8; 32]> = live().filter_map(|d| self.server_of(&d.key.hash())).collect();
        [hubs, admins, members]
    }

    /// Whether a list got needs a new version for want: a key it wants is
    /// missing, the first ones are not want in order when ordered, or it
    /// names a kept server key it no longer wants. Padding never matches.
    fn stale(&self, got: &[[u8; 32]], want: &[[u8; 32]], ordered: bool) -> bool {
        let kept = |h: &[u8; 32]| self.servers.values().any(|s| s.c.key.as_deref().is_some_and(|p| &hash_of(p).0 == h));
        (ordered && got.get(..want.len()) != Some(want))
            || want.iter().any(|k| !got.contains(k))
            || got.iter().any(|k| !want.contains(k) && kept(k))
    }

    /// Whether the root should start a new period at now_ms.
    pub fn period_due(&self, state: &State, now_ms: u64) -> bool {
        let Some(p) = &self.period else { return true };
        let left = p.c.expires_ms.saturating_sub(now_ms);
        let (lifetime, renew) =
            (cbb_core::benchtime::d(PERIOD_LIFETIME_MS) as u64, cbb_core::benchtime::d(PERIOD_RENEW_MS) as u64);
        left < lifetime.saturating_sub(renew) || self.left || self.servers.keys().any(|k| member_of(state, k).is_none())
    }
}

/// What a device shows a relay of 0.6: its server key for the period, the
/// hubs' and the members' credentials, the period credential and the
/// root's key that signed it (for a relay with a list of groups), and the
/// device ID each pseudonym of the group's other devices stands for (the
/// pseudonym in standard base64, the ID in hex).
pub struct ForRelay {
    pub key: ServerKey,
    pub credentials: Vec<Vec<u8>>,
    pub period: Vec<u8>,
    pub root: Vec<u8>,
    pub names: std::collections::HashMap<String, String>,
}

impl Kept {
    /// What the device of member key `me` shows a relay: None until the
    /// period counts, has not expired and its members' credential lists
    /// the device's server key.
    pub fn for_relay(&self, state: &State, me: &KeyHash, secret: &[u8; 32], now_ms: u64) -> Option<ForRelay> {
        let (period, hubs, members) = (self.period.as_ref()?, self.hubs.as_ref()?, self.members.as_ref()?);
        if [period, hubs, members].iter().any(|h| !h.c.live(now_ms)) {
            return None;
        }
        let (scalar, point) = alias::server_key(secret, &period.c.tag?);
        if !members.c.members.contains(&hash_of(&point).0) || member_of(state, me).is_none() {
            return None;
        }
        let names = self
            .servers
            .iter()
            .filter(|(k, _)| *k != me)
            .filter_map(|(k, h)| {
                let d = member_of(state, k)?;
                let name = hash_of(h.c.key.as_deref()?).0;
                members.c.members.contains(&name).then(|| (b64(&name), cbb_core::certs::hex(&d.id.0)))
            })
            .collect();
        Some(ForRelay {
            key: ServerKey::from_scalar(&scalar).ok()?,
            credentials: vec![hubs.env.clone(), members.env.clone()],
            period: period.env.clone(),
            root: period.c.signer.clone(),
            names,
        })
    }
}

fn b64(b: &[u8]) -> String {
    base64::Engine::encode(&base64::engine::general_purpose::STANDARD, b)
}

/// What signs on this device: its member key, the root's key when it holds
/// the current root, and its server secret.
pub struct Signers<'a> {
    pub member: &'a dyn ExternalKey,
    pub root: Option<&'a dyn ExternalKey>,
    pub secret: &'a [u8; 32],
}

/// A server the group shows a face of its own (A-55): its pin, the hash
/// of its key, and its address (host:port), which message
/// `member-credentials` carries in its fields 4 and 5.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Server {
    pub pin: [u8; 32],
    pub address: String,
}

/// The most faces a member keeps: the servers a group meets, with room
/// for a key that changes.
pub const MAX_FACES: usize = 16;
/// The longest address of a server, as field 5 takes it.
const MAX_ADDRESS: usize = 261;

/// The root's period key for a face's tag, kept in a file.
#[derive(Clone)]
struct PeriodKey {
    tag: [u8; 16],
    scalar: [u8; 32],
}

/// One server's face: its address and its period's credentials.
#[derive(Clone, Default)]
struct Face {
    address: String,
    kept: Kept,
}

/// The group's server credentials on this member, a face for each server.
pub struct Faces {
    dir: PathBuf,
    secret: [u8; 32],
    faces: Mutex<BTreeMap<[u8; 32], Face>>,
    period_keys: Mutex<BTreeMap<[u8; 32], PeriodKey>>,
    changes: AtomicUsize,
    log: Arc<dyn Fn(&str) + Send + Sync>,
}

fn read_or_none(path: &Path) -> Result<Option<Vec<u8>>> {
    match std::fs::read(path) {
        Ok(b) => Ok(Some(b)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(Error::with(format!("cannot read {}", path.display()), e)),
    }
}

/// An address field 5 takes: 1 to 261 bytes, no control character.
fn plain_address(a: &str) -> bool {
    (1..=MAX_ADDRESS).contains(&a.len()) && !a.chars().any(char::is_control)
}

impl Faces {
    /// Opens the credentials kept in dir against the state; the server
    /// secret is made on first use. Credentials that cannot be read leave
    /// a face empty, since the peers give them again; a period key that
    /// cannot be read means a new period for its face.
    pub fn open(dir: &Path, state: &State, log: Arc<dyn Fn(&str) + Send + Sync>) -> Result<Faces> {
        let secret_path = dir.join(SECRET_FILE);
        let secret: [u8; 32] = match read_or_none(&secret_path)? {
            Some(b) => b.try_into().map_err(|_| Error::msg(format!("{} is not 32 bytes", secret_path.display())))?,
            None => {
                let s = cbb_core::certs::random_bytes();
                files::write_atomic(&secret_path, &s, 0o600)?;
                s
            }
        };
        let mut faces = BTreeMap::new();
        let now = crate::uptime::wall_ms().max(0) as u64;
        if let Some(b) = read_or_none(&dir.join(FILE)).unwrap_or_else(|e| {
            log(&format!("cbb: the server credentials: {}", e.for_log()));
            None
        }) {
            match cbor::decode(&b) {
                // Each face as [pin, address, [envelope...]].
                Ok(v) => {
                    for f in v.as_array().unwrap_or(&[]).iter().take(MAX_FACES) {
                        let Some([Value::Bytes(pin), Value::Text(address), Value::Array(envs)]) = f.as_array() else {
                            continue;
                        };
                        let Ok(pin) = <[u8; 32]>::try_from(*pin) else { continue };
                        let mut face = Face { address: address.to_string(), kept: Kept::default() };
                        for env in envs.iter().filter_map(Value::as_bytes) {
                            // One that no longer checks out is dropped.
                            let _ = face.kept.add(state, env, now);
                        }
                        faces.insert(pin, face);
                    }
                }
                Err(r) => log(&format!("cbb: the server credentials: {FILE} breaks {r}")),
            }
        }
        // The root's period keys, each the face's pin, tag and scalar.
        let mut period_keys = BTreeMap::new();
        if let Some(b) = read_or_none(&dir.join(PERIOD_KEY_FILE)).ok().flatten() {
            for r in b.chunks_exact(80) {
                let (Ok(pin), Ok(tag), Ok(scalar)) =
                    (<[u8; 32]>::try_from(&r[..32]), <[u8; 16]>::try_from(&r[32..48]), <[u8; 32]>::try_from(&r[48..]))
                else {
                    continue;
                };
                period_keys.insert(pin, PeriodKey { tag, scalar });
            }
        }
        Ok(Faces {
            dir: dir.to_path_buf(),
            secret,
            faces: Mutex::new(faces),
            period_keys: Mutex::new(period_keys),
            changes: AtomicUsize::new(0),
            log,
        })
    }

    /// How many times the credentials changed, so that a server link
    /// registers again.
    pub fn changes(&self) -> usize {
        self.changes.load(Ordering::SeqCst)
    }

    /// The servers this member keeps a face of, by pin.
    pub fn servers(&self) -> Vec<Server> {
        self.faces.lock().unwrap().iter().map(|(pin, f)| Server { pin: *pin, address: f.address.clone() }).collect()
    }

    /// The credentials kept now for the server of pin; empty for a server
    /// without a face.
    pub fn kept(&self, pin: &[u8; 32]) -> Kept {
        self.faces.lock().unwrap().get(pin).map(|f| f.kept.clone()).unwrap_or_default()
    }

    /// This device's server secret.
    pub fn secret(&self) -> &[u8; 32] {
        &self.secret
    }

    /// What this device, of member key `member`, shows a relay of 0.6
    /// (`cbb-relay/3`) whose key has one of `pins`, at now_ms: the face of
    /// the first pin whose members' credential lists its server key; None
    /// while no face of those pins does.
    pub fn for_relay(
        &self,
        state: &State,
        member: &[u8],
        pins: &[[u8; 32]],
        now_ms: u64,
    ) -> Option<(Server, ForRelay)> {
        let faces = self.faces.lock().unwrap();
        pins.iter().find_map(|pin| {
            let f = faces.get(pin)?;
            let shown = f.kept.for_relay(state, &hash_of(member), &self.secret, now_ms)?;
            Some((Server { pin: *pin, address: f.address.clone() }, shown))
        })
    }

    fn save(&self, faces: &BTreeMap<[u8; 32], Face>) {
        let all: Vec<(Vec<u8>, Vec<Vec<u8>>)> =
            faces.iter().map(|(pin, f)| (pin.to_vec(), f.kept.envelopes())).collect();
        let b = Value::Array(
            all.iter()
                .zip(faces.values())
                .map(|((pin, envs), f)| {
                    Value::Array(vec![
                        Value::Bytes(pin),
                        Value::Text(&f.address),
                        Value::Array(envs.iter().map(|e| Value::Bytes(e)).collect()),
                    ])
                })
                .collect(),
        )
        .encode();
        if let Err(e) = files::write_atomic(&self.dir.join(FILE), &b, 0o600) {
            (self.log)(&format!("cbb: saving the server credentials: {}", e.for_log()));
        }
    }

    /// Takes envelopes for the server's face (from a peer, or signed
    /// here), saves the faces and gives those that were new. A face is
    /// made for a server not seen before, up to [`MAX_FACES`]; its address
    /// follows the newest message that brought something new.
    pub fn add(&self, state: &State, from: &str, server: &Server, envs: &[Vec<u8>]) -> Vec<Vec<u8>> {
        let now = crate::uptime::wall_ms().max(0) as u64;
        let mut faces = self.faces.lock().unwrap();
        if !faces.contains_key(&server.pin) && faces.len() >= MAX_FACES {
            (self.log)(&format!("cbb: dropped the server credentials of another server from {from}: {MAX_FACES} kept"));
            return Vec::new();
        }
        let face = faces.entry(server.pin).or_default();
        let mut fresh = Vec::new();
        for env in envs.iter().take(MAX_CREDENTIALS) {
            match face.kept.add(state, env, now) {
                Ok(true) => fresh.push(env.clone()),
                Ok(false) => {}
                Err(e) => (self.log)(&format!("cbb: dropped a server credential from {from}: {}", e.for_log())),
            }
        }
        if !fresh.is_empty() && plain_address(&server.address) {
            face.address.clone_from(&server.address);
        }
        if face.kept.period.is_none() {
            faces.remove(&server.pin);
        }
        if !fresh.is_empty() {
            self.save(&faces);
            self.changes.fetch_add(1, Ordering::SeqCst);
        }
        fresh
    }

    /// Message `member-credentials` (t 11), its body: the server it names
    /// and the envelopes in it, or an error when it is not that message.
    pub fn read_message(msg: &[u8]) -> Result<(Server, Vec<Vec<u8>>)> {
        let (t, v, _) =
            cbb_core::msg::read_noted(msg).map_err(|r| Error::msg(format!("message member-credentials breaks {r}")))?;
        if t != T_CREDENTIALS {
            return Err(Error::msg("not message member-credentials"));
        }
        let pin = v
            .get(4)
            .and_then(Value::as_bytes)
            .and_then(|b| <[u8; 32]>::try_from(b).ok())
            .ok_or_else(|| Error::msg("message member-credentials names no server"))?;
        let address = v.get(5).and_then(Value::as_text).unwrap_or_default().to_string();
        // Each credential rides as its envelope's value.
        let envs = v.get(2).and_then(Value::as_array).unwrap_or(&[]).iter().map(Value::encode).collect();
        Ok((Server { pin, address }, envs))
    }

    /// The frames of message `member-credentials` carrying envs for the
    /// server's face, as many as they need, each in the order a receiver
    /// takes them.
    pub fn messages(server: &Server, envs: &[Vec<u8>]) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        let mut cur: Vec<Value<'_>> = Vec::new();
        let mut used = 0usize;
        let flush = |cur: &mut Vec<Value<'_>>, out: &mut Vec<Vec<u8>>| {
            if !cur.is_empty() {
                let mut m = vec![
                    (frame::FIELD_T, Value::Uint(T_CREDENTIALS)),
                    (2, Value::Array(core::mem::take(cur))),
                    (4, Value::Bytes(&server.pin)),
                ];
                if plain_address(&server.address) {
                    m.push((5, Value::Text(&server.address)));
                }
                out.push(frame::write(&Value::Map(m)));
            }
        };
        for e in envs {
            let Ok(v) = cbor::decode(e) else { continue };
            let item = e.len().saturating_add(9);
            if !cur.is_empty() && (cur.len() >= MAX_CREDENTIALS || used.saturating_add(item) > PART_BYTES) {
                flush(&mut cur, &mut out);
                used = 0;
            }
            cur.push(v);
            used = used.saturating_add(item);
        }
        flush(&mut cur, &mut out);
        out
    }

    /// Every face's credentials as its messages, for a peer that just
    /// connected.
    pub fn all_messages(&self) -> Vec<Vec<u8>> {
        let faces = self.faces.lock().unwrap();
        faces
            .iter()
            .flat_map(|(pin, f)| {
                Faces::messages(&Server { pin: *pin, address: f.address.clone() }, &f.kept.envelopes())
            })
            .collect()
    }

    fn save_period_keys(&self, keys: &BTreeMap<[u8; 32], PeriodKey>) -> Result<()> {
        let mut b = Vec::with_capacity(keys.len() * 80);
        for (pin, k) in keys {
            b.extend_from_slice(pin);
            b.extend_from_slice(&k.tag);
            b.extend_from_slice(&k.scalar);
        }
        files::write_atomic(&self.dir.join(PERIOD_KEY_FILE), &b, 0o600)
    }

    /// Brings the credentials up to date as far as this device can (the
    /// module's comment), a face for each server: on the root, a face for
    /// each of `servers` it has none of or whose period is due; on every
    /// member, its server key and the lists of each face it keeps. A face
    /// whose period expired goes. Gives what it signed, by face, to send to
    /// the peers.
    pub fn refresh(&self, state: &State, s: &Signers<'_>, servers: &[Server]) -> Result<Vec<(Server, Vec<Vec<u8>>)>> {
        let now = crate::uptime::wall_ms().max(0) as u64;
        {
            let mut faces = self.faces.lock().unwrap();
            for f in faces.values_mut() {
                f.kept.prune(state);
            }
            faces.retain(|_, f| f.kept.period.as_ref().is_some_and(|p| p.c.live(now)));
            let mut keys = self.period_keys.lock().unwrap();
            let n = keys.len();
            keys.retain(|pin, _| faces.contains_key(pin) || servers.iter().any(|s| &s.pin == pin));
            if keys.len() != n {
                self.save_period_keys(&keys)?;
            }
        }
        let mut all: Vec<Server> = servers.iter().take(MAX_FACES).cloned().collect();
        for kept in self.servers() {
            if !all.iter().any(|s| s.pin == kept.pin) {
                all.push(kept);
            }
        }
        let mut out = Vec::new();
        for server in all {
            let listed = servers.iter().any(|s| s.pin == server.pin);
            let signed = self.refresh_face(state, s, &server, listed, now)?;
            if !signed.is_empty() {
                out.push((server, signed));
            }
        }
        Ok(out)
    }

    fn refresh_face(
        &self,
        state: &State,
        s: &Signers<'_>,
        server: &Server,
        listed: bool,
        now: u64,
    ) -> Result<Vec<Vec<u8>>> {
        let mut signed = Vec::new();
        let mut sign = |c: Credential, by: &dyn ExternalKey, what: &str| -> Result<()> {
            let env = c.sign(by).map_err(|e| e.context(format!("signing {what}")))?;
            signed.extend(self.add(state, "this device", server, &[env]));
            Ok(())
        };
        let kept = || self.kept(&server.pin);
        let blank = |kind: u64, group: [u8; 16], version: u64, expires_ms: u64| Credential {
            kind,
            group,
            signer: Vec::new(),
            version,
            expires_ms,
            tag: None,
            key: None,
            hubs: Vec::new(),
            admins: Vec::new(),
            members: Vec::new(),
            id: [0; 32],
        };

        // The period, on the root, for a server it lists.
        if let (Some(root), true) = (s.root, listed && kept().period_due(state, now)) {
            let scalar: [u8; 32] = loop {
                let d = cbb_core::certs::random_bytes();
                if SigningKey::from_slice(&d).is_ok() {
                    break d;
                }
            };
            let pk = ServerKey::from_scalar(&scalar)?;
            let ends = now.saturating_add(cbb_core::benchtime::d(PERIOD_LIFETIME_MS) as u64);
            let face = alias::new_face(pk.public(), &self.secret, now, ends);
            {
                let mut keys = self.period_keys.lock().unwrap();
                keys.insert(server.pin, PeriodKey { tag: face.tag, scalar });
                self.save_period_keys(&keys)?;
            }
            // The next period counts above the one it follows, by a
            // random step; the first starts where its face does.
            let step = u64::from(u16::from_be_bytes(cbb_core::certs::random_bytes::<2>())).saturating_add(1);
            let prev = kept().period.as_ref().map(|p| p.c.version);
            let version = prev.map_or(face.version, |v| v.saturating_add(step));
            let mut c = blank(TYPE_PERIOD, state.group.0, version, face.expires_ms);
            c.tag = Some(face.tag);
            c.key = Some(face.period_key);
            sign(c, root, "the period")?;
        }
        let Some(period) = kept().period.clone() else { return Ok(signed) };
        let tag = period.c.tag.unwrap_or_default();
        let next = |v: Option<u64>| v.map_or(period.c.version, |v| v.saturating_add(1));

        // This device's server key for the face.
        let me = hash_of(&s.member.public());
        let (scalar, point) = alias::server_key(&self.secret, &tag);
        let mine = kept().servers.get(&me).map(|h| (h.c.key.clone(), h.c.version));
        if mine.as_ref().is_none_or(|(k, _)| k.as_deref() != Some(point.as_slice())) {
            let mut c = blank(TYPE_SERVER, state.group.0, next(mine.map(|(_, v)| v)), period.c.expires_ms);
            c.tag = Some(tag);
            c.key = Some(point.clone());
            sign(c, s.member, "the server key")?;
        }
        let own = ServerKey::from_scalar(&scalar)?;

        // The hubs' and the members' credentials.
        let k = kept();
        let [hubs, admins, members] = k.lists(state);
        let period_key = self
            .period_keys
            .lock()
            .unwrap()
            .get(&server.pin)
            .cloned()
            .filter(|pk| pk.tag == tag && s.root.is_some())
            .map(|pk| ServerKey::from_scalar(&pk.scalar))
            .transpose()?
            .filter(|pk| period.c.key.as_deref() == Some(pk.public().as_slice()));
        let signer: &dyn ExternalKey = if let Some(pk) = &period_key {
            if k.hubs.as_ref().is_none_or(|h| k.stale(&h.c.hubs, &hubs, true) || k.stale(&h.c.admins, &admins, false)) {
                let mut c = blank(TYPE_HUBS, tag, next(k.hubs.as_ref().map(|h| h.c.version)), period.c.expires_ms);
                c.hubs = hubs;
                c.admins = admins;
                sign(c, pk, "the hubs' credential")?;
            }
            pk
        } else if k.hubs.as_ref().is_some_and(|h| h.c.admins.contains(&hash_of(&point).0)) {
            &own
        } else {
            return Ok(signed);
        };
        let k = kept();
        if k.members.as_ref().is_none_or(|m| k.stale(&m.c.members, &members, false)) {
            let mut c = blank(TYPE_MEMBERS, tag, next(k.members.as_ref().map(|m| m.c.version)), period.c.expires_ms);
            c.members = members;
            sign(c, signer, "the members' credential")?;
        }
        Ok(signed)
    }
}

/// The project's servers a group of 0.6 shows a face to (A-55), by the
/// newest keys.json held, else the pins built in: the relay and the
/// forwarder at cbb.tools. A server whose key changes has a face for each
/// key listed while both are.
#[cfg(feature = "tunnel")]
pub fn project_servers(entries: Option<&crate::entries::Entries>, now_ms: i64) -> Vec<Server> {
    use base64::Engine as _;
    let b64pin =
        |p: &str| base64::engine::general_purpose::STANDARD.decode(p).ok().and_then(|b| <[u8; 32]>::try_from(b).ok());
    let mut out = Vec::new();
    for (usage, name, built_in) in [
        ("relay", crate::away::PROJECT_RELAY, crate::away::PROJECT_RELAY_PINS),
        ("forwarder", crate::away::PROJECT_FORWARDER, crate::away::PROJECT_FORWARDER_PINS),
    ] {
        let listed = entries.map(|e| e.keys_for(usage, name, now_ms)).unwrap_or_default();
        let pins: Vec<[u8; 32]> = if listed.is_empty() {
            built_in.iter().filter_map(|p| b64pin(p)).collect()
        } else {
            listed.iter().map(|spki| cbb_core::certs::sha256(spki)).collect()
        };
        out.extend(pins.into_iter().map(|pin| Server { pin, address: name.to_string() }));
    }
    out
}

/// Without sync away from home a group meets no server.
#[cfg(not(feature = "tunnel"))]
pub fn project_servers(_: Option<&crate::entries::Entries>, _: i64) -> Vec<Server> {
    Vec::new()
}

#[cfg(test)]
mod tests;
