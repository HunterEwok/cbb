// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The member's side of push on the records of 0.6: what the mesh gives the
//! push sender (`crate::pusher`) through its seam. The push service's face
//! is the group's face toward it (`crate::faces`, A-55): its server key and
//! the hubs' and members' credentials of the current period. The phones'
//! registrations are kept in `push.cbor` in the group's directory, each
//! device's message `push` (t 28) as it came, so that a restart sends on.

use std::collections::BTreeMap;
use std::net::{SocketAddr, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, Weak};

use cbb_core::format::cbor::{self, Value};
use cbb_core::format::frame;
use cbb_core::push::Registration;
use cbb_core::records::eval::State;
use cbb_core::records::key::{DeviceId, GroupId};

use super::Mesh;
use crate::files;
use crate::pusher::{self, Face, Role};

/// The file the phones' registrations are kept in.
pub(super) const FILE: &str = "push.cbor";

/// The push service's face of the group, by the newest keys.json held
/// (use `push`; no pin is built in) and the group's current period.
pub(super) struct PushFaces(pub(super) Weak<Mesh>);

impl pusher::Faces for PushFaces {
    fn faces(&self, group: &GroupId) -> Vec<Face> {
        let Some(mesh) = self.0.upgrade() else { return Vec::new() };
        let state = mesh.state();
        if state.group != *group {
            return Vec::new();
        }
        let now = crate::uptime::wall_ms();
        let pins: Vec<[u8; 32]> = mesh
            .entries()
            .map(|e| e.keys_for("push", pusher::SERVICE, now))
            .unwrap_or_default()
            .iter()
            .map(|spki| cbb_core::certs::sha256(spki))
            .collect();
        let member = mesh.own.member.public();
        let Some((server, shown)) = mesh.faces.for_relay(&state, &member, &pins, now.max(0) as u64) else {
            return Vec::new();
        };
        let Some(addr) = resolve(&server.address) else {
            mesh.logf(&format!("cbb: the push service {} could not be looked up", server.address));
            return Vec::new();
        };
        // The previous period's face is not kept: a registration under it
        // is asked to register again (pusher, "Under a face this member no
        // longer has").
        vec![Face {
            addr,
            pin: server.pin,
            key: Arc::new(shown.key),
            credentials: shown.credentials,
            tag: shown.tag,
            expires_ms: shown.expires_ms,
        }]
    }
}

fn resolve(address: &str) -> Option<SocketAddr> {
    address.to_socket_addrs().ok()?.next()
}

/// Where the registrations are kept: each device's message `push`, its
/// frame as [`Registration::write`] makes it.
pub(super) struct PushSaved {
    path: PathBuf,
    regs: Mutex<BTreeMap<DeviceId, Vec<u8>>>,
    log: Arc<dyn Fn(&str) + Send + Sync>,
}

impl PushSaved {
    /// Opens the file in dir, and gives the registrations it holds for
    /// group. A damaged file is set aside in the log and starts empty: the
    /// phones register again at their next connection.
    pub(super) fn open(
        dir: &Path,
        group: GroupId,
        log: Arc<dyn Fn(&str) + Send + Sync>,
    ) -> (PushSaved, Vec<(GroupId, DeviceId, Registration)>) {
        let path = dir.join(FILE);
        let mut regs = BTreeMap::new();
        let mut loaded = Vec::new();
        match std::fs::read(&path) {
            Ok(b) => match read_file(&b) {
                Some(all) => {
                    for (d, f) in all {
                        let Some(r) =
                            frame::read(&f, frame::LIMIT_MEMBER).ok().and_then(|m| Registration::read(&m.map).ok())
                        else {
                            continue;
                        };
                        loaded.push((group, d, r));
                        regs.insert(d, f);
                    }
                }
                None => log(&format!("cbb: {FILE} is damaged; the phones register again")),
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => log(&format!("cbb: cannot read {FILE}: {e}")),
        }
        (PushSaved { path, regs: Mutex::new(regs), log }, loaded)
    }

    /// The devices with a registration kept.
    pub(super) fn devices(&self) -> Vec<DeviceId> {
        self.regs.lock().unwrap().keys().copied().collect()
    }
}

fn read_file(b: &[u8]) -> Option<Vec<(DeviceId, Vec<u8>)>> {
    let v = cbor::decode(b).ok()?;
    let mut out = Vec::new();
    for e in v.as_array()? {
        let pair = e.as_array()?;
        let d = <[u8; 16]>::try_from(pair.first()?.as_bytes()?).ok()?;
        out.push((DeviceId(d), pair.get(1)?.as_bytes()?.to_vec()));
    }
    Some(out)
}

impl pusher::Saved for PushSaved {
    fn save(&self, _group: &GroupId, device: &DeviceId, r: Option<&Registration>) {
        let mut regs = self.regs.lock().unwrap();
        match r.and_then(Registration::write) {
            Some(f) => {
                regs.insert(*device, f);
            }
            None => {
                regs.remove(device);
            }
        }
        let b =
            Value::Array(regs.iter().map(|(d, f)| Value::Array(vec![Value::Bytes(&d.0), Value::Bytes(f)])).collect())
                .encode();
        if let Err(e) = files::write_atomic(&self.path, &b, 0o600) {
            (self.log)(&format!("cbb: saving the phones' push registrations: {}", e.for_log()));
        }
    }
}

impl Mesh {
    /// Message `push` (t 28) from the peer over its own connection: its
    /// registration, with its role by the records.
    pub(super) fn take_push(&self, peer: &DeviceId, msg: &[u8]) {
        let state = self.state();
        let Some(d) = state.device(peer).filter(|d| !d.frozen) else { return };
        if let Ok((_, v, _)) = cbb_core::msg::read_noted(msg) {
            self.push.registration(&state.group, peer, d.role, &v);
        }
    }

    /// Drops the registrations of devices the group removed or froze.
    pub(super) fn prune_push(&self, state: &State) {
        for d in self.push_saved.devices() {
            if state.device(&d).is_none_or(|s| s.frozen) {
                self.push.forget(&state.group, &d);
            }
        }
    }

    /// A copy made here or received, its message `copy` read: each phone
    /// it is sealed to with a registration gets its body
    /// (`cbb_core::push::copy_body`), unless it is connected.
    pub(super) fn push_copy(&self, msg: &Value<'_>, role: Role) {
        if role == Role::Neither || self.push.held() == 0 {
            return;
        }
        let state = self.state();
        let Some(v) = msg.get(2) else { return };
        let Ok(c) = cbb_core::copies::check(v, &state) else { return };
        let readers: Vec<DeviceId> = c.readers.iter().map(|(d, _)| *d).collect();
        self.push.copy(&state.group, role, &readers, None, &|phone| {
            cbb_core::push::copy_body(&c.copy, &c.readers, phone, c.id, c.origin.0)
        });
    }

    /// Why this device sends a copy it received: it has the `hub` right.
    pub(super) fn push_role_received(&self) -> Role {
        let state = self.state();
        match state.device(&self.device()) {
            Some(d) if !d.frozen && d.rights & cbb_core::records::body::RIGHT_HUB != 0 => Role::Hub,
            _ => Role::Neither,
        }
    }
}
