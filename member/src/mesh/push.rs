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
use crate::pusher::{self, Face};
pub(super) use crate::pusher::{Role, Sender};

/// The file the phones' registrations are kept in.
pub(super) const FILE: &str = "push.cbor";

/// The push service's face of the group, by the newest keys.json held
/// (use `push`; no pin is built in) and the group's current period; and
/// the previous period's, kept until its credentials expire for the
/// registrations made under it (`Sender::needs_face`), never for a new one.
pub(super) struct PushFaces {
    mesh: Weak<Mesh>,
    seen: Mutex<Seen>,
}

/// A face of the push service.
#[derive(Clone)]
struct Held {
    addr: SocketAddr,
    pin: [u8; 32],
    key: Arc<crate::faces::ServerKey>,
    credentials: Vec<Vec<u8>>,
    tag: [u8; 16],
    expires_ms: u64,
}

impl Held {
    fn face(&self) -> Face {
        Face {
            addr: self.addr,
            pin: self.pin,
            key: self.key.clone(),
            credentials: self.credentials.clone(),
            tag: self.tag,
            expires_ms: self.expires_ms,
        }
    }
}

/// The current face as last seen, and the one before it.
#[derive(Default)]
struct Seen {
    current: Option<Held>,
    previous: Option<Held>,
}

impl Seen {
    /// The current face now: when its period changed, the one seen before
    /// becomes the previous face. None (no face now) changes nothing.
    fn see(&mut self, now: Option<Held>) {
        let Some(now) = now else { return };
        if let Some(old) = self.current.take()
            && old.tag != now.tag
        {
            self.previous = Some(old);
        }
        self.current = Some(now);
    }

    /// The faces the sender may use at now_ms: the current one, and the
    /// previous while `needed` says a registration names it and it has not
    /// expired; once either fails it is dropped for good.
    fn faces(&mut self, now_ms: u64, needed: impl Fn(&[u8; 16]) -> bool) -> Vec<Face> {
        if self.previous.as_ref().is_some_and(|p| p.expires_ms <= now_ms || !needed(&p.tag)) {
            self.previous = None;
        }
        self.current.iter().chain(self.previous.iter()).map(Held::face).collect()
    }
}

impl PushFaces {
    pub(super) fn new(mesh: Weak<Mesh>) -> PushFaces {
        PushFaces { mesh, seen: Mutex::new(Seen::default()) }
    }

    /// Looks at the current face, so that the previous one is kept when
    /// the period changes. The mesh calls it whenever the group's
    /// credentials may have changed.
    pub(super) fn look(&self, mesh: &Mesh, state: &State) {
        let now = current(mesh, state);
        self.seen.lock().unwrap().see(now);
    }
}

/// The current period's face toward the push service, when the newest
/// keys.json names the service and the period counts.
fn current(mesh: &Mesh, state: &State) -> Option<Held> {
    let now = crate::uptime::wall_ms();
    let pins: Vec<[u8; 32]> = mesh
        .entries()
        .map(|e| e.keys_for("push", pusher::SERVICE, now))
        .unwrap_or_default()
        .iter()
        .map(|spki| cbb_core::certs::sha256(spki))
        .collect();
    if pins.is_empty() {
        return None;
    }
    let member = mesh.own.member.public();
    let (server, shown) = mesh.faces.for_relay(state, &member, &pins, now.max(0) as u64)?;
    let Some(addr) = resolve(&server.address) else {
        mesh.logf(&format!("cbb: the push service {} could not be looked up", server.address));
        return None;
    };
    Some(Held {
        addr,
        pin: server.pin,
        key: Arc::new(shown.key),
        credentials: shown.credentials,
        tag: shown.tag,
        expires_ms: shown.expires_ms,
    })
}

impl pusher::Faces for PushFaces {
    fn faces(&self, group: &GroupId) -> Vec<Face> {
        let Some(mesh) = self.mesh.upgrade() else { return Vec::new() };
        let state = mesh.state();
        if state.group != *group {
            return Vec::new();
        }
        self.look(&mesh, &state);
        let now = crate::uptime::wall_ms().max(0) as u64;
        self.seen.lock().unwrap().faces(now, |tag| mesh.push.needs_face(group, tag))
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

/// What the member had applied when it last looked for the phones' events:
/// the records that counted, the recovery records of the chain and the
/// devices by member key.
#[derive(Clone, Default)]
pub(super) struct Applied {
    counting: std::collections::BTreeSet<cbb_core::records::key::RecordId>,
    changes: std::collections::BTreeSet<cbb_core::records::key::RecordId>,
    devices: Vec<(cbb_core::records::key::KeyHash, DeviceId)>,
}

impl Applied {
    pub(super) fn of(state: &State) -> Applied {
        Applied {
            counting: state.counting.clone(),
            changes: state.changes.iter().map(|c| c.record).collect(),
            devices: state.devices.iter().map(|d| (d.key.hash(), d.id)).collect(),
        }
    }
}

/// One event a phone hears of (rule 33's): its ID, the first 16 bytes of
/// the record's ID, so that every sender gives the same; what happened;
/// the device it names; and the record's own time.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Event {
    pub id: [u8; 16],
    pub event: u64,
    pub device: Option<DeviceId>,
    pub time_ms: Option<u64>,
}

fn event_id(r: &cbb_core::records::key::RecordId) -> [u8; 16] {
    let mut id = [0; 16];
    id.copy_from_slice(&r.0[..16]);
    id
}

/// The events the records applied since `before` make, in `set` whose
/// state is `state`: a device that joined, devices removed (the device
/// named when one is), and a change of root that took effect.
pub(super) fn events(before: &Applied, set: &cbb_core::records::RecordSet, state: &State) -> Vec<Event> {
    use cbb_core::push::{EVENT_JOINED, EVENT_REMOVED, EVENT_ROOT};
    use cbb_core::records::Kind;
    let mut out = Vec::new();
    let time = |ms: u64| (ms != 0).then_some(ms);
    for id in state.counting.difference(&before.counting) {
        let Some(r) = set.get(id) else { continue };
        let b = r.body();
        match &b.kind {
            Kind::Device(d) => {
                let Some(now) = state.device_by_key(&d.key.hash()) else { continue };
                if before.devices.iter().all(|(_, was)| *was != now.id) {
                    out.push(Event {
                        id: event_id(id),
                        event: EVENT_JOINED,
                        device: Some(now.id),
                        time_ms: time(b.time_ms),
                    });
                }
            }
            Kind::Revoke(rm) => {
                let named: Vec<DeviceId> = rm
                    .keys
                    .iter()
                    .filter_map(|k| before.devices.iter().find(|(h, _)| h == k).map(|(_, d)| *d))
                    .collect();
                if !named.is_empty() {
                    let device = (named.len() == 1).then(|| named[0]);
                    out.push(Event { id: event_id(id), event: EVENT_REMOVED, device, time_ms: time(b.time_ms) });
                }
            }
            _ => {}
        }
    }
    for c in &state.changes {
        if c.state == cbb_core::records::eval::ChangeState::Effective && !before.changes.contains(&c.record) {
            let time_ms = set.get(&c.record).and_then(|r| time(r.body().time_ms));
            out.push(Event { id: event_id(&c.record), event: EVENT_ROOT, device: None, time_ms });
        }
    }
    out
}

impl Mesh {
    /// After records were applied: the phones' events they make go to the
    /// push sender, from a hub, else from the root's or an admin's device
    /// when the group has no hub.
    pub(super) fn push_events(&self, set: &cbb_core::records::RecordSet) {
        let state = set.state();
        let before = std::mem::replace(&mut *self.applied.lock().unwrap(), Applied::of(&state));
        if self.push.held() == 0 {
            return;
        }
        let me = self.device();
        let sends = if state.hubs.is_empty() {
            state.root_device == Some(me) || state.device(&me).is_some_and(|d| d.admin.is_some() && !d.frozen)
        } else {
            state.hubs.contains(&me)
        };
        for e in events(&before, set, &state) {
            self.push.event(&state.group, &e.id, e.event, e.device, sends, e.time_ms);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn held(tag: u8, expires_ms: u64) -> Held {
        Held {
            addr: "192.0.2.1:8767".parse().unwrap(),
            pin: [1; 32],
            key: Arc::new(crate::faces::ServerKey::from_scalar(&[tag; 32]).unwrap()),
            credentials: vec![vec![tag]],
            tag: [tag; 16],
            expires_ms,
        }
    }

    fn tags(f: &[Face]) -> Vec<u8> {
        f.iter().map(|f| f.tag[0]).collect()
    }

    /// The previous period's face serves the registrations under it until
    /// it expires, so that a phone on it is not asked to register again
    /// before then (the sender asks only when a registration's face is not
    /// given: pushd's tests, the_previous_face_serves_push_only_until_the_
    /// phone_registers_again); a new period never brings it back.
    #[test]
    fn the_previous_face_stays_until_it_expires_or_nobody_needs_it() {
        let mut s = Seen::default();
        s.see(Some(held(1, 100)));
        assert_eq!(tags(&s.faces(10, |_| true)), [1]);
        // The period changes: the old face stays for those under it.
        s.see(Some(held(2, 200)));
        s.see(Some(held(2, 200)));
        s.see(None);
        assert_eq!(tags(&s.faces(50, |t| t == &[1; 16])), [2, 1]);
        assert_eq!(tags(&s.faces(99, |t| t == &[1; 16])), [2, 1], "before it expires");
        // Expired: gone for good.
        assert_eq!(tags(&s.faces(100, |_| true)), [2]);
        assert_eq!(tags(&s.faces(10, |_| true)), [2]);
        // Nobody under it: gone as well.
        s.see(Some(held(3, 300)));
        assert_eq!(tags(&s.faces(150, |_| false)), [3]);
        assert_eq!(tags(&s.faces(150, |_| true)), [3]);
    }

    /// Every device that applies a record gives the phones' event the same
    /// ID, the first 16 bytes of the record's ID, so that a phone woken by
    /// a hub and by the root shows it once.
    #[test]
    fn two_senders_give_one_event_id() {
        let (da, db) = super::super::tests::two_dirs("push-events");
        let load = |d: &Path| crate::set::load(d, &crate::set::local_key(d).unwrap()).unwrap().unwrap();
        let (a, mut b) = (load(&da), load(&db));
        // b lacks the record that adds c; a has it.
        let before = Applied::of(&b.state());
        let (sa, sb) = (a.state(), b.state());
        let new: Vec<_> = sa.counting.difference(&sb.counting).copied().collect();
        assert_eq!(new.len(), 1);
        let at_a = events(&before, &a, &sa);
        b.insert(a.get(&new[0]).unwrap().clone()).unwrap();
        let at_b = events(&before, &b, &b.state());
        assert_eq!(at_a, at_b);
        assert_eq!(at_a.len(), 1);
        assert_eq!(at_a[0].event, cbb_core::push::EVENT_JOINED);
        assert_eq!(at_a[0].id[..], new[0].0[..16]);
        assert!(at_a[0].device.is_some() && at_a[0].time_ms.is_some());
        // Applied again: nothing new.
        assert!(events(&Applied::of(&sa), &a, &sa).is_empty());
    }
}
