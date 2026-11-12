// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The member's push sender (format section 20.4, P-3): it keeps the
//! phones' registrations, decides when a copy or an event wakes a phone
//! whose app is closed, seals the body to that phone and asks the
//! project's push service (src/pushd, through [`crate::push::Client`]).
//!
//! # The seam
//!
//! The member's sync (wave 5) calls only these, and nothing else of this
//! module; it never edits it:
//!
//! - [`Sender::registration`]: message `push` (t 28) arrived from a device
//!   over its own member connection, in a group, with the device's role
//!   (only a phone's or a computer's is taken, `cbb_core::push::may_register`);
//! - [`Sender::forget`]: a device was removed or frozen;
//! - [`Sender::connected`] and [`Sender::left`]: a peer's member connection
//!   opened or closed;
//! - [`Sender::renewals`]: when a peer's member connection opens, the
//!   `push-renew` messages (t 29) to send it, one per group in which the
//!   service found its registration stale, so that its app registers
//!   again there;
//! - [`Sender::copy`]: a copy was made here or received, with its readers
//!   and how to make the body for one reader (`cbb_core::push::copy_body`,
//!   None for a device the copy is not sealed to);
//! - [`Sender::event`]: a record was applied that a phone hears of (rule
//!   33's events), with the record's own time;
//! - [`Faces`]: how the member gives the sender, per group, the push
//!   service's address and pin, its server key for the service's face and
//!   the face's hubs' and members' credentials;
//! - [`Saved`]: where the registrations are kept across a restart, in the
//!   group's section of the member's state.
//!
//! **Required test when wave 5 wires the seam** (an e2e test of
//! internal/service with `phone-on-linux`, never skipped): a phone
//! registers over its member connection; it disconnects; a computer of the
//! group makes a copy and applies a removal; a cbb-push with a fake platform
//! receives one body per event, from the origin or a hub, and none while the
//! phone is connected; the body opens with `push_open` under the phone's
//! registration; after the phone registers again with a higher seq, a send
//! under the old one is answered `stale`. Until then, the phone side is
//! tried on a real iPhone with the test tool in src/pushd/tests.rs
//! (`live_push_to_a_phone`).
//!
//! Who sends: the copy's origin, once while it runs, and every device with
//! the `hub` right that received it. Every one of them makes the same
//! bytes (the copy reduced with age 0, the nonce derived from the
//! plaintext), and the service drops the repeats by those bytes. Events: a
//! hub, else the root's or an admin's device, each with the record's own
//! time. Nobody sends to a phone it is connected to, and a sender waits two
//! seconds after a copy, in case the phone connects meanwhile. A send the
//! service answers `stale` (an older registration than one it saw, or a
//! send key the token's confirmed binding does not take) is dropped, the
//! registration kept, and the phone is asked to register again at its next
//! connection; one answered `key` (a send key algorithm the service does
//! not take) is dropped.

use std::collections::{BTreeMap, HashMap};
use std::net::SocketAddr;
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use cbb_core::format::cbor::Value;
use cbb_core::push::{self, Body, Registration};
use cbb_core::records::key::Key;
use cbb_core::records::key::{DeviceId, GroupId};

use crate::push::{Client, ServerKey};

/// The push service of a group's face: where it is, its pin, this device's
/// server key for the face and the face's hubs' and members' credentials.
pub struct Face {
    pub addr: SocketAddr,
    pub pin: [u8; 32],
    pub key: Arc<ServerKey>,
    pub credentials: Vec<Vec<u8>>,
}

/// The member gives the sender each group's face (it changes each period).
pub trait Faces: Send + Sync {
    fn face(&self, group: &GroupId) -> Option<Face>;
}

/// Where the registrations are kept: the group's section of the member's
/// saved state. `None` drops the device's.
pub trait Saved: Send + Sync {
    fn save(&self, group: &GroupId, device: &DeviceId, r: Option<&Registration>);
}

/// Why this device sends a copy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    /// It made the copy.
    Origin,
    /// It has the `hub` right and received it.
    Hub,
    /// Neither: it does not send.
    Neither,
}

/// The project's push service, as keys.json names its key (use `push`,
/// [`crate::entries::Entries::push_keys`]) and where it is reached.
pub const SERVICE: &str = "cbb.tools:8767";

/// How long a sender waits after a copy before it pushes.
pub const WAIT: Duration = Duration::from_secs(2);
/// Tries of one body at most.
const TRIES: u32 = 5;

/// One body waiting to go.
struct Job {
    group: GroupId,
    phone: DeviceId,
    body: Vec<u8>,
    env: u64,
    token: Vec<u8>,
    ttl: Option<u64>,
    send_key: Key,
    send_sig: Vec<u8>,
    seq: u64,
    slot: [u8; 16],
    challenge: Option<[u8; 16]>,
    at: Instant,
    tries: u32,
}

#[derive(Default)]
struct State {
    regs: BTreeMap<(GroupId, DeviceId), Registration>,
    connected: HashMap<DeviceId, usize>,
    jobs: Vec<Job>,
    /// The registrations the service found stale, by their slot: the phone
    /// is asked to register again.
    renew: BTreeMap<(GroupId, DeviceId), [u8; 16]>,
    clients: HashMap<GroupId, Client>,
    stop: bool,
}

struct Inner {
    faces: Arc<dyn Faces>,
    saved: Arc<dyn Saved>,
    state: Mutex<State>,
    wake: Condvar,
    log: Arc<dyn Fn(&str) + Send + Sync>,
}

/// The sender, with its thread.
pub struct Sender {
    inner: Arc<Inner>,
}

impl Sender {
    /// Starts the sender with the registrations the member saved.
    pub fn start(
        faces: Arc<dyn Faces>,
        saved: Arc<dyn Saved>,
        loaded: Vec<(GroupId, DeviceId, Registration)>,
        log: Arc<dyn Fn(&str) + Send + Sync>,
    ) -> Sender {
        let mut st = State::default();
        for (g, d, r) in loaded {
            st.regs.insert((g, d), r);
        }
        let inner = Arc::new(Inner { faces, saved, state: Mutex::new(st), wake: Condvar::new(), log });
        let me = inner.clone();
        let _ = std::thread::Builder::new().name("cbb push sender".into()).spawn(move || me.run());
        Sender { inner }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.inner.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Message `push` arrived from `device`, whose role in `group` is
    /// `role`, over its own connection. A refused message, or one from a
    /// device that may not register, changes nothing.
    pub fn registration(&self, group: &GroupId, device: &DeviceId, role: u64, msg: &Value<'_>) {
        if !push::may_register(role) {
            return;
        }
        let Ok(r) = Registration::read(msg) else { return };
        let mut st = self.lock();
        let now =
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_millis() as u64);
        if st.regs.get(&(*group, *device)).is_some_and(|old| !old.replaced_by(&r, now)) {
            return;
        }
        if r.on.is_none() {
            st.regs.remove(&(*group, *device));
            self.inner.saved.save(group, device, None);
        } else {
            self.inner.saved.save(group, device, Some(&r));
            st.regs.insert((*group, *device), r);
        }
        // A newer key: bodies sealed under the old one are not sent.
        st.jobs.retain(|j| !(j.group == *group && j.phone == *device));
        st.renew.remove(&(*group, *device));
    }

    /// The `push-renew` frames for `device`, whose member connection just
    /// opened: one for each group where the service found its registration
    /// stale. Each is given once.
    pub fn renewals(&self, device: &DeviceId) -> Vec<(GroupId, Vec<u8>)> {
        let mut st = self.lock();
        let due: Vec<(GroupId, [u8; 16])> =
            st.renew.iter().filter(|((_, d), _)| d == device).map(|((g, _), s)| (*g, *s)).collect();
        for (g, _) in &due {
            st.renew.remove(&(*g, *device));
        }
        due.into_iter().map(|(g, s)| (g, push::renew(&s))).collect()
    }

    /// A device was removed or frozen: its registration goes.
    pub fn forget(&self, group: &GroupId, device: &DeviceId) {
        let mut st = self.lock();
        st.regs.remove(&(*group, *device));
        st.jobs.retain(|j| !(j.group == *group && j.phone == *device));
        st.renew.remove(&(*group, *device));
        self.inner.saved.save(group, device, None);
    }

    /// A peer's member connection opened.
    pub fn connected(&self, device: &DeviceId) {
        let mut st = self.lock();
        *st.connected.entry(*device).or_default() += 1;
        // The app is open: what waited for it goes directly.
        st.jobs.retain(|j| j.phone != *device);
    }

    /// A peer's member connection closed.
    pub fn left(&self, device: &DeviceId) {
        let mut st = self.lock();
        if let Some(n) = st.connected.get_mut(device) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                st.connected.remove(device);
            }
        }
    }

    fn queue(&self, group: &GroupId, phone: &DeviceId, kind: u64, body: &Body, ttl: Option<u64>) {
        let mut st = self.lock();
        if st.connected.contains_key(phone) {
            return;
        }
        let Some(r) = st.regs.get(&(*group, *phone)) else { return };
        if !r.wants(kind) {
            return;
        }
        let Some(on) = r.on.as_ref() else { return };
        let Some(sealed) = push::seal(&on.key, r.seq, on.env, body) else { return };
        let job = Job {
            group: *group,
            phone: *phone,
            body: sealed,
            env: on.env,
            token: on.token.clone(),
            ttl,
            send_key: on.send_key.clone(),
            send_sig: on.send_sig.clone(),
            seq: r.seq,
            slot: on.slot,
            challenge: on.challenge,
            at: Instant::now() + WAIT,
            tries: 0,
        };
        st.jobs.push(job);
        self.inner.wake.notify_all();
    }

    /// A copy was made here (`Role::Origin`) or received (`Role::Hub` when
    /// this device has the `hub` right): each reader with a registration
    /// that is not connected gets the body `body_for` makes for it; a
    /// device `body_for` makes none for (the copy is not sealed to it)
    /// gets nothing.
    pub fn copy(
        &self,
        group: &GroupId,
        role: Role,
        readers: &[DeviceId],
        ttl: Option<u64>,
        body_for: &dyn Fn(&DeviceId) -> Option<Body>,
    ) {
        if role == Role::Neither {
            return;
        }
        for phone in readers {
            let wanted = self.lock().regs.contains_key(&(*group, *phone));
            if wanted && let Some(body) = body_for(phone) {
                self.queue(group, phone, push::KIND_COPIES, &body, ttl);
            }
        }
    }

    /// A record was applied that the group's phones hear of. `sends` says
    /// whether this device sends events: a hub, else the root's or an
    /// admin's device when the group has no hub. `record_ms` is the
    /// record's own time, so that every sender makes the same body.
    pub fn event(
        &self,
        group: &GroupId,
        id: &[u8; 16],
        event: u64,
        device: Option<DeviceId>,
        sends: bool,
        record_ms: Option<u64>,
    ) {
        if !sends {
            return;
        }
        let body = Body::Event { id: *id, event, device: device.map(|d| d.0), time_ms: record_ms };
        let phones: Vec<DeviceId> = self.lock().regs.keys().filter(|(g, _)| g == group).map(|(_, d)| *d).collect();
        for p in phones {
            self.queue(group, &p, push::KIND_EVENTS, &body, Some(4));
        }
    }

    /// The registrations held, for status and tests.
    pub fn held(&self) -> usize {
        self.lock().regs.len()
    }

    /// Bodies waiting to go.
    pub fn waiting(&self) -> usize {
        self.lock().jobs.len()
    }

    pub fn stop(&self) {
        self.lock().stop = true;
        self.inner.wake.notify_all();
    }
}

impl Inner {
    fn run(self: Arc<Self>) {
        let mut st = self.state.lock().unwrap_or_else(|e| e.into_inner());
        loop {
            if st.stop {
                return;
            }
            let now = Instant::now();
            let due = st.jobs.iter().position(|j| j.at <= now);
            let Some(i) = due else {
                let next = st.jobs.iter().map(|j| j.at).min();
                let wait = next.map_or(Duration::from_secs(3600), |t| t.saturating_duration_since(now));
                st = self.wake.wait_timeout(st, wait).map(|(g, _)| g).unwrap_or_else(|e| e.into_inner().0);
                continue;
            };
            let mut job = st.jobs.swap_remove(i);
            if st.connected.contains_key(&job.phone) {
                continue;
            }
            // The connection to the service, made outside the lock.
            let client = st.clients.remove(&job.group);
            drop(st);
            let mut client = client.or_else(|| {
                let f = self.faces.face(&job.group)?;
                let refs: Vec<&[u8]> = f.credentials.iter().map(Vec::as_slice).collect();
                match Client::connect(f.addr, f.pin, f.key, &refs) {
                    Ok(c) => Some(c),
                    Err(e) => {
                        (self.log)(&format!("push: {e}"));
                        None
                    }
                }
            });
            let result = client.as_mut().map(|c| {
                c.send(push::Send {
                    n: 0,
                    token: &job.token,
                    env: job.env,
                    body: &job.body,
                    ttl: job.ttl,
                    key: job.send_key.clone(),
                    sig: &job.send_sig,
                    seq: job.seq,
                    slot: job.slot,
                    challenge: job.challenge,
                })
            });
            st = self.state.lock().unwrap_or_else(|e| e.into_inner());
            let retry = match result {
                Some(Ok(sent)) => {
                    if let Some(c) = client {
                        st.clients.insert(job.group, c);
                    }
                    match sent.status {
                        // Sent, or a repeat of what another sender sent; or
                        // a send key it does not take: trying again
                        // changes nothing.
                        push::SENT | push::SENT_REPEAT | push::SENT_KEY => None,
                        // An older registration than one the service saw:
                        // the phone registers again when it next connects.
                        push::SENT_STALE => {
                            let key = (job.group, job.phone);
                            if st.regs.get(&key).is_some_and(|r| r.seq == job.seq) {
                                st.renew.insert(key, job.slot);
                            }
                            None
                        }
                        push::SENT_GONE => {
                            // The app is gone from the phone: its token too.
                            let key = (job.group, job.phone);
                            if st.regs.get(&key).and_then(|r| r.on.as_ref()).is_some_and(|o| o.token == job.token) {
                                st.regs.remove(&key);
                                self.saved.save(&job.group, &job.phone, None);
                            }
                            None
                        }
                        _ => Some(sent.retry_ms.map_or(Duration::from_secs(30), Duration::from_millis)),
                    }
                }
                // No connection, or it broke: try again on a new one.
                _ => Some(Duration::from_secs(10)),
            };
            if let Some(after) = retry {
                job.tries += 1;
                if job.tries < TRIES {
                    job.at = Instant::now() + after.min(Duration::from_secs(600));
                    st.jobs.push(job);
                }
            }
        }
    }
}
