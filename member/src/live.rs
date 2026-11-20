// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The member of 0.6 that a computer's service runs: the member connection
//! (`mesh`), the clipboard state (`board`) and the glue between them, and
//! what discovery needs to find, dial and take its peers
//! (`discovery::Peers`). A copy a peer brings goes through the board's
//! rule; one to write goes to the service's clipboard watchers (`OnWrite`).

use std::collections::{HashMap, HashSet};
use std::net::{SocketAddr, TcpStream};
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, RwLock, Weak};
use std::time::Duration;

use cbb_core::certs;
use cbb_core::clip::{Kind, Via};
use cbb_core::media::Manifest;
use cbb_core::records::body::CAP_DIALS;
use cbb_core::records::{DeviceId, State};
use cbb_core::rule::Verdict;

use crate::board::{Board, LIVE_WINDOW_MS};
use crate::discovery::{Admit, Dialed, Peers};
use crate::error::{Error, Result};
use crate::mesh::{Arrived, Mesh};
use crate::networks::Networks;
use crate::own::Own;
use crate::pair::home_address;
use crate::roster::id_text;
use crate::sealed::Blob;
use crate::uptime;

/// How long a device that discovery found still counts as at home: anyone
/// on a network can announce a device and the group's tag, so past that
/// only a connection to it counts.
const NEAR_GRACE: Duration = Duration::from_secs(30);
/// The devices found at home that are remembered, as many as a group has.
const MAX_HOME: usize = 256;

/// A copy from the group to write to this device's clipboard.
#[derive(Clone, Debug)]
pub struct Write {
    /// The copy's ID, which a paste of its images or files names.
    pub id: [u8; 16],
    pub text: String,
    pub kind: Kind,
    /// The manifest of a copy with images or files, whose blob is fetched
    /// before they are written.
    pub media: Option<Manifest>,
    pub blob: Option<Blob>,
    /// The member it came from, which a fetch asks first.
    pub from: DeviceId,
    /// For a secret: how long it may stay in the clipboard.
    pub ttl: Option<Duration>,
}

/// Gets each copy to write.
pub type OnWrite = Box<dyn Fn(Write) + Send + Sync>;

/// The group's tag as mDNS publishes it (`g`): the first 8 bytes of the
/// group ID in hex.
pub fn tag(state: &State) -> String {
    certs::hex(&state.group.0[..8])
}

/// A device ID as discovery and the old member name it.
fn shown(id: &DeviceId) -> certs::DeviceId {
    // 16 bytes in hex are always a device ID.
    certs::DeviceId::parse(&id_text(id)).unwrap_or_else(|_| certs::DeviceId::random())
}

/// A device ID discovery names.
fn of(id: &certs::DeviceId) -> Option<DeviceId> {
    let s = id.as_str();
    let mut b = [0u8; 16];
    for (i, out) in b.iter_mut().enumerate() {
        *out = u8::from_str_radix(s.get(i * 2..i * 2 + 2)?, 16).ok()?;
    }
    Some(DeviceId(b))
}

/// The member of 0.6 on a computer.
pub struct Live {
    pub mesh: Arc<Mesh>,
    pub board: Board,
    me: DeviceId,
    on_write: RwLock<Option<OnWrite>>,
    kick: (Mutex<u64>, Condvar),
    redials: AtomicUsize,
    paused: AtomicBool,
    closed: AtomicBool,
    window_open: AtomicBool,
    unreached: Mutex<HashSet<DeviceId>>,
    /// The devices discovery found at home, and when (uptime).
    home: Mutex<HashMap<DeviceId, Duration>>,
    networks: RwLock<Option<Arc<Networks>>>,
    log: Arc<dyn Fn(&str) + Send + Sync>,
}

impl Live {
    /// Opens the member of the group kept in dir; an error when the device
    /// is in no group of 0.6.
    pub fn open(dir: &Path, own: Own, log: Arc<dyn Fn(&str) + Send + Sync>) -> Result<Arc<Live>> {
        let mesh = Mesh::open(dir, own, log.clone())?;
        let board = Board::new(Box::new(uptime::wall_ms));
        // Images and files go to the clipboard watchers that take them.
        board.set_takes_media(true);
        let live = Arc::new(Live {
            me: mesh.device(),
            mesh,
            board,
            on_write: RwLock::new(None),
            kick: (Mutex::new(0), Condvar::new()),
            redials: AtomicUsize::new(0),
            paused: AtomicBool::new(false),
            closed: AtomicBool::new(false),
            window_open: AtomicBool::new(false),
            unreached: Mutex::new(HashSet::new()),
            home: Mutex::new(HashMap::new()),
            networks: RwLock::new(None),
            log,
        });
        live.settle(&live.mesh.state());
        if let Err(e) = live.mesh.rotate() {
            live.logf(&format!("cbb: {}", e.for_log()));
        }
        let w = Arc::downgrade(&live);
        live.mesh.on_copy(Box::new(move |a| {
            if let Some(l) = w.upgrade() {
                l.arrived(a);
            }
        }));
        let w: Weak<Live> = Arc::downgrade(&live);
        live.mesh.on_set(Box::new(move |set| {
            if let Some(l) = w.upgrade() {
                l.settle(&set.state());
                // The records may let in devices refused until now.
                l.redial();
            }
        }));
        Ok(live)
    }

    /// Sets what gets the copies to write.
    pub fn on_write(&self, f: OnWrite) {
        *self.on_write.write().unwrap() = Some(f);
    }

    /// The group's tag, which mDNS publishes.
    pub fn tag(&self) -> String {
        tag(&self.mesh.state())
    }

    /// What follows from the records: the window for incoming copies.
    fn settle(&self, state: &State) {
        let (_, secret_ms) = self.board.lifetimes();
        self.board.set_lifetimes(state.incoming_ms.unwrap_or(LIVE_WINDOW_MS), secret_ms);
    }

    /// A copy a peer brought, which the core found new.
    fn arrived(&self, a: &Arrived) {
        match self.board.received(a) {
            Verdict::Write => {}
            Verdict::Mode | Verdict::Held | Verdict::Unread => return,
            v => {
                self.logf(&format!("cbb: a copy from {} stays out of the clipboard: {v:?}", id_text(&a.origin)));
                return;
            }
        }
        let c = &a.content;
        let secret = c.is_secret();
        let (_, secret_ms) = self.board.lifetimes();
        let w = Write {
            id: a.id,
            text: c.text.clone().unwrap_or_default(),
            kind: if c.manifest.is_some() {
                Kind::Media
            } else if secret {
                Kind::Secret
            } else {
                Kind::Text
            },
            media: c.manifest.clone(),
            blob: a.blob,
            from: a.from,
            ttl: secret.then(|| Duration::from_millis(secret_ms.saturating_sub(a.age_ms))),
        };
        if let Some(f) = &*self.on_write.read().unwrap() {
            f(w);
        }
    }

    /// A clipboard watcher saw the clipboard change: it goes to the group
    /// unless the board keeps it here.
    pub fn copied(&self, text: &str, kind: Kind, via: Via) -> Result<()> {
        if let Some(c) = self.board.copied(text, kind, via)? {
            self.mesh.copy(&c)?;
        }
        Ok(())
    }

    /// A deliberate send (cbb copy): to the group, unless muted.
    pub fn send(&self, text: &str, kind: Kind, via: Via) -> Result<()> {
        let c = self.board.send(text, kind, via)?;
        if !self.mesh.copy(&c)? {
            return Err(Error::msg("the group has no device that may read this copy"));
        }
        Ok(())
    }

    /// The known networks, where the member port takes connections and
    /// mDNS publishes this device.
    pub fn set_networks(&self, n: Arc<Networks>) {
        *self.networks.write().unwrap() = Some(n);
    }

    /// A pairing window opened or closed.
    pub fn set_window_open(&self, open: bool) {
        self.window_open.store(open, Ordering::SeqCst);
        self.kick();
    }

    /// Stops dialing and taking connections until resume.
    pub fn pause(&self) {
        self.paused.store(true, Ordering::SeqCst);
        self.mesh.close_connections();
        self.kick();
    }

    pub fn resume(&self) {
        self.paused.store(false, Ordering::SeqCst);
        self.kick();
    }

    /// Makes the dial loops try at once.
    pub fn redial(&self) {
        self.redials.fetch_add(1, Ordering::SeqCst);
        self.kick();
    }

    /// Whether discovery found the device at home within NEAR_GRACE.
    pub fn at_home(&self, id: &DeviceId) -> bool {
        self.home.lock().unwrap().get(id).is_some_and(|at| uptime::now().saturating_sub(*at) < NEAR_GRACE)
    }

    /// The members connected only because this one dialed them back.
    pub fn unreached(&self) -> Vec<String> {
        let connected = self.mesh.connected();
        let mut out: Vec<String> =
            self.unreached.lock().unwrap().iter().filter(|id| connected.contains(id)).map(id_text).collect();
        out.sort();
        out
    }

    /// Stops the member: every connection ends with a goodbye.
    pub fn close(&self) {
        self.closed.store(true, Ordering::SeqCst);
        self.mesh.close();
        self.kick();
    }
}

impl Peers for Live {
    fn me(&self) -> certs::DeviceId {
        shown(&self.me)
    }

    fn is_closed(&self) -> bool {
        self.closed.load(Ordering::SeqCst) || self.mesh.is_closed()
    }

    fn is_paused(&self) -> bool {
        self.paused.load(Ordering::SeqCst)
    }

    fn redials(&self) -> usize {
        self.redials.load(Ordering::SeqCst)
    }

    fn nap(&self, d: Duration) -> bool {
        let (m, cv) = &self.kick;
        let g = m.lock().unwrap();
        let start = *g;
        let (g, _) = cv.wait_timeout_while(g, d, |n| *n == start && !self.is_closed()).unwrap();
        *g != start
    }

    fn kick(&self) {
        let (m, cv) = &self.kick;
        *m.lock().unwrap() += 1;
        cv.notify_all();
    }

    fn connected(&self, id: &certs::DeviceId) -> bool {
        of(id).is_some_and(|d| self.mesh.connected().contains(&d))
    }

    /// Any connection up counts: the member of 0.6 dials only at home, so
    /// no dial to a tunnel's port replaces one.
    fn connected_for(&self, id: &certs::DeviceId, _addr: &SocketAddr) -> bool {
        Peers::connected(self, id)
    }

    fn set_unreached(&self, id: &certs::DeviceId, unreached: bool) {
        let Some(d) = of(id) else { return };
        let mut u = self.unreached.lock().unwrap();
        if unreached {
            u.insert(d);
        } else {
            u.remove(&d);
        }
    }

    fn dial_ended(&self, addr: SocketAddr, peer: Option<certs::DeviceId>) -> Result<Dialed> {
        if self.is_closed() {
            return Err(Error::msg("the service is stopping"));
        }
        if self.is_paused() {
            return Err(Error::msg("the member is paused"));
        }
        if !home_address(addr.ip()) {
            return Err(Error::msg(format!(
                "{addr} is not on the home network; on the records of 0.6 this device reaches its group only at home for now"
            )));
        }
        let expect = match &peer {
            Some(p) => Some(of(p).ok_or_else(|| Error::msg(format!("{p} is not a device ID")))?),
            None => None,
        };
        let id = self.mesh.dial(addr, expect)?;
        Ok(Dialed { up: true, again: false, id: Some(shown(&id)) })
    }

    fn accept_checked(
        &self,
        sock: TcpStream,
        _addr: SocketAddr,
        handshaken: &mut dyn FnMut(),
        admit: Option<&Admit>,
    ) -> Result<()> {
        if self.is_closed() {
            return Err(Error::msg("the service is stopping"));
        }
        if self.is_paused() {
            return Err(Error::msg("the member is paused"));
        }
        if admit.is_some() {
            return Err(Error::msg(
                "a listener that checks its callers (a relay's) is not on the records of 0.6 yet",
            ));
        }
        self.mesh.accept_port_with(sock, handshaken).map(|_| ())
    }

    fn takes_on(&self, local: SocketAddr, from: SocketAddr) -> bool {
        let Some(n) = self.networks.read().unwrap().clone() else { return true };
        from.ip().to_canonical().is_loopback() || self.window_open.load(Ordering::SeqCst) || n.knows(local.ip())
    }

    fn logf(&self, s: &str) {
        (self.log)(s)
    }

    fn can_dial(&self) -> bool {
        let st = self.mesh.state();
        st.devices.iter().find(|d| d.id == self.me).is_none_or(|d| d.caps & CAP_DIALS != 0)
    }

    fn networks(&self) -> Option<Arc<Networks>> {
        self.networks.read().unwrap().clone()
    }

    fn window_open(&self) -> bool {
        self.window_open.load(Ordering::SeqCst)
    }

    fn found(&self, id: &certs::DeviceId, here: bool) {
        let Some(d) = of(id) else { return };
        let mut home = self.home.lock().unwrap();
        if !here {
            home.remove(&d);
        } else if home.len() < MAX_HOME || home.contains_key(&d) {
            home.entry(d).or_insert_with(uptime::now);
        }
    }

    fn known(&self) -> Vec<String> {
        let mut out: Vec<String> = self.mesh.state().devices.iter().map(|d| id_text(&d.id)).collect();
        out.sort();
        out
    }
}

#[cfg(test)]
mod tests;
