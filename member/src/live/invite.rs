// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! Remote invitations on the records of 0.6 (docs/protocol.md, section 12).
//!
//! On the hub: the invitation's guest key goes into the hub's tunnel as a
//! peer that reaches only the hub's guest address (`hub::GUEST_HUB`), where
//! each of its connections gets the pairing of that invitation and, once
//! the admin admitted a device, that device's member connection alone, for
//! its first `tunnel` (t 15); the guest goes once the hub answered that, or
//! a day after the admission.
//!
//! On the device that joined: until a hub's offer is kept, it dials the hub
//! through the invitation's guest tunnel, with the invitation kept in
//! `invite-guest`, so that its `tunnel` reaches the hub.
//!
//! A build without the tunnel (MIPS) neither serves invitations nor joins by
//! one: it joins at home.

#![cfg_attr(not(feature = "tunnel"), allow(dead_code, unused_imports))]

use std::collections::HashMap;
use std::net::{Ipv6Addr, Shutdown, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, mpsc};
use std::time::{Duration, Instant};

use cbb_core::join::PairExporter;
use cbb_core::join::invitation::{Invitation, Path, PathKind};
use cbb_core::records::DeviceId;

use super::Live;
use crate::discovery::Peers as _;
use crate::error::{Context as _, Error, Result};
#[cfg(feature = "tunnel")]
use crate::hub;
use crate::tls;

/// A pairing connection of a guest, its handshake over.
pub type Pair = (TcpStream, tls::Session, PairExporter);

/// How long an invitation waits for the hub's tunnel that is starting.
const TUNNEL_START: Duration = Duration::from_secs(10);
/// The most invitations of its own the hub keeps open at once.
pub const MAX_OPEN: usize = crate::inviter::MAX_OPEN;
/// The most invitations of other admins the hub carries at once.
const MAX_THROUGH: usize = 16;
/// The most bytes one pairing connection passes through the hub to its
/// admin, and the most such connections of one guest at once: a pairing
/// takes a few kilobytes, one at a time.
const MAX_PASSED: usize = 1 << 20;
const MAX_CONNS: usize = 2;
/// How long a pairing connection passed to an admin may stay silent: the
/// admin has five minutes to confirm the device.
const PASS_IDLE: Duration = Duration::from_secs(360);
/// How long a guest stays at most after its device was admitted, for the
/// device's first member connection: a device whose service starts late
/// still reaches the hub.
const GUEST_GRACE: Duration = Duration::from_secs(24 * 3600);
/// How long a guest stays after its invitation ended without a device, for
/// the last answer to reach the device.
const FAIL_GRACE: Duration = Duration::from_secs(10);
/// The file in the state directory that holds the invitation a device
/// joined with, until a hub's offer is kept.
pub const GUEST_FILE: &str = "invite-guest";

/// The guest of an open invitation, on the hub.
#[cfg(feature = "tunnel")]
pub(super) struct Guest {
    peer: hub::Peer,
    /// Where the guest's pairing connections go: the invitation's window,
    /// on this hub; None for an admin's invitation through it.
    pairs: Option<mpsc::SyncSender<Pair>>,
    /// The admin whose invitation it is, when not this hub's own: its
    /// pairing connections go to that admin, in `guest` messages.
    owner: Option<DeviceId>,
    /// The pairing connections passed to the owner, by number.
    conns: HashMap<u32, TcpStream>,
    next_conn: u32,
    /// The device the admin admitted, None until then.
    admitted: Option<DeviceId>,
    /// The hub answered the admitted device's `tunnel`.
    offered: bool,
    /// The admitted device's member connection through the guest ended
    /// after the hub answered it: the guest can go.
    done: bool,
}

/// The guests of the open invitations, by their tunnel addresses.
#[cfg(feature = "tunnel")]
pub(super) type Guests = std::sync::Mutex<HashMap<Ipv6Addr, Guest>>;
#[cfg(not(feature = "tunnel"))]
pub(super) type Guests = std::sync::Mutex<()>;

/// What an invitation's guest path gives of the hub, and the pairing
/// connections of its guest.
pub struct Opened {
    pub path: Path,
    pub pairs: mpsc::Receiver<Pair>,
}

#[cfg(feature = "tunnel")]
impl Live {
    /// Lets the guest of an invitation this hub makes into its tunnel: its
    /// one-time key and pre-shared key. Gives the invitation's guest path
    /// and the guest's pairing connections. Refused while this device does
    /// not serve as a hub.
    pub fn open_guest(self: &Arc<Self>, key: [u8; 32], public: [u8; 32], psk: [u8; 32]) -> Result<Opened> {
        let (tx, rx) = mpsc::sync_channel(1);
        let (hub_key, endpoints, obfuscation) = self.let_in(public, psk, Some(tx), None)?;
        let path =
            Path { kind: PathKind::Guest, endpoints, hub_key: Some(hub_key), guest: Some((key, psk)), obfuscation };
        Ok(Opened { path, pairs: rx })
    }

    /// Lets a guest into the hub's tunnel, its pairing connections going to
    /// pairs on this hub, or to the admin owner: refused while this device
    /// does not serve as a hub, for a key in use, and past the limits.
    /// Gives what the invitation says of the hub: its key, its addresses
    /// and the group's obfuscation settings.
    fn let_in(
        &self,
        public: [u8; 32],
        psk: [u8; 32],
        pairs: Option<mpsc::SyncSender<Pair>>,
        owner: Option<DeviceId>,
    ) -> Result<([u8; 32], Vec<String>, Option<cbb_core::msg::Obfuscation>)> {
        let away = self.away().ok_or_else(|| Error::msg(NOT_SERVING))?;
        if !away.is_hub_now() {
            return Err(Error::msg(NOT_SERVING));
        }
        // A hub that was just made starts its tunnel in a moment.
        let until = Instant::now() + TUNNEL_START;
        while self.hub.lock().unwrap().is_none() && Instant::now() < until && !self.is_closed() {
            std::thread::sleep(Duration::from_millis(100));
        }
        if self.hub.lock().unwrap().is_none() {
            return Err(Error::msg(if self.stands_by() {
                "this hub stands by while a hub above it in the group's order serves: make the invitation there"
            } else {
                "the hub's tunnel is not running yet; try again in a minute"
            }));
        }
        let way = away.guest_way()?;
        let addr = hub::guest_addr(&public);
        {
            let mut guests = self.guests.lock().unwrap();
            let through = guests.values().filter(|g| g.owner.is_some());
            match &owner {
                None if guests.values().filter(|g| g.owner.is_none()).count() >= MAX_OPEN => {
                    return Err(Error::msg(format!("{MAX_OPEN} invitations are open already")));
                }
                Some(_) if through.clone().count() >= MAX_THROUGH => {
                    return Err(Error::msg("the hub carries as many invitations of other admins as it takes"));
                }
                Some(o) if through.filter(|g| g.owner.as_ref() == Some(o)).count() >= MAX_OPEN => {
                    return Err(Error::msg(format!("{MAX_OPEN} invitations of this admin are open already")));
                }
                _ => {}
            }
            if guests.contains_key(&addr) {
                return Err(Error::msg("that guest key is in use"));
            }
            let peer = hub::Peer { key: public, psk, older_psks: Vec::new(), addr, until: None, source: None };
            let g = Guest {
                peer,
                pairs,
                owner,
                conns: HashMap::new(),
                next_conn: 0,
                admitted: None,
                offered: false,
                done: false,
            };
            guests.insert(addr, g);
        }
        self.give_hub_peers();
        Ok(way)
    }

    /// The invitation of the guest with the public key ended: with the
    /// device the admin admitted, whose first member connection comes
    /// through the guest, after which the guest goes; without one, the
    /// guest goes a little later, since the attempt that ended it still
    /// sends the device its answer.
    pub fn guest_ended(self: &Arc<Self>, public: &[u8; 32], admitted: Option<DeviceId>) {
        let addr = hub::guest_addr(public);
        let w = Arc::downgrade(self);
        match admitted {
            Some(d) => {
                if let Some(g) = self.guests.lock().unwrap().get_mut(&addr) {
                    g.admitted = Some(d);
                }
                std::thread::spawn(move || {
                    let until = Instant::now() + GUEST_GRACE;
                    loop {
                        let Some(l) = w.upgrade() else { return };
                        let gone = l.guests.lock().unwrap().get(&addr).is_none_or(|g| g.done);
                        if gone || Instant::now() >= until || l.is_closed() {
                            l.drop_guest(&addr);
                            return;
                        }
                        drop(l);
                        std::thread::sleep(Duration::from_millis(200));
                    }
                });
            }
            None => {
                std::thread::spawn(move || {
                    std::thread::sleep(FAIL_GRACE);
                    if let Some(l) = w.upgrade() {
                        l.drop_guest(&addr);
                    }
                });
            }
        }
    }

    /// Forgets a guest: its packets are dropped from then on.
    fn drop_guest(&self, addr: &Ipv6Addr) {
        let Some(g) = self.guests.lock().unwrap().remove(addr) else { return };
        for c in g.conns.values() {
            let _ = c.shutdown(Shutdown::Both);
        }
        self.give_hub_peers();
    }

    /// The guests' peers, for the hub's tunnel.
    pub(super) fn guest_peers(&self) -> Vec<hub::Peer> {
        self.guests.lock().unwrap().values().map(|g| g.peer.clone()).collect()
    }

    /// The hub answered the `tunnel` of from, which a guest may have
    /// admitted.
    pub(super) fn guest_offered(&self, from: &DeviceId) {
        for g in self.guests.lock().unwrap().values_mut() {
            if g.admitted.as_ref() == Some(from) {
                g.offered = true;
            }
        }
    }

    /// Serves a connection that came through the guest tunnel of from: the
    /// pairing of its invitation, and once the admin admitted a device,
    /// that device's member connection alone. Any other is closed.
    pub(super) fn serve_guest(self: &Arc<Self>, sock: TcpStream, from: Ipv6Addr) {
        let Some((pairs, admitted, owner)) =
            self.guests.lock().unwrap().get(&from).map(|g| (g.pairs.clone(), g.admitted, g.owner))
        else {
            let _ = sock.shutdown(Shutdown::Both);
            return;
        };
        // An admin's invitation: its pairing goes to that admin.
        if let (None, Some(owner)) = (admitted, owner) {
            return self.pass_to_owner(sock, from, owner);
        }
        match admitted {
            Some(d) => {
                let res = self.mesh.accept_checked(sock, &|id| *id == d);
                if let Some(g) = self.guests.lock().unwrap().get_mut(&from) {
                    g.done = g.offered;
                }
                if let Err(e) = res
                    && !self.is_closed()
                {
                    self.logf(&format!("cbb: a member connection through a guest tunnel: {}", e.for_log()));
                }
            }
            None => {
                let Some(pairs) = pairs else {
                    let _ = sock.shutdown(Shutdown::Both);
                    return;
                };
                match self.mesh.pair_handshake(sock) {
                    // One attempt at a time: another waits for none.
                    Ok(p) => {
                        if let Err(mpsc::TrySendError::Full(p) | mpsc::TrySendError::Disconnected(p)) =
                            pairs.try_send(p)
                        {
                            let _ = p.0.shutdown(Shutdown::Both);
                        }
                    }
                    Err(e) => self.logf(&format!("cbb: a pairing through a guest tunnel: {}", e.for_log())),
                }
            }
        }
    }

    /// Dials the hub of the invitation this device joined with through its
    /// guest tunnel while no hub's offer is kept, so that its `tunnel`
    /// reaches the hub; once an offer is kept, the guest connection ends and
    /// the invitation is forgotten. Whether it tried.
    pub(super) fn through_guest(&self, away: &crate::away::Away) -> bool {
        let path = self.mesh.dir().join(GUEST_FILE);
        let Ok(text) = std::fs::read_to_string(&path) else { return false };
        let old = std::fs::metadata(&path)
            .and_then(|m| m.modified())
            .ok()
            .and_then(|t| t.elapsed().ok())
            .is_none_or(|age| age > GUEST_GRACE);
        let link =
            Invitation::parse(text.trim()).ok().filter(|_| !old).and_then(|i| guest_link(&i, self.log.clone()).ok());
        let Some(link) = link.filter(|_| away.hubs_kept().is_empty()) else {
            let _ = std::fs::remove_file(&path);
            return false;
        };
        let kept = || away.hubs_kept().into_iter().filter_map(|h| super::id_of_hex(&h.device)).collect::<Vec<_>>();
        let dialing = AtomicBool::new(true);
        let res = std::thread::scope(|s| {
            s.spawn(|| {
                while dialing.load(Ordering::SeqCst) {
                    let hubs = kept();
                    if !hubs.is_empty() {
                        for h in &hubs {
                            self.mesh.disconnect(h);
                        }
                        return;
                    }
                    std::thread::sleep(Duration::from_millis(200));
                }
            });
            let res = self.mesh.dial(link.local(), None);
            dialing.store(false, Ordering::SeqCst);
            res
        });
        if kept().is_empty() {
            if let Err(e) = res {
                let e = if link.answered() {
                    e
                } else {
                    e.context("the hub does not answer through the invitation's guest tunnel; this device tries again for a day")
                };
                self.logf(&format!("cbb: reaching the hub through the invitation's guest tunnel: {}", e.for_log()));
            }
        } else {
            let _ = std::fs::remove_file(&path);
            self.logf("cbb: the hub took this device's tunnel key; the invitation's guest tunnel is closed");
        }
        std::thread::sleep(Duration::from_secs(1));
        true
    }
}

#[cfg(feature = "tunnel")]
impl Live {
    /// Sends a `guest` message to the device to; whether it went.
    pub(super) fn send_guest(&self, to: &DeviceId, g: &cbb_core::join::guest::Guest) -> bool {
        match cbb_core::format::cbor::decode(&g.encode()) {
            Ok(v) => self.mesh.send(to, cbb_core::format::frame::write(&v)),
            Err(_) => false,
        }
    }

    /// A `guest` message came from peer: on the hub, from the admin whose
    /// invitation it is about (or one that opens it); on that admin, from
    /// the hub it opened the invitation through.
    pub(super) fn guest_from(self: &Arc<Self>, peer: &DeviceId, msg: &[u8]) {
        use cbb_core::join::guest::{Guest, Op};
        let g = match Guest::read(msg) {
            Ok(g) => g,
            Err(e) => {
                self.logf(&format!("cbb: ignored message guest from {}: {e}", super::id_text4(peer)));
                return;
            }
        };
        if self.through_from(peer, &g) {
            return;
        }
        let addr = hub::guest_addr(&g.key);
        let owned = || self.guests.lock().unwrap().get(&addr).is_some_and(|x| x.owner.as_ref() == Some(peer));
        match g.op {
            Op::Open { psk, expires_ms, .. } => {
                let op = match self.open_for(peer, g.key, psk, expires_ms) {
                    Ok(offer) => Op::Opened { offer },
                    Err(e) => {
                        self.logf(&format!(
                            "cbb: refused an invitation of {} through this hub: {}",
                            super::id_text4(peer),
                            e.for_log()
                        ));
                        Op::Refused { reason: e.for_user() }
                    }
                };
                self.send_guest(peer, &Guest { key: g.key, op });
            }
            Op::Admitted { device } if owned() => {
                let d = DeviceId(device);
                self.logf(&format!(
                    "cbb: {} admitted {} with an invitation through this hub",
                    super::id_text4(peer),
                    super::id_text4(&d)
                ));
                self.guest_ended(&g.key, Some(d));
            }
            Op::Close if owned() => self.guest_ended(&g.key, None),
            Op::Data { conn, ref data } if owned() => {
                let c = self.guests.lock().unwrap().get(&addr).and_then(|x| x.conns.get(&conn)?.try_clone().ok());
                if let Some(mut c) = c
                    && std::io::Write::write_all(&mut c, data).is_err()
                {
                    let _ = c.shutdown(Shutdown::Write);
                }
            }
            Op::End { conn } if owned() => {
                if let Some(c) = self.guests.lock().unwrap().get(&addr).and_then(|x| x.conns.get(&conn)) {
                    let _ = c.shutdown(Shutdown::Write);
                }
            }
            _ => {}
        }
    }

    /// Lets the guest of an invitation the admin from makes through this
    /// hub in, until expires_ms, and gives the hub's side of it as an
    /// offer: its key, its addresses and the group's obfuscation settings.
    fn open_for(self: &Arc<Self>, from: &DeviceId, key: [u8; 32], psk: [u8; 32], expires_ms: u64) -> Result<Vec<u8>> {
        use cbb_core::format::cbor::Value;
        if !cbb_core::join::waiting::holder_may_send(&self.mesh.state(), from) {
            return Err(Error::msg("only the group's root or an admin that admits devices makes invitations"));
        }
        let now = crate::uptime::wall_ms().max(0) as u64;
        let most = now.saturating_add(crate::inviter::MAX_LIFETIME.as_millis() as u64 + 60_000);
        if expires_ms <= now || expires_ms > most {
            return Err(Error::msg("an invitation is valid for 24h0m0s at most"));
        }
        let (hub_key, endpoints, obfuscation) = self.let_in(key, psk, None, Some(*from))?;
        // The guest goes at its expiry unless its device was admitted.
        let (w, addr) = (Arc::downgrade(self), hub::guest_addr(&key));
        let left = Duration::from_millis(expires_ms - now);
        std::thread::spawn(move || {
            // On the clock that counts sleep: a hub that slept does not
            // keep the guest past the invitation.
            let until = crate::uptime::now() + left;
            while crate::uptime::now() < until {
                std::thread::sleep(Duration::from_secs(1));
                let Some(l) = w.upgrade() else { return };
                if l.guests.lock().unwrap().get(&addr).is_none_or(|g| g.admitted.is_some()) {
                    return;
                }
            }
            if let Some(l) = w.upgrade()
                && l.guests.lock().unwrap().get(&addr).is_some_and(|g| g.admitted.is_none())
            {
                l.drop_guest(&addr);
            }
        });
        self.logf(&format!(
            "cbb: an invitation of {} is open through this hub for {} minutes",
            super::id_text4(from),
            left.as_secs() / 60
        ));
        let hk = cbb_core::format::Key::new(cbb_core::format::Alg::X25519, &hub_key);
        let mut m = vec![(1, hk.to_value()), (2, Value::Array(endpoints.iter().map(|e| Value::Text(e)).collect()))];
        let obf = match &obfuscation {
            Some(o) => Some(
                cbb_core::format::cbor::decode(o.encoding())
                    .map_err(|_| Error::msg("the obfuscation settings do not decode"))?,
            ),
            None => None,
        };
        if let Some(o) = obf {
            m.push((3, o));
        }
        let v = Value::Map(m);
        cbb_core::msg::read_map(&cbb_core::msg::tables::OFFER, &v)
            .map_err(|r| Error::msg(format!("the hub's offer breaks {r}")))?;
        Ok(v.encode())
    }

    /// Passes a pairing connection that came through the guest of the
    /// admin owner's invitation to that admin, and what it answers back,
    /// until either side ends it.
    fn pass_to_owner(&self, sock: TcpStream, from: Ipv6Addr, owner: DeviceId) {
        use cbb_core::join::guest::{Guest, MAX_DATA, Op};
        if !self.mesh.connected().contains(&owner) {
            self.logf(&format!(
                "cbb: a device used an invitation of {}, which is not connected to this hub now; it can try again later",
                super::id_text4(&owner)
            ));
            let _ = sock.shutdown(Shutdown::Both);
            return;
        }
        let (key, conn) = {
            let mut gs = self.guests.lock().unwrap();
            let Some(g) = gs.get_mut(&from) else { return };
            let Ok(c) = sock.try_clone() else { return };
            if g.conns.len() >= MAX_CONNS {
                let _ = sock.shutdown(Shutdown::Both);
                return;
            }
            g.next_conn = g.next_conn.wrapping_add(1).max(1);
            g.conns.insert(g.next_conn, c);
            (g.peer.key, g.next_conn)
        };
        let _ = sock.set_read_timeout(Some(PASS_IDLE));
        let mut buf = vec![0u8; MAX_DATA];
        let mut total = 0usize;
        loop {
            let n = match std::io::Read::read(&mut &sock, &mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            total = total.saturating_add(n);
            if total > MAX_PASSED {
                self.logf("cbb: a pairing connection through a guest tunnel passed too much; closed");
                break;
            }
            let data = buf.get(..n).unwrap_or_default().to_vec();
            if !self.send_guest(&owner, &Guest { key, op: Op::Data { conn, data } }) {
                break;
            }
        }
        self.send_guest(&owner, &Guest { key, op: Op::End { conn } });
        if let Some(g) = self.guests.lock().unwrap().get_mut(&from) {
            g.conns.remove(&conn);
        }
        let _ = sock.shutdown(Shutdown::Both);
    }
}

/// Why an invitation is refused on a device that does not serve as a hub.
pub const NOT_SERVING: &str = "invitations come from a hub of the group, and this device is none; make it one with cbb global hub, or invite on a hub";

/// The guest path of an invitation, which a device joins by.
pub fn guest_path(inv: &Invitation) -> Result<&Path> {
    inv.paths
        .iter()
        .find(|p| p.kind == PathKind::Guest)
        .ok_or_else(|| Error::msg("the invitation has no way in through a hub; ask for a new one"))
}

/// The guest tunnel of an invitation to its hub, whose loopback port leads
/// to the hub's guest address.
#[cfg(feature = "tunnel")]
pub fn guest_link(inv: &Invitation, log: Arc<dyn Fn(&str) + Send + Sync>) -> Result<crate::tunnel::Link> {
    let p = guest_path(inv)?;
    let (key, psk) = p.guest.ok_or_else(|| Error::msg("the invitation's guest path has no guest key"))?;
    let hub_key = p.hub_key.ok_or_else(|| Error::msg("the invitation's guest path has no hub key"))?;
    let endpoints = p
        .endpoints
        .iter()
        .map(|e| e.parse::<std::net::SocketAddr>().map_err(|e| Error::with("an address of the hub is not ip:port", e)))
        .collect::<Result<Vec<_>>>()?;
    let obfuscation = match &p.obfuscation {
        Some(o) => {
            let v = cbb_core::format::cbor::decode(o.encoding())
                .map_err(|_| Error::msg("the invitation's obfuscation settings do not decode"))?;
            Some(crate::awg::Obfuscation::from_cbor(&v)?.to_value())
        }
        None => None,
    };
    let st = crate::tunnel::State::with_key(&key)?;
    let hub = crate::tunnel::Hub {
        device: String::new(),
        key: hub_key.to_vec(),
        psk: psk.to_vec(),
        endpoints,
        obfuscation,
        ..Default::default()
    };
    let own = hub::guest_addr(&crate::tunnel::key32(&crate::tunnel::public_of(&key))?);
    crate::tunnel::Link::start_at(&st, &hub, own, hub::GUEST_HUB, log)
}

/// How many connections a join through the guest tunnel tries while each
/// ends before its TLS handshake.
#[cfg(feature = "tunnel")]
const HANDSHAKE_TRIES: u32 = 5;

/// Joins the group of a remote invitation of 0.6 (cbb pair -invite): through
/// the invitation's guest tunnel to the hub, with its secret; the hub's
/// admin confirms the device before it is admitted, so each step may wait
/// that long. Sync away from home goes on, and the invitation is kept for
/// the service to reach the hub through its guest tunnel, before the set,
/// which the service takes.
#[cfg(feature = "tunnel")]
pub fn join(
    dir: &std::path::Path,
    me: &crate::joining::Me<'_>,
    text: &str,
    log: Arc<dyn Fn(&str) + Send + Sync>,
) -> Result<Box<cbb_core::join::session::Admitted>> {
    let inv = Invitation::parse(text.trim()).map_err(|r| Error::msg(format!("this is not an invitation: {r}")))?;
    let link = guest_link(&inv, log)?;
    let text = text.trim().to_string();
    let before = |a: &cbb_core::join::session::Admitted| -> Result<()> {
        crate::tunnel::State::new(&super::tag(&a.state))?.save(dir)?;
        crate::files::write_atomic(&dir.join(GUEST_FILE), text.as_bytes(), 0o600)
    };
    let step = crate::window::CONFIRM_WAIT + Duration::from_secs(60);
    // A connection that ends before its TLS handshake never reached the
    // window, as when the hub passes it to an admin not connected just
    // then: it counts as no attempt, and the next one goes after a pause.
    let mut tries = 0;
    let (joined, kept) = loop {
        tries += 1;
        let sock = TcpStream::connect_timeout(&link.local(), Duration::from_secs(10))
            .context("cannot reach the tunnel's local port")?;
        let kept = sock.try_clone().context("cannot use the tunnel's connection")?;
        match crate::joining::over_with(dir, sock, "the hub", me, inv.clone(), None, step, &before) {
            Err(e) if tries < HANDSHAKE_TRIES && e.message().starts_with(crate::joining::NO_HANDSHAKE) => {
                std::thread::sleep(Duration::from_secs(2));
            }
            Err(e) if !link.answered() => return Err(e.context("the hub did not answer; check that the invitation is still valid, that the hub is on, and that its UDP port or its forwarder can be reached")),
            res => break (res?, kept),
        }
    };
    // The last message must reach the hub before the tunnel stops: the hub
    // ends the connection once it has it.
    let _ = kept.set_read_timeout(Some(Duration::from_secs(5)));
    let _ = std::io::Read::read(&mut &kept, &mut [0u8; 64]);
    Ok(joined)
}

/// A build without the tunnel joins at home only.
#[cfg(not(feature = "tunnel"))]
pub fn join(
    _dir: &std::path::Path,
    _me: &crate::joining::Me<'_>,
    _text: &str,
    _log: Arc<dyn Fn(&str) + Send + Sync>,
) -> Result<Box<cbb_core::join::session::Admitted>> {
    Err(Error::msg(super::off::NO_TUNNEL))
}
