// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! Remote invitations on the hub (docs/design.md, "Joining from another
//! network"), as Go's internal/service/invite.go: the hub makes a one-time
//! guest key that reaches only the pairing inside its tunnel, and a pairing
//! window on a 128-bit secret whose admin confirms the device before it is
//! admitted. The new device pairs through the guest tunnel, then offers its
//! own tunnel key through it as a member, and from then on reaches the hub
//! as an ordinary client.
//!
//! An admin that is not the hub makes an invitation through it
//! (docs/protocol.md, section 12, "Through the hub"; src/inviter.rs): the
//! hub lets the admin's guest in and passes the bytes of each pairing
//! connection through the guest tunnel to that admin, whose window answers
//! them.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{Ipv6Addr, Shutdown, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use cbb_core::invite::Invitation;

use super::Away;
use crate::certs::{Cert, DeviceId};
use crate::error::{Context, Error, Result};
use crate::hub::{self, Hub};
use crate::inviter::{GuestKeys, Opened};
use crate::node::{Node, OnPairing};
use crate::window::Window;
use crate::wire;

/// How long an invitation waits for a hub's tunnel that is starting.
const TUNNEL_START: Duration = Duration::from_secs(10);
/// The most invitations the hub carries for one admin through it, and for
/// all of them.
const MAX_PER_ADMIN: usize = crate::inviter::MAX_OPEN;
const MAX_THROUGH: usize = 16;
/// The most bytes one pairing connection passes through the hub to its
/// admin, and the most such connections of one guest at once: a pairing
/// takes a few kilobytes, one at a time.
const MAX_RELAYED: usize = 1 << 20;
const MAX_CONNS: usize = 2;
/// How long a pairing connection passed to an admin may stay silent: the
/// window waits up to five minutes for its admin to confirm the device.
const RELAY_IDLE: Duration = Duration::from_secs(360);
/// How long a guest tunnel stays at most after its device was admitted,
/// for the device's first member connection, in which it offers its own
/// tunnel key; once the hub answered that offer, the guest goes as soon as
/// that connection ends. It reaches only that device's member TLS by then,
/// so it may wait for a device whose service starts late: a day.
const GUEST_GRACE: Duration = Duration::from_secs(24 * 3600);
/// How long a guest tunnel stays after its invitation ended without a
/// device, for the last answer to reach the device.
const FAIL_GRACE: Duration = Duration::from_secs(10);

/// The guest tunnel of an open invitation, on the hub.
pub(super) struct Guest {
    peer: hub::Peer,
    /// The hub's own window; None for an admin's invitation through it.
    window: Option<Arc<Window>>,
    /// The admin whose invitation it is, when not the hub's own: the
    /// pairing connections go to it.
    owner: Option<DeviceId>,
    /// The pairing connections passed to the owner, by number.
    conns: HashMap<i64, TcpStream>,
    next_conn: i64,
    /// The device the window admitted, None until then.
    admitted: Option<DeviceId>,
    /// The hub answered the admitted device's tunnel key.
    offered: bool,
    /// The admitted device's member connection through the guest ended
    /// after the hub answered its key: the guest can go.
    done: bool,
}

/// What an invitation gives of its hub: its key, its addresses, the group's
/// AmneziaWG settings and the way to its forwarder over VLESS.
type GuestWay =
    ([u8; 32], Vec<std::net::SocketAddr>, Option<cbb_core::invite::Obfuscation>, Option<cbb_core::invite::Vless>);

/// The guests of the open invitations, by their tunnel addresses.
pub(super) type Guests = Arc<Mutex<HashMap<Ipv6Addr, Guest>>>;

impl Away {
    /// Opens the guest tunnel of an invitation this hub makes, whose
    /// pairing connections the window serves.
    pub fn open_own(self: &Arc<Self>, keys: &GuestKeys, w: &Arc<Window>) -> Result<Opened> {
        let addr = hub::guest_addr(&keys.public);
        let peer = hub::Peer { key: keys.public, psk: keys.psk, addr, until: None };
        let (hub_key, endpoints, obfuscation, vless) = self.open_guest(peer, Some(w.clone()), None)?;
        let me = self.clone();
        Ok(Opened {
            hub: self.me.as_str().to_string(),
            hub_key,
            endpoints,
            obfuscation,
            vless,
            ended: Box::new(move |admitted| me.guest_ended(addr, admitted)),
        })
    }

    /// The window of the guest at addr ended: with a device, whose first
    /// member connection comes through the guest tunnel to offer its own
    /// key, after which the guest goes; without one, the guest goes a
    /// little later, since the attempt that closed the window still sends
    /// the device its answer through it.
    fn guest_ended(self: &Arc<Self>, addr: Ipv6Addr, admitted: Option<&DeviceId>) {
        let me = self.clone();
        match admitted {
            Some(d) => {
                if let Some(g) = self.guests.lock().unwrap().get_mut(&addr) {
                    g.admitted = Some(d.clone());
                }
                std::thread::spawn(move || {
                    let until = Instant::now() + GUEST_GRACE;
                    while Instant::now() < until && !me.guests.lock().unwrap().get(&addr).is_none_or(|g| g.done) {
                        std::thread::sleep(Duration::from_millis(200));
                    }
                    me.drop_guest(&addr);
                });
            }
            None => {
                std::thread::spawn(move || {
                    std::thread::sleep(FAIL_GRACE);
                    me.drop_guest(&addr);
                });
            }
        }
    }

    /// Lets the guest of an invitation into the running hub, and returns
    /// what the invitation gives of the hub: its key, its addresses, the
    /// group's AmneziaWG settings and the way to its forwarder over VLESS.
    fn open_guest(&self, peer: hub::Peer, window: Option<Arc<Window>>, owner: Option<DeviceId>) -> Result<GuestWay> {
        // A hub that was just made starts its tunnel in a moment: the
        // invitation waits for it, or for its failure, a little.
        let until = Instant::now() + TUNNEL_START;
        while self.serving.lock().unwrap().is_none() && self.error.lock().unwrap().is_none() && Instant::now() < until {
            std::thread::sleep(Duration::from_millis(100));
        }
        let cur = self.st.lock().unwrap();
        let st = cur.as_ref().filter(|s| s.is_hub).ok_or_else(|| {
            Error::msg("invitations come from the group's hub, and this device is not the hub; make it the hub with cbb global hub, or invite on the hub")
        })?;
        let endpoints = st.hub_endpoints();
        if endpoints.is_empty() {
            return Err(Error::msg(
                "the hub has no address away from home yet; run cbb global hub with its addresses or a forwarder there",
            ));
        }
        if self.serving.lock().unwrap().is_none() {
            return Err(Error::msg(match self.error.lock().unwrap().as_ref() {
                Some((why, _)) => format!("the hub's tunnel is not running: {why}"),
                None => "the hub's tunnel is not running yet; try again in a minute".to_string(),
            }));
        }
        let obfuscation = match &st.obfuscation {
            Some(v) => Some(
                cbb_core::invite::obfuscation_from_json(v)
                    .ok_or_else(|| Error::msg("the group's obfuscation settings are damaged"))?,
            ),
            None => None,
        };
        // The way over VLESS is the one the hub's offer gives its clients;
        // a hub still waiting for its forwarder's answer has none yet, and
        // REALITY is left out, since the joiner may be a phone.
        let vless = super::serve::own_offer(st, &[0u8; 32])
            .and_then(|o| o.vless)
            .and_then(|v| cbb_core::invite::vless_from_offer(&v));
        let addr = peer.addr;
        {
            let mut guests = self.guests.lock().unwrap();
            if let Some(o) = &owner {
                if guests.values().filter(|g| g.owner.is_some()).count() >= MAX_THROUGH {
                    return Err(Error::msg("the hub carries as many invitations of other admins as it takes"));
                }
                if guests.values().filter(|g| g.owner.as_ref() == Some(o)).count() >= MAX_PER_ADMIN {
                    return Err(Error::msg(format!("{MAX_PER_ADMIN} invitations of this admin are open already")));
                }
            }
            guests.insert(
                addr,
                Guest {
                    peer,
                    window,
                    owner,
                    conns: HashMap::new(),
                    next_conn: 0,
                    admitted: None,
                    offered: false,
                    done: false,
                },
            );
        }
        self.set_peers(st);
        Ok((crate::tunnel::key32(&crate::tunnel::public_of(&st.serving_key()?))?, endpoints, obfuscation, vless))
    }

    /// Forgets a guest tunnel: its packets are dropped from then on.
    fn drop_guest(&self, addr: &Ipv6Addr) {
        let Some(g) = self.guests.lock().unwrap().remove(addr) else { return };
        for c in g.conns.values() {
            let _ = c.shutdown(Shutdown::Both);
        }
        if let Some(st) = self.st.lock().unwrap().as_ref() {
            self.set_peers(st);
        }
    }

    /// The guests' peers, for the running hub.
    pub(super) fn guest_peers(&self) -> Vec<hub::Peer> {
        self.guests.lock().unwrap().values().map(|g| g.peer.clone()).collect()
    }

    /// Notes that the hub answered the tunnel key of from, which a guest
    /// may have admitted.
    pub(super) fn guest_offered(&self, from: &DeviceId) {
        for g in self.guests.lock().unwrap().values_mut() {
            if g.admitted.as_ref() == Some(from) {
                g.offered = true;
            }
        }
    }
}

impl Away {
    /// Takes, on the hub, a guest message from the admin from, whose chain
    /// the member connection proved (Node::on_guest): an invitation the
    /// admin makes through this hub (docs/protocol.md, section 12, "Through
    /// the hub").
    pub fn guest_message(self: &Arc<Self>, node: &Node, from: &DeviceId, chain: &[Cert], g: wire::Guest) {
        let addr = hub::guest_addr(&match <[u8; 32]>::try_from(g.key.as_slice()) {
            Ok(k) => k,
            Err(_) => return,
        });
        match g.op.as_str() {
            "open" => {
                let answer = match self.open_for(node, from, chain, &g) {
                    Ok(a) => a,
                    Err(e) => {
                        (self.log)(&format!("cbb: refused an invitation of {from} through this hub: {}", e.for_log()));
                        wire::Guest { op: "refused".into(), key: g.key, reason: e.for_user(), ..Default::default() }
                    }
                };
                node.send_to(from, wire::guest(&answer));
            }
            "admitted" => {
                let Ok(d) = DeviceId::parse(&g.device) else { return };
                if self.guests.lock().unwrap().get(&addr).is_some_and(|x| x.owner.as_ref() == Some(from)) {
                    (self.log)(&format!("cbb: {from} admitted {d} with an invitation through this hub"));
                    self.guest_ended(addr, Some(&d));
                }
            }
            "close" => {
                if self.guests.lock().unwrap().get(&addr).is_some_and(|x| x.owner.as_ref() == Some(from)) {
                    self.guest_ended(addr, None);
                }
            }
            "data" | "end" => {
                let c = self
                    .guests
                    .lock()
                    .unwrap()
                    .get(&addr)
                    .filter(|x| x.owner.as_ref() == Some(from))
                    .and_then(|x| x.conns.get(&g.conn))
                    .and_then(|c| c.try_clone().ok());
                let Some(mut c) = c else { return };
                if g.op == "end" || c.write_all(g.data.as_deref().unwrap_or_default()).is_err() {
                    let _ = c.shutdown(Shutdown::Write);
                }
            }
            _ => {}
        }
    }

    /// Lets the guest of an admin's invitation in, and answers with the
    /// hub's side of it.
    fn open_for(
        self: &Arc<Self>,
        node: &Node,
        from: &DeviceId,
        chain: &[Cert],
        g: &wire::Guest,
    ) -> Result<wire::Guest> {
        if !self.is_hub() {
            return Err(Error::msg(crate::inviter::NOT_A_HUB));
        }
        if !node.records().lock().unwrap().admit_peer(from.as_str(), chain) {
            return Err(Error::msg("only the group's root or an admin that admits devices makes invitations"));
        }
        let now = crate::uptime::wall_ms();
        let most = now.saturating_add(crate::inviter::MAX_LIFETIME.as_millis() as i64 + 60_000);
        if g.expires_ms <= now || g.expires_ms > most {
            return Err(Error::msg("an invitation is valid for 24h0m0s at most"));
        }
        let key: [u8; 32] = g.key.as_slice().try_into().map_err(|_| Error::msg("the guest's key is not 32 bytes"))?;
        let psk: [u8; 32] =
            g.psk.as_deref().and_then(|p| p.try_into().ok()).ok_or_else(|| Error::msg("no preshared key"))?;
        let addr = hub::guest_addr(&key);
        if self.guests.lock().unwrap().contains_key(&addr) {
            return Err(Error::msg("that guest key is in use"));
        }
        let peer = hub::Peer { key, psk, addr, until: None };
        let (hub_key, endpoints, obfuscation, vless) = self.open_guest(peer, None, Some(from.clone()))?;
        // The guest goes at its expiry unless its window admitted a device.
        let (me, left) = (self.clone(), Duration::from_millis(u64::try_from(g.expires_ms - now).unwrap_or(0)));
        std::thread::spawn(move || {
            // On the clock that counts sleep, as the window's: a hub that
            // slept does not keep the guest past the invitation.
            let until = crate::uptime::now() + left;
            while crate::uptime::now() < until {
                std::thread::sleep(Duration::from_secs(1));
                if me.guests.lock().unwrap().get(&addr).is_none_or(|g| g.admitted.is_some()) {
                    return;
                }
            }
            if me.guests.lock().unwrap().get(&addr).is_some_and(|g| g.admitted.is_none()) {
                me.drop_guest(&addr);
            }
        });
        (self.log)(&format!(
            "cbb: an invitation of {from} is open through this hub for {} minutes",
            left.as_secs() / 60
        ));
        Ok(wire::Guest {
            op: "opened".into(),
            key: key.to_vec(),
            hub_key: Some(hub_key.to_vec()),
            endpoints: endpoints.iter().map(ToString::to_string).collect(),
            obfuscation: obfuscation.as_ref().map(cbb_core::invite::Obfuscation::to_json),
            vless: vless.as_ref().map(cbb_core::invite::Vless::to_json),
            ..Default::default()
        })
    }
}

/// Passes a pairing connection that came through the guest tunnel of the
/// admin owner's invitation to that admin, and what it answers back, until
/// either side ends it.
fn relay(sock: TcpStream, from: Ipv6Addr, owner: DeviceId, node: Arc<Node>, guests: Guests) {
    if !node.connected(&owner) {
        node.logf(&format!(
            "cbb: a device used an invitation of {owner}, which is not connected to this hub now; it can try again later"
        ));
        let _ = sock.shutdown(Shutdown::Both);
        return;
    }
    let (key, conn) = {
        let mut gs = guests.lock().unwrap();
        let Some(g) = gs.get_mut(&from) else { return };
        let Ok(c) = sock.try_clone() else { return };
        if g.conns.len() >= MAX_CONNS {
            let _ = sock.shutdown(Shutdown::Both);
            return;
        }
        g.next_conn += 1;
        g.conns.insert(g.next_conn, c);
        (g.peer.key.to_vec(), g.next_conn)
    };
    let _ = sock.set_read_timeout(Some(RELAY_IDLE));
    let mut r = &sock;
    let mut buf = vec![0u8; wire::MAX_GUEST_DATA];
    let mut total = 0usize;
    loop {
        let n = match r.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        total = total.saturating_add(n);
        if total > MAX_RELAYED {
            node.logf("cbb: a pairing connection through a guest tunnel passed too much; closed");
            break;
        }
        let data = buf.get(..n).unwrap_or_default().to_vec();
        let g = wire::Guest { op: "data".into(), key: key.clone(), conn, data: Some(data), ..Default::default() };
        if !node.send_to(&owner, wire::guest(&g)) {
            break;
        }
    }
    node.send_to(&owner, wire::guest(&wire::Guest { op: "end".into(), key, conn, ..Default::default() }));
    if let Some(g) = guests.lock().unwrap().get_mut(&from) {
        g.conns.remove(&conn);
    }
    let _ = sock.shutdown(Shutdown::Both);
}

/// Serves, on the hub, the connections through the guest tunnels that come
/// to the loopback listener ln: the pairing of each guest's invitation, and
/// once that admitted a device, that device's member connection.
pub(super) fn serve_guests(ln: TcpListener, hub: std::sync::Weak<Hub>, node: std::sync::Weak<Node>, guests: Guests) {
    std::thread::spawn(move || {
        for sock in ln.incoming() {
            let (Some(h), Some(node), Ok(sock)) = (hub.upgrade(), node.upgrade(), sock) else { return };
            let from = sock.peer_addr().ok().and_then(|a| super::serve::tunnel_addr_of(&h, a.port()));
            drop(h);
            let Some(from) = from else { continue };
            let Some((w, admitted, owner)) =
                guests.lock().unwrap().get(&from).map(|g| (g.window.clone(), g.admitted.clone(), g.owner.clone()))
            else {
                continue;
            };
            let guests = guests.clone();
            std::thread::spawn(move || {
                // An admin's invitation: its pairing goes to that admin.
                if let (None, Some(owner)) = (&admitted, owner) {
                    return relay(sock, from, owner, node, guests);
                }
                let pairing: OnPairing = {
                    let node = Arc::downgrade(&node);
                    Arc::new(move |sock, session, exporter, addr| {
                        let node = node.upgrade().ok_or_else(|| Error::msg("the service is stopping"))?;
                        match &w {
                            Some(w) => w.serve(&node, sock, session, exporter, addr),
                            None => Err(Error::msg("the invitation's window is not on this hub")),
                        }
                    })
                };
                let member = admitted.is_some();
                if let Err(e) = node.accept_guest(sock, from, pairing, admitted)
                    && !node.is_closed()
                {
                    node.logf(&format!("cbb: a connection through a guest tunnel: {}", e.for_log()));
                }
                // The device reaches the hub with its own key from now on.
                if member && let Some(g) = guests.lock().unwrap().get_mut(&from) {
                    g.done = g.offered;
                }
            });
        }
    });
}

/// The file in the state directory that holds the invitation a device
/// joined with until it has the hub's offer: the service dials the hub
/// through its guest tunnel meanwhile, to offer its own key.
const GUEST_FILE: &str = "invite-guest";
/// How long after the join the guest tunnel is tried at most: as long as
/// the hub keeps the guest for the admitted device.
const GUEST_FILE_LIFE: Duration = GUEST_GRACE;

/// Joins the group of a remote invitation (cbb pair -invite), as Go's
/// joinInvite: through the guest tunnel to the hub, with the invitation's
/// secret, once the hub's admin confirmed the device. Sync away from home
/// goes on with the join, and the service then offers this device's own
/// tunnel key to the hub through the guest tunnel (Away::through_guest).
/// shown gets the device's key fingerprint, which the admin compares.
pub fn join_invite(
    dir: &std::path::Path,
    joiner: &crate::pair::Joiner,
    save: &crate::pair::Save,
    text: &str,
    shown: &dyn Fn(&str),
    log: Arc<dyn Fn(&str) + Send + Sync>,
) -> Result<crate::identity::Identity> {
    let inv = cbb_core::invite::parse(text).map_err(|r| Error::msg(r.message()))?;
    if inv.expired(crate::uptime::wall_ms() / 1000) {
        return Err(Error::msg("the invitation has expired; ask for a new one"));
    }
    shown(&joiner.fingerprint());
    let link = guest_link(&inv, log)?;
    let sock = std::net::TcpStream::connect_timeout(&link.local(), Duration::from_secs(10))
        .context("cannot reach the tunnel's local port")?;
    let text = text.trim().to_string();
    let save_all = |id: &crate::identity::Identity, rs: &[crate::records::Record], ts: &[crate::records::ClaimTime]| {
        // Sync away from home is on, and the guest file there, before the
        // identity, which a running service takes.
        crate::tunnel::State::new(&id.tag())?.save(dir)?;
        crate::files::write_atomic(&dir.join(GUEST_FILE), text.as_bytes(), 0o600)?;
        save(id, rs, ts)
    };
    crate::pair::join_secret(joiner, sock, &inv.secret, &inv.group, &save_all).map_err(|e| {
        if link.answered() {
            e
        } else {
            e.context("the hub did not answer; check that the invitation is still valid, that the hub is on, and that its UDP port or its forwarder can be reached")
        }
    })
}

/// Keeps the invitation a device joined with in the state directory, once
/// sync away from home is on there: the member then offers its own tunnel
/// key to the hub through the invitation's guest tunnel, as after cbb pair
/// -invite. A phone's app calls it after it stored its identity.
pub fn keep_guest(dir: &std::path::Path, text: &str) -> Result<()> {
    crate::files::write_atomic(&dir.join(GUEST_FILE), text.trim().as_bytes(), 0o600)
}

/// The guest tunnel of an invitation that a phone's app joins with: the
/// app dials its loopback port, which leads to the hub's pairing port, and
/// runs the join there with the invitation's secret.
pub struct GuestTunnel(crate::tunnel::Link);

impl GuestTunnel {
    /// Starts the invitation's guest tunnel.
    pub fn start(inv: &Invitation, log: Arc<dyn Fn(&str) + Send + Sync>) -> Result<GuestTunnel> {
        guest_link(inv, log).map(GuestTunnel)
    }

    /// The loopback port that leads to the hub's pairing port.
    pub fn port(&self) -> u16 {
        self.0.local().port()
    }

    /// Whether the hub has answered through the tunnel.
    pub fn answered(&self) -> bool {
        self.0.answered()
    }

    /// The tunnel's link, for a phone's app that keeps it as its other
    /// tunnels.
    pub fn into_link(self) -> crate::tunnel::Link {
        self.0
    }
}

/// The guest tunnel of an invitation to its hub.
fn guest_link(inv: &Invitation, log: Arc<dyn Fn(&str) + Send + Sync>) -> Result<crate::tunnel::Link> {
    let st = crate::tunnel::State::with_key(&inv.guest_key)?;
    let obfuscation = Some(inv.to_json()["obfuscation"].clone()).filter(|v| !v.is_null());
    let hub = crate::tunnel::Hub {
        device: inv.hub.clone(),
        key: inv.hub_key.to_vec(),
        psk: inv.guest_psk.to_vec(),
        endpoints: inv.endpoints.clone(),
        next: Vec::new(),
        obfuscation,
        vless: inv.vless.as_ref().map(cbb_core::invite::Vless::to_json),
    };
    let own = hub::guest_addr(&crate::tunnel::key32(&crate::tunnel::public_of(&inv.guest_key))?);
    let peer = crate::tunnel::addr(&inv.hub).ok_or_else(|| Error::msg("the invitation names no hub"))?;
    crate::tunnel::Link::start_at(&st, &hub, own, peer, log)
}

impl Away {
    /// Dials the hub of the invitation this device joined with through its
    /// guest tunnel, until the hub's offer came, as Go's keepUntilHub: the
    /// hello offers this device's own tunnel key. Returns whether it tried.
    pub(super) fn through_guest(&self, node: &Node, st: &crate::tunnel::State) -> bool {
        let path = self.dir.join(GUEST_FILE);
        let Ok(text) = std::fs::read_to_string(&path) else { return false };
        let old = std::fs::metadata(&path)
            .and_then(|m| m.modified())
            .ok()
            .and_then(|t| t.elapsed().ok())
            .is_none_or(|age| age > GUEST_FILE_LIFE);
        let inv = cbb_core::invite::parse(&text).ok();
        let Some(inv) = inv.filter(|i| !old && st.hub(&i.hub).is_none()) else {
            let _ = std::fs::remove_file(&path);
            return false;
        };
        let Ok(hub) = DeviceId::parse(&inv.hub) else { return false };
        match guest_link(&inv, self.log.clone()) {
            Ok(link) => {
                // Once the hub's offer came, this device reaches the hub
                // with its own key: the guest connection ends.
                let has_hub = || self.st.lock().unwrap().as_ref().is_some_and(|s| s.hub(hub.as_str()).is_some());
                let dialing = AtomicBool::new(true);
                let res = std::thread::scope(|s| {
                    s.spawn(|| {
                        while dialing.load(Ordering::SeqCst) {
                            if has_hub() {
                                node.disconnect(&hub);
                                return;
                            }
                            std::thread::sleep(Duration::from_millis(200));
                        }
                    });
                    let res = node.dial(link.local(), Some(hub.clone()));
                    dialing.store(false, Ordering::SeqCst);
                    res
                });
                if has_hub() {
                    let _ = std::fs::remove_file(&path);
                    (self.log)(&format!(
                        "cbb: the hub {hub} took this device's key; the invitation's guest tunnel is closed"
                    ));
                } else if let Err(e) = res {
                    let e = if link.answered() {
                        e
                    } else {
                        e.context("the hub does not answer through the invitation's guest tunnel; it tries again, and if the hub was restarted since the join, ask its admin to remove this device and invite it again")
                    };
                    (self.log)(&format!(
                        "cbb: offering this device's key to the hub {hub} through the invitation's guest tunnel: {}",
                        e.for_log()
                    ));
                }
            }
            Err(e) => self.fail(&e),
        }
        std::thread::sleep(Duration::from_secs(1));
        true
    }
}
