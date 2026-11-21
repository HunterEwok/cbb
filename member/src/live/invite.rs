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
use crate::hub;
use crate::tls;

/// A pairing connection of a guest, its handshake over.
pub type Pair = (TcpStream, tls::Session, PairExporter);

/// How long an invitation waits for the hub's tunnel that is starting.
const TUNNEL_START: Duration = Duration::from_secs(10);
/// The most invitations of its own the hub keeps open at once.
pub const MAX_OPEN: usize = crate::inviter::MAX_OPEN;
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
pub(super) struct Guest {
    peer: hub::Peer,
    /// Where the guest's pairing connections go: the invitation's window.
    pairs: mpsc::SyncSender<Pair>,
    /// The device the admin admitted, None until then.
    admitted: Option<DeviceId>,
    /// The hub answered the admitted device's `tunnel`.
    offered: bool,
    /// The admitted device's member connection through the guest ended
    /// after the hub answered it: the guest can go.
    done: bool,
}

/// The guests of the open invitations, by their tunnel addresses.
pub(super) type Guests = std::sync::Mutex<HashMap<Ipv6Addr, Guest>>;

/// What an invitation's guest path gives of the hub, and the pairing
/// connections of its guest.
pub struct Opened {
    pub path: Path,
    pub pairs: mpsc::Receiver<Pair>,
}

impl Live {
    /// Lets the guest of an invitation this hub makes into its tunnel: its
    /// one-time key and pre-shared key. Gives the invitation's guest path
    /// and the guest's pairing connections. Refused while this device does
    /// not serve as a hub.
    pub fn open_guest(self: &Arc<Self>, key: [u8; 32], public: [u8; 32], psk: [u8; 32]) -> Result<Opened> {
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
        let (hub_key, endpoints, obfuscation) = away.guest_way()?;
        let addr = hub::guest_addr(&public);
        let (tx, rx) = mpsc::sync_channel(1);
        {
            let mut guests = self.guests.lock().unwrap();
            if guests.len() >= MAX_OPEN {
                return Err(Error::msg(format!("{MAX_OPEN} invitations are open already")));
            }
            if guests.contains_key(&addr) {
                return Err(Error::msg("that guest key is in use"));
            }
            let peer = hub::Peer { key: public, psk, older_psks: Vec::new(), addr, until: None, source: None };
            guests.insert(addr, Guest { peer, pairs: tx, admitted: None, offered: false, done: false });
        }
        self.give_hub_peers();
        let path =
            Path { kind: PathKind::Guest, endpoints, hub_key: Some(hub_key), guest: Some((key, psk)), obfuscation };
        Ok(Opened { path, pairs: rx })
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
        if self.guests.lock().unwrap().remove(addr).is_some() {
            self.give_hub_peers();
        }
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
        let Some((pairs, admitted)) = self.guests.lock().unwrap().get(&from).map(|g| (g.pairs.clone(), g.admitted))
        else {
            let _ = sock.shutdown(Shutdown::Both);
            return;
        };
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
            None => match self.mesh.pair_handshake(sock) {
                // One attempt at a time: another waits for none.
                Ok(p) => {
                    if let Err(mpsc::TrySendError::Full(p) | mpsc::TrySendError::Disconnected(p)) = pairs.try_send(p) {
                        let _ = p.0.shutdown(Shutdown::Both);
                    }
                }
                Err(e) => self.logf(&format!("cbb: a pairing through a guest tunnel: {}", e.for_log())),
            },
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

/// Joins the group of a remote invitation of 0.6 (cbb pair -invite): through
/// the invitation's guest tunnel to the hub, with its secret; the hub's
/// admin confirms the device before it is admitted, so each step may wait
/// that long. Sync away from home goes on, and the invitation is kept for
/// the service to reach the hub through its guest tunnel, before the set,
/// which the service takes.
pub fn join(
    dir: &std::path::Path,
    me: &crate::joining::Me<'_>,
    text: &str,
    log: Arc<dyn Fn(&str) + Send + Sync>,
) -> Result<Box<cbb_core::join::session::Admitted>> {
    let inv = Invitation::parse(text.trim()).map_err(|r| Error::msg(format!("this is not an invitation: {r}")))?;
    let link = guest_link(&inv, log)?;
    let sock = TcpStream::connect_timeout(&link.local(), Duration::from_secs(10))
        .context("cannot reach the tunnel's local port")?;
    let text = text.trim().to_string();
    let before = |a: &cbb_core::join::session::Admitted| -> Result<()> {
        crate::tunnel::State::new(&super::tag(&a.state))?.save(dir)?;
        crate::files::write_atomic(&dir.join(GUEST_FILE), text.as_bytes(), 0o600)
    };
    let step = crate::window::CONFIRM_WAIT + Duration::from_secs(60);
    let kept = sock.try_clone().context("cannot use the tunnel's connection")?;
    let joined = crate::joining::over_with(dir, sock, "the hub", me, inv, None, step, &before).map_err(|e| {
        if link.answered() {
            e
        } else {
            e.context("the hub did not answer; check that the invitation is still valid, that the hub is on, and that its UDP port or its forwarder can be reached")
        }
    })?;
    // The last message must reach the hub before the tunnel stops: the hub
    // ends the connection once it has it.
    let _ = kept.set_read_timeout(Some(Duration::from_secs(5)));
    let _ = std::io::Read::read(&mut &kept, &mut [0u8; 64]);
    Ok(joined)
}
