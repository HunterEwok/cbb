// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! Remote invitations on the hub (docs/design.md, "Joining from another
//! network"), as Go's internal/service/invite.go: the hub makes a one-time
//! guest key that reaches only the pairing inside its tunnel, and a pairing
//! window on a 128-bit secret whose admin confirms the device before it is
//! admitted. The new device pairs through the guest tunnel, then offers its
//! own tunnel key through it as a member, and from then on reaches the hub
//! as an ordinary client.

use std::collections::HashMap;
use std::io::Write;
use std::net::{Ipv6Addr, TcpListener};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use cbb_core::admit::{self, Admitter};
use cbb_core::invite::Invitation;

use super::Away;
use crate::certs::DeviceId;
use crate::control::{self, Header, Joining};
use crate::error::{Context, Error, Result};
use crate::hub::{self, Hub};
use crate::node::{Node, OnPairing};
use crate::window::{self, Window};

/// How long an invitation waits for a hub's tunnel that is starting.
const TUNNEL_START: Duration = Duration::from_secs(10);
/// How long an invitation is valid unless the admin asks otherwise, and at
/// most, as Go's invite.DefaultLifetime and MaxLifetime.
const DEFAULT_LIFETIME: Duration = Duration::from_secs(3600);
const MAX_LIFETIME: Duration = Duration::from_secs(24 * 3600);
/// How long a guest tunnel stays at most after its device was admitted,
/// for the device's first member connection, in which it offers its own
/// tunnel key; once the hub answered that offer, the guest goes as soon as
/// that connection ends.
const GUEST_GRACE: Duration = Duration::from_secs(120);
/// How long a guest tunnel stays after its invitation ended without a
/// device, for the last answer to reach the device.
const FAIL_GRACE: Duration = Duration::from_secs(10);

/// The guest tunnel of an open invitation, on the hub.
pub(super) struct Guest {
    peer: hub::Peer,
    window: Arc<Window>,
    /// The device the window admitted, None until then.
    admitted: Option<DeviceId>,
    /// The hub answered the admitted device's tunnel key.
    offered: bool,
    /// The admitted device's member connection through the guest ended
    /// after the hub answered its key: the guest can go.
    done: bool,
}

/// The guests of the open invitations, by their tunnel addresses.
pub(super) type Guests = Arc<Mutex<HashMap<Ipv6Addr, Guest>>>;

impl Away {
    /// Makes a remote invitation on the hub for cbb invite and answers with
    /// its text, then asks the client to confirm each device that uses it,
    /// and answers how it ended. A client that hangs up cancels it.
    pub fn invite(
        self: &Arc<Self>,
        admitter: Admitter,
        expires: i64,
        mut r: control::Reader<crate::sys::UnixStream>,
        out: &mut crate::sys::UnixStream,
    ) -> Result<()> {
        let lifetime = if expires > 0 { Duration::from_secs(expires as u64) } else { DEFAULT_LIFETIME };
        if lifetime > MAX_LIFETIME {
            return Err(Error::msg("an invitation is valid for 24h0m0s at most"));
        }
        // Drawn as returned values rather than filled in place.
        let mut secret = Vec::with_capacity(cbb_core::invite::MIN_SECRET + 8);
        while secret.len() < cbb_core::invite::MIN_SECRET {
            let r = getrandom::u64().map_err(|_| Error::msg("cannot make a secret: the system has no randomness"))?;
            secret.extend_from_slice(&r.to_le_bytes());
        }
        secret.truncate(cbb_core::invite::MIN_SECRET);
        let guest_key = crate::tunnel::key32(&crate::tunnel::new_key()?)?;
        let guest_psk = crate::tunnel::key32(&crate::tunnel::new_key()?)?;
        let guest_public = crate::tunnel::key32(&crate::tunnel::public_of(&guest_key))?;

        // The client's answers, and its hang-up.
        let (answers, asked) = mpsc::sync_channel::<bool>(1);
        let hung = Arc::new(AtomicBool::new(false));
        let writer = Arc::new(Mutex::new(out.try_clone().context("the control connection broke")?));
        let window_cell: Arc<Mutex<Option<Arc<Window>>>> = Arc::new(Mutex::new(None));
        {
            let (hung, cell) = (hung.clone(), window_cell.clone());
            std::thread::spawn(move || {
                while let Ok(Some(m)) = r.read() {
                    if m.header.op == "answer" {
                        let _ = answers.try_send(m.header.consent);
                    }
                }
                hung.store(true, Ordering::SeqCst);
                if let Some(w) = cell.lock().unwrap().as_ref() {
                    w.close();
                }
            });
        }
        let confirm: window::Confirm = {
            let (writer, hung) = (writer.clone(), hung.clone());
            let asked = Mutex::new(asked);
            Box::new(move |req: &admit::Request| {
                let joining = Joining {
                    id: req.device.as_str().to_string(),
                    name: req.name.clone(),
                    os: req.os.clone(),
                    fingerprint: req.fingerprint.clone(),
                };
                let m = control::partial(Header { joining: Some(joining), ..Default::default() });
                if control::write(&mut *writer.lock().unwrap(), &m).is_err() {
                    return false;
                }
                let asked = asked.lock().unwrap();
                // Drops an answer left from before.
                while asked.try_recv().is_ok() {}
                let until = Instant::now() + window::CONFIRM_WAIT;
                loop {
                    if hung.load(Ordering::SeqCst) || Instant::now() > until {
                        return false;
                    }
                    match asked.recv_timeout(Duration::from_millis(200)) {
                        Ok(yes) => return yes,
                        Err(mpsc::RecvTimeoutError::Timeout) => {}
                        Err(mpsc::RecvTimeoutError::Disconnected) => return false,
                    }
                }
            })
        };
        let w = Window::open_secret(admitter, &secret, lifetime, confirm)?;
        *window_cell.lock().unwrap() = Some(w.clone());
        if hung.load(Ordering::SeqCst) {
            w.close();
        }
        let addr = hub::guest_addr(&guest_public);
        let peer = hub::Peer { key: guest_public, psk: guest_psk, addr, until: None };
        let (hub_key, endpoints, obfuscation) = match self.open_guest(peer, w.clone()) {
            Ok(h) => h,
            Err(e) => {
                w.close();
                return Err(e);
            }
        };
        let now = crate::uptime::wall_ms() / 1000;
        let inv = Invitation {
            group: self.group.clone(),
            hub: self.me.as_str().to_string(),
            hub_key,
            endpoints,
            guest_key,
            guest_psk,
            secret,
            expires: now.saturating_add(lifetime.as_secs() as i64),
            obfuscation,
        };
        (self.log)(&format!("cbb: an invitation is open for {} minutes", lifetime.as_secs() / 60));
        let opened = control::partial(Header {
            invite: inv.to_text(),
            expires: lifetime.as_secs() as i64,
            ..Default::default()
        });
        let wrote = control::write(&mut *writer.lock().unwrap(), &opened);
        let end = if wrote.is_ok() {
            w.wait(&|| crate::service::stopping() || hung.load(Ordering::SeqCst))
        } else {
            Err(cbb_core::pair::Refusal::Closed)
        };
        w.close();
        let me = self.clone();
        match end {
            Ok(j) => {
                // The device makes its first member connection through the
                // guest tunnel, to offer its own key; then the guest goes.
                if let Some(g) = self.guests.lock().unwrap().get_mut(&addr) {
                    g.admitted = DeviceId::parse(&j.device).ok();
                }
                std::thread::spawn(move || {
                    let until = Instant::now() + GUEST_GRACE;
                    while Instant::now() < until && !me.guests.lock().unwrap().get(&addr).is_none_or(|g| g.done) {
                        std::thread::sleep(Duration::from_millis(200));
                    }
                    me.drop_guest(&addr);
                });
                let m = control::reply(Header { name: j.name, done: true, ..Default::default() }, Vec::new());
                control::write(&mut *writer.lock().unwrap(), &m)
            }
            Err(why) => {
                // The attempt that closed the window still sends the device
                // its answer through the guest tunnel: the guest goes a
                // little later, or the device waits minutes for nothing.
                std::thread::spawn(move || {
                    std::thread::sleep(FAIL_GRACE);
                    me.drop_guest(&addr);
                });
                let e = Error::with("the invitation ended", why);
                (self.log)(&format!("cbb: {}", e.for_log()));
                if hung.load(Ordering::SeqCst) {
                    return Ok(());
                }
                let mut wr = writer.lock().unwrap();
                control::write(&mut *wr, &control::failure(&e))?;
                let _ = wr.flush();
                Ok(())
            }
        }
    }

    /// Lets the guest of an invitation into the running hub, and returns
    /// what the invitation gives of the hub: its key, its addresses and the
    /// group's AmneziaWG settings.
    fn open_guest(
        &self,
        peer: hub::Peer,
        window: Arc<Window>,
    ) -> Result<([u8; 32], Vec<std::net::SocketAddr>, Option<cbb_core::invite::Obfuscation>)> {
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
        let addr = peer.addr;
        self.guests.lock().unwrap().insert(addr, Guest { peer, window, admitted: None, offered: false, done: false });
        self.set_peers(st);
        Ok((crate::tunnel::key32(&crate::tunnel::public_of(&st.serving_key()?))?, endpoints, obfuscation))
    }

    /// Forgets a guest tunnel: its packets are dropped from then on.
    fn drop_guest(&self, addr: &Ipv6Addr) {
        if self.guests.lock().unwrap().remove(addr).is_none() {
            return;
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
            let Some((w, admitted)) = guests.lock().unwrap().get(&from).map(|g| (g.window.clone(), g.admitted.clone()))
            else {
                continue;
            };
            let guests = guests.clone();
            std::thread::spawn(move || {
                let pairing: OnPairing = {
                    let node = Arc::downgrade(&node);
                    Arc::new(move |sock, session, exporter, addr| {
                        let node = node.upgrade().ok_or_else(|| Error::msg("the service is stopping"))?;
                        w.serve(&node, sock, session, exporter, addr)
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
/// How long after the join the guest tunnel is tried at most; the hub lets
/// the guest go two minutes after it admitted the device.
const GUEST_FILE_LIFE: Duration = Duration::from_secs(600);

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
    crate::pair::join_secret(joiner, sock, &inv.secret, &save_all).map_err(|e| {
        if link.answered() {
            e
        } else {
            e.context("the hub did not answer; check that the invitation is still valid, that the hub is on, and that its UDP port or its forwarder can be reached")
        }
    })
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
        vless: None,
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
