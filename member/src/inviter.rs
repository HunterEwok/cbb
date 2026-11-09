// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! Remote invitations that an admin that is not the group's hub makes
//! through the hub (docs/protocol.md, section 12, "Through the hub"): the
//! admin makes the guest key, the preshared key and the secret, asks the hub
//! for a guest tunnel with a guest message, and runs the invitation's
//! pairing window itself. The hub passes the bytes of each pairing
//! connection that comes through the guest tunnel to the admin over their
//! member connection, without reading them: the pairing's TLS runs between
//! the joiner and the admin's window, and the hub holds no key that admits.
//! Here each connection the hub passes on becomes a loopback connection to
//! this node, served as a guest's (Node::accept_guest), so the window runs
//! as it does on a hub.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{Ipv6Addr, Shutdown, TcpListener, TcpStream};
use std::sync::mpsc;
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;

use crate::certs::DeviceId;
use crate::error::{Error, Result};
use crate::node::{Node, OnPairing};
use crate::window::Window;
use crate::wire::{self, Guest};

/// How long the admin waits for the hub's answer to its open.
const OPEN_WAIT: Duration = Duration::from_secs(10);
/// What a hub that is not one answers an open with.
pub const NOT_A_HUB: &str = "this device is not a hub of the group";
/// The most invitations an admin keeps open through hubs at once, as a hub
/// carries for one admin.
pub const MAX_OPEN: usize = 4;

/// The invitations this admin keeps open through hubs, by guest key.
#[derive(Default)]
pub struct Inviter {
    open: Mutex<HashMap<Vec<u8>, Pending>>,
}

struct Pending {
    /// The hub that carries the guest tunnel.
    hub: DeviceId,
    /// The guest's address in the hub's tunnel.
    addr: Ipv6Addr,
    node: Weak<Node>,
    /// Waits for the hub's answer to the open.
    answer: Option<mpsc::SyncSender<Guest>>,
    /// The window, once the hub opened the guest tunnel.
    window: Option<Arc<Window>>,
    /// This end of each loopback connection, by the hub's connection
    /// number.
    conns: HashMap<i64, TcpStream>,
}

impl Inviter {
    /// Whether a guest message from a peer is for this admin's side: the
    /// hub's answer to an open, or the bytes of an invitation it keeps.
    pub fn handles(&self, g: &Guest) -> bool {
        match g.op.as_str() {
            "opened" | "refused" => true,
            "data" | "end" => self.open.lock().unwrap().contains_key(&g.key),
            _ => false,
        }
    }

    /// Asks the hub for a guest tunnel with the guest's public key and
    /// preshared key until expires_ms, and returns the hub's answer: its key,
    /// its addresses, its AmneziaWG settings and its way over VLESS.
    pub fn open(
        &self,
        node: &Arc<Node>,
        hub: &DeviceId,
        key: &[u8; 32],
        psk: &[u8; 32],
        expires_ms: i64,
    ) -> Result<Guest> {
        let (tx, rx) = mpsc::sync_channel(1);
        {
            let mut open = self.open.lock().unwrap();
            if open.len() >= MAX_OPEN {
                return Err(Error::msg(format!(
                    "{MAX_OPEN} invitations are open already; cancel one or wait until one ends"
                )));
            }
            open.insert(
                key.to_vec(),
                Pending {
                    hub: hub.clone(),
                    addr: crate::tunnel_guest_addr(key),
                    node: Arc::downgrade(node),
                    answer: Some(tx),
                    window: None,
                    conns: HashMap::new(),
                },
            );
        }
        let g =
            Guest { op: "open".into(), key: key.to_vec(), psk: Some(psk.to_vec()), expires_ms, ..Default::default() };
        if !node.send_to(hub, wire::guest(&g)) {
            self.forget(key);
            return Err(Error::msg(format!("the hub {hub} is not connected")));
        }
        let answer = rx.recv_timeout(OPEN_WAIT);
        match answer {
            Ok(g) if g.op == "opened" => Ok(g),
            Ok(g) => {
                self.forget(key);
                Err(Error::msg(format!("{hub} refused the invitation: {}", clean(&g.reason))))
            }
            Err(_) => {
                self.forget(key);
                Err(Error::msg(format!(
                    "the hub {hub} did not answer; it may be a phone or have an older version, which carry no invitations of other admins"
                )))
            }
        }
    }

    /// Lets the pairing connections of the invitation of key reach window.
    pub fn attach(&self, key: &[u8; 32], window: Arc<Window>) {
        if let Some(o) = self.open.lock().unwrap().get_mut(key.as_slice()) {
            o.window = Some(window);
        }
    }

    /// Ends the invitation of key: the hub hears which device the window
    /// admitted, whose first member connection it lets through the guest
    /// tunnel, or that the guest tunnel can go.
    pub fn end(&self, key: &[u8; 32], admitted: Option<&DeviceId>) {
        let Some(o) = self.forget(key) else { return };
        let Some(node) = o.node.upgrade() else { return };
        let g = match admitted {
            Some(d) => Guest { op: "admitted".into(), key: key.to_vec(), device: d.to_string(), ..Default::default() },
            None => Guest { op: "close".into(), key: key.to_vec(), ..Default::default() },
        };
        node.send_to(&o.hub, wire::guest(&g));
    }

    fn forget(&self, key: &[u8]) -> Option<Pending> {
        let o = self.open.lock().unwrap().remove(key)?;
        for c in o.conns.values() {
            let _ = c.shutdown(Shutdown::Both);
        }
        Some(o)
    }

    /// Takes a guest message from the peer from for this admin's side.
    pub fn take(&self, from: &DeviceId, g: Guest) {
        let mut open = self.open.lock().unwrap();
        let Some(o) = open.get_mut(&g.key).filter(|o| &o.hub == from) else { return };
        match g.op.as_str() {
            "opened" | "refused" => {
                if let Some(tx) = o.answer.take() {
                    let _ = tx.try_send(g);
                }
            }
            "data" => {
                let data = g.data.unwrap_or_default();
                if let Some(c) = o.conns.get_mut(&g.conn) {
                    if c.write_all(&data).is_err() {
                        let _ = c.shutdown(Shutdown::Both);
                        o.conns.remove(&g.conn);
                    }
                    return;
                }
                // A new connection: the window serves it as a guest's.
                let Some(window) = o.window.clone() else { return };
                let Some(node) = o.node.upgrade() else { return };
                match loopback(&node, &window, o.addr) {
                    Ok(mut c) => {
                        if c.write_all(&data).is_ok() {
                            if let Ok(r) = c.try_clone() {
                                pump(r, node, o.hub.clone(), g.key.clone(), g.conn);
                            }
                            o.conns.insert(g.conn, c);
                        }
                    }
                    Err(e) => node.logf(&format!("cbb: a pairing connection through the hub: {}", e.for_log())),
                }
            }
            "end" => {
                if let Some(c) = o.conns.remove(&g.conn) {
                    let _ = c.shutdown(Shutdown::Write);
                }
            }
            _ => {}
        }
    }
}

/// A loopback connection whose other end this node serves as a connection
/// through the guest tunnel from addr, for window: it returns this end.
fn loopback(node: &Arc<Node>, window: &Arc<Window>, addr: Ipv6Addr) -> Result<TcpStream> {
    let ln =
        TcpListener::bind(("127.0.0.1", 0)).map_err(|e| Error::with("cannot listen on the loopback address", e))?;
    let at = ln.local_addr().map_err(|e| Error::with("cannot listen on the loopback address", e))?;
    let near = TcpStream::connect(at).map_err(|e| Error::with("cannot connect on the loopback address", e))?;
    let (far, _) = ln.accept().map_err(|e| Error::with("cannot connect on the loopback address", e))?;
    let _ = near.set_nodelay(true);
    let (node, window) = (node.clone(), window.clone());
    std::thread::spawn(move || {
        let pairing: OnPairing = {
            let (n, w) = (Arc::downgrade(&node), window.clone());
            Arc::new(move |sock, session, exporter, at| {
                let node = n.upgrade().ok_or_else(|| Error::msg("the service is stopping"))?;
                w.serve(&node, sock, session, exporter, at)
            })
        };
        if let Err(e) = node.accept_guest(far, addr, pairing, None)
            && !node.is_closed()
        {
            node.logf(&format!("cbb: a pairing connection through the hub: {}", e.for_log()));
        }
    });
    Ok(near)
}

/// Passes what the window writes on the loopback connection r to the hub,
/// until it closes.
fn pump(mut r: TcpStream, node: Arc<Node>, hub: DeviceId, key: Vec<u8>, conn: i64) {
    std::thread::spawn(move || {
        let mut buf = vec![0u8; wire::MAX_GUEST_DATA];
        loop {
            let n = match r.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            let data = buf.get(..n).unwrap_or_default().to_vec();
            let g = Guest { op: "data".into(), key: key.clone(), conn, data: Some(data), ..Default::default() };
            if !node.send_to(&hub, wire::guest(&g)) {
                break;
            }
        }
        let g = Guest { op: "end".into(), key, conn, ..Default::default() };
        node.send_to(&hub, wire::guest(&g));
    });
}

/// A peer's text as the log and the user see it: control characters as
/// spaces, at most 256 bytes.
fn clean(s: &str) -> String {
    let mut out = String::new();
    for c in s.chars().map(|c| if c.is_control() { ' ' } else { c }) {
        if out.len() + c.len_utf8() > 256 {
            break;
        }
        out.push(c);
    }
    out
}

/// How long an invitation is valid unless the admin asks otherwise, and at
/// most, as Go's invite.DefaultLifetime and MaxLifetime.
pub const DEFAULT_LIFETIME: Duration = Duration::from_secs(3600);
pub const MAX_LIFETIME: Duration = Duration::from_secs(24 * 3600);

/// The keys of an invitation's guest: its WireGuard private key, which the
/// invitation carries, its public key, which the hub admits, and the
/// preshared key.
pub struct GuestKeys {
    pub key: [u8; 32],
    pub public: [u8; 32],
    pub psk: [u8; 32],
}

impl GuestKeys {
    /// New keys for a guest.
    pub fn new() -> Result<GuestKeys> {
        let key = random32()?;
        Ok(GuestKeys { key, public: cbb_core::invite::guest_public(&key), psk: random32()? })
    }
}

fn random32() -> Result<[u8; 32]> {
    let mut b = [0u8; 32];
    getrandom::fill(&mut b).map_err(|_| Error::msg("cannot make a key: the system has no randomness"))?;
    Ok(b)
}

/// A new pairing secret for an invitation, 128 bits.
pub fn new_secret() -> Result<Vec<u8>> {
    let mut b = vec![0u8; cbb_core::invite::MIN_SECRET];
    getrandom::fill(&mut b).map_err(|_| Error::msg("cannot make a secret: the system has no randomness"))?;
    Ok(b)
}

/// What opening an invitation's guest tunnel gives: the hub's side of the
/// invitation, and what to do once the window ended, with the device it
/// admitted or none.
pub struct Opened {
    pub hub: String,
    pub hub_key: [u8; 32],
    pub endpoints: Vec<std::net::SocketAddr>,
    pub obfuscation: Option<cbb_core::invite::Obfuscation>,
    pub vless: Option<cbb_core::invite::Vless>,
    pub ended: Ended,
}

/// What to do once an invitation's window ended, with the device it
/// admitted or none.
pub type Ended = Box<dyn FnOnce(Option<&DeviceId>) + Send>;

/// Opens a guest tunnel for the keys, whose pairing connections the window
/// serves, valid for the lifetime.
pub type Open<'a> = dyn Fn(&GuestKeys, &Arc<Window>, Duration) -> Result<Opened> + 'a;

/// An open invitation: its text, its pairing window and its guest tunnel.
pub struct Invite {
    /// The invitation's text, cbb://invite#...
    pub text: String,
    /// How long it is valid from now.
    pub lifetime: Duration,
    window: Arc<Window>,
    ended: Mutex<Option<Ended>>,
}

impl Invite {
    /// Makes an invitation for lifetime (DEFAULT_LIFETIME when zero, at
    /// most MAX_LIFETIME): its keys, secret and window, whose devices
    /// confirm is asked about, and its guest tunnel, which open opens (on
    /// this hub, or through a hub).
    pub fn start(
        admitter: cbb_core::admit::Admitter,
        group: &str,
        lifetime: Duration,
        confirm: crate::window::Confirm,
        open: &Open<'_>,
    ) -> Result<Invite> {
        let lifetime = if lifetime.is_zero() { DEFAULT_LIFETIME } else { lifetime };
        if lifetime > MAX_LIFETIME {
            return Err(Error::msg("an invitation is valid for 24h0m0s at most"));
        }
        let secret = new_secret()?;
        let keys = GuestKeys::new()?;
        let w = Window::open_secret(admitter, &secret, lifetime, confirm)?;
        let opened = match open(&keys, &w, lifetime) {
            Ok(o) => o,
            Err(e) => {
                w.close();
                return Err(e);
            }
        };
        let now = crate::uptime::wall_ms() / 1000;
        let inv = cbb_core::invite::Invitation {
            group: group.to_string(),
            hub: opened.hub.clone(),
            hub_key: opened.hub_key,
            endpoints: opened.endpoints.clone(),
            guest_key: keys.key,
            guest_psk: keys.psk,
            secret,
            expires: now.saturating_add(lifetime.as_secs() as i64),
            obfuscation: opened.obfuscation.clone(),
            vless: opened.vless.clone(),
        };
        Ok(Invite { text: inv.to_text(), lifetime, window: w, ended: Mutex::new(Some(opened.ended)) })
    }

    /// Waits until the invitation admitted a device or ended, and closes
    /// its guest tunnel then; stop is asked every second, and ends it when
    /// true.
    pub fn wait(&self, stop: &dyn Fn() -> bool) -> std::result::Result<crate::window::Joined, cbb_core::pair::Refusal> {
        let end = self.window.wait(stop);
        self.window.close();
        if let Some(ended) = self.ended.lock().unwrap().take() {
            let admitted = end.as_ref().ok().and_then(|j| DeviceId::parse(&j.device).ok());
            ended(admitted.as_ref());
        }
        end
    }

    /// Ends the invitation: wait returns.
    pub fn close(&self) {
        self.window.close();
    }
}

impl Drop for Invite {
    fn drop(&mut self) {
        self.window.close();
        if let Some(ended) = self.ended.get_mut().unwrap().take() {
            ended(None);
        }
    }
}

/// Runs the control operation invite (cbb invite): makes the invitation
/// with open, answers with its text, asks the client to confirm each
/// device that uses it, and answers how it ended. A client that hangs up
/// cancels it.
pub fn run_invite(
    admitter: cbb_core::admit::Admitter,
    group: &str,
    expires: i64,
    mut r: crate::control::Reader<crate::sys::UnixStream>,
    out: &mut crate::sys::UnixStream,
    log: &(dyn Fn(&str) + Send + Sync),
    open: &Open<'_>,
) -> Result<()> {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Instant;

    use crate::control::{self, Header, Joining};
    use crate::error::Context;

    // The client's answers, and its hang-up.
    let (answers, asked) = mpsc::sync_channel::<bool>(1);
    let hung = Arc::new(AtomicBool::new(false));
    let writer = Arc::new(Mutex::new(out.try_clone().context("the control connection broke")?));
    let cell: Arc<Mutex<Option<Arc<Invite>>>> = Arc::new(Mutex::new(None));
    {
        let (hung, cell) = (hung.clone(), cell.clone());
        std::thread::spawn(move || {
            while let Ok(Some(m)) = r.read() {
                if m.header.op == "answer" {
                    let _ = answers.try_send(m.header.consent);
                }
            }
            hung.store(true, Ordering::SeqCst);
            if let Some(i) = cell.lock().unwrap().as_ref() {
                i.close();
            }
        });
    }
    let confirm: crate::window::Confirm = {
        let (writer, hung) = (writer.clone(), hung.clone());
        let asked = Mutex::new(asked);
        Box::new(move |req: &cbb_core::admit::Request| {
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
            let until = Instant::now() + crate::window::CONFIRM_WAIT;
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
    let lifetime = Duration::from_secs(expires.max(0) as u64);
    let inv = Arc::new(Invite::start(admitter, group, lifetime, confirm, open)?);
    *cell.lock().unwrap() = Some(inv.clone());
    if hung.load(Ordering::SeqCst) {
        inv.close();
    }
    log(&format!("cbb: an invitation is open for {} minutes", inv.lifetime.as_secs() / 60));
    let text = control::partial(Header {
        invite: inv.text.clone(),
        expires: inv.lifetime.as_secs() as i64,
        ..Default::default()
    });
    let wrote = control::write(&mut *writer.lock().unwrap(), &text);
    let end = if wrote.is_ok() {
        inv.wait(&|| crate::service::stopping() || hung.load(Ordering::SeqCst))
    } else {
        inv.close();
        inv.wait(&|| true)
    };
    match end {
        Ok(j) => {
            let m = control::reply(Header { name: j.name, done: true, ..Default::default() }, Vec::new());
            control::write(&mut *writer.lock().unwrap(), &m)
        }
        Err(why) => {
            let e = Error::with("the invitation ended", why);
            log(&format!("cbb: {}", e.for_log()));
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

/// Opens an invitation's guest tunnel through the hub, for an admin that is
/// not the hub: what run_invite's open does there.
pub fn open_through(
    node: &Arc<Node>,
    hub: &DeviceId,
    keys: &GuestKeys,
    w: &Arc<Window>,
    lifetime: Duration,
) -> Result<Opened> {
    let expires_ms = crate::uptime::wall_ms().saturating_add(lifetime.as_millis() as i64);
    let g = node.inviter.open(node, hub, &keys.public, &keys.psk, expires_ms)?;
    node.inviter.attach(&keys.public, w.clone());
    let refuse = |why: &str| {
        node.inviter.end(&keys.public, None);
        Error::msg(format!("the hub {hub}'s answer {why}"))
    };
    let hub_key: [u8; 32] =
        g.hub_key.as_deref().and_then(|k| k.try_into().ok()).ok_or_else(|| refuse("lacks its key"))?;
    let endpoints = g
        .endpoints
        .iter()
        .take(cbb_core::invite::MAX_ENDPOINTS)
        .map(|e| cbb_core::invite::parse_endpoint(e))
        .collect::<Option<Vec<_>>>()
        .filter(|e| !e.is_empty())
        .ok_or_else(|| refuse("has an address that is not ip:port"))?;
    let obfuscation = match &g.obfuscation {
        Some(v) => {
            Some(cbb_core::invite::obfuscation_from_json(v).ok_or_else(|| refuse("has damaged obfuscation settings"))?)
        }
        None => None,
    };
    let vless = g.vless.as_ref().and_then(cbb_core::invite::vless_from_offer);
    let (n, key) = (Arc::downgrade(node), keys.public);
    Ok(Opened {
        hub: hub.to_string(),
        hub_key,
        endpoints,
        obfuscation,
        vless,
        ended: Box::new(move |admitted| {
            if let Some(node) = n.upgrade() {
                node.inviter.end(&key, admitted);
            }
        }),
    })
}

/// Opens an invitation's guest tunnel where it goes: on this device when
/// it is a hub and no other hub is asked for, else through hub, or through
/// the first connected hub of the group that takes it.
pub fn open_where(
    node: &Arc<Node>,
    away: &Arc<crate::away::Away>,
    hub: Option<&DeviceId>,
    keys: &GuestKeys,
    w: &Arc<Window>,
    lifetime: Duration,
) -> Result<Opened> {
    let me = node.identity().id.clone();
    if away.is_hub() && hub.is_none_or(|h| *h == me) {
        return away.open_own(keys, w);
    }
    let hubs = match hub {
        Some(h) if *h == me => return Err(Error::msg(NOT_A_HUB)),
        Some(h) => vec![h.clone()],
        None => hubs_to_try(node),
    };
    open_through_any(node, &hubs, keys, w, lifetime)
}

/// The hubs to make an invitation through, in the order to try them: the
/// group's hubs in their order that are connected now and are members, not
/// phones. One that is not a hub after all refuses, and the next is tried.
pub fn hubs_to_try(node: &Node) -> Vec<DeviceId> {
    let me = node.identity().id.clone();
    let peers = node.peers();
    node.hub_order()
        .iter()
        .filter_map(|h| DeviceId::parse(h).ok())
        .filter(|h| *h != me)
        .filter(|h| peers.iter().any(|p| &p.id == h && p.role == cbb_core::authority::ROLE_MEMBER))
        .collect()
}

/// Opens an invitation's guest tunnel through the first of hubs that takes
/// it.
pub fn open_through_any(
    node: &Arc<Node>,
    hubs: &[DeviceId],
    keys: &GuestKeys,
    w: &Arc<Window>,
    lifetime: Duration,
) -> Result<Opened> {
    // A refusal other than "not a hub" says more than that no hub took it.
    let mut other = None;
    for hub in hubs {
        match open_through(node, hub, keys, w, lifetime) {
            Ok(o) => return Ok(o),
            Err(e) if e.message().contains(NOT_A_HUB) => {}
            Err(e) => other = Some(e),
        }
    }
    Err(other.unwrap_or_else(|| {
        Error::msg(
            "no hub of the group is connected: invitations come through the group's hub, so make a computer the hub (cbb global hub) and connect to it",
        )
    }))
}
