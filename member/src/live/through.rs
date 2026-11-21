// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! A remote invitation of 0.6 made through a hub, the admin's side
//! (docs/protocol.md, section 12, "Through the hub"): the admin keeps the
//! window and its keys; the hub lets the guest in and passes the bytes of
//! each of its pairing connections in `guest` messages (t 17). Each such
//! connection becomes a loopback connection here, whose far end the window
//! takes as it takes one on the hub.

use std::collections::HashMap;
use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::{Arc, mpsc};
use std::time::Duration;

use cbb_core::join::guest::{Guest, MAX_DATA, Op};
use cbb_core::join::invitation::{Path, PathKind};
use cbb_core::records::DeviceId;

use super::Live;
use super::invite::{Opened, Pair};
use crate::discovery::Peers as _;
use crate::error::{Context as _, Error, Result};

/// How long the admin waits for the hub to let the guest in.
const OPEN_WAIT: Duration = Duration::from_secs(10);

/// Why a hub refused because it serves as none: the admin tries the next.
const NOT_A_HUB: &str = "this device is none";

/// An invitation this admin makes through a hub.
pub(super) struct Through {
    hub: DeviceId,
    /// Where the hub's answer to `open` goes, until it came.
    opened: Option<mpsc::SyncSender<std::result::Result<Vec<u8>, String>>>,
    /// Where the guest's pairing connections go: the invitation's window.
    pairs: mpsc::SyncSender<Pair>,
    /// The loopback ends of the guest's connections, by the hub's number.
    conns: HashMap<u32, TcpStream>,
}

/// The invitations this admin makes through hubs, by their guests' keys.
pub(super) type Throughs = std::sync::Mutex<HashMap<[u8; 32], Through>>;

impl Live {
    /// Opens an invitation's guest through hub, named, or the first hub of
    /// the group's order connected now that takes it: the guest's one-time
    /// key and pre-shared key, until expires_ms, for the invitation
    /// invite. Gives the invitation's guest path and the guest's pairing
    /// connections, and the hub it went through.
    pub fn open_through(
        self: &Arc<Self>,
        hub: Option<DeviceId>,
        (key, public, psk): ([u8; 32], [u8; 32], [u8; 32]),
        expires_ms: u64,
        invite: [u8; 16],
    ) -> Result<(Opened, DeviceId)> {
        let me = self.mesh.device();
        let connected = self.mesh.connected();
        let hubs: Vec<DeviceId> = match hub {
            Some(h) => vec![h],
            None => self.mesh.hub_order().into_iter().filter(|h| *h != me && connected.contains(h)).collect(),
        };
        // A refusal other than "not a hub" says more than that no hub took it.
        let mut other = None;
        for h in hubs {
            match self.open_at(h, key, public, psk, expires_ms, invite) {
                Ok(o) => return Ok((o, h)),
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

    #[allow(clippy::too_many_arguments)]
    fn open_at(
        &self,
        hub: DeviceId,
        key: [u8; 32],
        public: [u8; 32],
        psk: [u8; 32],
        expires_ms: u64,
        invite: [u8; 16],
    ) -> Result<Opened> {
        let (answer, answered) = mpsc::sync_channel(1);
        let (pairs, rx) = mpsc::sync_channel(1);
        {
            let mut t = self.through.lock().unwrap();
            if t.contains_key(&public) {
                return Err(Error::msg("that guest key is in use"));
            }
            t.insert(public, Through { hub, opened: Some(answer), pairs, conns: HashMap::new() });
        }
        let forget = || {
            self.through.lock().unwrap().remove(&public);
        };
        if !self.send_guest(&hub, &Guest { key: public, op: Op::Open { psk, expires_ms, invite } }) {
            forget();
            return Err(Error::msg(format!("the hub {} is not connected", super::id_text4(&hub))));
        }
        let offer = match answered.recv_timeout(OPEN_WAIT) {
            Ok(Ok(o)) => o,
            Ok(Err(why)) => {
                forget();
                return Err(Error::msg(format!("the hub {} refused: {why}", super::id_text4(&hub))));
            }
            Err(_) => {
                forget();
                return Err(Error::msg(format!("the hub {} did not answer", super::id_text4(&hub))));
            }
        };
        match path_of(&offer, key, psk) {
            Ok(path) => Ok(Opened { path, pairs: rx }),
            Err(e) => {
                self.through_ended(&public, None);
                Err(e.context(format!("the hub {}'s answer", super::id_text4(&hub))))
            }
        }
    }

    /// The invitation through a hub of the guest with the public key ended:
    /// the hub hears of the device admitted, for its first member
    /// connection, or that it ended without one.
    pub fn through_ended(&self, public: &[u8; 32], admitted: Option<DeviceId>) {
        let Some(t) = self.through.lock().unwrap().remove(public) else { return };
        for c in t.conns.values() {
            let _ = c.shutdown(Shutdown::Both);
        }
        let op = match admitted {
            Some(d) => Op::Admitted { device: d.0 },
            None => Op::Close,
        };
        self.send_guest(&t.hub, &Guest { key: *public, op });
    }

    /// A `guest` message from peer about an invitation this admin makes
    /// through it: the hub's answer to `open`, or bytes of a pairing
    /// connection. Whether it was about one.
    pub(super) fn through_from(self: &Arc<Self>, peer: &DeviceId, g: &Guest) -> bool {
        let mut through = self.through.lock().unwrap();
        let Some(t) = through.get_mut(&g.key).filter(|t| t.hub == *peer) else { return false };
        match &g.op {
            Op::Opened { offer } => {
                if let Some(a) = t.opened.take() {
                    let _ = a.try_send(Ok(offer.clone()));
                }
            }
            Op::Refused { reason } => {
                if let Some(a) = t.opened.take() {
                    let _ = a.try_send(Err(reason.clone()));
                }
            }
            Op::Data { conn, data } => {
                if !t.conns.contains_key(conn) {
                    match self.take_conn(g.key, *conn, t.hub, t.pairs.clone()) {
                        Ok(c) => {
                            t.conns.insert(*conn, c);
                        }
                        Err(e) => {
                            self.logf(&format!("cbb: a pairing through the hub: {}", e.for_log()));
                            return true;
                        }
                    }
                }
                if let Some(mut c) = t.conns.get(conn).and_then(|c| c.try_clone().ok())
                    && std::io::Write::write_all(&mut c, data).is_err()
                {
                    let _ = c.shutdown(Shutdown::Write);
                }
            }
            Op::End { conn } => {
                if let Some(c) = t.conns.get(conn) {
                    let _ = c.shutdown(Shutdown::Write);
                }
            }
            _ => {}
        }
        true
    }

    /// A new pairing connection the hub passes: a loopback connection whose
    /// one end takes the hub's bytes and sends back what comes out, and
    /// whose other end the window takes once its handshake is over. Gives
    /// the first end.
    fn take_conn(
        self: &Arc<Self>,
        key: [u8; 32],
        conn: u32,
        hub: DeviceId,
        pairs: mpsc::SyncSender<Pair>,
    ) -> Result<TcpStream> {
        let ln = TcpListener::bind("127.0.0.1:0").context("cannot open a local port")?;
        let near = TcpStream::connect(ln.local_addr().context("cannot open a local port")?)
            .context("cannot open a local connection")?;
        let (far, _) = ln.accept().context("cannot open a local connection")?;
        // What the window answers goes back to the hub.
        let (w, back) = (Arc::downgrade(self), near.try_clone().context("cannot use a local connection")?);
        std::thread::spawn(move || {
            let mut buf = vec![0u8; MAX_DATA];
            loop {
                let n = match std::io::Read::read(&mut &back, &mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => n,
                };
                let Some(l) = w.upgrade() else { return };
                let data = buf.get(..n).unwrap_or_default().to_vec();
                if !l.send_guest(&hub, &Guest { key, op: Op::Data { conn, data } }) {
                    break;
                }
            }
            if let Some(l) = w.upgrade() {
                l.send_guest(&hub, &Guest { key, op: Op::End { conn } });
                if let Some(t) = l.through.lock().unwrap().get_mut(&key) {
                    t.conns.remove(&conn);
                }
            }
        });
        // The window's side: its handshake, then the window takes it; one
        // attempt at a time.
        let w = Arc::downgrade(self);
        std::thread::spawn(move || {
            let Some(l) = w.upgrade() else { return };
            match l.mesh.pair_handshake(far) {
                Ok(p) => {
                    if let Err(mpsc::TrySendError::Full(p) | mpsc::TrySendError::Disconnected(p)) = pairs.try_send(p) {
                        let _ = p.0.shutdown(Shutdown::Both);
                    }
                }
                Err(e) => l.logf(&format!("cbb: a pairing through the hub: {}", e.for_log())),
            }
        });
        Ok(near)
    }
}

/// The guest path of an invitation from the hub's offer: its key, its
/// addresses and the group's obfuscation settings, with the guest's keys.
fn path_of(offer: &[u8], key: [u8; 32], psk: [u8; 32]) -> Result<Path> {
    use cbb_core::format::cbor::Value;
    let v = cbb_core::format::cbor::decode(offer).map_err(|_| Error::msg("the offer does not decode"))?;
    let v = cbb_core::msg::read_map(&cbb_core::msg::tables::OFFER, &v)
        .map_err(|r| Error::msg(format!("the offer breaks {r}")))?;
    let k = cbb_core::format::Key::from_value(v.get(1).ok_or_else(|| Error::msg("the offer has no key"))?)
        .map_err(|_| Error::msg("the offer's key is damaged"))?;
    let hub_key: [u8; 32] = k.public.try_into().map_err(|_| Error::msg("the offer's key is not 32 bytes"))?;
    let endpoints: Vec<String> = match v.get(2) {
        Some(Value::Array(a)) => a.iter().filter_map(|e| e.as_text().map(str::to_string)).collect(),
        _ => Vec::new(),
    };
    if endpoints.is_empty() {
        return Err(Error::msg("the hub has no address away from home"));
    }
    let obfuscation = match v.get(3) {
        Some(o) => Some(
            cbb_core::msg::Obfuscation::read(o, "invite/obfuscation")
                .map_err(|r| Error::msg(format!("the offer's obfuscation settings break {r}")))?,
        ),
        None => None,
    };
    Ok(Path { kind: PathKind::Guest, endpoints, hub_key: Some(hub_key), guest: Some((key, psk)), obfuscation })
}
