// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! A group without a hub meets at a blind relay (docs/design.md, "Blind
//! relay"), as Go's joinRelayLocked: the service keeps the device
//! registered there with the link the phones use (src/relay.rs), and joins
//! the other devices of the group that it does not reach another way. The
//! member protocol's TLS runs between the two devices; the relay passes
//! only its ciphertext. A call the relay brings comes to a loopback port of
//! its own, where the node serves it only when the member certificate names
//! the device the relay said calls.

use std::collections::VecDeque;
use std::net::{SocketAddr, TcpListener};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::Value;

use super::Away;
use crate::certs::DeviceId;
use crate::control::{self, Header};
use crate::error::{Context, Error, Result};
use crate::identity::ExternalKey;
use crate::node::{Admit, Node};
use crate::relay::{self, Relay, Report};
use crate::tunnel::{Forwarder, State};

/// What stands for the project's relay in cbb global relay, and its
/// address, as Go's relay.Project and relay.ProjectHost.
pub(super) const PROJECT_KEY: &str = "default";
const PROJECT_HOST: &str = "cbb.tools:8765";
/// The pins of the project's relay's key this release knows; keys.json may
/// name others, which take their place (docs/protocol.md, section 16).
const PROJECT_PINS: &[&str] = &["hnHvkm6ZrTMmfPEP4Bo0s38nlnNKeyXEdhQNKYt2Pzw="];

/// How long a call waits for the relay to say whose it is, and the most
/// calls kept.
const CALLER_WAIT: Duration = Duration::from_secs(5);
const MAX_CALLS: usize = 16;

/// The link to the relay while the device meets the group there.
pub(super) struct Meeting {
    /// The relay as the state names it: a change starts the link again.
    at: Forwarder,
    /// Dropped first: the link stops before its listener.
    _relay: Relay,
    report: Arc<Mutex<Report>>,
    records: Arc<Mutex<Vec<Value>>>,
    /// What it registers with in place of the member certificate once the
    /// group's credentials list this device, and the credentials' changes
    /// it was made at.
    credentials: Arc<Mutex<Option<Arc<relay::Credentialed>>>>,
    credentials_at: u64,
    _listener: Listener,
}

/// The loopback port the relay's calls come to.
struct Listener {
    addr: SocketAddr,
    stop: Arc<AtomicBool>,
}

impl Drop for Listener {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        // Wakes the accept loop.
        let _ = std::net::TcpStream::connect_timeout(&self.addr, Duration::from_secs(1));
    }
}

/// The service's side of the link.
struct Events {
    node: Arc<Node>,
    /// The calls the relay announced: the loopback port each comes from
    /// and the device it said calls.
    calls: Arc<Mutex<VecDeque<(u16, String)>>>,
    report: Arc<Mutex<Report>>,
    endpoint: SocketAddr,
    log: Arc<dyn Fn(&str) + Send + Sync>,
}

impl relay::Events for Events {
    fn wanted(&self, peer: &str) -> bool {
        DeviceId::parse(peer).is_ok_and(|id| !self.node.connected(&id) && !self.node.at_home(&id))
    }

    fn dial(&self, peer: &str, port: u16) {
        let Ok(id) = DeviceId::parse(peer) else { return };
        let (node, log) = (self.node.clone(), self.log.clone());
        std::thread::spawn(move || {
            if let Err(e) = node.dial(SocketAddr::from(([127, 0, 0, 1], port)), Some(id.clone()))
                && !node.is_closed()
            {
                log(&format!("cbb: sync away from home: a connection through the relay to {id}: {}", e.for_log()));
            }
        });
    }

    fn calling(&self, peer: &str, port: u16) {
        let mut calls = self.calls.lock().unwrap();
        calls.retain(|(p, _)| *p != port);
        calls.push_back((port, peer.to_string()));
        while calls.len() > MAX_CALLS {
            calls.pop_front();
        }
    }

    fn changed(&self, r: &Report) {
        let mut cur = self.report.lock().unwrap();
        match &r.error {
            Some(e) if cur.error.as_ref() != Some(e) => {
                (self.log)(&format!("cbb: sync away from home: the relay at {}: {e}", self.endpoint));
            }
            None if r.connected && !cur.connected => {
                (self.log)(&format!("cbb: sync away from home: connected to the relay at {}", self.endpoint));
            }
            _ => {}
        }
        *cur = r.clone();
    }

    fn log(&self, line: &str) {
        (self.log)(line);
    }
}

/// The check of the relay's port: the call is served only when its
/// certificate names the device the relay said calls from that port.
fn caller_check(calls: Arc<Mutex<VecDeque<(u16, String)>>>) -> Admit {
    Arc::new(move |port: u16, id: &DeviceId| {
        // The relay names the caller right after it connects, which can be
        // after the handshake on a busy machine.
        let until = Instant::now() + CALLER_WAIT;
        loop {
            {
                let mut c = calls.lock().unwrap();
                if let Some(i) = c.iter().position(|(p, _)| *p == port) {
                    let (_, said) = c.remove(i).unwrap_or_default();
                    return said == id.as_str();
                }
            }
            if Instant::now() >= until {
                return false;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    })
}

impl Away {
    /// Serves cbb global relay: the device meets the group at the relay
    /// the request gives, its address and its key's pin or `default` for
    /// the project's, which turns sync away from home on and takes the
    /// place of the group's hubs, once the user agreed to what the relay
    /// learns, as Go's away relay. Returns the keys the hellos offer.
    pub fn meet_at(&self, node: &Node, h: &Header) -> Result<(Vec<u8>, Vec<u8>)> {
        let endpoint = match h.relay.parse::<SocketAddr>() {
            Ok(ep) if ep.port() != 0 => super::serve::unmapped(ep),
            _ => {
                return Err(Error::msg(format!(
                    "{:?} is not the relay's address with a port, such as 203.0.113.9:8764",
                    h.relay
                )));
            }
        };
        let project = h.relay_key == PROJECT_KEY;
        let pin = if project {
            project_pins(node).swap_remove(0)
        } else {
            pin_of(&h.relay_key)?;
            h.relay_key.clone()
        };
        if !h.consent {
            return Err(Error::msg(
                "a relay learns which devices of the group talk, when and how much, and their addresses; run cbb global relay and read what it says",
            ));
        }
        let mut cur = self.st.lock().unwrap();
        let base = match cur.as_ref() {
            Some(st) => st.clone(),
            None => State::new(&self.group)?,
        };
        let r = Forwarder { endpoint, pin, vless_id: String::new(), vless: None, project };
        let mut next = base.meeting_at(r);
        next.keys_in_file = true;
        next.save(&self.dir)?;
        self.stop_serving();
        let keys = (next.public_key(), next.psk.clone());
        *cur = Some(next);
        *self.error.lock().unwrap() = None;
        drop(cur);
        // The next turn of the run loop starts the link at the new relay.
        self.meeting.lock().unwrap().take();
        (self.log)(&format!("cbb: sync away from home goes through the relay at {endpoint}"));
        Ok(keys)
    }

    /// Keeps the link to the relay the state names running, with the
    /// group's records as they are now, and stops it when the state names
    /// none; reports whether the device meets the group at a relay.
    pub(super) fn meet(&self, node: &Arc<Node>, st: Option<&State>) -> bool {
        let Some((st, at)) = st.and_then(|s| s.relay.clone().map(|r| (s, r))) else {
            self.meeting.lock().unwrap().take();
            return false;
        };
        let records = node_records(node);
        let creds = self.credentials.lock().unwrap().clone();
        let mut m = self.meeting.lock().unwrap();
        if let Some(cur) = m.as_mut().filter(|cur| cur.at == at) {
            *cur.records.lock().unwrap() = records;
            // The group's credentials changed: it registers with them when
            // they list this device.
            if let Some(c) = creds.filter(|c| c.changes() != cur.credentials_at) {
                cur.credentials_at = c.changes();
                *cur.credentials.lock().unwrap() = c.relay(node).map(Arc::new);
            }
            return true;
        }
        m.take();
        match self.start_meeting(node, st, at, records) {
            Ok(started) => *m = Some(started),
            Err(e) => self.fail(&e),
        }
        true
    }

    fn start_meeting(&self, node: &Arc<Node>, st: &State, at: Forwarder, records: Vec<Value>) -> Result<Meeting> {
        let Shown { key, chain } = shown(node)?;
        let pins = if at.project { project_pins(node) } else { vec![at.pin.clone()] };
        let calls = Arc::new(Mutex::new(VecDeque::new()));
        let listener = self.listen(node, caller_check(calls.clone()))?;
        let report = Arc::new(Mutex::new(Report::default()));
        let records = Arc::new(Mutex::new(records));
        let creds = self.credentials.lock().unwrap().clone();
        let credentials_at = creds.as_ref().map_or(0, |c| c.changes());
        let credentials = Arc::new(Mutex::new(creds.and_then(|c| c.relay(node)).map(Arc::new)));
        let cfg = relay::Config {
            endpoint: at.endpoint,
            pins: pins.iter().map(|p| pin_of(p)).collect::<Result<_>>()?,
            chain,
            key,
            device: self.me.to_string(),
            wg_key: st.private_key(),
            records: records.clone(),
            member_port: listener.addr.port(),
            credentials: credentials.clone(),
        };
        let events = Arc::new(Events {
            node: node.clone(),
            calls,
            report: report.clone(),
            endpoint: at.endpoint,
            log: self.log.clone(),
        });
        let relay = Relay::start(cfg, events);
        Ok(Meeting { at, _relay: relay, report, records, credentials, credentials_at, _listener: listener })
    }

    /// Opens the loopback port the relay's calls come to.
    fn listen(&self, node: &Arc<Node>, admit: Admit) -> Result<Listener> {
        let ln = TcpListener::bind("127.0.0.1:0").context("cannot open the port for the relay's calls")?;
        let addr = ln.local_addr().context("cannot open the port for the relay's calls")?;
        let stop = Arc::new(AtomicBool::new(false));
        let (node, log, done) = (node.clone(), self.log.clone(), stop.clone());
        std::thread::spawn(move || {
            for sock in ln.incoming() {
                if done.load(Ordering::SeqCst) || node.is_closed() {
                    return;
                }
                let Ok(sock) = sock else { continue };
                let Ok(from) = sock.peer_addr() else { continue };
                let (node, log, admit) = (node.clone(), log.clone(), admit.clone());
                std::thread::spawn(move || {
                    if let Err(e) = node.accept_checked(sock, from, &mut || {}, Some(&admit))
                        && !node.is_closed()
                    {
                        log(&format!("cbb: sync away from home: a call through the relay: {}", e.for_log()));
                    }
                });
            }
        });
        Ok(Listener { addr, stop })
    }

    /// What cbb global shows of the link to the relay r, and whether a
    /// member connection goes through it now.
    pub(super) fn meeting_status(&self, r: &Forwarder) -> (control::Relay, bool) {
        let endpoint = r.endpoint.to_string();
        let m = self.meeting.lock().unwrap();
        let Some(m) = m.as_ref() else {
            let error = "the link to the relay is not running".to_string();
            return (control::Relay { endpoint, error, ..Default::default() }, false);
        };
        let rep = m.report.lock().unwrap().clone();
        let (error, detail) = match &rep.error {
            Some(e) => (problem(e, r.project), e.clone()),
            None => (String::new(), String::new()),
        };
        (control::Relay { endpoint, connected: rep.connected, online: rep.online, error, detail }, rep.through > 0)
    }
}

/// What the device shows a forwarder or a relay it registers with, as
/// Go's ForwarderCertificate: the key of its member certificate, and the
/// certificate with its issuer and the group's roots, which the group's
/// records show it a member, the root or an admin by.
pub(super) struct Shown {
    pub key: Arc<dyn ExternalKey>,
    pub chain: Vec<Vec<u8>>,
}

pub(super) fn shown(node: &Node) -> Result<Shown> {
    let ident = node.identity();
    let key: Arc<dyn ExternalKey> = match &ident.external {
        Some(k) => k.clone(),
        None => Arc::new(cbb_core::identity::FileKey::new(&ident.key)?),
    };
    let roots = node.records().lock().unwrap().roots();
    let mut chain = ident.chain();
    for c in std::iter::once(ident.group_ca.clone()).chain(roots) {
        if !chain.contains(&c.der) {
            chain.push(c.der);
        }
    }
    Ok(Shown { key, chain })
}

/// The group's records as a forwarder or a relay takes them.
pub(super) fn node_records(node: &Node) -> Vec<Value> {
    let rs = node.records();
    let rs = rs.lock().unwrap();
    rs.all().iter().filter_map(|r| serde_json::to_value(r).ok()).collect()
}

/// The pins this device accepts from the project's relay: those of the
/// keys the newest keys.json it holds names for it, else the built-in ones,
/// as Go's projectRelayPins.
fn project_pins(node: &Node) -> Vec<String> {
    let listed = node.entries().relay_keys(PROJECT_HOST, crate::uptime::wall_ms());
    if listed.is_empty() {
        return PROJECT_PINS.iter().map(ToString::to_string).collect();
    }
    use base64::Engine as _;
    listed.iter().map(|spki| base64::engine::general_purpose::STANDARD.encode(cbb_core::certs::sha256(spki))).collect()
}

/// A relay's pin, 32 bytes of base64, as Go's relay.CheckPin.
fn pin_of(pin: &str) -> Result<[u8; 32]> {
    use base64::Engine as _;
    let e = base64::engine::general_purpose::STANDARD;
    e.decode(pin).ok().filter(|b| e.encode(b) == pin).and_then(|b| <[u8; 32]>::try_from(b).ok()).ok_or_else(|| {
        Error::msg(format!("{pin:?} is not a relay's key; cbb relay prints it, 44 characters of base64"))
    })
}

/// A short message for status of why the device is not connected to its
/// relay, as Go's relayProblem; the whole error goes to the detail.
fn problem(msg: &str, project: bool) -> String {
    if msg.contains("refused the registration") {
        msg.to_string()
    } else if project && msg.contains("not the one given") {
        "the project's relay has a key this device does not know yet; a newer signed list brings it".to_string()
    } else if msg.contains("not the one given") {
        "the relay's key is not the one given with -key".to_string()
    } else if msg.starts_with("reaching the relay") {
        "the relay could not be reached".to_string()
    } else if msg.contains("tunnel does not answer") {
        "the relay's tunnel does not answer; its UDP port may be blocked".to_string()
    } else {
        "the connection to the relay failed".to_string()
    }
}
