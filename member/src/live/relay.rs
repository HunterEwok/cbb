// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! Meeting the group at a blind relay on the records of 0.6 (docs/design.md,
//! "Blind relay"; docs/protocol.md, section 14): once the group's root chose
//! a relay (the `settings` record's relays, D-121) and sync away from home
//! is on here, the device registers there under the period's server
//! credentials of that relay's face (`cbb-relay/3`, `crate::relay`), and the
//! relay joins it to the devices of the group it does not reach another
//! way, at home or through a hub. The member protocol's TLS runs between
//! the two devices; the relay passes only its ciphertext. A call the relay
//! brings comes to a loopback port of its own, where it is served only when
//! its certificate names the device the relay said calls.

use std::collections::VecDeque;
use std::net::{SocketAddr, TcpListener, ToSocketAddrs as _};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant};

use cbb_core::records::body::SERVER_RELAY;

use super::Live;
use crate::discovery::Peers as _;
use crate::relay::{self, Credentialed, Relay, Report};

/// How often the meeting looks at the group's relays and credentials.
const LOOK: Duration = Duration::from_secs(1);
/// How long a relay may fail before the next of the group's relays is
/// tried.
#[cfg(not(test))]
const NEXT_AFTER: Duration = Duration::from_secs(60);
#[cfg(test)]
const NEXT_AFTER: Duration = Duration::from_secs(3);
const MAX_CALLS: usize = 16;

/// A relay of the group's settings: its address as given (a name or an
/// address with a port) and the pins of its keys. The project's relay is
/// where the newest entry points held put it, with the keys the newest
/// keys.json names (else its own name and the keys built in), so that a
/// move or a new key there needs no new settings.
#[derive(Clone, PartialEq, Eq, Debug)]
struct At {
    endpoint: String,
    pins: Vec<[u8; 32]>,
    project: bool,
}

/// The link to the relay while the device meets the group there.
pub(super) struct Meeting {
    at: At,
    addr: SocketAddr,
    /// Dropped first: the link stops before its listener.
    _relay: Relay,
    report: Arc<Mutex<Report>>,
    credentials: Arc<Mutex<Option<Arc<Credentialed>>>>,
    /// What the credentials it holds were made of: the period's tag and
    /// when they expire, and the pseudonyms it knows.
    shown: Option<([u8; 16], u64, usize)>,
    failing_since: Option<Instant>,
    /// The project's relay's last error that fetched the signed lists
    /// again, and when.
    tried: Option<(String, Instant)>,
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

/// The member's side of the link.
struct Events {
    live: Weak<Live>,
    calls: Arc<Mutex<VecDeque<(u16, String)>>>,
    report: Arc<Mutex<Report>>,
    endpoint: String,
}

impl relay::Events for Events {
    fn wanted(&self, peer: &str) -> bool {
        let (Some(l), Some(id)) = (self.live.upgrade(), super::id_of_hex(peer)) else { return false };
        !l.mesh.connected().contains(&id) && !l.at_home(&id)
    }

    fn dial(&self, peer: &str, port: u16) {
        let (Some(l), Some(id)) = (self.live.upgrade(), super::id_of_hex(peer)) else { return };
        std::thread::spawn(move || {
            if let Err(e) = l.mesh.dial(SocketAddr::from(([127, 0, 0, 1], port)), Some(id))
                && !l.is_closed()
            {
                l.logf(&format!(
                    "cbb: sync away from home: a connection through the relay to {}: {}",
                    super::id_text(&id),
                    e.for_log()
                ));
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
        let Some(l) = self.live.upgrade() else { return };
        let mut cur = self.report.lock().unwrap();
        match &r.error {
            Some(e) if cur.error.as_ref() != Some(e) => {
                l.logf(&format!("cbb: sync away from home: the relay at {}: {e}", self.endpoint));
            }
            None if r.connected && !cur.connected => {
                l.logf(&format!("cbb: sync away from home: connected to the relay at {}", self.endpoint));
            }
            _ => {}
        }
        *cur = r.clone();
    }

    fn log(&self, line: &str) {
        if let Some(l) = self.live.upgrade() {
            l.logf(line);
        }
    }
}

impl Live {
    /// The relays the group's settings name, in their order; the
    /// project's at each address its entry points give.
    fn relays(&self) -> Vec<At> {
        let mut out = Vec::new();
        for s in self.mesh.state().settings.servers.iter().filter(|s| s.kind == SERVER_RELAY) {
            if s.endpoint != crate::faces::PROJECT_RELAY {
                out.push(At { endpoint: s.endpoint.clone(), pins: vec![s.pin], project: false });
                continue;
            }
            let now = crate::uptime::wall_ms();
            let entries = self.mesh.entries();
            let pins: Vec<[u8; 32]> = crate::faces::project_servers(entries.as_deref(), now)
                .into_iter()
                .filter(|p| p.address == crate::faces::PROJECT_RELAY)
                .map(|p| p.pin)
                .collect();
            let mut endpoints =
                entries.map(|e| e.relay_endpoints(crate::faces::PROJECT_RELAY, now)).unwrap_or_default();
            if endpoints.is_empty() {
                endpoints.push(crate::faces::PROJECT_RELAY.to_string());
            }
            out.extend(endpoints.into_iter().map(|endpoint| At { endpoint, pins: pins.clone(), project: true }));
        }
        out
    }

    /// What cbb global shows of the link to the group's relay, while the
    /// device meets the group at one.
    pub(crate) fn relay_status(&self) -> Option<crate::control::Relay> {
        let m = self.meeting.lock().unwrap();
        let m = m.as_ref()?;
        let rep = m.report.lock().unwrap().clone();
        let project = m.at.project;
        let (error, detail) = match &rep.error {
            Some(e) => (crate::away::meet::problem(e, project), e.clone()),
            None => (String::new(), String::new()),
        };
        Some(crate::control::Relay {
            endpoint: m.addr.to_string(),
            connected: rep.connected,
            online: rep.online,
            error,
            detail,
        })
    }

    /// Starts the link to the relay at, with its own loopback port for the
    /// relay's calls.
    fn start_meeting(self: &Arc<Self>, at: At) -> crate::error::Result<Meeting> {
        use crate::error::Context as _;
        let addr = crate::away::meet::test_resolve(&at.endpoint)
            .unwrap_or_else(|| at.endpoint.to_socket_addrs().ok().and_then(|mut a| a.next()))
            .ok_or_else(|| crate::error::Error::msg(format!("the relay {} could not be looked up", at.endpoint)))?;
        let calls = Arc::new(Mutex::new(VecDeque::new()));
        let ln = TcpListener::bind("127.0.0.1:0").context("cannot open the port for the relay's calls")?;
        let port = ln.local_addr().context("cannot open the port for the relay's calls")?;
        let stop = Arc::new(AtomicBool::new(false));
        {
            let (w, done, admit) = (Arc::downgrade(self), stop.clone(), crate::away::meet::caller_check(calls.clone()));
            std::thread::spawn(move || {
                for sock in ln.incoming() {
                    let Some(l) = w.upgrade() else { return };
                    if done.load(Ordering::SeqCst) || l.is_closed() {
                        return;
                    }
                    let Ok(sock) = sock else { continue };
                    let Ok(from) = sock.peer_addr() else { continue };
                    let admit = admit.clone();
                    std::thread::spawn(move || {
                        if let Err(e) = l.accept_checked(sock, from, &mut || {}, Some(&admit))
                            && !l.is_closed()
                        {
                            l.logf(&format!("cbb: sync away from home: a call through the relay: {}", e.for_log()));
                        }
                    });
                }
            });
        }
        let report = Arc::new(Mutex::new(Report::default()));
        let credentials = Arc::new(Mutex::new(None));
        let cfg = relay::Config {
            endpoint: addr,
            pins: at.pins.clone(),
            member_port: port.port(),
            credentials: credentials.clone(),
        };
        let events = Arc::new(Events {
            live: Arc::downgrade(self),
            calls,
            report: report.clone(),
            endpoint: at.endpoint.clone(),
        });
        let relay = Relay::start(cfg, events);
        Ok(Meeting {
            at,
            addr,
            _relay: relay,
            report,
            credentials,
            shown: None,
            failing_since: None,
            tried: None,
            _listener: Listener { addr: port, stop },
        })
    }

    /// Gives the link what it registers with: the period's server key and
    /// credentials of the relay's face, once they list this device.
    fn give_credentials(&self, m: &mut Meeting) {
        let st = self.mesh.state();
        let now = crate::uptime::wall_ms().max(0) as u64;
        let member = self.mesh.own().member.public();
        let Some((_, shown)) = self.mesh.relay_credentials(&st, &member, &m.at.pins, now) else {
            if m.shown.take().is_some() {
                *m.credentials.lock().unwrap() = None;
            }
            return;
        };
        let made = (shown.tag, shown.expires_ms, shown.names.len());
        if m.shown == Some(made) {
            return;
        }
        match Credentialed::new(Arc::new(shown.key), shown.credentials, shown.period, shown.root, shown.names, now) {
            Ok(c) => {
                *m.credentials.lock().unwrap() = Some(Arc::new(c));
                m.shown = Some(made);
            }
            Err(e) => self.logf(&format!("cbb: sync away from home: the relay's credentials: {}", e.for_log())),
        }
    }
}

/// How soon the same error of the project's relay may fetch the signed
/// lists again (`away::meet::refetch_every` bounds every fetch).
const TRY_AGAIN: Duration = Duration::from_secs(60);

/// What fetches the project's signed lists again after its relay failed:
/// when it last did, and whether a fetch runs.
#[derive(Default)]
struct Refetch {
    last: Option<Instant>,
    running: Arc<AtomicBool>,
}

impl Live {
    /// After the link to the project's relay failed with an error not tried
    /// lately, as the old member's project_relay_failed: fetches the newest
    /// signed lists from the mirror on the relay's server, at most every
    /// refetch_every and in the background; newer ones give the relay's
    /// keys and addresses, and the link follows (`relays`).
    fn project_relay_failed(self: &Arc<Self>, m: &mut Meeting, r: &mut Refetch) {
        let Some(e) = m.report.lock().unwrap().error.clone() else { return };
        if m.tried.as_ref().is_some_and(|(t, when)| *t == e && when.elapsed() < TRY_AGAIN) {
            return;
        }
        m.tried = Some((e, Instant::now()));
        if r.last.is_some_and(|t| t.elapsed() < crate::away::meet::refetch_every())
            || r.running.swap(true, Ordering::SeqCst)
        {
            return;
        }
        r.last = Some(Instant::now());
        let (l, ip, running) = (self.clone(), m.addr.ip(), r.running.clone());
        std::thread::spawn(move || {
            match crate::update::fetch_lists_at(ip, l.mesh.dir()).and_then(|set| l.mesh.put_entries(&set)) {
                Ok(true) => l.logf("cbb: sync away from home: took newer signed lists from the relay's server"),
                Ok(false) => {}
                Err(e) => l.logf(&format!(
                    "cbb: sync away from home: fetching the signed lists for the relay: {}",
                    e.for_log()
                )),
            }
            running.store(false, Ordering::SeqCst);
        });
    }
}

/// Keeps the device registered at the group's relay while sync away from
/// home is on and the root chose one; the next of the group's relays when
/// one keeps failing; until the member closes.
pub(super) fn meet(w: &Weak<Live>) {
    let mut next = 0usize;
    let mut refetch = Refetch::default();
    loop {
        let Some(l) = w.upgrade() else { return };
        if l.is_closed() {
            l.meeting.lock().unwrap().take();
            return;
        }
        let on = l.away.get().is_some_and(|a| a.is_on());
        let relays = if on { l.relays() } else { Vec::new() };
        if relays.is_empty() {
            // Stopped out of the lock: the link's thread may take a while
            // to end, and status reads the meeting meanwhile.
            let old = l.meeting.lock().unwrap().take();
            drop(old);
        } else {
            let mut m = l.meeting.lock().unwrap();
            // The relay it meets at stays while the settings name it.
            let keep = m.as_ref().and_then(|cur| relays.iter().position(|r| *r == cur.at));
            if let Some(i) = keep {
                next = i;
            }
            let failed_long =
                m.as_ref().is_some_and(|cur| cur.failing_since.is_some_and(|t| t.elapsed() >= NEXT_AFTER));
            if keep.is_none() || (failed_long && relays.len() > 1) {
                if keep.is_some() {
                    next = (next + 1) % relays.len();
                }
                let at = relays[next % relays.len()].clone();
                let old = m.take();
                drop(m);
                drop(old);
                let started = l.start_meeting(at.clone());
                m = l.meeting.lock().unwrap();
                match started {
                    Ok(started) => {
                        l.logf(&format!("cbb: sync away from home: meeting the group at the relay {}", at.endpoint));
                        *m = Some(started);
                    }
                    Err(e) => l.logf(&format!("cbb: sync away from home: {}", e.for_log())),
                }
            }
            if let Some(cur) = m.as_mut() {
                l.give_credentials(cur);
                let failing = cur.report.lock().unwrap().error.is_some();
                if failing && cur.at.project {
                    l.project_relay_failed(cur, &mut refetch);
                }
                match (failing, cur.failing_since) {
                    (true, None) => cur.failing_since = Some(Instant::now()),
                    (false, Some(_)) => cur.failing_since = None,
                    _ => {}
                }
            }
        }
        drop(l);
        std::thread::sleep(LOOK);
    }
}
