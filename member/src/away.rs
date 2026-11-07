// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! Sync away from home on the lite member (docs/protocol.md, section 11):
//! off until the user turns it on (cbb global on), then the hellos offer the
//! device's tunnel key and its own preshared key, it keeps the offers of the
//! group's hubs, and whenever no hub is found at home or connected it dials,
//! through the tunnel, the first hub in the group's order that answers
//! ("Several hubs"). It fails closed: without the tunnel, it syncs at home
//! only, and cbb global says why.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::certs::DeviceId;
use crate::control;
use crate::error::{Error, Result};
use crate::node::Node;
use crate::tunnel::{self, Link, State};
use crate::uptime;
use crate::wire::TunnelOffer;

mod hubs;
mod movehub;
mod serve;

pub use movehub::is_stop;

const MAX_WAIT: Duration = Duration::from_secs(30);
/// The longest wait between tries of a hub that is a phone, there only
/// while its app is open (docs/design.md, "The phone as the hub"): a try
/// costs one handshake initiation, which the forwarder drops while the
/// phone is not registered.
const PHONE_HUB_WAIT: Duration = Duration::from_secs(5);
const STEADY: Duration = Duration::from_secs(30);
/// How long the member stays on a hub that is not the first in the order
/// before it tries the ones above again.
const UP_CHECK: Duration = Duration::from_secs(300);
/// How long discovery is given to find the hub at home after the service
/// starts, before the tunnel is tried.
const FIRST_WAIT: Duration = Duration::from_secs(5);

/// Sync away from home on this device.
pub struct Away {
    dir: PathBuf,
    group: String,
    me: DeviceId,
    st: Mutex<Option<State>>,
    /// What went wrong last, for the user, and the details behind it.
    error: Mutex<Option<(String, String)>>,
    /// A connection to the hub through the tunnel is being made or is up.
    through: AtomicBool,
    /// The hub this member dials through the tunnel now, and how many
    /// links it started, so a timer ends only its own.
    using: Mutex<Option<(String, u64)>>,
    /// Where the tunnel sends its packets instead of the hubs' addresses.
    via: Option<SocketAddr>,
    /// The hub, while this device serves as one.
    serving: Mutex<Option<serve::Serving>>,
    /// Why the hub, while it serves, is to try the hubs above it.
    standby: Mutex<Option<String>>,
    /// The hub passes a hub above's offer on before it gives way.
    giving_way: AtomicBool,
    log: Arc<dyn Fn(&str) + Send + Sync>,
}

impl Away {
    /// Reads the tunnel state; a state of another group is dropped, so the
    /// user turns sync away from home on again for this one.
    pub fn new(dir: PathBuf, group: String, me: DeviceId, log: Arc<dyn Fn(&str) + Send + Sync>) -> Away {
        let mut error = None;
        let st = match State::load(&dir) {
            Ok(Some(st)) if st.group == group => Some(st),
            Ok(Some(_)) => {
                if let Err(e) = State::remove(&dir) {
                    log(&format!("cbb: {}", e.for_log()));
                }
                None
            }
            Ok(None) => None,
            Err(e) => {
                // Fails closed: off, and cbb global says why.
                log(&format!("cbb: sync away from home is off: {}", e.for_log()));
                error = Some((e.message().to_string(), e.details()));
                None
            }
        };
        Away {
            dir,
            group,
            me,
            st: Mutex::new(st),
            error: Mutex::new(error),
            through: AtomicBool::new(false),
            using: Mutex::new(None),
            via: None,
            serving: Mutex::new(None),
            standby: Mutex::new(None),
            giving_way: AtomicBool::new(false),
            log,
        }
    }

    /// Sends the tunnel's packets to via, a local UDP port that leads to
    /// the hub, instead of the hubs' own addresses.
    pub fn via(mut self, via: Option<SocketAddr>) -> Away {
        self.via = via;
        self
    }

    /// Whether this device is one of the group's hubs.
    pub fn is_hub(&self) -> bool {
        self.st.lock().unwrap().as_ref().is_some_and(|s| s.is_hub)
    }

    /// The tunnel key and preshared key the hellos offer; None while sync
    /// away from home is off.
    pub fn key(&self) -> Option<(Vec<u8>, Vec<u8>)> {
        self.st.lock().unwrap().as_ref().map(|s| (s.public_key(), s.psk.clone()))
    }

    /// Turns sync away from home on, with new keys if it was off, and
    /// returns them.
    pub fn turn_on(&self) -> Result<(Vec<u8>, Vec<u8>)> {
        let mut st = self.st.lock().unwrap();
        if st.is_none() {
            let mut next = State::new(&self.group)?;
            next.save(&self.dir)?;
            *st = Some(next);
            (self.log)("cbb: sync away from home is on");
        }
        *self.error.lock().unwrap() = None;
        let st = st.as_ref().unwrap();
        Ok((st.public_key(), st.psk.clone()))
    }

    /// Turns sync away from home off and forgets its keys.
    pub fn turn_off(&self) -> Result<()> {
        let mut st = self.st.lock().unwrap();
        State::remove(&self.dir)?;
        self.stop_serving();
        if st.take().is_some() {
            (self.log)("cbb: sync away from home is off");
        }
        *self.error.lock().unwrap() = None;
        Ok(())
    }

    /// Keeps an offer the group's root or an admin sent, if sync away from
    /// home is on: the sender's own, or that of another of the group's hubs
    /// the sender passes on, one per hub. One passed on when the sender
    /// moved the hub elsewhere (`moved`) makes it forget the sender's own.
    /// An offer naming a device `may_host` does not take, and one that does
    /// not decode, are ignored. Returns the hub the offer is for, when it
    /// changed what is kept, so the caller tries it if it is above the hub
    /// in use.
    pub fn offered(&self, from: &DeviceId, v: &serde_json::Value, may_host: &dyn Fn(&str) -> bool) -> Option<DeviceId> {
        let mut st = self.st.lock().unwrap();
        let cur = st.as_mut()?;
        let offer = match serde_json::from_value::<TunnelOffer>(v.clone()) {
            Ok(o) => o,
            Err(e) => {
                let e = Error::with("the hub's offer does not decode", e);
                (self.log)(&format!("cbb: ignored a tunnel offer from {from}: {}", e.for_log()));
                *self.error.lock().unwrap() = Some((e.message().to_string(), e.details()));
                return None;
            }
        };
        let hub_id = match &offer.hub {
            None => from.clone(),
            Some(h) => match DeviceId::parse(h) {
                Ok(id) if id == self.me => return None,
                Ok(id) if may_host(id.as_str()) => id,
                _ => {
                    (self.log)(&format!(
                        "cbb: ignored the tunnel offer from {from}: it names {h} as a hub, which is not the group's root or an admin"
                    ));
                    return None;
                }
            },
        };
        let hub = match tunnel::hub_from_offer(&hub_id, &offer) {
            Ok(h) => h,
            Err(e) => {
                (self.log)(&format!("cbb: ignored a tunnel offer from {from}: {}", e.for_log()));
                *self.error.lock().unwrap() = Some((e.message().to_string(), e.details()));
                return None;
            }
        };
        let mut next = cur.clone();
        let forgot = offer.moved && next.hubs.iter().any(|h| h.device == from.as_str());
        if forgot {
            next.hubs.retain(|h| h.device != from.as_str());
        }
        let known = next.hub(hub_id.as_str()).is_some();
        if next.hub(hub_id.as_str()) == Some(&hub) && !forgot {
            return None;
        }
        next.hubs.retain(|h| h.device != hub_id.as_str());
        next.hubs.push(hub);
        if let Err(e) = next.save(&self.dir) {
            (self.log)(&format!("cbb: {}", e.for_log()));
            return None;
        }
        if forgot {
            (self.log)(&format!("cbb: {from} is no hub any more; the group's hub is {hub_id}"));
        } else if !known {
            (self.log)(&format!("cbb: {hub_id} is one of the group's hubs for sync away from home"));
        }
        *cur = next;
        Some(hub_id)
    }

    /// Ends the link through the tunnel when the hub `hub`, whose offer
    /// changed, is above the hub in use or is that hub, so the member tries
    /// again from the first hub.
    pub fn retry(&self, node: &Node, hub: &DeviceId) {
        let Some((using, _)) = self.using.lock().unwrap().clone() else { return };
        let order = node.hub_order();
        let rank = |d: &str| order.iter().position(|o| o == d).unwrap_or(order.len());
        if rank(hub.as_str()) <= rank(&using)
            && let Ok(id) = DeviceId::parse(&using)
        {
            node.disconnect(&id);
        }
    }

    /// What cbb global and cbb status show; None while it is off.
    pub fn status(&self, node: &Node) -> Option<control::Away> {
        let st = self.st.lock().unwrap();
        let error = self.error.lock().unwrap().clone();
        let Some(st) = st.as_ref() else {
            // Off, unless the state could not be read.
            return error.map(|(e, d)| control::Away { error: e, detail: d, ..Default::default() });
        };
        let mut a = control::Away { keys_in_file: true, ..Default::default() };
        let using = self.using.lock().unwrap().clone().map(|(d, _)| d);
        let hubs = st.hubs_above(&node.hub_order(), self.me.as_str());
        // A hub waiting as the client of a hub above shows that hub.
        let standby = st.is_hub && self.serving.lock().unwrap().is_none();
        if st.is_hub {
            self.hub_status(st, &mut a, standby);
        }
        if let Some(h) = using
            .as_deref()
            .and_then(|d| st.hub(d))
            .or(hubs.first())
            .filter(|_| !st.is_hub || standby || using.is_some())
        {
            a.hub_device = h.device.clone();
            a.endpoints = h.endpoints.iter().map(ToString::to_string).collect();
            a.through = self.through.load(Ordering::SeqCst)
                && using.as_deref() == Some(h.device.as_str())
                && DeviceId::parse(&h.device).is_ok_and(|id| node.connected(&id));
        }
        if let Some((e, d)) = error {
            a.error = e;
            a.detail = d;
        }
        Some(a)
    }

    fn fail(&self, e: &Error) {
        let mut cur = self.error.lock().unwrap();
        if cur.as_ref().is_none_or(|(m, _)| m != e.message()) {
            (self.log)(&format!("cbb: away from home: {}", e.for_log()));
        }
        *cur = Some((e.message().to_string(), e.details()));
    }

    /// Dials, through the tunnel, the first hub in the group's order that
    /// answers, whenever no hub is found at home or connected, until the
    /// service stops; on a hub below the first it tries the ones above
    /// again after UP_CHECK. A hub serves while no hub above it answers
    /// (Go's reachHubs with standby): starting, it tries them once; once it
    /// loses the hub above, it tries them for a minute (standby_grace); while it
    /// serves, it tries them again every HUB_RECHECK and when a hub above
    /// says it serves.
    pub fn run(self: Arc<Self>, node: Arc<Node>) {
        std::thread::sleep(FIRST_WAIT);
        let mut wait = Duration::from_secs(1);
        let mut links = 0u64;
        let grace_over = || Instant::now().checked_sub(hubs::standby_grace());
        // When this hub last had a hub above it.
        let mut lost = grace_over();
        while !node.is_closed() {
            let st = self.st.lock().unwrap().clone();
            let hubs = st.as_ref().map(|s| s.hubs_above(&node.hub_order(), self.me.as_str())).unwrap_or_default();
            match &st {
                Some(s) if s.is_hub => {
                    let since = self.serving.lock().unwrap().as_ref().map(|v| v.since);
                    let why = self.standby.lock().unwrap().take();
                    if let Some(since) = since {
                        let why = why.or_else(|| {
                            (since.elapsed() >= hubs::HUB_RECHECK)
                                .then(|| "it is time to look for the hubs above this one".to_string())
                        });
                        match why {
                            Some(why) if !hubs.is_empty() => {
                                (self.log)(&format!("cbb: {why}; this hub tries the hubs above it"));
                                self.stop_serving();
                                self.share(&node, None);
                                lost = grace_over();
                            }
                            _ => {
                                self.vless_learned(&node);
                                std::thread::sleep(Duration::from_secs(1));
                                continue;
                            }
                        }
                    } else if hubs.is_empty() {
                        self.serve(&node, s);
                        std::thread::sleep(Duration::from_secs(1));
                        continue;
                    }
                }
                _ => self.stop_serving(),
            }
            // A phone's app in the background makes no connection.
            if node.is_paused() {
                std::thread::sleep(Duration::from_secs(1));
                continue;
            }
            let (Some(st), false) = (st, hubs.is_empty()) else {
                std::thread::sleep(Duration::from_secs(1));
                continue;
            };
            let ids: Vec<DeviceId> = hubs.iter().filter_map(|h| DeviceId::parse(&h.device).ok()).collect();
            if ids.iter().any(|id| node.connected(id) || node.at_home(id)) {
                // At home the tunnel is not used, so it sends nothing; a hub
                // waits as the client of the hub above.
                wait = Duration::from_secs(1);
                lost = Some(Instant::now());
                std::thread::sleep(Duration::from_secs(1));
                continue;
            }
            let mut reached = false;
            for (hub, id) in hubs.iter().zip(&ids) {
                let mut hub = hub.clone();
                if let Some(v) = self.via {
                    hub.endpoints = vec![v];
                }
                let link = match Link::start(&st, &hub, &self.me, self.log.clone()) {
                    Ok(l) => l,
                    Err(e) => {
                        self.fail(&e);
                        continue;
                    }
                };
                links += 1;
                *self.using.lock().unwrap() = Some((hub.device.clone(), links));
                if hub.device != hubs[0].device {
                    // A hub below the first: the ones above are tried again
                    // after a while.
                    let (away, node, id, n) = (self.clone(), node.clone(), id.clone(), links);
                    std::thread::spawn(move || {
                        std::thread::sleep(UP_CHECK);
                        if away.using.lock().unwrap().as_ref().is_some_and(|(_, m)| *m == n) {
                            node.disconnect(&id);
                        }
                    });
                }
                let start = uptime::now();
                self.through.store(true, Ordering::SeqCst);
                let res = node.dial(link.local(), Some(id.clone()));
                self.through.store(false, Ordering::SeqCst);
                *self.using.lock().unwrap() = None;
                match res {
                    Ok(()) => *self.error.lock().unwrap() = None,
                    Err(e) if !link.answered() => self.fail(&e.context(format!(
                        "the hub {id} does not answer through the tunnel: it may be off, its UDP port closed, or the network on the way down"
                    ))),
                    Err(e) => self.fail(&e),
                }
                if uptime::now().saturating_sub(start) > STEADY {
                    wait = Duration::from_secs(1);
                }
                if link.answered() {
                    reached = true;
                    break;
                }
            }
            if reached {
                lost = Some(Instant::now());
                continue;
            }
            if st.is_hub && lost.is_none_or(|l| l.elapsed() >= hubs::standby_grace()) {
                (self.log)("cbb: no hub above this one answers; this device serves as the group's hub");
                self.serve(&node, &st);
                continue;
            }
            std::thread::sleep(wait);
            wait = (wait * 2).min(hub_wait(&node.devices(), &hubs[0].device));
        }
    }
}

/// The longest wait between tries of the hub: short for a phone, which
/// comes and goes, and MAX_WAIT for any other.
fn hub_wait(devices: &[crate::records::Device], hub: &str) -> Duration {
    if devices.iter().any(|d| d.id == hub && d.role == "phone") { PHONE_HUB_WAIT } else { MAX_WAIT }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn device(id: &str, role: &str) -> crate::records::Device {
        crate::records::Device {
            id: id.into(),
            name: role.into(),
            role: role.into(),
            os: String::new(),
            key: Default::default(),
            store: "file".into(),
            admin: true,
            admin_key: None,
            frozen: false,
            keys: vec![],
            ..Default::default()
        }
    }

    #[test]
    fn a_phone_hub_is_tried_often() {
        let devices = [device("p", "phone"), device("c", "full")];
        assert_eq!(hub_wait(&devices, "p"), PHONE_HUB_WAIT);
        assert_eq!(hub_wait(&devices, "c"), MAX_WAIT);
        assert_eq!(hub_wait(&[], "p"), MAX_WAIT);
    }

    /// The offers kept, one per hub: the sender's own, one passed on for
    /// another hub, a moved one that drops the sender's, and none naming a
    /// device that is no admin.
    #[test]
    fn keeps_every_hubs_offer() {
        let dir = std::env::temp_dir().join(format!("cbb-away-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let id = |c: char| DeviceId::parse(&c.to_string().repeat(32)).unwrap();
        let (me, pi, mac, deck) = (id('d'), id('a'), id('b'), id('c'));
        let away = Away::new(dir.clone(), "g".into(), me.clone(), Arc::new(|_: &str| {}));
        away.turn_on().unwrap();
        let offer = |key: u8, hub: Option<&DeviceId>, moved: bool| {
            serde_json::to_value(TunnelOffer {
                hub_key: vec![key; 32],
                psk: vec![9; 32],
                endpoints: vec!["192.0.2.1:8764".into()],
                hub: hub.map(ToString::to_string),
                moved,
                ..Default::default()
            })
            .unwrap()
        };
        let admins = |d: &str| d != deck.as_str();
        assert_eq!(away.offered(&pi, &offer(1, None, false), &admins), Some(pi.clone()));
        assert_eq!(away.offered(&pi, &offer(1, None, false), &admins), None, "the same offer again");
        assert_eq!(away.offered(&pi, &offer(2, Some(&mac), false), &admins), Some(mac.clone()));
        assert_eq!(away.offered(&pi, &offer(3, Some(&deck), false), &admins), None, "a device that is no admin");
        assert_eq!(away.offered(&pi, &offer(3, Some(&me), false), &admins), None, "this device's own");
        let kept = |d: &DeviceId| away.st.lock().unwrap().as_ref().unwrap().hub(d.as_str()).cloned();
        assert_eq!(kept(&pi).unwrap().key, vec![1; 32]);
        assert_eq!(kept(&mac).unwrap().key, vec![2; 32]);
        assert_eq!(away.offered(&pi, &offer(4, Some(&mac), true), &admins), Some(mac.clone()));
        assert!(kept(&pi).is_none(), "a hub that moved is forgotten");
        assert_eq!(kept(&mac).unwrap().key, vec![4; 32]);
        let st = State::load(&dir).unwrap().unwrap();
        assert_eq!(st.hubs_to_try(&[pi.to_string(), mac.to_string()]).len(), 1);
        assert_eq!(st.psk.len(), 32);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
