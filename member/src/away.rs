// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! Sync away from home on cbb (docs/protocol.md, section 11):
//! off until the user turns it on (cbb global on), then the hellos offer the
//! device's tunnel key and its own preshared key, it keeps the offers of the
//! group's hubs, and whenever no hub is found at home or connected it dials,
//! through the tunnel, the first hub in the group's order that answers
//! ("Several hubs"). It fails closed: without the tunnel, it syncs at home
//! only, and cbb global says why.
//!
//! The state of sync away from home that the member of 0.6 drives
//! (`crate::live`, live/away.rs): the hubs' offers kept (held.rs, offer.rs),
//! the way toward a hub (toward.rs), a hub's own keys and registration
//! (serve.rs), and the relay's small parts (meet.rs).

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};

use crate::certs::DeviceId;
use crate::error::{Error, Result};
use crate::tunnel::{self, State};
use crate::wire::TunnelOffer;

mod held;
pub(crate) mod meet;
mod offer;
mod serve;
mod toward;

pub use held::{forwarder_named, offer_result};

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
    /// The hub and the key of the link up through the tunnel, while a
    /// member connection goes through it.
    link_up: Mutex<Option<(String, Vec<u8>)>>,
    /// Where the tunnel sends its packets instead of the hubs' addresses.
    via: Option<SocketAddr>,
    /// The hub is moving to another device: it offers itself to no member
    /// that connects meanwhile, which would keep it as a hub after the move.
    moving: AtomicBool,
    /// The hub of 0.6's registration with its forwarder, while it serves.
    hub_report: Mutex<Option<Arc<Mutex<crate::forward::Report>>>>,
    log: Arc<dyn Fn(&str) + Send + Sync>,
}

impl Away {
    /// Reads the tunnel state; a state of another group is dropped, so the
    /// user turns sync away from home on again for this one.
    pub fn new(dir: PathBuf, group: String, me: DeviceId, log: Arc<dyn Fn(&str) + Send + Sync>) -> Away {
        let mut error = None;
        let st = match State::load(&dir) {
            Ok(Some(st)) if st.group == group => Some(st),
            // A state made before this device joined, as one that turned
            // sync away from home on in no group, takes this group.
            Ok(Some(mut st)) if st.group.is_empty() => {
                st.group = group.clone();
                match st.save(&dir) {
                    Ok(()) => Some(st),
                    Err(e) => {
                        log(&format!("cbb: sync away from home is off: {}", e.for_log()));
                        None
                    }
                }
            }
            Ok(Some(_)) => {
                match State::remove(&dir) {
                    Ok(()) => log("cbb: sync away from home is off, since this device is in another group now"),
                    Err(e) => log(&format!("cbb: sync away from home is off: {}", e.for_log())),
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
            link_up: Mutex::new(None),
            via: None,
            moving: AtomicBool::new(false),
            hub_report: Mutex::new(None),
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
        // The link up is already through the hub's key in the new offer,
        // which reaches it the same way: it stays up, and the next try takes
        // the new offer, as Go's addHubOffer. Starting it again would try the
        // hubs above it first, which may be off, before this one again.
        let keeps_link = !forgot
            && next.hub(hub_id.as_str()).is_some_and(|p| same_way(p, &hub))
            && self.link_up.lock().unwrap().as_ref().is_some_and(|(d, k)| *d == hub_id.as_str() && *k == hub.key);
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
        if keeps_link { None } else { Some(hub_id) }
    }

    /// The way of [`Away::update_way`] in the group's order of hubs
    /// `order` (device IDs in hex): the member on the records of 0.6 gives
    /// its own order (`Live::update_way`).
    pub fn update_way_in(&self, order: &[String]) -> Option<serde_json::Value> {
        let cur = self.st.lock().unwrap();
        let st = cur.as_ref()?;
        if st.is_hub {
            let f = st.forwarder.as_ref().filter(|f| !f.vless_id.is_empty())?;
            let mut v = f.vless.clone()?;
            v.as_object_mut()?.insert("id".into(), f.vless_id.clone().into());
            return Some(v);
        }
        let using = self.using.lock().unwrap().as_ref().map(|(d, _)| d.clone());
        let hub = using.and_then(|d| st.hub(&d).cloned()).or_else(|| st.hubs_to_try(order).into_iter().next());
        hub?.vless
    }

    fn fail(&self, e: &Error) {
        let mut cur = self.error.lock().unwrap();
        if cur.as_ref().is_none_or(|(m, _)| m != e.message()) {
            (self.log)(&format!("cbb: away from home: {}", e.for_log()));
        }
        *cur = Some((e.message().to_string(), e.details()));
    }
}

/// Whether two offers of a hub reach it the same way, apart from its keys,
/// as Go's sameWay.
fn same_way(a: &tunnel::Hub, b: &tunnel::Hub) -> bool {
    a.psk == b.psk && a.endpoints == b.endpoints && a.obfuscation == b.obfuscation && a.vless == b.vless
}

#[cfg(test)]
mod tests {
    use super::*;

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

    /// A new offer of the hub the link up goes through, with the link's key
    /// and the same way to it, is kept without starting the link again; any
    /// other change starts it again.
    #[test]
    fn keeps_the_link_up_through_the_offered_key() {
        let dir = std::env::temp_dir().join(format!("cbb-away-link-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let id = |c: char| DeviceId::parse(&c.to_string().repeat(32)).unwrap();
        let (me, pi) = (id('d'), id('a'));
        let away = Away::new(dir.clone(), "g".into(), me.clone(), Arc::new(|_: &str| {}));
        away.turn_on().unwrap();
        let offer = |key: u8, next: u8, port: u16| {
            serde_json::to_value(TunnelOffer {
                hub_key: vec![key; 32],
                psk: vec![9; 32],
                endpoints: vec![format!("192.0.2.1:{port}")],
                next_key: if next == 0 { Vec::new() } else { vec![next; 32] },
                ..Default::default()
            })
            .unwrap()
        };
        let admins = |_: &str| true;
        assert_eq!(away.offered(&pi, &offer(1, 0, 8764), &admins), Some(pi.clone()));
        *away.link_up.lock().unwrap() = Some((pi.to_string(), vec![1; 32]));
        assert_eq!(away.offered(&pi, &offer(1, 2, 8764), &admins), None, "only the next key is new");
        let kept = || away.st.lock().unwrap().as_ref().unwrap().hub(pi.as_str()).cloned().unwrap();
        assert_eq!(kept().next, vec![2; 32], "the new offer is kept");
        assert_eq!(away.offered(&pi, &offer(1, 2, 8765), &admins), Some(pi.clone()), "another address");
        assert_eq!(away.offered(&pi, &offer(3, 0, 8765), &admins), Some(pi.clone()), "another key");
        *away.link_up.lock().unwrap() = None;
        assert_eq!(away.offered(&pi, &offer(3, 4, 8765), &admins), Some(pi.clone()), "no link up");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
