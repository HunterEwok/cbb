// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The Rust service as one of the group's hubs (docs/protocol.md, section
//! 11), as Go's service is one: it admits the tunnel keys its members'
//! hellos offer, answers each with its offer and those of the other hubs it
//! keeps, and serves them on its Hub (src/hub.rs). A
//! connection through the tunnel goes to a loopback port of its own, where
//! the node takes the member protocol only, from the device whose tunnel
//! address it came from.

use std::net::SocketAddr;
use std::sync::Mutex;
use std::time::Duration;

use super::Away;
use crate::control::Header;
use crate::error::{Error, Result};
use crate::forward::{self};
use crate::tunnel::{Forwarder, State};

/// The pins of the project's forwarder's key this release knows, as Go's
/// forward.projectPins, and what stands for them in a hub request.
pub(super) const PROJECT_PINS: &[&str] = crate::faces::PROJECT_FORWARDER_PINS;
const PROJECT_KEY: &str = "default";

impl Away {
    /// Makes this device one of the group's hubs with the addresses, port
    /// and AmneziaWG a hub request gives (cbb global hub), as Go's
    /// awayLocked: sync away from home goes on first with consent. Returns
    /// whether the hellos must go again with the keys, which it returns.
    pub fn make_hub(&self, h: &Header) -> Result<(Vec<u8>, Vec<u8>)> {
        let mut fw = forwarder_of(&h.forwarder, &h.forwarder_key)?;
        if !(0..=65535).contains(&h.port) {
            return Err(Error::msg(format!("a bad port {}", h.port)));
        }
        let mut cur = self.st.lock().unwrap();
        if cur.is_none() && !h.consent {
            return Err(Error::msg(
                "sync away from home is off here; turn it on first: cbb global on, or cbb global hub -away-on",
            ));
        }
        let mut st = match cur.clone() {
            Some(st) => st,
            None => State::new(&self.group)?,
        };
        let (mut endpoints, mut port) = (hub_addrs(&h.addrs, fw.is_some())?, h.port as u16);
        if h.keep {
            if !st.is_hub {
                return Err(Error::msg(
                    "this device is not a hub yet, so it has no settings to keep; make it one first: cbb global hub",
                ));
            }
            if h.addrs.is_empty() {
                endpoints = st.endpoints.clone();
            }
            if h.port == 0 {
                port = st.listen_port;
            }
            if h.forwarder.is_empty() {
                fw.clone_from(&st.forwarder);
            }
        }
        if endpoints.is_empty() && fw.is_none() {
            return Err(Error::msg("the hub needs an address away from home or a forwarder"));
        }
        // A hub offers AmneziaWG and, with a forwarder, VLESS unless the
        // request turns them off. VLESS comes with AmneziaWG: the clients
        // try it over UDP first, and inside VLESS it hides WireGuard's sizes
        // (docs/protocol.md, section 11, "VLESS").
        let vless = fw.is_some() && !h.vless_off;
        if vless && h.obfuscate_off {
            return Err(Error::msg(
                "VLESS carries AmneziaWG, so plain WireGuard goes with no VLESS at the forwarder: add -no-vless",
            ));
        }
        if let Some(f) = fw.as_mut() {
            vless_for(f, vless, st.forwarder.as_ref());
        }
        // Kept as they are when the hub is set again, so its clients'
        // offers stay good.
        let obfuscation = match (!h.obfuscate_off, st.obfuscation.take()) {
            (false, _) => None,
            (true, Some(o)) => Some(o),
            (true, None) => Some(crate::awg::Obfuscation::random()?.to_value()),
        };
        st.is_hub = true;
        st.retired = false;
        st.endpoints = endpoints;
        st.listen_port = port;
        st.forwarder = fw;
        st.relay = None;
        st.obfuscation = obfuscation;
        st.save(&self.dir)?;
        let keys = (st.public_key(), st.psk.clone());
        if cur.is_none() {
            (self.log)("cbb: sync away from home is on");
        }
        *cur = Some(st);
        drop(cur);
        // It serves again with the new settings once the loop sees them.
        *self.error.lock().unwrap() = None;
        (self.log)("cbb: this device is one of the group's hubs for sync away from home");
        Ok(keys)
    }

    /// The hub of 0.6 at the period of its forwarder's face (`period`, the
    /// face's tag in hex; docs/protocol.md, section 11, "The hub's key"):
    /// it holds the next key and settings, and serves with them once due
    /// (`State::rotate`). Gives whether they changed, for the clients to
    /// take the new offer, and whether the hub serves with the next key now,
    /// for its tunnel to start again.
    pub fn rotate_live(&self, period: &str) -> (bool, bool) {
        let ahead = i64::try_from(hub_key_ahead().as_millis()).unwrap_or(i64::MAX);
        let mut cur = self.st.lock().unwrap();
        let Some(st) = cur.as_mut() else { return (false, false) };
        let mut next = st.clone();
        let (changed, switched) = match next.rotate(period, crate::uptime::wall_ms(), ahead) {
            Ok(r) => r,
            Err(e) => {
                (self.log)(&format!("cbb: {}", e.for_log()));
                return (false, false);
            }
        };
        if !changed {
            return (false, false);
        }
        if let Err(e) = next.save(&self.dir) {
            (self.log)(&format!("cbb: saving the tunnel state: {}", e.for_log()));
            return (false, false);
        }
        if switched {
            (self.log)("cbb: the hub serves with its key and settings for the new period from now on");
        }
        *st = next;
        (true, switched)
    }
}

/// The credential a hub that serves with its key for the period serving_for
/// registers with, while the period now is that of the credential `now` gives:
/// that one while they agree (or before the hub's first period), which it
/// keeps in held; once they differ, the one it kept, so that it stays under
/// its period until it switches. A hub that started again meanwhile kept none
/// and takes the new period's. The hub on a group of 0.6 takes its hubs'
/// credential through it once away from home runs on that group (wave 5,
/// item D); until then a hub registers with none and waits.
#[allow(dead_code)]
fn credential_for<T: Clone>(
    serving_for: &str,
    period: Option<&str>,
    held: &Mutex<Option<T>>,
    now: impl FnOnce() -> Option<T>,
) -> Option<T> {
    if serving_for.is_empty() || period == Some(serving_for) {
        let now = now();
        held.lock().unwrap().clone_from(&now);
        return now;
    }
    held.lock().unwrap().clone().or_else(now)
}

/// The hub's addresses away from home, as Go's hubAddrs reads them.
pub(super) fn hub_addrs(addrs: &[String], forwarder: bool) -> Result<Vec<SocketAddr>> {
    let mut out = Vec::new();
    for a in addrs {
        let ep: SocketAddr = match a.parse::<SocketAddr>() {
            Ok(ep) if ep.port() != 0 => unmapped(ep),
            _ => {
                return Err(Error::msg(format!(
                    "{a:?} is not an address with a port, such as 203.0.113.7:8764 or [2001:db8::7]:8764"
                )));
            }
        };
        out.push(ep);
    }
    if out.len() > 7 || !forwarder && out.len() > 8 {
        return Err(Error::msg("at most 8 addresses, the forwarder's included"));
    }
    Ok(out)
}

/// Whether a hub that could not register with its forwarder (failed)
/// should be told its list of entry points is out of date: the forwarder
/// is the project's and this device holds no list that has not expired.
pub(super) fn entries_stale(project: bool, failed: bool, entries_held: bool) -> bool {
    failed && project && !entries_held
}

/// The hub's forwarder that a request or a hub command gives, as Go's
/// hubAddrs reads it: its address and its key's pin, or `default` for the
/// project's forwarder, whose pins this release knows; None for none.
pub(super) fn forwarder_of(fwd: &str, key: &str) -> Result<Option<Forwarder>> {
    if fwd.is_empty() {
        if !key.is_empty() {
            return Err(Error::msg("a forwarder's key without its address"));
        }
        return Ok(None);
    }
    let endpoint = match fwd.parse::<SocketAddr>() {
        Ok(ep) if ep.port() != 0 => unmapped(ep),
        _ => {
            return Err(Error::msg(format!(
                "{fwd:?} is not the forwarder's address with a port, such as 203.0.113.9:8764"
            )));
        }
    };
    let (pin, project) = if key == PROJECT_KEY {
        (PROJECT_PINS[0].to_string(), true)
    } else {
        pin_bytes(key)?;
        (key.to_string(), PROJECT_PINS.contains(&key))
    };
    Ok(Some(Forwarder { endpoint, pin, vless_id: String::new(), vless: None, project }))
}

/// Gives the forwarder f the group's VLESS user ID when the hub's clients
/// come over VLESS, as Go's awayLocked: the one old had, with old's
/// settings while the forwarder stays the same, else a new one.
fn vless_for(f: &mut Forwarder, vless: bool, old: Option<&Forwarder>) {
    (f.vless_id, f.vless) = (String::new(), None);
    if !vless {
        return;
    }
    match old.filter(|o| !o.vless_id.is_empty()) {
        Some(o) => {
            f.vless_id.clone_from(&o.vless_id);
            if o.endpoint == f.endpoint && o.pin == f.pin {
                f.vless.clone_from(&o.vless);
            }
        }
        None => f.vless_id = crate::vless::random_uuid(),
    }
}

/// A forwarder's pin: SHA-256 of its key, 44 characters of base64.
pub(super) fn pin_bytes(pin: &str) -> Result<[u8; 32]> {
    use base64::Engine as _;
    let e = base64::engine::general_purpose::STANDARD;
    e.decode(pin).ok().filter(|b| e.encode(b) == pin).and_then(|b| <[u8; 32]>::try_from(b).ok()).ok_or_else(|| {
        Error::msg(format!("{pin:?} is not a forwarder's key; cbb forward prints it, 44 characters of base64"))
    })
}

/// An IPv4 address mapped into IPv6 is the IPv4 address.
pub(super) fn unmapped(ep: SocketAddr) -> SocketAddr {
    match ep {
        SocketAddr::V6(v6) => match v6.ip().to_ipv4_mapped() {
            Some(v4) => SocketAddr::from((v4, v6.port())),
            None => ep,
        },
        v4 => v4,
    }
}

/// A short message for status of why the hub is not registered, as Go's
/// forwarderProblem; the whole error goes to the detail.
pub(super) fn forwarder_problem(detail: &str) -> String {
    if detail.is_empty() {
        String::new()
    } else if detail.contains(forward::NOT_LISTED) {
        forward::NOT_LISTED.to_string()
    } else if let Some(i) = detail.find("the forwarder refused the registration") {
        detail[i..].to_string()
    } else if detail.contains("pin") {
        "the forwarder's key is not the one given with -forwarder-key".to_string()
    } else {
        "the registration with the forwarder failed".to_string()
    }
}

/// How long before the hub serves with its key and settings for a new
/// period its offers give its clients them, as Go's hubKeyAhead: three days,
/// or CBB_TEST_HUB_KEY_AHEAD seconds, which tests set shorter.
fn hub_key_ahead() -> Duration {
    static AHEAD: std::sync::OnceLock<Duration> = std::sync::OnceLock::new();
    *AHEAD.get_or_init(|| {
        let s = crate::testbuild::env("CBB_TEST_HUB_KEY_AHEAD")
            .and_then(|v| v.parse().ok())
            .unwrap_or(cbb_core::benchtime::d(3 * 24 * 3600) as u64);
        Duration::from_secs(s)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The hub stays under the period it serves with until it switches;
    /// one that started again in between has kept nothing and takes the
    /// new period's credential.
    #[test]
    fn registers_under_the_period_it_serves() {
        let held = Mutex::new(None);
        assert_eq!(credential_for("", Some("p1"), &held, || Some("c1")), Some("c1"), "before the first period");
        assert_eq!(credential_for("p1", Some("p1"), &held, || Some("c1v2")), Some("c1v2"), "a newer one of the period");
        assert_eq!(
            credential_for("p1", Some("p2"), &held, || Some("c2")),
            Some("c1v2"),
            "a new period, not switched yet"
        );
        assert_eq!(credential_for("p2", Some("p2"), &held, || Some("c2")), Some("c2"), "switched");
        let restarted = Mutex::new(None);
        assert_eq!(credential_for("p2", Some("p3"), &restarted, || Some("c3")), Some("c3"), "started again in between");
        assert_eq!(credential_for::<&str>("p2", None, &Mutex::new(None), || None), None);
    }

    /// The project's forwarder: the command line sends its resolved address
    /// and "default", and the hub takes the first pin it knows; a pin of it
    /// marks it the same way, and another forwarder's does not (Go's
    /// TestHubAddrsProjectForwarder).
    #[test]
    fn the_project_s_forwarder() {
        let f = forwarder_of("198.51.100.20:8764", PROJECT_KEY).unwrap().unwrap();
        assert!(f.project && f.pin == PROJECT_PINS[0] && f.endpoint.to_string() == "198.51.100.20:8764");
        let f = forwarder_of("198.51.100.20:8764", PROJECT_PINS[0]).unwrap().unwrap();
        assert!(f.project);
        let other = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE=";
        let f = forwarder_of("198.51.100.9:8764", other).unwrap().unwrap();
        assert!(!f.project && f.pin == other);
        assert!(forwarder_of("", PROJECT_KEY).is_err(), "the project's key without an address");
        assert!(forwarder_of("", "").unwrap().is_none());
    }

    /// A hub of the project's forwarder that does not register is told the
    /// list is out of date only while it holds none that has not expired
    /// (Go's TestEntriesStale).
    #[test]
    fn entries_out_of_date() {
        assert!(entries_stale(true, true, false));
        assert!(!entries_stale(true, false, false), "registered");
        assert!(!entries_stale(false, true, false), "a forwarder of its own");
        assert!(!entries_stale(true, true, true), "with entry points held");
    }
}
