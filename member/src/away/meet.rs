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
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::certs::DeviceId;

/// How long a call waits for the relay to say whose it is, and the most
/// calls kept.
const CALLER_WAIT: Duration = Duration::from_secs(5);
/// How often a failing link to the project's relay fetches the signed lists
/// again, as Go's relayRefetch, and looks for another address after the
/// same error.
const REFETCH: Duration = Duration::from_secs(600);

/// REFETCH, or what the service's tests shorten it to with
/// CBB_TEST_REFETCH_EVERY (milliseconds), a test hook a release ignores.
pub(crate) fn refetch_every() -> Duration {
    crate::testbuild::env("CBB_TEST_REFETCH_EVERY").and_then(|v| v.parse().ok()).map_or(REFETCH, Duration::from_millis)
}

/// The check of the relay's port: the call is served only when its
/// certificate names the device the relay said calls from that port.
pub(crate) fn caller_check(calls: Arc<Mutex<VecDeque<(u16, String)>>>) -> crate::discovery::Admit {
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

/// The address CBB_TEST_RESOLVE gives a relay's name, as Go's tests set
/// lookupIP: "host=ip" pairs separated by commas, for the tests only, since
/// entries.json names a relay only by a host name. "host=none" is a name
/// that does not resolve (Some(None)); None is a name the variable leaves
/// to the system.
pub(crate) fn test_resolve(name: &str) -> Option<Option<SocketAddr>> {
    let v = crate::testbuild::env("CBB_TEST_RESOLVE")?;
    let (host, port) = name.rsplit_once(':')?;
    let port: u16 = port.parse().ok()?;
    v.split(',').find_map(|pair| {
        let (h, ip) = pair.trim().split_once('=')?;
        if h != host {
            return None;
        }
        if ip == "none" {
            return Some(None);
        }
        ip.parse::<std::net::IpAddr>().ok().map(|ip| Some(SocketAddr::new(ip, port)))
    })
}

/// A short message for status of why the device is not connected to its
/// relay, as Go's relayProblem; the whole error goes to the detail.
pub(crate) fn problem(msg: &str, project: bool) -> String {
    if msg.contains("refused the registration") || msg.contains("do not list this device") {
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

#[cfg(test)]
#[path = "../nettest/away_meet.rs"]
mod net_tests;
