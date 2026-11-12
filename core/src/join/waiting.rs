// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! A request that waits for an admin (A-49). A joiner that reaches the
//! group while no device that may admit is there (away from home, through a
//! hub's guest path) leaves its request with the device it reached, the
//! holder: a hub of the group. When a device that may admit connects, the
//! holder sends it `waiting` (t 26) with what knocked; that admin's app
//! shows each request (the invitation's name, what the device says, from
//! which network, how long it waited and how often it tried) and the user
//! opens the way or dismisses it (`dismiss`, t 27). The holder decides
//! nothing and admits nobody: it only keeps and passes on.
//!
//! The rules the core checks:
//! - The holder sends `waiting` only to a device that may admit: the root's
//!   device, or a device whose admin key has `admit` (`decide::may_admit`).
//! - An admin takes `waiting` only from a device the records let be a hub.
//! - The holder takes `dismiss` only from a device that may admit.
//! - The holder keeps a request until the invitation's guest path expires
//!   (the expiry its admin gave with `guest`), and never more than a day; at
//!   most 16 requests by guest paths, one per invitation and key, and at
//!   most 2 of one invitation (a third key is refused, so it cannot push
//!   out the first);
//!   a second knock of the same counts as an attempt. The invitation is
//!   the one of the guest path the joiner came by, as the holder knows it;
//!   an Info that names another is refused. From the home network, where
//!   no guest path tells it, one request per source address and at most 32
//!   in all, the oldest giving way. So a host on the home network can push
//!   other requests from home out (requests the holder cannot tell apart
//!   by invitation), and the joiner then asks again; home is the trusted
//!   network, and an admin there admits directly.

use alloc::vec::Vec;

use super::decide::{Signer, may_admit};
use super::info::Info;
use super::invitation::Network;
use crate::format::{Alg, DeviceId, KeyHash, Rule, Value, cbor};
use crate::msg::tables::{T_DISMISS, T_WAITING};
use crate::records::State;
use crate::records::body::RIGHT_HUB;

/// The longest a holder keeps a request.
pub const MAX_WAIT_MS: u64 = 86_400_000;
/// The most requests by guest paths a holder keeps.
pub const MAX_REQUESTS: usize = 16;
/// The most requests of one invitation: whoever holds one invitation
/// cannot take the places of the others.
pub const MAX_PER_INVITATION: usize = 2;
/// The most requests from the home network, where no guest path tells the
/// invitation: one per source address, the oldest giving way.
pub const MAX_HOME: usize = 32;
/// The most requests in one `waiting` message: those by guest paths and
/// those from home.
pub const MAX_MESSAGE: usize = MAX_REQUESTS + MAX_HOME;

/// How a joiner reached the holder.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Came {
    /// By a guest or bypass path: the invitation of that path, as the
    /// holder knows it (the `guest` message that opened the path), not as
    /// the joiner names it.
    Path([u8; 16]),
    /// From the home network, from this source address.
    Home(core::net::IpAddr),
}

pub const RULE_WAITING: Rule = Rule::field("waiting/requests");
pub const RULE_DISMISS: Rule = Rule::field("dismiss/invite");

/// One request, as the holder keeps it.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Request {
    pub invite: [u8; 16],
    /// The joiner's member key, a point.
    pub key: Vec<u8>,
    pub info: Info,
    pub network: Network,
    /// When it first knocked, by the holder's clock.
    pub since_ms: u64,
    /// When the holder drops it.
    pub until_ms: u64,
    pub attempts: u8,
    /// How it came: by a path (the holder knows the invitation) or from
    /// home (only the joiner names it).
    pub came: Came,
}

/// One request, as an admin reads it.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Seen {
    pub invite: [u8; 16],
    pub key: Vec<u8>,
    pub info: Info,
    pub network: Network,
    /// How long it has waited when the holder sent it.
    pub waited_ms: u64,
    pub attempts: u8,
}

fn network_number(n: Network) -> u64 {
    match n {
        Network::Home => 1,
        Network::Guest => 2,
        Network::Bypass => 3,
    }
}

/// Whether the holder may send `waiting` to device `to`.
pub fn holder_may_send(state: &State, to: &DeviceId) -> bool {
    let Some(d) = state.device(to) else { return false };
    if d.frozen {
        return false;
    }
    if state.root_device == Some(*to) {
        return state.roots.last().is_some_and(|r| may_admit(state, &d.key.hash(), Signer::Root, r));
    }
    may_admit(state, &d.key.hash(), Signer::Admin, &KeyHash([0; 32]))
}

/// Whether an admin takes `waiting` from device `from`: its record lets it
/// be a hub (`hub` in its rights), and it is not frozen.
pub fn admin_may_take(state: &State, from: &DeviceId) -> bool {
    state.device(from).is_some_and(|d| !d.frozen && d.rights & RIGHT_HUB != 0)
}

/// Whether the holder takes `dismiss` from device `from`: only from a
/// device it may send `waiting` to, one that may admit.
pub fn holder_takes_dismiss(state: &State, from: &DeviceId) -> bool {
    holder_may_send(state, from)
}

/// The requests a holder keeps.
#[derive(Clone, Default, PartialEq, Eq, Debug)]
pub struct Held {
    pub requests: Vec<Request>,
}

impl Held {
    /// A joiner knocked at `now_ms` from `network`, by the way `came`.
    /// `expires_ms` is when that way ends. Returns whether the request is
    /// kept.
    pub fn knock(
        &mut self,
        key: &[u8],
        info: Info,
        network: Network,
        came: Came,
        now_ms: u64,
        expires_ms: u64,
    ) -> bool {
        self.drop_old(now_ms);
        let Some(invite) = info.invite else { return false };
        if matches!(came, Came::Path(p) if p != invite) || now_ms >= expires_ms {
            return false;
        }
        if let Some(r) = self.requests.iter_mut().find(|r| r.invite == invite && r.key == key) {
            r.attempts = r.attempts.saturating_add(1);
            r.info = info;
            r.network = network;
            r.came = came;
            return true;
        }
        match came {
            Came::Path(_) => {
                if self.requests.iter().filter(|r| matches!(r.came, Came::Path(_))).count() >= MAX_REQUESTS
                    || self.requests.iter().filter(|r| r.came == came).count() >= MAX_PER_INVITATION
                {
                    return false;
                }
            }
            Came::Home(_) => {
                // One place per source address, MAX_HOME in all: the
                // oldest gives way.
                self.requests.retain(|r| r.came != came);
                let home = |r: &Request| matches!(r.came, Came::Home(_));
                while self.requests.iter().filter(|r| home(r)).count() >= MAX_HOME {
                    let Some(i) = self
                        .requests
                        .iter()
                        .enumerate()
                        .filter(|(_, r)| home(r))
                        .min_by_key(|(_, r)| r.since_ms)
                        .map(|(i, _)| i)
                    else {
                        break;
                    };
                    self.requests.remove(i);
                }
            }
        }
        let until_ms = expires_ms.min(now_ms.saturating_add(MAX_WAIT_MS));
        self.requests.push(Request {
            invite,
            key: key.to_vec(),
            info,
            network,
            since_ms: now_ms,
            until_ms,
            attempts: 1,
            came,
        });
        true
    }

    /// Drops what is past its time.
    pub fn drop_old(&mut self, now_ms: u64) {
        self.requests.retain(|r| now_ms < r.until_ms);
    }

    /// The admin dismissed the requests of an invitation, or of one key.
    pub fn dismiss(&mut self, invite: &[u8; 16], key: Option<&KeyHash>) {
        self.requests.retain(|r| {
            &r.invite != invite || key.is_some_and(|k| &crate::format::Key::new(Alg::Es256, &r.key).hash() != k)
        });
    }

    /// The `waiting` message at `now_ms`, unpadded; None when nothing waits.
    pub fn message(&mut self, now_ms: u64) -> Option<Vec<u8>> {
        self.drop_old(now_ms);
        if self.requests.is_empty() {
            return None;
        }
        let infos: Vec<Vec<u8>> = self.requests.iter().map(|r| r.info.encode()).collect();
        let mut reqs = Vec::new();
        for (r, i) in self.requests.iter().zip(&infos) {
            let info = cbor::decode(i).ok()?;
            let mut m = alloc::vec![
                (1u16, Value::Bytes(&r.invite)),
                (2, Value::Array(alloc::vec![Value::Uint(Alg::Es256.number()), Value::Bytes(&r.key)])),
                (3, info),
                (4, Value::Uint(network_number(r.network))),
            ];
            let waited = now_ms.saturating_sub(r.since_ms).min(MAX_WAIT_MS);
            if waited != 0 {
                m.push((5, Value::Uint(waited)));
            }
            m.push((6, Value::Uint(u64::from(r.attempts))));
            reqs.push(Value::Map(m));
        }
        Some(Value::Map(alloc::vec![(0, Value::Uint(T_WAITING)), (2, Value::Array(reqs))]).encode())
    }
}

/// Reads `waiting`: each request checked against its table.
pub fn read(msg: &[u8]) -> Result<Vec<Seen>, Rule> {
    if crate::msg::check(msg)? != T_WAITING {
        return Err(RULE_WAITING);
    }
    let v = cbor::decode(msg)?;
    let mut out = Vec::new();
    for r in v.get(2).and_then(Value::as_array).ok_or(RULE_WAITING)? {
        let invite: [u8; 16] =
            r.get(1).and_then(Value::as_bytes).and_then(|b| b.try_into().ok()).ok_or(RULE_WAITING)?;
        let key = crate::format::Key::from_value(r.get(2).ok_or(RULE_WAITING)?).map_err(|_| RULE_WAITING)?;
        let info = Info::decode(&r.get(3).ok_or(RULE_WAITING)?.encode())?;
        if info.invite != Some(invite) {
            return Err(RULE_WAITING);
        }
        let network = match r.get(4).and_then(Value::as_uint) {
            Some(1) => Network::Home,
            Some(2) => Network::Guest,
            _ => Network::Bypass,
        };
        let waited_ms = r.get(5).and_then(Value::as_uint).unwrap_or(0);
        let attempts = r.get(6).and_then(Value::as_uint).and_then(|a| u8::try_from(a).ok()).ok_or(RULE_WAITING)?;
        out.push(Seen { invite, key: key.public.to_vec(), info, network, waited_ms, attempts });
    }
    Ok(out)
}

/// The `dismiss` message: the requests of an invitation, or of one key.
pub fn dismiss_message(invite: &[u8; 16], key: Option<&KeyHash>) -> Vec<u8> {
    let mut m = alloc::vec![(0u16, Value::Uint(T_DISMISS)), (2, Value::Bytes(invite))];
    if let Some(k) = key {
        m.push((3, Value::Bytes(&k.0)));
    }
    Value::Map(m).encode()
}

/// Reads `dismiss`.
pub fn read_dismiss(msg: &[u8]) -> Result<([u8; 16], Option<KeyHash>), Rule> {
    if crate::msg::check(msg)? != T_DISMISS {
        return Err(RULE_DISMISS);
    }
    let v = cbor::decode(msg)?;
    let invite = v.get(2).and_then(Value::as_bytes).and_then(|b| b.try_into().ok()).ok_or(RULE_DISMISS)?;
    let key = v.get(3).and_then(Value::as_bytes).and_then(|b| <[u8; 32]>::try_from(b).ok()).map(KeyHash);
    Ok((invite, key))
}
