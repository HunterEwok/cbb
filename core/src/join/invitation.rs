// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The invitation of 0.6 (architecture review, section 8: A-41 … A-49,
//! A-23): one form for home and away, with the ways to reach the group, the
//! profile of the device it admits, and one-time values only.
//!
//! - **One form, several paths** (A-41): the home network, the hub's guest
//!   tunnel, the way around a block. A QR code carries the same invitation;
//!   its long secret replaces the six digits, which stay for typing by hand.
//! - **The profile** (A-42) says what the device may be: its role, its
//!   rights, whether it may be a hub, and whether it may join only from
//!   home. The device cannot ask for more.
//! - **One-time values only** (A-46): an ID, a secret, a guest key. Nothing
//!   that stays the group's after the invitation is used.
//! - **The admitter checks the expiry** (A-47): a board has no clock; it
//!   learns the time from the Welcome.
//! - **The user decides** (A-43, A-44): the admitter keeps the invitation's
//!   name, when it was made and whether it was used, and shows them with
//!   what the device says and what was proven about it.
//!
//! The invitation is not a secret to guard: it may leak, which must not
//! harm. It is one-time, limited by its profile, and the user still decides.

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

use crate::format::{Alg, Rule, Value, cbor};
use crate::records::State;
use crate::records::body::{CAP_HUB, RIGHT_HUB, RIGHT_READ, RIGHT_SECRETS, RIGHT_SEND, ROLE_LEAF};

use super::PairError;
use super::info::Info;

/// The start of an invitation's text.
pub const PREFIX: &str = "cbb://join#";
/// The secret's length: 256 bits, so the QR code's long secret leaves
/// nothing to guess (A-23).
pub const SECRET: usize = 32;
/// The most endpoints of one path.
pub const MAX_ENDPOINTS: usize = 8;
/// The most paths.
pub const MAX_PATHS: usize = 4;
/// The most failed attempts before an open invitation closes (A-49).
pub const MAX_FAILURES: u32 = 3;

pub const RULE_SHAPE: Rule = Rule::field("invite/shape");
pub const RULE_PATH: Rule = Rule::field("invite/path");
pub const RULE_PROFILE: Rule = Rule::field("invite/profile");

/// How a path reaches the group.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PathKind {
    /// The home network: the device finds the group's members there.
    Home = 1,
    /// The hub's WireGuard tunnel, as a guest with a one-time key.
    Guest = 2,
    /// The way around a block (VLESS to a forwarder).
    Bypass = 3,
}

/// One path of an invitation.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Path {
    pub kind: PathKind,
    /// Addresses as `host:port`; none for the home network (discovery
    /// finds the members).
    pub endpoints: Vec<String>,
    /// The hub's WireGuard key (alg 3), for a guest path.
    pub hub_key: Option<[u8; 32]>,
    /// The guest's one-time WireGuard private key and pre-shared key.
    pub guest: Option<([u8; 32], [u8; 32])>,
}

/// What the invited device may be (A-42).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Profile {
    /// 1 member, 2 phone, 3 watch, 4 leaf.
    pub role: u64,
    /// The most rights it gets: read, send, hub, secrets.
    pub rights: u64,
    /// It may join only from the home network.
    pub home_only: bool,
    /// A guarded leaf: only the root admits it.
    pub guarded: bool,
}

impl Profile {
    /// The profile of a small device without a screen (a kettle, a lamp):
    /// a leaf that reads and sends nothing by default, home only.
    pub fn small_device() -> Profile {
        Profile { role: ROLE_LEAF, rights: 0, home_only: true, guarded: false }
    }
}

/// An invitation.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Invitation {
    /// The one-time ID, which the joiner's Info names (`invite`).
    pub id: [u8; 16],
    /// CPace's password.
    pub secret: [u8; SECRET],
    pub paths: Vec<Path>,
    pub profile: Profile,
}

impl Invitation {
    /// A new invitation with fresh one-time values.
    pub fn new(paths: Vec<Path>, profile: Profile) -> Invitation {
        Invitation { id: crate::certs::random_bytes(), secret: crate::certs::random_bytes(), paths, profile }
    }

    /// The encoding.
    pub fn encode(&self) -> Vec<u8> {
        let paths: Vec<Value<'_>> = self
            .paths
            .iter()
            .map(|p| {
                let mut m = alloc::vec![(1u16, Value::Uint(p.kind as u64))];
                if !p.endpoints.is_empty() {
                    m.push((2, Value::Array(p.endpoints.iter().map(|e| Value::Text(e)).collect())));
                }
                if let Some(k) = &p.hub_key {
                    m.push((3, Value::Array(alloc::vec![Value::Uint(Alg::X25519.number()), Value::Bytes(k)])));
                }
                if let Some((k, psk)) = &p.guest {
                    m.push((4, Value::Bytes(k)));
                    m.push((5, Value::Bytes(psk)));
                }
                Value::Map(m)
            })
            .collect();
        let pr = self.profile;
        let mut prof = alloc::vec![(1u16, Value::Uint(pr.role))];
        if pr.rights != 0 {
            prof.push((2, Value::Uint(pr.rights)));
        }
        if pr.home_only {
            prof.push((3, Value::Uint(1)));
        }
        if pr.guarded {
            prof.push((4, Value::Uint(1)));
        }
        Value::Map(alloc::vec![
            (1, Value::Bytes(&self.id)),
            (2, Value::Bytes(&self.secret)),
            (3, Value::Array(paths)),
            (4, Value::Map(prof)),
        ])
        .encode()
    }

    /// The text form, for a QR code, a link or a file beside an installer.
    /// Never a command line argument and never part of a request to a
    /// server (A-45).
    pub fn text(&self) -> String {
        let mut s = PREFIX.to_string();
        s.push_str(&URL_SAFE_NO_PAD.encode(self.encode()));
        s
    }

    /// Reads the text form.
    pub fn parse(text: &str) -> Result<Invitation, Rule> {
        let b64 = text.trim().strip_prefix(PREFIX).ok_or(RULE_SHAPE)?;
        let b = URL_SAFE_NO_PAD.decode(b64).map_err(|_| RULE_SHAPE)?;
        Invitation::decode(&b)
    }

    /// Reads the encoding and checks every field.
    pub fn decode(b: &[u8]) -> Result<Invitation, Rule> {
        let v = cbor::decode(b)?;
        let bytes_n = |k: u16, n: usize| -> Result<Vec<u8>, Rule> {
            v.get(k).and_then(Value::as_bytes).filter(|b| b.len() == n).map(<[u8]>::to_vec).ok_or(RULE_SHAPE)
        };
        let id: [u8; 16] = bytes_n(1, 16)?.try_into().map_err(|_| RULE_SHAPE)?;
        let secret: [u8; SECRET] = bytes_n(2, SECRET)?.try_into().map_err(|_| RULE_SHAPE)?;
        if id == [0; 16] || secret == [0; SECRET] {
            return Err(RULE_SHAPE);
        }
        let arr = v.get(3).and_then(Value::as_array).ok_or(RULE_PATH)?;
        if arr.is_empty() || arr.len() > MAX_PATHS {
            return Err(RULE_PATH);
        }
        let mut paths = Vec::new();
        for p in arr {
            let kind = match p.get(1).and_then(Value::as_uint) {
                Some(1) => PathKind::Home,
                Some(2) => PathKind::Guest,
                Some(3) => PathKind::Bypass,
                _ => return Err(RULE_PATH),
            };
            let mut endpoints = Vec::new();
            if let Some(e) = p.get(2) {
                let e = e.as_array().ok_or(RULE_PATH)?;
                if e.is_empty() || e.len() > MAX_ENDPOINTS {
                    return Err(RULE_PATH);
                }
                for x in e {
                    let t = x.as_text().ok_or(RULE_PATH)?;
                    if t.parse::<core::net::SocketAddr>().is_err() {
                        return Err(RULE_PATH);
                    }
                    endpoints.push(t.to_string());
                }
            }
            let key32 = |b: Option<&[u8]>| -> Result<Option<[u8; 32]>, Rule> {
                match b {
                    None => Ok(None),
                    Some(b) => {
                        let k: [u8; 32] = b.try_into().map_err(|_| RULE_PATH)?;
                        if k == [0; 32] {
                            return Err(RULE_PATH);
                        }
                        Ok(Some(k))
                    }
                }
            };
            let hub_key = match p.get(3) {
                None => None,
                Some(k) => {
                    let k = crate::format::Key::from_value(k).map_err(|_| RULE_PATH)?;
                    if k.alg != Alg::X25519 {
                        return Err(RULE_PATH);
                    }
                    key32(Some(k.public))?
                }
            };
            let guest = match (key32(p.get(4).and_then(Value::as_bytes))?, key32(p.get(5).and_then(Value::as_bytes))?) {
                (Some(k), Some(psk)) => Some((k, psk)),
                (None, None) => None,
                _ => return Err(RULE_PATH),
            };
            let ok = match kind {
                PathKind::Home => endpoints.is_empty() && hub_key.is_none() && guest.is_none(),
                PathKind::Guest => !endpoints.is_empty() && hub_key.is_some() && guest.is_some(),
                PathKind::Bypass => !endpoints.is_empty(),
            };
            if !ok {
                return Err(RULE_PATH);
            }
            paths.push(Path { kind, endpoints, hub_key, guest });
        }
        let pv = v.get(4).ok_or(RULE_PROFILE)?;
        let role = pv.get(1).and_then(Value::as_uint).filter(|r| (1..=4).contains(r)).ok_or(RULE_PROFILE)?;
        let flag = |k: u16| -> Result<bool, Rule> {
            match pv.get(k) {
                None => Ok(false),
                Some(Value::Uint(1)) => Ok(true),
                Some(_) => Err(RULE_PROFILE),
            }
        };
        let rights = match pv.get(2) {
            None => 0,
            Some(r) => r
                .as_uint()
                .filter(|r| r & !(RIGHT_READ | RIGHT_SEND | RIGHT_HUB | RIGHT_SECRETS) == 0)
                .ok_or(RULE_PROFILE)?,
        };
        let profile = Profile { role, rights, home_only: flag(3)?, guarded: flag(4)? };
        if profile.guarded && role != ROLE_LEAF {
            return Err(RULE_PROFILE);
        }
        if profile.home_only && paths.iter().any(|p| p.kind != PathKind::Home) {
            return Err(RULE_PROFILE);
        }
        Ok(Invitation { id, secret, paths, profile })
    }
}

/// The network a joiner came from.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Network {
    Home,
    Guest,
    Bypass,
}

/// An invitation the admitter keeps open (A-49): what the user named it,
/// when it was made, until when it is good, and how it went.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Open {
    pub invitation: Invitation,
    /// The name the user gave it ("the kettle in the kitchen").
    pub name: String,
    pub created_ms: u64,
    pub expires_ms: u64,
    pub used: bool,
    pub failures: u32,
    /// A key allowed ahead of time: the board's key read over the cable
    /// when CBB flashed it (A-43). A joiner with this key needs no other
    /// match; any other key is refused.
    pub allowed_key: Option<crate::format::KeyHash>,
}

impl Open {
    /// Whether a joiner from `network` at `now_ms` may use it; why not.
    pub fn may_use(&self, network: Network, now_ms: u64) -> Result<(), PairError> {
        if self.used {
            return Err(PairError::Closed);
        }
        if now_ms >= self.expires_ms {
            return Err(PairError::Expired);
        }
        if self.failures >= MAX_FAILURES {
            return Err(PairError::TooMany);
        }
        if self.invitation.profile.home_only && network != Network::Home {
            return Err(PairError::Refused);
        }
        Ok(())
    }

    /// Whether the joiner's key matches a key allowed ahead of time: None
    /// when the invitation names no such key (the user matches it another
    /// way), else whether it is that key.
    pub fn key_allowed(&self, joiner: &crate::format::KeyHash) -> Option<bool> {
        self.allowed_key.map(|k| &k == joiner)
    }

    /// The joiner asks for more than the profile allows: a role of its
    /// own, or the hub's capability without hub rights.
    pub fn asks_more(&self, info: &Info) -> bool {
        let p = self.invitation.profile;
        info.role != p.role || (info.caps & CAP_HUB != 0 && p.rights & RIGHT_HUB == 0)
    }
}

/// What the attestation showed about the joiner's key.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Attestation {
    /// Evidence the admitter checked: 1 android-tee, 2 android-strongbox,
    /// 3 tpm.
    Proven(u64),
    /// Nothing proven: counted as a file.
    NotProven,
}

/// What the decision screen shows the user (A-44).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Decision {
    /// The invitation's name, or None for a code typed by hand.
    pub invitation: Option<String>,
    /// How long ago the invitation was made.
    pub age_ms: u64,
    /// Whether it had been used before (then the request is refused, and
    /// the user is told that someone else used it first).
    pub used_before: bool,
    pub network: Network,
    /// What the device says it is: its name, role and system.
    pub name: String,
    pub role: u64,
    pub os: u64,
    pub attestation: Attestation,
    /// The rights it gets.
    pub rights: u64,
    /// A device of the group with a name like this one's.
    pub similar: Option<String>,
}

impl Decision {
    /// The screen's data for a joiner.
    pub fn of(
        state: &State,
        open: Option<&Open>,
        network: Network,
        info: &Info,
        attestation: Attestation,
        rights: u64,
        now_ms: u64,
    ) -> Decision {
        Decision {
            invitation: open.map(|o| o.name.clone()),
            age_ms: open.map_or(0, |o| now_ms.saturating_sub(o.created_ms)),
            used_before: open.is_some_and(|o| o.used),
            network,
            name: info.name.clone(),
            role: info.role,
            os: info.os,
            attestation,
            rights,
            similar: similar_name(state, &info.name),
        }
    }
}

/// A device of the group whose name is like `name`: the same letters and
/// digits, case aside, or one letter apart. A joiner that calls itself
/// "Ewok's MacBook" next to "Ewok’s Macbook" is worth a second look.
pub fn similar_name(state: &State, name: &str) -> Option<String> {
    let norm =
        |s: &str| -> Vec<char> { s.chars().filter(|c| c.is_alphanumeric()).flat_map(char::to_lowercase).collect() };
    let n = norm(name);
    state.devices.iter().find(|d| within_one(&norm(&d.name), &n)).map(|d| d.name.clone())
}

/// Whether two strings are at most one edit apart.
fn within_one(a: &[char], b: &[char]) -> bool {
    let (s, l) = if a.len() <= b.len() { (a, b) } else { (b, a) };
    if l.len().saturating_sub(s.len()) > 1 {
        return false;
    }
    let mut i = 0;
    while i < s.len() && s.get(i) == l.get(i) {
        i = i.saturating_add(1);
    }
    if s.len() == l.len() {
        s.get(i.saturating_add(1)..) == l.get(i.saturating_add(1)..)
    } else {
        s.get(i..) == l.get(i.saturating_add(1)..)
    }
}

/// The short code both screens show, for a device with a screen and no
/// camera (A-43): six digits from the pairing session's exporter, which
/// both ends share only when nobody sits between them. The user answers
/// "they match".
pub fn short_code(exporter: &[u8]) -> String {
    let h = crate::format::sha256(&[b"cbb short code v1\0", exporter]);
    let n = u32::from_be_bytes([h[0], h[1], h[2], h[3]]) % 1_000_000;
    alloc::format!("{n:06}")
}
