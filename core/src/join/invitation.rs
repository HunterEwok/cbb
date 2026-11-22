// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The invitation of 0.6 (architecture review, section 8: A-41 … A-49,
//! A-23): one form for home and away, with the ways to reach the group, the
//! profile of the device it admits, and one-time values only.
//!
//! - **One form, several paths** (A-41): the home network, the hub's guest
//!   tunnel, the way around a block. A QR code carries the same invitation.
//!   A home window ([`Invitation::home`]) has six digits instead of a long
//!   secret: its QR code carries them with its ID, and they stay for
//!   typing by hand.
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
use zeroize::Zeroize;

use crate::format::grant::{Binding, Kept};
use crate::format::{Alg, DeviceId, KeyHash, Rule, Value, cbor};
use crate::records::State;
use crate::records::body::{CAP_HUB, RIGHT_HUB, RIGHT_READ, RIGHT_SECRETS, RIGHT_SEND, ROLE_LEAF};

use super::info::Info;
use super::{PairError, PairExporter};

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
pub const RULE_OBFUSCATION: Rule = Rule::field("invite/obfuscation");

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
    /// A group with AmneziaWG: its obfuscation settings, which the guest
    /// needs before it can reach the hub (A-46: the one value of an
    /// invitation that is not one-time; in 0.6 they change only by hand).
    /// Only on a guest or bypass path.
    pub obfuscation: Option<crate::msg::Obfuscation>,
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

/// A profile's role that admits any role but a leaf's: a home window's,
/// where the device says what it is and the admitter gives the rights of
/// that role. It is never encoded: a home window is not written as an
/// invitation's text.
pub const ROLE_ANY: u64 = 0;

impl Profile {
    /// The profile of a small device without a screen (a kettle, a lamp):
    /// a leaf that reads and sends nothing by default, home only.
    pub fn small_device() -> Profile {
        Profile { role: ROLE_LEAF, rights: 0, home_only: true, guarded: false }
    }

    /// A home window's profile: a computer, a phone or a watch that joins
    /// from the home network, with at most the rights a pairing at home
    /// gives (read, send, secrets, and hub for a member with the cap).
    pub fn home() -> Profile {
        Profile {
            role: ROLE_ANY,
            rights: RIGHT_READ | RIGHT_SEND | RIGHT_SECRETS | RIGHT_HUB,
            home_only: true,
            guarded: false,
        }
    }
}

/// The label of a home window's secret, from its six digits.
pub const HOME_CODE_LABEL: &[u8] = b"cbb pair home code v1\0";
/// How many digits a home window's code has.
pub const HOME_DIGITS: usize = 6;

/// A home window's secret, CPace's password, from its six ASCII digits:
/// SHA-256(`cbb pair home code v1` 0x00 ‖ digits). None for anything but
/// six digits.
pub fn home_secret(digits: &str) -> Option<[u8; SECRET]> {
    (digits.len() == HOME_DIGITS && digits.bytes().all(|b| b.is_ascii_digit()))
        .then(|| crate::format::sha256(&[HOME_CODE_LABEL, digits.as_bytes()]))
}

/// An invitation.
#[derive(Clone, PartialEq, Eq)]
pub struct Invitation {
    /// The one-time ID, which the joiner's Info names (`invite`).
    pub id: [u8; 16],
    /// CPace's password.
    pub secret: [u8; SECRET],
    pub paths: Vec<Path>,
    pub profile: Profile,
}

impl Drop for Invitation {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

impl core::fmt::Debug for Invitation {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Invitation")
            .field("id", &self.id)
            .field("secret", &crate::secret::Redacted(self.secret.len()))
            .field("paths", &self.paths)
            .field("profile", &self.profile)
            .finish()
    }
}

impl Invitation {
    /// A new invitation: its ID and secret drawn here, never all zero
    /// bytes, which readers refuse (`invite/shape`).
    pub fn new(paths: Vec<Path>, profile: Profile) -> Invitation {
        Invitation {
            id: not_zero(crate::certs::random_bytes),
            secret: not_zero(crate::certs::random_bytes),
            paths,
            profile,
        }
    }

    /// A home window (owner, 11-20): a new ID, never all zero bytes, and
    /// six new digits, from which its secret comes ([`home_secret`]), with
    /// the home profile ([`Profile::home`]) and the home path. The window
    /// shows the digits and its QR code carries them with the ID; the
    /// joiner derives the same secret ([`Invitation::typed`]). Gives the
    /// invitation and its digits.
    pub fn home() -> (Invitation, String) {
        let id = not_zero(crate::certs::random_bytes);
        let digits = loop {
            // 10^6 divides 2^32 unevenly: draws from the top are taken
            // again, so every code is as likely.
            let n = u32::from_be_bytes(crate::certs::random_bytes::<4>());
            if n < u32::MAX - u32::MAX % 1_000_000 {
                break alloc::format!("{:06}", n % 1_000_000);
            }
        };
        #[allow(clippy::expect_used, reason = "six digits always give a secret")]
        let inv = Invitation::typed(id, &digits).expect("six digits");
        (inv, digits)
    }

    /// The home window a joiner names by its ID (from the window's QR code
    /// or its mDNS announcement) and its six digits (from the QR code, or
    /// typed by the person). None for an ID of zero bytes or anything but
    /// six digits.
    pub fn typed(id: [u8; 16], digits: &str) -> Option<Invitation> {
        if id == [0; 16] {
            return None;
        }
        let secret = home_secret(digits)?;
        let home = Path { kind: PathKind::Home, endpoints: Vec::new(), hub_key: None, guest: None, obfuscation: None };
        Some(Invitation { id, secret, paths: alloc::vec![home], profile: Profile::home() })
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
                if let Some(o) = p.obfuscation.as_ref().and_then(crate::msg::Obfuscation::value) {
                    m.push((6, o));
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

    /// Reads the encoding and checks every field, as a reader of this
    /// version does (`crate::msg::read_map`): unknown rights bits are
    /// ignored, and a path whose settings this version cannot read is
    /// unusable and skipped; an invitation with no usable path is refused.
    pub fn decode(b: &[u8]) -> Result<Invitation, Rule> {
        let v = crate::msg::read_map(&crate::msg::tables::INVITE, &cbor::decode(b)?)?;
        let bytes_n = |k: u16, n: usize| -> Result<Vec<u8>, Rule> {
            v.get(k).and_then(Value::as_bytes).filter(|b| b.len() == n).map(<[u8]>::to_vec).ok_or(RULE_SHAPE)
        };
        let id: [u8; 16] = bytes_n(1, 16)?.try_into().map_err(|_| RULE_SHAPE)?;
        let secret: [u8; SECRET] = bytes_n(2, SECRET)?.try_into().map_err(|_| RULE_SHAPE)?;
        if id == [0; 16] || crate::secret::ct_eq(&secret, &[0; SECRET]) {
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
                if e.is_empty() || e.len() > MAX_ENDPOINTS || !crate::msg::each_once(e) {
                    return Err(RULE_PATH);
                }
                for x in e {
                    let t = x.as_text().ok_or(RULE_PATH)?;
                    if !crate::msg::valid_addr(t) {
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
            let obfuscation = match p.get(6) {
                None => None,
                Some(_) if kind == PathKind::Home => return Err(RULE_OBFUSCATION),
                // Settings of a later version: this way is unusable.
                Some(o) if crate::msg::later::unusable(o) => continue,
                Some(o) => Some(crate::msg::Obfuscation::read(o, "invite/obfuscation")?),
            };
            paths.push(Path { kind, endpoints, hub_key, guest, obfuscation });
        }
        if paths.is_empty() {
            return Err(RULE_PATH);
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
    /// The attempt in progress: one at a time.
    pub attempt: Option<Attempt>,
    /// The number the next attempt gets.
    pub next_attempt: u64,
}

/// The longest one attempt may take at the member: from `pair/start` to
/// `pair/done`. No person answers in between: the secret approves.
pub const ATTEMPT_MS: u64 = 30_000;

/// An attempt in progress on an open invitation, at the member.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Attempt {
    /// Its number, from [`Open::begin`]; the later steps name it.
    pub number: u64,
    pub since_ms: u64,
}

impl Attempt {
    /// Whether the attempt is still open at `now_ms`.
    fn open_at(&self, now_ms: u64) -> bool {
        now_ms.saturating_sub(self.since_ms) < ATTEMPT_MS
    }
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
        let role = if p.role == ROLE_ANY { info.role == ROLE_LEAF } else { info.role != p.role };
        role || (info.caps & CAP_HUB != 0 && p.rights & RIGHT_HUB == 0)
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

/// What draw gives that is not all zero bytes, drawn again until it is.
pub(crate) fn not_zero<const N: usize>(mut draw: impl FnMut() -> [u8; N]) -> [u8; N] {
    loop {
        let b = draw();
        if b != [0; N] {
            return b;
        }
    }
}

/// A joiner's pairing session at a home window (an invitation whose
/// profile is home only, [`Invitation::home`]) in which the joiner
/// verified the member's `Tb` under the window's secret: the member proved
/// it holds the secret the window shows, in this session. It is the only
/// source of a guarded leaf's binding ([`Proven::binding`]). It lives with
/// that session alone: it is neither cloned nor kept, and a restart has
/// none. Only the joiner's session makes one
/// (`session::JoinerSession::proven`).
#[derive(Debug)]
pub struct Proven {
    local: DeviceId,
    /// The session's mark (`grant::session_mark` of its exporter): the
    /// proof names that session and serves no other.
    session: [u8; 32],
    /// The hash of the member's key the session's handshake proved: the
    /// proof is of that member and no other.
    member: KeyHash,
}

impl Proven {
    /// The proof of the session with this exporter, in which the joiner's
    /// own key has the device ID `local` and the member's handshake proved
    /// `member`. Only for a home window: None for an invitation whose
    /// profile is not home only.
    pub(crate) fn new(
        invitation: &Invitation,
        local: DeviceId,
        exporter: &PairExporter,
        member: &[u8; 65],
    ) -> Option<Proven> {
        invitation.profile.home_only.then(|| Proven {
            local,
            session: crate::format::grant::session_mark(exporter.bytes()),
            member: crate::format::Key::new(Alg::Es256, member).hash(),
        })
    }

    /// A guarded leaf's binding in person (`grant::read_bound`): the grant
    /// this session brings, and only it, binds the leaf to the root it
    /// waits for; `kept` and `head` are what the leaf stored
    /// (`Kept::start`). None when the leaf waits for no binding. What a
    /// binding names comes from the leaf's own state and this session's
    /// own key, never from the peer. `exporter` is the current session's:
    /// none for a proof from another session. It takes the proof by value:
    /// one proof serves one grant.
    pub fn binding(self, kept: &Kept, head: Option<(KeyHash, u64)>, exporter: &PairExporter) -> Option<Binding> {
        if !self.of(exporter) {
            return None;
        }
        Binding::matched(kept, head, self.local, self.session)
    }

    /// Whether the proof was made in the session with this exporter.
    pub(crate) fn of(&self, exporter: &PairExporter) -> bool {
        crate::secret::ct_eq(&self.session, &crate::format::grant::session_mark(exporter.bytes()))
    }

    /// Whether the proof is of the member with this key: the one a grant
    /// it reads came from.
    pub fn to(&self, member: &[u8; 65]) -> bool {
        crate::format::Key::new(Alg::Es256, member).hash() == self.member
    }
}

/// The joiner's sessions with one invitation (kept across restarts): at
/// most [`MAX_FAILURES`] in all, each started only by the person's action
/// (the app asks "start again?" and never starts a session by itself, nor
/// reconnects on its own).
#[derive(Clone, Default, PartialEq, Eq, Debug)]
pub struct JoinerAttempts {
    pub started: u32,
}

impl JoinerAttempts {
    /// The person started a session; refused after [`MAX_FAILURES`]
    /// sessions ([`PairError::TooMany`]).
    pub fn start(&mut self) -> Result<(), PairError> {
        if self.started >= MAX_FAILURES {
            return Err(PairError::TooMany);
        }
        self.started = self.started.saturating_add(1);
        Ok(())
    }
}

impl Open {
    /// A joiner starts an attempt at `now_ms`: refused while another is in
    /// progress ([`PairError::Busy`]), until it ends or [`ATTEMPT_MS`] is
    /// over, and when the invitation may not be used ([`Open::may_use`]).
    /// The attempt counts as failed from here, unless it ends in a Welcome
    /// ([`Open::end`]): a joiner that does not hold the secret, or that
    /// goes away, spends one of the [`MAX_FAILURES`]. Returns the attempt's
    /// number, which the later steps name.
    pub fn begin(&mut self, network: Network, now_ms: u64) -> Result<u64, PairError> {
        if let Some(a) = &self.attempt
            && a.open_at(now_ms)
        {
            return Err(PairError::Busy);
        }
        self.attempt = None;
        self.may_use(network, now_ms)?;
        let number = self.next_attempt;
        self.next_attempt = self.next_attempt.saturating_add(1);
        self.failures = self.failures.saturating_add(1);
        self.attempt = Some(Attempt { number, since_ms: now_ms });
        Ok(number)
    }

    /// The attempt ended at `now_ms`: `welcomed` when the joiner got its
    /// Welcome, which closes the invitation (one success each) and, on
    /// the attempt still open, takes back the failure counted at the
    /// start. Otherwise an attempt of another number than the open one
    /// changes nothing.
    pub fn end(&mut self, number: u64, welcomed: bool, now_ms: u64) {
        if welcomed {
            self.used = true;
        }
        if self.attempt.as_ref().is_none_or(|a| a.number != number) {
            return;
        }
        if welcomed && self.attempt.as_ref().is_some_and(|a| a.open_at(now_ms)) {
            self.failures = self.failures.saturating_sub(1);
        }
        self.attempt = None;
    }
}

/// The start of a home window's QR code text.
pub const WINDOW_PREFIX: &str = "cbb://pair?";
/// The longest text a reader of a window's QR code takes.
pub const MAX_WINDOW_TEXT: usize = 512;
/// The most addresses a window's QR code carries.
pub const MAX_WINDOW_ADDRS: usize = 4;

/// What a home window's QR code carries (owner, 11-20):
/// `cbb://pair?addr=…&fp=…&i=<ID hex>&c=<digits>`, an `addr` for each of
/// the member's addresses (host:port), `fp` the hex of its TLS key's hash,
/// `i` the window's ID and `c` its six digits. The window's mDNS
/// announcement carries the ID and the hash, never the digits.
#[derive(Clone, PartialEq, Eq)]
pub struct WindowLink {
    pub addrs: Vec<String>,
    pub fp: KeyHash,
    pub id: [u8; 16],
    pub digits: String,
}

impl core::fmt::Debug for WindowLink {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("WindowLink")
            .field("addrs", &self.addrs)
            .field("fp", &self.fp)
            .field("id", &self.id)
            .field("digits", &crate::secret::Redacted(self.digits.len()))
            .finish()
    }
}

impl Drop for WindowLink {
    fn drop(&mut self) {
        self.digits.zeroize();
    }
}

impl WindowLink {
    /// The QR code's text.
    pub fn text(&self) -> String {
        let mut t = String::from(WINDOW_PREFIX);
        for a in &self.addrs {
            t.push_str("addr=");
            for b in a.bytes() {
                if b.is_ascii_alphanumeric() || b"-._~:[]".contains(&b) {
                    t.push(char::from(b));
                } else {
                    t.push_str(&alloc::format!("%{b:02X}"));
                }
            }
            t.push('&');
        }
        t.push_str(&alloc::format!(
            "fp={}&i={}&c={}",
            crate::certs::hex(&self.fp.0),
            crate::certs::hex(&self.id),
            self.digits
        ));
        t
    }

    /// Reads a window's QR code text: at least one and at most
    /// [`MAX_WINDOW_ADDRS`] addresses, the key hash, an ID that is not all
    /// zero and six digits, each once. None for anything else.
    pub fn parse(text: &str) -> Option<WindowLink> {
        if text.len() > MAX_WINDOW_TEXT {
            return None;
        }
        let query = text.trim().strip_prefix(WINDOW_PREFIX)?;
        let (mut addrs, mut fp, mut id, mut digits) = (Vec::new(), None, None, None);
        for item in query.split('&') {
            let (k, v) = item.split_once('=')?;
            match k {
                "addr" if addrs.len() < MAX_WINDOW_ADDRS => addrs.push(unescape(v)?),
                "addr" => return None,
                "fp" if fp.is_none() => fp = Some(KeyHash(hex_bytes(v)?)),
                "i" if id.is_none() => id = Some(hex_bytes::<16>(v).filter(|i| i != &[0; 16])?),
                "c" if digits.is_none() => digits = home_secret(v).map(|_| v.to_string()),
                // A key this version does not know is skipped.
                "fp" | "i" | "c" => return None,
                _ => {}
            }
        }
        if addrs.is_empty() || addrs.iter().any(String::is_empty) {
            return None;
        }
        Some(WindowLink { addrs, fp: fp?, id: id?, digits: digits? })
    }

    /// The joiner's invitation from the link ([`Invitation::typed`]).
    pub fn invitation(&self) -> Option<Invitation> {
        Invitation::typed(self.id, &self.digits)
    }
}

/// The %XX escapes of a QR code's value decoded; None for a bad escape or
/// text that is not UTF-8.
fn unescape(s: &str) -> Option<String> {
    let mut out = Vec::with_capacity(s.len());
    let mut bytes = s.bytes();
    while let Some(b) = bytes.next() {
        if b == b'%' {
            let hex = [bytes.next()?, bytes.next()?];
            out.push(u8::from_str_radix(core::str::from_utf8(&hex).ok()?, 16).ok()?);
        } else {
            out.push(b);
        }
    }
    String::from_utf8(out).ok()
}

/// N bytes from their lower-case hex, as the link and mDNS write them.
pub fn hex_bytes<const N: usize>(s: &str) -> Option<[u8; N]> {
    if s.len() != N.saturating_mul(2) || !s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
        return None;
    }
    let mut out = [0u8; N];
    for (o, pair) in out.iter_mut().zip(s.as_bytes().chunks(2)) {
        *o = u8::from_str_radix(core::str::from_utf8(pair).ok()?, 16).ok()?;
    }
    Some(out)
}
