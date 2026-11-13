// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! Commands in the 0.6 format (format section 6, label `cbb command v3`):
//! a device is controlled only by commands (A-16), each signed by its
//! commander and, when it carries orders, sealed to the receiver's sealing
//! key, so that only the receiver reads them. A device's own news goes the
//! other way as content of type 4, "state" (A-17, `crate::content`); type
//! 10 here is the "command to a device" its firmware declares.
//!
//! There are no command classes (owner, 2026-11-11). Who obeys whom:
//!
//! - A member obeys the current root, and an admin whose device record
//!   lists the command's type in `commands`, as long as
//!   [`State::may_command`] says so: a key with two histories, a removed or
//!   frozen key, and every admin while the group is stopped command nothing
//!   (audit pass 1); a counted takeover decides who the root is.
//! - An ordinary leaf obeys the commanders its grant names.
//! - A guarded leaf obeys the commanders its grant names too, but each
//!   command carries a one-time number the leaf gave out ([`Nonces`]) and
//!   is signed only after a person confirmed it on the commander's device;
//!   with a stale grant it obeys nobody.
//!
//! Every receiver keeps the last counter `n` of each signer and refuses one
//! not above it ([`Counters`]); a receiver with a clock checks the 30 s
//! lifetime too.
//!
//! This is the new path beside the old one (`crate::command`); the service
//! and the phones switch to it in wave 5.

pub mod orders;

#[cfg(test)]
mod tests;

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use crate::error::Error;
use crate::format::cbor::{self, Value};
use crate::format::envelope::{self, Envelope};
use crate::format::grant::Kept;
use crate::format::{Rule, frame, sig};
use crate::identity::ExternalKey;
use crate::keystore::KeyStore;
use crate::records::body::{Kind, command_bit};
use crate::records::eval::State;
use crate::records::key::{self as rkey, DeviceId, GroupId, Key, KeyHash};
use crate::records::set::RecordSet;

/// The message type of a command.
pub const T_COMMAND: u64 = crate::msg::wave4::T_COMMAND;
/// The message type of a one-time number.
pub const T_NONCE: u64 = crate::msg::wave4::T_NONCE;

/// A command's longest life: `expires_ms` is 1 ms to 30 s after `time_ms`.
pub const LIFETIME_MS: u64 = 30_000;
/// How far a receiver's clock may be from its commander's.
pub const SKEW_MS: u64 = 60_000;
/// A command body's ceiling, and a `paste`'s.
pub const MAX_BODY: usize = 64 << 10;
pub const MAX_PASTE_BODY: usize = 2 << 20;
/// How long a guarded leaf's grant lives when it does not say: 35 days on
/// the leaf's running time.
pub const DEFAULT_LIFE_MS: u64 = 3_024_000_000;

/// The command types (section 6); they are the records' too.
pub use crate::records::body::{
    COMMAND_ACTION, COMMAND_ACTIONS_OFF, COMMAND_AWAY_OFF, COMMAND_DEVICE, COMMAND_HUB, COMMAND_MODE, COMMAND_MUTE,
    COMMAND_PASTE, COMMAND_PASTE_OFF, COMMAND_UNMUTE,
};

/// A type with orders: these are sealed, the others carry none.
pub const fn has_orders(t: u64) -> bool {
    matches!(t, COMMAND_MODE | COMMAND_HUB | COMMAND_PASTE | COMMAND_ACTION | COMMAND_MUTE | COMMAND_DEVICE)
}

pub const RULE_TYPE: Rule = Rule::field("commands/type");
pub const RULE_GROUP: Rule = Rule::field("commands/group");
pub const RULE_SIGNER: Rule = Rule::field("commands/signer");
pub const RULE_N: Rule = Rule::field("commands/n");
pub const RULE_TIME: Rule = Rule::field("commands/time");
pub const RULE_EXPIRES: Rule = Rule::field("commands/expires");
pub const RULE_TO: Rule = Rule::field("commands/to");
pub const RULE_ID: Rule = Rule::field("commands/id");
/// A nonce of the wrong size, or a guarded leaf's command without the
/// one-time number it gave out.
pub const RULE_NONCE: Rule = Rule::field("commands/nonce");
/// `epoch` without `sealed` or the reverse, or an epoch the receiver does
/// not hold.
pub const RULE_EPOCH: Rule = Rule::field("commands/epoch");
/// `sealed` on a type without orders, orders in the open, or a seal that
/// does not open.
pub const RULE_SEALED: Rule = Rule::field("commands/sealed");
/// A signer that may not give this command to this receiver.
pub const RULE_RIGHT: Rule = Rule::field("commands/right");
/// A counter not above the last one this receiver kept of the signer.
pub const RULE_COUNTER: Rule = Rule::field("commands/counter");
/// A command a receiver with a clock finds expired or from the future.
pub const RULE_LATE: Rule = Rule::field("commands/late");
/// A guarded leaf's grant is stale: it obeys nobody until a fresh one.
pub const RULE_STALE: Rule = Rule::field("commands/stale");

/// The body's fields below 256 that 0.6 defines.
const FIELDS: [u16; 11] = [1, 2, 3, 4, 6, 7, 10, 11, 13, 14, 15];

/// A command read from its envelope and checked for its form.
#[derive(Clone, Debug)]
pub struct Command<'a> {
    pub envelope: Envelope<'a>,
    pub kind: u64,
    pub group: GroupId,
    pub signer: KeyHash,
    pub n: u64,
    pub time_ms: u64,
    pub expires_ms: u64,
    pub to: DeviceId,
    pub id: [u8; 16],
    pub nonce: Option<[u8; 16]>,
    pub epoch: Option<u64>,
    pub sealed: Option<&'a [u8]>,
}

fn fixed<const N: usize>(v: Option<&Value<'_>>, rule: Rule) -> Result<[u8; N], Rule> {
    v.and_then(Value::as_bytes).and_then(|b| b.try_into().ok()).ok_or(rule)
}

impl<'a> Command<'a> {
    /// Reads a command from its envelope: the size, the envelope and the
    /// profile, each field's row (no critical field 0.6 does not define, so
    /// no `class` and no `signer2`), the lifetime within 30 s, `epoch`
    /// exactly with `sealed`, and `sealed` only on a type with orders. The
    /// signature's form is checked here, the signature itself by
    /// [`accept_member`] or [`accept_leaf`], which know the signer's key.
    pub fn read(b: &'a [u8]) -> Result<Command<'a>, Rule> {
        let e = Envelope::parse_limited(b, MAX_PASTE_BODY)?;
        let m = &e.map;
        if m.as_map().unwrap_or(&[]).iter().any(|(k, _)| *k < 256 && !FIELDS.contains(k)) {
            return Err(Rule::FORM_CRITICAL);
        }
        let kind = m.get(1).and_then(Value::as_uint).filter(|t| (1..=10).contains(t)).ok_or(RULE_TYPE)?;
        let max = if kind == COMMAND_PASTE { MAX_PASTE_BODY } else { MAX_BODY };
        if e.body.len() > max {
            return Err(Rule::ENV_SIZE);
        }
        sig::check_form(e.sig)?;
        let group = DeviceId(fixed(m.get(2), RULE_GROUP)?);
        let signer = KeyHash(fixed(m.get(3), RULE_SIGNER)?);
        let n = m.get(4).and_then(Value::as_uint).filter(|n| *n >= 1).ok_or(RULE_N)?;
        let time_ms = m.get(6).and_then(Value::as_uint).ok_or(RULE_TIME)?;
        let expires_ms = m.get(7).and_then(Value::as_uint).ok_or(RULE_EXPIRES)?;
        if expires_ms <= time_ms || expires_ms.saturating_sub(time_ms) > LIFETIME_MS {
            return Err(RULE_EXPIRES);
        }
        let to = DeviceId(fixed(m.get(10), RULE_TO)?);
        let id = fixed(m.get(11), RULE_ID)?;
        let nonce = m.get(13).map(|v| fixed(Some(v), RULE_NONCE)).transpose()?;
        let epoch = match m.get(14) {
            None => None,
            Some(Value::Uint(0)) => return Err(Rule::FORM_DEFAULT),
            Some(v) => Some(v.as_uint().ok_or(RULE_EPOCH)?),
        };
        let sealed = match m.get(15) {
            None => None,
            Some(v) => Some(v.as_bytes().filter(|s| s.len() >= crate::seal::OVERHEAD).ok_or(RULE_SEALED)?),
        };
        if sealed.is_some() != epoch.is_some() {
            return Err(RULE_EPOCH);
        }
        if sealed.is_some() && !has_orders(kind) {
            return Err(RULE_SEALED);
        }
        Ok(Command { envelope: e, kind, group, signer, n, time_ms, expires_ms, to, id, nonce, epoch, sealed })
    }

    /// The associated data of the sealed orders: the label, a zero byte and
    /// the body without field 15.
    fn seal_ad(&self) -> Vec<u8> {
        let rest: Vec<(u16, Value<'_>)> =
            self.envelope.map.as_map().unwrap_or(&[]).iter().filter(|(k, _)| *k != 15).cloned().collect();
        sig::message(sig::LABEL_COMMAND, &Value::Map(rest).encode())
    }

    /// Opens the sealed orders with the receiver's key store and checks
    /// them against the type's rows; a type without orders gives None.
    fn open(&self, store: &dyn KeyStore) -> Result<Option<Vec<u8>>, Rule> {
        if !has_orders(self.kind) {
            return Ok(None);
        }
        let (Some(sealed), Some(epoch)) = (self.sealed, self.epoch) else { return Err(RULE_SEALED) };
        let secret = store.sealing(epoch).ok_or(RULE_EPOCH)?;
        let plain = crate::seal::open(&secret, &self.seal_ad(), sealed).map_err(|_| RULE_SEALED)?;
        let max = if self.kind == COMMAND_PASTE { MAX_PASTE_BODY } else { MAX_BODY };
        if plain.len() > max {
            return Err(Rule::ENV_SIZE);
        }
        orders::check(self.kind, &plain)?;
        Ok(Some(plain))
    }

    /// Checks what a receiver with a clock checks: the command is not
    /// expired, nor from the future, on now_ms.
    fn in_time(&self, now_ms: Option<u64>) -> Result<(), Rule> {
        match now_ms {
            Some(now)
                if now > self.expires_ms.saturating_add(SKEW_MS) || self.time_ms > now.saturating_add(SKEW_MS) =>
            {
                Err(RULE_LATE)
            }
            _ => Ok(()),
        }
    }
}

/// What a commander writes: the receiver, the type, the counter, the clock,
/// the guarded leaf's one-time number, and the orders (a map in the profile)
/// with the receiver's epoch and sealing key.
#[derive(Clone, Debug)]
pub struct Draft<'a> {
    pub kind: u64,
    pub group: GroupId,
    pub to: DeviceId,
    pub n: u64,
    pub time_ms: u64,
    pub nonce: Option<[u8; 16]>,
    pub orders: Option<&'a [u8]>,
    /// The receiver's statement epoch and sealing key, for the orders.
    pub seal_to: Option<(u64, &'a [u8])>,
}

/// Writes and signs a command: its ID random, its lifetime 30 s, its orders
/// sealed to the receiver. The envelope's bytes.
pub fn make(d: &Draft<'_>, signer: &dyn ExternalKey) -> Result<Vec<u8>, Error> {
    let mut id = [0u8; 16];
    getrandom::fill(&mut id).map_err(|_| Error::msg("commands: the system has no randomness"))?;
    if has_orders(d.kind) != d.orders.is_some() {
        return Err(Error::msg("a command of this type has orders exactly when it is one with orders"));
    }
    if let Some(o) = d.orders {
        orders::check(d.kind, o).map_err(|r| Error::msg(alloc::format!("the orders break {r}")))?;
    }
    let signer_hash = Key::es256(signer.public()).hash();
    let mut m: Vec<(u16, Value<'_>)> = alloc::vec![
        (1, Value::Uint(d.kind)),
        (2, Value::Bytes(&d.group.0)),
        (3, Value::Bytes(&signer_hash.0)),
        (4, Value::Uint(d.n)),
        (6, Value::Uint(d.time_ms)),
        (7, Value::Uint(d.time_ms.saturating_add(LIFETIME_MS))),
        (10, Value::Bytes(&d.to.0)),
        (11, Value::Bytes(&id)),
    ];
    if let Some(n) = &d.nonce {
        m.push((13, Value::Bytes(n)));
    }
    let sealed;
    if let Some(o) = d.orders {
        let (epoch, key) = d.seal_to.ok_or_else(|| Error::msg("orders are sealed to the receiver's key"))?;
        m.push((14, Value::Uint(epoch)));
        let ad = sig::message(sig::LABEL_COMMAND, &Value::Map(m.clone()).encode());
        sealed = crate::seal::seal(key, &ad, o)?;
        m.push((15, Value::Bytes(&sealed)));
    }
    let body = Value::Map(m).encode();
    let s = rkey::sign_es256(signer, sig::LABEL_COMMAND, &body)?;
    Ok(envelope::write(&body, &s, None))
}

/// The last counter of each signer a receiver took, saved across restarts.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct Counters(pub BTreeMap<KeyHash, u64>);

impl Counters {
    fn check(&self, signer: &KeyHash, n: u64) -> Result<(), Rule> {
        if self.0.get(signer).is_some_and(|last| n <= *last) { Err(RULE_COUNTER) } else { Ok(()) }
    }

    fn take(&mut self, signer: KeyHash, n: u64) {
        self.0.insert(signer, n);
    }

    /// As bytes to save: an array of `[key hash, n]`, sorted.
    pub fn encode(&self) -> Vec<u8> {
        Value::Array(
            self.0.iter().map(|(k, n)| Value::Array(alloc::vec![Value::Bytes(&k.0), Value::Uint(*n)])).collect(),
        )
        .encode()
    }

    pub fn decode(b: &[u8]) -> Result<Counters, Rule> {
        let bad = Rule::field("counters/shape");
        let mut out = BTreeMap::new();
        for e in cbor::decode(b)?.as_array().ok_or(bad)? {
            match e.as_array() {
                Some([Value::Bytes(k), Value::Uint(n)]) => {
                    out.insert(KeyHash::from_slice(k).ok_or(bad)?, *n);
                }
                _ => return Err(bad),
            }
        }
        Ok(Counters(out))
    }
}

/// The keys a set's records name, by their hashes: its first root, the
/// new roots of claims, and the admin and member keys of device records.
/// A member builds it once when its set changes, so a command's signer is
/// found by its hash, not by walking the records. Whether that key may
/// command is the state's to say.
#[derive(Clone, Debug, Default)]
pub struct Keys(BTreeMap<KeyHash, Key>);

impl Keys {
    pub fn of(set: &RecordSet) -> Keys {
        let mut m = BTreeMap::new();
        let root = set.root().clone();
        m.insert(root.hash(), root);
        for id in set.ids() {
            let Some(r) = set.get(id) else { continue };
            match &r.body().kind {
                Kind::Device(d) => {
                    for k in d.admin.iter().chain(core::iter::once(&d.key)) {
                        m.entry(k.hash()).or_insert_with(|| k.clone());
                    }
                }
                Kind::Recovery { root, .. } => {
                    m.entry(root.hash()).or_insert_with(|| root.clone());
                }
                _ => {}
            }
        }
        Keys(m)
    }

    /// The key with hash h.
    pub fn get(&self, h: &KeyHash) -> Option<&Key> {
        self.0.get(h)
    }
}

/// A member receiving a command: who it is, the group's state and records,
/// and its clock.
pub struct Member<'a> {
    pub me: DeviceId,
    pub state: &'a State,
    /// The keys of the member's set ([`Keys::of`]).
    pub keys: &'a Keys,
    pub now_ms: Option<u64>,
}

/// A command refused: the rule, and whether the receiver answers it with
/// `result` ([`refusal`]). Every refusal before the signature verified is
/// [`RULE_SIGNER`] and unanswered, so a stranger learns nothing; every one
/// after it is answered with its own rule.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Refusal {
    pub rule: Rule,
    pub answer: bool,
}

impl Refusal {
    /// A refusal before the signature verified.
    pub const SILENT: Refusal = Refusal { rule: RULE_SIGNER, answer: false };

    fn signed(rule: Rule) -> Refusal {
        Refusal { rule, answer: true }
    }
}

/// Takes a command at a member: signed by the key it names (an unknown key
/// or a bad signature is [`Refusal::SILENT`]), then for its group and for
/// this device, from a signer that may command (the current root, or an
/// admin whose record lists the type, by [`State::may_command`]), in time,
/// above the signer's last counter, and with its orders sealed to this
/// device and within their rows. On success it keeps the counter and gives
/// the opened orders.
pub fn accept_member(
    c: &Command<'_>,
    at: &Member<'_>,
    counters: &mut Counters,
    store: &dyn KeyStore,
) -> Result<Option<Vec<u8>>, Refusal> {
    let key = at.keys.get(&c.signer).ok_or(Refusal::SILENT)?;
    c.envelope.verify(&key.public, sig::LABEL_COMMAND).map_err(|_| Refusal::SILENT)?;
    let refuse = |r| Err(Refusal::signed(r));
    if c.group != at.state.group {
        return refuse(RULE_GROUP);
    }
    if c.to != at.me {
        return refuse(RULE_TO);
    }
    if !at.state.may_command(&c.signer) {
        return refuse(RULE_SIGNER);
    }
    if !at.state.is_root(&c.signer) {
        let listed = at
            .state
            .devices
            .iter()
            .any(|d| d.admin.as_ref() == Some(&c.signer) && d.commands & command_bit(c.kind) != 0);
        if !listed {
            return refuse(RULE_RIGHT);
        }
    }
    c.in_time(at.now_ms).map_err(Refusal::signed)?;
    counters.check(&c.signer, c.n).map_err(Refusal::signed)?;
    let orders = c.open(store).map_err(Refusal::signed)?;
    counters.take(c.signer, c.n);
    Ok(orders)
}

/// A leaf receiving a command: its ID, its group, the grant it keeps and
/// whether that grant is stale ([`stale`]), and its clock if it has one.
pub struct Leaf<'a> {
    pub me: DeviceId,
    pub group: GroupId,
    pub kept: &'a Kept,
    pub stale: bool,
    pub now_ms: Option<u64>,
}

/// Whether a leaf's grant is stale: a guarded leaf's grant lives `life_ms`
/// (35 days when it does not say) on the leaf's running time since it took
/// the grant; an ordinary leaf's never goes stale.
pub fn stale(guarded: bool, life_ms: Option<u64>, ran_ms: u64) -> bool {
    guarded && ran_ms >= life_ms.unwrap_or(DEFAULT_LIFE_MS)
}

/// Takes a command at a leaf: from a commander of its grant, signed by
/// that key (else [`Refusal::SILENT`]), for its group and for it, in time,
/// above the commander's last counter, with its orders sealed to the leaf.
/// A guarded leaf also wants a grant that is not stale and the one-time
/// number it gave that commander; the number is used up only by a signed
/// command that shows it, after its counter passed, so an old command sent
/// again leaves it as it is.
pub fn accept_leaf(
    c: &Command<'_>,
    at: &Leaf<'_>,
    counters: &mut Counters,
    nonces: &mut Nonces,
    store: &dyn KeyStore,
) -> Result<Option<Vec<u8>>, Refusal> {
    // A leaf that holds a fork of its root obeys nobody (`Kept::fork`).
    let point = at.kept.commander(&c.signer).filter(|_| !at.kept.forked).ok_or(Refusal::SILENT)?;
    c.envelope.verify(point, sig::LABEL_COMMAND).map_err(|_| Refusal::SILENT)?;
    let refuse = |r| Err(Refusal::signed(r));
    if c.group != at.group {
        return refuse(RULE_GROUP);
    }
    if c.to != at.me {
        return refuse(RULE_TO);
    }
    c.in_time(at.now_ms).map_err(Refusal::signed)?;
    counters.check(&c.signer, c.n).map_err(Refusal::signed)?;
    if at.kept.guarded {
        if at.stale {
            return refuse(RULE_STALE);
        }
        let n = c.nonce.ok_or(Refusal::signed(RULE_NONCE))?;
        if !nonces.take(&c.signer, &n) {
            return refuse(RULE_NONCE);
        }
    }
    let orders = c.open(store).map_err(Refusal::signed)?;
    counters.take(c.signer, c.n);
    Ok(orders)
}

/// The most one-time numbers a guarded leaf has out at once.
pub const MAX_NONCES: usize = 16;

/// The one-time numbers a guarded leaf gave out: one per commander, for
/// its next command; a new one replaces the old, and a number is used up
/// by the first signed command that shows it. They live in memory only: after a
/// restart the commander asks again.
#[derive(Clone, Debug, Default)]
pub struct Nonces {
    out: BTreeMap<KeyHash, ([u8; 16], u64)>,
    count: u64,
}

impl Nonces {
    /// A new number for the commander peer.
    pub fn issue(&mut self, peer: &KeyHash) -> Result<[u8; 16], Error> {
        let mut n = [0u8; 16];
        getrandom::fill(&mut n).map_err(|_| Error::msg("commands: the system has no randomness"))?;
        self.count = self.count.saturating_add(1);
        self.out.insert(*peer, (n, self.count));
        while self.out.len() > MAX_NONCES {
            let Some(oldest) = self.out.iter().min_by_key(|(_, (_, c))| *c).map(|(k, _)| *k) else { break };
            self.out.remove(&oldest);
        }
        Ok(n)
    }

    /// Uses up peer's number when n is it; reports whether it was. Another
    /// number leaves it as it is.
    pub fn take(&mut self, peer: &KeyHash, n: &[u8; 16]) -> bool {
        if self.out.get(peer).is_some_and(|(m, _)| m == n) {
            self.out.remove(peer);
            true
        } else {
            false
        }
    }
}

/// Message `nonce` (t 21): from a leaf with its number, or to a leaf
/// without one ("give me one").
pub fn nonce_message(n: Option<&[u8; 16]>) -> Vec<u8> {
    let mut m = alloc::vec![(frame::FIELD_T, Value::Uint(T_NONCE))];
    if let Some(n) = n {
        m.push((2, Value::Bytes(n)));
    }
    frame::write(&Value::Map(m))
}

/// `result` status 2: refused.
pub const STATUS_REFUSED: u64 = 2;

/// Message `result` (t 10) to the sender of a command this device refused:
/// the command's ID, this device, status refused, and the rule's name as
/// the reason, so the sender's app can say why (`commands/late`: one of the
/// two clocks is off). None for a refusal before the signature verified: a
/// stranger gets no answer.
pub fn refusal(id: &[u8; 16], me: &DeviceId, r: Refusal) -> Option<Vec<u8>> {
    let rule = r.rule;
    r.answer.then(|| {
        frame::write(&Value::Map(alloc::vec![
            (frame::FIELD_T, Value::Uint(crate::msg::tables::T_RESULT)),
            (2, Value::Bytes(id)),
            (3, Value::Bytes(&me.0)),
            (4, Value::Uint(STATUS_REFUSED)),
            (5, Value::Text(rule.name())),
        ]))
    })
}

/// Message `command` (t 9) carrying a command's envelope.
pub fn message(envelope: &[u8]) -> Result<Vec<u8>, Rule> {
    let v = cbor::decode(envelope)?;
    Ok(frame::write(&Value::Map(alloc::vec![(frame::FIELD_T, Value::Uint(T_COMMAND)), (2, v)])))
}
