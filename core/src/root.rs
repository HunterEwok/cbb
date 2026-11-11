// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! What the group's current root signs about the group itself, with its key
//! held outside the core (the phone's Secure Enclave, StrongBox or OP-TEE):
//! the settings record that sets how long a claim waits and which keys may
//! be admins, the handover that lets an admin's claim take effect at once,
//! and the recovery key's admin CA and record, or its removal
//! (docs/protocol.md, section 10, "Handing the group over" and "The
//! recovery key"). The rules are those of the phone kits' PhoneGroup and
//! the service's admin: only the current root signs them, a settings record
//! keeps what it does not change, and the record set checks the rest when
//! the record is added.

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use p256::elliptic_curve::sec1::ToSec1Point as _;

use crate::authority::{self, Body, Hash, Record};
use crate::certs::{self, Cert, DeviceId};
use crate::error::{Error, Result};
use crate::group::Records;
use crate::identity;
use crate::issue;
use crate::manage::Signer;
use crate::recovery;

/// What a settings record changes; it keeps the other from the root's
/// newest settings record.
pub enum Setting<'a> {
    /// How long a claim from a lost root waits on each member, in
    /// milliseconds, from 0 to authority::MAX_DELAY.
    Delay(i64),
    /// Which keys may be the root, an admin or a hub: one of
    /// authority::KEY_LEVELS.
    KeyLevel(&'a str),
}

/// Fails unless s is the group's current root.
fn current_root(rs: &Records, s: &Signer) -> Result<()> {
    if rs.state().roots.last() == Some(&s.hash()) {
        Ok(())
    } else {
        Err(Error::msg("only the group's current root signs this"))
    }
}

fn body(s: &Signer, kind: &str, now_ms: i64) -> Body {
    Body {
        v: 2,
        alg: authority::ALG_ES256.into(),
        kind: kind.into(),
        signer: s.hash(),
        time_ms: now_ms,
        ..Default::default()
    }
}

fn sign(rs: &Records, s: &Signer, b: Body) -> Result<Record> {
    let body = rs.next_body(b)?;
    let sig = identity::sign_external(s.key, &body)?;
    Ok(Record::new(body, sig, None))
}

/// What the newest settings record of the root whose key hash is root set:
/// the delay and the key level, which a new one keeps.
pub fn settings_of(rs: &Records, root: &Hash) -> (Option<i64>, String) {
    rs.all()
        .iter()
        .filter_map(|r| Body::parse(&r.body).ok())
        .filter(|b| b.kind == authority::TYPE_SETTINGS && b.signer == *root)
        .max_by_key(|b| b.seq)
        .map(|b| (b.takeover_delay_ms, b.key_level))
        .unwrap_or_default()
}

/// Whether a device whose keys live in store may hold the root's or an
/// admin's key at level, the user consenting to a file: as manage's.
fn level_allows(level: &str, store: &str) -> bool {
    match store {
        "rootless" => false,
        "proven" => true,
        "file" => level == "files",
        _ => level != "proven",
    }
}

/// The settings record that changes what set says, signed by the current
/// root s. A key level that the root's own device (s.me) does not pass is
/// refused; the admins below it stay until the user removes them
/// (below_level lists them).
pub fn settings(rs: &Records, s: &Signer, set: &Setting, now_ms: i64) -> Result<Record> {
    current_root(rs, s)?;
    let (delay, level) = settings_of(rs, &s.hash());
    let mut b = body(s, authority::TYPE_SETTINGS, now_ms);
    match set {
        Setting::Delay(ms) => {
            if !(0..=authority::MAX_DELAY).contains(ms) {
                return Err(Error::msg("a claim waits from 0 to 7 days"));
            }
            b.takeover_delay_ms = Some(*ms);
            b.key_level = level;
        }
        Setting::KeyLevel(l) => {
            if !authority::KEY_LEVELS.contains(l) {
                return Err(Error::msg("the key level is proven, hardware or files"));
            }
            let own = rs.devices().into_iter().find(|d| d.id == s.me).map(|d| d.store);
            if !level_allows(l, own.as_deref().unwrap_or("hardware")) {
                return Err(Error::msg("this phone's own keys are below that key level"));
            }
            b.takeover_delay_ms = delay;
            b.key_level = (*l).to_string();
        }
    }
    sign(rs, s, b)
}

/// The admins and hubs other than me whose keys level would not let in, by
/// device ID: they stay until the user removes them.
pub fn below_level(rs: &Records, me: &str, level: &str) -> Vec<String> {
    let hubs = rs.state().hubs;
    rs.devices()
        .into_iter()
        .filter(|d| (d.admin || hubs.contains(&d.id)) && d.id != me && !level_allows(level, &d.store))
        .map(|d| d.id)
        .collect()
}

/// The handover to the admin device, signed by the current root s: it names
/// the device's admin key, so that its claim takes effect at once.
pub fn hand_over(rs: &Records, s: &Signer, device: &str, now_ms: i64) -> Result<Record> {
    current_root(rs, s)?;
    if device == s.me {
        return Err(Error::msg("this phone is the group's root already"));
    }
    let d = rs.devices().into_iter().find(|d| d.id == device).ok_or_else(|| Error::msg("unknown device"))?;
    let admin = d
        .admin_key
        .filter(|_| d.admin && !d.frozen)
        .ok_or_else(|| Error::msg("the device is no admin: make it one first, then hand the group over"))?;
    let mut b = body(s, authority::TYPE_HANDOVER, now_ms);
    b.admin = Some(Hash(admin));
    sign(rs, s, b)
}

/// The admin CA for the recovery key point (uncompressed), under the
/// current root s, and the recovery record that names it, which replaces
/// the recovery key before it. Its CN names a random ID, since the key has
/// no device.
pub fn recovery_for(rs: &Records, s: &Signer, point: &[u8], now_ms: i64) -> Result<(Vec<u8>, Record)> {
    current_root(rs, s)?;
    let ca = issue::admin_ca(&DeviceId::random(), point, s.ca, now_ms / 1000, &mut |tbs| {
        identity::sign_external(s.key, tbs)
    })?;
    let mut b = body(s, authority::TYPE_RECOVERY, now_ms);
    b.admin = Some(Hash(Cert::parse(&ca)?.key_hash()));
    b.cert = ca.clone();
    Ok((ca, sign(rs, s, b)?))
}

/// A new recovery key made by the current root s: the record to add and
/// send, and the sheet to show once. Nothing of the key stays in the core.
pub struct NewRecovery {
    pub record: Record,
    /// The sheet's QR code: the key, its admin CA and the group's tag.
    pub qr: String,
    /// The key alone, in groups of four characters.
    pub text: String,
}

/// Makes the group's recovery key on the current root s (recovery_for with
/// a new key).
pub fn make_recovery(rs: &Records, s: &Signer, now_ms: i64) -> Result<NewRecovery> {
    let key = recovery::secret_key(&certs::random_bytes::<32>())
        .ok_or_else(|| Error::msg("the recovery key cannot be made"))?;
    let point = key.public_key().to_sec1_point(false).as_bytes().to_vec();
    let (ca, record) = recovery_for(rs, s, &point, now_ms)?;
    let qr = recovery::qr(&key, &ca, rs.tag()).map_err(|r| Error::msg(r.message()))?;
    Ok(NewRecovery { record, qr, text: recovery::text(&key) })
}

/// The removal of the group's recovery key, signed by the current root s: a
/// revocation of its key.
pub fn remove_recovery(rs: &Records, s: &Signer, now_ms: i64) -> Result<Record> {
    current_root(rs, s)?;
    let k = rs.state().recovery.ok_or_else(|| Error::msg("the group has no recovery key"))?;
    let mut b = body(s, authority::TYPE_REVOKE, now_ms);
    b.keys = alloc::vec![k];
    sign(rs, s, b)
}

/// What the group's records set that the root's settings show.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct View {
    /// How long a claim from a lost root waits, in milliseconds.
    pub delay_ms: i64,
    /// The key level: proven, hardware or files.
    pub key_level: String,
    /// Whether the group has a recovery key.
    pub recovery: bool,
    /// The device the current root handed the group to, if any.
    pub handed_to: Option<String>,
}

/// The settings the group's records hold now, under its current root.
pub fn view(rs: &Records) -> View {
    let st = rs.state();
    let delay_ms = st.roots.last().and_then(|r| settings_of(rs, r).0).unwrap_or(authority::DEFAULT_DELAY);
    let key_level = if st.key_level.is_empty() { "hardware".to_string() } else { st.key_level.clone() };
    let handed_to =
        rs.handed_to().and_then(|k| rs.devices().into_iter().find(|d| d.admin_key == Some(k)).map(|d| d.id));
    View { delay_ms, key_level, recovery: st.recovery.is_some(), handed_to }
}

#[cfg(test)]
#[path = "root/tests.rs"]
mod tests;
