// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! What an admin's app signs about another device of its group, with the
//! admin key or the root's key held outside the core (the Aurora app's key
//! in OP-TEE): a removal, a new name or a thaw as a record
//! (docs/protocol.md, section 10), and a mute or an unmute as a command
//! (section 15). The rules are those of the phone kits' PhoneGroup: an
//! admin removes any device but itself and the root's, renames one that
//! the root did not record (a root's record beats an admin's), thaws a
//! frozen admin; the record set checks the rest when the record is added.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::authority::{self, Body, Hash, Record};
use crate::certs::{self, Cert, KeyHash};
use crate::command::{self, Command};
use crate::error::{Error, Result};
use crate::group::{Device, Records};
use crate::identity::{self, ExternalKey};

/// A change to a device of the group, as a record.
pub enum Change<'a> {
    /// Remove it: revoke every key it had, its admin key among them.
    Remove,
    /// Give it another name, which is trimmed first.
    Rename(&'a str),
    /// End every freeze of a frozen admin.
    Thaw,
}

/// A command for a device of the group.
pub enum Order {
    /// Keep its copies from the group for so many milliseconds, 0 for until
    /// an unmute.
    Mute(i64),
    Unmute,
}

/// The signer: the CA whose key signs (an admin CA, or the group's root),
/// the key, and this phone's device ID.
pub struct Signer<'a> {
    pub ca: &'a Cert,
    pub key: &'a dyn ExternalKey,
    pub me: &'a str,
}

impl Signer<'_> {
    fn hash(&self) -> Hash {
        Hash(self.ca.key_hash())
    }

    /// The admin CA that goes with what it signs: none for the root.
    fn chain(&self, rs: &Records) -> Option<Vec<u8>> {
        (!rs.state().roots.contains(&self.hash())).then(|| self.ca.der.clone())
    }

    /// Fails unless the signer is the group's root or an admin that is not
    /// frozen.
    fn check(&self, rs: &Records) -> Result<()> {
        let h = self.hash();
        if rs.state().roots.contains(&h) || rs.devices().iter().any(|d| d.admin && d.admin_key == Some(h.0)) {
            Ok(())
        } else {
            Err(Error::msg("this phone is no admin of the group"))
        }
    }
}

fn find(rs: &Records, device: &str) -> Result<Device> {
    rs.devices().into_iter().find(|d| d.id == device).ok_or_else(|| Error::msg("unknown device"))
}

/// Whether a root's own key signed a device record of device.
fn root_recorded(rs: &Records, device: &str) -> bool {
    rs.all().iter().any(|r| {
        r.chain.is_empty() && Body::parse(&r.body).is_ok_and(|b| b.kind == authority::TYPE_DEVICE && b.device == device)
    })
}

/// The body of a change, before next_body fills in its place in the
/// signer's history.
fn change_body(rs: &Records, s: &Signer, device: &str, c: &Change, now_ms: i64) -> Result<Body> {
    let d = find(rs, device)?;
    let mut b =
        Body { v: 2, alg: authority::ALG_ES256.into(), signer: s.hash(), time_ms: now_ms, ..Default::default() };
    match c {
        Change::Remove => {
            if device == s.me {
                return Err(Error::msg("this phone cannot remove itself"));
            }
            if rs.root_member().is_some_and(|(r, _)| r == device) {
                return Err(Error::msg("the root's phone is removed by taking the group over"));
            }
            let mut keys: Vec<KeyHash> = d.keys.clone();
            if let Some(a) = d.admin_key
                && !keys.contains(&a)
            {
                keys.push(a);
            }
            b.kind = authority::TYPE_REVOKE.into();
            b.keys = keys.into_iter().map(Hash).collect();
        }
        Change::Rename(name) => {
            let name = name.trim();
            if !authority::valid_name(name) {
                return Err(Error::msg("a name has 1 to 64 bytes and no control characters"));
            }
            let root = rs.state().roots.contains(&s.hash());
            if !root && root_recorded(rs, device) {
                // A root's device record beats an admin's (section 10).
                return Err(Error::msg("the group's root recorded this device, so only the root renames it"));
            }
            let holds_root = root && device == s.me && rs.root_member().is_some_and(|(r, _)| r == device);
            b.kind = authority::TYPE_DEVICE.into();
            b.device = d.id.clone();
            b.name = name.to_string();
            b.role = d.role.clone();
            b.os = d.os.clone();
            b.key = Some(Hash(d.key));
            b.admin = d.admin_key.map(Hash);
            if d.admin_key.is_some() {
                b.powers = d.powers.clone();
                b.commands = d.commands.clone();
            }
            b.store = d.store.clone();
            b.hardware = d.kind.clone();
            b.proof = d.proof.clone();
            b.seal = d.seal.clone();
            b.forward_only = d.forward_only;
            b.holds_root = holds_root;
        }
        Change::Thaw => {
            let freezes = d.admin_key.map(|a| rs.freezes_of(&a)).unwrap_or_default();
            if !d.frozen || freezes.is_empty() {
                return Err(Error::msg("the device is not frozen"));
            }
            b.kind = authority::TYPE_THAW.into();
            b.records = freezes;
        }
    }
    Ok(b)
}

/// Signs the record of a change to device; the caller adds it to the
/// records and sends it to the group. now_ms is the wall clock in Unix
/// milliseconds.
pub fn change(rs: &Records, s: &Signer, device: &str, c: &Change, now_ms: i64) -> Result<Record> {
    s.check(rs)?;
    let body = rs.next_body(change_body(rs, s, device, c, now_ms)?)?;
    let sig = identity::sign_external(s.key, &body)?;
    Ok(Record::new(body, sig, s.chain(rs)))
}

/// Signs a command for device, sealed to its key for sealed messages when
/// its record names one (docs/protocol.md, section 15, "Sealed commands");
/// the caller sends it and waits for the result.
pub fn order(rs: &Records, s: &Signer, device: &str, o: &Order, now_ms: i64) -> Result<Record> {
    s.check(rs)?;
    let d = find(rs, device)?;
    if device == s.me {
        return Err(Error::msg("a command goes to another device"));
    }
    let mut id = [0u8; 16];
    getrandom::fill(&mut id).map_err(|_| Error::msg("the system has no randomness"))?;
    let mut m = serde_json::Map::new();
    let mut put = |k: &str, v: serde_json::Value| {
        m.insert(String::from(k), v);
    };
    put("v", 1.into());
    put("group", rs.tag().into());
    put("by", s.me.into());
    put("to", device.into());
    put("id", certs::hex(&id).into());
    put("time_ms", now_ms.into());
    put("expires_ms", now_ms.saturating_add(command::COMMAND_LIFETIME_MS).into());
    match o {
        Order::Mute(ms) => {
            if !(0..=command::MAX_MUTE_MS).contains(ms) {
                return Err(Error::msg(format!("a mute lasts from 0 to {} ms", command::MAX_MUTE_MS)));
            }
            put("type", "mute".into());
            if *ms > 0 {
                put("for_ms", (*ms).into());
            }
        }
        Order::Unmute => put("type", "unmute".into()),
    }
    let mut body = Vec::new();
    crate::strict::write_canonical(&mut body, &serde_json::Value::Object(m));
    Command::parse(&body)?;
    if !d.seal.is_empty() {
        body = Command::seal_body(&body, &d.seal)?;
    }
    let sig = identity::sign_external(s.key, &body)?;
    Ok(Record::new(body, sig, s.chain(rs)))
}

#[cfg(test)]
#[path = "manage/tests.rs"]
mod tests;
