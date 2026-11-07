// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! What an admin's app signs about another device of its group, with the
//! admin key or the root's key held outside the core (the Aurora app's key
//! in OP-TEE): a removal, a new name or a thaw as a record
//! (docs/protocol.md, section 10), and a mute or an unmute as a command
//! (section 15), a computer made an admin, and a renewed member
//! certificate. The rules are those of the phone kits' PhoneGroup: an
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
use crate::issue;

/// A change to a device of the group, as a record.
pub enum Change<'a> {
    /// Remove it: revoke every key it had, its admin key among them.
    Remove,
    /// Give it another name, which is trimmed first.
    Rename(&'a str),
    /// End every freeze of a frozen admin.
    Thaw,
    /// As the root, void the records an alert names: both histories of a
    /// key, or a claim (docs/protocol.md, section 10, "Stopping the
    /// exchange"). It names no device.
    Resolve(Vec<Hash>),
}

/// A command for a device of the group.
pub enum Order {
    /// Keep its copies from the group for so many milliseconds, 0 for until
    /// an unmute.
    Mute(i64),
    Unmute,
    /// Be a hub of the group, or stop being one, by the hub order
    /// (docs/protocol.md, section 15): its forwarder, addresses and the
    /// clients handed over, or `stop`.
    Hub(serde_json::Value),
    /// Turn sync away from home off; only its own user turns it on again.
    AwayOff,
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
    let mut b =
        Body { v: 2, alg: authority::ALG_ES256.into(), signer: s.hash(), time_ms: now_ms, ..Default::default() };
    if let Change::Resolve(records) = c {
        if !rs.state().roots.contains(&s.hash()) {
            return Err(Error::msg("only the group's root decides"));
        }
        if records.is_empty() {
            return Err(Error::msg("a resolve names the records it voids"));
        }
        b.kind = authority::TYPE_RESOLVE.into();
        b.records = records.clone();
        return Ok(b);
    }
    let d = find(rs, device)?;
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
        Change::Resolve(_) => {}
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
        Order::AwayOff => put("type", "away-off".into()),
        Order::Hub(h) => {
            put("type", "hub".into());
            put("hub", h.clone());
        }
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

/// What the group's records stop and what ends it, for the app's card
/// (docs/protocol.md, section 10, "Stopping the exchange"), as the phone
/// kits' GroupAlert: the group's stop, each conflict, each claim that waits
/// or stops the group, and records of a later version.
#[derive(serde::Serialize, Debug, PartialEq)]
pub struct Alert {
    /// stopped (every member exchanges records only), secrets_stopped,
    /// two_histories (the root voids both: records), admins (admins removed
    /// or froze each other: the root removes one of devices), claims (two
    /// claims: the root voids one or both), claim_pending (a claim waits
    /// left_ms unless the root voids it), claim_stopped (the group stops
    /// until the root voids the claim), newer (update the app: count).
    pub kind: &'static str,
    /// The names and IDs of the devices involved, those known here.
    pub names: Vec<String>,
    pub devices: Vec<String>,
    /// The records a resolve names to end it.
    pub records: Vec<Hash>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub left_ms: Option<i64>,
    #[serde(skip_serializing_if = "is_zero")]
    pub count: usize,
}

fn is_zero(n: &usize) -> bool {
    *n == 0
}

/// The alerts of the records' state, in the order the apps show them.
pub fn alerts(rs: &Records) -> Vec<Alert> {
    let st = rs.state();
    let devices = rs.devices();
    // The device of a signer's key: whose admin key it is, or the root's
    // own device for a root's key.
    let involved = |keys: &[Hash]| -> (Vec<String>, Vec<String>) {
        keys.iter()
            .filter_map(|k| {
                devices.iter().find(|d| d.admin_key == Some(k.0)).or_else(|| {
                    if st.roots.contains(k) { devices.iter().find(|d| d.id == st.root_device) } else { None }
                })
            })
            .map(|d| (d.name.clone(), d.id.clone()))
            .unzip()
    };
    let alert = |kind, (names, devices): (Vec<String>, Vec<String>), records: Vec<Hash>| Alert {
        kind,
        names,
        devices,
        records,
        left_ms: None,
        count: 0,
    };
    let mut out = Vec::new();
    match st.stop.as_str() {
        "full" => out.push(alert("stopped", Default::default(), Vec::new())),
        "secrets" => out.push(alert("secrets_stopped", Default::default(), Vec::new())),
        _ => {}
    }
    for c in &st.conflicts {
        let kind = match c.kind {
            authority::CONFLICT_TWO_HISTORIES => "two_histories",
            authority::CONFLICT_ADMINS => "admins",
            authority::CONFLICT_CLAIMS => "claims",
            _ => continue,
        };
        out.push(alert(kind, involved(&c.signers), c.records.clone()));
    }
    for c in &st.claims {
        match c.state {
            "pending" => out.push(Alert {
                left_ms: Some(c.left_ms),
                ..alert("claim_pending", involved(&[c.claimant]), alloc::vec![c.record])
            }),
            "disputed" | "competing" => {
                out.push(alert("claim_stopped", involved(&[c.claimant]), alloc::vec![c.record]))
            }
            _ => {}
        }
    }
    if !st.newer.is_empty() {
        out.push(Alert { count: st.newer.len(), ..alert("newer", Default::default(), Vec::new()) });
    }
    out
}

/// Whether a device whose keys live in store may hold an admin key at the
/// group's key level, as the phone kits' Records.levelAllows: never a
/// rootless install, always proven hardware, a file only at the level
/// `files` and with the user's consent, other hardware unless the level
/// asks for proven keys.
fn level_allows(level: &str, store: &str, consent: bool) -> bool {
    match store {
        "rootless" => false,
        "proven" => true,
        "file" => level == "files" && consent,
        _ => level != "proven",
    }
}

/// What making a computer an admin gives: the admin CA for the admin key
/// its hello offered, for the admin message, and its device record again
/// naming that CA, to add and send.
pub struct NewAdmin {
    pub admin_ca: Vec<u8>,
    pub record: Record,
}

/// Makes the computer device an admin, as the group's root
/// (docs/protocol.md, section 10, "A computer as admin"): admin_key is the
/// SubjectPublicKeyInfo its hello offered and key_store where its hello
/// says its keys live; a computer that keeps them in a file becomes one
/// only when the group's key level allows files and the user consented
/// (allow_file_key).
pub fn make_admin(
    rs: &Records,
    s: &Signer,
    device: &str,
    admin_key: &[u8],
    key_store: &str,
    allow_file_key: bool,
    now_ms: i64,
) -> Result<NewAdmin> {
    if !rs.state().roots.contains(&s.hash()) {
        return Err(Error::msg("only the group's root makes admins"));
    }
    let d = find(rs, device)?;
    if d.role != "full" {
        return Err(Error::msg("only a computer is made an admin this way"));
    }
    if d.frozen {
        return Err(Error::msg("the computer is frozen: unfreeze it or remove it"));
    }
    if d.admin_key.is_some() {
        return Err(Error::msg("the computer is an admin already"));
    }
    let point = certs::p256_spki(admin_key)
        .ok_or_else(|| Error::msg("the computer offers no P-256 admin key"))?
        .to_sec1_point(false)
        .as_bytes()
        .to_vec();
    let proven = d.store == "proven";
    let store = if proven { d.store.clone() } else { command::store_of(key_store, &d.role).to_string() };
    if store == "rootless" || d.store == "rootless" {
        return Err(Error::msg("a computer that runs without root keeps no admin key"));
    }
    let level = rs.state().key_level;
    let level = if level.is_empty() { "hardware" } else { level.as_str() };
    if !level_allows(level, &store, allow_file_key) {
        return Err(Error::msg(if store == "file" {
            "the computer keeps its keys in a file, which the group's key level does not allow for an admin"
        } else {
            "the computer's keys are below the group's key level"
        }));
    }
    let id = certs::DeviceId::parse(device)?;
    let ca = issue::admin_ca(&id, &point, s.ca, now_ms / 1000, &mut |tbs| identity::sign_external(s.key, tbs))?;
    let admin = Hash(Cert::parse(&ca)?.key_hash());
    let b = Body {
        v: 2,
        alg: authority::ALG_ES256.into(),
        kind: authority::TYPE_DEVICE.into(),
        signer: s.hash(),
        time_ms: now_ms,
        device: d.id.clone(),
        name: d.name.clone(),
        role: d.role.clone(),
        os: d.os.clone(),
        key: Some(Hash(d.key)),
        admin: Some(admin),
        powers: authority::POWERS.iter().map(|p| (*p).into()).collect(),
        commands: authority::COMMANDS.iter().map(|c| (*c).into()).collect(),
        store,
        hardware: if proven { d.kind.clone() } else { String::new() },
        proof: if proven { d.proof.clone() } else { String::new() },
        seal: d.seal.clone(),
        ..Default::default()
    };
    let body = rs.next_body(b)?;
    let sig = identity::sign_external(s.key, &body)?;
    Ok(NewAdmin { admin_ca: ca, record: Record::new(body, sig, None) })
}

/// A renewed member certificate for a peer's chain (leaf first), when the
/// leaf is due and from one of the group's roots, directly or through an
/// admin CA under one; None when it is not due. The signer issues it from
/// its own CA, whoever issued the old one, as the phone kits' renewal.
/// now is Unix seconds.
pub fn renewal(chain: &[Cert], roots: &[Cert], s: &Signer, now: i64) -> Result<Option<Vec<u8>>> {
    let Some(leaf) = chain.first() else { return Ok(None) };
    let device = certs::verify_member(chain, roots, now, certs::Usage::Client)?;
    if !due(leaf, s.ca, now) {
        return Ok(None);
    }
    issue::member(&device, leaf.public_key(), s.ca, now, &mut |tbs| identity::sign_external(s.key, tbs)).map(Some)
}

/// Whether a member certificate is due for renewal, as Go's renewable: less
/// than 240 days left, and its CA lasts longer than it. A clock before the
/// CA's start is wrong, and nothing is due then.
pub fn due(cert: &Cert, ca: &Cert, now: i64) -> bool {
    const RENEW_BEFORE: i64 = 240 * 24 * 3600;
    now >= ca.not_before && now > cert.not_after.saturating_sub(RENEW_BEFORE) && ca.not_after > cert.not_after
}

#[cfg(test)]
#[path = "manage/tests.rs"]
mod tests;
