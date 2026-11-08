// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! Taking the group over (docs/protocol.md, section 10, "Handing the group
//! over" and "The recovery key"), with the keys held outside the core: an
//! admin's claim that hands the group to a new root, from a lost root, as
//! the admin the root handed the group to, or with the recovery key; the
//! claim's state while it waits; the records the new root starts with once
//! it took effect; and a new admin CA from the new root for an admin whose
//! CA is from an earlier one. The phones' apps and the computers' service
//! do it alike: each keeps the new root's key, and the new root CA from
//! issue::root_ca, before the claim goes out, so that a claim never takes
//! effect for a key the device lost.

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::authority::{self, Body, Hash, Record, Seen};
use crate::certs::{self, Cert, DeviceId};
use crate::error::{Error, Result};
use crate::group::Records;
use crate::identity;
use crate::issue;
use crate::manage::Signer;

/// How the claim takes the group.
pub enum How<'a> {
    /// From its root, which the device with this ID was and is lost: the
    /// claim waits the group's delay, and the root cancels it meanwhile if
    /// it is still in use. It needs the power to take the group over.
    From(&'a str),
    /// As the admin the current root handed the group to: the claim takes
    /// effect at once, and the old root's device stays.
    HandedOver,
    /// With the group's recovery key, whose admin CA signs.
    Recovery,
}

/// The signer's claim, signed with its admin key (or the recovery key)
/// through s, that hands the group to new_root, a root CA (DER) for a new
/// key of this device. The caller adds it to the records and sends it.
/// now_ms is the wall clock in Unix milliseconds.
pub fn claim(rs: &Records, s: &Signer, how: How, new_root: &[u8], now_ms: i64) -> Result<Record> {
    let st = rs.state();
    let h = s.hash();
    if st.roots.last() == Some(&h) {
        return Err(Error::msg("this device is the group's root already"));
    }
    let root = Cert::parse(new_root)?;
    if !root.is_ca || !root.cert_sign || !root.signed_by(&root) {
        return Err(Error::msg("the new root is not a root CA"));
    }
    if st.roots.contains(&Hash(root.key_hash())) {
        return Err(Error::msg("the new root is a root of the group already"));
    }
    if st.claims.iter().any(|c| c.claimant == h && c.state == "pending") {
        return Err(Error::msg("this device's claim to take the group over is waiting already"));
    }
    let current = rs.path_certs().pop().ok_or_else(|| Error::msg("the group has no root"))?;
    match how {
        How::From(lost) => {
            s.check(rs)?;
            if lost != st.root_device || lost.is_empty() {
                return Err(Error::msg("the device is not the group's root"));
            }
            if lost == s.me {
                return Err(Error::msg("this device is the group's root already"));
            }
            if !s.ca.signed_by(&current) {
                return Err(Error::msg(
                    "this admin's CA is from a root before the current one, so a new root from it would split the group; the current root renews it when they next meet",
                ));
            }
            let me = rs.devices().into_iter().find(|d| d.id == s.me && d.admin_key == Some(h.0));
            if !me.is_some_and(|d| d.may(authority::POWER_TAKEOVER)) {
                return Err(Error::msg("the root did not give this admin the power to take the group over"));
            }
        }
        How::HandedOver => {
            if rs.handed_to() != Some(h.0) {
                return Err(Error::msg("the group's root did not hand the group to this admin"));
            }
        }
        How::Recovery => {
            if st.recovery != Some(h) {
                return Err(Error::msg("this is not the group's recovery key"));
            }
        }
    }
    let body = rs.next_body(Body {
        v: 2,
        alg: authority::ALG_ES256.into(),
        kind: authority::TYPE_CLAIM.into(),
        signer: h,
        time_ms: now_ms,
        root: new_root.to_vec(),
        ..Default::default()
    })?;
    let sig = identity::sign_external(s.key, &body)?;
    Ok(Record::new(body, sig, s.chain(rs)))
}

/// Where a claim to new_root (DER) stands, as the records say.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClaimState {
    /// "effective" once new_root is the group's current root, else the
    /// state's: "pending", "cancelled", "void", "competing" or "disputed".
    pub state: String,
    /// How long a pending claim still waits, in milliseconds.
    pub left_ms: i64,
}

/// The state of the claim to new_root; None when the records hold none.
pub fn claim_state(rs: &Records, new_root: &[u8]) -> Option<ClaimState> {
    let k = Hash(Cert::parse(new_root).ok()?.key_hash());
    let st = rs.state();
    if st.roots.last() == Some(&k) {
        return Some(ClaimState { state: "effective".into(), left_ms: 0 });
    }
    let c = st.claims.iter().rev().find(|c| c.root == k)?;
    Some(ClaimState { state: c.state.to_string(), left_ms: c.left_ms })
}

/// What the new root's record of its own device says when the records
/// list it under no other root: a device that claimed with the recovery
/// key has no record yet. A listed device keeps its record, with these
/// filling what it leaves empty.
pub struct Own<'a> {
    pub name: &'a str,
    /// `member` or `phone`.
    pub role: &'a str,
    /// A member's capabilities (`admin`, `dials`, `hub`), none for a phone.
    pub caps: &'a [String],
    pub os: &'a str,
    pub store: &'a str,
    /// Its key for sealed messages, empty for none.
    pub seal: &'a [u8],
}

/// What the new root starts with.
pub struct Finished {
    /// This device's member certificate from the new root, as a root admits
    /// only with a certificate of its own.
    pub cert: Vec<u8>,
    /// Its records, in order, to add and send: its own device that holds
    /// the root, the admins it keeps, a removal of the lost root's device,
    /// and the old root's settings again.
    pub records: Vec<Record>,
}

/// Makes this device the root once the records make its claim's new root
/// the current root: s is the new root (its CA and key), member_point
/// this device's member key (an uncompressed P-256 point). It fails while
/// the claim has not taken effect.
pub fn finish(rs: &Records, s: &Signer, member_point: &[u8], own: &Own, now_ms: i64) -> Result<Finished> {
    let path = rs.path_certs();
    let n = path.len();
    if n < 2 || path.last() != Some(s.ca) {
        return Err(Error::msg("the claim has not taken effect"));
    }
    let new_root = s.hash();
    let old_root = path.get(n.saturating_sub(2)).map(|c| Hash(c.key_hash())).unwrap_or_default();
    let device = DeviceId::parse(s.me)?;
    let cert =
        issue::member(&device, member_point, s.ca, now_ms / 1000, &mut |tbs| identity::sign_external(s.key, tbs))?;
    let member_key = Hash(Cert::parse(&cert)?.key_hash());

    let all = rs.all();
    let bodies: Vec<Body> = all.iter().filter_map(|r| Body::parse(&r.body).ok()).collect();
    let claimant = rs.state().claims.iter().find(|c| c.root == new_root).map(|c| c.claimant);
    // A root that handed the group over keeps its device; a lost one goes.
    let handed = bodies.iter().any(|b| {
        b.kind == authority::TYPE_HANDOVER && b.signer == old_root && b.admin.is_some() && b.admin == claimant
    });
    let lost = if handed {
        String::new()
    } else {
        bodies
            .iter()
            .filter(|b| b.kind == authority::TYPE_DEVICE && b.holds_root && b.signer == old_root)
            .max_by_key(|b| b.seq)
            .map(|b| b.device.clone())
            .unwrap_or_default()
    };

    let devs = rs.devices();
    let base = |kind: &str| Body {
        v: 2,
        alg: authority::ALG_ES256.into(),
        kind: kind.into(),
        signer: new_root,
        time_ms: now_ms,
        ..Default::default()
    };
    let mut me = base(authority::TYPE_DEVICE);
    me.device = s.me.to_string();
    me.key = Some(member_key);
    me.holds_root = true;
    match devs.iter().find(|d| d.id == s.me) {
        Some(d) => {
            me.name = d.name.clone();
            me.role = d.role.clone();
            me.caps = d.caps.clone();
            me.os = if d.os.is_empty() { own.os.into() } else { d.os.clone() };
            me.store = if d.store.is_empty() { own.store.into() } else { d.store.clone() };
            me.hardware = d.kind.clone();
            me.proof = d.proof.clone();
            me.seal = if d.seal.is_empty() { own.seal.to_vec() } else { d.seal.clone() };
        }
        None => {
            if !authority::valid_name(own.name) {
                return Err(Error::msg("a name has 1 to 64 bytes and no control characters"));
            }
            me.name = own.name.into();
            me.role = own.role.into();
            me.caps = own.caps.to_vec();
            me.os = own.os.into();
            me.store = own.store.into();
            me.seal = own.seal.to_vec();
        }
    }
    let mut out = alloc::vec![me];
    let mut revoke: Vec<Hash> = Vec::new();
    for d in devs.iter().filter(|d| d.id != s.me) {
        if !lost.is_empty() && d.id == lost {
            revoke.extend(d.keys.iter().copied().map(Hash));
        } else if let Some(a) = d.admin_key.filter(|_| !d.frozen) {
            let mut b = base(authority::TYPE_DEVICE);
            b.device = d.id.clone();
            b.name = d.name.clone();
            b.role = d.role.clone();
            b.caps = d.caps.clone();
            b.os = d.os.clone();
            b.key = Some(Hash(d.key));
            b.admin = Some(Hash(a));
            b.powers = d.powers.clone();
            b.commands = d.commands.clone();
            b.store = d.store.clone();
            b.hardware = d.kind.clone();
            b.proof = d.proof.clone();
            b.seal = d.seal.clone();
            b.forward_only = d.forward_only;
            out.push(b);
        }
    }
    if !revoke.is_empty() {
        revoke.sort_by_key(|k| certs::hex(&k.0));
        revoke.dedup();
        let mut b = base(authority::TYPE_REVOKE);
        b.keys = revoke;
        out.push(b);
    }
    // The state counts only the current root's settings, so the new root
    // signs the old root's again: the takeover delay and the key level.
    if let Some(old) =
        bodies.iter().filter(|b| b.kind == authority::TYPE_SETTINGS && b.signer == old_root).max_by_key(|b| b.seq)
    {
        let mut b = base(authority::TYPE_SETTINGS);
        b.takeover_delay_ms = old.takeover_delay_ms;
        b.key_level = old.key_level.clone();
        out.push(b);
    }
    Ok(Finished { cert, records: sign_in_turn(rs, s, out)? })
}

/// Signs bodies in turn as the signer's next records: each after the one
/// before, as the set would number them once it holds those.
fn sign_in_turn(rs: &Records, s: &Signer, bodies: Vec<Body>) -> Result<Vec<Record>> {
    let mut out: Vec<Record> = Vec::new();
    let (mut seq, mut prev) = rs.next_for(&s.hash());
    for mut b in bodies {
        let bytes = if out.is_empty() {
            rs.next_body(b)?
        } else {
            b.group = rs.tag().to_string();
            b.seq = seq;
            b.prev = prev;
            if b.kind == authority::TYPE_REVOKE {
                let mut seen = rs.seen();
                seen.retain(|e| e.key != b.signer);
                seen.push(Seen { key: b.signer, seq: seq.saturating_sub(1) });
                b.seen = seen;
            }
            b.sort();
            b.encode()?
        };
        let sig = identity::sign_external(s.key, &bytes)?;
        let r = Record::new(bytes, sig, None);
        seq = seq.saturating_add(1);
        prev = Some(r.id());
        out.push(r);
    }
    Ok(out)
}

/// A new admin CA from the current root for the admin key of device (an
/// uncompressed P-256 point), whose CA is from an earlier root, as after a
/// takeover: the records name the key, so they stay, and a takeover by that
/// admin later hangs under this root.
pub struct AdminRenewal {
    pub admin_ca: Vec<u8>,
    /// The current root's own record of the admin, when it has none yet:
    /// it lets the admin take the group over from this root in turn. The
    /// caller adds and sends it before the admin CA.
    pub record: Option<Record>,
}

/// The renewal of the admin CA of device, signed by the current root s.
pub fn renew_admin_ca(rs: &Records, s: &Signer, device: &str, point: &[u8], now_ms: i64) -> Result<AdminRenewal> {
    let root = s.hash();
    if rs.state().roots.last() != Some(&root) {
        return Err(Error::msg("only the group's current root renews an admin's CA"));
    }
    let key = certs::sha256(&certs::p256_spki_of(point));
    let d = rs
        .devices()
        .into_iter()
        .find(|d| d.id == device && d.admin_key == Some(key))
        .ok_or_else(|| Error::msg("the device is no admin of the group with this key"))?;
    if rs.revoked(&key) || rs.frozen(&key) {
        return Err(Error::msg("the admin is removed or frozen"));
    }
    let id = DeviceId::parse(device)?;
    let admin_ca = issue::admin_ca(&id, point, s.ca, now_ms / 1000, &mut |tbs| identity::sign_external(s.key, tbs))?;
    let listed = rs.all().iter().filter_map(|r| Body::parse(&r.body).ok()).any(|b| {
        b.kind == authority::TYPE_DEVICE && b.signer == root && b.admin == Some(Hash(key)) && b.device == device
    });
    let record = if listed {
        None
    } else {
        let mut powers = d.powers.clone();
        let mut commands = d.commands.clone();
        if powers.is_empty() {
            powers = authority::POWERS.iter().map(|p| (*p).into()).collect();
            commands = authority::COMMANDS.iter().map(|c| (*c).into()).collect();
        }
        let body = rs.next_body(Body {
            v: 2,
            alg: authority::ALG_ES256.into(),
            kind: authority::TYPE_DEVICE.into(),
            signer: root,
            time_ms: now_ms,
            device: d.id.clone(),
            name: d.name.clone(),
            role: d.role.clone(),
            caps: d.caps.clone(),
            os: d.os.clone(),
            key: Some(Hash(d.key)),
            admin: Some(Hash(key)),
            powers,
            commands,
            store: d.store.clone(),
            hardware: d.kind.clone(),
            proof: d.proof.clone(),
            seal: d.seal.clone(),
            forward_only: d.forward_only,
            ..Default::default()
        })?;
        let sig = identity::sign_external(s.key, &body)?;
        Some(Record::new(body, sig, None))
    };
    Ok(AdminRenewal { admin_ca, record })
}

#[cfg(test)]
#[path = "takeover/tests.rs"]
mod tests;
