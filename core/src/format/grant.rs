// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! A leaf's grant (format section 7): one signed envelope `[body, sig]`,
//! label `cbb grant v1`, like every other signed thing. The root signs a
//! guarded leaf's grant, each one by itself; the root or an admin with
//! `admit` signs an ordinary leaf's, and message `grant` then carries the
//! root's record of that admin key.

use super::cbor::Value;
use super::envelope::Envelope;
use super::key::{Alg, DeviceId, Key, KeyHash};
use super::{Rule, sig};

/// The largest grant body.
pub const MAX_GRANT: usize = 2048;

/// Message `grant`'s field of the grant envelope.
pub const FIELD_GRANT: u16 = 2;
/// Message `grant`'s field of the root's record of the admin that signed
/// the grant, when an admin did.
pub const FIELD_ADMIN: u16 = 3;

/// The grant's field of the leaf's commanders (a guarded leaf's only).
pub const FIELD_COMMANDERS: u16 = 12;
/// The grant's field of its lifetime (a guarded leaf's only).
pub const FIELD_LIFE: u16 = 11;
/// The grant's field of its readers.
pub const FIELD_READERS: u16 = 13;
/// The grant's flag of a guarded leaf.
pub const FIELD_GUARDED: u16 = 15;
/// The most readers of a leaf.
pub const MAX_READERS: usize = 4;

/// A guarded leaf's grant that a root did not sign.
pub const RULE_GUARDED: Rule = Rule::field("grants/guarded");
/// Commanders or a lifetime in an ordinary leaf's grant.
pub const RULE_COMMANDERS: Rule = Rule::field("grants/commanders");
/// More than four readers.
pub const RULE_READERS: Rule = Rule::field("grants/readers");
/// An admin's grant without the root's record of that admin key, or with
/// one that does not make it an admin that admits.
pub const RULE_ADMIN: Rule = Rule::field("grants/admin");

/// A grant as message `grant` carries it, checked to its signature and its
/// kind.
#[derive(Clone, Debug)]
pub struct Granted<'a> {
    /// The grant envelope; its body is the grant.
    pub grant: Envelope<'a>,
    /// The root's record of the admin that signed the grant, when an admin
    /// did.
    pub admin: Option<Envelope<'a>>,
    /// Whether the grant is a guarded leaf's.
    pub guarded: bool,
}

/// The admin key of the root's record in field 3, if it makes that key an
/// admin with `admit`: a `device` record (type 1) the root signed, with its
/// `admin` Key (20) and the admit bit in its `powers` (21).
fn admin_key<'a>(record: &Envelope<'a>, root: &[u8]) -> Result<[u8; 65], Rule> {
    record.verify(root, sig::LABEL_RECORD).map_err(|_| RULE_ADMIN)?;
    let m = &record.map;
    let root_hash = Key::new(Alg::Es256, root).hash();
    let by_root = m.get(3).and_then(Value::as_bytes).and_then(KeyHash::from_slice) == Some(root_hash);
    let device = m.get(1).and_then(Value::as_uint) == Some(1);
    let admits = m.get(21).and_then(Value::as_uint).is_some_and(|p| p & 1 == 1);
    let key = m.get(20).map(Key::from_value).transpose().map_err(|_| RULE_ADMIN)?.ok_or(RULE_ADMIN)?;
    if !(by_root && device && admits && key.alg == Alg::Es256) || key.check().is_err() {
        return Err(RULE_ADMIN);
    }
    key.public.try_into().map_err(|_| RULE_ADMIN)
}

/// Reads a grant from the map of message `grant` (or the Welcome's `grant`):
/// field 2 the grant envelope, 3 the root's record of the admin that signed
/// it. Checks the signature (by the root's uncompressed point, or by an
/// admin key that the root's record in field 3 makes an admin with `admit`)
/// and the rules of the two kinds of leaf (design-small-device section 15):
/// a guarded grant only from the root; commanders and a lifetime only in a
/// guarded grant; at most four readers. The grant's other fields are its
/// reader's matter.
pub fn read<'a>(msg: &Value<'a>, root: &[u8]) -> Result<Granted<'a>, Rule> {
    let grant = Envelope::from_value(msg.get(FIELD_GRANT).ok_or(Rule::GRANTS_SHAPE)?)?;
    if grant.body.len() > MAX_GRANT {
        return Err(Rule::ENV_SIZE);
    }
    let signer = grant.signer().and_then(Value::as_bytes).and_then(KeyHash::from_slice).ok_or(Rule::GRANTS_SHAPE)?;
    let admin = if signer == Key::new(Alg::Es256, root).hash() {
        grant.verify(root, sig::LABEL_GRANT)?;
        None
    } else {
        let record = Envelope::from_value(msg.get(FIELD_ADMIN).ok_or(RULE_ADMIN)?)?;
        let key = admin_key(&record, root)?;
        if Key::new(Alg::Es256, &key).hash() != signer {
            return Err(RULE_ADMIN);
        }
        grant.verify(&key, sig::LABEL_GRANT)?;
        Some(record)
    };
    let map = &grant.map;
    let guarded = match map.get(FIELD_GUARDED) {
        None => false,
        Some(Value::Uint(1)) => true,
        Some(_) => return Err(Rule::field("grants/guarded-value")),
    };
    if guarded && admin.is_some() {
        return Err(RULE_GUARDED);
    }
    if !guarded && (map.get(FIELD_COMMANDERS).is_some() || map.get(FIELD_LIFE).is_some()) {
        return Err(RULE_COMMANDERS);
    }
    if map.get(FIELD_READERS).and_then(Value::as_array).is_some_and(|r| r.len() > MAX_READERS) {
        return Err(RULE_READERS);
    }
    Ok(Granted { grant, admin, guarded })
}

/// A copy to a leaf from a device its grant does not let send it copies.
pub const RULE_COPY_SENDER: Rule = Rule::field("copy/leaf-sender");

/// Whether a leaf takes a copy whose header names origin, by the grant it
/// keeps (owner, 2026-11-11): an ordinary leaf takes copies from its readers
/// (field 13, `[device ID, Key]`), the same devices it seals to; a guarded
/// leaf only from its commanders (field 12, Keys), whose device IDs are
/// their keys' IDs.
pub fn copy_sender(grant: &Value<'_>, origin: &DeviceId) -> Result<(), Rule> {
    let list = |field| grant.get(field).and_then(Value::as_array).unwrap_or(&[]);
    let named = if grant.get(FIELD_GUARDED).is_some() {
        list(FIELD_COMMANDERS).iter().any(|k| Key::from_value(k).is_ok_and(|k| k.device_id() == *origin))
    } else {
        list(FIELD_READERS)
            .iter()
            .any(|r| r.as_array().and_then(|a| a.first()).and_then(Value::as_bytes) == Some(origin.0.as_slice()))
    };
    if named { Ok(()) } else { Err(RULE_COPY_SENDER) }
}
