// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The joiner's Info (format 11.2), in `ADa` of its first pairing message:
//! what it says about itself. Nothing here is taken on its word except its
//! name, system and kind: its key is the one TLS proved, an admin key needs
//! its proof of possession, and where its keys are stored is never read
//! from it (a store needs evidence the admitter checks itself).

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::format::{Alg, Rule, Value, cbor};
use crate::records::Key;
use crate::records::body::{CAP_ADMIN, CAP_DIALS, CAP_HUB, ROLE_LEAF, ROLE_MEMBER, ROLE_PHONE};

/// A field outside its row.
pub const RULE_NAME: Rule = Rule::field("pair/info/name");
pub const RULE_ROLE: Rule = Rule::field("pair/info/role");
pub const RULE_CAPS: Rule = Rule::field("pair/info/caps");
pub const RULE_ADMIN: Rule = Rule::field("pair/info/admin");
pub const RULE_SHAPE: Rule = Rule::field("pair/info/shape");

/// The joiner's Info.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Info {
    pub name: String,
    /// Any number: one this version does not name is kept and shown as
    /// unknown.
    pub os: u64,
    pub caps: u64,
    pub role: u64,
    /// The admin key a phone, or a member with `admin` in its caps, offers.
    pub admin: Option<Vec<u8>>,
    /// Its signature over the session's exporter (`crate::join::sign_admin_pop`).
    pub admin_pop: Option<Vec<u8>>,
    /// The joiner's keys statement, epoch 1, as its envelope.
    pub keys: Option<Vec<u8>>,
    /// The hello's `device` map, as its encoding.
    pub device: Option<Vec<u8>>,
    /// The one-time ID of the invitation it joins by.
    pub invite: Option<[u8; 16]>,
}

/// Reports whether a name may stand in a record: 1 to 64 bytes, no control
/// character (format 4.1).
pub fn valid_name(s: &str) -> bool {
    !s.is_empty() && s.len() <= 64 && !s.chars().any(|c| c.is_control())
}

impl Info {
    /// A joiner of a role with a name and a system.
    pub fn new(name: &str, os: u64, role: u64) -> Info {
        Info {
            name: name.to_string(),
            os,
            caps: 0,
            role,
            admin: None,
            admin_pop: None,
            keys: None,
            device: None,
            invite: None,
        }
    }

    /// The admin key offered, checked as a P-256 key.
    pub fn admin_key(&self) -> Option<Key> {
        self.admin.as_ref().map(|p| Key::es256(p.clone()))
    }

    /// The encoding, fields in order, defaults left out.
    pub fn encode(&self) -> Vec<u8> {
        let mut m: Vec<(u16, Value<'_>)> = Vec::new();
        m.push((1, Value::Text(&self.name)));
        if self.os != 0 {
            m.push((2, Value::Uint(self.os)));
        }
        if self.caps != 0 {
            m.push((3, Value::Uint(self.caps)));
        }
        m.push((4, Value::Uint(self.role)));
        if let Some(a) = &self.admin {
            m.push((5, Value::Array(alloc::vec![Value::Uint(Alg::Es256.number()), Value::Bytes(a)])));
        }
        if let Some(p) = &self.admin_pop {
            m.push((6, Value::Bytes(p)));
        }
        let keys;
        if let Some(k) = &self.keys {
            keys = cbor::decode(k).ok();
            if let Some(v) = &keys {
                m.push((7, v.clone()));
            }
        }
        let device;
        if let Some(d) = &self.device {
            device = cbor::decode(d).ok();
            if let Some(v) = &device {
                m.push((8, v.clone()));
            }
        }
        if let Some(i) = &self.invite {
            m.push((9, Value::Bytes(i)));
        }
        Value::Map(m).encode()
    }

    /// Reads an Info and checks each field against its row, as a reader of
    /// this version does (`crate::msg::read_map`: unknown capability bits
    /// are ignored). Unknown fields are skipped: messages are not signed
    /// and later versions add fields.
    pub fn decode(b: &[u8]) -> Result<Info, Rule> {
        let v = crate::msg::read_map(&crate::msg::tables::INFO, &cbor::decode(b)?)?;
        let name = v.get(1).and_then(Value::as_text).ok_or(RULE_NAME)?;
        if !valid_name(name) {
            return Err(RULE_NAME);
        }
        let os = opt_uint(&v, 2)?;
        let caps = opt_uint(&v, 3)?;
        let role = v.get(4).and_then(Value::as_uint).ok_or(RULE_ROLE)?;
        if !(1..=ROLE_LEAF).contains(&role) {
            return Err(RULE_ROLE);
        }
        if caps & !(CAP_ADMIN | CAP_DIALS | CAP_HUB) != 0 || (caps != 0 && role != ROLE_MEMBER) {
            return Err(RULE_CAPS);
        }
        let admin = match v.get(5) {
            None => None,
            Some(k) => {
                let key = crate::format::Key::from_value(k).map_err(|_| RULE_ADMIN)?;
                if key.alg != Alg::Es256 || key.check().is_err() {
                    return Err(RULE_ADMIN);
                }
                Some(key.public.to_vec())
            }
        };
        let admin_pop = match v.get(6) {
            None => None,
            Some(p) => Some(p.as_bytes().filter(|p| p.len() == 64).ok_or(RULE_ADMIN)?.to_vec()),
        };
        // An admin key comes with its proof, and only from a phone or a
        // member that says it is an admin.
        if admin.is_some() != admin_pop.is_some() || (admin.is_some() && role != ROLE_PHONE && caps & CAP_ADMIN == 0) {
            return Err(RULE_ADMIN);
        }
        let keys = v.get(7).map(Value::encode);
        let device = match v.get(8) {
            None => None,
            Some(d) if d.as_map().is_some() => Some(d.encode()),
            Some(_) => return Err(RULE_SHAPE),
        };
        let invite = match v.get(9) {
            None => None,
            Some(i) => Some(i.as_bytes().and_then(|b| <[u8; 16]>::try_from(b).ok()).ok_or(RULE_SHAPE)?),
        };
        Ok(Info { name: name.to_string(), os, caps, role, admin, admin_pop, keys, device, invite })
    }
}

fn opt_uint(v: &Value<'_>, k: u16) -> Result<u64, Rule> {
    match v.get(k) {
        None => Ok(0),
        Some(x) => x.as_uint().ok_or(RULE_SHAPE),
    }
}
