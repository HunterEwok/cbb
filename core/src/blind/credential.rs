// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! Server credentials (format section 8, label `cbb credential v2`): the
//! signer's Key is in the body, since a server has no records to find it in.

use alloc::vec::Vec;

use crate::format::sig::LABEL_CREDENTIAL;
use crate::format::{Alg, Envelope, Key, KeyHash, Rule, Value};

/// A credential body's ceiling (format section 13).
pub const MAX_BODY: usize = 16 * 1024;

pub const TYPE_PERIOD: u64 = 1;
pub const TYPE_SERVER: u64 = 2;
pub const TYPE_HUBS: u64 = 3;
pub const TYPE_MEMBERS: u64 = 4;

/// The padded lengths of each list.
const HUBS_LENGTHS: &[usize] = &[4, 8, 16];
const ADMINS_LENGTHS: &[usize] = &[4, 8, 16, 32, 64];
const MEMBERS_LENGTHS: &[usize] = &[4, 8, 16, 32, 64, 128, 256];

/// A credential read, its signature checked by the Key in it.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Credential {
    pub kind: u64,
    /// period and server: the group ID; hubs and members: the period's tag.
    pub group: [u8; 16],
    /// The signer's point.
    pub signer: Vec<u8>,
    pub version: u64,
    pub expires_ms: u64,
    /// period and server: the period's tag.
    pub tag: Option<[u8; 16]>,
    /// period: the period key; server: the device's server key.
    pub key: Option<Vec<u8>>,
    pub hubs: Vec<[u8; 32]>,
    pub admins: Vec<[u8; 32]>,
    pub members: Vec<[u8; 32]>,
    /// SHA-256 over the body.
    pub id: [u8; 32],
}

fn rule(kind: u64, field: &str) -> Rule {
    let t = match kind {
        TYPE_PERIOD => "period",
        TYPE_SERVER => "server",
        TYPE_HUBS => "hubs",
        TYPE_MEMBERS => "members",
        _ => "type",
    };
    // The rule names are fixed strings, one per type and field.
    Rule::field(match (t, field) {
        ("period", "tag") => "credentials/period/tag",
        ("period", "key") => "credentials/period/key",
        ("server", "tag") => "credentials/server/tag",
        ("server", "key") => "credentials/server/key",
        ("hubs", "tag") => "credentials/hubs/tag",
        ("hubs", "key") => "credentials/hubs/key",
        ("hubs", "hubs") => "credentials/hubs/hubs",
        ("hubs", "admins") => "credentials/hubs/admins",
        ("members", "tag") => "credentials/members/tag",
        ("members", "key") => "credentials/members/key",
        ("members", "members") => "credentials/members/members",
        (_, "hubs") => "credentials/hubs/hubs",
        (_, "admins") => "credentials/hubs/admins",
        (_, "members") => "credentials/members/members",
        (_, "signer") => "credentials/signer",
        (_, "version") => "credentials/version",
        (_, "expires") => "credentials/expires",
        (_, "group") => "credentials/group",
        _ => "credentials/type",
    })
}

fn hashes(v: &Value<'_>, lengths: &[usize], r: Rule) -> Result<Vec<[u8; 32]>, Rule> {
    let a = v.as_array().ok_or(r)?;
    if !lengths.contains(&a.len()) {
        return Err(r);
    }
    a.iter().map(|x| x.as_bytes().and_then(|b| <[u8; 32]>::try_from(b).ok()).ok_or(r)).collect()
}

impl Credential {
    /// Reads a credential envelope: its form, each field against its type's
    /// row, then its signature by the Key in it.
    pub fn read(b: &[u8]) -> Result<Credential, Rule> {
        let env = Envelope::parse_limited(b, MAX_BODY)?;
        let m = &env.map;
        // A second signature is taken on the first alone, which covers it.
        crate::format::envelope::signer2(m, Rule::field("credentials/signer2"))?;
        let kind = m.get(1).and_then(Value::as_uint).ok_or(rule(0, "type"))?;
        if !(TYPE_PERIOD..=TYPE_MEMBERS).contains(&kind) {
            return Err(rule(kind, "type"));
        }
        let allowed: &[u16] = match kind {
            TYPE_PERIOD | TYPE_SERVER => &[1, 2, 3, 4, 7, 10, 11],
            TYPE_HUBS => &[1, 2, 3, 4, 7, 12, 13],
            _ => &[1, 2, 3, 4, 7, 14],
        };
        for (k, _) in m.as_map().unwrap_or(&[]) {
            // The optional zone (format 3.3): skipped, the signature covers it.
            if *k >= 256 || *k == crate::format::envelope::FIELD_SIGNER2 {
                continue;
            }
            if !allowed.contains(k) {
                let name = match k {
                    10 => "tag",
                    11 => "key",
                    12 => "hubs",
                    13 => "admins",
                    14 => "members",
                    _ => "type",
                };
                // A critical field of a later version, or a field the type
                // does not list: refused (a server takes only what it
                // understands).
                return Err(if name == "type" { Rule::FORM_CRITICAL } else { rule(kind, name) });
            }
        }
        let group: [u8; 16] =
            m.get(2).and_then(Value::as_bytes).and_then(|b| b.try_into().ok()).ok_or(rule(kind, "group"))?;
        let signer = Key::from_value(m.get(3).ok_or(rule(kind, "signer"))?).map_err(|_| rule(kind, "signer"))?;
        if signer.alg != Alg::Es256 || signer.check().is_err() {
            return Err(rule(kind, "signer"));
        }
        let version = m.get(4).and_then(Value::as_uint).filter(|v| *v >= 1).ok_or(rule(kind, "version"))?;
        let expires_ms = m.get(7).and_then(Value::as_uint).filter(|v| *v >= 1).ok_or(rule(kind, "expires"))?;
        let (mut tag, mut key) = (None, None);
        let (mut hubs, mut admins, mut members) = (Vec::new(), Vec::new(), Vec::new());
        match kind {
            TYPE_PERIOD | TYPE_SERVER => {
                tag = Some(
                    m.get(10)
                        .and_then(Value::as_bytes)
                        .and_then(|b| <[u8; 16]>::try_from(b).ok())
                        .ok_or(rule(kind, "tag"))?,
                );
                let k = Key::from_value(m.get(11).ok_or(rule(kind, "key"))?).map_err(|_| rule(kind, "key"))?;
                if k.alg != Alg::Es256 || k.check().is_err() {
                    return Err(rule(kind, "key"));
                }
                key = Some(k.public.to_vec());
            }
            TYPE_HUBS => {
                hubs = hashes(m.get(12).ok_or(rule(kind, "hubs"))?, HUBS_LENGTHS, rule(kind, "hubs"))?;
                admins = hashes(m.get(13).ok_or(rule(kind, "admins"))?, ADMINS_LENGTHS, rule(kind, "admins"))?;
            }
            _ => {
                members = hashes(m.get(14).ok_or(rule(kind, "members"))?, MEMBERS_LENGTHS, rule(kind, "members"))?;
            }
        }
        env.verify(signer.public, LABEL_CREDENTIAL)?;
        Ok(Credential {
            kind,
            group,
            signer: signer.public.to_vec(),
            version,
            expires_ms,
            tag,
            key,
            hubs,
            admins,
            members,
            id: env.id(),
        })
    }

    /// The signer's key hash.
    pub fn signer_hash(&self) -> KeyHash {
        Key::new(Alg::Es256, &self.signer).hash()
    }

    /// Whether it is still good at `now_ms` (servers have clocks; this is
    /// not a group rule).
    pub fn live(&self, now_ms: u64) -> bool {
        now_ms < self.expires_ms
    }

    /// A relay with a fixed list of groups: the period is signed by the
    /// group's first root key, whose Group ID with the two halves of the
    /// group's recovery key (K1 a P-256 point, K2 an SLH-DSA key) is on the
    /// list. Only the root signs periods in 0.6.
    pub fn period_of_listed_group(&self, root: &[u8], recovery: &[u8], recovery2: &[u8], listed: &[[u8; 16]]) -> bool {
        use crate::records::{Key, Recovery, group_id, key::ALG_SLH_DSA};
        let Some(rec) = Recovery::new(Key::es256(recovery.to_vec()), Key::new(ALG_SLH_DSA, recovery2.to_vec())) else {
            return false;
        };
        let gid = group_id(&Key::es256(root.to_vec()), &rec);
        self.kind == TYPE_PERIOD && self.signer == root && self.group == gid.0 && listed.contains(&self.group)
    }
}

/// Pads a list of hashes with random entries to the next of its lengths
/// (real entries first), so that its length tells little. None when the
/// list is too long.
pub fn pad(real: &[[u8; 32]], lengths: &[usize]) -> Option<Vec<[u8; 32]>> {
    let n = *lengths.iter().find(|n| **n >= real.len())?;
    let mut out = real.to_vec();
    while out.len() < n {
        out.push(crate::certs::random_bytes());
    }
    Some(out)
}

/// The padded lengths of a hubs credential's `hubs`, its `admins`, and a
/// members credential's `members`.
pub const LENGTHS_HUBS: &[usize] = HUBS_LENGTHS;
pub const LENGTHS_ADMINS: &[usize] = ADMINS_LENGTHS;
pub const LENGTHS_MEMBERS: &[usize] = MEMBERS_LENGTHS;

/// Why a set of credentials does not hold together.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Chain {
    /// The period is not signed by the root it names, or is not a period.
    Period,
    /// The hubs credential is not the period key's, of the period's tag.
    Hubs,
    /// The members credential is signed neither by the period key nor by a
    /// server key among the hubs credential's admins.
    Members,
}

/// Checks that credentials hold together as a server needs them: the hubs
/// credential signed by the period key under the period's tag, and the
/// members credential by the period key or by a server key the hubs
/// credential lists among its admins. The period itself is checked against
/// the root only where a relay has a fixed list of groups
/// ([`Credential::period_of_listed_group`]); a server otherwise knows the
/// period key by the hubs credential that came first.
pub fn check_chain(period: &Credential, hubs: &Credential, members: Option<&Credential>) -> Result<(), Chain> {
    if period.kind != TYPE_PERIOD {
        return Err(Chain::Period);
    }
    let (Some(tag), Some(pkey)) = (period.tag, period.key.as_ref()) else { return Err(Chain::Period) };
    if hubs.kind != TYPE_HUBS || &hubs.signer != pkey || hubs.group != tag {
        return Err(Chain::Hubs);
    }
    if let Some(m) = members {
        let by_period = &m.signer == pkey;
        let by_admin = hubs.admins.contains(&m.signer_hash().0);
        if m.kind != TYPE_MEMBERS || m.group != tag || !(by_period || by_admin) {
            return Err(Chain::Members);
        }
    }
    Ok(())
}
