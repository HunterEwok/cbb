// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! Server credentials (docs/protocol.md, section 18), read and checked as
//! the Go package internal/group does: the group lives in periods, for each
//! of which its root signs a period credential with a fresh tag and period
//! key, each device signs its server key with its member key, and the
//! period key signs the hubs' and the members' credentials, the only ones
//! the servers see. The lite member registers with no server, so it signs
//! none; it reads them, and works out what the records say they must list.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::certs::{KeyHash, b64, sha256};
use crate::error::{Error, Result};
use crate::group::Records;

/// The types of credentials.
pub const PERIOD: &str = "period";
pub const SERVER: &str = "server";
pub const HUBS: &str = "hubs";
pub const MEMBERS: &str = "members";

/// The most hubs a credential lists, the first of the order.
pub const MAX_HUBS: usize = 16;
/// The most members a credential lists.
pub const MAX_MEMBERS: usize = 256;
/// The most admins a credential lists.
pub const MAX_ADMINS: usize = 64;
const MAX_BODY: usize = 16 << 10;

/// A signed credential body: the body's exact bytes, an ECDSA P-256
/// signature over them, and the signer's SubjectPublicKeyInfo.
#[derive(Clone, Serialize, Deserialize, PartialEq, Debug)]
pub struct Credential {
    #[serde(with = "b64")]
    pub body: Vec<u8>,
    #[serde(with = "b64")]
    pub sig: Vec<u8>,
    #[serde(with = "b64")]
    pub key: Vec<u8>,
}

/// What a credential says.
#[derive(Clone, Serialize, Deserialize, PartialEq, Debug, Default)]
pub struct Body {
    pub v: i64,
    #[serde(rename = "type")]
    pub kind: String,
    /// The group's own tag in a period or a server credential, the
    /// period's tag in a hubs' or a members' credential.
    pub group: String,
    pub version: u64,
    pub expires_ms: i64,
    /// A period's tag, or the period a server credential is for.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub tag: String,
    /// The period key or the server key (SubjectPublicKeyInfo).
    #[serde(with = "b64", default, skip_serializing_if = "Vec::is_empty")]
    pub key: Vec<u8>,
    #[serde(with = "b64::hashes", default, skip_serializing_if = "Vec::is_empty")]
    pub hubs: Vec<KeyHash>,
    #[serde(with = "b64::hashes", default, skip_serializing_if = "Vec::is_empty")]
    pub admins: Vec<KeyHash>,
    #[serde(with = "b64::hashes", default, skip_serializing_if = "Vec::is_empty")]
    pub members: Vec<KeyHash>,
}

impl Credential {
    /// The hash of the key that signed it.
    pub fn signer(&self) -> KeyHash {
        sha256(&self.key)
    }

    /// Checks the signature and returns the body. It checks neither who
    /// signed it nor the group.
    pub fn open(&self) -> Result<Body> {
        let b = Body::parse(&self.body)?;
        let key = p256_key(&self.key)?;
        let sig =
            Signature::from_der(&self.sig).map_err(|_| Error::msg("the credential's signature does not verify"))?;
        key.verify(&self.body, &sig).map_err(|_| Error::msg("the credential's signature does not verify"))?;
        Ok(b)
    }
}

fn p256_key(spki: &[u8]) -> Result<VerifyingKey> {
    crate::certs::p256_spki(spki).ok_or_else(|| Error::msg("the credential's key is not a P-256 key"))
}

/// Whether s is a tag: 16 lower-case hex characters.
pub fn valid_tag(s: &str) -> bool {
    s.len() == 16 && s.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

impl Body {
    /// Reads and checks a credential's body: its size, the strict form of
    /// signed bodies, then its fields.
    pub(crate) fn parse(data: &[u8]) -> Result<Body> {
        if data.len() > MAX_BODY {
            return Err(Error::msg("the credential is too large"));
        }
        crate::strict::check(data, &["v", "type", "group", "version", "expires_ms"])?;
        let b: Body = serde_json::from_slice(data).map_err(|_| Error::msg("the credential does not decode"))?;
        b.check()?;
        Ok(b)
    }

    fn check(&self) -> Result<()> {
        if self.v != 1 {
            return Err(Error::msg(format!("unknown credential version {}", self.v)));
        }
        if self.version == 0 || self.expires_ms <= 0 {
            return Err(Error::msg("a credential without a version or an expiry"));
        }
        if !valid_tag(&self.group) {
            return Err(Error::msg("a credential's group is not a tag"));
        }
        let lists = self.hubs.len().saturating_add(self.admins.len()).saturating_add(self.members.len());
        match self.kind.as_str() {
            PERIOD | SERVER => {
                if !valid_tag(&self.tag) {
                    return Err(Error::msg("a credential's period tag is not a tag"));
                }
                p256_key(&self.key)?;
                if lists != 0 {
                    return Err(Error::msg("a period or server credential lists keys"));
                }
            }
            HUBS => {
                if self.hubs.len() > MAX_HUBS || self.admins.len() > MAX_ADMINS {
                    return Err(Error::msg("a hubs' credential lists too many keys"));
                }
                if !self.tag.is_empty() || !self.key.is_empty() || !self.members.is_empty() {
                    return Err(Error::msg("a hubs' credential carries more than its lists"));
                }
            }
            MEMBERS => {
                if self.members.len() > MAX_MEMBERS {
                    return Err(Error::msg("a members' credential lists too many keys"));
                }
                if !self.tag.is_empty() || !self.key.is_empty() || !(self.hubs.is_empty() && self.admins.is_empty()) {
                    return Err(Error::msg("a members' credential carries more than its list"));
                }
            }
            k => return Err(Error::msg(format!("unknown credential type {k:?}"))),
        }
        Ok(())
    }
}

/// The name of a server key at the relay: its fingerprint, the hash in
/// standard base64.
pub fn pseudonym(k: &KeyHash) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(k)
}

/// What the group's credentials must list, by member key, as Go's
/// Records.CredentialLists: the hubs in their order, at most MAX_HUBS; the
/// admins that are not frozen, other than the root's own device, which
/// holds the period key; and every device that is not frozen, at most
/// MAX_MEMBERS.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Lists {
    pub hubs: Vec<KeyHash>,
    pub admins: Vec<KeyHash>,
    pub members: Vec<KeyHash>,
}

pub fn lists(s: &Records) -> Lists {
    let mut l = Lists::default();
    let root = s.root_member();
    let devs = s.devices();
    for id in s.hub_order() {
        if l.hubs.len() == MAX_HUBS {
            break;
        }
        if let Some((r, k)) = &root
            && *r == id
        {
            l.hubs.push(*k);
            continue;
        }
        l.hubs.extend(devs.iter().filter(|d| d.id == id).map(|d| d.key));
    }
    let root = root.map(|(id, _)| id);
    for d in devs.iter().filter(|d| !d.frozen) {
        if d.admin && root.as_deref() != Some(d.id.as_str()) && l.admins.len() < MAX_ADMINS {
            l.admins.push(d.key);
        }
        if l.members.len() < MAX_MEMBERS {
            l.members.push(d.key);
        }
    }
    l
}

/// What a server checked of the credentials a device presented.
#[derive(Clone, Debug)]
pub struct Presented {
    /// The period's tag.
    pub tag: String,
    /// The period key, which signed the hubs' credential.
    pub signer: KeyHash,
    pub hubs: Body,
    pub members: Option<Body>,
    /// The period credential and the key that signed it, which only a
    /// relay that serves a fixed list of groups is shown.
    pub period: Option<(Body, Vec<u8>)>,
}

/// Checks the credentials a device presents a server, as Go's
/// CheckPresented: one hubs' credential, and with it at most one members'
/// credential of the same period, which the period key or an admin that
/// the hubs' credential lists signed, and at most one period credential
/// whose tag and key are those of the hubs' credential. None may have
/// expired at now_ms.
pub fn check_presented(cs: &[Credential], now_ms: i64) -> Result<Presented> {
    let wrong =
        || Error::msg("the credentials are not a hubs' credential with at most a members' and a period credential");
    if cs.is_empty() || cs.len() > 3 {
        return Err(wrong());
    }
    let (mut hubs, mut members, mut period) = (None, None, None);
    for c in cs {
        let b = c.open()?;
        if now_ms >= b.expires_ms {
            return Err(Error::msg(format!("the {} credential expired", b.kind)));
        }
        let slot = match b.kind.as_str() {
            HUBS => &mut hubs,
            MEMBERS => &mut members,
            PERIOD => &mut period,
            _ => return Err(wrong()),
        };
        if slot.is_some() {
            return Err(wrong());
        }
        *slot = Some((b, c));
    }
    let (hubs, hc) = hubs.ok_or_else(|| Error::msg("no hubs' credential"))?;
    let mut p = Presented { tag: hubs.group.clone(), signer: hc.signer(), hubs, members: None, period: None };
    if let Some((b, c)) = members {
        if b.group != p.tag {
            return Err(Error::msg("a members' credential of another period"));
        }
        if c.key != hc.key && !p.hubs.admins.contains(&c.signer()) {
            return Err(Error::msg("a members' credential that neither the period key nor a listed admin signed"));
        }
        p.members = Some(b);
    }
    if let Some((b, c)) = period {
        if b.tag != p.tag || b.key != hc.key {
            return Err(Error::msg("a period credential of another period"));
        }
        p.period = Some((b, c.key.clone()));
    }
    Ok(p)
}
