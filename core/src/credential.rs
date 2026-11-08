// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! Server credentials (docs/protocol.md, section 18), read and checked as
//! the Go package internal/group does: the group lives in periods, for each
//! of which its root signs a period credential with a fresh tag and period
//! key, each device signs its server key with its member key, and the
//! period key signs the hubs' and the members' credentials, the only ones
//! the servers see. `Store` keeps a member's credentials as Go's
//! group.Credentials, and the `sign_*` functions make them, with the key
//! behind a callback, which may be in the hardware.

use alloc::collections::BTreeMap;
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
    // A watch reaches the group only through its phone, so no server needs
    // its key.
    for d in devs.iter().filter(|d| !d.frozen && d.role != "watch") {
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

/// How long a period lasts, and how old it may get before the root starts
/// the next, as Go's PeriodLifetime and PeriodRenew.
pub const PERIOD_LIFETIME_MS: i64 = 35 * 24 * 3600 * 1000;
pub const PERIOD_RENEW_MS: i64 = 30 * 24 * 3600 * 1000;
/// The most credentials a member keeps and sends: the period, the hubs'
/// and the members' credentials and one server credential for each member.
pub const MAX_CREDENTIALS: usize = MAX_MEMBERS + 3;

/// The order Store::add takes credentials in: each counts against the ones
/// before.
fn rank(c: &Credential) -> usize {
    #[derive(Deserialize)]
    struct Kind {
        #[serde(rename = "type", default)]
        kind: String,
    }
    let k = serde_json::from_slice::<Kind>(&c.body).map(|k| k.kind).unwrap_or_default();
    [PERIOD, SERVER, HUBS, MEMBERS].iter().position(|t| *t == k).unwrap_or(usize::MAX)
}

/// A member's credentials, as Go's group.Credentials: the newest period
/// that the group's current root signed, and for it each member's newest
/// server credential and the newest hubs' and members' credentials.
#[derive(Clone, Debug, Default)]
pub struct Store {
    /// The group's own tag.
    group: String,
    period: Option<Credential>,
    /// By the member key that signed it.
    servers: BTreeMap<KeyHash, Credential>,
    hubs: Option<Credential>,
    members: Option<Credential>,
}

impl Store {
    /// An empty set for the group of the tag `group` (certs::tag).
    pub fn new(group: &str) -> Store {
        Store { group: group.into(), ..Store::default() }
    }

    /// Takes the credentials that are valid for the group and newer than
    /// what it keeps, as Go's Credentials.Add, and returns those it took
    /// and why it refused the others. root is the SubjectPublicKeyInfo of
    /// the group's current root; member tells whether a key is the member
    /// key of a device in the group that is not frozen. A newer period
    /// drops the credentials of the one before.
    pub fn add(
        &mut self,
        root: &[u8],
        member: &dyn Fn(&KeyHash) -> bool,
        cs: &[Credential],
    ) -> (Vec<Credential>, Vec<Error>) {
        let mut order: Vec<&Credential> = cs.iter().collect();
        order.sort_by_key(|c| rank(c));
        let newer =
            |old: Option<&Credential>, b: &Body| old.is_none_or(|o| o.open().map_or(true, |ob| b.version > ob.version));
        let (mut fresh, mut errs) = (Vec::new(), Vec::new());
        for c in order {
            let b = match c.open() {
                Ok(b) => b,
                Err(e) => {
                    errs.push(e);
                    continue;
                }
            };
            let p = self.period_body(root);
            match b.kind.as_str() {
                PERIOD => {
                    if b.group != self.group {
                        errs.push(Error::msg("a period of another group"));
                        continue;
                    }
                    if c.key != root {
                        errs.push(Error::msg("a period that the group's root did not sign"));
                        continue;
                    }
                    let cur = p.as_ref().and(self.period.as_ref());
                    if !newer(cur, &b) {
                        continue;
                    }
                    if p.as_ref().is_none_or(|p| p.tag != b.tag) {
                        self.servers.clear();
                        (self.hubs, self.members) = (None, None);
                    }
                    self.period = Some(c.clone());
                }
                SERVER => {
                    if p.is_none_or(|p| b.group != self.group || b.tag != p.tag) {
                        continue; // of a period it does not keep
                    }
                    if !member(&c.signer()) {
                        errs.push(Error::msg("a server credential that no member signed"));
                        continue;
                    }
                    let old = self.servers.get(&c.signer());
                    if old.is_some() && !newer(old, &b) {
                        continue;
                    }
                    if old.is_none() && self.servers.len() >= MAX_MEMBERS {
                        errs.push(Error::msg("too many server credentials"));
                        continue;
                    }
                    self.servers.insert(c.signer(), c.clone());
                }
                HUBS => {
                    let Some(p) = p.filter(|p| b.group == p.tag) else { continue };
                    if c.key != p.key {
                        errs.push(Error::msg("a hubs' credential that the period key did not sign"));
                        continue;
                    }
                    if !newer(self.hubs.as_ref(), &b) {
                        continue;
                    }
                    self.hubs = Some(c.clone());
                }
                MEMBERS => {
                    let Some(p) = p.filter(|p| b.group == p.tag) else { continue };
                    if c.key != p.key && !self.listed_admin(&c.signer()) {
                        errs.push(Error::msg(
                            "a members' credential that neither the period key nor a listed admin signed",
                        ));
                        continue;
                    }
                    if !newer(self.members.as_ref(), &b) {
                        continue;
                    }
                    self.members = Some(c.clone());
                }
                _ => continue,
            }
            fresh.push(c.clone());
        }
        (fresh, errs)
    }

    /// The period kept, if root signed it.
    fn period_body(&self, root: &[u8]) -> Option<Body> {
        self.period.as_ref().filter(|p| p.key == root).and_then(|p| p.open().ok())
    }

    fn listed_admin(&self, k: &KeyHash) -> bool {
        self.hubs.as_ref().and_then(|h| h.open().ok()).is_some_and(|b| b.admins.contains(k))
    }

    /// Every credential it keeps: the period, the server credentials, the
    /// hubs' and the members', each kind ordered by its ID.
    pub fn all(&self) -> Vec<Credential> {
        let mut out: Vec<Credential> =
            [&self.period, &self.hubs, &self.members].into_iter().flatten().cloned().collect();
        out.extend(self.servers.values().cloned());
        out.sort_by(|a, b| rank(a).cmp(&rank(b)).then_with(|| sha256(&a.body).cmp(&sha256(&b.body))));
        out
    }

    /// The period kept and its body, if the group's current root root
    /// signed it.
    pub fn period(&self, root: &[u8]) -> Option<(Credential, Body)> {
        let b = self.period_body(root)?;
        self.period.clone().map(|c| (c, b))
    }

    /// The hash of the server key that the member key member signed for the
    /// period kept.
    pub fn server(&self, member: &KeyHash) -> Option<KeyHash> {
        self.servers.get(member).and_then(|c| c.open().ok()).map(|b| sha256(&b.key))
    }

    /// The member key that signed the server key k for the period kept:
    /// whom a pseudonym at the relay names.
    pub fn member_of_server(&self, k: &KeyHash) -> Option<KeyHash> {
        self.servers.iter().find(|(_, c)| c.open().is_ok_and(|b| sha256(&b.key) == *k)).map(|(m, _)| *m)
    }

    /// Each member key that sent a server key for the period kept, with
    /// the hash of that key.
    pub fn servers(&self) -> Vec<(KeyHash, KeyHash)> {
        self.servers.iter().filter_map(|(m, c)| c.open().ok().map(|b| (*m, sha256(&b.key)))).collect()
    }

    /// The server keys of the member keys ms, in their order, leaving out
    /// those that sent none for the period kept.
    pub fn server_keys(&self, ms: &[KeyHash]) -> Vec<KeyHash> {
        ms.iter().filter_map(|m| self.server(m)).collect()
    }

    /// The hubs' credential kept for the period, and its body.
    pub fn hubs(&self) -> Option<(Credential, Body)> {
        self.hubs.as_ref().and_then(|c| c.open().ok().map(|b| (c.clone(), b)))
    }

    /// The members' credential kept for the period, and its body.
    pub fn members(&self) -> Option<(Credential, Body)> {
        self.members.as_ref().and_then(|c| c.open().ok().map(|b| (c.clone(), b)))
    }

    /// Whether the root must start a new period, as Go's PeriodStale: there
    /// is none from this root, it is PERIOD_RENEW_MS old, or a member that
    /// sent a server credential for it is no longer in the group.
    pub fn period_stale(&self, root: &[u8], member: &dyn Fn(&KeyHash) -> bool, now_ms: i64) -> bool {
        let Some(p) = self.period_body(root) else { return true };
        if p.expires_ms.saturating_sub(now_ms) < PERIOD_LIFETIME_MS - PERIOD_RENEW_MS {
            return true;
        }
        self.servers.keys().any(|m| !member(m))
    }

    /// Whether a credential's list got needs a new version for the server
    /// keys want, as Go's ListStale: a key it wants is missing, the first
    /// ones are not want in its order when ordered, or it names a server key
    /// it keeps that it no longer wants. Padding never matches a kept key.
    pub fn list_stale(&self, got: &[KeyHash], want: &[KeyHash], ordered: bool) -> bool {
        if got.len() != pad_to(want.len()) || ordered && got.get(..want.len()) != Some(want) {
            return true;
        }
        want.iter().any(|k| !got.contains(k))
            || got.iter().any(|k| !want.contains(k) && self.member_of_server(k).is_some())
    }
}

/// The size a list of n entries is padded to: the next of 4, 8, 16, 32,
/// 64, 128 and 256.
pub fn pad_to(n: usize) -> usize {
    let mut size = 4;
    while size < n {
        size = size.saturating_mul(2);
    }
    size
}

/// ks with random 32-byte strings up to pad_to(len): a key hash looks
/// random, so the padding cannot be told from a real entry.
fn pad(ks: &[KeyHash]) -> Result<Vec<KeyHash>> {
    let mut out = ks.to_vec();
    while out.len() < pad_to(ks.len()) {
        out.push(random32()?);
    }
    Ok(out)
}

/// 32 random bytes, drawn as returned values.
fn random32() -> Result<[u8; 32]> {
    let word = || getrandom::u64().map(u128::from).map_err(|_| Error::msg("the system has no randomness"));
    let (a, b) = ((word()? << 64 | word()?).to_le_bytes(), (word()? << 64 | word()?).to_le_bytes());
    let mut k = a.to_vec();
    k.extend_from_slice(&b);
    k.try_into().map_err(|_| Error::msg("the system has no randomness"))
}

/// The version of a credential after prev: one above it, or the time in
/// seconds when that is more, so that a signer that lost its state still
/// signs a newer version.
pub fn next_version(prev: u64, now_ms: i64) -> u64 {
    prev.saturating_add(1).max(u64::try_from(now_ms / 1000).unwrap_or(0))
}

/// A fresh tag for the servers: 8 random bytes in hex.
pub fn new_period_tag() -> Result<String> {
    let b = getrandom::u64().map_err(|_| Error::msg("the system has no randomness"))?.to_le_bytes();
    Ok(b.iter().map(|x| format!("{x:02x}")).collect())
}

/// Signs a credential body: `signer` is the key's SubjectPublicKeyInfo,
/// and `sign` makes an ECDSA P-256 signature with SHA-256 over the bytes
/// it is given, DER, as Go's SignCredential.
pub fn sign(mut b: Body, signer: &[u8], sign: &mut dyn FnMut(&[u8]) -> Result<Vec<u8>>) -> Result<Credential> {
    b.v = 1;
    b.check()?;
    let body = serde_json::to_vec(&b).map_err(|_| Error::msg("cannot encode the credential"))?;
    Body::parse(&body)?;
    let c = Credential { sig: sign(&body)?, body, key: signer.to_vec() };
    c.open()?;
    Ok(c)
}

/// The period of the group of group_tag with the servers' tag and the
/// period key, lasting PERIOD_LIFETIME_MS from now, which the root signs.
pub fn period_body(group_tag: &str, tag: &str, key_spki: &[u8], version: u64, now_ms: i64) -> Body {
    Body {
        kind: PERIOD.into(),
        group: group_tag.into(),
        version,
        expires_ms: now_ms.saturating_add(PERIOD_LIFETIME_MS),
        tag: tag.into(),
        key: key_spki.to_vec(),
        ..Body::default()
    }
}

/// A device's server key for the period p, which its member key signs.
pub fn server_body(p: &Body, key_spki: &[u8], version: u64) -> Body {
    Body {
        kind: SERVER.into(),
        group: p.group.clone(),
        version,
        expires_ms: p.expires_ms,
        tag: p.tag.clone(),
        key: key_spki.to_vec(),
        ..Body::default()
    }
}

/// The period's hubs' credential, the hubs' and the admins' server keys
/// padded, which the period key signs.
pub fn hubs_body(p: &Body, hubs: &[KeyHash], admins: &[KeyHash], version: u64) -> Result<Body> {
    Ok(Body {
        kind: HUBS.into(),
        group: p.tag.clone(),
        version,
        expires_ms: p.expires_ms,
        hubs: pad(hubs)?,
        admins: pad(admins)?,
        ..Body::default()
    })
}

/// The period's members' credential, the members' server keys padded,
/// which the period key or an admin's server key signs.
pub fn members_body(p: &Body, members: &[KeyHash], version: u64) -> Result<Body> {
    Ok(Body {
        kind: MEMBERS.into(),
        group: p.tag.clone(),
        version,
        expires_ms: p.expires_ms,
        members: pad(members)?,
        ..Body::default()
    })
}
