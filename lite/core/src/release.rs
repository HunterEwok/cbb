// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The signed files that describe a release (docs/protocol.md, section 16),
//! checked as the Go package internal/release checks them: keys.json, in
//! which a root key certifies the release keys; release.json, which lists a
//! release's files with their hashes; and a channel file such as
//! stable.json, which names the current release of its channel.

use alloc::collections::BTreeSet;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use p256::ecdsa::Signature;
use p256::ecdsa::signature::Verifier;
use serde::{Deserialize, Serialize};

use crate::certs::{b64, hex, sha256};
use crate::error::{Error, Result};

/// The largest body a file may carry.
pub const MAX_BODY: usize = 256 << 10;
/// The longest a keys or channel file may stay valid after it was signed.
pub const MAX_LIFETIME_MS: i64 = 100 * 24 * 3600 * 1000;
/// The longest attest-status.json stays valid after it was signed: it
/// must follow Google's list closely.
pub const MAX_STATUS_LIFETIME_MS: i64 = 8 * 24 * 3600 * 1000;

/// The envelope of every release file.
#[derive(Clone, Serialize, Deserialize, PartialEq, Debug)]
pub struct File {
    #[serde(with = "b64")]
    pub body: Vec<u8>,
    #[serde(with = "b64")]
    pub sig: Vec<u8>,
    /// SHA-256 of the signer's SubjectPublicKeyInfo.
    #[serde(with = "b64")]
    pub key: Vec<u8>,
}

#[derive(Deserialize)]
struct Head {
    #[serde(default)]
    v: i64,
    #[serde(default, rename = "type")]
    kind: String,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Key {
    #[serde(with = "b64")]
    pub key: Vec<u8>,
    pub name: String,
    /// `release` when absent; a key of another use, such as the `status`
    /// key of the revocation mirror or the `channel` key that renews the
    /// channel files, signs no release.
    #[serde(default, rename = "use")]
    pub usage: String,
}

/// The body of keys.json.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Keys {
    pub seq: u64,
    pub time_ms: i64,
    pub expires_ms: i64,
    pub keys: Vec<Key>,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Binary {
    pub name: String,
    pub sha256: String,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Asset {
    pub name: String,
    pub size: i64,
    pub sha256: String,
    #[serde(default)]
    pub binaries: Vec<Binary>,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Docker {
    pub image: String,
    pub digest: String,
}

/// The body of release.json.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Release {
    pub version: String,
    pub channel: String,
    pub time_ms: i64,
    #[serde(default)]
    pub min_from: String,
    pub files: Vec<Asset>,
    #[serde(default)]
    pub docker: Option<Docker>,
}

/// The body of a channel file.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Channel {
    pub channel: String,
    pub seq: u64,
    pub time_ms: i64,
    pub expires_ms: i64,
    pub release: String,
    pub release_sha256: String,
}

/// The body of attest-status.json, signed by a status key: the serial
/// numbers Google's list of Android attestation keys revokes.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Status {
    pub seq: u64,
    pub time_ms: i64,
    pub expires_ms: i64,
    /// When Google last changed its list, 0 when it did not say.
    #[serde(default, skip_serializing_if = "is_zero_i64")]
    pub source_ms: i64,
    pub android_revoked: Vec<String>,
}

/// The body of entries.json, signed by a release or channel key: where the
/// project's forwarders and relays are entered (docs/protocol.md, section
/// 16, "Entry points"); their keys stay in keys.json.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Entries {
    pub seq: u64,
    pub time_ms: i64,
    pub expires_ms: i64,
    pub forwarders: Vec<EntryForwarder>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub relays: Vec<EntryRelay>,
}

/// One of the project's blind relays in entries.json.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct EntryRelay {
    /// Its address as keys.json names its key, host:port.
    pub name: String,
    /// Where it is reached now, host:port; none for its name.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub endpoints: Vec<String>,
}

/// One of the project's forwarders in entries.json.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct EntryForwarder {
    /// Its address as keys.json names its key, host:port.
    pub name: String,
    /// The ways in over VLESS for a hub's first registration.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub vless: Vec<EntryVless>,
}

/// A way in over VLESS: XHTTP behind the web server of a site.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct EntryVless {
    pub transport: String,
    pub server_name: String,
    pub port: u16,
    pub path: String,
}

fn is_zero_i64(n: &i64) -> bool {
    *n == 0
}

/// What a device keeps between checks: the highest sequence numbers and
/// version it has taken.
#[derive(Clone, Default, Serialize, Deserialize, PartialEq, Debug)]
pub struct Seen {
    #[serde(default)]
    pub keys_seq: u64,
    #[serde(default)]
    pub channel_seq: u64,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub version: String,
    /// The revocation list's, which the lite member does not take but keeps.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub status_seq: u64,
    /// The keys.json seq under which channel_seq and status_seq hold, as
    /// Go's Seen: keys_seq when 0, as kept before. A newer keys.json, which
    /// only a root signs, starts them again.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub channel_keys_seq: u64,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub status_keys_seq: u64,
    /// The highest entries.json seq taken and the keys.json seq it was
    /// taken under, which check_entries alone sets, as Go's Seen.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub entries_seq: u64,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub entries_keys_seq: u64,
}

/// The most a channel seq may rise past the one held under the same
/// keys.json, as Go's MaxSeqStep.
pub const MAX_SEQ_STEP: u64 = 1 << 16;

/// How far ahead of the device's clock a file may have been signed, when
/// that clock reads 2026 or later, as Go's MaxAhead: a day.
pub const MAX_AHEAD_MS: i64 = 24 * 3600 * 1000;

/// 2026-01-01: before it the clock is not trusted to refuse files signed
/// ahead of it.
const PLAUSIBLE: i64 = 1_767_225_600_000;

/// The seq a file signed under keys.json keys_seq may not go below, as Go's
/// floor.
fn floor(seq: u64, at: u64, seen_keys: u64, keys_seq: u64) -> u64 {
    let at = if at == 0 { seen_keys } else { at };
    if keys_seq > at { 0 } else { seq }
}

fn signed_ahead(time_ms: i64, now_ms: i64) -> bool {
    now_ms >= PLAUSIBLE && time_ms > now_ms.saturating_add(MAX_AHEAD_MS)
}

fn is_zero(n: &u64) -> bool {
    *n == 0
}

impl File {
    /// SHA-256 over the body, which names a release.json.
    pub fn hash(&self) -> [u8; 32] {
        sha256(&self.body)
    }

    fn verify(&self, spkis: &[&[u8]]) -> Result<()> {
        if self.body.len() > MAX_BODY {
            return Err(Error::msg("the file is too large"));
        }
        for spki in spkis {
            if sha256(spki)[..] != self.key[..] {
                continue;
            }
            // As Go's release.ErrSignature, each of these is an answer.
            let key = crate::certs::p256_spki(spki).ok_or_else(|| Error::msg("a key is not P-256").answer())?;
            let sig = Signature::from_der(&self.sig).map_err(|_| Error::msg("the signature is not valid").answer())?;
            return key.verify(&self.body, &sig).map_err(|_| Error::msg("the signature is not valid").answer());
        }
        Err(Error::msg("the signature is not valid").answer())
    }
}

fn decode<'a, T: Deserialize<'a>>(body: &'a [u8], kind: &str) -> Result<T> {
    // The strict form of signed bodies first, so that every program reads
    // a file alike (docs/protocol.md, section 16).
    crate::strict::check(body, &["v", "type"])?;
    let h: Head = serde_json::from_slice(body).map_err(|e| Error::with("the file is not valid", e))?;
    if h.kind != kind {
        return Err(Error::msg(format!("the file is a {:?}, not a {kind:?}", h.kind)));
    }
    if h.v != 1 {
        return Err(Error::msg(format!("unknown version {}", h.v)));
    }
    serde_json::from_slice(body).map_err(|e| Error::with("the file is not valid", e))
}

fn lifetime(time_ms: i64, expires_ms: i64) -> Result<()> {
    lifetime_up_to(time_ms, expires_ms, MAX_LIFETIME_MS)
}

fn lifetime_up_to(time_ms: i64, expires_ms: i64, max: i64) -> Result<()> {
    // A time before 1970 is no signing time; from it the difference cannot
    // leave the range of i64.
    if time_ms < 0 || expires_ms <= time_ms || expires_ms.saturating_sub(time_ms) > max {
        return Err(Error::msg("the file's lifetime is out of range"));
    }
    Ok(())
}

fn is_hex_sha256(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

fn is_channel(s: &str) -> bool {
    let b = s.as_bytes();
    !b.is_empty()
        && b.len() <= 32
        && b.first().is_some_and(u8::is_ascii_lowercase)
        && b.iter().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-')
}

/// Whether s is a site's name: labels of lowercase letters, digits and
/// inner hyphens, at most 63 bytes each, and a last one of 2 to 63 letters.
fn is_site(s: &str) -> bool {
    let labels: Vec<&str> = s.split('.').collect();
    labels.len() >= 2
        && labels.iter().enumerate().all(|(i, l)| {
            let b = l.as_bytes();
            if i.checked_add(1) == Some(labels.len()) {
                (2..=63).contains(&b.len()) && b.iter().all(u8::is_ascii_lowercase)
            } else {
                (1..=63).contains(&b.len())
                    && b.iter().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-')
                    && b.first() != Some(&b'-')
                    && b.last() != Some(&b'-')
            }
        })
}

/// Whether s is a forwarder's name, host:port.
fn is_entry_name(s: &str) -> bool {
    match s.rsplit_once(':') {
        Some((host, port)) => {
            is_site(host)
                && !port.is_empty()
                && port.len() <= 5
                && !port.starts_with('0')
                && port.bytes().all(|c| c.is_ascii_digit())
                && port.parse::<u32>().is_ok_and(|p| p <= 65535)
        }
        None => false,
    }
}

/// Whether s is the path of a way in: a slash and 8 to 64 letters, digits,
/// '-' or '_'.
fn is_entry_path(s: &str) -> bool {
    let b = s.as_bytes();
    b.first() == Some(&b'/')
        && (9..=65).contains(&b.len())
        && b.get(1..).is_some_and(|r| r.iter().all(|c| c.is_ascii_alphanumeric() || *c == b'-' || *c == b'_'))
}

/// The bounds of entries.json.
const MAX_ENTRY_FORWARDERS: usize = 16;
const MAX_ENTRY_VLESS: usize = 8;
const MAX_ENTRY_RELAYS: usize = 16;
const MAX_ENTRY_ENDPOINTS: usize = 8;

pub(crate) fn decode_entries(body: &[u8]) -> Result<Entries> {
    let e: Entries = decode(body, "entries")?;
    if e.seq == 0 {
        return Err(Error::msg("entries.json has no sequence number"));
    }
    lifetime(e.time_ms, e.expires_ms)?;
    if e.forwarders.len() > MAX_ENTRY_FORWARDERS {
        return Err(Error::msg("entries.json has too long a list of forwarders"));
    }
    let mut names = BTreeSet::new();
    for f in &e.forwarders {
        if !is_entry_name(&f.name) || !names.insert(f.name.as_str()) {
            return Err(Error::msg(format!("{:?} is not a forwarder's name, or twice", f.name)));
        }
        if f.vless.len() > MAX_ENTRY_VLESS {
            return Err(Error::msg(format!("{} has too many ways in", f.name)));
        }
        for v in &f.vless {
            if v.transport != "xhttp" || !is_site(&v.server_name) || v.port == 0 || !is_entry_path(&v.path) {
                return Err(Error::msg(format!("a way in to {} is not usable", f.name)));
            }
        }
    }
    if e.relays.len() > MAX_ENTRY_RELAYS {
        return Err(Error::msg("entries.json has too long a list of relays"));
    }
    let mut names = BTreeSet::new();
    for r in &e.relays {
        if !is_entry_name(&r.name) || !names.insert(r.name.as_str()) {
            return Err(Error::msg(format!("{:?} is not a relay's name, or twice", r.name)));
        }
        if r.endpoints.len() > MAX_ENTRY_ENDPOINTS {
            return Err(Error::msg(format!("{} has too many addresses", r.name)));
        }
        if let Some(ep) = r.endpoints.iter().find(|ep| !is_entry_name(ep)) {
            return Err(Error::msg(format!("{ep:?} is not an address of {}", r.name)));
        }
    }
    Ok(e)
}

fn name_ok(s: &str, max: usize, slash: bool) -> bool {
    let b = s.as_bytes();
    !b.is_empty()
        && b.len() <= max
        && b.first().is_some_and(|c| c.is_ascii_alphanumeric() || *c == b'_')
        && b.iter().all(|c| c.is_ascii_alphanumeric() || b"._-".contains(c) || (slash && *c == b'/'))
}

/// Parses a version of the form X.Y.Z or X.Y.Z-rc.N into X, Y, Z and the
/// release candidate's number, u32::MAX for a release.
pub fn parse_version(s: &str) -> Option<[u32; 4]> {
    fn number(part: &str, zero: bool) -> Option<u32> {
        if part.is_empty() || part.len() > 6 || !part.bytes().all(|c| c.is_ascii_digit()) {
            return None;
        }
        if (part.len() > 1 || !zero) && part.starts_with('0') {
            return None;
        }
        part.parse().ok()
    }
    let (main, rc) = match s.split_once("-rc.") {
        Some((m, n)) => (m, number(n, false)?),
        None => (s, u32::MAX),
    };
    let mut out = [0u32, 0, 0, rc];
    let mut parts = main.split('.');
    for p in out.iter_mut().take(3) {
        *p = number(parts.next()?, true)?;
    }
    if parts.next().is_some() { None } else { Some(out) }
}

/// Compares two versions, a release candidate before its release; a string that is not a version sorts below
/// every version.
pub fn compare(a: &str, b: &str) -> core::cmp::Ordering {
    parse_version(a).cmp(&parse_version(b))
}

pub(crate) fn decode_keys(body: &[u8]) -> Result<Keys> {
    let k: Keys = decode(body, "keys")?;
    if k.seq == 0 {
        return Err(Error::msg("keys.json has no sequence number"));
    }
    lifetime(k.time_ms, k.expires_ms)?;
    if k.keys.is_empty() || k.keys.len() > 8 {
        return Err(Error::msg("keys.json must hold 1 to 8 keys"));
    }
    for key in &k.keys {
        if key.name.is_empty() || key.name.len() > 64 {
            return Err(Error::msg("a key has no valid name"));
        }
        crate::certs::p256_spki(&key.key).ok_or_else(|| Error::msg("a key is not P-256"))?;
    }
    // A key's use is left out for a release key, never written empty.
    #[derive(Deserialize)]
    struct RawKey {
        #[serde(rename = "use")]
        usage: Option<String>,
    }
    #[derive(Deserialize)]
    struct RawKeys {
        keys: Vec<RawKey>,
    }
    let raw: RawKeys = serde_json::from_slice(body).map_err(|e| Error::with("the file is not valid", e))?;
    if raw.keys.iter().any(|k| k.usage.as_deref() == Some("")) {
        return Err(Error::msg("a key's use is empty"));
    }
    Ok(k)
}

pub(crate) fn decode_release(body: &[u8]) -> Result<Release> {
    let r: Release = decode(body, "release")?;
    if parse_version(&r.version).is_none() || (!r.min_from.is_empty() && parse_version(&r.min_from).is_none()) {
        return Err(Error::msg("release.json names no valid version"));
    }
    if !is_channel(&r.channel) || r.files.is_empty() || r.files.len() > 256 {
        return Err(Error::msg("release.json is not valid"));
    }
    let mut names = BTreeSet::new();
    for a in &r.files {
        if !name_ok(&a.name, 128, false) || !names.insert(a.name.as_str()) {
            return Err(Error::msg(format!("{:?} is not a valid file name", a.name)));
        }
        if a.size < 0 || !is_hex_sha256(&a.sha256) || a.binaries.len() > 64 {
            return Err(Error::msg(format!("the entry for {} is not valid", a.name)));
        }
        for b in &a.binaries {
            if !name_ok(&b.name, 256, true) || b.name.contains("..") || !is_hex_sha256(&b.sha256) {
                return Err(Error::msg(format!("a binary in {} is not valid", a.name)));
            }
        }
    }
    if let Some(d) = &r.docker {
        let ok = d.digest.strip_prefix("sha256:").is_some_and(is_hex_sha256);
        if d.image.is_empty() || !ok {
            return Err(Error::msg("the Docker image is not valid"));
        }
    }
    Ok(r)
}

pub(crate) fn decode_channel(body: &[u8]) -> Result<Channel> {
    let c: Channel = decode(body, "channel")?;
    if !is_channel(&c.channel) || c.seq == 0 {
        return Err(Error::msg("the channel file is not valid"));
    }
    lifetime(c.time_ms, c.expires_ms)?;
    if parse_version(&c.release).is_none() || !is_hex_sha256(&c.release_sha256) {
        return Err(Error::msg("the channel file names no valid release"));
    }
    Ok(c)
}

/// Whether s is a serial number as attest-status.json writes it: lowercase
/// hex without leading zeros, at most 64 digits.
fn is_serial(s: &str) -> bool {
    let b = s.as_bytes();
    s == "0"
        || (!b.is_empty()
            && b.len() <= 64
            && b.first().is_some_and(|c| *c != b'0')
            && b.iter().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(c)))
}

/// Orders serial numbers as numbers: the shorter first, then as strings.
fn serial_less(a: &str, b: &str) -> bool {
    if a.len() != b.len() { a.len() < b.len() } else { a < b }
}

pub(crate) fn decode_status(body: &[u8]) -> Result<Status> {
    let s: Status = decode(body, "attest-status")?;
    if s.seq == 0 {
        return Err(Error::msg("attest-status.json has no sequence number"));
    }
    lifetime_up_to(s.time_ms, s.expires_ms, MAX_STATUS_LIFETIME_MS)?;
    let mut prev: Option<&String> = None;
    for r in &s.android_revoked {
        if !is_serial(r) || prev.is_some_and(|p| !serial_less(p, r)) {
            return Err(Error::msg(format!("{r:?} is not a serial number in order")));
        }
        prev = Some(r);
    }
    Ok(s)
}

/// Checks keys.json against the pinned root keys (SubjectPublicKeyInfos,
/// DER) at now_ms, and that it is not older than seen.
pub fn verify_keys(f: &File, roots: &[&[u8]], now_ms: i64, seen: &Seen) -> Result<Keys> {
    f.verify(roots)?;
    let k = decode_keys(&f.body)?;
    if now_ms >= k.expires_ms {
        return Err(Error::msg("keys.json has expired"));
    }
    if signed_ahead(k.time_ms, now_ms) {
        return Err(Error::msg("keys.json was signed ahead of this device's clock"));
    }
    if k.seq < seen.keys_seq {
        return Err(Error::msg("keys.json is older than one already seen").answer());
    }
    Ok(k)
}

/// Checks a channel file and the release.json it names, as Go's
/// release.Check does, and returns the release and the new Seen to keep.
pub fn check(
    keys: &File,
    channel: &File,
    rel: &File,
    roots: &[&[u8]],
    name: &str,
    now_ms: i64,
    seen: &Seen,
) -> Result<(Release, Seen)> {
    let k = verify_keys(keys, roots, now_ms, seen).map_err(|e| e.context("keys.json is not valid"))?;
    let of = |usage: &str| -> Vec<&[u8]> {
        k.keys
            .iter()
            .filter(|key| key.usage == usage || (key.usage.is_empty() && usage == "release"))
            .map(|key| key.key.as_slice())
            .collect()
    };
    let spkis = of("release");
    // A channel key signs channel files and nothing else.
    let mut channel_spkis = spkis.clone();
    channel_spkis.extend(of("channel"));
    channel.verify(&channel_spkis).map_err(|e| e.context(format!("{name}.json is not valid")))?;
    let c = decode_channel(&channel.body).map_err(|e| e.context(format!("{name}.json is not valid")))?;
    if c.channel != name {
        return Err(Error::msg(format!("{name}.json is for the channel {:?}", c.channel)));
    }
    if now_ms >= c.expires_ms {
        return Err(Error::msg(format!("{name}.json has expired")));
    }
    if signed_ahead(c.time_ms, now_ms) {
        return Err(Error::msg(format!("{name}.json was signed ahead of this device's clock")));
    }
    let at = floor(seen.channel_seq, seen.channel_keys_seq, seen.keys_seq, k.seq);
    if c.seq < at {
        return Err(Error::msg(format!("{name}.json is older than one already seen")).answer());
    }
    if c.seq.saturating_sub(at) > MAX_SEQ_STEP {
        return Err(Error::msg(format!("{name}.json is too far ahead of the one already seen")));
    }
    rel.verify(&spkis).map_err(|e| e.context("release.json is not valid"))?;
    if hex(&rel.hash()) != c.release_sha256 {
        return Err(Error::msg(format!("release.json is not the release {name}.json names")));
    }
    let r = decode_release(&rel.body).map_err(|e| e.context("release.json is not valid"))?;
    if r.version != c.release || r.channel != c.channel {
        return Err(Error::msg(format!(
            "release.json is {} on {}, {name}.json names {}",
            r.version, r.channel, c.release
        )));
    }
    if !seen.version.is_empty() && compare(&r.version, &seen.version).is_lt() {
        return Err(Error::msg("release.json is older than a release already seen").answer());
    }
    let version = if !seen.version.is_empty() && compare(&seen.version, &r.version).is_gt() {
        seen.version.clone()
    } else {
        r.version.clone()
    };
    let status_keys_seq = if seen.status_keys_seq == 0 { seen.keys_seq } else { seen.status_keys_seq };
    Ok((
        r,
        Seen {
            keys_seq: k.seq,
            channel_seq: c.seq,
            version,
            status_seq: seen.status_seq,
            channel_keys_seq: k.seq,
            status_keys_seq,
            entries_seq: seen.entries_seq,
            entries_keys_seq: seen.entries_keys_seq,
        },
    ))
}

/// Checks entries.json as Go's release.CheckEntries does: keys.json under
/// the pinned roots, the list under a release or channel key of it, its
/// expiry, and that neither is older than seen. Returns the list and the
/// Seen to keep.
pub fn check_entries(
    keys: &File,
    entries: &File,
    roots: &[&[u8]],
    now_ms: i64,
    seen: &Seen,
) -> Result<(Entries, Seen)> {
    let k = verify_keys(keys, roots, now_ms, seen).map_err(|e| e.context("keys.json is not valid"))?;
    let spkis: Vec<&[u8]> = k
        .keys
        .iter()
        .filter(|key| key.usage.is_empty() || key.usage == "release" || key.usage == "channel")
        .map(|key| key.key.as_slice())
        .collect();
    let bad = |e: Error| e.context("entries.json is not valid");
    entries.verify(&spkis).map_err(bad)?;
    let e = decode_entries(&entries.body).map_err(bad)?;
    if now_ms >= e.expires_ms {
        return Err(Error::msg("entries.json has expired"));
    }
    if signed_ahead(e.time_ms, now_ms) {
        return Err(Error::msg("entries.json was signed ahead of this device's clock"));
    }
    let at = floor(seen.entries_seq, seen.entries_keys_seq, seen.keys_seq, k.seq);
    if e.seq < at {
        return Err(Error::msg("entries.json is older than one already seen").answer());
    }
    if e.seq.saturating_sub(at) > MAX_SEQ_STEP {
        return Err(Error::msg("entries.json is too far ahead of the one already seen"));
    }
    let next = Seen { keys_seq: k.seq, entries_seq: e.seq, entries_keys_seq: k.seq, ..seen.clone() };
    Ok((e, next))
}

impl Release {
    /// Reports whether a device at installed may update to this release in
    /// one step, or must first take min_from.
    pub fn direct(&self, installed: &str) -> bool {
        self.min_from.is_empty() || compare(installed, &self.min_from).is_ge()
    }

    /// Checks that data is the release's file name.
    pub fn check_file(&self, name: &str, data: &[u8]) -> Result<()> {
        let a = self
            .files
            .iter()
            .find(|a| a.name == name)
            .ok_or_else(|| Error::msg(format!("{name} is not in the release")))?;
        if a.size != data.len() as i64 || hex(&sha256(data)) != a.sha256 {
            return Err(Error::msg(format!("{name} does not match release.json")));
        }
        Ok(())
    }
}

/// The files zxnext.json lists, each once: the ZX Spectrum Next's dot
/// command, its overlay, its driver and the Pi's cbb.
pub const ZXNEXT_NAMES: [&str; 4] = ["CBB", "CBB.OVL", "CBB.DRV", "cbb"];
/// The largest file zxnext.json may list.
pub const MAX_ZXNEXT_FILE: i64 = 64 << 20;

/// One of the Next's files, as packaging/zxnext/site.sh lists it.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct ZXNextFile {
    pub name: String,
    pub size: i64,
    pub crc32: String,
    pub sha256: String,
}

/// The body of zxnext.json, signed by a release key: the Next's files of a
/// release, which the Pi's cbb checks before `.cbb update` takes a newer
/// CBB (docs/protocol.md, section 16, "The ZX Spectrum Next's files").
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct ZXNext {
    pub version: String,
    pub time_ms: i64,
    pub files: Vec<ZXNextFile>,
}

pub(crate) fn decode_zxnext(body: &[u8]) -> Result<ZXNext> {
    let z: ZXNext = decode(body, "zxnext")?;
    if parse_version(&z.version).is_none() {
        return Err(Error::msg(format!("{:?} is not a version", z.version)));
    }
    if z.time_ms < 0 {
        return Err(Error::msg("zxnext.json has no signing time"));
    }
    if z.files.len() != ZXNEXT_NAMES.len() {
        return Err(Error::msg("zxnext.json must list the Next's four files"));
    }
    let mut names = BTreeSet::new();
    for f in &z.files {
        if !ZXNEXT_NAMES.contains(&f.name.as_str()) || !names.insert(f.name.as_str()) {
            return Err(Error::msg(format!("{:?} is not one of the Next's files, or twice", f.name)));
        }
        let crc = f.crc32.len() == 8 && f.crc32.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c));
        if f.size <= 0 || f.size > MAX_ZXNEXT_FILE || !crc || !is_hex_sha256(&f.sha256) {
            return Err(Error::msg(format!("the entry for {} is not valid", f.name)));
        }
    }
    Ok(z)
}

/// Checks zxnext.json as Go's release.CheckZXNext does: keys.json under the
/// pinned roots, the list under one of its release keys, not signed ahead
/// of now_ms, and not of a release older than installed, the version of
/// the cbb that checks it (none when empty).
pub fn check_zxnext(keys: &File, list: &File, roots: &[&[u8]], now_ms: i64, installed: &str) -> Result<ZXNext> {
    let k = verify_keys(keys, roots, now_ms, &Seen::default()).map_err(|e| e.context("keys.json is not valid"))?;
    let spkis: Vec<&[u8]> = k
        .keys
        .iter()
        .filter(|key| key.usage.is_empty() || key.usage == "release")
        .map(|key| key.key.as_slice())
        .collect();
    let bad = |e: Error| e.context("zxnext.json is not valid");
    list.verify(&spkis).map_err(bad)?;
    let z = decode_zxnext(&list.body).map_err(bad)?;
    if signed_ahead(z.time_ms, now_ms) {
        return Err(Error::msg("zxnext.json was signed ahead of this device's clock"));
    }
    if !installed.is_empty() && compare(&z.version, installed).is_lt() {
        return Err(Error::msg(format!("zxnext.json is of {}, older than this cbb, {installed}", z.version)));
    }
    Ok(z)
}
