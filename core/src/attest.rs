// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! Android Key Attestation (docs/protocol.md, section 17, "Evidence" and
//! "Revoked attestations"), as Go's internal/attest CheckAndroid, the Swift
//! kit's AndroidAttestation and the Kotlin kit's do, for a root phone whose
//! app signs through the core: the leaf certifies the key and carries the
//! Keystore's description of it, every certificate that signs another is a
//! CA that may sign it, and the chain leads to one of Google's attestation
//! roots. testdata/interop/go-attest.json keeps the four in step.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt::Write as _;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use sha2::{Digest, Sha256};

use crate::tls::web::verify_signed;

/// The SubjectPublicKeyInfos of Google's attestation roots: the RSA root of
/// every chain until 2026 and the ECDSA P-384 "Key Attestation CA1", in
/// base64.
pub const GOOGLE_ROOTS: [&str; 2] = [
    "MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAr7bHgiuxpwHsK7Qui8xUFmOr75gvMsd/dTEDDJdSSxtf6An7xyqpRR90PL2abxM1dEqlXnf2tqw1Ne4Xwl5jlRfdnJLmN0pTy/4lj4/7tv0Sk3iiKkypnEUtR6WfMgH0QZfKHM1+di+y9TFRtv6y//0rb+T+W8a9nsNL/ggjnar86461qO0rOs2cXjp3kOG1FEJ5MVmFmBGtnrKpa73XpXyTqRxB/M0n1n/W9nGqC4FSYa04T6N5RIZGBN2z2MT5IKGbFlbC8UrW0DxW7AYImQQcHtGl/m00QLVWutHQoVJYnFPlXTcHYvASLu+RhhsbDmxMgJJ0mcDpvsC4PjvB+TxywElgS70vE0XmLD+OJtvsBslHZvPBKCOdT0MS+tgSOIfga+z1Z1g7+DVagf7quvmag8jfPioyKvxnK/EgsTUVi2ghzq8wm27ud/mIM7AY2qEORR8Go3TVB4HzWQgpZrt3i5MIlCaY504LzSRiigHCzAPlHws+W0rB5N+er5/2pJKnfBSDiCiFAVtCLOZ7gLiMm0jhO2B6tUXHI/+MRPjy02i59lINMRRev56GKtcd9qO/0kUJWdZTdA2XoS82ixPvZtXQpUpuL12ab+9EaDK8Z4RHJYYfCT3Q5vNAXaiWQ+8PTWm2QgBR/bkwSWc+NpUFgNPN9PvQi8WEg5UmAGMCAwEAAQ==",
    "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEI9ojcU7fPlsFCjxy6IRqzgeOoK0b+YsV9FPQywiyw8EQRTkJ9u3qwfnI4DGoSLlBqClTXJfgfCcZvs60FikNMHnu4fkRzObfgDkU2KNXezT9/RQ+XvNslxPHrHCowhGr",
];

pub const KIND_TEE: &str = "android-tee";
pub const KIND_STRONGBOX: &str = "android-strongbox";
/// The stores a device record names (docs/protocol.md, section 10).
pub const STORE_PROVEN: &str = "proven";
pub const STORE_HARDWARE: &str = "hardware";
pub const STORE_FILE: &str = "file";
/// The size of the salt a phone keeps with its key.
pub const SALT_SIZE: usize = 16;

const OID_KEY_DESCRIPTION: &str = "1.3.6.1.4.1.11129.2.1.17";
const OID_PROVISIONING: &str = "1.3.6.1.4.1.11129.2.1.30";
const OID_BASIC_CONSTRAINTS: &str = "2.5.29.19";
const OID_KEY_USAGE: &str = "2.5.29.15";
/// keyCertSign in the first byte of a key usage's bits.
const KEY_CERT_SIGN: u8 = 0x04;
const LEVEL_SOFTWARE: i64 = 0;
const LEVEL_STRONGBOX: i64 = 2;
const BOOT_VERIFIED: i64 = 0;
const BOOT_SELF_SIGNED: i64 = 1;
const TAG_ROOT_OF_TRUST: u32 = 704;

/// The challenge a phone's key is made with, so that its attestation proves
/// it belongs to this device and, when there is one, this group:
///
/// ```text
/// SHA-256("cbb attest v1" || field(group tag) || field(member key) || salt)
/// ```
///
/// field is a two-byte big-endian length and the bytes.
pub fn challenge(group_tag: &str, member_key: &[u8], salt: &[u8]) -> Result<[u8; 32], Invalid> {
    if salt.len() != SALT_SIZE {
        return Err(Invalid::new(format!("a salt of {} bytes", salt.len())));
    }
    let mut h = Sha256::new();
    h.update(b"cbb attest v1");
    for f in [group_tag.as_bytes(), member_key] {
        let n = u16::try_from(f.len()).map_err(|_| Invalid::new(format!("a field of {} bytes", f.len())))?;
        h.update(n.to_be_bytes());
        h.update(f);
    }
    h.update(salt);
    Ok(h.finalize().into())
}

/// What a valid attestation shows of a key; why is empty when its store is
/// proven.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Shown {
    pub store: String,
    pub kind: String,
    pub rkp: bool,
    pub why: String,
    pub serials: Vec<String>,
}

/// strict proves only chains of Remote Key Provisioning; revoked holds
/// lowercase hex serials; roots are Google's when None.
#[derive(Debug, Clone, Default)]
pub struct Policy<'a> {
    pub strict: bool,
    pub revoked: &'a [String],
    pub roots: Option<&'a [Vec<u8>]>,
}

/// An attestation that proves nothing: a broken chain, another root, key
/// or challenge, or a revoked certificate (revoked).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invalid {
    pub reason: String,
    pub revoked: bool,
}

impl Invalid {
    fn new(reason: String) -> Invalid {
        Invalid { reason, revoked: false }
    }
}

impl core::fmt::Display for Invalid {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "invalid attestation: {}", self.reason)
    }
}

fn bad(s: &str) -> Invalid {
    Invalid::new(s.to_string())
}

/// Checks chain (DER certificates, leaf first) for the key spki made with
/// challenge.
pub fn check(chain: &[Vec<u8>], spki: &[u8], challenge: &[u8], policy: &Policy<'_>) -> Result<Shown, Invalid> {
    if !(2..=10).contains(&chain.len()) {
        return Err(Invalid::new(format!("a chain of {} certificates", chain.len())));
    }
    let mut certs = Vec::with_capacity(chain.len());
    for (i, der) in chain.iter().enumerate() {
        certs.push(Cert::parse(der).map_err(|e| Invalid::new(format!("certificate {i}: {}", e.reason)))?);
    }
    let mut rkp = false;
    for (i, c) in certs.iter().enumerate() {
        if let Some(next) = certs.get(i.saturating_add(1))
            && !c.signed_by(&next.spki)
        {
            return Err(Invalid::new(format!("certificate {i} is not signed by the next")));
        }
        if policy.revoked.contains(&c.serial) {
            return Err(Invalid { reason: format!("certificate {i} ({}) is revoked", c.serial), revoked: true });
        }
        if i == 0 {
            continue; // the leaf signs nothing and says nothing of provisioning
        }
        // Every other certificate signed the one before it: it must be a CA
        // that may sign certificates, with a path length that fits.
        if !c.is_ca {
            return Err(Invalid::new(format!("certificate {i} signs another and is not a CA")));
        }
        if c.key_usage.is_some_and(|u| u & KEY_CERT_SIGN == 0) {
            return Err(Invalid::new(format!("certificate {i} signs another and may not sign certificates")));
        }
        let below = i.saturating_sub(1);
        if let Some(limit) = c.path_len
            && limit < below
        {
            return Err(Invalid::new(format!("certificate {i} allows {limit} CAs below it, the chain has {below}")));
        }
        if c.extension(OID_PROVISIONING).is_some() {
            rkp = true;
        }
    }
    let last = certs.last().ok_or_else(|| bad("an empty chain"))?;
    let google: Vec<Vec<u8>>;
    let roots: &[Vec<u8>] = match policy.roots {
        Some(r) => r,
        None => {
            google = GOOGLE_ROOTS.iter().filter_map(|r| STANDARD.decode(r).ok()).collect();
            &google
        }
    };
    if !roots.iter().any(|r| last.signed_by(r)) {
        return Err(bad("the chain does not lead to a known root"));
    }
    let leaf = certs.first().ok_or_else(|| bad("an empty chain"))?;
    if leaf.spki != spki {
        return Err(bad("the leaf certifies another key"));
    }
    let ext = leaf.extension(OID_KEY_DESCRIPTION).ok_or_else(|| bad("the leaf has no key description"))?;
    let kd = KeyDescription::parse(ext).map_err(|e| Invalid::new(format!("the key description: {}", e.reason)))?;
    if kd.challenge != challenge {
        return Err(bad("another challenge"));
    }
    let serials: Vec<String> = certs.iter().map(|c| c.serial.clone()).collect();
    if kd.attestation_level == LEVEL_SOFTWARE || kd.key_mint_level == LEVEL_SOFTWARE {
        return Ok(Shown {
            store: STORE_FILE.into(),
            kind: String::new(),
            rkp,
            why: "the Keystore keeps the key in software".into(),
            serials,
        });
    }
    let kind = if kd.attestation_level == LEVEL_STRONGBOX && kd.key_mint_level == LEVEL_STRONGBOX {
        KIND_STRONGBOX
    } else {
        KIND_TEE
    };
    let why = match kd.root {
        Some((locked, _)) if !locked => "the phone's bootloader is unlocked",
        Some((_, BOOT_SELF_SIGNED)) => "the phone boots a system signed with its own key",
        Some((_, state)) if state != BOOT_VERIFIED => "the phone's boot is not verified",
        Some(_) if policy.strict && !rkp => "the chain did not come through Remote Key Provisioning",
        Some(_) => "",
        None => "the key description has no root of trust",
    };
    Ok(Shown {
        store: if why.is_empty() { STORE_PROVEN } else { STORE_HARDWARE }.into(),
        kind: kind.into(),
        rkp,
        why: why.into(),
        serials,
    })
}

/// The proof a device record keeps of a proven key: the hex SHA-256 of the
/// attestation's leaf.
pub fn proof(leaf: &[u8]) -> String {
    hex(&Sha256::digest(leaf))
}

fn hex(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len().saturating_mul(2));
    for x in b {
        let _ = write!(s, "{x:02x}");
    }
    s
}

/// What check reads of a certificate.
struct Cert {
    tbs: Vec<u8>,
    algorithm: String,
    signature: Vec<u8>,
    serial: String,
    spki: Vec<u8>,
    extensions: Vec<(String, Vec<u8>)>,
    is_ca: bool,
    path_len: Option<usize>,
    /// The first byte of the key usage's bits; None without the extension.
    key_usage: Option<u8>,
}

impl Cert {
    fn parse(der: &[u8]) -> Result<Cert, Invalid> {
        let top = Tlv::read(der, 0, der.len())?;
        if top.tag != 0x30 || top.end != der.len() {
            return Err(bad("not a certificate"));
        }
        let f = top.children(der)?;
        let [tbs, alg, sig] = f.as_slice() else {
            return Err(Invalid::new(format!("{} fields", f.len())));
        };
        let alg = alg.expect(0x30)?.children(der)?;
        let algorithm = oid(alg.first().ok_or_else(|| bad("no algorithm"))?.expect(0x06)?.content(der))?;
        let bits = sig.expect(0x03)?.content(der);
        let Some((0, signature)) = bits.split_first() else {
            return Err(bad("a signature with unused bits"));
        };
        let mut t = tbs.expect(0x30)?.children(der)?;
        if t.first().is_some_and(|x| x.cls == 2 && x.number == 0) {
            t.remove(0);
        }
        if t.len() < 6 {
            return Err(bad("a short TBSCertificate"));
        }
        let field = |i: usize| t.get(i).ok_or_else(|| bad("a short TBSCertificate"));
        let serial = serial_hex(field(0)?.expect(0x02)?.content(der));
        let spki = field(5)?.expect(0x30)?.full(der).to_vec();
        let mut c = Cert {
            tbs: tbs.full(der).to_vec(),
            algorithm,
            signature: signature.to_vec(),
            serial,
            spki,
            extensions: Vec::new(),
            is_ca: false,
            path_len: None,
            key_usage: None,
        };
        for e in t.iter().skip(6).filter(|e| e.cls == 2 && e.number == 3) {
            let inner = e.children(der)?;
            let Some(list) = inner.first() else { continue };
            for x in list.expect(0x30)?.children(der)? {
                let parts = x.expect(0x30)?.children(der)?;
                let (Some(id), Some(value)) = (parts.first(), parts.last()) else {
                    return Err(bad("an extension"));
                };
                if parts.len() < 2 {
                    return Err(bad("an extension"));
                }
                c.extensions.push((oid(id.expect(0x06)?.content(der))?, value.expect(0x04)?.content(der).to_vec()));
            }
        }
        if let Some(bc) = c.extension(OID_BASIC_CONSTRAINTS) {
            let b = Tlv::read(bc, 0, bc.len())?;
            if b.tag != 0x30 || b.end != bc.len() {
                return Err(bad("basic constraints"));
            }
            let (mut is_ca, mut path_len) = (false, None);
            for (n, x) in b.children(bc)?.iter().enumerate() {
                let v = x.content(bc);
                match (x.tag, v) {
                    (0x01, [flag]) if n == 0 => is_ca = *flag != 0,
                    (0x02, [a]) if a & 0x80 == 0 => path_len = Some(usize::from(*a)),
                    (0x02, [a, b]) if a & 0x80 == 0 => path_len = Some(usize::from(*a) << 8 | usize::from(*b)),
                    _ => return Err(bad("basic constraints")),
                }
            }
            c.is_ca = is_ca;
            // A path length means something on a CA only.
            c.path_len = if is_ca { path_len } else { None };
        }
        if let Some(ku) = c.extension(OID_KEY_USAGE) {
            let b = Tlv::read(ku, 0, ku.len())?;
            if b.tag != 0x03 || b.end != ku.len() {
                return Err(bad("key usage"));
            }
            c.key_usage = Some(b.content(ku).get(1).copied().unwrap_or(0));
        }
        Ok(c)
    }

    fn extension(&self, id: &str) -> Option<&[u8]> {
        self.extensions.iter().rev().find(|(k, _)| k == id).map(|(_, v)| v.as_slice())
    }

    /// Whether the key spki signed this certificate.
    fn signed_by(&self, spki: &[u8]) -> bool {
        let Ok((alg, curve, key)) = spki_parts(spki) else { return false };
        verify_signed(&alg, &curve, key, &self.algorithm, &self.tbs, &self.signature)
    }
}

/// A SubjectPublicKeyInfo's algorithm, its curve (empty for RSA) and its
/// key's bits.
fn spki_parts(spki: &[u8]) -> Result<(String, String, &[u8]), Invalid> {
    let top = Tlv::read(spki, 0, spki.len())?;
    if top.tag != 0x30 || top.end != spki.len() {
        return Err(bad("not a public key"));
    }
    let f = top.children(spki)?;
    let [alg, bits] = f.as_slice() else { return Err(bad("not a public key")) };
    let a = alg.expect(0x30)?.children(spki)?;
    let id = oid(a.first().ok_or_else(|| bad("no algorithm"))?.expect(0x06)?.content(spki))?;
    let curve = match a.get(1) {
        Some(c) if c.tag == 0x06 => oid(c.content(spki))?,
        _ => String::new(),
    };
    let Some((0, key)) = bits.expect(0x03)?.content(spki).split_first() else {
        return Err(bad("a key with unused bits"));
    };
    Ok((id, curve, key))
}

/// A serial number as Google's revocation list writes it: lowercase hex
/// without leading zeros.
fn serial_hex(b: &[u8]) -> String {
    let s = hex(b);
    let t = s.trim_start_matches('0');
    if t.is_empty() { "0".into() } else { t.into() }
}

/// attestationVersion, attestationSecurityLevel, keyMintVersion,
/// keyMintSecurityLevel, attestationChallenge, uniqueId, softwareEnforced,
/// hardwareEnforced; only the hardware-enforced root of trust counts, as
/// (deviceLocked, verifiedBootState).
struct KeyDescription {
    attestation_level: i64,
    key_mint_level: i64,
    challenge: Vec<u8>,
    root: Option<(bool, i64)>,
}

impl KeyDescription {
    fn parse(der: &[u8]) -> Result<KeyDescription, Invalid> {
        let top = Tlv::read(der, 0, der.len())?;
        if top.tag != 0x30 || top.end != der.len() {
            return Err(bad("not a sequence"));
        }
        let f = top.children(der)?;
        if f.len() < 8 {
            return Err(Invalid::new(format!("{} fields", f.len())));
        }
        let field = |i: usize| f.get(i).ok_or_else(|| bad("a short key description"));
        let mut kd = KeyDescription {
            attestation_level: enumerated(field(1)?, der)?,
            key_mint_level: enumerated(field(3)?, der)?,
            challenge: field(4)?.expect(0x04)?.content(der).to_vec(),
            root: None,
        };
        for a in field(7)?.expect(0x30)?.children(der)? {
            if a.cls != 2 || a.number != TAG_ROOT_OF_TRUST {
                continue;
            }
            let inner = a.children(der)?;
            let [r] = inner.as_slice() else { return Err(bad("rootOfTrust")) };
            let r = r.expect(0x30)?.children(der)?;
            let (Some(locked), Some(state)) = (r.get(1), r.get(2)) else {
                return Err(bad("rootOfTrust"));
            };
            let [locked] = locked.expect(0x01)?.content(der) else {
                return Err(bad("deviceLocked"));
            };
            kd.root = Some((*locked != 0, enumerated(state, der)?));
        }
        Ok(kd)
    }
}

fn enumerated(t: &Tlv, der: &[u8]) -> Result<i64, Invalid> {
    let b = t.expect(0x0a)?.content(der);
    let Some(&first) = b.first() else { return Err(bad("an empty enumerated")) };
    if b.len() > 4 {
        return Err(Invalid::new(format!("an enumerated of {} bytes", b.len())));
    }
    let start: i64 = if first & 0x80 != 0 { -1 } else { 0 };
    Ok(b.iter().fold(start, |v, &x| v << 8 | i64::from(x)))
}

/// One DER element of a buffer, with the tags above 30 that the Keystore's
/// authorization lists use: tag is the first byte, cls (0 universal, 2
/// context-specific) and number the tag itself.
#[derive(Debug, Clone, Copy)]
struct Tlv {
    start: usize,
    tag: u8,
    cls: u8,
    number: u32,
    body: usize,
    end: usize,
}

impl Tlv {
    fn content<'a>(&self, b: &'a [u8]) -> &'a [u8] {
        b.get(self.body..self.end).unwrap_or_default()
    }

    fn full<'a>(&self, b: &'a [u8]) -> &'a [u8] {
        b.get(self.start..self.end).unwrap_or_default()
    }

    fn expect(&self, t: u8) -> Result<&Tlv, Invalid> {
        if self.tag != t {
            return Err(Invalid::new(format!("tag {:02x}, not {t:02x}", self.tag)));
        }
        Ok(self)
    }

    fn children(&self, b: &[u8]) -> Result<Vec<Tlv>, Invalid> {
        if self.tag & 0x20 == 0 {
            return Err(bad("a primitive element"));
        }
        let mut out = Vec::new();
        let mut p = self.body;
        while p < self.end {
            let t = Tlv::read(b, p, self.end)?;
            out.push(t);
            p = t.end;
        }
        Ok(out)
    }

    fn read(b: &[u8], start: usize, limit: usize) -> Result<Tlv, Invalid> {
        let limit = limit.min(b.len());
        let mut p = start;
        let mut next = || -> Result<u8, Invalid> {
            if p >= limit {
                return Err(bad("truncated"));
            }
            let x = b.get(p).copied().ok_or_else(|| bad("truncated"))?;
            p = p.saturating_add(1);
            Ok(x)
        };
        let tag = next()?;
        let mut number = u32::from(tag & 0x1f);
        if number == 0x1f {
            number = 0;
            loop {
                let x = next()?;
                if number > 0xffff {
                    return Err(bad("a tag too long"));
                }
                number = number << 7 | u32::from(x & 0x7f);
                if x & 0x80 == 0 {
                    break;
                }
            }
        }
        let mut n = usize::from(next()?);
        if n & 0x80 != 0 {
            let k = n & 0x7f;
            if !(1..=3).contains(&k) {
                return Err(Invalid::new(format!("a length of {k} bytes")));
            }
            n = 0;
            for _ in 0..k {
                n = n << 8 | usize::from(next()?);
            }
        }
        let left = limit.checked_sub(p).ok_or_else(|| bad("truncated"))?;
        if n > left {
            return Err(bad("truncated"));
        }
        Ok(Tlv { start, tag, cls: tag >> 6, number, body: p, end: p.saturating_add(n) })
    }
}

/// An OBJECT IDENTIFIER's content in its dotted form.
fn oid(c: &[u8]) -> Result<String, Invalid> {
    let Some((&first, rest)) = c.split_first() else { return Err(bad("an empty OID")) };
    if c.last().is_some_and(|x| x & 0x80 != 0) {
        return Err(bad("a truncated OID"));
    }
    let mut s =
        if first >= 80 { format!("2.{}", first.saturating_sub(80)) } else { format!("{}.{}", first / 40, first % 40) };
    let mut v: u64 = 0;
    for &x in rest {
        if v > 1 << 48 {
            return Err(bad("an OID arc too long"));
        }
        v = v << 7 | u64::from(x & 0x7f);
        if x & 0x80 == 0 {
            let _ = write!(s, ".{v}");
            v = 0;
        }
    }
    Ok(s)
}

#[cfg(test)]
mod tests {
    use serde_json::Value;

    use super::*;

    fn vectors() -> Value {
        let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../testdata/interop/go-attest.json");
        serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
    }

    fn bytes(v: &Value) -> Vec<u8> {
        STANDARD.decode(v.as_str().unwrap_or_default()).unwrap()
    }

    fn list(v: &Value) -> Vec<Vec<u8>> {
        v.as_array().map(|a| a.iter().map(bytes).collect()).unwrap_or_default()
    }

    /// The challenges Go makes.
    #[test]
    fn challenges() {
        for c in vectors()["challenges"].as_array().unwrap() {
            let (tag, key, salt) = (c["group_tag"].as_str().unwrap(), bytes(&c["member_key"]), bytes(&c["salt"]));
            let got = challenge(tag, &key, &salt).unwrap();
            assert_eq!(got.to_vec(), bytes(&c["challenge"]), "{c}");
            // The same salt a byte short, or a byte long, is refused.
            assert!(challenge(tag, &key, &salt[..SALT_SIZE - 1]).is_err(), "{c}");
            assert!(challenge(tag, &key, &[salt.as_slice(), &salt[..1]].concat()).is_err(), "{c}");
        }
    }

    /// Google's roots are the ones Go pins.
    #[test]
    fn google_roots() {
        let want: Vec<Vec<u8>> = list(&vectors()["google_roots"]);
        let have: Vec<Vec<u8>> = GOOGLE_ROOTS.iter().map(|r| STANDARD.decode(r).unwrap()).collect();
        assert_eq!(have, want);
    }

    /// Every vector decides as Go's CheckAndroid does.
    #[test]
    fn go_vectors() {
        for v in vectors()["vectors"].as_array().unwrap() {
            let name = v["name"].as_str().unwrap();
            let roots = (!v["roots"].is_null()).then(|| list(&v["roots"]));
            let revoked: Vec<String> = v["revoked"]
                .as_array()
                .map(|a| a.iter().map(|s| s.as_str().unwrap().to_string()).collect())
                .unwrap_or_default();
            let policy = Policy { strict: v["strict"] == true, revoked: &revoked, roots: roots.as_deref() };
            let got = check(&list(&v["chain"]), &bytes(&v["spki"]), &bytes(&v["challenge"]), &policy);
            if v["ok"] != true {
                let err = got.expect_err(name);
                assert_eq!(err.revoked, !revoked.is_empty() && name.contains("revoked"), "{name}: {err}");
                continue;
            }
            let s = got.unwrap_or_else(|e| panic!("{name}: {e}"));
            assert_eq!(s.store, v["store"].as_str().unwrap(), "{name}");
            assert_eq!(s.kind, v["kind"].as_str().unwrap_or_default(), "{name}");
            assert_eq!(s.rkp, v["rkp"] == true, "{name}");
            let serials: Vec<&str> = v["serials"].as_array().unwrap().iter().map(|s| s.as_str().unwrap()).collect();
            assert_eq!(s.serials, serials, "{name}");
            assert_eq!(s.why.is_empty(), s.store == STORE_PROVEN, "{name}");
        }
    }

    #[test]
    fn oids_and_serials() {
        assert_eq!(oid(&[0x2b, 0x06, 0x01, 0x04, 0x01, 0xd6, 0x79, 0x02, 0x01, 0x11]).unwrap(), OID_KEY_DESCRIPTION);
        assert!(oid(&[]).is_err());
        assert!(oid(&[0x2b, 0x86]).is_err());
        assert_eq!(serial_hex(&[0x00, 0x10, 0x03]), "1003");
        assert_eq!(serial_hex(&[0x00]), "0");
    }

    /// Readers of what a peer sends never panic on bytes cut anywhere.
    #[test]
    fn cut_certificates() {
        let v = vectors();
        let chain = list(&v["vectors"][0]["chain"]);
        let leaf = chain.first().unwrap();
        for n in 0..leaf.len() {
            let _ = Cert::parse(&leaf[..n]);
        }
    }
}
