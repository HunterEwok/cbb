// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! Device IDs, certificates and their checks (docs/protocol.md, sections 1,
//! 2 and 10), as the Go package internal/group does them.
//!
//! Every key is ECDSA P-256 and every signature ECDSA with SHA-256. This
//! module parses certificates and checks them; a lite member never issues
//! one, except the self-signed certificate it pairs with (pair.rs).

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;
use core::fmt;

use base64::Engine as _;
use der::asn1::ObjectIdentifier;
use der::{Decode, Encode, Tagged};
use p256::ecdsa::signature::{Signer, Verifier};
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};
use x509_cert::certificate::{CertificateInner, Raw};
use x509_cert::ext::pkix::name::GeneralName;
use x509_cert::ext::pkix::{BasicConstraints, ExtendedKeyUsage, KeyUsage, SubjectAltName};

use crate::error::{Error, Result};

/// A device ID: 128 random bits as 32 lowercase hex characters.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub struct DeviceId(String);

impl DeviceId {
    /// Checks that s is a device ID.
    pub fn parse(s: &str) -> Result<DeviceId> {
        if is_id(s) { Ok(DeviceId(s.to_string())) } else { Err(Error::msg(format!("{s:?} is not a device ID"))) }
    }

    /// A new random device ID.
    pub fn random() -> DeviceId {
        DeviceId(random_id())
    }

    /// The device's mDNS host name, cb-<device ID>.local, which is also the
    /// one DNS name of its member certificate.
    pub fn host_name(&self) -> String {
        format!("cb-{}.local", self.0)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for DeviceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Reports whether s is 32 lowercase hex characters: a device or event ID.
pub fn is_id(s: &str) -> bool {
    s.len() == 32 && s.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

/// A random event or device ID.
pub fn random_id() -> String {
    hex(&random_bytes::<16>())
}

/// Random bytes from the platform. A platform without randomness cannot
/// make keys or IDs at all, so that stops the program instead of going on.
#[allow(clippy::expect_used, reason = "no randomness means no keys; there is nothing to go on with")]
pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    getrandom::fill(&mut b).expect("the system has no randomness");
    b
}

/// The SubjectPublicKeyInfo of a P-256 key up to its point, which follows
/// uncompressed (`0x04`, X, Y), as Go's x509 and the phone kits take it.
const P256_SPKI_PREFIX: [u8; 27] = [
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce,
    0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04,
];

/// The SubjectPublicKeyInfo of a P-256 key from its uncompressed point.
pub fn p256_spki_of(point: &[u8]) -> Vec<u8> {
    let mut spki = P256_SPKI_PREFIX[..26].to_vec();
    spki.extend_from_slice(point);
    spki
}

/// The P-256 key in spki, a SubjectPublicKeyInfo with an uncompressed
/// point; a compressed point is refused, as Go refuses it.
pub fn p256_spki(spki: &[u8]) -> Option<VerifyingKey> {
    if spki.len() != 91 || spki.get(..27)? != P256_SPKI_PREFIX {
        return None;
    }
    VerifyingKey::from_sec1_bytes(spki.get(26..)?).ok()
}

pub fn hex(b: &[u8]) -> String {
    b.iter().map(|c| format!("{c:02x}")).collect()
}

pub fn sha256(b: &[u8]) -> [u8; 32] {
    Sha256::digest(b).into()
}

/// The hash that names a key in records: SHA-256 over its
/// SubjectPublicKeyInfo.
pub type KeyHash = [u8; 32];

/// The fingerprint of a certificate's key, the one form of docs/protocol.md
/// (Conventions, "Fingerprints"): SHA-256 over its SubjectPublicKeyInfo in
/// standard base64, as a record's key hash; empty for bytes that are no
/// certificate. A join QR code carries it.
pub fn fingerprint(der: &[u8]) -> String {
    match Cert::parse(der) {
        Ok(c) => base64::engine::general_purpose::STANDARD.encode(sha256(&c.spki)),
        Err(_) => String::new(),
    }
}

/// The short identifier of a group: the first 8 bytes of SHA-256 over the
/// group CA certificate, in hex.
pub fn tag(group_ca: &Cert) -> String {
    hex(&sha256(&group_ca.der)[..8])
}

pub(crate) const OID_P256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
pub(crate) const OID_EC_PUBLIC_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
pub(crate) const OID_ECDSA_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");
pub(crate) const OID_SERVER_AUTH: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.1");
pub(crate) const OID_CLIENT_AUTH: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.2");
const OID_ANY_EKU: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.37.0");
pub(crate) const OID_COMMON_NAME: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.3");

/// A parsed certificate: its DER and what the checks need from it.
#[derive(Clone)]
pub struct Cert {
    pub der: Vec<u8>,
    pub common_name: Option<String>,
    pub dns_names: Vec<String>,
    pub not_before: i64, // Unix seconds
    pub not_after: i64,
    pub is_ca: bool,
    pub path_len: Option<u32>, // the basic constraints' path length, when present
    pub cert_sign: bool,       // key usage certSign
    pub server_auth: bool,
    pub client_auth: bool,
    pub spki: Vec<u8>,
    pub p256: bool,
    point: Vec<u8>, // the uncompressed public key
    tbs: Vec<u8>,
    ecdsa_sha256: bool,
    sig: Vec<u8>,
    issuer_name: Vec<u8>,
    pub(crate) subject_name: Vec<u8>,
}

impl fmt::Debug for Cert {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Cert({:?})", self.common_name)
    }
}

impl PartialEq for Cert {
    fn eq(&self, other: &Cert) -> bool {
        self.der == other.der
    }
}

impl Cert {
    /// Parses a DER certificate.
    pub fn parse(der: &[u8]) -> Result<Cert> {
        let c = CertificateInner::<Raw>::from_der(der).map_err(|e| Error::msg(format!("not a certificate: {e}")))?;
        let tbs = c.tbs_certificate();
        let ext_err = |e: der::Error| Error::msg(format!("a certificate's extensions: {e}"));
        let bc = tbs.get_extension::<BasicConstraints>().map_err(ext_err)?.map(|(_, v)| v);
        let ku = tbs.get_extension::<KeyUsage>().map_err(ext_err)?.map(|(_, v)| v);
        let eku = tbs.get_extension::<ExtendedKeyUsage>().map_err(ext_err)?.map(|(_, v)| v);
        let san = tbs.get_extension::<SubjectAltName>().map_err(ext_err)?.map(|(_, v)| v);
        let has_eku =
            |oid: ObjectIdentifier| eku.as_ref().is_some_and(|e| e.0.iter().any(|o| *o == oid || *o == OID_ANY_EKU));
        let spki = tbs.subject_public_key_info();
        let p256 = spki.algorithm.oid == OID_EC_PUBLIC_KEY
            && spki.algorithm.parameters.as_ref().and_then(|p| p.decode_as::<ObjectIdentifier>().ok())
                == Some(OID_P256);
        let enc = |e: der::Error| Error::msg(format!("not a certificate: {e}"));
        let unix = |t: &x509_cert::time::Time| t.to_unix_duration().as_secs() as i64;
        let common_name =
            tbs.subject().iter().filter(|a| a.oid == OID_COMMON_NAME).last().and_then(|a| directory_string(&a.value));
        Ok(Cert {
            der: der.to_vec(),
            common_name,
            dns_names: san
                .map(|s| {
                    s.0.iter()
                        .filter_map(|n| match n {
                            GeneralName::DnsName(d) => Some(d.to_string()),
                            _ => None,
                        })
                        .collect()
                })
                .unwrap_or_default(),
            not_before: unix(&tbs.validity().not_before),
            not_after: unix(&tbs.validity().not_after),
            is_ca: bc.as_ref().is_some_and(|b| b.ca),
            path_len: bc.as_ref().and_then(|b| b.path_len_constraint).map(u32::from),
            cert_sign: ku.as_ref().is_some_and(|k| k.key_cert_sign()),
            server_auth: has_eku(OID_SERVER_AUTH),
            client_auth: has_eku(OID_CLIENT_AUTH),
            spki: spki.to_der().map_err(enc)?,
            p256,
            point: spki.subject_public_key.raw_bytes().to_vec(),
            tbs: first_element(der).ok_or_else(|| Error::msg("not a certificate: no TBSCertificate"))?.to_vec(),
            ecdsa_sha256: c.signature_algorithm().oid == OID_ECDSA_SHA256,
            sig: c.signature().raw_bytes().to_vec(),
            issuer_name: tbs.issuer().to_der().map_err(enc)?,
            subject_name: tbs.subject().to_der().map_err(enc)?,
        })
    }

    /// The hash of the certificate's public key, as records name it.
    pub fn key_hash(&self) -> KeyHash {
        sha256(&self.spki)
    }

    /// The certificate's public key, uncompressed.
    pub fn public_key(&self) -> &[u8] {
        &self.point
    }

    /// Reports whether data carries a valid signature by this
    /// certificate's key (ECDSA P-256 with SHA-256, DER).
    pub fn verifies(&self, data: &[u8], sig: &[u8]) -> bool {
        if !self.p256 {
            return false;
        }
        let (Ok(key), Ok(sig)) = (VerifyingKey::from_sec1_bytes(&self.point), Signature::from_der(sig)) else {
            return false;
        };
        key.verify(data, &sig).is_ok()
    }

    /// Reports whether parent signed this certificate.
    pub fn signed_by(&self, parent: &Cert) -> bool {
        self.ecdsa_sha256 && parent.verifies(&self.tbs, &self.sig)
    }

    /// Reports whether the CA parent issued this certificate: its name and
    /// its signature.
    pub fn issued_by(&self, parent: &Cert) -> bool {
        parent.is_ca && self.issuer_name == parent.subject_name && self.signed_by(parent)
    }

    fn valid_at(&self, t: i64) -> bool {
        self.not_before <= t && t <= self.not_after
    }
}

/// The text of a directory string (UTF8String, PrintableString or
/// IA5String), as a CN carries it.
fn directory_string(v: &der::Any) -> Option<String> {
    match v.tag() {
        der::Tag::Utf8String | der::Tag::PrintableString | der::Tag::Ia5String => {
            core::str::from_utf8(v.value()).ok().map(str::to_string)
        }
        _ => None,
    }
}

/// The first element of the DER SEQUENCE in der, with its tag and length:
/// the signed part of a certificate, exactly as it came.
fn first_element(der: &[u8]) -> Option<&[u8]> {
    let (_, outer) = tlv(der)?;
    let (len, _) = tlv(outer)?;
    outer.get(..len)
}

/// Reads the tag and length at the start of b, and returns the length of
/// the whole element and its contents.
fn tlv(b: &[u8]) -> Option<(usize, &[u8])> {
    let first = *b.get(1)?;
    let (hdr, len) = if first < 0x80 {
        (2, first as usize)
    } else {
        let n = (first & 0x7f) as usize;
        if n == 0 || n > 4 {
            return None;
        }
        let mut len = 0usize;
        // n is 1 to 4, so neither the sum nor the shifts overflow.
        let hdr = n.checked_add(2)?;
        for &c in b.get(2..hdr)? {
            len = len << 8 | c as usize;
        }
        (hdr, len)
    };
    let total = hdr.checked_add(len)?;
    Some((total, b.get(hdr..total)?))
}

/// Makes the self-signed certificate a joining device presents in pairing,
/// as Go's joiner makes it: the device ID as its CN, a P-256 key, valid
/// from 1970 to 9999, key usage digital signature, and empty basic
/// constraints. Nobody trusts it; the QR code's fingerprint names it, and
/// the pairing exchange binds it.
pub fn self_signed(id: &DeviceId, key: &SigningKey) -> Result<Vec<u8>> {
    let point = VerifyingKey::from(key).to_sec1_point(false);
    self_signed_by(id, point.as_bytes(), &mut |tbs| {
        let sig: Signature = key.sign(tbs);
        Ok(sig.to_der().as_bytes().to_vec())
    })
}

/// The self-signed certificate of self_signed for the public key point
/// (SEC1, uncompressed), signed by sign: ECDSA P-256 with SHA-256 over the
/// bytes it gets, DER. A key kept outside the core signs it this way.
pub fn self_signed_by(id: &DeviceId, point: &[u8], sign: &mut dyn FnMut(&[u8]) -> Result<Vec<u8>>) -> Result<Vec<u8>> {
    let basic = seq(&[&oid(&ObjectIdentifier::new_unwrap("2.5.29.19")), &[0x01, 0x01, 0xff], &tagged(0x04, &seq(&[]))]);
    self_signed_cert(id.as_str(), point, &basic, sign)
}

/// The common name of a server certificate.
pub const SERVER_CERT_NAME: &str = "cbb server";

/// The certificate of a server key that a device presents a relay or the
/// forwarder in place of its member certificate (docs/protocol.md, section
/// 18), as Go's group.ServerCertificate makes it: self-signed, `cbb
/// server` as its CN, no SAN, valid from 1970 to 9999, key usage digital
/// signature and extended key usage client authentication. It names
/// neither a device nor a group. sign signs as for self_signed_by.
pub fn server_cert_by(point: &[u8], sign: &mut dyn FnMut(&[u8]) -> Result<Vec<u8>>) -> Result<Vec<u8>> {
    let client_auth = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.2");
    let eku = seq(&[&oid(&ObjectIdentifier::new_unwrap("2.5.29.37")), &tagged(0x04, &seq(&[&oid(&client_auth)]))]);
    self_signed_cert(SERVER_CERT_NAME, point, &eku, sign)
}

/// A self-signed P-256 certificate with cn as its subject and issuer, key
/// usage digital signature and the extension ext.
fn self_signed_cert(
    cn: &str,
    point: &[u8],
    ext: &[u8],
    sign: &mut dyn FnMut(&[u8]) -> Result<Vec<u8>>,
) -> Result<Vec<u8>> {
    let alg = seq(&[&oid(&OID_ECDSA_SHA256)]);
    let name = seq(&[&set(&[&seq(&[&oid(&OID_COMMON_NAME), &tagged(0x0c, cn.as_bytes())])])]);
    let spki = seq(&[&seq(&[&oid(&OID_EC_PUBLIC_KEY), &oid(&OID_P256)]), &bit_string(point)]);
    let mut serial = random_bytes::<16>();
    serial[0] = (serial[0] & 0x7f) | 0x01; // positive, and 16 bytes long
    let key_usage = seq(&[
        &oid(&ObjectIdentifier::new_unwrap("2.5.29.15")),
        &[0x01, 0x01, 0xff],
        &tagged(0x04, &bit_string_bits(0x80, 7)),
    ]);
    let tbs = seq(&[
        &tagged(0xa0, &tagged(0x02, &[2])), // v3
        &tagged(0x02, &serial),
        &alg,
        &name,
        &seq(&[&tagged(0x17, b"700101000000Z"), &tagged(0x18, b"99991231235959Z")]),
        &name,
        &spki,
        &tagged(0xa3, &seq(&[&key_usage, ext])),
    ]);
    let sig = sign(&tbs)?;
    Ok(seq(&[&tbs, &alg, &bit_string(&sig)]))
}

/// A DER element with the given tag.
pub(crate) fn tagged(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let n = content.len();
    if n < 0x80 {
        out.push(n as u8);
    } else {
        let len = (n as u32).to_be_bytes();
        let used: &[u8] = len.iter().position(|b| *b != 0).and_then(|i| len.get(i..)).unwrap_or(&len);
        out.push(0x80 | used.len() as u8);
        out.extend_from_slice(used);
    }
    out.extend_from_slice(content);
    out
}

pub(crate) fn seq(parts: &[&[u8]]) -> Vec<u8> {
    tagged(0x30, &parts.concat())
}

pub(crate) fn set(parts: &[&[u8]]) -> Vec<u8> {
    tagged(0x31, &parts.concat())
}

pub(crate) fn oid(o: &ObjectIdentifier) -> Vec<u8> {
    tagged(0x06, o.as_bytes())
}

pub(crate) fn bit_string(b: &[u8]) -> Vec<u8> {
    tagged(0x03, &[&[0u8][..], b].concat())
}

pub(crate) fn bit_string_bits(bits: u8, unused: u8) -> Vec<u8> {
    tagged(0x03, &[unused, bits])
}

/// Checks a group CA or root certificate: self-signed, a P-256 key, and a
/// path length from 0 to max_path (Go's checkCA).
pub fn check_ca(c: &Cert, what: &str, max_path: u32) -> Result<()> {
    if !c.is_ca || c.path_len.is_none_or(|n| n > max_path) {
        return Err(Error::msg(format!("the {what} certificate is not a CA with a path length of at most {max_path}")));
    }
    if !c.p256 {
        return Err(Error::msg(format!("the {what} key is not a P-256 key")));
    }
    if !c.signed_by(c) {
        return Err(Error::msg(format!("the {what} certificate is not self-signed")));
    }
    Ok(())
}

/// Checks the new root of a root record: a self-signed CA with path length
/// 1 and a P-256 key.
pub fn check_root(c: &Cert) -> Result<()> {
    check_ca(c, "new root", 1)?;
    if c.path_len != Some(1) || !c.cert_sign {
        return Err(Error::msg("the new root does not certify admin CAs"));
    }
    Ok(())
}

/// Checks that c is an admin CA certified by root: a CA with path length 0
/// and a P-256 key, signed by root, which allows one level of CAs below it.
pub fn check_admin_ca(c: &Cert, root: &Cert) -> Result<()> {
    if !c.is_ca || c.path_len != Some(0) || !c.cert_sign {
        return Err(Error::msg("the signer is not an admin CA"));
    }
    if !c.p256 {
        return Err(Error::msg("the admin CA key is not a P-256 key"));
    }
    if root.path_len.is_none_or(|n| n < 1) {
        return Err(Error::msg("the group CA certifies no admin CAs"));
    }
    if !c.signed_by(root) {
        return Err(Error::msg("the admin CA is not from the group CA"));
    }
    Ok(())
}

/// Returns the device ID a member certificate names: its CN, and exactly one
/// DNS name, cb-<that ID>.local.
pub fn device_of(c: &Cert) -> Result<DeviceId> {
    let id = DeviceId::parse(c.common_name.as_deref().unwrap_or(""))?;
    if c.dns_names.len() != 1 || c.dns_names.first().is_none_or(|n| *n != id.host_name()) {
        return Err(Error::msg(format!("the certificate of {id} does not name {}", id.host_name())));
    }
    Ok(id)
}

/// The side of a member connection that a peer's certificate must be good
/// for: the member this one dialed is the server, one that dialed it the
/// client.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Usage {
    Server,
    Client,
}

/// Verifies a peer's member certificate chain (leaf first, then the admin
/// CA that issued it, if one did) to one of the trusted roots at time t,
/// Unix seconds, for the use the peer's side needs, and returns the device
/// it names. The time is max(now, the current root's NotBefore), as Go's
/// verifyTime: a device whose clock is behind still accepts certificates,
/// an expired one is rejected.
pub fn verify_member(chain: &[Cert], trusted: &[Cert], t: i64, usage: Usage) -> Result<DeviceId> {
    verify_member_chain(chain, trusted, t, usage).map(|(dev, _)| dev)
}

/// verify_member, and the position in chain of the admin CA that issued
/// the leaf, None when a root did: wherever the peer put it, as a peer may
/// send certificates it does not need.
pub fn verify_member_chain(
    chain: &[Cert],
    trusted: &[Cert],
    t: i64,
    usage: Usage,
) -> Result<(DeviceId, Option<usize>)> {
    let leaf = chain.first().ok_or_else(|| Error::msg("the peer sent no certificate"))?;
    if leaf.is_ca {
        return Err(Error::msg("the peer's certificate is a CA"));
    }
    let usable = match usage {
        Usage::Server => leaf.server_auth,
        Usage::Client => leaf.client_auth,
    };
    if !usable || !leaf.valid_at(t) {
        return Err(Error::msg("the peer's certificate is expired or not for this use"));
    }
    let from = |child: &Cert, parent: &Cert| child.issuer_name == parent.subject_name && child.signed_by(parent);
    let issuer = if trusted.iter().any(|root| root.valid_at(t) && from(leaf, root)) {
        None
    } else {
        // Through one admin CA under a root.
        let admin = chain.iter().enumerate().skip(1).find(|(_, admin)| {
            admin.valid_at(t)
                && from(leaf, admin)
                && trusted.iter().any(|root| {
                    root.valid_at(t) && admin.issuer_name == root.subject_name && check_admin_ca(admin, root).is_ok()
                })
        });
        match admin {
            Some((i, _)) => Some(i),
            None => return Err(Error::msg("the peer's certificate is not from the group")),
        }
    };
    Ok((device_of(leaf)?, issuer))
}

/// Checks a peer's member chain at time t (verify_member_chain) and returns
/// its device with the certificates the records judge: the leaf and the
/// admin CA that issued it, if one did, wherever the peer put it.
pub fn member_chain(chain: Vec<Cert>, trusted: &[Cert], t: i64, usage: Usage) -> Result<(DeviceId, Vec<Cert>)> {
    let (dev, issuer) = verify_member_chain(&chain, trusted, t, usage)?;
    let mut used = Vec::new();
    for (i, c) in chain.into_iter().enumerate() {
        if i == 0 || Some(i) == issuer {
            used.push(c);
        }
    }
    Ok((dev, used))
}

/// Serde helpers for byte strings as standard base64, Go's encoding of
/// []byte in JSON.
pub mod b64 {
    use alloc::string::String;
    use alloc::vec::Vec;
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(b: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&STANDARD.encode(b))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = Option::<String>::deserialize(d)?.unwrap_or_default();
        STANDARD.decode(s).map_err(serde::de::Error::custom)
    }

    pub mod opt {
        use super::*;

        pub fn serialize<S: Serializer>(b: &Option<Vec<u8>>, s: S) -> Result<S::Ok, S::Error> {
            match b {
                Some(b) => s.serialize_str(&STANDARD.encode(b)),
                None => s.serialize_none(),
            }
        }

        pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Vec<u8>>, D::Error> {
            match Option::<String>::deserialize(d)? {
                Some(s) => STANDARD.decode(s).map(Some).map_err(serde::de::Error::custom),
                None => Ok(None),
            }
        }
    }

    pub mod list {
        use super::*;
        use serde::ser::SerializeSeq;

        pub fn serialize<S: Serializer>(v: &[Vec<u8>], s: S) -> Result<S::Ok, S::Error> {
            let mut seq = s.serialize_seq(Some(v.len()))?;
            for b in v {
                seq.serialize_element(&STANDARD.encode(b))?;
            }
            seq.end()
        }

        pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<Vec<u8>>, D::Error> {
            let v = Option::<Vec<String>>::deserialize(d)?.unwrap_or_default();
            v.into_iter().map(|s| STANDARD.decode(s).map_err(serde::de::Error::custom)).collect()
        }
    }

    pub mod hashes {
        use super::*;
        use serde::ser::SerializeSeq;

        pub fn serialize<S: Serializer>(v: &[[u8; 32]], s: S) -> Result<S::Ok, S::Error> {
            let mut seq = s.serialize_seq(Some(v.len()))?;
            for b in v {
                seq.serialize_element(&STANDARD.encode(b))?;
            }
            seq.end()
        }

        pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<[u8; 32]>, D::Error> {
            let v = Option::<Vec<String>>::deserialize(d)?.unwrap_or_default();
            v.into_iter()
                .map(|s| {
                    let raw = STANDARD.decode(s).map_err(serde::de::Error::custom)?;
                    raw.try_into().map_err(|_| serde::de::Error::custom("a key hash is not 32 bytes"))
                })
                .collect()
        }
    }

    pub mod opt_hash {
        use super::*;

        pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<[u8; 32]>, D::Error> {
            match Option::<String>::deserialize(d)? {
                Some(s) => {
                    let raw = STANDARD.decode(s).map_err(serde::de::Error::custom)?;
                    raw.try_into().map(Some).map_err(|_| serde::de::Error::custom("a key hash is not 32 bytes"))
                }
                None => Ok(None),
            }
        }
    }
}
