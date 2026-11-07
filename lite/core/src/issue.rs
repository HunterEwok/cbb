// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! Issuing certificates, as an admin or the root does (docs/protocol.md,
//! sections 2, 9 and 10), with the profiles of Go's internal/group/cert.go
//! and the Swift kit's GroupCertificates: member certificates under the
//! root or an admin CA, admin CAs under the root, and a new group's root.
//!
//! The CA's key never enters the core: sign gets the bytes to sign and
//! returns an ECDSA P-256 signature with SHA-256 over them, DER, made by a
//! key in a TEE, a Secure Enclave or a file. Every certificate is checked
//! against its issuer before it is returned, so a signer with the wrong key
//! is an error, not a certificate nobody accepts.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use core::time::Duration;

use der::asn1::{GeneralizedTime, ObjectIdentifier, UtcTime};
use der::{DateTime, Encode};
use sha1::{Digest, Sha1};

use crate::certs::{
    Cert, DeviceId, OID_CLIENT_AUTH, OID_COMMON_NAME, OID_EC_PUBLIC_KEY, OID_ECDSA_SHA256, OID_P256, OID_SERVER_AUTH,
    bit_string, bit_string_bits, check_admin_ca, check_root, oid, random_bytes, seq, set, tagged,
};
use crate::error::{Error, Result};

/// A signing callback: an ECDSA P-256 signature with SHA-256 over the bytes
/// it gets, DER.
pub type Sign<'a> = &'a mut dyn FnMut(&[u8]) -> Result<Vec<u8>>;

/// How long a member certificate lasts.
pub const MEMBER_YEARS: u16 = 2;
/// How long a root lasts.
pub const CA_YEARS: u16 = 20;
/// A root starts this much before now, for clocks a little behind.
pub const BACKDATE: i64 = 24 * 3600;

const OID_KEY_USAGE: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.15");
const OID_EXT_KEY_USAGE: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.37");
const OID_SUBJECT_ALT_NAME: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.17");
const OID_BASIC_CONSTRAINTS: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.19");
const OID_SUBJECT_KEY_ID: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.14");
const OID_AUTHORITY_KEY_ID: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.35");

/// A member certificate for the device's public key point (SEC1,
/// uncompressed), issued by ca, the root or an admin CA, whose key sign
/// holds: the device ID as its CN, cb-<ID>.local as its one DNS name, for
/// server and client use, from the CA's start until two years from now or
/// the CA's end, whichever is sooner. now is Unix seconds; a clock outside
/// the CA's lifetime is an error, as the certificate would be useless.
pub fn member(device: &DeviceId, point: &[u8], ca: &Cert, now: i64, sign: Sign) -> Result<Vec<u8>> {
    if !ca.is_ca || !ca.cert_sign {
        return Err(Error::msg("the issuer is not a CA"));
    }
    in_lifetime(ca, now)?;
    let not_after = add_years(now, MEMBER_YEARS)?.min(ca.not_after);
    let host = format!("cb-{}.local", device.as_str());
    let extensions = [
        ext(&OID_KEY_USAGE, true, &bit_string_bits(0x80, 7)), // digitalSignature
        ext(&OID_EXT_KEY_USAGE, false, &seq(&[&oid(&OID_SERVER_AUTH), &oid(&OID_CLIENT_AUTH)])),
        ext(&OID_BASIC_CONSTRAINTS, true, &seq(&[])),
        ext(&OID_SUBJECT_ALT_NAME, false, &seq(&[&tagged(0x82, host.as_bytes())])),
        ext(&OID_AUTHORITY_KEY_ID, false, &seq(&[&tagged(0x80, &key_id(ca.public_key()))])),
    ];
    let der = build(&ca.subject_name, &name(device.as_str()), point, ca.not_before, not_after, &extensions, sign)?;
    let c = Cert::parse(&der)?;
    if !c.issued_by(ca) {
        return Err(Error::msg("the signing key is not the CA's"));
    }
    Ok(der)
}

/// An admin CA for the admin key point of the device, issued by root,
/// whose key sign holds: a CA with path length 0 that issues member
/// certificates and signs records, valid as long as the root, named
/// "cbb admin <device>". Only a root with path length 1 issues one.
pub fn admin_ca(device: &DeviceId, point: &[u8], root: &Cert, now: i64, sign: Sign) -> Result<Vec<u8>> {
    check_root(root)?;
    in_lifetime(root, now)?;
    let extensions = [
        ext(&OID_BASIC_CONSTRAINTS, true, &seq(&[&[0x01, 0x01, 0xff], &tagged(0x02, &[0])])),
        ext(&OID_KEY_USAGE, true, &bit_string_bits(0x06, 1)), // keyCertSign, cRLSign
        ext(&OID_SUBJECT_KEY_ID, false, &tagged(0x04, &key_id(point))),
        ext(&OID_AUTHORITY_KEY_ID, false, &seq(&[&tagged(0x80, &key_id(root.public_key()))])),
    ];
    let cn = format!("cbb admin {}", device.as_str());
    let der = build(&root.subject_name, &name(&cn), point, root.not_before, root.not_after, &extensions, sign)?;
    let c = Cert::parse(&der)?;
    check_admin_ca(&c, root).map_err(|_| Error::msg("the signing key is not the root's"))?;
    Ok(der)
}

/// A new group's root for the key point that sign holds: self-signed, a CA
/// with path length 1, for certificate and CRL signing, named "cbb group
/// root YYYY-MM-DD", valid from a day before now for 20 years.
pub fn root_ca(point: &[u8], now: i64, sign: Sign) -> Result<Vec<u8>> {
    let day = date(now)?;
    let cn = format!("cbb group root {:04}-{:02}-{:02}", day.year(), day.month(), day.day());
    let extensions = [
        ext(&OID_BASIC_CONSTRAINTS, true, &seq(&[&[0x01, 0x01, 0xff], &tagged(0x02, &[1])])),
        ext(&OID_KEY_USAGE, true, &bit_string_bits(0x06, 1)),
        ext(&OID_SUBJECT_KEY_ID, false, &tagged(0x04, &key_id(point))),
    ];
    let n = name(&cn);
    let start = now.checked_sub(BACKDATE).ok_or_else(|| Error::msg("the date is out of range"))?;
    let der = build(&n, &n, point, start, add_years(now, CA_YEARS)?, &extensions, sign)?;
    check_root(&Cert::parse(&der)?).map_err(|_| Error::msg("the signing key does not match the root's key"))?;
    Ok(der)
}

fn in_lifetime(ca: &Cert, now: i64) -> Result<()> {
    if now < ca.not_before || now >= ca.not_after {
        let cn = ca.common_name.clone().unwrap_or_default();
        return Err(Error::msg(format!("the clock is outside the lifetime of {cn:?}; check the date")));
    }
    Ok(())
}

/// The key identifier Go uses: SHA-1 over the public key's bits.
fn key_id(point: &[u8]) -> Vec<u8> {
    Sha1::digest(point).to_vec()
}

fn name(cn: &str) -> Vec<u8> {
    seq(&[&set(&[&seq(&[&oid(&OID_COMMON_NAME), &tagged(0x0c, cn.as_bytes())])])])
}

fn ext(o: &ObjectIdentifier, critical: bool, value: &[u8]) -> Vec<u8> {
    if critical {
        seq(&[&oid(o), &[0x01, 0x01, 0xff], &tagged(0x04, value)])
    } else {
        seq(&[&oid(o), &tagged(0x04, value)])
    }
}

fn build(
    issuer: &[u8],
    subject: &[u8],
    point: &[u8],
    not_before: i64,
    not_after: i64,
    extensions: &[Vec<u8>],
    sign: Sign,
) -> Result<Vec<u8>> {
    if point.len() != 65 || point.first() != Some(&4) || p256::PublicKey::from_sec1_bytes(point).is_err() {
        return Err(Error::msg("the key to certify is not a P-256 key"));
    }
    let alg = seq(&[&oid(&OID_ECDSA_SHA256)]);
    let spki = seq(&[&seq(&[&oid(&OID_EC_PUBLIC_KEY), &oid(&OID_P256)]), &bit_string(point)]);
    let mut serial = random_bytes::<16>();
    serial[0] = (serial[0] & 0x7f) | 0x01; // positive, and 16 bytes long
    let exts: Vec<&[u8]> = extensions.iter().map(Vec::as_slice).collect();
    let tbs = seq(&[
        &tagged(0xa0, &tagged(0x02, &[2])), // v3
        &tagged(0x02, &serial),
        &alg,
        issuer,
        &seq(&[&time(not_before)?, &time(not_after)?]),
        subject,
        &spki,
        &tagged(0xa3, &seq(&exts)),
    ]);
    let sig = sign(&tbs)?;
    Ok(seq(&[&tbs, &alg, &bit_string(&sig)]))
}

/// The date and time of t, Unix seconds from 1970 to 9999.
fn date(t: i64) -> Result<DateTime> {
    let secs = u64::try_from(t).map_err(|_| Error::msg("the clock is before 1970; check the date"))?;
    DateTime::from_unix_duration(Duration::from_secs(secs)).map_err(|_| Error::msg("the date is out of range"))
}

/// A certificate time: UTCTime from 1950 to 2049, GeneralizedTime
/// otherwise (RFC 5280, 4.1.2.5).
fn time(t: i64) -> Result<Vec<u8>> {
    let d = date(t)?;
    let der = if d.year() < 2050 {
        UtcTime::from_date_time(d).and_then(|u| u.to_der())
    } else {
        GeneralizedTime::from_date_time(d).to_der()
    };
    der.map_err(|e| Error::msg(format!("cannot encode a certificate's time: {e}")))
}

/// t plus years, as Go's AddDate does it: the same day and time of day,
/// with February 29 becoming March 1 in a year that has none.
fn add_years(t: i64, years: u16) -> Result<i64> {
    let d = date(t)?;
    let y = d.year().checked_add(years).ok_or_else(|| Error::msg("the date is out of range"))?;
    let at = |month, day| DateTime::new(y, month, day, d.hour(), d.minutes(), d.seconds());
    let end = at(d.month(), d.day()).or_else(|_| at(3, 1)).map_err(|_| Error::msg("the date is out of range"))?;
    i64::try_from(end.unix_duration().as_secs()).map_err(|_| Error::msg("the date is out of range"))
}

/// The name of an admin CA's subject, as Go's AdminName gives it.
pub fn admin_name(device: &DeviceId) -> String {
    format!("cbb admin {}", device.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::certs::{Usage, verify_member_chain};
    use p256::ecdsa::signature::Signer;
    use p256::ecdsa::{Signature, SigningKey, VerifyingKey};

    fn key() -> (SigningKey, Vec<u8>) {
        let k = SigningKey::from_bytes(&random_bytes::<32>().into()).unwrap();
        let p = VerifyingKey::from(&k).to_sec1_point(false).as_bytes().to_vec();
        (k, p)
    }

    fn signer(k: &SigningKey) -> impl FnMut(&[u8]) -> Result<Vec<u8>> + '_ {
        move |b| {
            let s: Signature = k.sign(b);
            Ok(s.to_der().as_bytes().to_vec())
        }
    }

    const NOW: i64 = 1_793_000_000; // 2026-10-26

    #[test]
    fn dates() {
        let leap = 951_782_400; // 2000-02-29
        // February 29 plus a year is March 1, as in Go.
        assert_eq!(add_years(leap, 1).unwrap(), 951_782_400 + 366 * 86400);
        assert_eq!(add_years(leap + 61, 4).unwrap(), leap + 61 + (366 + 365 * 3) * 86400);
        assert_eq!(time(0).unwrap(), tagged(0x17, b"700101000000Z"));
        assert_eq!(time(2_524_608_061).unwrap(), tagged(0x18, b"20500101000101Z"));
        assert!(time(-1).is_err());
    }

    #[test]
    fn root_admin_and_members() {
        let (rk, rp) = key();
        let root = Cert::parse(&root_ca(&rp, NOW, &mut signer(&rk)).unwrap()).unwrap();
        check_root(&root).unwrap();
        assert_eq!(root.not_before, NOW - BACKDATE);
        assert!(root.common_name.as_deref().unwrap().starts_with("cbb group root 2026-"));

        let admin_dev = DeviceId::random();
        let (ak, ap) = key();
        let admin = Cert::parse(&admin_ca(&admin_dev, &ap, &root, NOW, &mut signer(&rk)).unwrap()).unwrap();
        check_admin_ca(&admin, &root).unwrap();
        assert_eq!(admin.common_name, Some(admin_name(&admin_dev)));
        assert_eq!((admin.not_before, admin.not_after), (root.not_before, root.not_after));

        // A member under the admin CA, checked as a peer checks it.
        let dev = DeviceId::random();
        let (_, mp) = key();
        let leaf = Cert::parse(&member(&dev, &mp, &admin, NOW, &mut signer(&ak)).unwrap()).unwrap();
        assert_eq!(leaf.not_before, admin.not_before);
        assert_eq!(leaf.not_after, add_years(NOW, MEMBER_YEARS).unwrap());
        let chain = [leaf.clone(), admin.clone()];
        for usage in [Usage::Server, Usage::Client] {
            let (got, at) = verify_member_chain(&chain, core::slice::from_ref(&root), NOW, usage).unwrap();
            assert_eq!((got, at), (dev.clone(), Some(1)));
        }

        // And one under the root itself.
        let leaf = Cert::parse(&member(&dev, &mp, &root, NOW, &mut signer(&rk)).unwrap()).unwrap();
        let (got, at) = verify_member_chain(&[leaf], core::slice::from_ref(&root), NOW, Usage::Server).unwrap();
        assert_eq!((got, at), (dev, None));
    }

    #[test]
    fn refusals() {
        let (rk, rp) = key();
        let root = Cert::parse(&root_ca(&rp, NOW, &mut signer(&rk)).unwrap()).unwrap();
        let dev = DeviceId::random();
        let (other, mp) = key();
        // The wrong signing key.
        assert!(member(&dev, &mp, &root, NOW, &mut signer(&other)).is_err());
        assert!(admin_ca(&dev, &mp, &root, NOW, &mut signer(&other)).is_err());
        // A clock outside the CA's lifetime.
        assert!(member(&dev, &mp, &root, NOW - 2 * BACKDATE, &mut signer(&rk)).is_err());
        // Not a P-256 point.
        assert!(member(&dev, &mp[..33], &root, NOW, &mut signer(&rk)).is_err());
        // A member certificate issues nothing; an admin CA issues no admin CA.
        let leaf = Cert::parse(&member(&dev, &mp, &root, NOW, &mut signer(&rk)).unwrap()).unwrap();
        assert!(member(&dev, &mp, &leaf, NOW, &mut signer(&other)).is_err());
        let admin = Cert::parse(&admin_ca(&dev, &mp, &root, NOW, &mut signer(&rk)).unwrap()).unwrap();
        assert!(admin_ca(&dev, &mp, &admin, NOW, &mut signer(&other)).is_err());
    }
}
