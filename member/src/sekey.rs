// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! P-256 keys in a Mac's Secure Enclave, as Go's internal/sekey keeps them
//! (docs/protocol.md, section 17): a key is made inside the enclave and
//! never leaves it; what the identity file keeps (`key_se`) is the
//! enclave's encrypted copy, which only that Mac's enclave opens. cbb uses
//! the enclave itself, without cbb-helper, and needs no keychain and no
//! entitlement for it.
//!
//! A secret is sealed as Go's sekey.Seal does: an ephemeral P-256 key
//! agrees on a secret with a new enclave key (ECDH), HKDF-SHA256 of it keys
//! AES-256-GCM. That part is plain Rust and tested on every system; only
//! the enclave itself is macOS.

// Elsewhere only the tests use the sealing.
#![cfg_attr(not(target_os = "macos"), allow(dead_code))]

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use cbb_core::certs::b64;
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

/// The info and associated data of a sealed secret, as Go's sealInfo.
const SEAL_INFO: &[u8] = b"cbb sekey seal v1";

/// A sealed secret as JSON, Go's field names: the enclave key's blob, the
/// ephemeral public key, and the nonce with the sealed secret in box.
#[derive(Serialize, Deserialize)]
struct Wire {
    v: u32,
    #[serde(with = "b64")]
    key: Vec<u8>,
    #[serde(with = "b64")]
    eph: Vec<u8>,
    #[serde(rename = "box", with = "b64")]
    sealed: Vec<u8>,
}

/// A key that agrees on secrets, as an enclave key does.
pub trait Agree {
    /// The blob that loads the key again.
    fn blob(&self) -> Vec<u8>;
    /// The public key, SEC1 uncompressed.
    fn public(&self) -> Vec<u8>;
    /// ECDH with the uncompressed point peer: the shared X coordinate.
    fn agree(&self, peer: &[u8]) -> Result<Vec<u8>>;
}

/// The AES-256-GCM key from the shared secret and both public keys.
fn aead(shared: &[u8], eph: &[u8], public: &[u8]) -> Result<Aes256Gcm> {
    if shared.len() != 32 {
        return Err(Error::msg("the agreed secret has the wrong length"));
    }
    let salt = [eph, public].concat();
    // HKDF writes the whole key into the buffer it is given.
    let mut key = aes_gcm::Key::<Aes256Gcm>::default();
    hkdf::Hkdf::<sha2::Sha256>::new(Some(&salt), shared)
        .expand(SEAL_INFO, &mut key)
        .map_err(|_| Error::msg("cannot derive the sealing key"))?;
    Ok(Aes256Gcm::new(&key))
}

/// Seals secret to key with the ephemeral secret eph and nonce: what
/// [`seal`] does with a new enclave key and fresh randomness.
pub fn seal_to(key: &dyn Agree, eph: &p256::NonZeroScalar, nonce: [u8; 12], secret: &[u8]) -> Result<Vec<u8>> {
    use p256::elliptic_curve::sec1::ToSec1Point as _;
    let public = key.public();
    let peer = p256::PublicKey::from_sec1_bytes(&public).map_err(|_| Error::msg("the enclave key is not on P-256"))?;
    let shared = p256::ecdh::diffie_hellman(eph, peer.as_affine());
    let eph_pub = p256::PublicKey::from_secret_scalar(eph).to_sec1_point(false).as_bytes().to_vec();
    let a = aead(shared.raw_secret_bytes().as_slice(), &eph_pub, &public)?;
    let mut sealed = nonce.to_vec();
    sealed.extend(
        a.encrypt(&Nonce::from(nonce), Payload { msg: secret, aad: SEAL_INFO })
            .map_err(|_| Error::msg("cannot seal the secret"))?,
    );
    serde_json::to_vec(&Wire { v: 1, key: key.blob(), eph: eph_pub, sealed })
        .map_err(|e| Error::with("cannot encode the sealed secret", e))
}

/// Loads an enclave key from its blob.
pub type Load<'a> = &'a dyn Fn(&[u8]) -> Result<Box<dyn Agree>>;

/// Opens what [`seal_to`] sealed, the key loaded from its blob by load.
pub fn unseal_with(b: &[u8], load: Load<'_>) -> Result<Vec<u8>> {
    let s: Wire = serde_json::from_slice(b).map_err(|e| Error::with("the sealed secret is not understood", e))?;
    if s.v != 1 {
        return Err(Error::msg(format!("a sealed secret of unknown version {}", s.v)));
    }
    p256::PublicKey::from_sec1_bytes(&s.eph)
        .map_err(|_| Error::msg("the sealed secret's ephemeral key is not on P-256"))?;
    let key = load(&s.key)?;
    let shared = key.agree(&s.eph)?;
    let a = aead(&shared, &s.eph, &key.public())?;
    if s.sealed.len() < 12 {
        return Err(Error::msg("the sealed secret is too short"));
    }
    let (nonce, body) = s.sealed.split_at(12);
    let nonce: [u8; 12] = nonce.try_into().map_err(|_| Error::msg("the sealed secret is too short"))?;
    a.decrypt(&Nonce::from(nonce), Payload { msg: body, aad: SEAL_INFO })
        .map_err(|_| Error::msg("the sealed secret does not open"))
}

#[cfg(target_os = "macos")]
pub use enclave::{Key, available, seal, unseal};

#[cfg(target_os = "macos")]
mod enclave {
    //! The enclave through Security.framework, as Go's cgo does.

    use std::ffi::{CStr, c_char, c_int, c_long, c_void};
    use std::ptr;
    use std::sync::OnceLock;

    use super::Agree;
    use crate::error::{Error, Result};

    type CFTypeRef = *const c_void;
    type CFAllocatorRef = *const c_void;
    type CFDictionaryRef = *const c_void;
    type CFDataRef = *const c_void;
    type CFStringRef = *const c_void;
    type CFNumberRef = *const c_void;
    type CFErrorRef = *const c_void;
    type CFBooleanRef = *const c_void;
    type CFIndex = c_long;
    type CFTypeID = usize;
    type SecKeyRef = *const c_void;
    type SecAccessControlRef = *const c_void;

    #[repr(C)]
    struct CFDictionaryCallBacks([usize; 6]);

    const K_CF_NUMBER_INT_TYPE: CFIndex = 9;
    const K_CF_STRING_ENCODING_UTF8: u32 = 0x0800_0100;
    const K_SEC_ACCESS_CONTROL_PRIVATE_KEY_USAGE: usize = 1 << 30;

    #[link(name = "CoreFoundation", kind = "framework")]
    unsafe extern "C" {
        static kCFTypeDictionaryKeyCallBacks: CFDictionaryCallBacks;
        static kCFTypeDictionaryValueCallBacks: CFDictionaryCallBacks;
        static kCFBooleanFalse: CFBooleanRef;
        fn CFRelease(cf: CFTypeRef);
        fn CFGetTypeID(cf: CFTypeRef) -> CFTypeID;
        fn CFDataGetTypeID() -> CFTypeID;
        fn CFDataCreate(a: CFAllocatorRef, bytes: *const u8, len: CFIndex) -> CFDataRef;
        fn CFDataGetBytePtr(d: CFDataRef) -> *const u8;
        fn CFDataGetLength(d: CFDataRef) -> CFIndex;
        fn CFNumberCreate(a: CFAllocatorRef, t: CFIndex, v: *const c_void) -> CFNumberRef;
        fn CFDictionaryCreate(
            a: CFAllocatorRef,
            keys: *const CFTypeRef,
            values: *const CFTypeRef,
            n: CFIndex,
            kcb: *const CFDictionaryCallBacks,
            vcb: *const CFDictionaryCallBacks,
        ) -> CFDictionaryRef;
        fn CFDictionaryGetValue(d: CFDictionaryRef, key: CFTypeRef) -> CFTypeRef;
        fn CFStringCreateWithCString(a: CFAllocatorRef, s: *const c_char, enc: u32) -> CFStringRef;
        fn CFStringGetCString(s: CFStringRef, buf: *mut c_char, n: CFIndex, enc: u32) -> u8;
        fn CFErrorCopyDescription(e: CFErrorRef) -> CFStringRef;
        fn CFErrorGetCode(e: CFErrorRef) -> CFIndex;
    }

    #[link(name = "Security", kind = "framework")]
    unsafe extern "C" {
        static kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly: CFStringRef;
        static kSecAttrIsPermanent: CFStringRef;
        static kSecAttrAccessControl: CFStringRef;
        static kSecAttrKeyType: CFStringRef;
        static kSecAttrKeySizeInBits: CFStringRef;
        static kSecAttrTokenID: CFStringRef;
        static kSecPrivateKeyAttrs: CFStringRef;
        static kSecAttrKeyTypeECSECPrimeRandom: CFStringRef;
        static kSecAttrTokenIDSecureEnclave: CFStringRef;
        static kSecAttrKeyClass: CFStringRef;
        static kSecAttrKeyClassPublic: CFStringRef;
        static kSecKeyAlgorithmECDSASignatureDigestX962SHA256: CFStringRef;
        static kSecKeyAlgorithmECDHKeyExchangeStandard: CFStringRef;
        fn SecAccessControlCreateWithFlags(
            a: CFAllocatorRef,
            protection: CFTypeRef,
            flags: usize,
            e: *mut CFErrorRef,
        ) -> SecAccessControlRef;
        fn SecKeyCreateRandomKey(attrs: CFDictionaryRef, e: *mut CFErrorRef) -> SecKeyRef;
        fn SecKeyCopyAttributes(key: SecKeyRef) -> CFDictionaryRef;
        fn SecKeyCopyPublicKey(key: SecKeyRef) -> SecKeyRef;
        fn SecKeyCopyExternalRepresentation(key: SecKeyRef, e: *mut CFErrorRef) -> CFDataRef;
        fn SecKeyCreateWithData(data: CFDataRef, attrs: CFDictionaryRef, e: *mut CFErrorRef) -> SecKeyRef;
        fn SecKeyCreateSignature(key: SecKeyRef, alg: CFStringRef, data: CFDataRef, e: *mut CFErrorRef) -> CFDataRef;
        fn SecKeyCopyKeyExchangeResult(
            key: SecKeyRef,
            alg: CFStringRef,
            public: SecKeyRef,
            params: CFDictionaryRef,
            e: *mut CFErrorRef,
        ) -> CFDataRef;
    }

    /// An owned Core Foundation object, released when it goes.
    struct Cf(CFTypeRef);

    impl Cf {
        fn new(r: CFTypeRef) -> Option<Cf> {
            // Never a Cf of NULL, even for a moment: dropping it would
            // CFRelease(NULL), which stops the process.
            if r.is_null() { None } else { Some(Cf(r)) }
        }
    }

    impl Drop for Cf {
        fn drop(&mut self) {
            // SAFETY: Cf owns one reference, made by a Create or Copy call.
            unsafe { CFRelease(self.0) }
        }
    }

    // SAFETY: SecKey objects may be used from any thread.
    unsafe impl Send for Cf {}
    // SAFETY: as above; signing does not change the key.
    unsafe impl Sync for Cf {}

    /// The error e describes, released, after what failed.
    fn error(what: &str, e: CFErrorRef) -> Error {
        if e.is_null() {
            return Error::msg(format!("the Secure Enclave: {what}"));
        }
        let e = Cf(e);
        let mut buf = [0 as c_char; 256];
        // SAFETY: e is a CFError; buf is long enough for the call's n.
        let desc = unsafe {
            let code = CFErrorGetCode(e.0);
            let d = Cf::new(CFErrorCopyDescription(e.0));
            let s = match d {
                Some(d)
                    if CFStringGetCString(d.0, buf.as_mut_ptr(), buf.len() as CFIndex, K_CF_STRING_ENCODING_UTF8)
                        != 0 =>
                {
                    CStr::from_ptr(buf.as_ptr()).to_string_lossy().into_owned()
                }
                _ => String::new(),
            };
            format!("{s} ({code})")
        };
        Error::with(format!("the Secure Enclave: {what}"), Remote(desc))
    }

    #[derive(Debug)]
    struct Remote(String);

    impl std::fmt::Display for Remote {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str(&self.0)
        }
    }

    impl std::error::Error for Remote {}

    fn data(b: &[u8]) -> Result<Cf> {
        // SAFETY: b is valid for its length.
        Cf::new(unsafe { CFDataCreate(ptr::null(), b.as_ptr(), b.len() as CFIndex) })
            .ok_or_else(|| Error::msg("the Secure Enclave: out of memory"))
    }

    /// The bytes of a CFData.
    fn bytes(d: &Cf) -> Vec<u8> {
        // SAFETY: d is a CFData; its bytes live while d does.
        unsafe {
            let n = CFDataGetLength(d.0);
            let p = CFDataGetBytePtr(d.0);
            if p.is_null() || n <= 0 { Vec::new() } else { std::slice::from_raw_parts(p, n as usize).to_vec() }
        }
    }

    /// A dictionary of the pairs, retained by it.
    fn dict(pairs: &[(CFTypeRef, CFTypeRef)]) -> Result<Cf> {
        let k: Vec<CFTypeRef> = pairs.iter().map(|p| p.0).collect();
        let v: Vec<CFTypeRef> = pairs.iter().map(|p| p.1).collect();
        // SAFETY: k and v have pairs.len() valid objects; the callbacks are
        // Core Foundation's own.
        Cf::new(unsafe {
            CFDictionaryCreate(
                ptr::null(),
                k.as_ptr(),
                v.as_ptr(),
                pairs.len() as CFIndex,
                &kCFTypeDictionaryKeyCallBacks,
                &kCFTypeDictionaryValueCallBacks,
            )
        })
        .ok_or_else(|| Error::msg("the Secure Enclave: out of memory"))
    }

    fn bits_256() -> Result<Cf> {
        let bits: c_int = 256;
        // SAFETY: bits is an int, as the type says.
        Cf::new(unsafe { CFNumberCreate(ptr::null(), K_CF_NUMBER_INT_TYPE, (&bits as *const c_int).cast()) })
            .ok_or_else(|| Error::msg("the Secure Enclave: out of memory"))
    }

    fn toid() -> Result<Cf> {
        // SAFETY: a NUL-terminated string.
        Cf::new(unsafe { CFStringCreateWithCString(ptr::null(), c"toid".as_ptr(), K_CF_STRING_ENCODING_UTF8) })
            .ok_or_else(|| Error::msg("the Secure Enclave: out of memory"))
    }

    /// A P-256 key in the enclave.
    pub struct Key {
        key: Cf,
        blob: Vec<u8>,
        public: Vec<u8>,
    }

    fn public_of(key: &Cf) -> Result<Vec<u8>> {
        // SAFETY: key is a SecKey.
        let p = Cf::new(unsafe { SecKeyCopyPublicKey(key.0) }).ok_or_else(|| error("no public key", ptr::null()))?;
        let mut e = ptr::null();
        // SAFETY: p is a SecKey; e receives an owned error.
        let d = Cf::new(unsafe { SecKeyCopyExternalRepresentation(p.0, &mut e) })
            .ok_or_else(|| error("reading the public key", e))?;
        let public = bytes(&d);
        if public.len() != 65 || public[0] != 4 {
            return Err(Error::msg("the Secure Enclave gave a public key that is not on P-256"));
        }
        Ok(public)
    }

    impl Key {
        /// Makes a key that no keychain keeps; its blob is the enclave's
        /// encrypted copy ("toid", CryptoKit's dataRepresentation).
        pub fn new() -> Result<Key> {
            let mut e = ptr::null();
            // AfterFirstUnlock: the service signs from boot on, before anyone
            // logs in; PrivateKeyUsage asks for no user presence.
            // SAFETY: the protection is a CFString constant; e receives an
            // owned error.
            let ac = Cf::new(unsafe {
                SecAccessControlCreateWithFlags(
                    ptr::null(),
                    kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
                    K_SEC_ACCESS_CONTROL_PRIVATE_KEY_USAGE,
                    &mut e,
                )
            })
            .ok_or_else(|| error("the access control", e))?;
            let bits = bits_256()?;
            // SAFETY: the keys and values are live CF objects and constants.
            let key = unsafe {
                let private = dict(&[(kSecAttrIsPermanent, kCFBooleanFalse), (kSecAttrAccessControl, ac.0)])?;
                let attrs = dict(&[
                    (kSecAttrKeyType, kSecAttrKeyTypeECSECPrimeRandom),
                    (kSecAttrKeySizeInBits, bits.0),
                    (kSecAttrTokenID, kSecAttrTokenIDSecureEnclave),
                    (kSecPrivateKeyAttrs, private.0),
                ])?;
                let mut e = ptr::null();
                Cf::new(SecKeyCreateRandomKey(attrs.0, &mut e)).ok_or_else(|| error("making the key", e))?
            };
            let toid = toid()?;
            // SAFETY: key is a SecKey; the value the dictionary gives lives
            // while a does.
            let blob = unsafe {
                let a = Cf::new(SecKeyCopyAttributes(key.0))
                    .ok_or_else(|| error("the enclave gave no copy of the key to keep", ptr::null()))?;
                let v = CFDictionaryGetValue(a.0, toid.0);
                if v.is_null() || CFGetTypeID(v) != CFDataGetTypeID() {
                    return Err(error("the enclave gave no copy of the key to keep", ptr::null()));
                }
                let n = CFDataGetLength(v);
                let p = CFDataGetBytePtr(v);
                if p.is_null() || n <= 0 {
                    return Err(error("the enclave gave no copy of the key to keep", ptr::null()));
                }
                std::slice::from_raw_parts(p, n as usize).to_vec()
            };
            let public = public_of(&key)?;
            Ok(Key { key, blob, public })
        }

        /// Opens a key from its blob, which only the enclave that made it
        /// opens. The enclave opens the key's sealed part only when it signs,
        /// so a damaged blob would load: one signature tells.
        pub fn load(blob: &[u8]) -> Result<Key> {
            if blob.is_empty() {
                return Err(Error::msg("the Secure Enclave: an empty key"));
            }
            let d = data(blob)?;
            let bits = bits_256()?;
            let toid = toid()?;
            // SecKeyCreateWithData would make a new key from the blob;
            // SecKeyCreateRandomKey with it as the token's object ID opens the
            // one it names, as CryptoKit does.
            // SAFETY: the keys and values are live CF objects and constants.
            let key = unsafe {
                let attrs = dict(&[
                    (kSecAttrKeyType, kSecAttrKeyTypeECSECPrimeRandom),
                    (kSecAttrKeySizeInBits, bits.0),
                    (kSecAttrTokenID, kSecAttrTokenIDSecureEnclave),
                    (toid.0, d.0),
                    (kSecAttrIsPermanent, kCFBooleanFalse),
                ])?;
                let mut e = ptr::null();
                Cf::new(SecKeyCreateRandomKey(attrs.0, &mut e)).ok_or_else(|| error("opening the key", e))?
            };
            let public = public_of(&key)?;
            let k = Key { key, blob: blob.to_vec(), public };
            let digest = cbb_core::certs::sha256(b"sekey: the key loads");
            k.sign_digest(&digest).map_err(|e| e.context("the Secure Enclave's key does not open"))?;
            Ok(k)
        }

        /// The blob the identity file keeps.
        pub fn blob(&self) -> Vec<u8> {
            self.blob.clone()
        }

        /// The public key, SEC1 uncompressed.
        pub fn public(&self) -> Vec<u8> {
            self.public.clone()
        }

        /// Signs a SHA-256 digest, DER; the signature is checked before it
        /// leaves, as the enclave signs whatever digest it is given.
        pub fn sign_digest(&self, digest: &[u8; 32]) -> Result<Vec<u8>> {
            use p256::ecdsa::signature::hazmat::PrehashVerifier as _;
            let d = data(digest)?;
            let mut e = ptr::null();
            // SAFETY: key is a SecKey, d a CFData; e receives an owned error.
            let sig = Cf::new(unsafe {
                SecKeyCreateSignature(self.key.0, kSecKeyAlgorithmECDSASignatureDigestX962SHA256, d.0, &mut e)
            })
            .ok_or_else(|| error("signing", e))?;
            let sig = bytes(&sig);
            let vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(&self.public)
                .map_err(|_| Error::msg("the Secure Enclave's key is not on P-256"))?;
            let s = p256::ecdsa::Signature::from_der(&sig)
                .map_err(|_| Error::msg("the Secure Enclave's signature is not understood"))?;
            vk.verify_prehash(digest, &s).map_err(|_| Error::msg("the Secure Enclave's signature does not verify"))?;
            Ok(sig)
        }
    }

    impl Agree for Key {
        fn blob(&self) -> Vec<u8> {
            self.blob.clone()
        }

        fn public(&self) -> Vec<u8> {
            self.public.clone()
        }

        fn agree(&self, peer: &[u8]) -> Result<Vec<u8>> {
            let d = data(peer)?;
            // SAFETY: the keys and values are constants and d; e receives an
            // owned error.
            unsafe {
                let attrs = dict(&[
                    (kSecAttrKeyType, kSecAttrKeyTypeECSECPrimeRandom),
                    (kSecAttrKeyClass, kSecAttrKeyClassPublic),
                ])?;
                let mut e = ptr::null();
                let p = Cf::new(SecKeyCreateWithData(d.0, attrs.0, &mut e))
                    .ok_or_else(|| error("reading the other public key", e))?;
                let params = dict(&[])?;
                let mut e = ptr::null();
                let shared = Cf::new(SecKeyCopyKeyExchangeResult(
                    self.key.0,
                    kSecKeyAlgorithmECDHKeyExchangeStandard,
                    p.0,
                    params.0,
                    &mut e,
                ))
                .ok_or_else(|| error("agreeing on a secret", e))?;
                Ok(bytes(&shared))
            }
        }
    }

    /// Whether the enclave makes keys here: one key, which no keychain
    /// keeps, tells, once. A Mac without one (an Intel Mac before the T2)
    /// says no.
    pub fn available() -> bool {
        static AVAILABLE: OnceLock<bool> = OnceLock::new();
        *AVAILABLE.get_or_init(|| Key::new().is_ok())
    }

    /// Seals secret to a new enclave key, as Go's sekey.Seal.
    pub fn seal(secret: &[u8]) -> Result<Vec<u8>> {
        let key = Key::new()?;
        let mut nonce = [0u8; 12];
        getrandom::fill(&mut nonce).map_err(|e| Error::msg(format!("no randomness: {e}")))?;
        let eph = loop {
            let mut b = [0u8; 32];
            getrandom::fill(&mut b).map_err(|e| Error::msg(format!("no randomness: {e}")))?;
            if let Some(s) = Option::<p256::NonZeroScalar>::from(p256::NonZeroScalar::from_repr(b.into())) {
                break s;
            }
        };
        super::seal_to(&key, &eph, nonce, secret)
    }

    /// Opens what seal sealed.
    pub fn unseal(b: &[u8]) -> Result<Vec<u8>> {
        super::unseal_with(b, &|blob| Ok(Box::new(Key::load(blob)?) as Box<dyn Agree>))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A software key in place of the enclave's, its blob its scalar.
    struct Soft(p256::NonZeroScalar);

    impl Agree for Soft {
        fn blob(&self) -> Vec<u8> {
            use p256::elliptic_curve::ff::PrimeField as _;
            self.0.to_repr().to_vec()
        }

        fn public(&self) -> Vec<u8> {
            use p256::elliptic_curve::sec1::ToSec1Point as _;
            p256::PublicKey::from_secret_scalar(&self.0).to_sec1_point(false).as_bytes().to_vec()
        }

        fn agree(&self, peer: &[u8]) -> Result<Vec<u8>> {
            let p = p256::PublicKey::from_sec1_bytes(peer).map_err(|_| Error::msg("not on P-256"))?;
            Ok(p256::ecdh::diffie_hellman(&self.0, p.as_affine()).raw_secret_bytes().to_vec())
        }
    }

    fn scalar(n: u8) -> p256::NonZeroScalar {
        let mut b = [0u8; 32];
        b[31] = n;
        Option::from(p256::NonZeroScalar::from_repr(b.into())).unwrap()
    }

    fn load(blob: &[u8]) -> Result<Box<dyn Agree>> {
        let s = Option::from(p256::NonZeroScalar::from_repr(<[u8; 32]>::try_from(blob).unwrap().into())).unwrap();
        Ok(Box::new(Soft(s)))
    }

    /// Go's sekey.Seal's format, from Go's own code with the same keys
    /// and nonce (crypto/ecdh, crypto/hkdf, AES-256-GCM), so that a secret
    /// Go sealed opens in Rust and the other way round.
    const GO_SEALED: &str = include_str!("../../testdata/interop/go-sekey-seal.json");

    /// The nonce Go sealed the vector with: the box's first 12 bytes.
    fn go_nonce() -> [u8; 12] {
        let go: Wire = serde_json::from_str(GO_SEALED).unwrap();
        go.sealed[..12].try_into().unwrap()
    }

    /// A random nonce, as seal draws one.
    fn random_nonce() -> [u8; 12] {
        let (a, b) = (getrandom::u64().unwrap(), getrandom::u32().unwrap());
        let mut n = a.to_le_bytes().to_vec();
        n.extend(b.to_le_bytes());
        n.try_into().unwrap()
    }

    #[test]
    fn seals_as_go_does() {
        let key = Soft(scalar(7));
        let b = seal_to(&key, &scalar(9), go_nonce(), b"the wireguard key").unwrap();
        assert_eq!(unseal_with(&b, &load).unwrap(), b"the wireguard key");
        let ours: serde_json::Value = serde_json::from_slice(&b).unwrap();
        let go: serde_json::Value = serde_json::from_str(GO_SEALED).unwrap();
        assert_eq!(ours, go);
    }

    /// The Mac's own enclave, as Go's sekey tests: only with CBB_SE_TEST=1,
    /// so that the tests' keys stay out of it otherwise.
    #[cfg(target_os = "macos")]
    #[test]
    fn the_enclave_signs_and_seals() {
        if std::env::var("CBB_SE_TEST").as_deref() != Ok("1") {
            return;
        }
        assert!(available());
        let k = Key::new().unwrap();
        let digest = cbb_core::certs::sha256(b"a record");
        k.sign_digest(&digest).unwrap();
        let again = Key::load(&k.blob()).unwrap();
        assert_eq!(again.public(), k.public());
        again.sign_digest(&digest).unwrap();
        let mut broken = k.blob();
        let n = broken.len() / 2;
        broken[n] ^= 1;
        assert!(Key::load(&broken).is_err(), "a damaged blob");
        let b = seal(b"the wireguard key").unwrap();
        assert_eq!(unseal(&b).unwrap(), b"the wireguard key");
    }

    #[test]
    fn refuses_what_does_not_open() {
        let key = Soft(scalar(7));
        let b = seal_to(&key, &scalar(9), random_nonce(), b"secret").unwrap();
        let mut w: Wire = serde_json::from_slice(&b).unwrap();
        let last = w.sealed.len() - 1;
        w.sealed[last] ^= 1;
        assert!(unseal_with(&serde_json::to_vec(&w).unwrap(), &load).is_err());
        let other = seal_to(&Soft(scalar(8)), &scalar(9), random_nonce(), b"secret").unwrap();
        let mut w2: Wire = serde_json::from_slice(&other).unwrap();
        w2.key = key.blob();
        assert!(unseal_with(&serde_json::to_vec(&w2).unwrap(), &load).is_err(), "another key's box");
        w2.v = 2;
        assert!(unseal_with(&serde_json::to_vec(&w2).unwrap(), &load).is_err(), "an unknown version");
    }
}
