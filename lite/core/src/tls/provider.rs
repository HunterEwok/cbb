// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! A rustls crypto provider of RustCrypto code, with only what the members
//! use: TLS 1.3 with AES-128-GCM or ChaCha20-Poly1305 and SHA-256, X25519
//! key exchange, ECDSA P-256 with SHA-256 keys and signatures. It needs no
//! operating system, so the same TLS runs on Linux and on a microcontroller.

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::marker::PhantomData;

use aes_gcm::Aes128Gcm;
use aes_gcm::aead::{AeadCore, AeadInOut, KeyInit};
use chacha20poly1305::ChaCha20Poly1305;
use hmac::Mac;
use p256::ecdsa::signature::{Signer as _, Verifier as _};
use p256::ecdsa::{Signature, SigningKey as EcdsaKey, VerifyingKey};
use p256::pkcs8::DecodePrivateKey;
use rustls::crypto::cipher::{
    AeadKey, InboundOpaqueMessage, InboundPlainMessage, Iv, MessageDecrypter, MessageEncrypter, Nonce,
    OutboundOpaqueMessage, OutboundPlainMessage, PrefixedPayload, Tls13AeadAlgorithm, UnsupportedOperationError,
    make_tls13_aad,
};
use rustls::crypto::tls13::HkdfUsingHmac;
use rustls::crypto::{
    ActiveKeyExchange, CipherSuiteCommon, CryptoProvider, GetRandomFailed, KeyProvider, SecureRandom, SharedSecret,
    SupportedKxGroup, WebPkiSupportedAlgorithms, hash, hmac as rhmac,
};
use rustls::pki_types::{AlgorithmIdentifier, InvalidSignature, PrivateKeyDer, SignatureVerificationAlgorithm, alg_id};
use rustls::sign::{Signer, SigningKey};
use rustls::{
    CipherSuite, ConnectionTrafficSecrets, ContentType, Error, NamedGroup, ProtocolVersion, SignatureAlgorithm,
    SignatureScheme, SupportedCipherSuite, Tls13CipherSuite,
};
use sha2::{Digest, Sha256};

/// The provider: the cipher suites in order of preference (ChaCha20 first,
/// as it is the faster one without AES instructions), X25519, and ECDSA
/// P-256 with SHA-256.
pub fn provider() -> CryptoProvider {
    CryptoProvider {
        cipher_suites: Vec::from([TLS13_CHACHA20_POLY1305_SHA256, TLS13_AES_128_GCM_SHA256]),
        kx_groups: Vec::from([&X25519 as &dyn SupportedKxGroup]),
        signature_verification_algorithms: ALGORITHMS,
        secure_random: &Random,
        key_provider: &Keys,
    }
}

/// The signature scheme of every key in a group.
pub const SCHEME: SignatureScheme = SignatureScheme::ECDSA_NISTP256_SHA256;

static ALGORITHMS: WebPkiSupportedAlgorithms =
    WebPkiSupportedAlgorithms { all: &[&EcdsaP256Sha256], mapping: &[(SCHEME, &[&EcdsaP256Sha256])] };

// SHA-256

struct Sha256Hash;

impl hash::Hash for Sha256Hash {
    fn start(&self) -> Box<dyn hash::Context> {
        Box::new(Sha256Context(Sha256::new()))
    }

    fn hash(&self, data: &[u8]) -> hash::Output {
        hash::Output::new(&Sha256::digest(data))
    }

    fn output_len(&self) -> usize {
        32
    }

    fn algorithm(&self) -> hash::HashAlgorithm {
        hash::HashAlgorithm::SHA256
    }
}

struct Sha256Context(Sha256);

impl hash::Context for Sha256Context {
    fn fork_finish(&self) -> hash::Output {
        hash::Output::new(&self.0.clone().finalize())
    }

    fn fork(&self) -> Box<dyn hash::Context> {
        Box::new(Sha256Context(self.0.clone()))
    }

    fn finish(self: Box<Self>) -> hash::Output {
        hash::Output::new(&self.0.finalize())
    }

    fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }
}

struct HmacSha256;

impl rhmac::Hmac for HmacSha256 {
    #[allow(clippy::expect_used, reason = "HMAC takes a key of any length, so this never fails")]
    fn with_key(&self, key: &[u8]) -> Box<dyn rhmac::Key> {
        Box::new(HmacKey(hmac::Hmac::<Sha256>::new_from_slice(key).expect("HMAC takes any key")))
    }

    fn hash_output_len(&self) -> usize {
        32
    }
}

struct HmacKey(hmac::Hmac<Sha256>);

impl rhmac::Key for HmacKey {
    fn sign_concat(&self, first: &[u8], middle: &[&[u8]], last: &[u8]) -> rhmac::Tag {
        let mut mac = self.0.clone();
        mac.update(first);
        for m in middle {
            mac.update(m);
        }
        mac.update(last);
        rhmac::Tag::new(&mac.finalize().into_bytes())
    }

    fn tag_len(&self) -> usize {
        32
    }
}

// The cipher suites

static SHA256: Sha256Hash = Sha256Hash;
static HKDF_SHA256: HkdfUsingHmac<'static> = HkdfUsingHmac(&HmacSha256);

pub static TLS13_CHACHA20_POLY1305_SHA256: SupportedCipherSuite = SupportedCipherSuite::Tls13(&Tls13CipherSuite {
    common: CipherSuiteCommon {
        suite: CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
        hash_provider: &SHA256,
        confidentiality_limit: u64::MAX,
    },
    hkdf_provider: &HKDF_SHA256,
    aead_alg: &Aead::<ChaCha20Poly1305>(PhantomData),
    quic: None,
});

pub static TLS13_AES_128_GCM_SHA256: SupportedCipherSuite = SupportedCipherSuite::Tls13(&Tls13CipherSuite {
    common: CipherSuiteCommon {
        suite: CipherSuite::TLS13_AES_128_GCM_SHA256,
        hash_provider: &SHA256,
        // RFC 8446, section 5.5.
        confidentiality_limit: 1 << 24,
    },
    hkdf_provider: &HKDF_SHA256,
    aead_alg: &Aead::<Aes128Gcm>(PhantomData),
    quic: None,
});

/// The tag that every AEAD here appends.
const TAG_LEN: usize = 16;

/// An AEAD of RustCrypto with a 12-byte nonce and a 16-byte tag.
trait Algorithm: AeadInOut + KeyInit + Send + Sync + 'static {
    const KEY_LEN: usize;
    fn secrets(key: AeadKey, iv: Iv) -> ConnectionTrafficSecrets;
}

impl Algorithm for ChaCha20Poly1305 {
    const KEY_LEN: usize = 32;
    fn secrets(key: AeadKey, iv: Iv) -> ConnectionTrafficSecrets {
        ConnectionTrafficSecrets::Chacha20Poly1305 { key, iv }
    }
}

impl Algorithm for Aes128Gcm {
    const KEY_LEN: usize = 16;
    fn secrets(key: AeadKey, iv: Iv) -> ConnectionTrafficSecrets {
        ConnectionTrafficSecrets::Aes128Gcm { key, iv }
    }
}

struct Aead<A>(PhantomData<A>);

// rustls makes the keys key_len() long, the length the cipher takes.
#[allow(clippy::expect_used, reason = "rustls hands over keys of the length key_len() names")]
impl<A: Algorithm> Tls13AeadAlgorithm for Aead<A> {
    fn encrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageEncrypter> {
        Box::new(Crypter::<A> { key: A::new_from_slice(key.as_ref()).expect("rustls makes keys of key_len"), iv })
    }

    fn decrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageDecrypter> {
        Box::new(Crypter::<A> { key: A::new_from_slice(key.as_ref()).expect("rustls makes keys of key_len"), iv })
    }

    fn key_len(&self) -> usize {
        A::KEY_LEN
    }

    fn extract_keys(&self, key: AeadKey, iv: Iv) -> Result<ConnectionTrafficSecrets, UnsupportedOperationError> {
        Ok(A::secrets(key, iv))
    }
}

struct Crypter<A> {
    key: A,
    iv: Iv,
}

#[allow(clippy::expect_used, reason = "TLS 1.3 nonces are 12 bytes, the size every cipher here takes")]
fn nonce<A: AeadCore>(iv: &Iv, seq: u64) -> aes_gcm::aead::Nonce<A> {
    let n = Nonce::new(iv, seq).0;
    aes_gcm::aead::Nonce::<A>::try_from(&n[..]).expect("every AEAD here takes a 12-byte nonce")
}

impl<A: Algorithm> MessageEncrypter for Crypter<A> {
    fn encrypt(&mut self, msg: OutboundPlainMessage<'_>, seq: u64) -> Result<OutboundOpaqueMessage, Error> {
        let total = self.encrypted_payload_len(msg.payload.len());
        let mut payload = PrefixedPayload::with_capacity(total);
        payload.extend_from_chunks(&msg.payload);
        payload.extend_from_slice(&msg.typ.to_array());
        let aad = make_tls13_aad(total);
        let tag = self
            .key
            .encrypt_inout_detached(&nonce::<A>(&self.iv, seq), &aad, payload.as_mut().into())
            .map_err(|_| Error::EncryptError)?;
        payload.extend_from_slice(&tag);
        // TLS 1.3 records carry the legacy version 1.2 (RFC 8446, section 5.1).
        Ok(OutboundOpaqueMessage::new(ContentType::ApplicationData, ProtocolVersion::TLSv1_2, payload))
    }

    fn encrypted_payload_len(&self, payload_len: usize) -> usize {
        payload_len.saturating_add(1 + TAG_LEN)
    }
}

impl<A: Algorithm> MessageDecrypter for Crypter<A> {
    fn decrypt<'a>(&mut self, mut msg: InboundOpaqueMessage<'a>, seq: u64) -> Result<InboundPlainMessage<'a>, Error> {
        let payload = &mut msg.payload;
        let len = payload.len();
        let aad = make_tls13_aad(len);
        let at = len.checked_sub(TAG_LEN).ok_or(Error::DecryptError)?;
        let (data, tag) = payload.split_at_mut(at);
        let tag = aes_gcm::aead::Tag::<A>::try_from(&tag[..]).map_err(|_| Error::DecryptError)?;
        self.key
            .decrypt_inout_detached(&nonce::<A>(&self.iv, seq), &aad, data.into(), &tag)
            .map_err(|_| Error::DecryptError)?;
        payload.truncate(at);
        msg.into_tls13_unpadded_message()
    }
}

// X25519

#[derive(Debug)]
struct X25519Group;

static X25519: X25519Group = X25519Group;

impl SupportedKxGroup for X25519Group {
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, Error> {
        let mut b = [0u8; 32];
        getrandom::fill(&mut b).map_err(|_| Error::FailedToGetRandomBytes)?;
        let secret = x25519_dalek::StaticSecret::from(b);
        let public = x25519_dalek::PublicKey::from(&secret);
        Ok(Box::new(X25519Exchange { secret, public }))
    }

    fn name(&self) -> NamedGroup {
        NamedGroup::X25519
    }
}

struct X25519Exchange {
    secret: x25519_dalek::StaticSecret,
    public: x25519_dalek::PublicKey,
}

impl ActiveKeyExchange for X25519Exchange {
    fn complete(self: Box<Self>, peer: &[u8]) -> Result<SharedSecret, Error> {
        let peer: [u8; 32] = peer.try_into().map_err(|_| Error::from(rustls::PeerMisbehaved::InvalidKeyShare))?;
        let shared = self.secret.diffie_hellman(&x25519_dalek::PublicKey::from(peer));
        // An all-zero secret means a low-order point (RFC 8446, section 7.4.2).
        if !shared.was_contributory() {
            return Err(rustls::PeerMisbehaved::InvalidKeyShare.into());
        }
        Ok(SharedSecret::from(&shared.as_bytes()[..]))
    }

    fn pub_key(&self) -> &[u8] {
        self.public.as_bytes()
    }

    fn group(&self) -> NamedGroup {
        NamedGroup::X25519
    }
}

// ECDSA P-256 with SHA-256

#[derive(Debug)]
pub(super) struct EcdsaP256Sha256;

impl SignatureVerificationAlgorithm for EcdsaP256Sha256 {
    fn verify_signature(&self, public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<(), InvalidSignature> {
        let key = VerifyingKey::from_sec1_bytes(public_key).map_err(|_| InvalidSignature)?;
        let sig = Signature::from_der(signature).map_err(|_| InvalidSignature)?;
        key.verify(message, &sig).map_err(|_| InvalidSignature)
    }

    fn public_key_alg_id(&self) -> AlgorithmIdentifier {
        alg_id::ECDSA_P256
    }

    fn signature_alg_id(&self) -> AlgorithmIdentifier {
        alg_id::ECDSA_SHA256
    }
}

#[derive(Debug)]
struct Random;

impl SecureRandom for Random {
    fn fill(&self, buf: &mut [u8]) -> Result<(), GetRandomFailed> {
        getrandom::fill(buf).map_err(|_| GetRandomFailed)
    }
}

#[derive(Debug)]
struct Keys;

impl KeyProvider for Keys {
    fn load_private_key(&self, der: PrivateKeyDer<'static>) -> Result<Arc<dyn SigningKey>, Error> {
        let PrivateKeyDer::Pkcs8(pkcs8) = der else {
            return Err(Error::General("the key is not PKCS #8".into()));
        };
        let key = EcdsaKey::from_pkcs8_der(pkcs8.secret_pkcs8_der())
            .map_err(|_| Error::General("the key is not a P-256 key".into()))?;
        Ok(Arc::new(EcdsaSigningKey(Arc::new(key))))
    }
}

/// A device's P-256 key, for its TLS signatures.
#[derive(Clone)]
struct EcdsaSigningKey(Arc<EcdsaKey>);

impl core::fmt::Debug for EcdsaSigningKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("EcdsaSigningKey")
    }
}

impl SigningKey for EcdsaSigningKey {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        offered.contains(&SCHEME).then(|| Box::new(self.clone()) as Box<dyn Signer>)
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::ECDSA
    }
}

impl Signer for EcdsaSigningKey {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        let sig: Signature = self.0.sign(message);
        Ok(sig.to_der().as_bytes().to_vec())
    }

    fn scheme(&self) -> SignatureScheme {
        SCHEME
    }
}

/// A device key the core does not hold (crate::identity::ExternalKey), for
/// the TLS signature of a joiner whose key is in a phone's hardware.
#[derive(Clone)]
pub(super) struct ExternalSigningKey(pub(super) Arc<dyn crate::identity::ExternalKey>);

impl core::fmt::Debug for ExternalSigningKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("ExternalSigningKey")
    }
}

impl SigningKey for ExternalSigningKey {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        offered.contains(&SCHEME).then(|| Box::new(self.clone()) as Box<dyn Signer>)
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::ECDSA
    }
}

impl Signer for ExternalSigningKey {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        crate::identity::sign_external(&*self.0, message).map_err(|e| Error::General(alloc::format!("{e}")))
    }

    fn scheme(&self) -> SignatureScheme {
        SCHEME
    }
}
