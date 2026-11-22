// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! X25519MLKEM768 (draft-ietf-tls-ecdhe-mlkem, group 0x11EC) as a rustls key
//! exchange on RustCrypto. The client's share is the ML-KEM-768
//! encapsulation key (1184 bytes) and an X25519 key (32); the server's is
//! the ciphertext (1088) and its X25519 key; the secret is the ML-KEM shared
//! key followed by the X25519 secret. A client also sends the X25519 half as
//! a share of its own, so that a server with X25519 alone answers at once
//! instead of asking again (HelloRetryRequest).

use alloc::boxed::Box;
use alloc::vec::Vec;

use ml_kem::kem::Decapsulate as _;
use ml_kem::{Ciphertext, EncapsulationKey, Key, KeyExport as _, MlKem768};
use rustls::crypto::{ActiveKeyExchange, CompletedKeyExchange, SharedSecret, SupportedKxGroup};
use rustls::{Error, NamedGroup, PeerMisbehaved};

const GROUP: NamedGroup = NamedGroup::X25519MLKEM768;
/// The encapsulation key's length.
const EK: usize = 1184;
/// The ciphertext's length.
const CT: usize = 1088;

#[derive(Debug)]
pub(super) struct X25519MlKem768;

pub(super) static HYBRID: X25519MlKem768 = X25519MlKem768;

fn random<const N: usize>() -> Result<[u8; N], Error> {
    let mut b = [0u8; N];
    getrandom::fill(&mut b).map_err(|_| Error::FailedToGetRandomBytes)?;
    Ok(b)
}

fn bad() -> Error {
    PeerMisbehaved::InvalidKeyShare.into()
}

/// X25519 with a peer's 32 bytes; an all-zero secret (a low-order point,
/// RFC 8446 section 7.4.2) is refused.
fn x25519(secret: &x25519_dalek::StaticSecret, peer: &[u8]) -> Result<[u8; 32], Error> {
    let peer: [u8; 32] = peer.try_into().map_err(|_| bad())?;
    let s = secret.diffie_hellman(&x25519_dalek::PublicKey::from(peer));
    if !s.was_contributory() {
        return Err(bad());
    }
    Ok(*s.as_bytes())
}

impl SupportedKxGroup for X25519MlKem768 {
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, Error> {
        let dk = ml_kem::DecapsulationKey::<MlKem768>::from_seed(random::<64>()?.into());
        let xs = x25519_dalek::StaticSecret::from(random::<32>()?);
        let mut public = dk.encapsulation_key().to_bytes().to_vec();
        public.extend_from_slice(x25519_dalek::PublicKey::from(&xs).as_bytes());
        Ok(Box::new(Client { dk, xs, public }))
    }

    fn start_and_complete(&self, client_share: &[u8]) -> Result<CompletedKeyExchange, Error> {
        let (Some(ek), Some(x)) = (client_share.get(..EK), client_share.get(EK..)) else {
            return Err(bad());
        };
        if x.len() != 32 {
            return Err(bad());
        }
        let ek = Key::<EncapsulationKey<MlKem768>>::try_from(ek).map_err(|_| bad())?;
        let ek = EncapsulationKey::<MlKem768>::new(&ek).map_err(|_| bad())?;
        let (ct, k) = ek.encapsulate_deterministic(&random::<32>()?.into());
        let xs = x25519_dalek::StaticSecret::from(random::<32>()?);
        let shared = x25519(&xs, x)?;
        let mut pub_key = ct.to_vec();
        pub_key.extend_from_slice(x25519_dalek::PublicKey::from(&xs).as_bytes());
        let mut secret: Vec<u8> = k.to_vec();
        secret.extend_from_slice(&shared);
        Ok(CompletedKeyExchange { group: GROUP, pub_key, secret: SharedSecret::from(&secret[..]) })
    }

    fn name(&self) -> NamedGroup {
        GROUP
    }
}

struct Client {
    dk: ml_kem::DecapsulationKey<MlKem768>,
    xs: x25519_dalek::StaticSecret,
    public: Vec<u8>,
}

impl ActiveKeyExchange for Client {
    fn complete(self: Box<Self>, peer: &[u8]) -> Result<SharedSecret, Error> {
        let (Some(ct), Some(x)) = (peer.get(..CT), peer.get(CT..)) else {
            return Err(bad());
        };
        let ct = Ciphertext::<MlKem768>::try_from(ct).map_err(|_| bad())?;
        let k = self.dk.decapsulate(&ct);
        let shared = x25519(&self.xs, x)?;
        let mut secret: Vec<u8> = k.to_vec();
        secret.extend_from_slice(&shared);
        Ok(SharedSecret::from(&secret[..]))
    }

    fn pub_key(&self) -> &[u8] {
        &self.public
    }

    fn hybrid_component(&self) -> Option<(NamedGroup, &[u8])> {
        Some((NamedGroup::X25519, self.public.get(EK..).unwrap_or_default()))
    }

    fn complete_hybrid_component(self: Box<Self>, peer: &[u8]) -> Result<SharedSecret, Error> {
        Ok(SharedSecret::from(&x25519(&self.xs, peer)?[..]))
    }

    fn group(&self) -> NamedGroup {
        GROUP
    }
}
