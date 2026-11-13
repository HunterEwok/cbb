// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! TLS between members without certificates (0.6, design-no-certificates
//! section 3): each side shows the key container of its member key
//! (`format::container`), a fixed template with only the key in it. The
//! peer's key is the identity: TLS's CertificateVerify proves the peer
//! holds it, the client checks its hash against the device it dialed, and
//! both sides ask the records whether that device is in the group
//! ([`standing`]). No server name is sent, and nothing in the handshake
//! names a device or the group: the container holds the key alone.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::fmt;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{DigitallySignedStruct, DistinguishedName, SignatureScheme};

use super::{Clock, OneCert, OneClientCert, TlsError, client_builder, no_tls12, provider, server_builder};
use crate::error::{Error, Result};
use crate::format::{Alg, DeviceId, Key, KeyHash, container};
use crate::identity::ExternalKey;

/// This side's member key: its point, for the container, and what signs.
#[derive(Clone)]
pub struct OwnKey {
    point: [u8; 65],
    signer: Arc<dyn rustls::sign::SigningKey>,
}

impl fmt::Debug for OwnKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OwnKey")
    }
}

impl OwnKey {
    /// A key kept outside the core (a TPM, the Secure Enclave, Keystore).
    pub fn external(key: Arc<dyn ExternalKey>) -> Result<OwnKey> {
        let point = point_of(&key.public())?;
        Ok(OwnKey { point, signer: Arc::new(provider::ExternalSigningKey(key)) })
    }

    /// A key the core holds, PKCS #8.
    pub fn pkcs8(der: &[u8]) -> Result<OwnKey> {
        let sk = crate::identity::signing_key(der)?;
        let point = point_of(sk.verifying_key().to_sec1_point(false).as_bytes())?;
        let signer = provider()
            .key_provider
            .load_private_key(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(der.to_vec())))
            .map_err(|e| Error::with("cannot use the member key", TlsError(e)))?;
        Ok(OwnKey { point, signer })
    }

    /// The key's point, SEC1 uncompressed.
    pub fn point(&self) -> &[u8; 65] {
        &self.point
    }

    /// The key's hash (format section 2).
    pub fn hash(&self) -> KeyHash {
        Key::new(Alg::Es256, &self.point).hash()
    }

    fn certified(&self) -> Arc<rustls::sign::CertifiedKey> {
        let c = CertificateDer::from(container::build(&self.point).to_vec());
        Arc::new(rustls::sign::CertifiedKey::new(vec![c], self.signer.clone()))
    }
}

fn point_of(b: &[u8]) -> Result<[u8; 65]> {
    let p: [u8; 65] = b.try_into().map_err(|_| Error::msg("the member key is not a P-256 point"))?;
    Key::new(Alg::Es256, &p).check().map_err(|_| Error::msg("the member key is not a P-256 point"))?;
    Ok(p)
}

pub use crate::peer::{Standing, standing};

/// Judges a peer's key during the handshake: Ok to go on, or why not. A
/// caller holds the records under its own lock and usually answers with
/// [`standing`], taking [`Standing::Unknown`] when it waits for an intro.
pub type Judge = Arc<dyn Fn(&[u8; 65]) -> core::result::Result<(), String> + Send + Sync>;

/// Reads a peer's presented certificates: exactly one, a key container.
fn peer_point(end_entity: &CertificateDer<'_>, intermediates: &[CertificateDer<'_>]) -> Result<[u8; 65]> {
    if !intermediates.is_empty() {
        return Err(Error::msg("a member shows one key container, nothing more"));
    }
    container::read(end_entity).map_err(|_| Error::msg("not a key container"))
}

/// The peer's key from the certificates a finished handshake saw.
pub fn peer_key(certs: Option<&[CertificateDer<'static>]>) -> Option<[u8; 65]> {
    match certs? {
        [one] => container::read(one).ok(),
        _ => None,
    }
}

fn verify_sig(
    message: &[u8],
    cert: &CertificateDer<'_>,
    dss: &DigitallySignedStruct,
) -> core::result::Result<HandshakeSignatureValid, rustls::Error> {
    if dss.scheme != provider::SCHEME {
        return Err(rustls::PeerMisbehaved::SignedHandshakeWithUnadvertisedSigScheme.into());
    }
    let point =
        container::read(cert).map_err(|_| rustls::Error::InvalidCertificate(rustls::CertificateError::BadEncoding))?;
    let key = p256::ecdsa::VerifyingKey::from_sec1_bytes(&point)
        .map_err(|_| rustls::Error::InvalidCertificate(rustls::CertificateError::BadEncoding))?;
    let sig = p256::ecdsa::Signature::from_der(dss.signature())
        .map_err(|_| rustls::Error::InvalidCertificate(rustls::CertificateError::BadSignature))?;
    use p256::ecdsa::signature::Verifier as _;
    key.verify(message, &sig).map_err(|_| rustls::Error::InvalidCertificate(rustls::CertificateError::BadSignature))?;
    Ok(HandshakeSignatureValid::assertion())
}

fn refuse(why: &str) -> rustls::Error {
    rustls::Error::General(why.to_string())
}

/// Checks the member this one dialed.
struct DialedVerifier {
    expect: Option<DeviceId>,
    judge: Judge,
}

impl fmt::Debug for DialedVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DialedVerifier")
    }
}

impl ServerCertVerifier for DialedVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> core::result::Result<ServerCertVerified, rustls::Error> {
        let point = peer_point(end_entity, intermediates).map_err(|e| refuse(e.message()))?;
        if let Some(want) = &self.expect
            && Key::new(Alg::Es256, &point).device_id() != *want
        {
            return Err(refuse("reached another device than the one dialed"));
        }
        (self.judge)(&point).map_err(|why| refuse(&why))?;
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> core::result::Result<HandshakeSignatureValid, rustls::Error> {
        no_tls12()
    }

    fn verify_tls13_signature(
        &self,
        m: &[u8],
        c: &CertificateDer<'_>,
        d: &DigitallySignedStruct,
    ) -> core::result::Result<HandshakeSignatureValid, rustls::Error> {
        verify_sig(m, c, d)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![provider::SCHEME]
    }
}

/// Checks a member that dialed this one.
struct DialerVerifier {
    judge: Judge,
}

impl fmt::Debug for DialerVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DialerVerifier")
    }
}

impl ClientCertVerifier for DialerVerifier {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _: UnixTime,
    ) -> core::result::Result<ClientCertVerified, rustls::Error> {
        let point = peer_point(end_entity, intermediates).map_err(|e| refuse(e.message()))?;
        (self.judge)(&point).map_err(|why| refuse(&why))?;
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> core::result::Result<HandshakeSignatureValid, rustls::Error> {
        no_tls12()
    }

    fn verify_tls13_signature(
        &self,
        m: &[u8],
        c: &CertificateDer<'_>,
        d: &DigitallySignedStruct,
    ) -> core::result::Result<HandshakeSignatureValid, rustls::Error> {
        verify_sig(m, c, d)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![provider::SCHEME]
    }
}

/// The server name a client hands rustls. It is never sent: SNI is off.
#[allow(clippy::expect_used, reason = "a fixed, valid DNS name")]
pub fn unsent_name() -> ServerName<'static> {
    ServerName::try_from("cbb.invalid").expect("a valid DNS name")
}

/// The client configuration for dialing a member by its key: TLS 1.3, the
/// hybrid key exchange, ALPN `alpn`, this side's key container, no server
/// name, no resumption. `expect` is the device discovery found, None for an
/// address given by hand; `judge` decides on the peer's key.
pub fn client(
    own: &OwnKey,
    expect: Option<DeviceId>,
    judge: Judge,
    alpn: &[u8],
    clock: &Clock,
) -> Result<rustls::ClientConfig> {
    let mut cfg = client_builder(clock)?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(DialedVerifier { expect, judge }))
        .with_client_cert_resolver(Arc::new(OneClientCert(own.certified())));
    cfg.alpn_protocols = vec![alpn.to_vec()];
    cfg.resumption = rustls::client::Resumption::disabled();
    cfg.enable_sni = false;
    Ok(cfg)
}

/// The server configuration for members that dial this one: TLS 1.3, the
/// hybrid key exchange, ALPN `alpn`, this side's key container, a client
/// container required and judged, no session tickets.
pub fn server(own: &OwnKey, judge: Judge, alpn: &[u8], clock: &Clock) -> Result<rustls::ServerConfig> {
    let mut cfg = server_builder(clock)?
        .with_client_cert_verifier(Arc::new(DialerVerifier { judge }))
        .with_cert_resolver(Arc::new(OneCert(own.certified())));
    cfg.alpn_protocols = vec![alpn.to_vec()];
    cfg.send_tls13_tickets = 0;
    Ok(cfg)
}

/// Lets a configuration export keying material: the exporter of the
/// connection it makes (RFC 8446 section 7.5), for the tunnel's pre-shared
/// key (`crate::hubkey`) and the admin key's proof. Use a new configuration
/// for each connection.
pub fn exporting_client(mut cfg: rustls::ClientConfig) -> (rustls::ClientConfig, Arc<super::Exporter>) {
    let x = Arc::new(super::Exporter::default());
    cfg.key_log = x.clone();
    (cfg, x)
}

/// The server's side of [`exporting_client`].
pub fn exporting_server(mut cfg: rustls::ServerConfig) -> (rustls::ServerConfig, Arc<super::Exporter>) {
    let x = Arc::new(super::Exporter::default());
    cfg.key_log = x.clone();
    (cfg, x)
}

/// A judge that takes every well-formed key: for pairing, where CPace bound
/// to both keys authenticates the peer, and for a server's own client
/// checks.
pub fn any_key() -> Judge {
    Arc::new(|_| Ok(()))
}

/// A judge from a device's view of the records: members go on, unknown
/// keys too when `unknown_ok` (the caller then waits for the intro), any
/// key of a halted group (the caller then gives and takes the recovery
/// key's records only, `RecordSet::for_peer`), a key that gets a root
/// fork's proof (`Standing::ForkProof`: the pair alone, both ways), the
/// rest are refused. `look` usually locks the caller's records and answers
/// with [`standing`].
pub fn by_standing(look: impl Fn(&[u8; 65]) -> Standing + Send + Sync + 'static, unknown_ok: bool) -> Judge {
    Arc::new(move |point| match look(point) {
        Standing::Member(_) | Standing::Halted | Standing::ForkProof => Ok(()),
        Standing::Unknown if unknown_ok => Ok(()),
        Standing::Unknown => Err("not a device of the group".to_string()),
        Standing::Refused(why) => Err(format!("refused: {why}")),
    })
}

#[cfg(test)]
mod tests;
