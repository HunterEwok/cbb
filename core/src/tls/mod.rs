// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The TLS of member connections and pairing (docs/protocol.md, sections 4
//! and 6) on rustls, without an operating system: the crypto provider
//! (provider.rs), the members' TLS by key (bykey), the configurations for
//! a server known by the pin of its key, for pairing and for a relay's
//! registrations, a connection without I/O (session.rs) and the pairing
//! exporter (exporter.rs).
//!
//! rustls takes the time from the TimeProvider each configuration is
//! given: the system clock on Linux, the clock a microcontroller set from
//! the network.

pub mod bykey;
mod exporter;
mod hybrid;
mod provider;
mod session;
#[cfg(feature = "web")]
pub mod web;

use alloc::string::ToString;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::fmt;

pub use exporter::Exporter;
pub use provider::provider;
/// The rustls this TLS is built on, for its types.
pub use rustls;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::time_provider::TimeProvider;
use rustls::{DigitallySignedStruct, DistinguishedName, SignatureScheme};
pub use session::Session;

use crate::alpn;
use crate::certs::{self, Cert, DeviceId};
use crate::error::{Error, Result};

/// The clock of the TLS configurations.
pub type Clock = Arc<dyn TimeProvider>;

/// A rustls error as a cause of this crate's errors (rustls's own error
/// type is an error only with the standard library).
pub struct TlsError(pub rustls::Error);

impl fmt::Display for TlsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

impl fmt::Debug for TlsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&self.0, f)
    }
}

impl core::error::Error for TlsError {}

fn tls_err(msg: &str) -> rustls::Error {
    rustls::Error::General(msg.to_string())
}

/// Verifies the TLS 1.3 handshake signature with the key of the
/// certificate: every key of a group is ECDSA P-256 with SHA-256.
fn verify_sig(
    message: &[u8],
    cert: &CertificateDer<'_>,
    dss: &DigitallySignedStruct,
) -> Result<HandshakeSignatureValid, rustls::Error> {
    if dss.scheme != provider::SCHEME {
        return Err(rustls::PeerMisbehaved::SignedHandshakeWithUnadvertisedSigScheme.into());
    }
    let c = Cert::parse(cert).map_err(|e| tls_err(e.message()))?;
    if !c.verifies(message, dss.signature()) {
        return Err(rustls::Error::InvalidCertificate(rustls::CertificateError::BadSignature));
    }
    Ok(HandshakeSignatureValid::assertion())
}

fn no_tls12() -> Result<HandshakeSignatureValid, rustls::Error> {
    Err(tls_err("members use TLS 1.3 only"))
}

/// One client certificate for every server.
#[derive(Debug)]
struct OneClientCert(Arc<rustls::sign::CertifiedKey>);

impl rustls::client::ResolvesClientCert for OneClientCert {
    fn resolve(&self, _: &[&[u8]], _: &[SignatureScheme]) -> Option<Arc<rustls::sign::CertifiedKey>> {
        Some(self.0.clone())
    }

    fn has_certs(&self) -> bool {
        true
    }
}

fn client_builder(clock: &Clock) -> Result<rustls::ConfigBuilder<rustls::ClientConfig, rustls::WantsVerifier>> {
    rustls::ClientConfig::builder_with_details(Arc::new(provider()), clock.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| Error::with("cannot set up TLS", TlsError(e)))
}

fn server_builder(clock: &Clock) -> Result<rustls::ConfigBuilder<rustls::ServerConfig, rustls::WantsVerifier>> {
    rustls::ServerConfig::builder_with_details(Arc::new(provider()), clock.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| Error::with("cannot set up TLS", TlsError(e)))
}

/// A server known only by the pin of its key: the SHA-256 of its
/// certificate's SubjectPublicKeyInfo (a forwarder's or a relay's).
struct PinVerifier {
    pins: Vec<certs::KeyHash>,
}

impl fmt::Debug for PinVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PinVerifier")
    }
}

impl ServerCertVerifier for PinVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let c = Cert::parse(end_entity).map_err(|e| tls_err(e.message()))?;
        if !self.pins.contains(&c.key_hash()) {
            return Err(tls_err("the server's key is not the one given for it"));
        }
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        no_tls12()
    }

    fn verify_tls13_signature(
        &self,
        m: &[u8],
        c: &CertificateDer<'_>,
        d: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_sig(m, c, d)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![provider::SCHEME]
    }
}

/// The client configuration for a server known only by the pin of its key,
/// a forwarder or a relay (docs/protocol.md, sections 13 and 14): TLS 1.3
/// only, ALPN alpn, and this member's certificate chain with a key kept
/// outside the core, such as a phone's.
pub fn pinned_client(
    chain: Vec<Vec<u8>>,
    key: Arc<dyn crate::identity::ExternalKey>,
    pins: Vec<certs::KeyHash>,
    alpn: &[u8],
    clock: &Clock,
) -> Result<rustls::ClientConfig> {
    if chain.is_empty() {
        return Err(Error::msg("the certificate chain is empty"));
    }
    let chain = chain.into_iter().map(CertificateDer::from).collect();
    let signer: Arc<dyn rustls::sign::SigningKey> = Arc::new(provider::ExternalSigningKey(key));
    let certified = Arc::new(rustls::sign::CertifiedKey::new(chain, signer));
    let mut cfg = client_builder(clock)?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PinVerifier { pins }))
        .with_client_cert_resolver(Arc::new(OneClientCert(certified)));
    cfg.alpn_protocols = vec![alpn.to_vec()];
    cfg.resumption = rustls::client::Resumption::disabled();
    Ok(cfg)
}

/// Takes any certificate of the peer that signed the handshake with its
/// key: the joiner checks the member through the CPace exchange and the
/// Welcome instead.
#[derive(Debug)]
struct AnyPeer;

impl ServerCertVerifier for AnyPeer {
    fn verify_server_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        no_tls12()
    }

    fn verify_tls13_signature(
        &self,
        m: &[u8],
        c: &CertificateDer<'_>,
        d: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_sig(m, c, d)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![provider::SCHEME]
    }
}

impl ClientCertVerifier for AnyPeer {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        no_tls12()
    }

    fn verify_tls13_signature(
        &self,
        m: &[u8],
        c: &CertificateDer<'_>,
        d: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_sig(m, c, d)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![provider::SCHEME]
    }
}

fn pair_identity(cert: &[u8], key: &[u8]) -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
    (vec![CertificateDer::from(cert.to_vec())], PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.to_vec())))
}

/// The joiner's server configuration, for a member that dials it: TLS 1.3,
/// ALPN cbb-pair/3, its self-signed certificate, any client
/// certificate required, no session tickets. Use a new one for each
/// connection: its Exporter gives the pairing's sid.
pub fn pair_server(cert: &[u8], key: &[u8], clock: &Clock) -> Result<(rustls::ServerConfig, Arc<Exporter>)> {
    let (chain, key) = pair_identity(cert, key);
    let mut cfg = server_builder(clock)?
        .with_client_cert_verifier(Arc::new(AnyPeer))
        .with_single_cert(chain, key)
        .map_err(|e| Error::with("cannot use the pairing certificate", TlsError(e)))?;
    cfg.alpn_protocols = alpn::offer(alpn::PAIRS);
    cfg.send_tls13_tickets = 0;
    let exporter = Arc::new(Exporter::default());
    cfg.key_log = exporter.clone();
    Ok((cfg, exporter))
}

/// A blind relay's server configuration for the registrations
/// (docs/protocol.md, section 14): TLS 1.3, ALPN protocol, its certificate
/// with its PKCS #8 key, any client certificate required, which the relay
/// checks itself, and no session tickets.
pub fn registration_server(cert: &[u8], key: &[u8], protocol: &[u8], clock: &Clock) -> Result<rustls::ServerConfig> {
    let (chain, key) = pair_identity(cert, key);
    let mut cfg = server_builder(clock)?
        .with_client_cert_verifier(Arc::new(AnyPeer))
        .with_single_cert(chain, key)
        .map_err(|e| Error::with("cannot use the relay's certificate", TlsError(e)))?;
    cfg.alpn_protocols = vec![protocol.to_vec()];
    cfg.send_tls13_tickets = 0;
    Ok(cfg)
}

/// One certificate for every connection.
#[derive(Debug)]
struct OneCert(Arc<rustls::sign::CertifiedKey>);

impl rustls::server::ResolvesServerCert for OneCert {
    fn resolve(&self, _: rustls::server::ClientHello<'_>) -> Option<Arc<rustls::sign::CertifiedKey>> {
        Some(self.0.clone())
    }
}

/// The joiner's client configuration, for dialing a member's open pairing
/// window. Use a new one for each connection: its Exporter gives the
/// pairing's sid.
pub fn pair_client(cert: &[u8], key: &[u8], clock: &Clock) -> Result<(rustls::ClientConfig, Arc<Exporter>)> {
    let (chain, key) = pair_identity(cert, key);
    let mut cfg = client_builder(clock)?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AnyPeer))
        .with_client_auth_cert(chain, key)
        .map_err(|e| Error::with("cannot use the pairing certificate", TlsError(e)))?;
    cfg.alpn_protocols = alpn::offer(alpn::PAIRS);
    cfg.resumption = rustls::client::Resumption::disabled();
    let exporter = Arc::new(Exporter::default());
    cfg.key_log = exporter.clone();
    Ok((cfg, exporter))
}

/// A server name for the TLS client: the peer's host name, or a fixed one
/// for an address given by hand (members do not look at it).
#[allow(clippy::expect_used, reason = "a fixed, valid DNS name")]
pub fn server_name(peer: Option<&DeviceId>) -> ServerName<'static> {
    let fallback = || ServerName::try_from("cbb.invalid").expect("a valid DNS name");
    match peer {
        Some(p) => ServerName::try_from(p.host_name()).unwrap_or_else(|_| fallback()),
        None => fallback(),
    }
}

#[cfg(test)]
mod tests;
