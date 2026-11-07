// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The TLS of member connections and pairing (docs/protocol.md, sections 4
//! and 6) on rustls, without an operating system: the crypto provider
//! (provider.rs), the configurations with this crate's own peer checks,
//! which follow Go's rules exactly (the chain to a root of the group at
//! max(now, the root's start), through at most one admin CA, and the
//! records' revocations), a connection without I/O (session.rs) and the
//! pairing exporter (exporter.rs).
//!
//! rustls takes the time from the TimeProvider each configuration is
//! given: the system clock on Linux, the clock a microcontroller set from
//! the network.

mod exporter;
mod provider;
mod session;
#[cfg(feature = "web")]
pub mod web;

use alloc::format;
use alloc::string::{String, ToString};
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

use crate::certs::{self, Cert, DeviceId, Usage};
use crate::error::{Error, Result};
use crate::identity::Identity;

/// The ALPN protocol of member connections.
pub const MEMBER_PROTOCOL: &[u8] = b"cbb/3";
/// The ALPN protocol of pairing connections.
pub const PAIR_PROTOCOL: &[u8] = b"cbb-pair/2";

/// The clock of the TLS configurations.
pub type Clock = Arc<dyn TimeProvider>;

/// Says why the records refuse a member chain (leaf, then its issuer), or
/// None when they take it: the caller's records under its own lock.
pub type Refused = Arc<dyn Fn(&[Cert]) -> Option<String> + Send + Sync>;

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

fn secs(t: UnixTime) -> i64 {
    t.as_secs() as i64
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

/// Checks a member chain as Go's checkPeer does at time now (Unix
/// seconds), and returns the device and the chain the records judged.
/// usage is the side the peer is on: Server for a member this one dialed.
pub fn check_member(
    chain: &[CertificateDer<'_>],
    trusted: &[Cert],
    root_start: i64,
    refused: &Refused,
    usage: Usage,
    now: i64,
) -> Result<(DeviceId, Vec<Cert>)> {
    let certs = chain.iter().map(|c| Cert::parse(c)).collect::<Result<Vec<_>>>()?;
    let (dev, used) = certs::member_chain(certs, trusted, now.max(root_start), usage)?;
    if let Some(why) = refused(&used) {
        return Err(Error::msg(why));
    }
    Ok((dev, used))
}

/// Checks the member that this member dialed.
struct MemberVerifier {
    self_id: DeviceId,
    peer: Option<DeviceId>, // the device discovery found; None for an address given by hand
    trusted: Vec<Cert>,
    root_start: i64,
    refused: Refused,
}

impl fmt::Debug for MemberVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MemberVerifier")
    }
}

impl ServerCertVerifier for MemberVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let mut chain = vec![end_entity.clone()];
        chain.extend(intermediates.iter().cloned());
        let (dev, _) = check_member(&chain, &self.trusted, self.root_start, &self.refused, Usage::Server, secs(now))
            .map_err(|e| tls_err(e.message()))?;
        if dev == self.self_id {
            return Err(tls_err("connected to itself"));
        }
        if let Some(want) = &self.peer {
            if &dev != want {
                return Err(tls_err(&format!("reached {dev} instead of {want}")));
            }
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

/// This member's certificate chain with its key, the core's own or one
/// kept outside it (Identity::external).
fn member_certified(id: &Identity) -> Result<Arc<rustls::sign::CertifiedKey>> {
    let chain = id.chain().into_iter().map(CertificateDer::from).collect();
    let signer: Arc<dyn rustls::sign::SigningKey> = match &id.external {
        Some(k) => Arc::new(provider::ExternalSigningKey(k.clone())),
        None => provider()
            .key_provider
            .load_private_key(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(id.key.clone())))
            .map_err(|e| Error::with("cannot use the member certificate", TlsError(e)))?,
    };
    Ok(Arc::new(rustls::sign::CertifiedKey::new(chain, signer)))
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

/// The client configuration for dialing a member: TLS 1.3 only, ALPN
/// cbb/3, this member's certificate with its issuer, and the
/// server checked against the group's roots and records. peer is the
/// device that discovery found, when known.
pub fn member_client(
    id: &Identity,
    peer: Option<DeviceId>,
    refused: Refused,
    clock: &Clock,
) -> Result<rustls::ClientConfig> {
    let verifier = MemberVerifier {
        self_id: id.id.clone(),
        peer,
        trusted: id.trusted(),
        root_start: id.root().not_before,
        refused,
    };
    let certified = member_certified(id)?;
    let mut cfg = client_builder(clock)?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_client_cert_resolver(Arc::new(OneClientCert(certified)));
    cfg.alpn_protocols = vec![MEMBER_PROTOCOL.to_vec()];
    cfg.resumption = rustls::client::Resumption::disabled();
    Ok(cfg)
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

/// Checks a member that dialed this one.
struct MemberClientVerifier {
    self_id: DeviceId,
    trusted: Vec<Cert>,
    root_start: i64,
    refused: Refused,
}

impl fmt::Debug for MemberClientVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MemberClientVerifier")
    }
}

impl ClientCertVerifier for MemberClientVerifier {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        let mut chain = vec![end_entity.clone()];
        chain.extend(intermediates.iter().cloned());
        let (dev, _) = check_member(&chain, &self.trusted, self.root_start, &self.refused, Usage::Client, secs(now))
            .map_err(|e| tls_err(e.message()))?;
        if dev == self.self_id {
            return Err(tls_err("connected to itself"));
        }
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

/// The server configuration for members that dial this one (phones, Macs
/// and lite members with a lower device ID): TLS 1.3 only, ALPN
/// cbb/3, this member's certificate with its issuer, a client
/// certificate of the group required, no session tickets.
pub fn member_server(id: &Identity, refused: Refused, clock: &Clock) -> Result<rustls::ServerConfig> {
    let verifier = MemberClientVerifier {
        self_id: id.id.clone(),
        trusted: id.trusted(),
        root_start: id.root().not_before,
        refused,
    };
    let certified = member_certified(id)?;
    let mut cfg = server_builder(clock)?
        .with_client_cert_verifier(Arc::new(verifier))
        .with_cert_resolver(Arc::new(OneCert(certified)));
    cfg.alpn_protocols = vec![MEMBER_PROTOCOL.to_vec()];
    cfg.send_tls13_tickets = 0;
    Ok(cfg)
}

/// Checks a client of the member port while it may be a joiner: a member
/// of the group, or one certificate with a P-256 key, which the pairing
/// exchange authenticates. Which of the two it must be follows from the
/// ALPN protocol, which the program checks after the handshake, with the
/// member's chain checked again (check_member).
struct MemberOrJoiner(MemberClientVerifier);

impl fmt::Debug for MemberOrJoiner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MemberOrJoiner")
    }
}

impl ClientCertVerifier for MemberOrJoiner {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        let member = self.0.verify_client_cert(end_entity, intermediates, now);
        if member.is_ok() || !intermediates.is_empty() {
            return member;
        }
        match Cert::parse(end_entity) {
            Ok(c) if c.p256 => Ok(ClientCertVerified::assertion()),
            _ => member,
        }
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

/// The server configuration of an admin's member port, which takes
/// joiners too, as Go's member port does: member_server's, with the ALPN
/// protocols cbb/3 and cbb-pair/2 and any single P-256 certificate taken
/// as a joiner's. The program checks the negotiated protocol after the
/// handshake: a member's chain again with check_member, a joiner through
/// the pairing exchange (admit::Admission::accept), whose sid the Exporter
/// gives. Use a new one for each connection.
pub fn member_or_pair_server(
    id: &Identity,
    refused: Refused,
    clock: &Clock,
) -> Result<(rustls::ServerConfig, Arc<Exporter>)> {
    let verifier = MemberOrJoiner(MemberClientVerifier {
        self_id: id.id.clone(),
        trusted: id.trusted(),
        root_start: id.root().not_before,
        refused,
    });
    let certified = member_certified(id)?;
    let mut cfg = server_builder(clock)?
        .with_client_cert_verifier(Arc::new(verifier))
        .with_cert_resolver(Arc::new(OneCert(certified)));
    cfg.alpn_protocols = vec![MEMBER_PROTOCOL.to_vec(), PAIR_PROTOCOL.to_vec()];
    cfg.send_tls13_tickets = 0;
    let exporter = Arc::new(Exporter::default());
    cfg.key_log = exporter.clone();
    Ok((cfg, exporter))
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
/// ALPN cbb-pair/2, its self-signed certificate, any client
/// certificate required, no session tickets. Use a new one for each
/// connection: its Exporter gives the pairing's sid.
pub fn pair_server(cert: &[u8], key: &[u8], clock: &Clock) -> Result<(rustls::ServerConfig, Arc<Exporter>)> {
    let (chain, key) = pair_identity(cert, key);
    let mut cfg = server_builder(clock)?
        .with_client_cert_verifier(Arc::new(AnyPeer))
        .with_single_cert(chain, key)
        .map_err(|e| Error::with("cannot use the pairing certificate", TlsError(e)))?;
    cfg.alpn_protocols = vec![PAIR_PROTOCOL.to_vec()];
    cfg.send_tls13_tickets = 0;
    let exporter = Arc::new(Exporter::default());
    cfg.key_log = exporter.clone();
    Ok((cfg, exporter))
}

/// The joiner's server configuration of pair_server for a device key the
/// core does not hold: key signs the handshake.
pub fn pair_server_external(
    cert: &[u8],
    key: Arc<dyn crate::identity::ExternalKey>,
    clock: &Clock,
) -> Result<(rustls::ServerConfig, Arc<Exporter>)> {
    let signer: Arc<dyn rustls::sign::SigningKey> = Arc::new(provider::ExternalSigningKey(key));
    let certified = Arc::new(rustls::sign::CertifiedKey::new(vec![CertificateDer::from(cert.to_vec())], signer));
    let mut cfg = server_builder(clock)?
        .with_client_cert_verifier(Arc::new(AnyPeer))
        .with_cert_resolver(Arc::new(OneCert(certified)));
    cfg.alpn_protocols = vec![PAIR_PROTOCOL.to_vec()];
    cfg.send_tls13_tickets = 0;
    let exporter = Arc::new(Exporter::default());
    cfg.key_log = exporter.clone();
    Ok((cfg, exporter))
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
    cfg.alpn_protocols = vec![PAIR_PROTOCOL.to_vec()];
    cfg.resumption = rustls::client::Resumption::disabled();
    let exporter = Arc::new(Exporter::default());
    cfg.key_log = exporter.clone();
    Ok((cfg, exporter))
}

/// The joiner's client configuration of pair_client for a device key the
/// core does not hold: key signs the handshake.
pub fn pair_client_external(
    cert: &[u8],
    key: Arc<dyn crate::identity::ExternalKey>,
    clock: &Clock,
) -> Result<(rustls::ClientConfig, Arc<Exporter>)> {
    let signer: Arc<dyn rustls::sign::SigningKey> = Arc::new(provider::ExternalSigningKey(key));
    let certified = Arc::new(rustls::sign::CertifiedKey::new(vec![CertificateDer::from(cert.to_vec())], signer));
    let mut cfg = client_builder(clock)?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AnyPeer))
        .with_client_cert_resolver(Arc::new(OneClientCert(certified)));
    cfg.alpn_protocols = vec![PAIR_PROTOCOL.to_vec()];
    cfg.resumption = rustls::client::Resumption::disabled();
    let exporter = Arc::new(Exporter::default());
    cfg.key_log = exporter.clone();
    Ok((cfg, exporter))
}

/// The client configuration of a member that dials a joiner which listens
/// and showed its QR code, to admit it: this member's certificate with its
/// issuer, wherever its key is, and any server certificate, which the
/// program checks against the QR code's fingerprint once the handshake is
/// done. Use a new one for each connection: its Exporter gives the
/// pairing's sid.
pub fn pair_admitter(id: &Identity, clock: &Clock) -> Result<(rustls::ClientConfig, Arc<Exporter>)> {
    let certified = member_certified(id)?;
    let mut cfg = client_builder(clock)?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AnyPeer))
        .with_client_cert_resolver(Arc::new(OneClientCert(certified)));
    cfg.alpn_protocols = vec![PAIR_PROTOCOL.to_vec()];
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
