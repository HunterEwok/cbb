// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The sans-I/O session and the exporter, both ends in memory, against
//! rustls's own buffered connections and exporter.

use std::sync::Arc;

use rustls::pki_types::UnixTime;
use rustls::time_provider::TimeProvider;

use super::*;
use crate::certs::{DeviceId, self_signed};
use crate::identity::{new_key, signing_key};

#[derive(Debug)]
struct SystemClock;

impl TimeProvider for SystemClock {
    fn current_time(&self) -> Option<UnixTime> {
        Some(UnixTime::now())
    }
}

fn clock() -> Clock {
    Arc::new(SystemClock)
}

/// A device's self-signed pairing certificate and its key.
fn device() -> (Vec<u8>, Vec<u8>) {
    let key = new_key().unwrap();
    let cert = self_signed(&DeviceId::random(), &signing_key(&key).unwrap()).unwrap();
    (cert, key)
}

/// Moves the bytes between two sessions until neither has any to send.
fn shuttle(a: &mut Session, b: &mut Session) {
    loop {
        let (x, y) = (a.take_outgoing(), b.take_outgoing());
        if x.is_empty() && y.is_empty() {
            return;
        }
        b.feed(&x).unwrap();
        a.feed(&y).unwrap();
    }
}

fn read_all(s: &mut Session) -> Vec<u8> {
    let mut out = Vec::new();
    let mut buf = [0u8; 1000];
    loop {
        let n = s.read(&mut buf);
        if n == 0 {
            return out;
        }
        out.extend_from_slice(&buf[..n]);
    }
}

fn pair_sessions() -> (Session, Arc<Exporter>, Session, Arc<Exporter>) {
    let ((jc, jk), (mc, mk)) = (device(), device());
    let (scfg, sx) = pair_server(&jc, &jk, &clock()).unwrap();
    let (ccfg, cx) = pair_client(&mc, &mk, &clock()).unwrap();
    let client = Session::client(Arc::new(ccfg), server_name(None)).unwrap();
    let server = Session::server(Arc::new(scfg)).unwrap();
    (client, cx, server, sx)
}

#[test]
fn handshake_data_and_close() {
    let (mut c, cx, mut s, sx) = pair_sessions();
    assert!(c.wants_write(), "the client hello is queued at once");
    assert!(c.write(b"early").is_err(), "no data before the handshake");
    shuttle(&mut c, &mut s);
    assert!(!c.is_handshaking() && !s.is_handshaking());
    assert_eq!(c.alpn_protocol(), Some(PAIR_PROTOCOL));
    assert_eq!(s.protocol_version(), Some(rustls::ProtocolVersion::TLSv1_3));
    assert_eq!(s.peer_certificates().map(|c| c.len()), Some(1), "the client certificate");

    // Both ends derive the same sid.
    let (mut a, mut b) = ([0u8; 32], [0u8; 32]);
    cx.export(b"EXPERIMENTAL-cbb-pair-v2", &[], &mut a).unwrap();
    sx.export(b"EXPERIMENTAL-cbb-pair-v2", &[], &mut b).unwrap();
    assert_eq!(a, b);
    assert_ne!(a, [0u8; 32]);

    // Small and large writes (more than one record) both ways.
    let big: Vec<u8> = (0..100_000u32).map(|i| i as u8).collect();
    c.write(b"hello").unwrap();
    c.write(&big).unwrap();
    s.write(b"welcome").unwrap();
    shuttle(&mut c, &mut s);
    let got = read_all(&mut s);
    assert_eq!(&got[..5], b"hello");
    assert_eq!(&got[5..], &big[..]);
    assert_eq!(read_all(&mut c), b"welcome");

    // Bytes that arrive one at a time.
    s.write(b"slowly").unwrap();
    for byte in s.take_outgoing() {
        c.feed(&[byte]).unwrap();
    }
    assert_eq!(read_all(&mut c), b"slowly");

    c.close().unwrap();
    shuttle(&mut c, &mut s);
    assert!(s.peer_closed());
    assert!(!c.peer_closed());
}

/// The exporter from the key log matches rustls's own, for the server
/// and the client side and for any length and context.
#[test]
fn exporter_matches_rustls() {
    let ((jc, jk), (mc, mk)) = (device(), device());
    let (scfg, sx) = pair_server(&jc, &jk, &clock()).unwrap();
    let (ccfg, cx) = pair_client(&mc, &mk, &clock()).unwrap();
    let mut client = rustls::ClientConnection::new(Arc::new(ccfg), server_name(None)).unwrap();
    let mut server = rustls::ServerConnection::new(Arc::new(scfg)).unwrap();
    while client.is_handshaking() || server.is_handshaking() || client.wants_write() || server.wants_write() {
        let mut buf = Vec::new();
        client.write_tls(&mut buf).unwrap();
        server.read_tls(&mut &buf[..]).unwrap();
        server.process_new_packets().unwrap();
        let mut buf = Vec::new();
        server.write_tls(&mut buf).unwrap();
        client.read_tls(&mut &buf[..]).unwrap();
        client.process_new_packets().unwrap();
    }
    for (label, context, len) in [(&b"EXPERIMENTAL-cbb-pair-v2"[..], &b""[..], 32), (b"another", b"with a context", 77)]
    {
        let want = client.export_keying_material(vec![0u8; len], label, Some(context)).unwrap();
        assert_eq!(want, server.export_keying_material(vec![0u8; len], label, Some(context)).unwrap());
        let (mut a, mut b) = (vec![0u8; len], vec![0u8; len]);
        cx.export(label, context, &mut a).unwrap();
        sx.export(label, context, &mut b).unwrap();
        assert_eq!(a, want);
        assert_eq!(b, want);
    }
}

#[test]
fn exporter_needs_a_handshake() {
    let (_, cx, _, _) = pair_sessions();
    assert!(cx.export(b"x", &[], &mut [0u8; 32]).is_err());
}

/// A peer that does not speak TLS fails the session, and the failure
/// stays.
#[test]
fn garbage_fails() {
    let (_, _, mut s, _) = pair_sessions();
    assert!(s.feed(b"GET / HTTP/1.1\r\n\r\n").is_err());
    assert!(s.feed(b"").is_err());
    assert!(s.write(b"x").is_err());
}

/// A client that offers only other ALPN protocols is refused, and told
/// so with an alert.
#[test]
fn wrong_protocol_fails() {
    let ((jc, jk), (mc, mk)) = (device(), device());
    let (scfg, _) = pair_server(&jc, &jk, &clock()).unwrap();
    let (mut ccfg, _) = pair_client(&mc, &mk, &clock()).unwrap();
    ccfg.alpn_protocols = vec![MEMBER_PROTOCOL.to_vec()];
    let mut c = Session::client(Arc::new(ccfg), server_name(None)).unwrap();
    let mut s = Session::server(Arc::new(scfg)).unwrap();
    assert!(s.feed(&c.take_outgoing()).is_err());
    // The alert follows the server hello, encrypted; the client learns why.
    let err = c.feed(&s.take_outgoing()).unwrap_err();
    assert!(err.details().contains("NoApplicationProtocol"), "{}", err.details());
}

/// Both cipher suites work, whichever the client prefers.
#[test]
fn both_cipher_suites() {
    for suite in provider().cipher_suites {
        let ((jc, jk), (mc, mk)) = (device(), device());
        let (scfg, _) = pair_server(&jc, &jk, &clock()).unwrap();
        let mut p = provider();
        p.cipher_suites = vec![suite];
        let ccfg = rustls::ClientConfig::builder_with_details(Arc::new(p), clock())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AnyPeer))
            .with_client_auth_cert(vec![CertificateDer::from(mc)], PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(mk)))
            .unwrap();
        let mut ccfg = ccfg;
        ccfg.alpn_protocols = vec![PAIR_PROTOCOL.to_vec()];
        let mut c = Session::client(Arc::new(ccfg), server_name(None)).unwrap();
        let mut s = Session::server(Arc::new(scfg)).unwrap();
        shuttle(&mut c, &mut s);
        c.write(b"ping").unwrap();
        shuttle(&mut c, &mut s);
        assert_eq!(read_all(&mut s), b"ping", "{:?}", suite.suite());
    }
}

/// A server that refuses every client certificate, as a member refuses a
/// device of another group.
#[derive(Debug)]
struct NoPeer;

impl rustls::server::danger::ClientCertVerifier for NoPeer {
    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        _: &rustls::pki_types::CertificateDer<'_>,
        _: &[rustls::pki_types::CertificateDer<'_>],
        _: rustls::pki_types::UnixTime,
    ) -> Result<rustls::server::danger::ClientCertVerified, rustls::Error> {
        Err(rustls::Error::InvalidCertificate(rustls::CertificateError::UnknownIssuer))
    }

    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &rustls::pki_types::CertificateDer<'_>,
        _: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::General("no TLS 1.2".into()))
    }

    fn verify_tls13_signature(
        &self,
        _: &[u8],
        _: &rustls::pki_types::CertificateDer<'_>,
        _: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![super::provider::SCHEME]
    }
}

/// A client certificate the server refuses ends the handshake with an
/// error and an alert, never a panic: the alert's flush handed rustls an
/// empty buffer while it still pointed into the client's flight, and a
/// device of another group that dialed a member brought its process down.
#[test]
fn a_refused_client_certificate_fails_without_a_panic() {
    let ((jc, jk), (mc, mk)) = (device(), device());
    let (chain, key) = super::pair_identity(&jc, &jk);
    let mut scfg = super::server_builder(&clock())
        .unwrap()
        .with_client_cert_verifier(Arc::new(NoPeer))
        .with_single_cert(chain, key)
        .unwrap();
    scfg.alpn_protocols = vec![PAIR_PROTOCOL.to_vec()];
    let (ccfg, _) = pair_client(&mc, &mk, &clock()).unwrap();
    let mut c = Session::client(Arc::new(ccfg), server_name(None)).unwrap();
    let mut s = Session::server(Arc::new(scfg)).unwrap();
    s.feed(&c.take_outgoing()).unwrap();
    c.feed(&s.take_outgoing()).unwrap();
    // The client's flight in pieces, as TCP may bring it: the server keeps
    // part of it when it refuses the certificate.
    let flight = c.take_outgoing();
    let mut refused = false;
    for piece in flight.chunks(40) {
        if s.feed(piece).is_err() {
            refused = true;
            break;
        }
    }
    assert!(refused, "the server took a certificate it refuses");
    assert!(!s.take_outgoing().is_empty(), "the server tells the client why");
    assert!(s.feed(b"more").is_err(), "a failed session stays failed");
}
