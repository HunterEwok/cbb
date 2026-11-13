// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The parts, each behind its feature. Their input comes through black_box,
//! so the compiler keeps every path of the code they call.

extern crate alloc;

use alloc::vec::Vec;
use core::hint::black_box;

static INPUT: [u8; 64] = [1; 64];

fn input() -> &'static [u8] {
    black_box(&INPUT[..])
}

/// Runs every part this program was built with.
pub fn run() {
    #[cfg(feature = "p256")]
    p256();
    #[cfg(feature = "json")]
    json();
    #[cfg(feature = "records")]
    records();
    #[cfg(feature = "seal")]
    seal();
    #[cfg(feature = "copy")]
    copy();
    #[cfg(feature = "pair")]
    pair();
    #[cfg(feature = "tls")]
    tls();
    #[cfg(feature = "api")]
    black_box(cbb_core::api::call(input()));
    black_box(Vec::<u8>::with_capacity(input().len()));
}

/// X.509 and P-256: a member certificate chain checked against a root.
#[cfg(feature = "p256")]
fn p256() {
    use cbb_core::certs::{Cert, Usage, verify_member};
    if let Ok(c) = Cert::parse(input()) {
        black_box(verify_member(core::slice::from_ref(&c), core::slice::from_ref(&c), 0, Usage::Client).is_ok());
    }
}

/// JSON, as the protocol's messages and records are written today.
#[cfg(feature = "json")]
fn json() {
    black_box(serde_json::from_slice::<serde_json::Value>(input()).is_ok());
}

/// The group's records: a record taken in and the group's state and devices.
#[cfg(feature = "records")]
fn records() {
    use cbb_core::authority::Record;
    use cbb_core::certs::Cert;
    use cbb_core::group::Records;
    if let Ok(ca) = Cert::parse(input()) {
        let mut r = Records::new(&ca);
        black_box(r.add(&Record::new(input().to_vec(), input().to_vec(), None)).is_ok());
        black_box(r.state());
        black_box(r.devices());
    }
}

/// Opening a message sealed to this device: X-Wing, HKDF, ChaCha20-Poly1305.
#[cfg(feature = "seal")]
fn seal() {
    black_box(cbb_core::seal::open(input(), input(), input()).is_ok());
}

/// A copy as it arrives: read, its signer checked on the records, opened.
#[cfg(feature = "copy")]
fn copy() {
    use cbb_core::certs::Cert;
    use cbb_core::copy::Sealed;
    use cbb_core::group::Records;
    if let (Ok(s), Ok(ca)) = (serde_json::from_slice::<Sealed>(input()), Cert::parse(input())) {
        black_box(s.check(&Records::new(&ca), 0).is_ok());
        black_box(s.open("0123456789abcdef0123456789abcdef", input()).is_ok());
    }
}

/// Joining a group: a joiner's key and certificate and the CPace exchange.
#[cfg(feature = "pair")]
fn pair() {
    if let Ok(j) = cbb_core::pair::Joiner::new("board") {
        black_box(j.start("123456", input(), input(), true).is_ok());
    }
}

/// The member TLS: a client and a server session and a handshake's bytes.
#[cfg(feature = "tls")]
fn tls() {
    use alloc::sync::Arc;
    use cbb_core::certs::{Cert, DeviceId};
    use cbb_core::identity::Identity;
    use cbb_core::tls::{self, Session};

    #[derive(Debug)]
    struct Never;
    impl rustls::time_provider::TimeProvider for Never {
        fn current_time(&self) -> Option<rustls::pki_types::UnixTime> {
            black_box(None)
        }
    }

    let (Ok(cert), Ok(id)) = (Cert::parse(input()), DeviceId::parse("0123456789abcdef0123456789abcdef")) else {
        return;
    };
    let me = Identity {
        id,
        key: input().to_vec(),
        external: None,
        cert: cert.clone(),
        issuer: None,
        group_ca: cert,
        roots: Vec::new(),
    };
    let clock: tls::Clock = Arc::new(Never);
    let refused: tls::Refused = Arc::new(|_| None);
    if let Ok(cfg) = tls::member_client(&me, None, refused.clone(), &clock)
        && let Ok(mut s) = Session::client(Arc::new(cfg), tls::server_name(None))
    {
        black_box(s.feed(input()).is_ok());
        black_box(s.write(input()).is_ok());
        black_box(s.take_outgoing());
    }
    if let Ok(cfg) = tls::member_server(&me, refused, &clock)
        && let Ok(mut s) = Session::server(Arc::new(cfg))
    {
        black_box(s.feed(input()).is_ok());
        black_box(s.take_outgoing());
    }
}
