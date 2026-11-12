// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! A member's side of the project's push service (format section 20.4,
//! src/pushd): the connection that asks the service to wake a phone. It
//! dials the service's pinned key with the certificate of its server key
//! for the service's face, says hello with the face's hubs' and members'
//! credentials, and sends sealed bodies, one answer for each.

use std::net::{SocketAddr, TcpStream};
use std::sync::Arc;
use std::time::Duration;

use cbb_core::format::frame;
use cbb_core::identity::ExternalKey;
use cbb_core::push;
use p256::ecdsa::SigningKey;
use rustls::{ClientConnection, StreamOwned};

use crate::error::{Context, Error, Result};

const TIMEOUT: Duration = Duration::from_secs(15);
const MAX_FRAME: usize = 16_384;

/// A server key for a face, from its scalar (`blind::alias::server_key`).
pub struct ServerKey(SigningKey);

impl ServerKey {
    pub fn from_scalar(d: &[u8; 32]) -> Result<ServerKey> {
        SigningKey::from_slice(d).map(ServerKey).map_err(|_| Error::msg("not a P-256 scalar"))
    }

    /// Its self-signed certificate, which the service reads the key from.
    pub fn cert(&self) -> Result<Vec<u8>> {
        use p256::ecdsa::{Signature, signature::Signer};
        let point = self.public();
        cbb_core::certs::server_cert_by(&point, &mut |tbs| {
            let sig: Signature = self.0.sign(tbs);
            Ok(sig.to_der().as_bytes().to_vec())
        })
    }
}

impl ExternalKey for ServerKey {
    fn public(&self) -> Vec<u8> {
        self.0.verifying_key().to_sec1_point(false).as_bytes().to_vec()
    }

    fn sign_digest(&self, digest: &[u8; 32]) -> cbb_core::error::Result<Vec<u8>> {
        use p256::ecdsa::signature::hazmat::PrehashSigner as _;
        let sig: p256::ecdsa::Signature =
            self.0.sign_prehash(digest).map_err(|_| cbb_core::error::Error::msg("cannot sign with the server key"))?;
        Ok(sig.to_der().as_bytes().to_vec())
    }
}

/// A connection to the push service, its hello answered.
pub struct Client {
    tls: StreamOwned<ClientConnection, TcpStream>,
    next: u64,
    /// Sends left this hour for the face's tag, as the service said.
    pub left: u64,
}

/// The service's answer to one send.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Sent {
    /// `push::SENT` …, an unknown status read as failed.
    pub status: u64,
    pub retry_ms: Option<u64>,
}

fn read_frame(s: &mut impl std::io::Read) -> Result<Vec<u8>> {
    let mut h = [0u8; 4];
    s.read_exact(&mut h).context("the push service closed the connection")?;
    let n = frame::length(h, MAX_FRAME)
        .map_err(|r| Error::msg(format!("the push service sent a bad frame ({})", r.name())))?;
    let mut f = vec![0u8; n + 4];
    f[..4].copy_from_slice(&h);
    s.read_exact(&mut f[4..]).context("the push service closed the connection")?;
    Ok(f)
}

impl Client {
    /// Dials the service at addr whose key has `pin`, as `key`, and says
    /// hello with the face's credentials (hubs', members').
    pub fn connect(addr: SocketAddr, pin: [u8; 32], key: Arc<ServerKey>, credentials: &[&[u8]]) -> Result<Client> {
        use std::io::Write;
        let cert = key.cert()?;
        let clock: cbb_core::tls::Clock = Arc::new(crate::forward::SystemClock);
        let cfg = cbb_core::tls::pinned_client(vec![cert], key, vec![pin], push::ALPN, &clock)?;
        let tcp = TcpStream::connect_timeout(&addr, TIMEOUT).context("cannot reach the push service")?;
        tcp.set_read_timeout(Some(TIMEOUT)).context("cannot set a timeout")?;
        tcp.set_write_timeout(Some(TIMEOUT)).context("cannot set a timeout")?;
        let conn = ClientConnection::new(Arc::new(cfg), cbb_core::tls::server_name(None))
            .context("cannot start TLS to the push service")?;
        let mut tls = StreamOwned::new(conn, tcp);
        while tls.conn.is_handshaking() {
            tls.conn.complete_io(&mut tls.sock).context("TLS to the push service failed")?;
        }
        let hello = push::hello(credentials)
            .map_err(|r| Error::msg(format!("a credential is not in the profile ({})", r.name())))?;
        tls.write_all(&hello).and_then(|()| tls.flush()).context("cannot write to the push service")?;
        let f = read_frame(&mut tls)?;
        let m = frame::read(&f, MAX_FRAME).map_err(|r| Error::msg(r.name()))?;
        match m.t {
            push::T_READY => {
                let left = m.map.get(2).and_then(cbb_core::format::Value::as_uint).unwrap_or(0);
                Ok(Client { tls, next: 1, left })
            }
            push::T_ERROR => {
                let why = m.map.get(2).and_then(cbb_core::format::Value::as_text).unwrap_or("refused");
                Err(Error::msg(format!("the push service refused: {why}")))
            }
            _ => Err(Error::msg("the push service answered something else")),
        }
    }

    /// Asks the service to pass one sealed body to a token.
    pub fn send(&mut self, token: &[u8], env: u64, once: [u8; 16], body: &[u8], ttl: Option<u64>) -> Result<Sent> {
        use std::io::Write;
        let n = self.next;
        self.next = if n >= u64::from(u32::MAX) { 1 } else { n + 1 };
        let f = push::Send { n, token, env, once, body, ttl }.write();
        self.tls.write_all(&f).and_then(|()| self.tls.flush()).context("cannot write to the push service")?;
        loop {
            let f = read_frame(&mut self.tls)?;
            let m = frame::read(&f, MAX_FRAME).map_err(|r| Error::msg(r.name()))?;
            match m.t {
                push::T_SENT if m.map.get(2).and_then(cbb_core::format::Value::as_uint) == Some(n) => {
                    let status = push::status(m.map.get(3).and_then(cbb_core::format::Value::as_uint).unwrap_or(0));
                    let retry_ms = m.map.get(4).and_then(cbb_core::format::Value::as_uint);
                    return Ok(Sent { status, retry_ms });
                }
                push::T_ERROR => {
                    let why = m.map.get(2).and_then(cbb_core::format::Value::as_text).unwrap_or("refused");
                    return Err(Error::msg(format!("the push service refused: {why}")));
                }
                _ => {}
            }
        }
    }
}
