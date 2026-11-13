// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! A member's side of the project's push service (format section 20.4,
//! src/pushd): the connection that asks the service to wake a phone. It
//! dials the service's pinned key with the certificate of its server key
//! for the service's face, says hello with the face's hubs' and members'
//! credentials, and sends sealed bodies, one answer for each.

use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::Arc;
use std::time::{Duration, Instant};

use cbb_core::format::frame;
use cbb_core::identity::ExternalKey;
use cbb_core::push;
use p256::ecdsa::SigningKey;
use rustls::{ClientConnection, StreamOwned};

use crate::error::{Context, Error, Result};

const TIMEOUT: Duration = Duration::from_secs(15);
/// How long a send waits for its own answer in all, whatever else the
/// service sends meanwhile; then the connection is given up.
#[cfg(not(test))]
pub const ANSWER_WITHIN: Duration = Duration::from_secs(30);
/// Short in tests, so that a service that never answers is shown quickly.
#[cfg(test)]
pub const ANSWER_WITHIN: Duration = Duration::from_secs(3);
const MAX_FRAME: usize = push::MAX_SERVICE_FRAME;

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

/// The socket under the TLS, with a deadline: every read and write waits
/// at most what is left of it (and at most [`TIMEOUT`]), and none starts
/// once it has passed, so a service that answers a byte at a time holds a
/// connect or a send no longer than its deadline.
struct Timed {
    sock: TcpStream,
    until: Instant,
}

impl Timed {
    fn left(&self) -> io::Result<Duration> {
        let left = self.until.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(io::Error::new(io::ErrorKind::TimedOut, "the push service did not answer in time"));
        }
        Ok(left.min(TIMEOUT))
    }
}

impl Read for Timed {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let t = self.left()?;
        self.sock.set_read_timeout(Some(t))?;
        self.sock.read(buf)
    }
}

impl Write for Timed {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let t = self.left()?;
        self.sock.set_write_timeout(Some(t))?;
        self.sock.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.sock.flush()
    }
}

/// A connection to the push service, its hello answered.
pub struct Client {
    tls: StreamOwned<ClientConnection, Timed>,
    next: u64,
    /// Sends left this hour for the face's tag, as the service said.
    pub left: u64,
    /// The face's tag, as its hubs' credential names it: a registration's
    /// signature must cover it to hold on this connection.
    pub face: [u8; 16],
    /// How long a send waits for its answer ([`ANSWER_WITHIN`]).
    pub answer_within: Duration,
}

/// What a failed read says: the deadline, or the connection gone.
fn read_failed(e: &io::Error) -> &'static str {
    match e.kind() {
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock => "the push service did not answer in time",
        _ => "the push service closed the connection",
    }
}

fn read_all(s: &mut impl Read, b: &mut [u8]) -> Result<()> {
    match s.read_exact(b) {
        Ok(()) => Ok(()),
        Err(e) => {
            let what = read_failed(&e);
            Err(e).context(what)
        }
    }
}

fn read_frame(s: &mut impl Read) -> Result<Vec<u8>> {
    let mut h = [0u8; 4];
    read_all(s, &mut h)?;
    let n = frame::length(h, MAX_FRAME)
        .map_err(|r| Error::msg(format!("the push service sent a bad frame ({})", r.name())))?;
    let mut f = vec![0u8; n + 4];
    f[..4].copy_from_slice(&h);
    read_all(s, &mut f[4..])?;
    Ok(f)
}

impl Client {
    /// Dials the service at addr whose key has `pin`, as `key`, and says
    /// hello with the face's credentials (hubs', members').
    pub fn connect(addr: SocketAddr, pin: [u8; 32], key: Arc<ServerKey>, credentials: &[&[u8]]) -> Result<Client> {
        // One deadline for the dial, the handshake and the service's ready.
        let until = Instant::now() + ANSWER_WITHIN;
        let cert = key.cert()?;
        let clock: cbb_core::tls::Clock = Arc::new(crate::forward::SystemClock);
        let cfg = cbb_core::tls::pinned_client(vec![cert], key, vec![pin], push::ALPN, &clock)?;
        let tcp =
            TcpStream::connect_timeout(&addr, TIMEOUT.min(ANSWER_WITHIN)).context("cannot reach the push service")?;
        let conn = ClientConnection::new(Arc::new(cfg), cbb_core::tls::server_name(None))
            .context("cannot start TLS to the push service")?;
        let mut tls = StreamOwned::new(conn, Timed { sock: tcp, until });
        while tls.conn.is_handshaking() {
            tls.conn.complete_io(&mut tls.sock).context("TLS to the push service failed")?;
        }
        let face = credentials
            .iter()
            .filter_map(|c| cbb_core::blind::credential::Credential::read(c).ok())
            .find(|c| c.kind == cbb_core::blind::credential::TYPE_HUBS)
            .map(|c| c.group)
            .ok_or_else(|| Error::msg("the face's hubs' credential is missing"))?;
        let hello = push::hello(credentials)
            .map_err(|r| Error::msg(format!("a credential is not in the profile ({})", r.name())))?;
        tls.write_all(&hello).and_then(|()| tls.flush()).context("cannot write to the push service")?;
        let f = read_frame(&mut tls)?;
        let m = frame::read(&f, MAX_FRAME).map_err(|r| Error::msg(r.name()))?;
        match m.t {
            push::T_READY => {
                let left = m.map.get(2).and_then(cbb_core::format::Value::as_uint).unwrap_or(0);
                Ok(Client { tls, next: 1, left, face, answer_within: ANSWER_WITHIN })
            }
            push::T_ERROR => {
                let why = m.map.get(2).and_then(cbb_core::format::Value::as_text).unwrap_or("refused");
                Err(Error::msg(format!("the push service refused: {why}")))
            }
            _ => Err(Error::msg("the push service answered something else")),
        }
    }

    /// Asks the service to pass one sealed body to a token, with the
    /// registration's send key, signature and seq; `s.n` is set here. The
    /// answer's status is as a sender acts on it ([`push::status`]).
    pub fn send(&mut self, mut s: push::Send<'_>) -> Result<push::Sent> {
        // One deadline for the write and the answer: a service that keeps
        // sending other answers, or its own a byte at a time, never holds the
        // sender past it. The caller drops a connection whose send failed.
        self.tls.sock.until = Instant::now() + self.answer_within;
        let n = self.next;
        self.next = if n >= u64::from(u32::MAX) { 1 } else { n + 1 };
        s.n = n;
        let f = s.write().ok_or_else(|| Error::msg("the send is not one the push service reads"))?;
        self.tls.write_all(&f).and_then(|()| self.tls.flush()).context("cannot write to the push service")?;
        loop {
            let f = read_frame(&mut self.tls)?;
            let m = frame::read(&f, MAX_FRAME).map_err(|r| Error::msg(r.name()))?;
            match m.t {
                push::T_SENT => {
                    let sent = push::Sent::read(&m.map)
                        .map_err(|r| Error::msg(format!("the push service sent a bad answer ({})", r.name())))?;
                    if sent.n == n {
                        return Ok(sent);
                    }
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
