// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! A TLS connection without I/O, over rustls's unbuffered API, which needs
//! no standard library. The caller moves the bytes: it feeds what the
//! socket received, sends what the session queued, and reads and writes
//! the plaintext. The lite member drives it over a blocking socket; a
//! microcontroller drives it over its own network stack.

use alloc::sync::Arc;
use alloc::vec::Vec;

use rustls::client::UnbufferedClientConnection;
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::server::UnbufferedServerConnection;
use rustls::unbuffered::UnbufferedConnectionCommon;
use rustls::unbuffered::{ConnectionState, EncodeError, EncryptError, UnbufferedStatus};
use rustls::{ClientConfig, CommonState, ProtocolVersion, ServerConfig};

use super::TlsError;
use crate::error::{Error, Result};

/// One TLS connection, as client or server.
pub struct Session {
    conn: Side,
    incoming: Vec<u8>, // received TLS bytes not yet processed
    bufs: Bufs,
}

enum Side {
    Client(UnbufferedClientConnection),
    Server(UnbufferedServerConnection),
}

#[derive(Default)]
struct Bufs {
    outgoing: Vec<u8>, // TLS bytes to send
    plain: Vec<u8>,    // received plaintext not yet read
    plain_pos: usize,
    peer_closed: bool,
    failed: Option<rustls::Error>,
}

/// What to do once the connection may send application data.
#[derive(Clone, Copy)]
enum Action<'a> {
    None,
    Write(&'a [u8]),
    Close,
}

impl Session {
    /// A client connection; its first flight is queued at once.
    pub fn client(cfg: Arc<ClientConfig>, name: ServerName<'static>) -> Result<Session> {
        let conn =
            UnbufferedClientConnection::new(cfg, name).map_err(|e| Error::with("cannot set up TLS", TlsError(e)))?;
        let mut s = Session { conn: Side::Client(conn), incoming: Vec::new(), bufs: Bufs::default() };
        s.run(Action::None)?;
        Ok(s)
    }

    /// A server connection, waiting for the client's hello.
    pub fn server(cfg: Arc<ServerConfig>) -> Result<Session> {
        let conn = UnbufferedServerConnection::new(cfg).map_err(|e| Error::with("cannot set up TLS", TlsError(e)))?;
        Ok(Session { conn: Side::Server(conn), incoming: Vec::new(), bufs: Bufs::default() })
    }

    /// Takes bytes received from the peer and processes them: the
    /// handshake moves on, plaintext becomes readable, and replies are
    /// queued for take_outgoing.
    pub fn feed(&mut self, tls: &[u8]) -> Result<()> {
        self.incoming.extend_from_slice(tls);
        self.run(Action::None)
    }

    /// The bytes to send to the peer, in order; the caller must send all of
    /// them.
    pub fn take_outgoing(&mut self) -> Vec<u8> {
        core::mem::take(&mut self.bufs.outgoing)
    }

    /// Reports whether bytes wait to be sent.
    pub fn wants_write(&self) -> bool {
        !self.bufs.outgoing.is_empty()
    }

    /// Reads received plaintext into buf and returns how much; 0 means none
    /// is there now (see peer_closed).
    pub fn read(&mut self, buf: &mut [u8]) -> usize {
        let b = &mut self.bufs;
        let rest = b.plain.get(b.plain_pos..).unwrap_or_default();
        let n = buf.len().min(rest.len());
        if let (Some(to), Some(from)) = (buf.get_mut(..n), rest.get(..n)) {
            to.copy_from_slice(from);
        }
        b.plain_pos = b.plain_pos.saturating_add(n);
        if b.plain_pos == b.plain.len() {
            b.plain.clear();
            b.plain_pos = 0;
        }
        n
    }

    /// Reports whether received plaintext waits to be read.
    pub fn readable(&self) -> bool {
        self.bufs.plain_pos < self.bufs.plain.len()
    }

    /// Reports whether the peer ended the connection cleanly (its
    /// close_notify): nothing more will come after the plaintext there is.
    pub fn peer_closed(&self) -> bool {
        self.bufs.peer_closed
    }

    /// Encrypts data for the peer and queues it. It fails while the
    /// handshake is not over.
    pub fn write(&mut self, data: &[u8]) -> Result<()> {
        self.run(Action::Write(data))
    }

    /// Queues a close_notify, which ends what this side sends.
    pub fn close(&mut self) -> Result<()> {
        self.run(Action::Close)
    }

    /// Reports whether the handshake is still going on.
    pub fn is_handshaking(&self) -> bool {
        self.common().is_handshaking()
    }

    /// The protocol agreed through ALPN.
    pub fn alpn_protocol(&self) -> Option<&[u8]> {
        self.common().alpn_protocol()
    }

    /// The TLS version agreed.
    pub fn protocol_version(&self) -> Option<ProtocolVersion> {
        self.common().protocol_version()
    }

    /// The certificates the peer presented, leaf first.
    pub fn peer_certificates(&self) -> Option<&[CertificateDer<'static>]> {
        self.common().peer_certificates()
    }

    fn common(&self) -> &CommonState {
        match &self.conn {
            Side::Client(c) => c,
            Side::Server(c) => c,
        }
    }

    fn run(&mut self, action: Action<'_>) -> Result<()> {
        if let Some(e) = &self.bufs.failed {
            return Err(Error::with("the TLS connection failed", TlsError(e.clone())));
        }
        let res = match &mut self.conn {
            Side::Client(c) => pump(c, &mut self.incoming, &mut self.bufs, action, |c, b| c.process_tls_records(b)),
            Side::Server(c) => pump(c, &mut self.incoming, &mut self.bufs, action, |c, b| c.process_tls_records(b)),
        };
        match res {
            Ok(true) => Ok(()),
            Ok(false) => Err(Error::msg("the TLS handshake is not over")),
            Err(e) => {
                self.bufs.failed = Some(e.clone());
                Err(Error::with("the TLS connection failed", TlsError(e)))
            }
        }
    }
}

/// Processes the connection until it waits for the peer, and carries out
/// action once it may send application data. It reports whether the
/// action was done.
fn pump<D>(
    conn: &mut UnbufferedConnectionCommon<D>,
    incoming: &mut Vec<u8>,
    bufs: &mut Bufs,
    mut action: Action<'_>,
    process: for<'c, 'i> fn(&'c mut UnbufferedConnectionCommon<D>, &'i mut [u8]) -> UnbufferedStatus<'c, 'i, D>,
) -> Result<bool, rustls::Error> {
    loop {
        let UnbufferedStatus { mut discard, state } = process(conn, &mut incoming[..]);
        let state = match state {
            Ok(s) => s,
            Err(e) => {
                incoming.drain(..discard);
                // The alert that tells the peer why, if rustls queued one.
                flush_alert(conn, &mut bufs.outgoing, process);
                return Err(e);
            }
        };
        let mut stop = false;
        match state {
            ConnectionState::ReadTraffic(mut r) => {
                while let Some(rec) = r.next_record() {
                    let rec = rec?;
                    discard = discard.saturating_add(rec.discard);
                    bufs.plain.extend_from_slice(rec.payload);
                }
            }
            ConnectionState::EncodeTlsData(mut e) => {
                append(&mut bufs.outgoing, |out| match e.encode(out) {
                    Ok(n) => Ok(Ok(n)),
                    Err(EncodeError::InsufficientSize(s)) => Ok(Err(s.required_size)),
                    Err(_) => Err(rustls::Error::General("cannot encode a TLS record".into())),
                })?;
            }
            // The bytes are in outgoing, and the caller sends them in order.
            ConnectionState::TransmitTlsData(t) => t.done(),
            ConnectionState::WriteTraffic(mut w) => {
                match action {
                    Action::None => {}
                    Action::Write(data) => append(&mut bufs.outgoing, |out| match w.encrypt(data, out) {
                        Ok(n) => Ok(Ok(n)),
                        Err(EncryptError::InsufficientSize(s)) => Ok(Err(s.required_size)),
                        Err(_) => Err(rustls::Error::EncryptError),
                    })?,
                    Action::Close => append(&mut bufs.outgoing, |out| match w.queue_close_notify(out) {
                        Ok(n) => Ok(Ok(n)),
                        Err(EncryptError::InsufficientSize(s)) => Ok(Err(s.required_size)),
                        Err(_) => Err(rustls::Error::EncryptError),
                    })?,
                }
                action = Action::None;
                stop = true;
            }
            ConnectionState::PeerClosed => bufs.peer_closed = true,
            ConnectionState::Closed => {
                bufs.peer_closed = true;
                stop = true;
            }
            // Early data is never accepted (max_early_data_size is 0), so
            // this and the states of later versions only wait.
            _ => stop = true,
        }
        incoming.drain(..discard);
        if stop {
            return Ok(matches!(action, Action::None));
        }
    }
}

/// Moves the records that rustls queued after a failure, its alert, to
/// outgoing.
fn flush_alert<D>(
    conn: &mut UnbufferedConnectionCommon<D>,
    out: &mut Vec<u8>,
    process: for<'c, 'i> fn(&'c mut UnbufferedConnectionCommon<D>, &'i mut [u8]) -> UnbufferedStatus<'c, 'i, D>,
) {
    for _ in 0..4 {
        match process(conn, &mut []).state {
            Ok(ConnectionState::EncodeTlsData(mut e)) => {
                let _ = append(out, |o| match e.encode(o) {
                    Ok(n) => Ok(Ok(n)),
                    Err(EncodeError::InsufficientSize(s)) => Ok(Err(s.required_size)),
                    Err(_) => Err(rustls::Error::General("cannot encode a TLS record".into())),
                });
            }
            Ok(ConnectionState::TransmitTlsData(t)) => t.done(),
            _ => return,
        }
    }
}

/// Appends what f writes to out. f returns the bytes written, or the size
/// it needs when the space is too small: the first call asks, so out grows
/// by exactly what the records take (memory is short on a microcontroller).
fn append(
    out: &mut Vec<u8>,
    mut f: impl FnMut(&mut [u8]) -> Result<Result<usize, usize>, rustls::Error>,
) -> Result<(), rustls::Error> {
    let start = out.len();
    let mut want = 0;
    loop {
        out.resize(start.saturating_add(want), 0);
        match f(out.get_mut(start..).unwrap_or_default()) {
            Ok(Ok(n)) => {
                out.truncate(start.saturating_add(n));
                return Ok(());
            }
            Ok(Err(need)) if need > want => want = need,
            Ok(Err(_)) => {
                out.truncate(start);
                return Err(rustls::Error::General("TLS asked for less space than it had".into()));
            }
            Err(e) => {
                out.truncate(start);
                return Err(e);
            }
        }
    }
}

// The Session is Send, so a connection can move between threads or tasks.
const _: () = {
    const fn send<T: Send>() {}
    send::<Session>();
};
