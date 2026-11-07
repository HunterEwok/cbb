// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! TLS for the lite member: the core's TLS (cbb_core::tls, the same code a
//! microcontroller runs) with the system clock, driven over blocking
//! sockets.

use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use cbb_core::tls::rustls::pki_types::UnixTime;
use cbb_core::tls::rustls::time_provider::TimeProvider;
pub use cbb_core::tls::*;

use crate::error::{Context, Result};
use crate::records::{Records, Refusal};

#[derive(Debug)]
struct SystemClock;

impl TimeProvider for SystemClock {
    fn current_time(&self) -> Option<UnixTime> {
        Some(UnixTime::since_unix_epoch(std::time::Duration::from_millis(crate::uptime::wall_ms().max(0) as u64)))
    }
}

/// The system clock, for the TLS configurations.
pub fn clock() -> Clock {
    Arc::new(SystemClock)
}

/// The records' judgement of a member chain, under their lock.
pub fn refused(records: &Arc<Mutex<Records>>) -> Refused {
    let records = records.clone();
    // A chain no counting device record names yet, or one the records
    // stop the exchange with, passes here: its connection carries records
    // only (Node::run).
    Arc::new(move |chain| match records.lock().unwrap().refused(chain) {
        Some(Refusal::Refused(why)) => Some(why.to_string()),
        Some(Refusal::NotListed | Refusal::Stopped) | None => None,
    })
}

/// Sends what the session queued.
pub fn flush(s: &mut Session, mut sock: &TcpStream) -> io::Result<()> {
    let out = s.take_outgoing();
    if out.is_empty() {
        return Ok(());
    }
    sock.write_all(&out)
}

/// Reads once from the socket into the session; false at the end of the
/// stream.
fn fill(s: &mut Session, mut sock: &TcpStream, buf: &mut [u8]) -> io::Result<bool> {
    let n = sock.read(buf)?;
    if n == 0 {
        return Ok(false);
    }
    s.feed(&buf[..n]).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.for_log()))?;
    Ok(true)
}

/// Completes the handshake over the socket; a failure has the message
/// what, and the cause under it.
///
/// The socket's read timeout, when it has one, bounds the whole handshake,
/// not each read: a peer that sends a byte now and then cannot hold it
/// longer. The socket's timeouts are as before when it returns.
pub fn handshake(s: &mut Session, sock: &TcpStream, what: &str) -> Result<()> {
    let (read, write) = (sock.read_timeout().ok().flatten(), sock.write_timeout().ok().flatten());
    let res = handshake_by(s, sock, what, read.map(|t| Instant::now() + t));
    let _ = sock.set_read_timeout(read);
    let _ = sock.set_write_timeout(write);
    res
}

fn handshake_by(s: &mut Session, mut sock: &TcpStream, what: &str, deadline: Option<Instant>) -> Result<()> {
    let mut buf = vec![0u8; 16 << 10];
    // What is left of the deadline, for the socket's timeouts; an error
    // once it has passed.
    let left = || -> io::Result<()> {
        let Some(d) = deadline else { return Ok(()) };
        let t = d.saturating_duration_since(Instant::now());
        if t.is_zero() {
            return Err(io::Error::from(io::ErrorKind::TimedOut));
        }
        sock.set_read_timeout(Some(t))?;
        sock.set_write_timeout(Some(t))
    };
    loop {
        left().context(what.to_string())?;
        flush(s, sock).context(what.to_string())?;
        if !s.is_handshaking() {
            return Ok(());
        }
        left().context(what.to_string())?;
        let n = sock.read(&mut buf).context(what.to_string())?;
        if n == 0 {
            return Err(io::Error::from(io::ErrorKind::UnexpectedEof)).context(what.to_string());
        }
        if let Err(e) = s.feed(&buf[..n]) {
            // The alert that tells the peer why, if rustls made one.
            let _ = flush(s, sock);
            return Err(e.context(what.to_string()));
        }
    }
}

/// A TLS stream over a blocking socket, for the pairing.
pub struct Stream {
    pub session: Session,
    pub sock: TcpStream,
    buf: Vec<u8>,
}

impl Stream {
    pub fn new(session: Session, sock: TcpStream) -> Stream {
        Stream { session, sock, buf: vec![0u8; 16 << 10] }
    }

    /// Sends a close_notify.
    pub fn close(&mut self) {
        if self.session.close().is_ok() {
            let _ = flush(&mut self.session, &self.sock);
        }
    }
}

impl Read for Stream {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        loop {
            let n = self.session.read(out);
            if n > 0 || out.is_empty() || self.session.peer_closed() {
                return Ok(n);
            }
            let more = fill(&mut self.session, &self.sock, &mut self.buf);
            flush(&mut self.session, &self.sock)?;
            if !more? {
                return Ok(0);
            }
        }
    }
}

impl Write for Stream {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        self.session.write(data).map_err(|e| io::Error::other(e.for_log()))?;
        flush(&mut self.session, &self.sock)?;
        Ok(data.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        flush(&mut self.session, &self.sock)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cbb_core::certs::{DeviceId, self_signed};
    use cbb_core::identity::{new_key, signing_key};
    use std::net::TcpListener;
    use std::time::Duration;

    fn device() -> (Vec<u8>, Vec<u8>) {
        let key = new_key().unwrap();
        let cert = self_signed(&DeviceId::random(), &signing_key(&key).unwrap()).unwrap();
        (cert, key)
    }

    /// The read timeout bounds the whole handshake: a client that sends its
    /// hello a byte at a time, each well within the timeout, is cut off once
    /// the timeout has passed since the start.
    #[test]
    fn handshake_has_one_deadline() {
        let ln = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = ln.local_addr().unwrap();
        let ((sc, sk), (cc, ck)) = (device(), device());
        let (scfg, _sx) = pair_server(&sc, &sk, &clock()).unwrap();
        let (ccfg, _cx) = pair_client(&cc, &ck, &clock()).unwrap();
        let mut client = Session::client(Arc::new(ccfg), server_name(None)).unwrap();
        let hello = client.take_outgoing();
        let limit = Duration::from_millis(600);
        let srv = std::thread::spawn(move || {
            let (sock, _) = ln.accept().unwrap();
            sock.set_read_timeout(Some(limit)).unwrap();
            let mut s = Session::server(Arc::new(scfg)).unwrap();
            let start = Instant::now();
            let r = handshake(&mut s, &sock, "the handshake");
            (r.is_err(), start.elapsed(), sock.read_timeout().unwrap())
        });
        let mut c = TcpStream::connect(addr).unwrap();
        for b in hello.iter().take(12) {
            if c.write_all(&[*b]).is_err() {
                break;
            }
            std::thread::sleep(Duration::from_millis(200));
        }
        drop(c);
        let (failed, took, timeout) = srv.join().unwrap();
        assert!(failed, "the handshake did not fail");
        assert!(took < limit + Duration::from_millis(400), "the handshake took {took:?}, past its {limit:?}");
        assert_eq!(timeout, Some(limit), "the socket's timeout was not put back");
    }
}
