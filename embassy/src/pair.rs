// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! Joining a group by the phone: the device shows a QR code with a pairing
//! code and its address, listens on the member port for the phone that
//! scanned it, and runs the TLS connection around the exchange of
//! cbb_core::pair, as cbb pair does. The phone confirms
//! the code first, so a device that does not know it learns nothing; three
//! wrong codes end the attempt.

use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::fmt;
use core::future::Future;

use cbb_core::error::{Context, Error, Result, Wrap};
use cbb_core::identity::Identity;
use cbb_core::pair::{self, Failure, Joiner, MAX_FAILURES, Refusal};
use cbb_core::tls::{self, Clock, Session};
use cbb_core::wire;
use embassy_net::tcp::TcpSocket;
use embassy_net::{IpAddress, Stack};
use embassy_time::{Duration, Instant, with_timeout};
use embedded_io_async::Write;

/// The member port, where the phone dials the device.
pub const PORT: u16 = 8764;
/// How long the device waits for the phone.
const WAIT: Duration = Duration::from_secs(5 * 60);
/// How long one attempt may take.
const ATTEMPT: Duration = Duration::from_secs(30);
/// How long the phone has, from its connection, for the TLS handshake and
/// to prove that it knows the code: it sends its CPace message and its tag
/// right after the handshake.
const PROVE: Duration = Duration::from_secs(10);
/// How many attempts from one address may end without a wrong code before
/// the device takes none from it.
const MAX_IDLE: u32 = 5;
/// How many addresses it counts one by one; the others share one count.
const MAX_SOURCES: usize = 64;

/// The attempts of each address that ended without a wrong code, so that
/// no device on the network holds the pairing for its whole wait.
#[derive(Default)]
struct Idle(alloc::collections::BTreeMap<[u8; 4], u32>);

impl Idle {
    fn key(&self, a: IpAddress) -> [u8; 4] {
        #[allow(irrefutable_let_patterns)]
        let k = if let IpAddress::Ipv4(v4) = a { v4.octets() } else { [0; 4] };
        if self.0.contains_key(&k) || self.0.len() < MAX_SOURCES { k } else { [0; 4] }
    }

    fn spent(&self, a: IpAddress) -> bool {
        self.0.get(&self.key(a)).is_some_and(|n| *n >= MAX_IDLE)
    }

    fn count(&mut self, a: IpAddress) {
        let k = self.key(a);
        *self.0.entry(k).or_insert(0) += 1;
    }
}

/// Keeps the identity a pairing gave, before the phone hears that it worked.
pub trait Saver {
    /// Saves id; false if it could not.
    fn save(&mut self, id: &Identity) -> impl Future<Output = bool>;
}

/// A pairing that waits for the phone.
pub struct Pairing {
    joiner: Joiner,
    code: String,
    /// The QR code's text, a cbb://join link.
    pub text: String,
}

impl Pairing {
    /// A new pairing code and pairing certificate for a device of this
    /// name, on the address the stack has now.
    pub fn new(stack: Stack<'_>, name: &str) -> Result<Pairing> {
        let Some(config) = stack.config_v4() else {
            return Err(Error::msg("the device has no IPv4 address yet"));
        };
        let joiner = Joiner::new(name)?;
        let code = pair::new_code();
        let addr = format!("{}:{PORT}", config.address.address());
        let text = pair::join_qr(&code, &[addr], &joiner.fingerprint());
        Ok(Pairing { joiner, code, text })
    }

    /// Waits up to five minutes for the phone and runs the pairing with
    /// it; log hears of each failed attempt.
    pub async fn run(
        &self,
        stack: Stack<'_>,
        clock: &Clock,
        saver: &mut impl Saver,
        log: fn(&str),
    ) -> Result<Identity> {
        let end = Instant::now() + WAIT;
        let mut failures = 0;
        let mut idle = Idle::default();
        let mut tries = pair::Attempts::default();
        let mut rx = vec![0u8; 4096];
        let mut tx = vec![0u8; 4096];
        loop {
            let left = end.saturating_duration_since(Instant::now());
            if left == Duration::from_ticks(0) {
                return Err(Error::msg("no phone joined the device in time; type pair again"));
            }
            let mut sock = TcpSocket::new(stack, &mut rx, &mut tx);
            sock.set_timeout(Some(ATTEMPT));
            match with_timeout(left, sock.accept(PORT)).await {
                Err(_) => return Err(Error::msg("no phone joined the device in time; type pair again")),
                Ok(Err(e)) => return Err(Error::with("cannot listen for the phone", Debug(format!("{e:?}")))),
                Ok(Ok(())) => {}
            }
            let from = sock.remote_endpoint().map(|e| e.addr);
            let Some(from) = from.filter(|a| home_address(*a) && !idle.spent(*a) && tries.allowed(*a)) else {
                sock.abort();
                continue;
            };
            let res = self.attempt(&mut sock, clock, saver).await;
            let _ = sock.flush().await;
            sock.close();
            match res {
                Ok(id) => return Ok(id),
                Err(e) => {
                    log(&format!("a pairing attempt failed: {}", e.for_user()));
                    tries.failed(from);
                    if pair::is_wrong_code(&e) {
                        failures += 1;
                        if failures >= MAX_FAILURES {
                            return Err(Error::with("the pairing failed", Refusal::TooMany));
                        }
                    } else {
                        idle.count(from);
                    }
                }
            }
        }
    }

    /// One attempt over a connection the phone dialed.
    async fn attempt(&self, sock: &mut TcpSocket<'_>, clock: &Clock, saver: &mut impl Saver) -> Result<Identity> {
        let j = &self.joiner;
        let (cfg, exporter) = tls::pair_server(&j.cert, &j.key, clock)?;
        let mut link = Link { session: Session::server(Arc::new(cfg))?, sock, buf: vec![0u8; 2048] };
        let (ex, confirm) = match with_timeout(PROVE, self.prove(&mut link, &exporter)).await {
            Ok(r) => r?,
            Err(_) => return Err(Error::msg("the phone did not prove that it knows the code in time")),
        };
        link.send(&confirm).await?;
        // The board keeps no wall clock: it takes none of the member's claim
        // times, which only a group handed over by waiting needs.
        let res = match ex.welcome(&link.read_frame().await?, 0) {
            Ok(id) if saver.save(&id).await => Ok(id),
            Ok(_) => Err(Error::msg("cannot save the group's identity")),
            Err(e) => Err(e),
        };
        let _ = link.send(&pair::done(res.is_ok())).await;
        link.close().await;
        res
    }

    /// The TLS handshake and the exchange until the phone proved that it
    /// knows the code: the exchange and the frame that answers it.
    async fn prove(&self, link: &mut Link<'_, '_>, exporter: &tls::Exporter) -> Result<(pair::Exchange, Vec<u8>)> {
        let j = &self.joiner;
        link.handshake().await.wrap("the TLS handshake failed")?;
        if link.session.alpn_protocol() != Some(tls::PAIR_PROTOCOL) {
            return Err(Error::msg("the device does not offer pairing"));
        }
        let member_der = link
            .session
            .peer_certificates()
            .and_then(|c| c.first())
            .map(|c| c.to_vec())
            .ok_or_else(|| Error::msg("the device does not offer pairing"))?;
        let mut sid = [0u8; 32];
        exporter.export(pair::EXPORTER_LABEL, &[], &mut sid).wrap("cannot bind the pairing to TLS")?;

        let (mut ex, first) = j.start(&self.code, &member_der, &sid, true)?;
        link.send(&first).await?;
        match ex.reply(&link.read_frame().await?) {
            Ok(f) => Ok((ex, f)),
            Err(Failure { error, send }) => {
                if let Some(f) = send {
                    let _ = link.send(&f).await;
                }
                Err(error)
            }
        }
    }
}

/// An address the phone may dial from: a private IPv4 address.
fn home_address(a: IpAddress) -> bool {
    match a {
        IpAddress::Ipv4(a) => a.is_private() || a.is_link_local(),
        // IPv6 is on only when another crate of the workspace turns it on
        // in smoltcp (cbb's tunnel); the phone dials over IPv4.
        #[allow(unreachable_patterns)]
        _ => false,
    }
}

/// The TLS session over a TCP socket.
struct Link<'a, 'b> {
    session: Session,
    sock: &'a mut TcpSocket<'b>,
    buf: Vec<u8>,
}

impl Link<'_, '_> {
    /// Sends what the session queued.
    async fn flush(&mut self) -> Result<()> {
        let out = self.session.take_outgoing();
        if !out.is_empty() {
            self.sock.write_all(&out).await.context("the connection broke")?;
            self.sock.flush().await.context("the connection broke")?;
        }
        Ok(())
    }

    /// Reads once from the socket into the session.
    async fn fill(&mut self) -> Result<()> {
        let n = self.sock.read(&mut self.buf).await.context("the connection broke")?;
        if n == 0 {
            return Err(Error::msg("the connection broke"));
        }
        if let Err(e) = self.session.feed(&self.buf[..n]) {
            // The alert that tells the peer why, if rustls made one.
            let _ = self.flush().await;
            return Err(e);
        }
        Ok(())
    }

    async fn handshake(&mut self) -> Result<()> {
        loop {
            self.flush().await?;
            if !self.session.is_handshaking() {
                return Ok(());
            }
            self.fill().await?;
        }
    }

    async fn read_exact(&mut self, out: &mut [u8]) -> Result<()> {
        let mut got = 0;
        while got < out.len() {
            let n = self.session.read(&mut out[got..]);
            got += n;
            if got == out.len() {
                break;
            }
            if n == 0 {
                if self.session.peer_closed() {
                    return Err(Error::msg("the connection broke in the middle of a frame"));
                }
                self.fill().await?;
                self.flush().await?;
            }
        }
        Ok(())
    }

    async fn read_frame(&mut self) -> Result<Vec<u8>> {
        let mut head = [0u8; 4];
        self.read_exact(&mut head).await?;
        let mut body = vec![0u8; wire::frame_len(head, pair::MAX_FRAME)?];
        self.read_exact(&mut body).await?;
        Ok(body)
    }

    async fn send(&mut self, frame: &[u8]) -> Result<()> {
        self.session.write(frame)?;
        self.flush().await
    }

    /// Sends a close_notify.
    async fn close(&mut self) {
        if self.session.close().is_ok() {
            let _ = self.flush().await;
        }
    }
}

/// The debug text of an error that is no core::error::Error.
#[derive(Debug)]
struct Debug(String);

impl fmt::Display for Debug {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl core::error::Error for Debug {}
