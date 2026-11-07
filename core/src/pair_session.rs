// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! One pairing attempt of a joiner that listens and showed its QR code,
//! without I/O: the program accepts the member's connection, passes what
//! arrives to [`Attempt::feed`] and sends what each step returns, for a
//! program whose own TLS cannot export the pairing's sid or whose key the
//! core does not hold (the Aurora app, through ffi/). The exchange is
//! pair's, inside the core's TLS; the member confirms first.

use alloc::boxed::Box;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::authority::Record;
use crate::error::{Error, Result};
use crate::group::ClaimTime;
use crate::identity::Identity;
use crate::pair::{self, Exchange, Failure, Joiner, MAX_FRAME, Refusal};
use crate::tls::{self, Clock, Exporter, Session};
use crate::wire;

/// What a successful attempt gives the program to store: the records that
/// lead to the group's roots, then the identity (empty key for an external
/// one).
pub struct Joined {
    pub identity: Identity,
    pub records: Vec<Record>,
    pub claim_times: Vec<ClaimTime>,
    /// The admin CA for the phone's admin key, when the member made it an
    /// admin (pair::Joiner::offering_admin_key).
    pub admin_ca: Option<Vec<u8>>,
}

/// Where an attempt is after a step.
pub enum Outcome {
    /// It waits for more from the member.
    Pending,
    /// The member admitted this device: the program stores it, then calls
    /// [`Attempt::finish`].
    Joined(Box<Joined>),
    /// The attempt is over. wrong_code is set when the member showed a
    /// wrong code, which counts toward pair::MAX_FAILURES.
    Failed { error: Error, wrong_code: bool },
}

/// What a step gives: the bytes to send, then where the attempt is.
pub struct Step {
    pub send: Vec<u8>,
    pub outcome: Outcome,
}

enum State {
    Handshake,
    Reply(Exchange),
    Welcome(Exchange),
    Over,
}

/// One connection a member dialed to this joiner.
pub struct Attempt {
    session: Session,
    exporter: Arc<Exporter>,
    joiner: Joiner,
    code: String,
    plain: Vec<u8>,
    state: State,
}

impl Attempt {
    /// An attempt for a connection the program accepted, with the code the
    /// QR code carries.
    pub fn listening(joiner: &Joiner, code: &str, clock: &Clock) -> Result<Attempt> {
        let code = pair::normalize_code(code)?;
        let (cfg, exporter) = match joiner.external_key() {
            Some(key) => tls::pair_server_external(&joiner.cert, key.clone(), clock)?,
            None => tls::pair_server(&joiner.cert, &joiner.key, clock)?,
        };
        Ok(Attempt {
            session: Session::server(Arc::new(cfg))?,
            exporter,
            joiner: joiner.clone(),
            code,
            plain: Vec::new(),
            state: State::Handshake,
        })
    }

    /// Takes what arrived on the connection (empty when the program only
    /// wants what is due) and returns what to send and where the attempt
    /// is. now_ms is the wall clock in Unix milliseconds, or 0 without one.
    pub fn feed(&mut self, data: &[u8], now_ms: i64) -> Step {
        let outcome = match self.advance(data, now_ms) {
            Ok(o) => o,
            Err(error) => {
                self.state = State::Over;
                Outcome::Failed { error, wrong_code: false }
            }
        };
        if let Outcome::Failed { .. } = outcome {
            let _ = self.session.close();
        }
        Step { send: self.session.take_outgoing(), outcome }
    }

    /// Ends a joined attempt: saved tells the member whether the program
    /// stored the identity. Returns the last bytes to send, after which
    /// the program closes the connection.
    pub fn finish(&mut self, saved: bool) -> Vec<u8> {
        let _ = self.session.write(&pair::done(saved));
        let _ = self.session.close();
        self.state = State::Over;
        self.session.take_outgoing()
    }

    fn advance(&mut self, data: &[u8], now_ms: i64) -> Result<Outcome> {
        if matches!(self.state, State::Over) {
            return Err(Error::msg("the pairing attempt is over"));
        }
        if !data.is_empty() {
            self.session.feed(data)?;
        }
        if matches!(self.state, State::Handshake) {
            if self.session.is_handshaking() {
                return Ok(Outcome::Pending);
            }
            if self.session.alpn_protocol() != Some(tls::PAIR_PROTOCOL) {
                return Err(Error::msg("the device does not offer pairing"));
            }
            let member_der = self
                .session
                .peer_certificates()
                .and_then(|c| c.first())
                .map(|c| c.to_vec())
                .ok_or_else(|| Error::msg("the device does not offer pairing"))?;
            let mut sid = [0u8; 32];
            self.exporter
                .export(pair::EXPORTER_LABEL, &[], &mut sid)
                .map_err(|e| Error::msg(alloc::format!("cannot bind the pairing to TLS: {e}")))?;
            let (ex, first) = self.joiner.start(&self.code, &member_der, &sid, true)?;
            self.session.write(&first)?;
            self.state = State::Reply(ex);
        }
        let mut buf = [0u8; 4096];
        loop {
            let n = self.session.read(&mut buf);
            if n == 0 {
                break;
            }
            self.plain.extend_from_slice(buf.get(..n).unwrap_or_default());
        }
        while let Some(body) = self.next_frame()? {
            match core::mem::replace(&mut self.state, State::Over) {
                State::Reply(mut ex) => match ex.reply(&body) {
                    Ok(confirm) => {
                        self.session.write(&confirm)?;
                        self.state = State::Welcome(ex);
                    }
                    Err(Failure { error, send }) => {
                        if let Some(f) = send {
                            let _ = self.session.write(&f);
                        }
                        let wrong_code = error.details().contains(Refusal::WrongCode.message());
                        return Ok(Outcome::Failed { error, wrong_code });
                    }
                },
                State::Welcome(ex) => {
                    return match ex.welcome(&body, now_ms) {
                        Ok(identity) => Ok(Outcome::Joined(Box::new(Joined {
                            identity,
                            records: ex.records(),
                            claim_times: ex.claim_times(),
                            admin_ca: ex.admin_ca(),
                        }))),
                        Err(error) => {
                            let _ = self.session.write(&pair::done(false));
                            Ok(Outcome::Failed { error, wrong_code: false })
                        }
                    };
                }
                State::Handshake | State::Over => return Err(Error::msg("the frames came out of order")),
            }
        }
        if self.session.peer_closed() {
            return Err(Error::msg("the other device closed the connection"));
        }
        Ok(Outcome::Pending)
    }

    /// Takes the next whole frame's body from what arrived, if one is there.
    fn next_frame(&mut self) -> Result<Option<Vec<u8>>> {
        let Some(head) = self.plain.get(..4) else { return Ok(None) };
        let mut h = [0u8; 4];
        h.copy_from_slice(head);
        // frame_len caps it at MAX_FRAME, far below usize's end.
        let end = wire::frame_len(h, MAX_FRAME)?.saturating_add(4);
        let Some(body) = self.plain.get(4..end).map(<[u8]>::to_vec) else { return Ok(None) };
        self.plain.drain(..end);
        Ok(Some(body))
    }
}

impl Joined {
    /// The device ID the member admitted.
    pub fn device(&self) -> String {
        self.identity.id.to_string()
    }
}
