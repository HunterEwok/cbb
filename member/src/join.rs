// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! Pairing of 0.6 over a connection (format section 11.1): the joiner's
//! and the member's sessions of `cbb_core::join::session` run on a TLS
//! connection of `cbb-pair/3` whose handshake is over. The steps and every
//! check are the core's; this carries the frames, asks the person about
//! the code shown at home, and hands the member's side the moment to write
//! the joiner's record and the joiner's side the moment to store its set.
//! A session that ends early tells the other end why, by message 69.

use std::io::{Read, Write};

use cbb_core::format::frame;
use cbb_core::join::PairError;
use cbb_core::join::invitation::{JoinerAttempts, Network, Open};
use cbb_core::join::session::{Admitted, Joined, JoinerSession, MemberSession, error_frame};
use cbb_core::join::{PairExporter, info::Info, invitation::Invitation, welcome::Joining};

use crate::error::{Error, Result};

/// What the joiner needs for one session.
pub struct Joiner<'a> {
    pub attempts: &'a mut JoinerAttempts,
    pub info: Info,
    /// None at home without an invitation.
    pub invitation: Option<Invitation>,
    pub joining: Joining,
    /// Both ends' TLS keys: this device's and the member's the handshake
    /// proved.
    pub own: [u8; 65],
    pub member: [u8; 65],
    pub exporter: PairExporter,
}

/// How the member takes this joiner.
pub enum Way<'a> {
    /// At home, without an invitation: both persons answer the code.
    Home,
    /// By an invitation the member keeps open, from a joiner on `network`.
    Invited { open: &'a mut Open, network: Network },
}

/// The person's answer to a shown code: true when they match.
pub type Ask<'a> = &'a mut dyn FnMut(&str) -> bool;

/// The member's admission once approved: writes the joiner's record and
/// gives the frames of [`MemberSession::welcome`].
pub type Admit<'a> = &'a mut dyn FnMut(&Info, &mut MemberSession) -> Result<Vec<Vec<u8>>>;

/// The joiner's side: runs the session to its end. `store` gets the
/// checked Welcome's set and state and must keep them before message 68
/// goes; it returns what it stored.
pub fn joiner(
    conn: &mut (impl Read + Write),
    j: Joiner<'_>,
    ask: Ask<'_>,
    now_ms: &dyn Fn() -> u64,
    store: &mut dyn FnMut(&Admitted) -> Result<()>,
) -> Result<Box<Admitted>> {
    let Joiner { attempts, info, invitation, joining, own, member, exporter } = j;
    let (mut s, m64) = JoinerSession::start(attempts, info, invitation, joining, own, member, exporter)
        .map_err(|e| failed("cannot start pairing", e))?;
    send(conn, &m64)?;
    let m65 = read(conn, frame::LIMIT_PAIRING)?;
    let r = match s.reply(attempts, &m65) {
        Ok(r) => r,
        Err(e) => return Err(end(conn, e, "the pairing did not go on")),
    };
    send(conn, &r.send)?;
    if let Some(code) = &r.code
        && let Err(e) = s.answered(attempts, ask(code))
    {
        return Err(end(conn, e, "the codes do not match"));
    }
    loop {
        // Message 67 and its parts come at the member connection's limit.
        let f = read(conn, frame::LIMIT_MEMBER)?;
        match s.take(&f, now_ms()) {
            Ok(Joined::Waiting) => {}
            Ok(Joined::Done(a)) => {
                store(&a)?;
                send(conn, &a.send)?;
                return Ok(a);
            }
            Err(e) => return Err(end(conn, e, "the group's answer did not hold")),
        }
    }
}

/// The member's side: runs the session to its end. `admit` is called once
/// the session is approved (at home by the person's "they match", by an
/// invitation by its secret) with the joiner's Info and the session: it
/// writes the joiner's record and gives the frames of
/// [`MemberSession::welcome`]. An error from it refuses the joiner. Gives
/// the joiner's Info once it confirmed it kept its identity.
pub fn member(
    conn: &mut (impl Read + Write),
    mut s: MemberSession,
    mut way: Way<'_>,
    ask: Ask<'_>,
    now_ms: &dyn Fn() -> u64,
    admit: Admit<'_>,
) -> Result<Info> {
    let m64 = read(conn, frame::LIMIT_PAIRING)?;
    let started = match &mut way {
        Way::Home => s.start_home(&m64),
        Way::Invited { open, network } => s.start_invited(open, *network, &m64, now_ms()),
    };
    let m65 = match started {
        Ok(f) => f,
        Err(e) => return Err(end(conn, e, "the device was not let in")),
    };
    send(conn, &m65)?;
    let m66 = read(conn, frame::LIMIT_PAIRING)?;
    let open = match &mut way {
        Way::Home => None,
        Way::Invited { open, .. } => Some(&mut **open),
    };
    let c = match s.confirm(&m66, open, now_ms()) {
        Ok(c) => c,
        Err(e) => return Err(end(conn, e, "the device did not prove the code")),
    };
    if let Some(code) = &c.code
        && let Err(e) = s.answered(ask(code))
    {
        return Err(end(conn, e, "the codes do not match"));
    }
    let info = s.info().cloned().ok_or_else(|| Error::msg("the device said nothing of itself"))?;
    let frames = match admit(&info, &mut s) {
        Ok(f) => f,
        Err(e) => {
            let _ = send(conn, &error_frame(PairError::Refused));
            return Err(e);
        }
    };
    for f in &frames {
        send(conn, f)?;
    }
    let m68 = read(conn, frame::LIMIT_PAIRING)?;
    let open = match &mut way {
        Way::Home => None,
        Way::Invited { open, .. } => Some(&mut **open),
    };
    s.done(&m68, open, now_ms()).map_err(|e| failed("the device did not keep its place", e))?;
    Ok(info)
}

/// Sends message 69 with why, where it is ours to say, and gives the error.
fn end(conn: &mut impl Write, e: PairError, what: &str) -> Error {
    // The other end's own message 69 needs no answer.
    let _ = send(conn, &error_frame(e));
    failed(what, e)
}

fn failed(what: &str, e: PairError) -> Error {
    Error::with(what, Failure(e))
}

/// A pairing error with its number, as the details show it.
#[derive(Debug)]
struct Failure(PairError);

impl std::fmt::Display for Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let why = match self.0 {
            PairError::WrongCode => "the code did not match",
            PairError::Closed => "the invitation is closed",
            PairError::Busy => "another pairing is going on",
            PairError::Expired => "the invitation expired",
            PairError::TooMany => "too many tries",
            PairError::Refused => "refused",
            PairError::Declined => "a person said the codes do not match",
            PairError::Taken => "the device's ID is taken",
        };
        write!(f, "{why} (pairing error {})", self.0.code())
    }
}

impl std::error::Error for Failure {}

fn send(conn: &mut impl Write, f: &[u8]) -> Result<()> {
    conn.write_all(f).and_then(|()| conn.flush()).map_err(|e| Error::with("cannot send to the device", e))
}

/// One whole frame, its header too, as the core's session reads it.
fn read(conn: &mut impl Read, limit: usize) -> Result<Vec<u8>> {
    let mut head = [0u8; 4];
    conn.read_exact(&mut head).map_err(|e| Error::with("the device did not answer", e))?;
    let n = frame::length(head, limit).map_err(|rule| Error::msg(format!("a frame breaks {rule}")))?;
    let mut f = vec![0u8; 4 + n];
    f[..4].copy_from_slice(&head);
    conn.read_exact(&mut f[4..]).map_err(|e| Error::with("the device did not answer", e))?;
    Ok(f)
}

#[cfg(test)]
mod tests;
