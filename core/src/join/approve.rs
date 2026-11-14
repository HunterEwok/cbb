// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! What lets the member send message 67 (`pair/welcome`) in a pairing
//! session: an [`Approved`] of that session, for that joiner. It has two
//! constructors and no other way to be made:
//!
//! - [`Approved::by_secret`]: the joiner's `Ta` verified in a CPace exchange
//!   whose password is an invitation's own secret, never all zero bytes:
//!   the joiner showed that it holds the secret (it scanned the QR code).
//! - [`Approved::by_answer`]: the member's person said "they match" on the
//!   code shown in this attempt ([`answered_at_home`],
//!   [`super::invitation::Open::answered`]).
//!
//! With the zero password ([`super::NO_SECRET`], at home without an
//! invitation) CPace authenticates nothing by itself, so a `Ta` that
//! verifies under it approves nothing: only the person's answer does.
//! [`super::welcome::message`] takes the approval and the exchange by value
//! and checks that the approval names the exchange's session and joiner:
//! one approval, one message 67, none for another session or another
//! joiner, and none before the approval exists. The joiner holds the same
//! rule at its end (`welcome::Way::Home`).

use alloc::vec::Vec;

use zeroize::Zeroizing;

use super::invitation::{Invitation, SECRET};
use super::{NO_INVITATION, NO_SECRET, PairError, channel_id};
use crate::format::{Alg, Key, KeyHash};
use crate::third_party::cpace;

/// CPace's password at the member, with the invitation ID that goes with
/// it.
#[derive(Clone, Copy, Debug)]
pub enum Password<'a> {
    /// At home without an invitation: [`NO_INVITATION`] and [`NO_SECRET`].
    Home,
    /// An invitation: its ID and its secret, neither all zero bytes.
    Invitation(&'a Invitation),
}

/// Whether an invitation ID and a CPace password go together, and whether
/// the password authenticates the joiner: both all zero bytes is a pairing
/// at home without an invitation (`false`); neither is an invitation
/// (`true`); one without the other is [`PairError::Refused`], since no
/// invitation has a zero ID or a zero secret.
pub fn inputs(id: &[u8; 16], secret: &[u8; SECRET]) -> Result<bool, PairError> {
    let zero_id = id == &NO_INVITATION;
    let zero_secret = crate::secret::ct_eq(secret, &NO_SECRET);
    match (zero_id, zero_secret) {
        (true, true) => Ok(false),
        (false, false) => Ok(true),
        _ => Err(PairError::Refused),
    }
}

/// The code shown at the member in one attempt, waiting for the person's
/// answer. It gives nothing by itself: only "they match" turns it into an
/// [`Approved`]. It names its session (the mark of its TLS exporter), its
/// joiner (the key the handshake proved) and, on an open invitation, its
/// attempt.
#[derive(Debug)]
pub struct MemberShown {
    attempt: Option<u64>,
    session: [u8; 32],
    joiner: KeyHash,
}

impl MemberShown {
    pub(super) fn new(attempt: Option<u64>, exporter: &[u8], joiner: &[u8; 65]) -> MemberShown {
        MemberShown {
            attempt,
            session: crate::format::grant::session_mark(exporter),
            joiner: Key::new(Alg::Es256, joiner).hash(),
        }
    }

    pub(super) fn attempt(&self) -> Option<u64> {
        self.attempt
    }
}

/// The member's person answered the code shown at home without an
/// invitation: an [`Approved`] only for "they match". A code of an open
/// invitation is answered through [`super::invitation::Open::answered`],
/// which knows whether its attempt is still open; here it gives nothing.
pub fn answered_at_home(shown: MemberShown, matched: bool) -> Option<Approved> {
    if !matched || shown.attempt.is_some() {
        return None;
    }
    Some(Approved::by_answer(shown))
}

/// The proof that message 67 may go in one session, to one joiner. It is
/// neither cloned nor built from outside this module.
#[derive(Debug)]
pub struct Approved {
    session: [u8; 32],
    joiner: KeyHash,
}

impl Approved {
    /// The joiner's `Ta` verified under an invitation's own secret.
    fn by_secret(ex: &MemberExchange) -> Option<Approved> {
        ex.keyed.then_some(Approved { session: ex.session, joiner: ex.joiner })
    }

    /// The member's person said "they match" on this code.
    pub(super) fn by_answer(shown: MemberShown) -> Approved {
        Approved { session: shown.session, joiner: shown.joiner }
    }
}

/// The member's CPace exchange in one pairing session, the responder's
/// side (the joiner initiates).
pub struct MemberExchange {
    state: cpace::State,
    isk: Zeroizing<Vec<u8>>,
    /// The password is an invitation's own secret.
    keyed: bool,
    /// The joiner's `Ta` verified.
    confirmed: bool,
    session: [u8; 32],
    joiner: KeyHash,
}

impl core::fmt::Debug for MemberExchange {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("MemberExchange")
            .field("keyed", &self.keyed)
            .field("confirmed", &self.confirmed)
            .field("joiner", &self.joiner)
            .finish_non_exhaustive()
    }
}

impl MemberExchange {
    /// Answers message 64: `ya` and `ada` are its `Ya` and `ADa`, `adb` what
    /// message 65 carries as `ADb`. `member` is the hash of the member's own
    /// TLS key, `joiner` the joiner's key the handshake proved, `exporter`
    /// the session's TLS exporter, CPace's session identifier. Returns the
    /// exchange and `Yb`.
    pub fn respond(
        password: Password<'_>,
        member: &KeyHash,
        joiner: &[u8; 65],
        exporter: &[u8],
        adb: &[u8],
        ya: &[u8],
        ada: &[u8],
    ) -> Result<(MemberExchange, Vec<u8>), PairError> {
        let (id, secret, keyed): (&[u8; 16], &[u8; SECRET], bool) = match password {
            Password::Home => (&NO_INVITATION, &NO_SECRET, false),
            Password::Invitation(i) => (&i.id, &i.secret, inputs(&i.id, &i.secret)?),
        };
        let joiner = Key::new(Alg::Es256, joiner).hash();
        let ci = channel_id(member, &joiner, id);
        let (mut state, yb) = cpace::start(&cpace::Config {
            role: cpace::Role::Responder,
            password: secret,
            channel_id: &ci,
            session_id: exporter,
            ad: adb,
        })
        .map_err(|_| PairError::Refused)?;
        let isk = state.finish(ya, ada).map_err(|_| PairError::Refused)?;
        let session = crate::format::grant::session_mark(exporter);
        Ok((MemberExchange { state, isk, keyed, confirmed: false, session, joiner }, yb))
    }

    /// Message 66's `Ta`. A `Ta` that does not verify is
    /// [`PairError::WrongCode`]: the two ends hold other passwords or other
    /// sessions, and the attempt ends. One that verifies under an
    /// invitation's secret approves message 67 ([`Approved::by_secret`]);
    /// under the zero password it approves nothing, and only the person's
    /// answer can.
    pub fn confirm(&mut self, ta: &[u8]) -> Result<Option<Approved>, PairError> {
        if self.confirmed || self.state.verify(ta).is_err() {
            return Err(PairError::WrongCode);
        }
        self.confirmed = true;
        Ok(Approved::by_secret(self))
    }

    /// Whether `approved` lets this exchange send message 67: its `Ta`
    /// verified, and the approval names this session and this joiner.
    pub(super) fn allows(&self, approved: &Approved) -> bool {
        self.confirmed && crate::secret::ct_eq(&self.session, &approved.session) && self.joiner == approved.joiner
    }

    /// `Tb`, once the exchange finished.
    pub(super) fn tb(&self) -> Option<Vec<u8>> {
        self.state.tag()
    }

    /// The intermediate session key, which keys the Welcome's tag.
    pub(super) fn isk(&self) -> &[u8] {
        &self.isk
    }
}
