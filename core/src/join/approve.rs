// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! What lets the member send message 67 (`pair/welcome`) in a pairing
//! session: an [`Approved`] of that session, for that joiner. It has one
//! constructor and no other way to be made: [`Approved::by_secret`], the
//! joiner's `Ta` verified in a CPace exchange whose password is an
//! invitation's own secret, never all zero bytes: the joiner showed that it
//! holds the secret (it scanned the QR code, or its person typed a home
//! window's six digits).
//!
//! [`super::welcome::message`] takes the approval and the exchange by value
//! and checks that the approval names the exchange's session and joiner:
//! one approval, one message 67, none for another session or another
//! joiner, and none before the approval exists.

use alloc::vec::Vec;

use zeroize::Zeroizing;

use super::invitation::Invitation;
use super::{PairError, PairExporter, channel_id};
use crate::format::{Alg, Key, KeyHash};
use crate::third_party::cpace;

/// The proof that message 67 may go in one session, to one joiner. It is
/// neither cloned nor built from outside this module.
#[derive(Debug)]
pub struct Approved {
    session: [u8; 32],
    joiner: KeyHash,
}

impl Approved {
    /// The joiner's `Ta` verified under an invitation's own secret.
    fn by_secret(ex: &MemberExchange) -> Approved {
        Approved { session: ex.session, joiner: ex.joiner }
    }
}

/// The member's CPace exchange in one pairing session, the responder's
/// side (the joiner initiates).
pub struct MemberExchange {
    state: cpace::State,
    isk: Zeroizing<Vec<u8>>,
    /// The joiner's `Ta` verified.
    confirmed: bool,
    session: [u8; 32],
    joiner: KeyHash,
}

impl core::fmt::Debug for MemberExchange {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("MemberExchange")
            .field("confirmed", &self.confirmed)
            .field("joiner", &self.joiner)
            .finish_non_exhaustive()
    }
}

impl MemberExchange {
    /// Answers message 64: `ya` and `ada` are its `Ya` and `ADa`, `adb` what
    /// message 65 carries as `ADb`. `member` is the hash of the member's own
    /// TLS key, `joiner` the joiner's key the handshake proved, `exporter`
    /// the session's pairing exporter, CPace's session identifier. Returns the
    /// exchange and `Yb`.
    pub fn respond(
        invitation: &Invitation,
        member: &KeyHash,
        joiner: &[u8; 65],
        exporter: &PairExporter,
        adb: &[u8],
        ya: &[u8],
        ada: &[u8],
    ) -> Result<(MemberExchange, Vec<u8>), PairError> {
        // No invitation has an ID or a secret of zero bytes
        // (`invite/shape`): such a password would be public.
        if invitation.id == [0; 16] || crate::secret::ct_eq(&invitation.secret, &[0; super::invitation::SECRET]) {
            return Err(PairError::Refused);
        }
        let (id, secret) = (&invitation.id, &invitation.secret);
        let joiner = Key::new(Alg::Es256, joiner).hash();
        let ci = channel_id(member, &joiner, id);
        let (mut state, yb) = cpace::start(&cpace::Config {
            role: cpace::Role::Responder,
            password: secret,
            channel_id: &ci,
            session_id: exporter.bytes(),
            ad: adb,
        })
        .map_err(|_| PairError::Refused)?;
        let isk = state.finish(ya, ada).map_err(|_| PairError::Refused)?;
        let session = crate::format::grant::session_mark(exporter.bytes());
        Ok((MemberExchange { state, isk, confirmed: false, session, joiner }, yb))
    }

    /// Message 66's `Ta`. A `Ta` that does not verify is
    /// [`PairError::WrongCode`]: the two ends hold other passwords or other
    /// sessions, and the attempt ends. One that verifies approves message
    /// 67 ([`Approved::by_secret`]).
    pub fn confirm(&mut self, ta: &[u8]) -> Result<Approved, PairError> {
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
