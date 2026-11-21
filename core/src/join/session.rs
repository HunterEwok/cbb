// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! One pairing session of 0.6 at each end, without I/O (format section
//! 11.1): the joiner's and the member's steps from message 64 to message
//! 68, inside a TLS session of `cbb-pair/3` that the caller runs (the
//! core's own, `tls::bykey`, or the platform's on a phone). The caller
//! passes each frame that arrives and sends the frames each step gives.
//!
//! The steps only put this module's pieces in their order: CPace with the
//! channel identifier over both TLS keys and the invitation's ID
//! ([`super::channel_id`]), its session identifier the session's pairing
//! exporter, its associated data the joiner's Info (`ADa`) and the
//! member's `ADb`; message 67 made only with an approval of this
//! session and this joiner ([`super::approve`]) and read only once its tag
//! holds ([`super::welcome::open`]); the Welcome's parts assembled
//! ([`super::welcome::Assembly`]) and the whole checked
//! ([`super::welcome::Welcome::check`]). Every frame is read by
//! [`super::read_pairing`]: before the confirm at the pairing limit, and a
//! Welcome before it refused.
//!
//! One way binds both ends: an invitation's secret, a QR code's long one or
//! a home window's from its six digits ([`Invitation::home`]). The joiner's
//! verified `Ta` approves message 67 at the member, and the member's
//! verified `Tb` lets the joiner take it. At a home window that `Tb` is
//! also the joiner's proof of the member in this session
//! ([`JoinerSession::proven`]), a guarded leaf's only way to be bound again.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;

use crate::format::cbor::Value;
use crate::format::{Alg, DeviceId, Key, KeyHash, frame};
use crate::records::{GroupId, RecordSet, State};
use crate::third_party::cpace;

use super::approve::{Approved, MemberExchange};
use super::info::Info;
use super::invitation::{Invitation, JoinerAttempts, Network, Open, Proven};
use super::welcome::{self, Assembly, Joining, Way, Welcome};
use super::{PairError, PairExporter, T_CONFIRM, T_DONE, T_ERROR, T_REPLY, T_START, T_WELCOME};

/// What the member's `ADb` says, which the joiner shows before CPace ends
/// ("you are joining …").
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Adb {
    pub group: GroupId,
    pub device: DeviceId,
    pub name: String,
}

impl Adb {
    /// The encoding message 65 carries.
    pub fn encode(&self) -> Vec<u8> {
        Value::Map(alloc::vec![
            (1, Value::Bytes(&self.group.0)),
            (2, Value::Bytes(&self.device.0)),
            (3, Value::Text(&self.name)),
        ])
        .encode()
    }

    fn decode(b: &[u8]) -> Result<Adb, PairError> {
        let v = crate::format::cbor::decode(b).map_err(|_| PairError::Refused)?;
        let v = crate::msg::read_map(&crate::msg::tables::ADB, &v).map_err(|_| PairError::Refused)?;
        let id16 = |n: u16| v.get(n).and_then(Value::as_bytes).and_then(|b| <[u8; 16]>::try_from(b).ok());
        Ok(Adb {
            group: DeviceId(id16(1).ok_or(PairError::Refused)?),
            device: DeviceId(id16(2).ok_or(PairError::Refused)?),
            name: v.get(3).and_then(Value::as_text).unwrap_or_default().into(),
        })
    }
}

fn write(t: u64, mut fields: Vec<(u16, Value<'_>)>) -> Vec<u8> {
    fields.insert(0, (frame::FIELD_T, Value::Uint(t)));
    frame::write(&Value::Map(fields))
}

/// Message 69 with its code: the other end learns why the session ends.
pub fn error_frame(e: PairError) -> Vec<u8> {
    write(T_ERROR, alloc::vec![(2, Value::Uint(e.code()))])
}

/// Reads one frame of the session: its type and its message. Message 69
/// ends the session with the other end's reason.
fn read(frame: &[u8], confirmed: bool, want: u64) -> Result<crate::format::frame::Message<'_>, PairError> {
    let m = super::read_pairing(frame, confirmed).map_err(|_| PairError::Refused)?;
    if m.t == T_ERROR {
        let code = m.get(2).and_then(Value::as_uint).unwrap_or(0);
        return Err(PairError::of(code).unwrap_or(PairError::Refused));
    }
    if m.t != want {
        return Err(PairError::Refused);
    }
    crate::msg::check(&m.map.encode()).map_err(|_| PairError::Refused)?;
    Ok(m)
}

fn bytes<'a>(m: &crate::format::frame::Message<'a>, n: u16) -> Result<&'a [u8], PairError> {
    match m.get(n) {
        Some(Value::Bytes(b)) => Ok(b),
        _ => Err(PairError::Refused),
    }
}

fn hash(point: &[u8; 65]) -> KeyHash {
    Key::new(Alg::Es256, point).hash()
}

// ------------------------------------------------------------- the joiner

enum JoinerStep {
    /// Message 64 went; message 65 is due.
    Reply {
        cpace: cpace::State,
    },
    /// Message 66 went; message 67 is due.
    Welcome {
        cpace: cpace::State,
        isk: crate::secret::Zeroizing<Vec<u8>>,
    },
    /// Message 67 came with parts to follow.
    Parts {
        assembly: Assembly,
    },
    Over,
}

/// The joiner's session.
pub struct JoinerSession {
    exporter: PairExporter,
    own: [u8; 65],
    member: [u8; 65],
    invitation: Invitation,
    joining: Joining,
    adb: Option<Adb>,
    proven: Option<Proven>,
    step: JoinerStep,
}

/// What the joiner's message 65 gave: message 66 to send and what the
/// member said it is.
#[derive(Debug)]
pub struct Replied {
    pub send: Vec<u8>,
    pub adb: Adb,
}

/// Where the joiner is after message 67 or a part.
pub enum Joined {
    /// More parts are due.
    Waiting,
    /// The Welcome checked.
    Done(Box<Admitted>),
}

/// The checked Welcome: the set and its state, to store, and message 68
/// to send once stored.
pub struct Admitted {
    pub set: RecordSet,
    pub state: State,
    pub welcome: Welcome,
    pub send: Vec<u8>,
}

impl JoinerSession {
    /// Starts a session the person started (`attempts` counts it): `info`
    /// is what the joiner says of itself (`invite` set here from the
    /// invitation it joins by), `own` and `member` the TLS keys of both
    /// ends, and `exporter` the session's pairing exporter. Gives message
    /// 64. An invitation with an ID of zero bytes is refused: no invitation
    /// has one (`invite/shape`).
    pub fn start(
        attempts: &mut JoinerAttempts,
        mut info: Info,
        invitation: Invitation,
        joining: Joining,
        own: [u8; 65],
        member: [u8; 65],
        exporter: PairExporter,
    ) -> Result<(JoinerSession, Vec<u8>), PairError> {
        if invitation.id == [0; 16] {
            return Err(PairError::Refused);
        }
        info.invite = Some(invitation.id);
        let ada = info.encode();
        attempts.start()?;
        let ci = super::channel_id(&hash(&member), &hash(&own), &invitation.id);
        let (cpace, ya) = cpace::start(&cpace::Config {
            role: cpace::Role::Initiator,
            password: &invitation.secret,
            channel_id: &ci,
            session_id: exporter.bytes(),
            ad: &ada,
        })
        .map_err(|_| PairError::Refused)?;
        let send = write(T_START, alloc::vec![(2, Value::Bytes(&ya)), (3, Value::Bytes(&ada))]);
        let s = JoinerSession {
            exporter,
            own,
            member,
            invitation,
            joining,
            adb: None,
            proven: None,
            step: JoinerStep::Reply { cpace },
        };
        Ok((s, send))
    }

    /// Takes message 65: gives message 66.
    pub fn reply(&mut self, frame: &[u8]) -> Result<Replied, PairError> {
        let JoinerStep::Reply { mut cpace } = core::mem::replace(&mut self.step, JoinerStep::Over) else {
            return Err(PairError::Refused);
        };
        let m = read(frame, false, T_REPLY)?;
        let (yb, adb_bytes) = (bytes(&m, 2)?, bytes(&m, 3)?);
        let adb = Adb::decode(adb_bytes)?;
        let isk = crate::secret::Zeroizing::new(cpace.finish(yb, adb_bytes).map_err(|_| PairError::Refused)?.to_vec());
        let ta = cpace.tag().ok_or(PairError::Refused)?;
        let send = write(T_CONFIRM, alloc::vec![(2, Value::Bytes(&ta))]);
        self.adb = Some(adb.clone());
        self.step = JoinerStep::Welcome { cpace, isk };
        Ok(Replied { send, adb })
    }

    /// At a home window, once the member's `Tb` verified under the
    /// window's secret in this session (message 67 taken): the proof of
    /// that member in this session ([`Proven`]), given once. None by any
    /// other invitation, and before `Tb` verified.
    pub fn proven(&mut self) -> Option<Proven> {
        self.proven.take()
    }

    /// Takes message 67, then each part that follows it.
    pub fn take(&mut self, frame: &[u8], now_ms: u64) -> Result<Joined, PairError> {
        match core::mem::replace(&mut self.step, JoinerStep::Over) {
            JoinerStep::Welcome { cpace, isk } => {
                let m = read(frame, true, T_WELCOME)?;
                cpace.verify(bytes(&m, 2)?).map_err(|_| PairError::WrongCode)?;
                // Tb verified: the member holds the secret, in this session.
                let local = Key::new(Alg::Es256, &self.own).device_id();
                self.proven = Proven::new(&self.invitation, local, &self.exporter, &self.member);
                let body = frame.get(4..).ok_or(PairError::Refused)?;
                let w = welcome::open(body, &isk).map_err(|_| PairError::Refused)?;
                let w = Welcome::decode(w).map_err(|_| PairError::Refused)?;
                if w.parts > 0 {
                    self.step =
                        JoinerStep::Parts { assembly: Assembly::new(w, now_ms).map_err(|_| PairError::Refused)? };
                    return Ok(Joined::Waiting);
                }
                self.check(w)
            }
            JoinerStep::Parts { mut assembly } => {
                assembly.take(frame, now_ms).map_err(|_| PairError::Refused)?;
                if assembly.due() > 0 {
                    self.step = JoinerStep::Parts { assembly };
                    return Ok(Joined::Waiting);
                }
                self.check(assembly.finish().map_err(|_| PairError::Refused)?)
            }
            _ => Err(PairError::Refused),
        }
    }

    fn check(&mut self, w: Welcome) -> Result<Joined, PairError> {
        let adb = self.adb.as_ref().ok_or(PairError::Refused)?;
        let (set, state) = w
            .check(&adb.group, &self.member, &self.own, self.joining, Way::Invited(&self.invitation))
            .map_err(|_| PairError::Refused)?;
        Ok(Joined::Done(Box::new(Admitted { set, state, welcome: w, send: write(T_DONE, Vec::new()) })))
    }
}

// ------------------------------------------------------------- the member

enum MemberStep {
    /// Message 64 is due.
    Start,
    /// Message 65 went; message 66 is due.
    Confirm {
        ex: MemberExchange,
    },
    /// The joiner's Ta verified: message 67 may go.
    Approve {
        ex: MemberExchange,
        approved: Approved,
    },
    /// Message 67 went; message 68 is due.
    Done,
    Over,
}

/// The member's session.
pub struct MemberSession {
    exporter: PairExporter,
    own: [u8; 65],
    joiner: [u8; 65],
    adb: Adb,
    /// The invitation's attempt.
    attempt: Option<u64>,
    info: Option<Info>,
    step: MemberStep,
}

impl MemberSession {
    /// A session with the joiner whose key the TLS handshake proved: `own`
    /// is the member's TLS key, `adb` what message 65 says of the group
    /// and this member.
    pub fn new(own: [u8; 65], joiner: [u8; 65], adb: Adb, exporter: PairExporter) -> MemberSession {
        MemberSession { exporter, own, joiner, adb, attempt: None, info: None, step: MemberStep::Start }
    }

    /// Whether the joiner's Info offers an admin key whose proof holds
    /// over this session's exporter (`crate::join::verify_admin_pop`);
    /// false when it offers none or its Info has not come.
    pub fn admin_pop_holds(&self) -> bool {
        match self.info().map(|i| (i.admin_key(), i.admin_pop.as_ref())) {
            Some((Some(k), Some(p))) => super::verify_admin_pop(&k, &self.exporter, p),
            _ => false,
        }
    }

    /// The joiner's Info, once message 64 came.
    pub fn info(&self) -> Option<&Info> {
        self.info.as_ref()
    }

    /// Takes message 64 on an open invitation, from a joiner on network at
    /// now_ms: the invitation counts the attempt. Gives message 65.
    pub fn start_invited(
        &mut self,
        open: &mut Open,
        network: Network,
        frame: &[u8],
        now_ms: u64,
    ) -> Result<Vec<u8>, PairError> {
        if !matches!(self.step, MemberStep::Start) {
            return Err(PairError::Refused);
        }
        let m = read(frame, false, T_START)?;
        let (ya, ada) = (bytes(&m, 2)?, bytes(&m, 3)?);
        let info = Info::decode(ada).map_err(|_| PairError::Refused)?;
        if info.invite != Some(open.invitation.id) {
            return Err(PairError::Refused);
        }
        if open.asks_more(&info) {
            return Err(PairError::Refused);
        }
        if open.key_allowed(&hash(&self.joiner)) == Some(false) {
            return Err(PairError::Refused);
        }
        let number = open.begin(network, now_ms)?;
        self.attempt = Some(number);
        let adb = self.adb.encode();
        let (ex, yb) =
            MemberExchange::respond(&open.invitation, &hash(&self.own), &self.joiner, &self.exporter, &adb, ya, ada)
                .inspect_err(|_| open.end(number, false, now_ms))?;
        self.info = Some(info);
        self.step = MemberStep::Confirm { ex };
        Ok(write(T_REPLY, alloc::vec![(2, Value::Bytes(&yb)), (3, Value::Bytes(&adb))]))
    }

    /// Takes message 66. A Ta that does not verify is
    /// [`PairError::WrongCode`]: the session ends, its attempt stays
    /// counted as failed ([`Open::begin`]), and nothing is written.
    pub fn confirm(&mut self, frame: &[u8], open: &mut Open, now_ms: u64) -> Result<(), PairError> {
        let MemberStep::Confirm { mut ex } = core::mem::replace(&mut self.step, MemberStep::Over) else {
            return Err(PairError::Refused);
        };
        let ended = |e: PairError, attempt: Option<u64>, open: &mut Open| {
            if let Some(n) = attempt {
                open.end(n, false, now_ms);
            }
            e
        };
        let m = read(frame, false, T_CONFIRM).map_err(|e| ended(e, self.attempt, open))?;
        let ta = bytes(&m, 2).map_err(|e| ended(e, self.attempt, open))?;
        let approved = ex.confirm(ta).map_err(|e| ended(e, self.attempt, open))?;
        self.step = MemberStep::Approve { ex, approved };
        Ok(())
    }

    /// The member refuses the joiner after it proved the secret (its admin
    /// declined it, or its record could not be written): the session ends,
    /// and so does its attempt, counted as failed ([`Open::begin`]), so
    /// that the invitation takes the next attempt at once.
    pub fn refuse(&mut self, open: &mut Open, now_ms: u64) {
        if let Some(n) = self.attempt.take() {
            open.end(n, false, now_ms);
        }
        self.step = MemberStep::Over;
    }

    /// Whether message 67 may go: the session is approved.
    pub fn approved(&self) -> bool {
        matches!(&self.step, MemberStep::Approve { .. })
    }

    /// Message 67 with the Welcome the caller built (its set already holds
    /// the joiner's record), then the parts that follow it.
    pub fn welcome(
        &mut self,
        w: &Welcome,
        parts: &[crate::records::sync::Part<'_>],
    ) -> Result<Vec<Vec<u8>>, PairError> {
        let MemberStep::Approve { ex, approved } = core::mem::replace(&mut self.step, MemberStep::Over) else {
            return Err(PairError::Refused);
        };
        let mut out = alloc::vec![welcome::message(ex, approved, &w.encode())?];
        out.extend(parts.iter().map(welcome::part_message));
        self.step = MemberStep::Done;
        Ok(out)
    }

    /// Takes message 68: the joiner kept its identity. The attempt ends
    /// welcomed, which closes the invitation ([`Open::end`]).
    pub fn done(&mut self, frame: &[u8], open: &mut Open, now_ms: u64) -> Result<(), PairError> {
        if !matches!(self.step, MemberStep::Done) {
            return Err(PairError::Refused);
        }
        read(frame, false, T_DONE)?;
        if let Some(n) = self.attempt {
            open.end(n, true, now_ms);
        }
        self.step = MemberStep::Over;
        Ok(())
    }
}
