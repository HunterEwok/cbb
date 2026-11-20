// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! One pairing session of 0.6 at each end, without I/O (format section
//! 11.1): the joiner's and the member's steps from message 64 to message
//! 68, inside a TLS session of `cbb-pair/3` that the caller runs (the
//! core's own, `tls::bykey`, or the platform's on a phone). The caller
//! passes each frame that arrives and sends the frames each step gives;
//! the person's answer to a shown code comes through `answered`.
//!
//! The steps only put this module's pieces in their order: CPace with the
//! channel identifier over both TLS keys and the invitation's ID
//! ([`super::channel_id`]), its session identifier the session's pairing
//! exporter, its associated data the joiner's Info (`ADa`) and the
//! member's `ADb`; the short code's commitment and nonces
//! ([`super::invitation`]); message 67 made only with an approval of this
//! session and this joiner ([`super::approve`]) and read only once its tag
//! holds ([`super::welcome::open`]); the Welcome's parts assembled
//! ([`super::welcome::Assembly`]) and the whole checked
//! ([`super::welcome::Welcome::check`]). Every frame is read by
//! [`super::read_pairing`]: before the confirm at the pairing limit, and a
//! Welcome before it refused.
//!
//! Two ways bind the member: an invitation's secret, whose verified `Ta`
//! approves message 67 by itself, and the pairing at home without an
//! invitation, where both ends show the code and only each person's "they
//! match" lets the session go on (the member's before it sends message 67,
//! the joiner's before it takes it).

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;

use crate::format::cbor::Value;
use crate::format::{Alg, DeviceId, Key, KeyHash, frame};
use crate::records::{GroupId, RecordSet, State};
use crate::third_party::cpace;

use super::approve::{self, Approved, MemberExchange, MemberShown, Password};
use super::info::Info;
use super::invitation::{self, Invitation, JoinerAttempts, JoinerCode, Matched, Network, Open, Shown};
use super::welcome::{self, Assembly, Joining, Way, Welcome};
use super::{
    NO_INVITATION, NO_SECRET, PairError, PairExporter, T_CONFIRM, T_DONE, T_ERROR, T_REPLY, T_START, T_WELCOME,
};

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

fn b32(m: &crate::format::frame::Message<'_>, n: u16) -> Result<[u8; 32], PairError> {
    bytes(m, n)?.try_into().map_err(|_| PairError::Refused)
}

fn hash(point: &[u8; 65]) -> KeyHash {
    Key::new(Alg::Es256, point).hash()
}

// ------------------------------------------------------------- the joiner

enum JoinerStep {
    /// Message 64 went; message 65 is due.
    Reply {
        cpace: cpace::State,
        code: JoinerCode,
    },
    /// Message 66 went; the code is shown, message 67 is due (and, at
    /// home, the person's answer).
    Welcome {
        cpace: cpace::State,
        isk: crate::secret::Zeroizing<Vec<u8>>,
        shown: Option<Shown>,
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
    invitation: Option<Invitation>,
    joining: Joining,
    adb: Option<Adb>,
    matched: Option<Matched>,
    step: JoinerStep,
}

/// What the joiner's message 65 gave: message 66 to send, the code to show
/// at home (none by an invitation) and what the member said it is.
#[derive(Debug)]
pub struct Replied {
    pub send: Vec<u8>,
    pub code: Option<String>,
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
    /// is what the joiner says of itself (`invite` set from the invitation
    /// it joins by), `own` and `member` the TLS keys of both ends, and
    /// `exporter` the session's pairing exporter. Gives message 64.
    pub fn start(
        attempts: &mut JoinerAttempts,
        mut info: Info,
        invitation: Option<Invitation>,
        joining: Joining,
        own: [u8; 65],
        member: [u8; 65],
        exporter: PairExporter,
    ) -> Result<(JoinerSession, Vec<u8>), PairError> {
        let (id, secret) = match &invitation {
            Some(i) if i.id == NO_INVITATION => return Err(PairError::Refused),
            Some(i) => (i.id, i.secret),
            None => (NO_INVITATION, NO_SECRET),
        };
        info.invite = invitation.as_ref().map(|i| i.id);
        let ada = info.encode();
        let (code, commitment) = attempts.start()?;
        let ci = super::channel_id(&hash(&member), &hash(&own), &id);
        let (cpace, ya) = cpace::start(&cpace::Config {
            role: cpace::Role::Initiator,
            password: &secret,
            channel_id: &ci,
            session_id: exporter.bytes(),
            ad: &ada,
        })
        .map_err(|_| PairError::Refused)?;
        let send = write(
            T_START,
            alloc::vec![(2, Value::Bytes(&ya)), (3, Value::Bytes(&ada)), (4, Value::Bytes(&commitment))],
        );
        let s = JoinerSession {
            exporter,
            own,
            member,
            invitation,
            joining,
            adb: None,
            matched: None,
            step: JoinerStep::Reply { cpace, code },
        };
        Ok((s, send))
    }

    /// Takes message 65: gives message 66, and at home the code to show.
    pub fn reply(&mut self, attempts: &mut JoinerAttempts, frame: &[u8]) -> Result<Replied, PairError> {
        let JoinerStep::Reply { mut cpace, code } = core::mem::replace(&mut self.step, JoinerStep::Over) else {
            return Err(PairError::Refused);
        };
        let m = read(frame, false, T_REPLY)?;
        let (yb, adb_bytes, nonce_m) = (bytes(&m, 2)?, bytes(&m, 3)?, b32(&m, 4)?);
        let adb = Adb::decode(adb_bytes)?;
        let isk = crate::secret::Zeroizing::new(cpace.finish(yb, adb_bytes).map_err(|_| PairError::Refused)?.to_vec());
        let ta = cpace.tag().ok_or(PairError::Refused)?;
        let local = Key::new(Alg::Es256, &self.own).device_id();
        let (shown_code, nj, shown) =
            attempts.open(code, &self.exporter, &nonce_m, self.invitation.as_ref(), local, &self.member)?;
        let send = write(T_CONFIRM, alloc::vec![(2, Value::Bytes(&ta)), (3, Value::Bytes(&nj))]);
        let at_home = self.invitation.is_none();
        if !at_home {
            // By an invitation its secret binds the member: nothing to ask.
            attempts.gave_up();
        }
        self.adb = Some(adb.clone());
        self.step = JoinerStep::Welcome { cpace, isk, shown: at_home.then_some(shown) };
        Ok(Replied { send, code: at_home.then_some(shown_code), adb })
    }

    /// The person answered the code shown at home. "They do not match"
    /// ends the session ([`PairError::Declined`]: send message 69 with it).
    pub fn answered(&mut self, attempts: &mut JoinerAttempts, matched: bool) -> Result<(), PairError> {
        let JoinerStep::Welcome { shown, .. } = &mut self.step else { return Err(PairError::Refused) };
        let Some(shown) = shown.take() else { return Err(PairError::Refused) };
        match attempts.answered(shown, matched) {
            Some(m) => {
                self.matched = Some(m);
                Ok(())
            }
            None => {
                self.step = JoinerStep::Over;
                Err(PairError::Declined)
            }
        }
    }

    /// Whether the joiner waits for its person's answer.
    pub fn asks(&self) -> bool {
        matches!(&self.step, JoinerStep::Welcome { shown: Some(_), .. })
    }

    /// Takes message 67, then each part that follows it.
    pub fn take(&mut self, frame: &[u8], now_ms: u64) -> Result<Joined, PairError> {
        match core::mem::replace(&mut self.step, JoinerStep::Over) {
            JoinerStep::Welcome { cpace, isk, shown } => {
                // At home the Welcome is taken only after "they match".
                if shown.is_some() || (self.invitation.is_none() && self.matched.is_none()) {
                    return Err(PairError::Refused);
                }
                let m = read(frame, true, T_WELCOME)?;
                cpace.verify(bytes(&m, 2)?).map_err(|_| PairError::WrongCode)?;
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
        let way = match (&self.invitation, self.matched.take()) {
            (Some(i), _) => Way::Invited(i),
            (None, Some(matched)) => Way::Home { matched, exporter: &self.exporter },
            (None, None) => return Err(PairError::Refused),
        };
        let (set, state) =
            w.check(&adb.group, &self.member, &self.own, self.joining, way).map_err(|_| PairError::Refused)?;
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
        commitment: [u8; 32],
        nonce: [u8; 32],
    },
    /// The joiner's Ta verified: message 67 waits for an approval.
    Approve {
        ex: MemberExchange,
        approved: Option<Approved>,
        shown: Option<MemberShown>,
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
    /// The invitation's attempt, on an open invitation.
    attempt: Option<u64>,
    info: Option<Info>,
    step: MemberStep,
}

/// What message 66 gave: at home the code to show and ask about; by an
/// invitation nothing to ask (the joiner's Ta approved message 67).
#[derive(Debug)]
pub struct Confirmed {
    pub code: Option<String>,
}

impl MemberSession {
    /// A session with the joiner whose key the TLS handshake proved: `own`
    /// is the member's TLS key, `adb` what message 65 says of the group
    /// and this member.
    pub fn new(own: [u8; 65], joiner: [u8; 65], adb: Adb, exporter: PairExporter) -> MemberSession {
        MemberSession { exporter, own, joiner, adb, attempt: None, info: None, step: MemberStep::Start }
    }

    /// The joiner's Info, once message 64 came.
    pub fn info(&self) -> Option<&Info> {
        self.info.as_ref()
    }

    /// Takes message 64 at home without an invitation: gives message 65.
    pub fn start_home(&mut self, frame: &[u8]) -> Result<Vec<u8>, PairError> {
        let nonce = invitation::not_zero(crate::certs::random_bytes);
        self.start(frame, Password::Home, nonce)
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
        let m = read(frame, false, T_START)?;
        let commitment = b32(&m, 4)?;
        let info = Info::decode(bytes(&m, 3)?).map_err(|_| PairError::Refused)?;
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
        let nonce = open.reply(number, commitment, now_ms)?;
        self.attempt = Some(number);
        let invitation = open.invitation.clone();
        self.start(frame, Password::Invitation(&invitation), nonce)
    }

    fn start(&mut self, frame: &[u8], password: Password<'_>, nonce: [u8; 32]) -> Result<Vec<u8>, PairError> {
        if !matches!(self.step, MemberStep::Start) {
            return Err(PairError::Refused);
        }
        let m = read(frame, false, T_START)?;
        let (ya, ada, commitment) = (bytes(&m, 2)?, bytes(&m, 3)?, b32(&m, 4)?);
        let info = Info::decode(ada).map_err(|_| PairError::Refused)?;
        if matches!(password, Password::Home) && info.invite.is_some() {
            return Err(PairError::Refused);
        }
        let adb = self.adb.encode();
        let (ex, yb) =
            MemberExchange::respond(password, &hash(&self.own), &self.joiner, &self.exporter, &adb, ya, ada)?;
        self.info = Some(info);
        self.step = MemberStep::Confirm { ex, commitment, nonce };
        Ok(write(T_REPLY, alloc::vec![(2, Value::Bytes(&yb)), (3, Value::Bytes(&adb)), (4, Value::Bytes(&nonce))]))
    }

    /// Takes message 66. A Ta that does not verify is
    /// [`PairError::WrongCode`] and ends the session.
    pub fn confirm(&mut self, frame: &[u8], open: Option<&mut Open>, now_ms: u64) -> Result<Confirmed, PairError> {
        let MemberStep::Confirm { mut ex, commitment, nonce } = core::mem::replace(&mut self.step, MemberStep::Over)
        else {
            return Err(PairError::Refused);
        };
        let m = read(frame, false, T_CONFIRM)?;
        let (ta, nj) = (bytes(&m, 2)?, b32(&m, 3)?);
        let by_secret = match ex.confirm(ta) {
            Ok(b) => b,
            Err(e) => {
                // A Ta that does not verify ends the invitation's attempt.
                if let (Some(n), Some(o)) = (self.attempt, open) {
                    o.end(n, false, now_ms);
                }
                return Err(e);
            }
        };
        match (self.attempt, open, by_secret) {
            // An invitation's secret: the verified Ta approves.
            (Some(_), Some(_), Some(approved)) => {
                self.step = MemberStep::Approve { ex, approved: Some(approved), shown: None };
                Ok(Confirmed { code: None })
            }
            // At home: the code, and the person's answer to come.
            (None, None, None) => {
                let (code, shown) = invitation::home_code(&commitment, &self.exporter, &nj, &nonce, &self.joiner)?;
                self.step = MemberStep::Approve { ex, approved: None, shown: Some(shown) };
                Ok(Confirmed { code: Some(code) })
            }
            (Some(n), Some(o), None) => {
                o.end(n, false, now_ms);
                Err(PairError::Refused)
            }
            _ => Err(PairError::Refused),
        }
    }

    /// The member's person answered the code shown at home. "They do not
    /// match" ends the session ([`PairError::Declined`]).
    pub fn answered(&mut self, matched: bool) -> Result<(), PairError> {
        let MemberStep::Approve { approved, shown, .. } = &mut self.step else { return Err(PairError::Refused) };
        let Some(s) = shown.take() else { return Err(PairError::Refused) };
        match approve::answered_at_home(s, matched) {
            Some(a) => {
                *approved = Some(a);
                Ok(())
            }
            None => {
                self.step = MemberStep::Over;
                Err(PairError::Declined)
            }
        }
    }

    /// Whether message 67 may go: the session is approved.
    pub fn approved(&self) -> bool {
        matches!(&self.step, MemberStep::Approve { approved: Some(_), .. })
    }

    /// Message 67 with the Welcome the caller built (its set already holds
    /// the joiner's record), then the parts that follow it.
    pub fn welcome(
        &mut self,
        w: &Welcome,
        parts: &[crate::records::sync::Part<'_>],
    ) -> Result<Vec<Vec<u8>>, PairError> {
        let MemberStep::Approve { ex, approved: Some(approved), .. } =
            core::mem::replace(&mut self.step, MemberStep::Over)
        else {
            return Err(PairError::Refused);
        };
        let mut out = alloc::vec![welcome::message(ex, approved, &w.encode())?];
        out.extend(parts.iter().map(welcome::part_message));
        self.step = MemberStep::Done;
        Ok(out)
    }

    /// Takes message 68: the joiner kept its identity. On an open
    /// invitation the attempt ends welcomed.
    pub fn done(&mut self, frame: &[u8], open: Option<&mut Open>, now_ms: u64) -> Result<(), PairError> {
        if !matches!(self.step, MemberStep::Done) {
            return Err(PairError::Refused);
        }
        read(frame, false, T_DONE)?;
        if let (Some(n), Some(o)) = (self.attempt, open) {
            o.end(n, true, now_ms);
            o.used = true;
        }
        self.step = MemberStep::Over;
        Ok(())
    }
}
