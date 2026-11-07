// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! Admitting a device (docs/protocol.md, section 6, "The joiner listens"):
//! the member's side of pairing, as an admin phone or the group's root
//! plays it, without I/O. The member dials a joiner that showed its QR
//! code, checks its certificate against the code's fingerprint, confirms
//! the code first, and sends the Welcome with a member certificate it
//! issued (crate::issue), and an admin CA when the root admits a phone that
//! offers an admin key.
//!
//! The program connects to one of the QR code's addresses, passes what
//! arrives to [`Admission::feed`] and sends what each step returns. Once a
//! step gives [`Outcome::Admitted`], the device counts as admitted: the
//! program adds the device record that [`device_record`] makes, whether or
//! not the joiner says it stored its identity.

use alloc::boxed::Box;
use alloc::collections::BTreeSet;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;

use p256::ecdsa::signature::Verifier as _;
use serde::{Deserialize, Serialize};

use crate::authority::{self, Body, Hash, Record};
use crate::certs::{self, Cert, DeviceId, KeyHash, b64};
use crate::error::{Context, Error, Result};
use crate::group::{ClaimTime, Records};
use crate::identity::{self, ExternalKey, Identity};
use crate::issue;
use crate::pair::{self, ADMIN_PROOF_LABEL, EXPORTER_LABEL, MAX_FRAME, MemberAd, Refusal};
use crate::third_party::cpace;
use crate::tls::{self, Clock, Exporter, Session};
use crate::wire;

/// What a Welcome leaves in its frame for the frame's other fields.
const WELCOME_ROOM: usize = 4 << 10;

/// The size of a key for sealed messages (an X-Wing public key).
pub const SEAL_KEY_SIZE: usize = 1216;

/// The systems of a phone with the app, which joins as a phone and may
/// become an admin.
pub const PHONE_SYSTEMS: [&str; 4] = ["ios", "android", "aurora", "sailfish"];

/// The joiner's description, its CPace associated data.
#[derive(Deserialize, Clone, Debug, PartialEq)]
pub struct Info {
    pub name: String,
    pub os: String,
    #[serde(default)]
    pub role: String,
    #[serde(with = "b64", default)]
    pub seal: Vec<u8>,
    #[serde(with = "b64", default)]
    pub admin_key: Vec<u8>,
    #[serde(with = "b64", default)]
    pub admin_proof: Vec<u8>,
}

impl Info {
    /// Whether it comes from a phone with the app.
    pub fn is_phone(&self) -> bool {
        PHONE_SYSTEMS.contains(&self.os.as_str())
    }

    /// Checks it as Go's member does: a known system, a valid name, a
    /// known role, a seal key of the right size, and an admin key only from
    /// a phone, a P-256 one, with its proof.
    fn check(&self) -> Result<()> {
        let known = ["linux", "windows", "macos"].contains(&self.os.as_str())
            || self.is_phone()
            || (self.os == "none" && self.role == "lite");
        if !known || !crate::command::valid_name(&self.name) || !(self.role.is_empty() || self.role == "lite") {
            return Err(Error::msg("the joining device's description is not valid"));
        }
        if !self.seal.is_empty() && self.seal.len() != SEAL_KEY_SIZE {
            return Err(Error::msg("the joining device's seal key is not valid"));
        }
        if self.admin_key.is_empty() != self.admin_proof.is_empty() {
            return Err(Error::msg("the joining device's admin key comes without its proof"));
        }
        if !self.admin_key.is_empty() && (!self.is_phone() || certs::p256_spki(&self.admin_key).is_none()) {
            return Err(Error::msg("only a phone offers an admin key, a P-256 one"));
        }
        Ok(())
    }

    /// Whether admin_proof is the admin key's signature over the label and
    /// the connection's sid.
    fn proves_admin_key(&self, sid: &[u8]) -> bool {
        let (Some(key), Ok(sig)) =
            (certs::p256_spki(&self.admin_key), p256::ecdsa::Signature::from_der(&self.admin_proof))
        else {
            return false;
        };
        let mut m = ADMIN_PROOF_LABEL.to_vec();
        m.extend_from_slice(sid);
        key.verify(&m, &sig).is_ok()
    }

    /// The admin key's point, SEC1 uncompressed.
    fn admin_point(&self) -> Option<Vec<u8>> {
        certs::p256_spki(&self.admin_key).map(|k| k.to_sec1_point(false).as_bytes().to_vec())
    }
}

/// What this member sends after the exchange.
#[derive(Serialize, Default)]
struct Welcome {
    #[serde(with = "b64")]
    cert: Vec<u8>,
    #[serde(with = "b64::opt", skip_serializing_if = "Option::is_none")]
    issuer: Option<Vec<u8>>,
    #[serde(with = "b64")]
    group_ca: Vec<u8>,
    #[serde(with = "b64::list", skip_serializing_if = "Vec::is_empty")]
    roots: Vec<Vec<u8>>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    records: Vec<Record>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    claim_times: Vec<ClaimTime>,
    #[serde(with = "b64::opt", skip_serializing_if = "Option::is_none")]
    admin_ca: Option<Vec<u8>>,
}

/// Every frame this member sends; each uses some of the fields.
#[derive(Serialize, Default)]
struct Out {
    #[serde(with = "b64::opt", skip_serializing_if = "Option::is_none")]
    msg: Option<Vec<u8>>,
    #[serde(with = "b64::opt", skip_serializing_if = "Option::is_none")]
    ad: Option<Vec<u8>>,
    #[serde(with = "b64::opt", skip_serializing_if = "Option::is_none")]
    tag: Option<Vec<u8>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    welcome: Option<Welcome>,
    #[serde(skip_serializing_if = "str::is_empty")]
    error: &'static str,
}

/// Every frame the joiner sends.
#[derive(Deserialize, Default)]
struct In {
    #[serde(with = "b64::opt", default)]
    msg: Option<Vec<u8>>,
    #[serde(with = "b64::opt", default)]
    ad: Option<Vec<u8>>,
    #[serde(with = "b64::opt", default)]
    tag: Option<Vec<u8>>,
    #[serde(default)]
    error: String,
    #[serde(default)]
    ok: bool,
}

/// The admitting member: its identity, which it dials with, and the CA it
/// issues with, its admin CA or the group's root, whose key ca_key holds.
#[derive(Clone)]
pub struct Admitter {
    pub identity: Identity,
    pub ca: Cert,
    pub ca_key: Arc<dyn ExternalKey>,
    /// The user opened this window to make the phone it admits an admin;
    /// only the root does, for a phone that offers an admin key.
    pub make_admins: bool,
}

impl Admitter {
    /// Whether it issues with the group's current root.
    pub fn is_root(&self) -> bool {
        self.ca == *self.identity.root()
    }

    /// The admin CA it issues with, when it is not the root.
    fn issuer(&self) -> Option<Vec<u8>> {
        (!self.is_root()).then(|| self.ca.der.clone())
    }

    fn sign(&self) -> impl FnMut(&[u8]) -> Result<Vec<u8>> + '_ {
        |tbs| identity::sign_external(&*self.ca_key, tbs)
    }
}

/// What the group's records give the exchange: the records and claim times
/// for the Welcome, the devices already in the group, and every admin key
/// the records name.
#[derive(Clone, Default)]
pub struct GroupView {
    pub records: Vec<Record>,
    pub claim_times: Vec<ClaimTime>,
    pub devices: BTreeSet<String>,
    pub admin_keys: BTreeSet<KeyHash>,
}

impl GroupView {
    /// The view of a set of records.
    pub fn of(rs: &Records) -> GroupView {
        let devices = rs.devices();
        GroupView {
            records: rs.all(),
            claim_times: rs.claim_times(),
            admin_keys: devices.iter().filter_map(|d| d.admin_key).collect(),
            devices: devices.into_iter().map(|d| d.id).collect(),
        }
    }
}

/// A device this member admitted.
#[derive(Clone, Debug)]
pub struct Admitted {
    pub device: DeviceId,
    pub info: Info,
    /// The member certificate it issued, DER.
    pub cert: Vec<u8>,
    /// The admin CA it issued for a phone's admin key, DER.
    pub admin_ca: Option<Vec<u8>>,
}

/// Where an admission is after a step.
pub enum Outcome {
    /// It waits for more from the joiner.
    Pending,
    /// The Welcome is out, and the device counts as admitted: the program
    /// adds its device record (device_record) and keeps feeding.
    Admitted(Box<Admitted>),
    /// The joiner answered the Welcome: whether it stored its identity.
    /// The admission is over.
    Done { confirmed: bool },
    /// The admission is over. wrong_code is set when the joiner did not
    /// know the code.
    Failed { error: Error, wrong_code: bool },
}

/// What a step gives: the bytes to send, then where the admission is.
pub struct Step {
    pub send: Vec<u8>,
    pub outcome: Outcome,
}

enum State {
    Handshake,
    First,
    Confirm { st: Box<cpace::State>, joiner: Joiner },
    Done,
    Over,
}

/// The joiner as the handshake gave it.
struct Joiner {
    device: DeviceId,
    point: Vec<u8>,
    info: Info,
}

/// One connection this member dialed to a joiner that listens.
pub struct Admission {
    session: Session,
    exporter: Arc<Exporter>,
    admitter: Admitter,
    view: GroupView,
    code: String,
    fingerprint: String,
    sid: [u8; 32],
    joiner_der: Vec<u8>,
    plain: Vec<u8>,
    state: State,
}

impl Admission {
    /// An admission for a connection the program is dialing to one of the
    /// QR code's addresses, with the QR code's code and fingerprint.
    pub fn dial(
        admitter: Admitter,
        view: GroupView,
        code: &str,
        fingerprint: &str,
        clock: &Clock,
    ) -> Result<Admission> {
        let code = pair::normalize_code(code)?;
        if fingerprint.is_empty() {
            return Err(Error::msg("the QR code names no device"));
        }
        if !admitter.ca.is_ca || !admitter.ca.cert_sign {
            return Err(Error::msg("this device is not an admin of the group"));
        }
        let (cfg, exporter) = tls::pair_admitter(&admitter.identity, clock)?;
        Ok(Admission {
            session: Session::client(Arc::new(cfg), tls::server_name(None))?,
            exporter,
            admitter,
            view,
            code,
            fingerprint: fingerprint.to_string(),
            sid: [0; 32],
            joiner_der: Vec::new(),
            plain: Vec::new(),
            state: State::Handshake,
        })
    }

    /// Takes what arrived on the connection (empty to get the TLS client
    /// hello and anything else that is due) and returns what to send and
    /// where the admission is. now_ms is the wall clock in Unix
    /// milliseconds: the certificates start from it.
    pub fn feed(&mut self, data: &[u8], now_ms: i64) -> Step {
        let outcome = match self.advance(data, now_ms) {
            Ok(o) => o,
            Err(error) => {
                self.state = State::Over;
                Outcome::Failed { error, wrong_code: false }
            }
        };
        if matches!(outcome, Outcome::Failed { .. } | Outcome::Done { .. }) {
            self.state = State::Over;
            let _ = self.session.close();
        }
        Step { send: self.session.take_outgoing(), outcome }
    }

    fn advance(&mut self, data: &[u8], now_ms: i64) -> Result<Outcome> {
        if matches!(self.state, State::Over) {
            return Err(Error::msg("the admission is over"));
        }
        if !data.is_empty() {
            self.session.feed(data)?;
        }
        if matches!(self.state, State::Handshake) {
            if self.session.is_handshaking() {
                return Ok(Outcome::Pending);
            }
            self.handshake_done()?;
            self.state = State::First;
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
            let f: In = serde_json::from_slice(&body).context("a frame is not a message")?;
            match core::mem::replace(&mut self.state, State::Over) {
                State::First => match self.first(f) {
                    Ok(next) => self.state = next,
                    Err(o) => return Ok(o),
                },
                State::Confirm { st, joiner } => return self.confirm(f, &st, joiner, now_ms),
                State::Done => {
                    return Ok(Outcome::Done { confirmed: f.ok });
                }
                State::Handshake | State::Over => return Err(Error::msg("the frames came out of order")),
            }
        }
        if self.session.peer_closed() {
            if matches!(self.state, State::Done) {
                return Ok(Outcome::Done { confirmed: false });
            }
            return Err(Error::msg("the other device closed the connection"));
        }
        Ok(Outcome::Pending)
    }

    /// Checks the joiner after the handshake, as Go's ClientTLS does: the
    /// pairing protocol, exactly one certificate, the QR code's
    /// fingerprint, a P-256 key and a device ID other than this one's.
    fn handshake_done(&mut self) -> Result<()> {
        if self.session.alpn_protocol() != Some(tls::PAIR_PROTOCOL) {
            return Err(Error::msg("the device does not offer pairing"));
        }
        let certs_in = self.session.peer_certificates().unwrap_or_default();
        let [der] = certs_in else {
            return Err(Error::msg("the joining device must send exactly one certificate"));
        };
        if certs::fingerprint(der) != self.fingerprint {
            return Err(Error::msg("the device is not the one in the QR code"));
        }
        self.joiner_der = der.to_vec();
        self.exporter
            .export(EXPORTER_LABEL, &[], &mut self.sid)
            .map_err(|e| Error::msg(format!("cannot bind the pairing to TLS: {e}")))?;
        Ok(())
    }

    /// Takes the joiner's first frame, its CPace message and description,
    /// and confirms the code first.
    fn first(&mut self, f: In) -> core::result::Result<State, Outcome> {
        let fail = |error: Error| Outcome::Failed { error, wrong_code: false };
        let cert = Cert::parse(&self.joiner_der).map_err(fail)?;
        let device = certs::DeviceId::parse(cert.common_name.as_deref().unwrap_or(""))
            .map_err(|_| fail(Error::msg("the joining device's certificate names no device ID")))?;
        if !cert.p256 {
            return Err(fail(Error::msg("the joining device's key is not a P-256 key")));
        }
        if device == self.admitter.identity.id {
            return Err(fail(Error::msg("the joining device has this member's own device ID")));
        }
        // A device picks its own ID, so one that is in the group already is
        // refused before the exchange.
        if self.view.devices.contains(device.as_str()) {
            self.send(&Out { error: "taken", ..Default::default() });
            return Err(fail(Error::with("the pairing failed", Refusal::Taken)));
        }
        let (Some(msg), Some(ad)) = (f.msg, f.ad) else {
            return Err(fail(Error::msg("the joining device sent a bad first frame")));
        };
        let info: Info = serde_json::from_slice(&ad)
            .map_err(|e| fail(Error::with("the joining device's description does not decode", e)))?;
        info.check().map_err(fail)?;
        let id = &self.admitter.identity;
        let my_ad = serde_json::to_vec(&MemberAd { device: id.id.to_string(), group: id.tag() })
            .map_err(|e| fail(Error::with("cannot encode this member's description", e)))?;
        let ci = pair::channel_id(&id.cert.der, &self.joiner_der);
        let started = cpace::start(&cpace::Config {
            role: cpace::Role::Responder,
            password: self.code.as_bytes(),
            channel_id: &ci,
            session_id: &self.sid,
            ad: &my_ad,
        });
        let (mut st, reply) = started.map_err(|_| fail(Error::msg("cannot start the exchange")))?;
        st.finish(&msg, &ad).map_err(|_| fail(Error::msg("the pairing failed")))?;
        self.send(&Out { msg: Some(reply), ad: Some(my_ad), tag: st.tag(), ..Default::default() });
        Ok(State::Confirm { st: Box::new(st), joiner: Joiner { device, point: cert.public_key().to_vec(), info } })
    }

    /// Takes the joiner's confirmation, then issues and sends the Welcome.
    fn confirm(&mut self, f: In, st: &cpace::State, joiner: Joiner, now_ms: i64) -> Result<Outcome> {
        if !f.error.is_empty() {
            // The joiner checks the code with the tag this side sent first:
            // its refusal is how a wrong code reaches the admin.
            let refusal = Refusal::of(&f.error);
            return Ok(Outcome::Failed {
                error: Error::with("the pairing failed", refusal),
                wrong_code: refusal == Refusal::WrongCode,
            });
        }
        if st.verify(&f.tag.unwrap_or_default()).is_err() {
            self.send(&Out { error: "wrong-code", ..Default::default() });
            return Ok(Outcome::Failed {
                error: Error::with("the pairing failed", Refusal::WrongCode),
                wrong_code: true,
            });
        }
        let info = &joiner.info;
        let a = &self.admitter;
        if !info.admin_key.is_empty() {
            // A phone that offers an admin key joins only through the root,
            // in a window opened to make an admin, with the proof that it
            // holds the key, and a key no device has yet.
            let why = if !a.is_root() {
                Some("a phone that asks to be an admin joins only through the group's root")
            } else if !a.make_admins {
                Some("the phone asks to be an admin; add it as an admin to admit it")
            } else if !info.proves_admin_key(&self.sid) {
                Some("the phone did not prove that it holds its admin key")
            } else if self.view.admin_keys.contains(&certs::sha256(&info.admin_key)) {
                Some("the phone's admin key belongs to another device")
            } else {
                None
            };
            if let Some(why) = why {
                self.send(&Out { error: "refused", ..Default::default() });
                return Err(Error::msg(why));
            }
        }
        let now = now_ms.div_euclid(1000);
        let cert = issue::member(&joiner.device, &joiner.point, &a.ca, now, &mut a.sign())?;
        let admin_ca = match info.admin_point() {
            Some(p) if !info.admin_key.is_empty() => {
                Some(issue::admin_ca(&joiner.device, &p, &a.ca, now, &mut a.sign())?)
            }
            _ => None,
        };
        let id = &a.identity;
        let mut w = Welcome {
            cert: cert.clone(),
            issuer: a.issuer(),
            group_ca: id.group_ca.der.clone(),
            roots: id.roots.iter().map(|c| c.der.clone()).collect(),
            records: self.view.records.clone(),
            claim_times: self.view.claim_times.clone(),
            admin_ca: admin_ca.clone(),
        };
        // A group never handed over leaves the records out when they do not
        // fit in a frame; the device gets them from its peers.
        let size = serde_json::to_vec(&w).map(|v| v.len()).unwrap_or(usize::MAX);
        if w.roots.is_empty() && size > MAX_FRAME.saturating_sub(WELCOME_ROOM) {
            w.records.clear();
            w.claim_times.clear();
        }
        self.send(&Out { welcome: Some(w), ..Default::default() });
        self.state = State::Done;
        Ok(Outcome::Admitted(Box::new(Admitted { device: joiner.device, info: joiner.info, cert, admin_ca })))
    }

    fn send(&mut self, f: &Out) {
        if let Ok(b) = wire::json_frame(f, MAX_FRAME) {
            let _ = self.session.write(&b);
        }
    }

    /// Takes the next whole frame's body from what arrived, if one is there.
    fn next_frame(&mut self) -> Result<Option<Vec<u8>>> {
        let Some(head) = self.plain.get(..4) else { return Ok(None) };
        let mut h = [0u8; 4];
        h.copy_from_slice(head);
        let end = wire::frame_len(h, MAX_FRAME)?.saturating_add(4);
        let Some(body) = self.plain.get(4..end).map(<[u8]>::to_vec) else { return Ok(None) };
        self.plain.drain(..end);
        Ok(Some(body))
    }
}

/// The device record for a device this member admitted, signed by the CA
/// key and ready to add to the records and send to the group: a phone as
/// a phone with a hardware key, an admin with its role's powers when it
/// got an admin CA; a computer as full, a lite member as lite. now_ms is
/// the wall clock in Unix milliseconds.
pub fn device_record(rs: &Records, admitter: &Admitter, a: &Admitted, now_ms: i64) -> Result<Record> {
    let cert = Cert::parse(&a.cert)?;
    let phone = a.info.is_phone();
    let admin = a.admin_ca.as_deref().map(Cert::parse).transpose()?.map(|c| Hash(c.key_hash()));
    let mut b = Body {
        v: 2,
        alg: authority::ALG_ES256.into(),
        kind: authority::TYPE_DEVICE.into(),
        signer: Hash(admitter.ca.key_hash()),
        time_ms: now_ms,
        device: a.device.to_string(),
        name: a.info.name.clone(),
        role: if phone {
            "phone".into()
        } else if a.info.role == "lite" {
            "lite".into()
        } else {
            "full".into()
        },
        os: a.info.os.clone(),
        key: Some(Hash(cert.key_hash())),
        store: if phone { "hardware".into() } else { String::new() },
        seal: a.info.seal.clone(),
        ..Default::default()
    };
    if admin.is_some() {
        b.admin = admin;
        b.powers = authority::POWERS.iter().map(|p| (*p).into()).collect();
        b.commands = authority::COMMANDS.iter().map(|c| (*c).into()).collect();
    }
    let body = rs.next_body(b)?;
    let sig = identity::sign_external(&*admitter.ca_key, &body)?;
    Ok(Record::new(body, sig, admitter.issuer()))
}

/// A group a phone makes for itself, with its root key held outside the
/// core (docs/protocol.md, section 3): the root CA, the phone's member
/// certificate under it, and its records, the phone's own device record
/// holding the root.
pub struct NewGroup {
    pub device: DeviceId,
    pub root: Cert,
    pub cert: Cert,
    pub records: Records,
}

/// The phone's own device in a group it makes: its name, system, member
/// key (a SEC1 point), where that key lives (`hardware` or `file`) and its
/// key for sealed messages.
pub struct OwnDevice<'a> {
    pub name: &'a str,
    pub os: &'a str,
    pub member_point: &'a [u8],
    pub store: &'a str,
    pub seal: Vec<u8>,
}

/// Makes a group whose root key is root_key, as the iPhone's
/// PhoneGroup.create does: a root CA, a member certificate for the
/// phone's member key, and the phone's device record, signed by the root.
pub fn new_group(root_key: &dyn ExternalKey, own: &OwnDevice, now_ms: i64) -> Result<NewGroup> {
    let now = now_ms.div_euclid(1000);
    let mut sign = |b: &[u8]| identity::sign_external(root_key, b);
    let root = Cert::parse(&issue::root_ca(&root_key.public(), now, &mut sign)?)?;
    let device = DeviceId::random();
    let cert = Cert::parse(&issue::member(&device, own.member_point, &root, now, &mut sign)?)?;
    let mut records = Records::new(&root);
    records.set_clock(move || now_ms);
    let b = Body {
        v: 2,
        alg: authority::ALG_ES256.into(),
        kind: authority::TYPE_DEVICE.into(),
        signer: Hash(root.key_hash()),
        time_ms: now_ms,
        device: device.to_string(),
        name: own.name.into(),
        role: "phone".into(),
        os: own.os.into(),
        key: Some(Hash(cert.key_hash())),
        store: own.store.into(),
        seal: own.seal.clone(),
        holds_root: true,
        ..Default::default()
    };
    let body = records.next_body(b)?;
    let sig = identity::sign_external(root_key, &body)?;
    if !records.add(&Record::new(body, sig, None)).map_err(|e| e.context("the phone's device record"))? {
        return Err(Error::msg("the group's first record was not taken"));
    }
    Ok(NewGroup { device, root, cert, records })
}

#[cfg(test)]
mod tests;
