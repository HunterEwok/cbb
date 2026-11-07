// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! Joining a group (docs/protocol.md, section 6): the joiner's side of the
//! pairing exchange, CPace and the Welcome, which runs inside TLS. This
//! module only decides; the program runs the TLS connection and passes the
//! frames (see [`Exchange`]).
//!
//! A lite member joins as a Mac does, without CA keys: either it listens and
//! shows a QR code that the phone app scans (the phone dials it and
//! confirms first), or it dials a Linux
//! member's open pairing window with the code that cbb pair shows.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::cell::RefCell;

use serde::{Deserialize, Serialize};

use crate::authority::Record;
use crate::certs::{self, Cert, DeviceId, b64};
use crate::error::{Context, Error, Result, Wrap};
use crate::group::{ClaimTime, Records};
use crate::identity::{self, ExternalKey, Identity};
use crate::third_party::cpace;
use crate::wire;

/// The TLS exporter label that binds the exchange to the connection.
pub const EXPORTER_LABEL: &[u8] = b"EXPERIMENTAL-cbb-pair-v2";
const CHANNEL_PREFIX: &[u8] = b"cbb pair v2\x00";
/// The largest frame of the exchange.
pub const MAX_FRAME: usize = 64 << 10;
/// How many wrong codes a listening join takes.
pub const MAX_FAILURES: u32 = 3;

/// The joiner's CPace associated data. The role tells the admitting member
/// that this is a lite member, which gets no CA keys and is listed as lite;
/// a phone has none.
#[derive(Serialize)]
struct Info<'a> {
    name: &'a str,
    os: &'a str,
    #[serde(skip_serializing_if = "str::is_empty")]
    role: &'a str,
    #[serde(with = "certs::b64", skip_serializing_if = "<[u8]>::is_empty")]
    seal: &'a [u8],
    /// A phone's admin key, a SubjectPublicKeyInfo, and its proof over the
    /// connection's sid, when it asks to be an admin.
    #[serde(with = "certs::b64", skip_serializing_if = "<[u8]>::is_empty")]
    admin_key: &'a [u8],
    #[serde(with = "certs::b64", skip_serializing_if = "<[u8]>::is_empty")]
    admin_proof: &'a [u8],
}

/// What a phone's admin key signs to prove it holds it, before the sid.
pub(crate) const ADMIN_PROOF_LABEL: &[u8] = b"cbb pairing admin key\x00";

/// The member's CPace associated data.
#[derive(Serialize, Deserialize)]
pub(crate) struct MemberAd {
    pub(crate) device: String,
    pub(crate) group: String,
}

/// What a new device receives after a successful exchange.
#[derive(Deserialize, Default)]
struct Welcome {
    #[serde(with = "b64", default)]
    cert: Vec<u8>,
    #[serde(with = "b64::opt", default)]
    issuer: Option<Vec<u8>>,
    #[serde(with = "b64", default)]
    group_ca: Vec<u8>,
    #[serde(with = "b64::list", default)]
    roots: Vec<Vec<u8>>,
    /// The records that lead to roots, by which the joiner checks them.
    #[serde(default)]
    records: Vec<Record>,
    /// When the member first held each claim of records.
    #[serde(default)]
    claim_times: Vec<ClaimTime>,
    /// The phone's admin CA for the admin key its info offered.
    #[serde(with = "b64::opt", default)]
    admin_ca: Option<Vec<u8>>,
}

/// Every frame of the exchange; each uses some of the fields.
#[derive(Serialize, Deserialize, Default)]
struct Frame {
    #[serde(with = "b64::opt", default, skip_serializing_if = "Option::is_none")]
    msg: Option<Vec<u8>>,
    #[serde(with = "b64::opt", default, skip_serializing_if = "Option::is_none")]
    ad: Option<Vec<u8>>,
    #[serde(with = "b64::opt", default, skip_serializing_if = "Option::is_none")]
    tag: Option<Vec<u8>>,
    #[serde(default, skip_serializing)]
    welcome: Option<Welcome>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    error: String,
    #[serde(default, skip_serializing_if = "core::ops::Not::not")]
    ok: bool,
}

/// Why a pairing failed, by the codes that travel in frames.
#[derive(Debug, PartialEq, Clone, Copy)]
pub enum Refusal {
    WrongCode,
    Closed,
    Busy,
    Expired,
    TooMany,
    Taken,
    Refused,
}

impl Refusal {
    /// The refusal a frame's error code names.
    pub fn of(code: &str) -> Refusal {
        match code {
            "wrong-code" => Refusal::WrongCode,
            "closed" => Refusal::Closed,
            "busy" => Refusal::Busy,
            "expired" => Refusal::Expired,
            "too-many" => Refusal::TooMany,
            "taken" => Refusal::Taken,
            _ => Refusal::Refused, // the peer's own words are never shown
        }
    }

    /// The code that travels in a frame.
    pub fn code(self) -> &'static str {
        match self {
            Refusal::WrongCode => "wrong-code",
            Refusal::Closed => "closed",
            Refusal::Busy => "busy",
            Refusal::Expired => "expired",
            Refusal::TooMany => "too-many",
            Refusal::Taken => "taken",
            Refusal::Refused => "refused",
        }
    }

    /// The message for the user.
    pub fn message(self) -> &'static str {
        match self {
            Refusal::WrongCode => "wrong code",
            Refusal::Closed => "the pairing window is closed",
            Refusal::Busy => "another device is pairing; try again in a minute",
            Refusal::Expired => "the pairing window expired",
            Refusal::TooMany => "three failed attempts; the pairing window is closed",
            Refusal::Taken => "the joining device's ID is in the group already; start the join again",
            Refusal::Refused => "the other device refused the pairing",
        }
    }
}

impl core::fmt::Display for Refusal {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.message())
    }
}

impl core::error::Error for Refusal {}

/// Returns the six digits of a code a user typed, without spaces and
/// dashes.
pub fn normalize_code(s: &str) -> Result<String> {
    let c: String = s.chars().filter(|c| *c != ' ' && *c != '-').collect();
    if c.len() != 6 || !c.bytes().all(|b| b.is_ascii_digit()) {
        return Err(Error::msg("the code is six digits"));
    }
    Ok(c)
}

/// A random six-digit code.
pub fn new_code() -> String {
    let n = u32::from_le_bytes(certs::random_bytes::<4>()) % 1_000_000;
    format!("{n:06}")
}

/// A device that joins: its new device ID, its key and the self-signed
/// certificate it pairs with.
#[derive(Clone)]
pub struct Joiner {
    pub id: DeviceId,
    /// The new device key, PKCS #8; empty when the key is external.
    pub key: Vec<u8>,
    /// The self-signed certificate it presents in the TLS handshake.
    pub cert: Vec<u8>,
    /// Its public key for sealed messages (crate::seal), which the info
    /// carries so that a phone that admits it records it at once; empty
    /// for none.
    pub seal: Vec<u8>,
    name: String,
    /// The system and role its info names: linux and lite for a lite
    /// member, a phone's system and no role for a phone.
    os: String,
    role: String,
    /// The device key when the core does not hold it.
    external: Option<Arc<dyn ExternalKey>>,
    /// A phone's admin key, which its info offers so that the root makes it
    /// an admin.
    admin: Option<Arc<dyn ExternalKey>>,
}

impl Joiner {
    /// A joiner with a new device ID and key; name is shown in the devices
    /// list.
    pub fn new(name: &str) -> Result<Joiner> {
        if !crate::command::valid_name(name) {
            return Err(Error::msg("the device name must be 1 to 64 bytes without control characters"));
        }
        let id = DeviceId::random();
        let key = identity::new_key()?;
        let cert =
            certs::self_signed(&id, &identity::signing_key(&key)?).wrap("cannot make the pairing certificate")?;
        Ok(Joiner {
            id,
            key,
            cert,
            seal: Vec::new(),
            name: name.to_string(),
            os: "linux".into(),
            role: "lite".into(),
            external: None,
            admin: None,
        })
    }

    /// A phone that joins with a key of its own hardware: a new device ID,
    /// the pairing certificate signed by key, and os, a phone's system
    /// (docs/protocol.md, section 6, ADa). It joins without an admin key,
    /// unless [`Joiner::offering_admin_key`] gives one.
    pub fn with_key(name: &str, os: &str, key: Arc<dyn ExternalKey>) -> Result<Joiner> {
        if !crate::command::valid_name(name) {
            return Err(Error::msg("the device name must be 1 to 64 bytes without control characters"));
        }
        if !matches!(os, "ios" | "android" | "aurora" | "sailfish") {
            return Err(Error::msg(format!("{os} is not a phone's system")));
        }
        let id = DeviceId::random();
        let cert = certs::self_signed_by(&id, &key.public(), &mut |tbs| identity::sign_external(&*key, tbs))
            .wrap("cannot make the pairing certificate")?;
        Ok(Joiner {
            id,
            key: Vec::new(),
            cert,
            seal: Vec::new(),
            name: name.to_string(),
            os: os.to_string(),
            role: String::new(),
            external: Some(key),
            admin: None,
        })
    }

    /// The joiner keeping its device key in the machine's hardware, as a
    /// computer's TPM: its pairing certificate and its handshakes are signed
    /// through key, and its identity holds key instead of a key of its own.
    pub fn holding_key(mut self, key: Arc<dyn ExternalKey>) -> Result<Joiner> {
        self.cert = certs::self_signed_by(&self.id, &key.public(), &mut |tbs| identity::sign_external(&*key, tbs))
            .wrap("cannot make the pairing certificate")?;
        self.key = Vec::new();
        self.external = Some(key);
        Ok(self)
    }

    /// The device joining as a computer with the service, a full member
    /// that may become an admin: no role, and its system.
    pub fn as_computer(mut self, os: &str) -> Joiner {
        self.role = String::new();
        self.os = os.into();
        self
    }

    /// The phone joining with an admin key too: only a window that may make
    /// admins, on the group's root or an admin phone, admits it, and its
    /// Welcome carries the admin CA for that key.
    pub fn offering_admin_key(mut self, key: Arc<dyn ExternalKey>) -> Result<Joiner> {
        if self.role == "lite" {
            return Err(Error::msg("a lite member is never an admin"));
        }
        self.admin = Some(key);
        Ok(self)
    }

    /// The device key when the core does not hold it.
    pub fn external_key(&self) -> Option<&Arc<dyn ExternalKey>> {
        self.external.as_ref()
    }

    /// The fingerprint of the joiner's certificate that the QR code carries.
    pub fn fingerprint(&self) -> String {
        certs::fingerprint(&self.cert)
    }

    /// Starts the exchange on a TLS connection whose handshake is done:
    /// member_der is the certificate the member presented, and sid the
    /// 32 bytes the connection exports for EXPORTER_LABEL. member_first is
    /// set when the member dialed this joiner, which showed its QR code:
    /// the member confirms first then, so a device that does not know the
    /// code learns nothing. Returns the exchange and the first frame to
    /// send.
    pub fn start(&self, code: &str, member_der: &[u8], sid: &[u8], member_first: bool) -> Result<(Exchange, Vec<u8>)> {
        let code = normalize_code(code)?;
        let member_cert = Cert::parse(member_der).wrap("the member's certificate")?;
        let ci = channel_id(member_der, &self.cert);
        let (admin_key, admin_proof) = match &self.admin {
            Some(k) => {
                let mut m = ADMIN_PROOF_LABEL.to_vec();
                m.extend_from_slice(sid);
                let proof = identity::sign_external(&**k, &m).wrap("the admin key did not sign")?;
                (certs::p256_spki_of(&k.public()), proof)
            }
            None => (Vec::new(), Vec::new()),
        };
        let ad = serde_json::to_vec(&Info {
            name: &self.name,
            os: &self.os,
            role: &self.role,
            seal: &self.seal,
            admin_key: &admin_key,
            admin_proof: &admin_proof,
        })
        .context("cannot encode the joiner's info")?;
        let (st, msg) = cpace::start(&cpace::Config {
            role: cpace::Role::Initiator,
            password: code.as_bytes(),
            channel_id: &ci,
            session_id: sid,
            ad: &ad,
        })
        .context("cannot start the exchange")?;
        let first = frame(&Frame { msg: Some(msg), ad: Some(ad), ..Default::default() })?;
        Ok((
            Exchange {
                joiner: self.clone(),
                st,
                member_cert,
                member_first,
                member: None,
                records: RefCell::new(Vec::new()),
                claim_times: RefCell::new(Vec::new()),
                admin_ca: RefCell::new(None),
            },
            first,
        ))
    }
}

/// The joiner's side of one exchange. The program sends the frame start
/// returned, passes the member's reply to [`Exchange::reply`] and sends what
/// it returns, passes the member's last frame to [`Exchange::welcome`],
/// stores the identity it returns, and sends [`done`] with whether it
/// could. A [`Failure`] may carry a frame to send before closing.
pub struct Exchange {
    joiner: Joiner,
    st: cpace::State,
    member_cert: Cert,
    member_first: bool,
    member: Option<MemberAd>,
    /// The records the Welcome gave that lead to the group's roots, once
    /// welcome took it: the program keeps them with the identity.
    records: RefCell<Vec<Record>>,
    /// When the joiner holds each claim of records from, the member's times
    /// where they are earlier.
    claim_times: RefCell<Vec<ClaimTime>>,
    /// The admin CA the Welcome gave for the phone's admin key.
    admin_ca: RefCell<Option<Vec<u8>>>,
}

/// A failed step: the error, and the frame that tells the member, if any.
#[derive(Debug)]
pub struct Failure {
    pub error: Error,
    pub send: Option<Vec<u8>>,
}

impl From<Error> for Failure {
    fn from(error: Error) -> Failure {
        Failure { error, send: None }
    }
}

impl Exchange {
    /// Takes the member's reply, a frame's JSON, and returns the frame
    /// with this joiner's confirmation.
    pub fn reply(&mut self, body: &[u8]) -> core::result::Result<Vec<u8>, Failure> {
        let reply: Frame = decode(body)?;
        if !reply.error.is_empty() {
            return Err(Error::with("the pairing failed", Refusal::of(&reply.error)).into());
        }
        let peer_ad = reply.ad.unwrap_or_default();
        self.st.finish(&reply.msg.unwrap_or_default(), &peer_ad).context("the pairing failed")?;
        let member: MemberAd = serde_json::from_slice(&peer_ad).context("the member's description does not decode")?;
        if self.member_first && self.st.verify(&reply.tag.unwrap_or_default()).is_err() {
            return Err(Failure {
                error: Error::with("the pairing failed", Refusal::WrongCode),
                send: frame(&Frame { error: "wrong-code".into(), ..Default::default() }).ok(),
            });
        }
        self.member = Some(member);
        Ok(frame(&Frame { tag: self.st.tag(), ..Default::default() })?)
    }

    /// Takes the member's last frame, which carries the Welcome, and
    /// returns the new identity for the program to store. If it fails, the
    /// program sends done(false). now_ms is the wall clock, in Unix
    /// milliseconds, or 0 when the device has none: it then takes none of
    /// the member's times for the claims, and a root a claim made only by
    /// waiting does not count yet.
    pub fn welcome(&self, body: &[u8], now_ms: i64) -> Result<Identity> {
        let member =
            self.member.as_ref().ok_or_else(|| Error::msg("the pairing failed: the frames came out of order"))?;
        let last: Frame = decode(body)?;
        if !last.error.is_empty() {
            return Err(Error::with("the pairing failed", Refusal::of(&last.error)));
        }
        let proved = self.member_first || last.tag.as_deref().is_some_and(|t| self.st.verify(t).is_ok());
        let Some(welcome) = last.welcome.filter(|_| proved) else {
            return Err(Error::msg("the other device did not prove that it knows the code"));
        };
        self.identity(&welcome, member, now_ms)
    }

    /// The records that lead to the group's roots, from the Welcome that
    /// welcome took; the program saves them before the identity.
    pub fn records(&self) -> Vec<Record> {
        self.records.borrow().clone()
    }

    /// When the joiner first held each claim of records, sorted by record.
    pub fn claim_times(&self) -> Vec<ClaimTime> {
        self.claim_times.borrow().clone()
    }

    /// The admin CA for the phone's admin key, DER, once welcome took a
    /// Welcome that made it an admin; the program keeps it with the
    /// identity.
    pub fn admin_ca(&self) -> Option<Vec<u8>> {
        self.admin_ca.borrow().clone()
    }

    /// Checks what the member sent and builds the new identity.
    fn identity(&self, w: &Welcome, member: &MemberAd, now_ms: i64) -> Result<Identity> {
        let member_cert = &self.member_cert;
        let group_ca = Cert::parse(&w.group_ca).wrap("the group CA")?;
        if certs::tag(&group_ca) != member.group {
            return Err(Error::msg("the member sent another group CA than it announced"));
        }
        // The roots are only those the records lead to: an admin could
        // otherwise name a root of its own, and every certificate from it
        // would pass here for good, whatever the group's root removes.
        let mut path = Records::new(&group_ca);
        path.set_clock(move || now_ms);
        let _ = path.add_all(&w.records);
        path.take_claim_times(&w.claim_times);
        let roots = path.roots();
        if roots.iter().map(|c| &c.der).ne(w.roots.iter()) {
            return Err(Error::msg("the member's roots are not the ones the group's records lead to"));
        }
        *self.records.borrow_mut() = path.all();
        *self.claim_times.borrow_mut() = path.claim_times();
        let mut id = Identity {
            id: self.joiner.id.clone(),
            key: self.joiner.key.clone(),
            external: self.joiner.external.clone(),
            cert: Cert::parse(&w.cert).wrap("the new member certificate")?,
            issuer: None,
            group_ca,
            roots,
        };
        // An admin issues with its admin CA, under one of the group's roots.
        let mut issuers = id.trusted();
        if let Some(der) = &w.issuer {
            let issuer = Cert::parse(der).wrap("the member's issuer")?;
            if !issuers.iter().any(|root| certs::check_admin_ca(&issuer, root).is_ok()) {
                return Err(Error::msg("the member's issuer is not under a root of the group"));
            }
            issuers.insert(0, issuer.clone());
            id.issuer = Some(issuer);
        }
        // The member's own certificate is from that CA, or from a root, and
        // names the device it announced.
        if !issuers.iter().any(|i| member_cert.signed_by(i)) {
            return Err(Error::msg("the member's certificate is not from the group CA"));
        }
        if certs::device_of(member_cert).map(|d| d.to_string()).ok().as_deref() != Some(member.device.as_str()) {
            return Err(Error::msg("the member's certificate does not name the member"));
        }
        match &self.joiner.external {
            Some(key) => id.check_key(&key.public())?,
            None => id.check()?,
        }
        *self.admin_ca.borrow_mut() = match (&w.admin_ca, &self.joiner.admin) {
            (None, _) => None,
            (Some(_), None) => {
                return Err(Error::msg("the member sent an admin CA, and this device offered no admin key"));
            }
            (Some(der), Some(key)) => {
                let ca = Cert::parse(der).wrap("the admin CA")?;
                certs::check_admin_ca(&ca, id.root()).wrap("the admin CA")?;
                if ca.public_key() != key.public().as_slice()
                    || ca.common_name.as_deref() != Some(format!("cbb admin {}", id.id).as_str())
                {
                    return Err(Error::msg("the admin CA is not for this phone's admin key"));
                }
                Some(der.clone())
            }
        };
        Ok(id)
    }
}

/// The joiner's last frame: ok once it stored its identity (the member
/// admitted the device when it sent the Welcome, whether or not it hears
/// this), refused otherwise.
#[allow(clippy::expect_used, reason = "a frame of a flag or a short word always encodes and fits")]
pub fn done(ok: bool) -> Vec<u8> {
    let f = if ok {
        Frame { ok: true, ..Default::default() }
    } else {
        Frame { error: "refused".into(), ..Default::default() }
    };
    frame(&f).expect("a small frame encodes")
}

fn frame(f: &Frame) -> Result<Vec<u8>> {
    wire::json_frame(f, MAX_FRAME)
}

fn decode(body: &[u8]) -> Result<Frame> {
    serde_json::from_slice(body).context("a frame is not a message")
}

/// The CPace channel identifier for the two certificates, the member's
/// first.
pub fn channel_id(member_cert: &[u8], joiner_cert: &[u8]) -> Vec<u8> {
    let mut ci = CHANNEL_PREFIX.to_vec();
    ci.extend_from_slice(&certs::sha256(member_cert));
    ci.extend_from_slice(&certs::sha256(joiner_cert));
    ci
}

/// The text of the join QR code, as Go's phone.JoinQR writes it.
pub fn join_qr(code: &str, addrs: &[String], fingerprint: &str) -> String {
    let mut text = format!("cbb://join?code={}", query_escape(code));
    for a in addrs {
        text.push_str(&format!("&addr={}", query_escape(a)));
    }
    if !fingerprint.is_empty() {
        text.push_str(&format!("&fp={}", query_escape(fingerprint)));
    }
    text
}

/// What a join QR code carries: the code, the joiner's addresses
/// (host:port) and its certificate's fingerprint.
#[derive(Debug, PartialEq, Clone)]
pub struct JoinLink {
    pub code: String,
    pub addrs: Vec<String>,
    pub fingerprint: String,
}

/// The most addresses a join QR code's reader takes.
pub const MAX_ADDRS: usize = 4;

/// Reads the text of a join QR code, as join_qr writes it: a cbb://join
/// link with a six-digit code, up to MAX_ADDRS addresses and the
/// fingerprint.
pub fn parse_join_qr(text: &str) -> Result<JoinLink> {
    let bad = || Error::msg("this is not a CBB join code");
    let query = text.trim().strip_prefix("cbb://join?").ok_or_else(bad)?;
    let mut link = JoinLink { code: String::new(), addrs: Vec::new(), fingerprint: String::new() };
    for item in query.split('&') {
        let (k, v) = item.split_once('=').unwrap_or((item, ""));
        let v = query_unescape(v).ok_or_else(bad)?;
        match k {
            "code" => link.code = normalize_code(&v)?,
            "addr" if link.addrs.len() < MAX_ADDRS && !v.is_empty() => link.addrs.push(v),
            "fp" => link.fingerprint = v,
            _ => {}
        }
    }
    if link.code.is_empty() || link.addrs.is_empty() || link.fingerprint.is_empty() {
        return Err(bad());
    }
    Ok(link)
}

/// Decodes the %XX escapes of a query value, as Go's ParseJoinQR and the
/// phone kits do: never a '+' as a space, since a fingerprint's base64 may
/// hold one. None for text that is not UTF-8 or a bad escape.
fn query_unescape(s: &str) -> Option<String> {
    let mut out = Vec::with_capacity(s.len());
    let mut bytes = s.bytes();
    while let Some(b) = bytes.next() {
        match b {
            b'%' => {
                let hex = [bytes.next()?, bytes.next()?];
                out.push(u8::from_str_radix(core::str::from_utf8(&hex).ok()?, 16).ok()?);
            }
            _ => out.push(b),
        }
    }
    String::from_utf8(out).ok()
}

/// Escapes s for a URL query as Go's url.QueryEscape does.
fn query_escape(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => out.push(b as char),
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// Decodes the frames of testdata/interop/pairing.json as a lite member
/// reads them, and encodes those it writes the same way.
#[cfg(test)]
pub fn check_frames_for_tests(frames: &[serde_json::Value]) {
    let decoded: Vec<Frame> = frames.iter().map(|f| serde_json::from_value(f.clone()).unwrap()).collect();
    // The joiner's first frame: its AD is the device info.
    let info: serde_json::Value = serde_json::from_slice(decoded[0].ad.as_deref().unwrap()).unwrap();
    assert_eq!(info["os"], "linux");
    assert_eq!(serde_json::to_value(&decoded[0]).unwrap(), frames[0]);
    // The member's AD names the device and the group.
    let member: MemberAd = serde_json::from_slice(decoded[1].ad.as_deref().unwrap()).unwrap();
    assert!(certs::is_id(&member.device));
    assert_eq!(member.group.len(), 16);
    assert!(decoded[1].tag.is_some() && decoded[2].tag.is_some());
    assert_eq!(serde_json::to_value(&decoded[2]).unwrap(), frames[2]);
    // A plain Welcome, and one from an admin of a group handed over.
    let plain = decoded[3].welcome.as_ref().unwrap();
    assert!(!plain.cert.is_empty() && !plain.group_ca.is_empty() && plain.issuer.is_none());
    let admin = decoded[4].welcome.as_ref().unwrap();
    assert!(admin.issuer.is_some() && admin.roots.len() == 1);
    assert_eq!(Refusal::of(&decoded[5].error), Refusal::WrongCode);
    assert!(decoded[6].ok);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes() {
        assert_eq!(normalize_code(" 123-456 ").unwrap(), "123456");
        assert!(normalize_code("12345").is_err());
        assert!(normalize_code("12345a").is_err());
        assert_eq!(new_code().len(), 6);
    }

    #[test]
    fn qr_text_as_go_writes_it() {
        let text = join_qr(
            "246802",
            &["192.168.1.20:8767".into(), "[fd00::5]:8767".into()],
            "qFnj7Uv+CE/WNnna2IEmMaLbkA6tHcKf0VijTRzekKA=",
        );
        assert_eq!(
            text,
            "cbb://join?code=246802&addr=192.168.1.20%3A8767&addr=%5Bfd00%3A%3A5%5D%3A8767&fp=qFnj7Uv%2BCE%2FWNnna2IEmMaLbkA6tHcKf0VijTRzekKA%3D"
        );
    }

    #[test]
    fn qr_text_read_back() {
        let addrs: Vec<String> = vec!["192.168.1.20:8767".into(), "[fd00::5]:8767".into()];
        let text = join_qr("246802", &addrs, "qFnj7Uv+CE/WNnna2IEmMaLbkA6tHcKf0VijTRzekKA=");
        let link = parse_join_qr(&text).unwrap();
        assert_eq!(link.code, "246802");
        assert_eq!(link.addrs, addrs);
        assert_eq!(link.fingerprint, "qFnj7Uv+CE/WNnna2IEmMaLbkA6tHcKf0VijTRzekKA=");
        // A '+' stays one, as Go's ParseJoinQR reads it.
        assert_eq!(parse_join_qr("cbb://join?code=246802&addr=a:1&fp=ab+c").unwrap().fingerprint, "ab+c");
        assert!(parse_join_qr("https://example.com/?code=246802").is_err());
        assert!(parse_join_qr("cbb://join?code=246802&fp=x").is_err());
        assert!(parse_join_qr("cbb://join?code=246802&addr=a:1&fp=%zz").is_err());
    }

    #[test]
    fn the_joiner_certificate() {
        let j = Joiner::new("router").unwrap();
        let c = Cert::parse(&j.cert).unwrap();
        assert_eq!(c.common_name.as_deref(), Some(j.id.as_str()));
        assert!(c.p256);
        assert_eq!(j.fingerprint().len(), 44);
    }
}
