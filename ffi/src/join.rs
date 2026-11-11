// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! A phone that joins a group by its QR code with a key the core does not
//! hold (the Aurora app's key in OP-TEE), as C functions beside `cbb_call`
//! (include/cbb_core.h): the joiner listens, shows the QR code these
//! functions give, and passes each connection's bytes through
//! cbb_core::pair_session, which runs the pairing inside the core's TLS and
//! asks the app's callback for each signature. The app does the sockets.
//! With a remote invitation in place of the QR code (docs/protocol.md,
//! section 12), the joiner starts the invitation's guest tunnel, the app
//! dials its loopback port, and the attempt proves the invitation's secret
//! to the hub's admin.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use cbb_core::certs::{self, Cert};
use cbb_core::error::{Error, Result};
use cbb_core::group::Records;
use cbb_core::identity::ExternalKey;
use cbb_core::pair::{self, Joiner};
use cbb_core::pair_session::{Attempt, Outcome};
use cbb_core::tls::Clock;
use cbb_core::tls::rustls::pki_types::UnixTime;
use cbb_core::tls::rustls::time_provider::TimeProvider;
use serde::{Deserialize, Serialize};

/// The app's signing callback: ECDSA P-256 over the 32-byte digest, DER,
/// written to sig (72 bytes of room) with its length in sig_len; 0 when it
/// signed.
pub type SignFn =
    unsafe extern "C" fn(ctx: *mut core::ffi::c_void, digest: *const u8, sig: *mut u8, sig_len: *mut usize) -> i32;

/// The app's events' callback: JSON at event, len bytes, on any thread.
pub type EventFn = unsafe extern "C" fn(ctx: *mut core::ffi::c_void, event: *const u8, len: usize);

/// The largest DER signature of P-256.
const MAX_SIG: usize = 72;

pub(crate) struct AppKey {
    pub(crate) public: Vec<u8>,
    pub(crate) sign: SignFn,
    pub(crate) ctx: usize,
}

impl ExternalKey for AppKey {
    fn public(&self) -> Vec<u8> {
        self.public.clone()
    }

    fn sign_digest(&self, digest: &[u8; 32]) -> Result<Vec<u8>> {
        let mut sig = [0u8; MAX_SIG];
        let mut n = 0usize;
        // SAFETY: the app gave a callback for the joiner's lifetime that
        // reads 32 bytes at digest and writes at most MAX_SIG at sig.
        let rc = unsafe { (self.sign)(self.ctx as *mut core::ffi::c_void, digest.as_ptr(), sig.as_mut_ptr(), &mut n) };
        match sig.get(..n) {
            Some(s) if rc == 0 && n > 0 => Ok(s.to_vec()),
            _ => Err(Error::msg(format!("the device key did not sign (code {rc})"))),
        }
    }
}

#[derive(Debug)]
struct SystemClock;

impl TimeProvider for SystemClock {
    fn current_time(&self) -> Option<UnixTime> {
        Some(UnixTime::since_unix_epoch(Duration::from_millis(wall_ms().max(0).unsigned_abs())))
    }
}

/// The system's clock, for the core's TLS.
pub(crate) fn clock() -> Clock {
    Arc::new(SystemClock)
}

pub(crate) fn wall_ms() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| i64::try_from(d.as_millis()).unwrap_or(0)).unwrap_or(0)
}

/// A joiner that listens, with its current attempt.
pub struct Join {
    joiner: Joiner,
    code: String,
    clock: Clock,
    attempt: Option<Attempt>,
    /// A remote invitation's secret, in place of the code.
    secret: Option<Vec<u8>>,
    /// The invitation's guest tunnel, whose loopback port the app dials.
    #[cfg(feature = "tunnel")]
    guest: Option<cbb_lite::phone::GuestTunnel>,
    /// The mDNS announcement while the app listens (`announce`).
    #[cfg(feature = "member")]
    announced: Option<cbb_lite::discovery::Announcement>,
}

#[derive(Deserialize)]
struct NewArgs {
    name: String,
    os: String,
    /// The key's public point, SEC1 uncompressed.
    #[serde(with = "certs::b64")]
    public: Vec<u8>,
    /// The admin key's public point, SEC1 uncompressed, for a phone that
    /// asks to be an admin (cbb_join_new_admin).
    #[serde(with = "certs::b64::opt", default)]
    admin_public: Option<Vec<u8>>,
    /// Its public key for sealed messages, optional.
    #[serde(with = "certs::b64", default)]
    seal: Vec<u8>,
    /// The addresses for the QR code, host:port.
    #[serde(default)]
    addrs: Vec<String>,
    /// The six-digit code, or a new one when absent.
    #[serde(default)]
    code: String,
    /// A remote invitation's text, cbb://invite#..., to join by in place
    /// of a QR code.
    #[serde(default)]
    invite: String,
}

#[derive(Serialize)]
struct NewAnswer {
    device: String,
    code: String,
    fingerprint: String,
    /// The QR code's text and its modules, a row of '1' and '0' each.
    qr: String,
    modules: Vec<String>,
    /// With an invitation: the loopback port of its guest tunnel, which the
    /// app dials for each attempt.
    #[serde(skip_serializing_if = "is_zero")]
    port: u16,
}

fn is_zero(n: &u16) -> bool {
    *n == 0
}

#[derive(Serialize)]
struct FeedAnswer {
    #[serde(with = "certs::b64")]
    send: Vec<u8>,
    /// pending, joined or failed.
    state: &'static str,
    #[serde(skip_serializing_if = "core::ops::Not::not")]
    wrong_code: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    joined: Option<JoinedAnswer>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<ErrorAnswer>,
}

#[derive(Serialize)]
struct JoinedAnswer {
    device: String,
    #[serde(with = "certs::b64")]
    cert: Vec<u8>,
    #[serde(with = "certs::b64::opt")]
    issuer: Option<Vec<u8>>,
    #[serde(with = "certs::b64")]
    group_ca: Vec<u8>,
    #[serde(with = "certs::b64::list")]
    roots: Vec<Vec<u8>>,
    /// The records file (docs/core-api.md, "The record set").
    #[serde(with = "certs::b64")]
    records: Vec<u8>,
    /// The admin CA for the admin key, when the member made the phone an
    /// admin.
    #[serde(with = "certs::b64::opt", skip_serializing_if = "Option::is_none")]
    admin_ca: Option<Vec<u8>>,
}

#[derive(Clone, Serialize)]
pub(crate) struct ErrorAnswer {
    message: String,
    details: String,
}

impl ErrorAnswer {
    pub(crate) fn of(e: &Error) -> ErrorAnswer {
        ErrorAnswer { message: e.to_string(), details: e.details() }
    }
}

pub(crate) fn answer<T: Serialize>(ok: Result<T>) -> Vec<u8> {
    let v = match ok {
        Ok(v) => serde_json::json!({ "ok": v }),
        Err(e) => serde_json::json!({ "error": ErrorAnswer::of(&e) }),
    };
    serde_json::to_vec(&v)
        .unwrap_or_else(|_| br#"{"error":{"message":"cannot encode the answer","details":""}}"#.to_vec())
}

impl Join {
    /// A joiner from the app's request (NewArgs) and its key's callback,
    /// with its answer.
    /// With admin, the admin key's callback and its context, the phone
    /// offers the admin key the request names.
    pub fn new(request: &[u8], sign: SignFn, ctx: usize, admin: Option<(SignFn, usize)>) -> (Option<Join>, Vec<u8>) {
        let made = (|| -> Result<(Join, NewAnswer)> {
            let a: NewArgs = serde_json::from_slice(request)
                .map_err(|e| Error::msg(format!("the join request does not decode: {e}")))?;
            let key = Arc::new(AppKey { public: a.public, sign, ctx });
            let mut joiner = Joiner::with_key(&a.name, &a.os, key)?;
            match (admin, a.admin_public) {
                (Some((sign, ctx)), Some(public)) => {
                    joiner = joiner.offering_admin_key(Arc::new(AppKey { public, sign, ctx }))?;
                }
                (None, None) => {}
                _ => return Err(Error::msg("the admin key needs both its public key and its callback")),
            }
            joiner.seal = a.seal;
            if !a.invite.is_empty() {
                return Join::invited(joiner, &a.invite);
            }
            let code = if a.code.is_empty() { pair::new_code() } else { pair::normalize_code(&a.code)? };
            let qr = pair::join_qr(&code, &a.addrs, &joiner.fingerprint());
            let modules = modules(&qr)?;
            let ans = NewAnswer {
                device: joiner.id.to_string(),
                code: code.clone(),
                fingerprint: joiner.fingerprint(),
                qr,
                modules,
                port: 0,
            };
            Ok((
                Join {
                    joiner,
                    code,
                    clock: clock(),
                    attempt: None,
                    secret: None,
                    #[cfg(feature = "tunnel")]
                    guest: None,
                    #[cfg(feature = "member")]
                    announced: None,
                },
                ans,
            ))
        })();
        match made {
            Ok((j, ans)) => (Some(j), answer(Ok(ans))),
            Err(e) => (None, answer::<()>(Err(e))),
        }
    }

    /// A joiner by the remote invitation text: its guest tunnel starts
    /// now, and the answer names its loopback port.
    #[cfg(feature = "tunnel")]
    fn invited(joiner: Joiner, text: &str) -> Result<(Join, NewAnswer)> {
        let inv = cbb_core::invite::parse(text).map_err(|r| Error::msg(r.message()))?;
        if inv.expired(wall_ms() / 1000) {
            return Err(Error::msg("the invitation has expired; ask for a new one"));
        }
        let guest = cbb_lite::phone::GuestTunnel::start(&inv, Arc::new(|_: &str| {}))?;
        let ans = NewAnswer {
            device: joiner.id.to_string(),
            code: String::new(),
            fingerprint: joiner.fingerprint(),
            qr: String::new(),
            modules: Vec::new(),
            port: guest.port(),
        };
        let j = Join {
            joiner,
            code: String::new(),
            clock: clock(),
            attempt: None,
            secret: Some(inv.secret.clone()),
            guest: Some(guest),
            #[cfg(feature = "member")]
            announced: None,
        };
        Ok((j, ans))
    }

    #[cfg(not(feature = "tunnel"))]
    fn invited(_joiner: Joiner, _text: &str) -> Result<(Join, NewAnswer)> {
        Err(Error::msg("this build has no tunnel: it cannot join by an invitation"))
    }

    /// Announces the joiner by mDNS while the app listens on port, so that
    /// a computer of the group finds it by the code typed there
    /// (docs/protocol.md, section 6); false when mDNS is not at hand. The
    /// announcement ends when the joiner is freed.
    #[cfg(feature = "member")]
    pub fn announce(&mut self, port: u16) -> bool {
        self.announced = cbb_lite::discovery::announce_joiner(&self.joiner.id, port, &self.joiner.fingerprint());
        self.announced.is_some()
    }

    /// Starts an attempt for a connection the app accepted, ending the one
    /// before; with an invitation, for a connection the app dialed to the
    /// guest tunnel's port, and the answer's send is the TLS client hello.
    pub fn accept(&mut self) -> Vec<u8> {
        #[derive(Serialize)]
        struct Started {
            #[serde(with = "certs::b64")]
            send: Vec<u8>,
        }
        let made = match &self.secret {
            Some(secret) => Attempt::dialing_secret(&self.joiner, secret, &self.clock),
            None => Attempt::listening(&self.joiner, &self.code, &self.clock),
        };
        answer(made.map(|mut a| {
            let send = if self.secret.is_some() { a.feed(&[], wall_ms()).send } else { Vec::new() };
            self.attempt = Some(a);
            Started { send }
        }))
    }

    /// Whether the invitation's hub has answered through the guest tunnel,
    /// for the app's message when an attempt fails: a hub that never
    /// answered is off, or its port cannot be reached.
    pub fn answered(&self) -> bool {
        #[cfg(feature = "tunnel")]
        if let Some(g) = &self.guest {
            return g.answered();
        }
        false
    }

    /// Takes what arrived on the attempt's connection.
    pub fn feed(&mut self, data: &[u8], now_ms: i64) -> Vec<u8> {
        let Some(att) = self.attempt.as_mut() else {
            return answer::<()>(Err(Error::msg("no connection to feed: accept one first")));
        };
        let now = if now_ms == 0 { wall_ms() } else { now_ms };
        let step = att.feed(data, now);
        let (state, wrong_code, joined, error) = match step.outcome {
            Outcome::Pending => ("pending", false, None, None),
            Outcome::Failed { error, wrong_code } => ("failed", wrong_code, None, Some(ErrorAnswer::of(&error))),
            Outcome::Joined(j) => match joined_answer(&j, now) {
                Ok(a) => ("joined", false, Some(a), None),
                Err(e) => ("failed", false, None, Some(ErrorAnswer::of(&e))),
            },
        };
        answer(Ok(FeedAnswer { send: step.send, state, wrong_code, joined, error }))
    }

    /// Ends a joined attempt, saved telling the member whether the app
    /// stored it.
    pub fn finish(&mut self, saved: bool) -> Vec<u8> {
        let Some(mut att) = self.attempt.take() else {
            return answer::<()>(Err(Error::msg("no attempt to finish")));
        };
        #[derive(Serialize)]
        struct Last {
            #[serde(with = "certs::b64")]
            send: Vec<u8>,
        }
        answer(Ok(Last { send: att.finish(saved) }))
    }
}

#[derive(Deserialize)]
struct NewGroupArgs {
    /// The phone's name and system, as for a join.
    name: String,
    os: String,
    /// Where the member key lives: `hardware` or `file`.
    store: String,
    /// The root key's public point, SEC1 uncompressed: the key whose
    /// callback signs.
    #[serde(with = "certs::b64")]
    root_public: Vec<u8>,
    /// The member key's public point, SEC1 uncompressed.
    #[serde(with = "certs::b64")]
    public: Vec<u8>,
    #[serde(with = "certs::b64", default)]
    seal: Vec<u8>,
}

/// A group the phone makes with its root key (cbb_core::admit::new_group),
/// from the app's request (NewGroupArgs); the answer has a join's fields,
/// so the app keeps it as it keeps a join.
pub fn new_group(request: &[u8], sign: SignFn, ctx: usize) -> Vec<u8> {
    answer((|| -> Result<JoinedAnswer> {
        let a: NewGroupArgs = serde_json::from_slice(request)
            .map_err(|e| Error::msg(format!("the group request does not decode: {e}")))?;
        if a.store != "hardware" && a.store != "file" {
            return Err(Error::msg(format!("the key store is hardware or file, not {:?}", a.store)));
        }
        let root_key = AppKey { public: a.root_public, sign, ctx };
        let own = cbb_core::admit::OwnDevice {
            name: &a.name,
            os: &a.os,
            role: "phone",
            caps: &[],
            member_point: &a.public,
            store: &a.store,
            seal: a.seal,
        };
        let g = cbb_core::admit::new_group(&root_key, &own, wall_ms())?;
        Ok(JoinedAnswer {
            device: g.device.to_string(),
            cert: g.cert.der.clone(),
            issuer: None,
            group_ca: g.root.der.clone(),
            roots: Vec::new(),
            records: g.records.to_file()?,
            admin_ca: None,
        })
    })())
}

fn joined_answer(j: &cbb_core::pair_session::Joined, now_ms: i64) -> Result<JoinedAnswer> {
    let id = &j.identity;
    let mut set = Records::new(&id.group_ca);
    set.set_clock(move || now_ms);
    let _ = set.add_all(&j.records);
    set.take_claim_times(&j.claim_times);
    Ok(JoinedAnswer {
        device: id.id.to_string(),
        cert: id.cert.der.clone(),
        issuer: id.issuer.as_ref().map(|c: &Cert| c.der.clone()),
        group_ca: id.group_ca.der.clone(),
        roots: id.roots.iter().map(|c| c.der.clone()).collect(),
        records: set.to_file()?,
        admin_ca: j.admin_ca.clone(),
    })
}

/// The QR code's modules for text, a string of '1' (dark) and '0' per row.
pub(crate) fn modules(text: &str) -> Result<Vec<String>> {
    let code = qrcode::QrCode::with_error_correction_level(text.as_bytes(), qrcode::EcLevel::M)
        .map_err(|e| Error::msg(format!("cannot make the QR code: {e}")))?;
    let width = code.width();
    let colors = code.to_colors();
    Ok(colors
        .chunks(width.max(1))
        .map(|row| row.iter().map(|c| if *c == qrcode::Color::Dark { '1' } else { '0' }).collect())
        .collect())
}
