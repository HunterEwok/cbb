// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! A phone that joins a group by its QR code with a key the core does not
//! hold (the Aurora app's key in OP-TEE), as C functions beside `cbb_call`
//! (include/cbb_core.h): the joiner listens, shows the QR code these
//! functions give, and passes each connection's bytes through
//! cbb_core::pair_session, which runs the pairing inside the core's TLS and
//! asks the app's callback for each signature. The app does the sockets.

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

pub(crate) fn wall_ms() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| i64::try_from(d.as_millis()).unwrap_or(0)).unwrap_or(0)
}

/// A joiner that listens, with its current attempt.
pub struct Join {
    joiner: Joiner,
    code: String,
    clock: Clock,
    attempt: Option<Attempt>,
}

#[derive(Deserialize)]
struct NewArgs {
    name: String,
    os: String,
    /// The key's public point, SEC1 uncompressed.
    #[serde(with = "certs::b64")]
    public: Vec<u8>,
    /// Its public key for sealed messages, optional.
    #[serde(with = "certs::b64", default)]
    seal: Vec<u8>,
    /// The addresses for the QR code, host:port.
    addrs: Vec<String>,
    /// The six-digit code, or a new one when absent.
    #[serde(default)]
    code: String,
}

#[derive(Serialize)]
struct NewAnswer {
    device: String,
    code: String,
    fingerprint: String,
    /// The QR code's text and its modules, a row of '1' and '0' each.
    qr: String,
    modules: Vec<String>,
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
}

#[derive(Serialize)]
struct ErrorAnswer {
    message: String,
    details: String,
}

impl ErrorAnswer {
    fn of(e: &Error) -> ErrorAnswer {
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
    pub fn new(request: &[u8], sign: SignFn, ctx: usize) -> (Option<Join>, Vec<u8>) {
        let made = (|| -> Result<(Join, NewAnswer)> {
            let a: NewArgs = serde_json::from_slice(request)
                .map_err(|e| Error::msg(format!("the join request does not decode: {e}")))?;
            let key = Arc::new(AppKey { public: a.public, sign, ctx });
            let mut joiner = Joiner::with_key(&a.name, &a.os, key)?;
            joiner.seal = a.seal;
            let code = if a.code.is_empty() { pair::new_code() } else { pair::normalize_code(&a.code)? };
            let qr = pair::join_qr(&code, &a.addrs, &joiner.fingerprint());
            let modules = modules(&qr)?;
            let ans = NewAnswer {
                device: joiner.id.to_string(),
                code: code.clone(),
                fingerprint: joiner.fingerprint(),
                qr,
                modules,
            };
            Ok((Join { joiner, code, clock: Arc::new(SystemClock), attempt: None }, ans))
        })();
        match made {
            Ok((j, ans)) => (Some(j), answer(Ok(ans))),
            Err(e) => (None, answer::<()>(Err(e))),
        }
    }

    /// Starts an attempt for a connection the app accepted, ending the one
    /// before.
    pub fn accept(&mut self) -> Vec<u8> {
        let made = Attempt::listening(&self.joiner, &self.code, &self.clock);
        answer(made.map(|a| {
            self.attempt = Some(a);
            serde_json::json!({})
        }))
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
    })
}

/// The QR code's modules for text, a string of '1' (dark) and '0' per row.
fn modules(text: &str) -> Result<Vec<String>> {
    let code = qrcode::QrCode::with_error_correction_level(text.as_bytes(), qrcode::EcLevel::M)
        .map_err(|e| Error::msg(format!("cannot make the QR code: {e}")))?;
    let width = code.width();
    let colors = code.to_colors();
    Ok(colors
        .chunks(width.max(1))
        .map(|row| row.iter().map(|c| if *c == qrcode::Color::Dark { '1' } else { '0' }).collect())
        .collect())
}
