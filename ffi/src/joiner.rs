// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! A new phone joins a group of 0.6 at home (format section 11.1): it scans
//! the QR code of a member's pairing window (`cbb://pair?addr=…&fp=…`, a
//! phone's `cbb_window_new` or a computer's), dials its addresses in turn
//! over TLS of `cbb-pair/3` with the member key the app holds, and takes
//! only the member whose key the code's fingerprint names. Both ends show
//! the code the session commits to; the app asks its person and answers.
//! On "they match" the member's Welcome is checked, the set is kept in the
//! app's folder (`group.cbor`, as `cbb_member::set` writes it) and only
//! then does the phone tell the member it kept it. The app then starts its
//! member on that folder.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, mpsc};
use std::time::{Duration, Instant};

use cbb_core::certs;
use cbb_core::error::{Error, Result};
use cbb_core::format::frame;
use cbb_core::identity::ExternalKey;
use cbb_core::join::PairError;
use cbb_core::join::info::Info;
use cbb_core::join::invitation::{ANSWER_MS, JoinerAttempts};
use cbb_core::join::session::{Joined, JoinerSession, error_frame};
use cbb_core::join::welcome::Joining as WelcomeJoining;
use cbb_core::records::Key;
use cbb_core::records::body::ROLE_PHONE;
use cbb_core::tls::bykey;
use cbb_member::roster::id_text;
use serde::{Deserialize, Serialize};

use crate::join::{AppKey, ErrorAnswer, SignFn, answer};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// How long each step of the machine may take; the person's answer has
/// its own time.
const STEP: Duration = Duration::from_secs(30);

#[derive(Deserialize)]
struct NewArgs {
    /// The app's folder, where the group's set is kept.
    dir: String,
    /// The window's QR code, cbb://pair?addr=…&fp=….
    qr: String,
    /// What the phone says of itself.
    name: String,
    os: String,
    /// The member key's public point, SEC1 uncompressed.
    #[serde(with = "certs::b64")]
    public: Vec<u8>,
}

/// The member whose code is shown, as it says of itself.
#[derive(Clone, Serialize)]
struct Shown {
    /// The member's device ID and name.
    device: String,
    name: String,
    /// The code both screens show, which the person compares.
    code: String,
}

#[derive(Clone, Serialize)]
struct StateAnswer {
    version: u64,
    /// dialing, joining (the app asks its person whether `shown.code`
    /// matches the member's screen), done (in the group: group, device)
    /// or failed (error).
    state: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    shown: Option<Shown>,
    #[serde(skip_serializing_if = "String::is_empty")]
    group: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    device: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<ErrorAnswer>,
}

struct Shared {
    st: Mutex<StateAnswer>,
    changed: Condvar,
    answers: Mutex<Option<mpsc::SyncSender<bool>>>,
    cancelled: AtomicBool,
}

impl Shared {
    fn lock(&self) -> MutexGuard<'_, StateAnswer> {
        self.st.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn set(&self, f: impl FnOnce(&mut StateAnswer)) {
        let mut st = self.lock();
        f(&mut st);
        st.version = st.version.saturating_add(1);
        self.changed.notify_all();
    }
}

/// A phone that joins a group by a window's QR code.
pub struct Joiner {
    shared: Arc<Shared>,
}

/// What a pairing window's QR code names: its addresses and the key
/// fingerprint of the member that holds it.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct PairCode {
    pub(crate) addrs: Vec<SocketAddr>,
    pub(crate) fingerprint: String,
}

/// Reads a window's QR code (`window::qr_text`): the scheme and host
/// without regard to case, percent escapes decoded, at most four
/// addresses, fields it does not know ignored.
pub(crate) fn read_code(text: &str) -> Result<PairCode> {
    let t = text.trim();
    let rest = t
        .get(..11)
        .filter(|p| p.eq_ignore_ascii_case("cbb://pair?"))
        .and_then(|_| t.get(11..))
        .ok_or_else(|| Error::msg("this is not the QR code of a pairing window"))?;
    let mut addrs = Vec::new();
    let mut fingerprint = String::new();
    for field in rest.split('&') {
        let (k, v) = field.split_once('=').unwrap_or((field, ""));
        let v = unpercent(v)?;
        match k {
            "addr" if addrs.len() < 4 => {
                if let Ok(a) = v.parse() {
                    addrs.push(a);
                }
            }
            "fp" => fingerprint = v.to_ascii_lowercase(),
            _ => {}
        }
    }
    if fingerprint.len() != 64 || !fingerprint.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(Error::msg("the QR code names no key fingerprint"));
    }
    if addrs.is_empty() {
        return Err(Error::msg("the QR code names no address to dial"));
    }
    Ok(PairCode { addrs, fingerprint })
}

fn unpercent(s: &str) -> Result<String> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0usize;
    while let Some(&c) = b.get(i) {
        if c == b'%' {
            let hex = s.get(i.saturating_add(1)..i.saturating_add(3)).ok_or_else(|| Error::msg("a broken escape"))?;
            out.push(u8::from_str_radix(hex, 16).map_err(|_| Error::msg("a broken escape"))?);
            i = i.saturating_add(3);
        } else {
            out.push(c);
            i = i.saturating_add(1);
        }
    }
    String::from_utf8(out).map_err(|_| Error::msg("a field that is not UTF-8"))
}

impl Joiner {
    /// Starts joining from the app's request (NewArgs) with the member
    /// key's callback; the answer is the first state.
    pub fn new(request: &[u8], sign: SignFn, ctx: usize) -> (Option<Joiner>, Vec<u8>) {
        match Joiner::start(request, sign, ctx) {
            Ok(j) => {
                let st = j.shared.lock().clone();
                (Some(j), answer(Ok(st)))
            }
            Err(e) => (None, answer::<()>(Err(e))),
        }
    }

    fn start(request: &[u8], sign: SignFn, ctx: usize) -> Result<Joiner> {
        let a: NewArgs =
            serde_json::from_slice(request).map_err(|e| Error::msg(format!("the request does not decode: {e}")))?;
        let code = read_code(&a.qr)?;
        let dir = PathBuf::from(&a.dir);
        std::fs::create_dir_all(&dir).map_err(|e| Error::with(format!("cannot make {}", dir.display()), e))?;
        let local = cbb_member::set::local_key(&dir)?;
        if cbb_member::set::load(&dir, &local)?.is_some() {
            return Err(Error::msg("this phone is in a group already: leave it first"));
        }
        let key: Arc<dyn ExternalKey> = Arc::new(AppKey { public: a.public, sign, ctx });
        let shared = Arc::new(Shared {
            st: Mutex::new(StateAnswer {
                version: 1,
                state: "dialing",
                shown: None,
                group: String::new(),
                device: String::new(),
                error: None,
            }),
            changed: Condvar::new(),
            answers: Mutex::new(None),
            cancelled: AtomicBool::new(false),
        });
        let sh = shared.clone();
        let mut info = Info::new(&a.name, cbb_core::format::print::os_number(&a.os), ROLE_PHONE);
        info.caps = 0;
        std::thread::Builder::new()
            .name("pair-join".into())
            .spawn(move || {
                let got = run(&code, key, info, &sh, &|a| cbb_member::set::save(&dir, &a.set, &local));
                match got {
                    Ok((group, device)) => sh.set(|s| {
                        s.state = "done";
                        s.shown = None;
                        s.group = group;
                        s.device = device;
                    }),
                    Err(e) => sh.set(|s| {
                        s.state = "failed";
                        s.shown = None;
                        s.error = Some(ErrorAnswer::of(&e));
                    }),
                }
            })
            .map_err(|e| Error::with("cannot start joining", e))?;
        Ok(Joiner { shared })
    }

    /// The state once its version passes `version`, or as it is after
    /// timeout_ms.
    pub fn next(&self, version: u64, timeout_ms: u64) -> Vec<u8> {
        let now = Instant::now();
        let until = now.checked_add(Duration::from_millis(timeout_ms)).unwrap_or(now);
        let mut st = self.shared.lock();
        while st.version <= version {
            let left = until.saturating_duration_since(Instant::now());
            if left.is_zero() {
                break;
            }
            st = self.shared.changed.wait_timeout(st, left).unwrap_or_else(|e| e.into_inner()).0;
        }
        answer(Ok(st.clone()))
    }

    /// The person's answer to the code of the state's `shown`.
    pub fn answer(&self, yes: bool) {
        if let Some(tx) = &*self.shared.answers.lock().unwrap_or_else(|e| e.into_inner()) {
            let _ = tx.try_send(yes);
        }
    }
}

impl Drop for Joiner {
    fn drop(&mut self) {
        // A session that waits for the person ends as "they do not match".
        self.shared.cancelled.store(true, Ordering::SeqCst);
        self.answer(false);
    }
}

/// Dials the window's addresses in turn and runs the session with the
/// first member whose key the fingerprint names: gives the group's and
/// this phone's IDs once the set is kept.
fn run(
    code: &PairCode,
    key: Arc<dyn ExternalKey>,
    info: Info,
    sh: &Shared,
    store: &dyn Fn(&cbb_core::join::session::Admitted) -> Result<()>,
) -> Result<(String, String)> {
    let own_point: [u8; 65] =
        key.public().try_into().map_err(|_| Error::msg("the phone's member key is not a P-256 point"))?;
    let tls_key = bykey::OwnKey::external(key.clone())?;
    let fp = code.fingerprint.clone();
    let judge: bykey::Judge = Arc::new(move |point: &[u8; 65]| {
        if certs::hex(&Key::es256(point.to_vec()).hash().0) == fp {
            Ok(())
        } else {
            Err("not the device whose QR code was scanned".to_string())
        }
    });
    let mut last = Error::msg("no address of the QR code answered");
    for addr in &code.addrs {
        if sh.cancelled.load(Ordering::SeqCst) {
            return Err(Error::msg("joining was cancelled"));
        }
        let sock = match TcpStream::connect_timeout(addr, CONNECT_TIMEOUT) {
            Ok(s) => s,
            Err(e) => {
                last = Error::with(format!("cannot reach {addr}"), e);
                continue;
            }
        };
        let _ = sock.set_read_timeout(Some(STEP));
        let (cfg, exporter) = bykey::exporting_client(bykey::client(
            &tls_key,
            None,
            judge.clone(),
            cbb_core::alpn::PAIR,
            &cbb_member::tls::clock(),
        )?);
        let mut s = cbb_core::tls::Session::client(Arc::new(cfg), bykey::unsent_name())?;
        if let Err(e) = cbb_member::tls::handshake(&mut s, &sock, "the handshake with the member failed") {
            last = e;
            continue;
        }
        let member = bykey::peer_key(s.peer_certificates()).ok_or_else(|| Error::msg("the member showed no key"))?;
        let x = bykey::pairing_exporter(&s, &exporter)?;
        let mut conn = cbb_member::tls::Stream::new(s, sock);
        // The first member that answered with the right key tried the
        // session: its outcome is the outcome.
        return session(&mut conn, own_point, member, x, info, sh, store);
    }
    Err(last)
}

fn session(
    conn: &mut cbb_member::tls::Stream,
    own: [u8; 65],
    member: [u8; 65],
    exporter: cbb_core::join::PairExporter,
    info: Info,
    sh: &Shared,
    store: &dyn Fn(&cbb_core::join::session::Admitted) -> Result<()>,
) -> Result<(String, String)> {
    let now = || cbb_member::uptime::wall_ms().max(0).unsigned_abs();
    let mut attempts = JoinerAttempts::default();
    let (mut s, m64) = JoinerSession::start(&mut attempts, info, None, WelcomeJoining::Ordinary, own, member, exporter)
        .map_err(|e| failed("cannot start pairing", e))?;
    send(conn, &m64)?;
    let m65 = read(conn, frame::LIMIT_PAIRING)?;
    let r = s.reply(&mut attempts, &m65).map_err(|e| end(conn, e, "the pairing did not go on"))?;
    send(conn, &r.send)?;
    let code = r.code.ok_or_else(|| Error::msg("no code to show"))?;
    let (tx, rx) = mpsc::sync_channel(1);
    *sh.answers.lock().unwrap_or_else(|e| e.into_inner()) = Some(tx);
    sh.set(|st| {
        st.state = "joining";
        st.shown = Some(Shown { device: id_text(&r.adb.device), name: r.adb.name.clone(), code });
    });
    let matched = rx.recv_timeout(Duration::from_millis(ANSWER_MS)).unwrap_or(false);
    s.answered(&mut attempts, matched).map_err(|e| end(conn, e, "the codes do not match"))?;
    loop {
        // Message 67 and its parts come at the member connection's limit.
        let f = read(conn, frame::LIMIT_MEMBER)?;
        match s.take(&f, now()) {
            Ok(Joined::Waiting) => {}
            Ok(Joined::Done(a)) => {
                store(&a)?;
                send(conn, &a.send)?;
                conn.close();
                let device = id_text(&Key::es256(own.to_vec()).device_id());
                return Ok((id_text(&a.state.group), device));
            }
            Err(e) => return Err(end(conn, e, "the group's answer did not hold")),
        }
    }
}

/// Sends message 69 with why and gives the error.
fn end(conn: &mut impl Write, e: PairError, what: &str) -> Error {
    let _ = send(conn, &error_frame(e));
    failed(what, e)
}

fn failed(what: &str, e: PairError) -> Error {
    Error::msg(format!("{what} (pairing error {})", e.code()))
}

fn send(conn: &mut impl Write, f: &[u8]) -> Result<()> {
    conn.write_all(f).and_then(|()| conn.flush()).map_err(|e| Error::with("cannot send to the member", e))
}

/// One whole frame, its header too, as the core's session reads it.
fn read(conn: &mut impl Read, limit: usize) -> Result<Vec<u8>> {
    let mut head = [0u8; 4];
    conn.read_exact(&mut head).map_err(|e| Error::with("the member did not answer", e))?;
    let n = frame::length(head, limit).map_err(|rule| Error::msg(format!("a frame breaks {rule}")))?;
    let mut f = vec![0u8; n.saturating_add(4)];
    f.get_mut(..4).ok_or_else(|| Error::msg("a frame without a header"))?.copy_from_slice(&head);
    conn.read_exact(f.get_mut(4..).ok_or_else(|| Error::msg("a frame without a body"))?)
        .map_err(|e| Error::with("the member did not answer", e))?;
    Ok(f)
}

#[cfg(test)]
mod tests;
