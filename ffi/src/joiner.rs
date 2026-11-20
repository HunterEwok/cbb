// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! A new phone joins a group of 0.6 at home (docs/protocol.md, "Pairing in
//! 0.6"): it scans the QR code of a member's home window
//! (`cbb://pair?addr=…&fp=…&i=…&c=…`, a phone's `cbb_window_new` or a
//! computer's `cbb pair`), or its person types the six digits the window
//! shows and the window is found by mDNS (its `i` and `f`). It dials the
//! window's addresses in turn over TLS of `cbb-pair/3` with the member key
//! the app holds, takes only the member whose key the window names, and
//! proves the window's digits (CPace's password): nobody is asked whether
//! anything matches. The member's Welcome is checked, the set is kept in
//! the app's folder (`group.cbor`, as `cbb_member::set` writes it) and only
//! then does the phone tell the member it kept it. The app then starts its
//! member on that folder.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use cbb_core::certs;
use cbb_core::error::{Error, Result};
use cbb_core::format::{KeyHash, frame};
use cbb_core::identity::ExternalKey;
use cbb_core::join::PairError;
use cbb_core::join::info::Info;
use cbb_core::join::invitation::{Invitation, JoinerAttempts, WINDOW_PREFIX, WindowLink, home_secret};
use cbb_core::join::session::{Joined, JoinerSession, error_frame};
use cbb_core::join::welcome::Joining as WelcomeJoining;
use cbb_core::records::Key;
use cbb_core::records::body::ROLE_PHONE;
use cbb_core::tls::bykey;
use cbb_member::roster::id_text;
use serde::{Deserialize, Serialize};

use crate::join::{AppKey, ErrorAnswer, SignFn, answer};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// How long each step of the session may take.
const STEP: Duration = Duration::from_secs(30);

#[derive(Deserialize)]
struct NewArgs {
    /// The app's folder, where the group's set is kept.
    dir: String,
    /// The window's QR code text; empty when the person typed the digits.
    #[serde(default)]
    qr: String,
    /// The six digits the window shows, which the person typed: the window
    /// is then found by mDNS (a phone without a camera, or a scan that
    /// failed).
    #[serde(default)]
    digits: String,
    /// What the phone says of itself.
    name: String,
    os: String,
    /// The member key's public point, SEC1 uncompressed.
    #[serde(with = "certs::b64")]
    public: Vec<u8>,
}

#[derive(Clone, Serialize)]
struct StateAnswer {
    version: u64,
    /// dialing (finding the window, dialing it and proving its digits),
    /// done (in the group: group, device, and name, the member that let
    /// the phone in) or failed (error).
    state: &'static str,
    #[serde(skip_serializing_if = "String::is_empty")]
    group: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    device: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<ErrorAnswer>,
}

struct Shared {
    st: Mutex<StateAnswer>,
    changed: Condvar,
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

/// A phone that joins a group by a home window.
pub struct Joiner {
    shared: Arc<Shared>,
}

/// The window to join: the addresses to dial in turn, its invitation (its
/// ID and the secret of its digits), and the hash of its member's key when
/// known.
pub(crate) struct Target {
    pub(crate) addrs: Vec<SocketAddr>,
    pub(crate) invitation: Invitation,
    pub(crate) fp: Option<KeyHash>,
}

/// The window of a QR code's text (`WindowLink`), at most four of its
/// addresses.
pub(crate) fn read_code(text: &str) -> Result<Target> {
    let t = text.trim();
    let starts = t.get(..WINDOW_PREFIX.len()).is_some_and(|p| p.eq_ignore_ascii_case(WINDOW_PREFIX));
    let link = starts.then(|| WindowLink::parse(t)).flatten();
    let link = link.ok_or_else(|| Error::msg("this is not the QR code of a pairing window"))?;
    let invitation = link.invitation().ok_or_else(|| Error::msg("this is not the QR code of a pairing window"))?;
    let addrs: Vec<SocketAddr> =
        link.addrs.iter().filter_map(|a| a.to_socket_addrs().ok().and_then(|mut i| i.next())).take(4).collect();
    if addrs.is_empty() {
        return Err(Error::msg("the QR code names no address to dial"));
    }
    Ok(Target { addrs, invitation, fp: Some(link.fp) })
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
        let code = if a.qr.trim().is_empty() {
            let digits: String = a.digits.chars().filter(|c| !c.is_whitespace()).collect();
            if home_secret(&digits).is_none() {
                return Err(Error::msg("type the six digits the pairing window shows"));
            }
            Err(digits)
        } else {
            Ok(read_code(&a.qr)?)
        };
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
                group: String::new(),
                device: String::new(),
                name: String::new(),
                error: None,
            }),
            changed: Condvar::new(),
            cancelled: AtomicBool::new(false),
        });
        let sh = shared.clone();
        let mut info = Info::new(&a.name, cbb_core::format::print::os_number(&a.os), ROLE_PHONE);
        info.caps = 0;
        std::thread::Builder::new()
            .name("pair-join".into())
            .spawn(move || {
                let got = code
                    .or_else(|digits| find(&digits))
                    .and_then(|t| run(t, key, info, &sh, &|a| cbb_member::set::save(&dir, &a.set, &local)));
                match got {
                    Ok((group, device, name)) => sh.set(|s| {
                        s.state = "done";
                        s.group = group;
                        s.device = device;
                        s.name = name;
                    }),
                    Err(e) => sh.set(|s| {
                        s.state = "failed";
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
}

impl Drop for Joiner {
    fn drop(&mut self) {
        // The next address is not dialed.
        self.shared.cancelled.store(true, Ordering::SeqCst);
    }
}

/// How long a phone without a camera browses for an open window.
const BROWSE: Duration = Duration::from_secs(10);

/// The one home window open on the network, found by mDNS, whose digits
/// the person typed.
fn find(digits: &str) -> Result<Target> {
    let w = cbb_member::discovery::find_window(BROWSE, None)?;
    let invitation = Invitation::typed(w.id, digits).ok_or_else(|| Error::msg("the window announces no ID"))?;
    Ok(Target { addrs: w.addrs, invitation, fp: w.fp })
}

/// Dials the window's addresses in turn and runs the session with the
/// first member whose key the window names: gives the group's and this
/// phone's IDs and the member's name once the set is kept.
fn run(
    code: Target,
    key: Arc<dyn ExternalKey>,
    info: Info,
    sh: &Shared,
    store: &dyn Fn(&cbb_core::join::session::Admitted) -> Result<()>,
) -> Result<(String, String, String)> {
    let own_point: [u8; 65] =
        key.public().try_into().map_err(|_| Error::msg("the phone's member key is not a P-256 point"))?;
    let tls_key = bykey::OwnKey::external(key.clone())?;
    let fp = code.fp;
    let judge: bykey::Judge = Arc::new(move |point: &[u8; 65]| match fp {
        Some(fp) if Key::es256(point.to_vec()).hash() != fp => Err("not the device whose window this is".to_string()),
        _ => Ok(()),
    });
    let Target { addrs, invitation, .. } = code;
    let mut invitation = Some(invitation);
    let mut last = Error::msg("no address of the window answered");
    for addr in &addrs {
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
        let invitation = invitation.take().ok_or_else(|| Error::msg("the window was tried already"))?;
        return session(&mut conn, own_point, member, x, info, invitation, store).map_err(|e| {
            // A member with no window open ends the connection at once.
            let eof = e.find::<std::io::Error>().is_some_and(|io| io.kind() == std::io::ErrorKind::UnexpectedEof);
            if eof { e.context(format!("{addr} has no pairing window open: open Add a device there again")) } else { e }
        });
    }
    Err(last)
}

fn session(
    conn: &mut cbb_member::tls::Stream,
    own: [u8; 65],
    member: [u8; 65],
    exporter: cbb_core::join::PairExporter,
    info: Info,
    invitation: Invitation,
    store: &dyn Fn(&cbb_core::join::session::Admitted) -> Result<()>,
) -> Result<(String, String, String)> {
    let now = || cbb_member::uptime::wall_ms().max(0).unsigned_abs();
    let mut attempts = JoinerAttempts::default();
    let (mut s, m64) =
        JoinerSession::start(&mut attempts, info, invitation, WelcomeJoining::Ordinary, own, member, exporter)
            .map_err(|e| failed("cannot start pairing", e))?;
    send(conn, &m64)?;
    let m65 = read(conn, frame::LIMIT_PAIRING)?;
    let r = s.reply(&m65).map_err(|e| end(conn, e, why(e, "the pairing did not go on")))?;
    send(conn, &r.send)?;
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
                return Ok((id_text(&a.state.group), device, r.adb.name.clone()));
            }
            Err(e) => return Err(end(conn, e, why(e, "the group's answer did not hold"))),
        }
    }
}

/// What the person reads when the session ends with e; other errors say
/// what.
fn why(e: PairError, other: &'static str) -> &'static str {
    match e {
        PairError::WrongCode => "the code is not the window's: check the six digits it shows and try again",
        PairError::TooMany => "the window took three wrong codes and closed: open a new one",
        PairError::Closed => "the window is closed: open a new one",
        PairError::Expired => "the window's time is up: open a new one",
        PairError::Busy => "another device is pairing with that window: try again in a moment",
        _ => other,
    }
}

/// Sends message 69 with why and gives the error.
fn end(conn: &mut impl Write, e: PairError, what: &str) -> Error {
    let _ = send(conn, &error_frame(e));
    failed(what, e)
}

/// The message for the person; the pairing error's number in the details.
fn failed(what: &str, e: PairError) -> Error {
    Error::with(what, Code(e))
}

/// A pairing error with its number, as the details show it.
#[derive(Debug)]
struct Code(PairError);

impl std::fmt::Display for Code {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "pairing error {}", self.0.code())
    }
}

impl std::error::Error for Code {}

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
