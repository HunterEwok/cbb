// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! A phone's pairing window on the records of 0.6 (format section 11.1): an
//! admin phone, or the root phone, lets a device join at home. The app
//! keeps its member port open (the member's `listen`), opens the window
//! with the key that admits (its admin key, or the root's) and shows the
//! QR code the window gives: the port's addresses and the phone's key
//! fingerprint, nothing secret. The new device dials, the TLS session of
//! `cbb-pair/3` reaches the window through the member port
//! (`Mesh::on_pair`), and both ends show the code the session commits to.
//! The app asks its person whether the codes match, with what the device
//! says of itself, and answers; on "they match" the phone writes the
//! device's record (`pair06::admit`) and sends the Welcome. One attempt at
//! a time; the window closes when the app frees it or its time is up.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use cbb_core::certs;
use cbb_core::error::{Error, Result};
use cbb_core::format::frame;
use cbb_core::identity::ExternalKey;
use cbb_core::join::invitation::ANSWER_MS;
use cbb_core::join::session::{Adb, MemberSession, error_frame};
use cbb_core::join::{PairError, PairExporter};
use cbb_core::records::Key;
use cbb_core::tls::bykey;
use cbb_member::live::Live;
use cbb_member::roster::id_text;
use serde::{Deserialize, Serialize};

use crate::join::{AppKey, ErrorAnswer, SignFn, answer};

/// How long a window stays open when the app gives no time.
const DEFAULT_SECS: u64 = 300;
/// The longest a window stays open.
const MAX_SECS: u64 = 3600;
/// How long each step of the machine may take: the persons' answer has
/// its own time.
const STEP: Duration = Duration::from_secs(30);

#[derive(Deserialize)]
struct NewArgs {
    /// The public point of the key that admits, SEC1 uncompressed: the
    /// phone's admin key, or the root's.
    #[serde(with = "certs::b64")]
    public: Vec<u8>,
    /// The phone's home addresses, without a port: the QR code names each
    /// with the member port's. At most four go into it, best first.
    #[serde(default)]
    addrs: Vec<String>,
    /// How long the window stays open, in seconds: five minutes when 0, an
    /// hour at most.
    #[serde(default)]
    expires: u64,
}

#[derive(Serialize)]
struct NewAnswer {
    /// The QR code's text, cbb://pair?addr=…&fp=…, for the new device.
    qr: String,
    /// The phone's key fingerprint, as the QR code's `fp`.
    fingerprint: String,
    /// How long the window stays open, in seconds.
    expires: u64,
    /// The QR code's modules, a row of '1' and '0' each.
    modules: Vec<String>,
}

/// The device whose code is shown, as it says of itself.
#[derive(Clone, Serialize)]
struct Joining {
    device: String,
    name: String,
    os: String,
    /// The code both screens show, which the person compares.
    code: String,
}

#[derive(Clone, Serialize)]
struct StateAnswer {
    /// Grows with each change; next waits for one past the version it is
    /// given.
    version: u64,
    /// open, joining (the app asks its person whether the codes match),
    /// done (a device joined: device and name), failed (error; the window
    /// stays open for another attempt) or closed (its time is up).
    state: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    joining: Option<Joining>,
    #[serde(skip_serializing_if = "String::is_empty")]
    name: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    device: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<ErrorAnswer>,
}

struct Shared {
    st: Mutex<StateAnswer>,
    changed: Condvar,
    /// An attempt runs: another gets `busy`.
    busy: AtomicBool,
    closed: AtomicBool,
    /// The person's answer to the code of the attempt that runs.
    answers: Mutex<Option<mpsc::SyncSender<bool>>>,
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

    fn failed(&self, e: &Error) {
        self.set(|s| {
            s.state = "failed";
            s.joining = None;
            s.error = Some(ErrorAnswer::of(e));
        });
    }
}

/// An open pairing window of a phone on the records of 0.6.
pub struct Window {
    live: Arc<Live>,
    shared: Arc<Shared>,
}

impl Window {
    /// Opens the window on the phone's member, whose port listens at
    /// `port`, from the app's request (NewArgs) and the admitting key's
    /// callback, with its answer.
    pub(crate) fn open(
        live: Arc<Live>,
        port: Option<u16>,
        request: &[u8],
        sign: SignFn,
        ctx: usize,
    ) -> (Option<Window>, Vec<u8>) {
        match Window::make(live, port, request, sign, ctx) {
            Ok((w, a)) => (Some(w), answer(Ok(a))),
            Err(e) => (None, answer::<()>(Err(e))),
        }
    }

    fn make(
        live: Arc<Live>,
        port: Option<u16>,
        request: &[u8],
        sign: SignFn,
        ctx: usize,
    ) -> Result<(Window, NewAnswer)> {
        let a: NewArgs = serde_json::from_slice(request)
            .map_err(|e| Error::msg(format!("the window's request does not decode: {e}")))?;
        let port = port.ok_or_else(|| Error::msg("the member port is closed: listen first"))?;
        let key: Arc<dyn ExternalKey> = Arc::new(AppKey { public: a.public, sign, ctx });
        let mesh = live.mesh.clone();
        let state = mesh.state();
        if state.stopped() {
            return Err(Error::msg("the group is stopped: nobody joins it until it is set right"));
        }
        let own = mesh.own().member.public();
        let point: [u8; 65] =
            own.as_slice().try_into().map_err(|_| Error::msg("this phone's member key is not a P-256 point"))?;
        let fingerprint = fingerprint(&point);
        let qr = qr_text(&a.addrs, port, &fingerprint);
        let secs = match a.expires {
            0 => DEFAULT_SECS,
            n => n.min(MAX_SECS),
        };
        let shared = Arc::new(Shared {
            st: Mutex::new(StateAnswer {
                version: 1,
                state: "open",
                joining: None,
                name: String::new(),
                device: String::new(),
                error: None,
            }),
            changed: Condvar::new(),
            busy: AtomicBool::new(false),
            closed: AtomicBool::new(false),
            answers: Mutex::new(None),
        });
        let (sh, k, l) = (shared.clone(), key.clone(), live.clone());
        mesh.on_pair(Some(Box::new(move |sock, session, exporter| {
            if sh.closed.load(Ordering::SeqCst) {
                return;
            }
            if sh.busy.swap(true, Ordering::SeqCst) {
                refuse(sock, session, PairError::Busy);
                return;
            }
            let (sh2, k, l) = (sh.clone(), k.clone(), l.clone());
            let spawned = std::thread::Builder::new().name("pair-window".into()).spawn(move || {
                let sh = sh2;
                match attempt(&l, k.as_ref(), &sh, sock, session, exporter) {
                    Ok((device, name)) => sh.set(|s| {
                        s.state = "done";
                        s.joining = None;
                        s.error = None;
                        s.device = device;
                        s.name = name;
                    }),
                    Err(e) => sh.failed(&e),
                }
                *sh.answers.lock().unwrap_or_else(|e| e.into_inner()) = None;
                sh.busy.store(false, Ordering::SeqCst);
            });
            if spawned.is_err() {
                shared_fail(&sh);
            }
        })));
        // Its time is up: the window closes and takes no more attempts.
        let (sh, m) = (shared.clone(), mesh.clone());
        let _ = std::thread::Builder::new().name("pair-window-time".into()).spawn(move || {
            let until = deadline(Duration::from_secs(secs));
            let mut st = sh.lock();
            while !sh.closed.load(Ordering::SeqCst) {
                let left = until.saturating_duration_since(Instant::now());
                if left.is_zero() {
                    break;
                }
                st = sh.changed.wait_timeout(st, left).unwrap_or_else(|e| e.into_inner()).0;
            }
            drop(st);
            if !sh.closed.swap(true, Ordering::SeqCst) {
                m.on_pair(None);
                sh.set(|s| s.state = "closed");
            }
        });
        let modules = crate::join::modules(&qr)?;
        Ok((Window { live, shared }, NewAnswer { qr, fingerprint, expires: secs, modules }))
    }

    /// The window's state once its version passes `version`, or as it is
    /// after timeout_ms.
    pub fn next(&self, version: u64, timeout_ms: u64) -> Vec<u8> {
        let until = deadline(Duration::from_millis(timeout_ms));
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

    /// The person's answer to the code the state's `joining` shows.
    pub fn answer(&self, yes: bool) {
        if let Some(tx) = &*self.shared.answers.lock().unwrap_or_else(|e| e.into_inner()) {
            let _ = tx.try_send(yes);
        }
    }
}

impl Drop for Window {
    fn drop(&mut self) {
        if !self.shared.closed.swap(true, Ordering::SeqCst) {
            self.live.mesh.on_pair(None);
        }
        // An attempt that waits for the person ends as "they do not match".
        self.answer(false);
        self.shared.changed.notify_all();
    }
}

/// The instant d from now, or now when the clock cannot hold it.
fn deadline(d: Duration) -> Instant {
    let now = Instant::now();
    now.checked_add(d).unwrap_or(now)
}

fn shared_fail(sh: &Shared) {
    sh.failed(&Error::msg("cannot start the attempt"));
    sh.busy.store(false, Ordering::SeqCst);
}

/// The key fingerprint the QR code names: the key hash of the phone's TLS
/// key, in hex.
fn fingerprint(point: &[u8; 65]) -> String {
    certs::hex(&Key::es256(point.to_vec()).hash().0)
}

/// The QR code's text: at most four of the phone's addresses with the
/// member port, and the fingerprint.
fn qr_text(hosts: &[String], port: u16, fp: &str) -> String {
    let mut s = String::from("cbb://pair?");
    for h in hosts.iter().filter(|h| !h.is_empty()).take(4) {
        let host = if h.contains(':') && !h.starts_with('[') { format!("[{h}]") } else { h.clone() };
        s.push_str("addr=");
        s.push_str(&percent(&format!("{host}:{port}")));
        s.push('&');
    }
    s.push_str("fp=");
    s.push_str(fp);
    s
}

#[cfg(test)]
pub(crate) fn qr_text_for_tests(hosts: &[String], port: u16, fp: &str) -> String {
    qr_text(hosts, port, fp)
}

/// Percent-encodes all but the unreserved characters of a URL.
fn percent(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
            out.push(char::from(b));
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// Tells a dialer that came while an attempt runs that the window is busy.
fn refuse(sock: TcpStream, session: cbb_core::tls::Session, why: PairError) {
    let mut s = cbb_member::tls::Stream::new(session, sock);
    let _ = send(&mut s, &error_frame(why));
    s.close();
}

/// One attempt, from message 64 to message 68: gives the device's ID and
/// name once it is in the group.
fn attempt(
    live: &Live,
    key: &dyn ExternalKey,
    sh: &Shared,
    sock: TcpStream,
    session: cbb_core::tls::Session,
    exporter: PairExporter,
) -> Result<(String, String)> {
    let mesh = &live.mesh;
    let joiner = bykey::peer_key(session.peer_certificates()).ok_or_else(|| Error::msg("the device showed no key"))?;
    let own_pub = mesh.own().member.public();
    let own: [u8; 65] =
        own_pub.as_slice().try_into().map_err(|_| Error::msg("this phone's member key is not a P-256 point"))?;
    let state = mesh.state();
    let me = mesh.device();
    let adb = Adb {
        group: cbb_core::format::DeviceId(state.group.0),
        device: cbb_core::format::DeviceId(me.0),
        name: state.device(&me).map(|d| d.name.clone()).unwrap_or_default(),
    };
    let _ = sock.set_read_timeout(Some(STEP));
    let mut conn = cbb_member::tls::Stream::new(session, sock);
    let mut s = MemberSession::new(own, joiner, adb, exporter);
    let now = || cbb_member::uptime::wall_ms().max(0).unsigned_abs();

    let m64 = read(&mut conn, frame::LIMIT_PAIRING)?;
    let m65 = s.start_home(&m64).map_err(|e| end(&mut conn, e, "the device was not let in"))?;
    send(&mut conn, &m65)?;
    let m66 = read(&mut conn, frame::LIMIT_PAIRING)?;
    let c = s.confirm(&m66, None, now()).map_err(|e| end(&mut conn, e, "the device did not prove the code"))?;
    let info = s.info().cloned().ok_or_else(|| Error::msg("the device said nothing of itself"))?;
    let code = c.code.ok_or_else(|| Error::msg("no code to show"))?;

    // The person compares the codes, with what the device says of itself.
    let (tx, rx) = mpsc::sync_channel(1);
    *sh.answers.lock().unwrap_or_else(|e| e.into_inner()) = Some(tx);
    let device = id_text(&Key::es256(joiner.to_vec()).device_id());
    let os = cbb_core::format::print::os_name(info.os).to_string();
    sh.set(|st| {
        st.state = "joining";
        st.error = None;
        st.joining = Some(Joining { device: device.clone(), name: info.name.clone(), os, code });
    });
    let matched = rx.recv_timeout(Duration::from_millis(ANSWER_MS)).unwrap_or(false);
    s.answered(matched).map_err(|e| end(&mut conn, e, "the codes do not match"))?;

    let mut statement = None;
    let frames = mesh.write_by(key, |set, k| {
        statement.clone_from(&info.keys);
        crate::pair06::admit(set, k, &own_pub, &joiner, &info, &crate::pair06::home_profile(info.role), &mut s, now())
    });
    let frames = match frames {
        Ok(f) => f,
        Err(e) => {
            let _ = send(&mut conn, &error_frame(PairError::Refused));
            return Err(e);
        }
    };
    for f in &frames {
        send(&mut conn, f)?;
    }
    let m68 = read(&mut conn, frame::LIMIT_PAIRING)?;
    s.done(&m68, None, now()).map_err(|e| failed("the device did not keep its place", e))?;
    conn.close();
    if let Some(env) = statement {
        mesh.take_statement(&env)?;
    }
    Ok((device, info.name))
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
    conn.write_all(f).and_then(|()| conn.flush()).map_err(|e| Error::with("cannot send to the device", e))
}

/// One whole frame, its header too, as the core's session reads it.
fn read(conn: &mut impl Read, limit: usize) -> Result<Vec<u8>> {
    let mut head = [0u8; 4];
    conn.read_exact(&mut head).map_err(|e| Error::with("the device did not answer", e))?;
    let n = frame::length(head, limit).map_err(|rule| Error::msg(format!("a frame breaks {rule}")))?;
    let mut f = vec![0u8; n.saturating_add(4)];
    f.get_mut(..4).ok_or_else(|| Error::msg("a frame without a header"))?.copy_from_slice(&head);
    conn.read_exact(f.get_mut(4..).ok_or_else(|| Error::msg("a frame without a body"))?)
        .map_err(|e| Error::with("the device did not answer", e))?;
    Ok(f)
}
