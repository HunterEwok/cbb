// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! A phone's home window on the records of 0.6 (docs/protocol.md, "Pairing
//! in 0.6"): an admin phone, or the root phone, lets a device join at home.
//! The app keeps its member port open (the member's `listen`), opens the
//! window with the key that admits (its admin key, or the root's) and shows
//! the QR code the window gives (the port's addresses, the phone's key
//! hash, the window's ID and its six digits) and the six digits, for a
//! device that types them. The new device dials, the TLS session of
//! `cbb-pair/3` reaches the window through the member port
//! (`Mesh::on_pair`), and the device proves the digits (CPace's password):
//! nobody is asked whether anything matches. Then the phone writes the
//! device's record (`pair06::admit`) and sends the Welcome. One attempt at
//! a time; three wrong codes or one device that joined close the window,
//! as do the app's free and the end of its time.

use std::io::Write;
use std::net::TcpStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use cbb_core::certs;
use cbb_core::error::{Error, Result};
use cbb_core::identity::ExternalKey;
use cbb_core::join::invitation::{MAX_FAILURES, Network, Open, WindowLink};
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
/// How long each step of the session may take.
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
    /// Announce the window by mDNS from the core (`p=1`, `f`, `i`), for a joiner
    /// without a camera: on Aurora, where the core does mDNS; the iPhone and
    /// Android announce it with the system's DNS-SD from the answer.
    #[serde(default)]
    mdns: bool,
}

#[derive(Serialize)]
struct NewAnswer {
    /// The QR code's text, cbb://pair?addr=…&fp=…&i=…&c=…, for the new
    /// device.
    qr: String,
    /// The six digits to show, for a device that types them.
    digits: String,
    /// The window's ID in hex, as the QR code's `i` and its mDNS `i`.
    id: String,
    /// The hash of the phone's member key in hex, as the QR code's `fp`.
    fingerprint: String,
    /// How long the window stays open, in seconds.
    expires: u64,
    /// The QR code's modules, a row of '1' and '0' each.
    modules: Vec<String>,
}

#[derive(Clone, Serialize)]
struct StateAnswer {
    /// Grows with each change; next waits for one past the version it is
    /// given.
    version: u64,
    /// open, joining (a device dialed and pairs), done (a device joined:
    /// device and name; the window is closed), failed (error; the window
    /// stays open for another attempt) or closed (its time is up, or it
    /// took three wrong codes: error).
    state: &'static str,
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
    /// The invitation the window keeps open: its ID and secret, its
    /// attempts and failures.
    open: Mutex<Open>,
    /// The window's mDNS announcement while it is open.
    announced: Mutex<Option<cbb_member::discovery::Announcement>>,
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
        let fp = Key::es256(point.to_vec()).hash();
        let fingerprint = certs::hex(&fp.0);
        let secs = match a.expires {
            0 => DEFAULT_SECS,
            n => n.min(MAX_SECS),
        };
        let now = cbb_member::uptime::wall_ms().max(0).unsigned_abs();
        let (open, digits) = cbb_member::admitting::home_window(now, Duration::from_secs(secs));
        let id = open.invitation.id;
        let link = WindowLink { addrs: addresses(&a.addrs, port), fp, id, digits: digits.clone() };
        let qr = link.text();
        let shared = Arc::new(Shared {
            st: Mutex::new(StateAnswer {
                version: 1,
                state: "open",
                name: String::new(),
                device: String::new(),
                error: None,
            }),
            changed: Condvar::new(),
            busy: AtomicBool::new(false),
            closed: AtomicBool::new(false),
            open: Mutex::new(open),
            announced: Mutex::new(None),
        });
        if a.mdns {
            let tag = live.tag();
            let ann = cbb_member::discovery::announce_window(
                &id_text(&mesh.device()),
                port,
                &tag,
                &fingerprint,
                &certs::hex(&id),
            )
            .ok_or_else(|| Error::msg("cannot announce the window by mDNS"))?;
            *shared.announced.lock().unwrap_or_else(|e| e.into_inner()) = Some(ann);
        }
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
                sh.set(|s| {
                    s.state = "joining";
                    s.error = None;
                });
                let mut open = sh.open.lock().unwrap_or_else(|e| e.into_inner());
                let got = attempt(&l, k.as_ref(), &mut open, sock, session, exporter);
                let failures = open.failures;
                drop(open);
                match got {
                    Ok((device, name)) => {
                        // One device joined: the window is closed.
                        close(&sh, &l);
                        sh.set(|s| {
                            s.state = "done";
                            s.error = None;
                            s.device = device;
                            s.name = name;
                        });
                    }
                    Err(e) if failures >= MAX_FAILURES => {
                        close(&sh, &l);
                        sh.set(|s| {
                            s.state = "closed";
                            s.error = Some(ErrorAnswer::of(&e.context("the window took three wrong codes and closed")));
                        });
                    }
                    Err(e) => sh.failed(&e),
                }
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
                drop(sh.announced.lock().unwrap_or_else(|e| e.into_inner()).take());
                sh.set(|s| {
                    s.state = "closed";
                    s.error = None;
                });
            }
        });
        let modules = crate::join::modules(&qr)?;
        Ok((
            Window { live, shared },
            NewAnswer { qr, digits, id: certs::hex(&id), fingerprint, expires: secs, modules },
        ))
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
}

impl Drop for Window {
    fn drop(&mut self) {
        if !self.shared.closed.swap(true, Ordering::SeqCst) {
            self.live.mesh.on_pair(None);
        }
        drop(self.shared.announced.lock().unwrap_or_else(|e| e.into_inner()).take());
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

/// Closes the window once a device joined or it took too many wrong
/// codes: no more attempts, no more announcement.
fn close(sh: &Shared, live: &Live) {
    if !sh.closed.swap(true, Ordering::SeqCst) {
        live.mesh.on_pair(None);
    }
    drop(sh.announced.lock().unwrap_or_else(|e| e.into_inner()).take());
}

/// The QR code's addresses: at most four of the phone's, with the member
/// port, an IPv6 address in brackets.
fn addresses(hosts: &[String], port: u16) -> Vec<String> {
    hosts
        .iter()
        .filter(|h| !h.is_empty())
        .take(4)
        .map(|h| if h.contains(':') && !h.starts_with('[') { format!("[{h}]:{port}") } else { format!("{h}:{port}") })
        .collect()
}

/// Tells a dialer that came while an attempt runs that the window is busy.
fn refuse(sock: TcpStream, session: cbb_core::tls::Session, why: PairError) {
    let mut s = cbb_member::tls::Stream::new(session, sock);
    let _ = send(&mut s, &error_frame(why));
    s.close();
}

/// One attempt by the window's invitation, which counts it: gives the
/// device's ID and name once it is in the group.
fn attempt(
    live: &Live,
    key: &dyn ExternalKey,
    open: &mut Open,
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
    let s = MemberSession::new(own, joiner, adb, exporter);
    let now = || cbb_member::uptime::wall_ms().max(0).unsigned_abs();
    let mut statement = None;
    let mut pop_holds = false;
    let way = cbb_member::join::Way { open, network: Network::Home };
    let info = cbb_member::join::member(&mut conn, s, way, &now, &mut |info, s| {
        statement.clone_from(&info.keys);
        pop_holds = s.admin_pop_holds();
        mesh.write_by(key, |set, k| {
            crate::pair06::admit(
                set,
                k,
                &own_pub,
                &joiner,
                info,
                &crate::pair06::home_profile(info.role, info.caps),
                s,
                now(),
            )
        })
    })?;
    conn.close();
    if let Some(env) = statement {
        mesh.take_statement(&env)?;
    }
    let device = id_text(&Key::es256(joiner.to_vec()).device_id());
    // The root keeps the admin key the device offered with its proof over
    // this session, as a computer's root does (cbb_member::offered), for
    // making it an admin later; an admin keeps none.
    let by_root = state.roots.last() == Some(&Key::es256(key.public()).hash());
    if let (true, true, Some(admin)) = (by_root, pop_holds, info.admin.as_ref()) {
        cbb_member::offered::keep(mesh.dir(), &device, admin)?;
    }
    Ok((device, info.name))
}

fn send(conn: &mut impl Write, f: &[u8]) -> Result<()> {
    conn.write_all(f).and_then(|()| conn.flush()).map_err(|e| Error::with("cannot send to the device", e))
}
