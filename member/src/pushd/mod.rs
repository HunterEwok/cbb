// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The project's push service (`cbb-push`, format section 20.4,
//! `cbb_core::push`): members of a group ask it to wake a phone whose app
//! is closed, and it passes a sealed body of one size to the phone's
//! platform (APNs for the iPhone and the iPad; FCM, UnifiedPush and Push
//! Kit follow). It holds the platforms' keys and none of a group's.
//!
//! - A member connects over TLS with ALPN `cbb-push/1` to the service's
//!   pinned key, presenting the certificate of its server key for the
//!   service's face, and sends `push/hello` with the face's hubs' and
//!   members' credentials (format section 8). The service takes the first
//!   period key it sees for a tag, never an older version of a credential,
//!   and the member only when the members' credential lists its key.
//! - Then `push/send` as often as the budgets allow: per tag, per token,
//!   per address. A repeated `once` for one token within a day is answered
//!   `repeat` and not sent, so that several members sending one copy give
//!   one notification.
//! - It sees its face's tag, server keys' hashes, tokens, times and one
//!   size per platform. It keeps all of it in memory only, the tokens and
//!   tags as keyed hashes under a secret drawn at start, and logs counts,
//!   never a token, a tag or an address.

pub mod apns;
pub mod command;
pub mod h2;

#[cfg(test)]
mod tests;

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use cbb_core::blind::credential::{Credential, TYPE_HUBS, TYPE_MEMBERS};
use cbb_core::format::cbor::Value;
use cbb_core::format::{Alg, Key, frame};
use cbb_core::push;
use hmac::{Hmac, KeyInit, Mac};
use rustls::{ServerConnection, StreamOwned};
use sha2::Sha256;

use crate::error::{Context, Error, Result};

/// What a platform did with a body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    Sent,
    /// The token is dead (the app was removed): the members drop it.
    Gone,
    /// Not now; try after this long.
    Later(Duration),
    /// The service has no way to this platform.
    NoPath,
}

/// A platform's push service.
pub trait Platform: Send + Sync {
    /// Sends a body to a token of env, to be dropped by the platform after
    /// `expires_s` (Unix seconds).
    fn send(&self, env: u64, token: &[u8], body: &[u8], expires_s: u64) -> Outcome;
}

/// The budgets (format section 20.4, P-4): sends an hour and the burst.
#[derive(Clone, Copy, Debug)]
pub struct Budgets {
    pub per_token: (f64, f64),
    pub per_tag: (f64, f64),
    /// Connections at once, in all and from one address.
    pub connections: usize,
    pub per_address: usize,
}

impl Default for Budgets {
    fn default() -> Budgets {
        Budgets { per_token: (120.0, 30.0), per_tag: (1200.0, 120.0), connections: 256, per_address: 16 }
    }
}

pub struct Config {
    pub listen: SocketAddr,
    /// The service's TLS certificate and its PKCS #8 key.
    pub cert: Vec<u8>,
    pub key: Vec<u8>,
    /// The platforms by env.
    pub platforms: HashMap<u64, Arc<dyn Platform>>,
    pub budgets: Budgets,
    pub log: Arc<dyn Fn(&str) + Send + Sync>,
}

/// How long a `once` is remembered, and how many at most.
const ONCE_FOR: Duration = Duration::from_secs(24 * 3600);
const ONCE_MAX: usize = 1 << 20;
/// Tags and token budgets kept at most.
const TAGS_MAX: usize = 65_536;
const TOKENS_MAX: usize = 1 << 20;
/// The hello within this, and at most this long between sends.
const HELLO_WAIT: Duration = Duration::from_secs(10);
const IDLE: Duration = Duration::from_secs(120);
/// The largest frame a member sends.
const MAX_FRAME: usize = 16_384;

/// A token bucket.
#[derive(Clone, Copy, Debug)]
struct Bucket {
    left: f64,
    at: Instant,
}

impl Bucket {
    fn take(&mut self, (per_hour, burst): (f64, f64), now: Instant) -> std::result::Result<(), Duration> {
        let rate = per_hour / 3600.0;
        self.left = (self.left + now.saturating_duration_since(self.at).as_secs_f64() * rate).min(burst);
        self.at = now;
        if self.left >= 1.0 {
            self.left -= 1.0;
            Ok(())
        } else {
            Err(Duration::from_secs_f64(((1.0 - self.left) / rate).max(1.0)))
        }
    }
}

/// What the service holds of one tag (one group's face toward it).
struct Period {
    key: Vec<u8>,
    hubs_version: u64,
    members_version: u64,
    budget: Bucket,
    seen: Instant,
}

#[derive(Default)]
struct State {
    periods: HashMap<[u8; 32], Period>,
    tokens: HashMap<[u8; 32], Bucket>,
    once: HashMap<[u8; 32], Instant>,
    connections: usize,
    per_address: HashMap<IpAddr, usize>,
}

struct Inner {
    cfg: Config,
    tls: Arc<rustls::ServerConfig>,
    /// The secret of the keyed hashes, drawn at start, never written.
    secret: [u8; 32],
    state: Mutex<State>,
    stop: AtomicBool,
    sent: AtomicU64,
}

/// A running service.
pub struct Service {
    inner: Arc<Inner>,
    addr: SocketAddr,
}

fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_millis() as u64)
}

/// The expiry of a body of `ttl` (the content's: one minute, ten minutes,
/// one hour, one day), in Unix seconds.
fn expires(ttl: Option<u64>) -> u64 {
    let secs = match ttl {
        Some(1) => 60,
        Some(2) => 600,
        Some(4) => 86_400,
        _ => 3600,
    };
    now_ms() / 1000 + secs
}

impl Inner {
    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn keyed(&self, what: &[u8], a: &[u8], b: &[u8]) -> [u8; 32] {
        let mut m = <Hmac<Sha256> as KeyInit>::new_from_slice(&self.secret).expect("HMAC takes any key");
        m.update(what);
        m.update(&(a.len() as u32).to_be_bytes());
        m.update(a);
        m.update(b);
        m.finalize().into_bytes().into()
    }

    /// Checks a hello: the face's hubs' and members' credentials and the
    /// member's server key among the members. Returns the tag's keyed hash.
    fn hello(&self, creds: &[&[u8]], server_key: &[u8], now: u64) -> std::result::Result<[u8; 32], &'static str> {
        let mut hubs = None;
        let mut members = None;
        for c in creds {
            let c = Credential::read(c).map_err(|_| "the group's credentials do not verify")?;
            match c.kind {
                TYPE_HUBS => hubs = Some(c),
                TYPE_MEMBERS => members = Some(c),
                _ => return Err("only the hubs' and members' credentials are taken"),
            }
        }
        let (Some(hubs), Some(members)) = (hubs, members) else {
            return Err("the hubs' and members' credentials are needed");
        };
        if !hubs.live(now) || !members.live(now) {
            return Err("the group's credentials expired");
        }
        let by_period = members.signer == hubs.signer;
        let by_admin = hubs.admins.contains(&members.signer_hash().0);
        if members.group != hubs.group || !(by_period || by_admin) {
            return Err("the members' credential is not of the hubs' period");
        }
        if !members.members.contains(&Key::new(Alg::Es256, server_key).hash().0) {
            return Err("the members' credential does not list this device");
        }
        let tag = self.keyed(b"tag", &hubs.group, &[]);
        let mut st = self.lock();
        let at = Instant::now();
        if !st.periods.contains_key(&tag) && st.periods.len() >= TAGS_MAX {
            // Forget the period not seen the longest.
            if let Some(old) = st.periods.iter().min_by_key(|(_, p)| p.seen).map(|(k, _)| *k) {
                st.periods.remove(&old);
            }
        }
        let burst = self.cfg.budgets.per_tag.1;
        let p = st.periods.entry(tag).or_insert_with(|| Period {
            key: hubs.signer.clone(),
            hubs_version: 0,
            members_version: 0,
            budget: Bucket { left: burst, at },
            seen: at,
        });
        if p.key != hubs.signer {
            return Err("another period key than the one first seen for this group");
        }
        if hubs.version < p.hubs_version || members.version < p.members_version {
            return Err("the group's credentials are older than ones seen before");
        }
        p.hubs_version = hubs.version;
        p.members_version = members.version;
        p.seen = at;
        Ok(tag)
    }

    /// Handles one `push/send`; returns the status and the wait.
    fn send(&self, tag: &[u8; 32], s: &push::Send<'_>) -> (u64, Option<u64>) {
        let Some(platform) = self.cfg.platforms.get(&s.env).cloned() else { return (push::SENT_FAILED, None) };
        if !s.sized() {
            return (push::SENT_FAILED, None);
        }
        if s.env == push::ENV_UNIFIEDPUSH && push::UnifiedPush::read(s.token).is_err() {
            return (push::SENT_FAILED, None);
        }
        let tok = self.keyed(b"token", &s.env.to_be_bytes(), s.token);
        let once = self.keyed(b"once", &tok, &s.once);
        let at = Instant::now();
        {
            let mut st = self.lock();
            if st.once.get(&once).is_some_and(|t| at.saturating_duration_since(*t) < ONCE_FOR) {
                return (push::SENT_REPEAT, None);
            }
            let budgets = self.cfg.budgets;
            let Some(p) = st.periods.get_mut(tag) else { return (push::SENT_FAILED, None) };
            if let Err(wait) = p.budget.take(budgets.per_tag, at) {
                return (push::SENT_BUDGET, Some(wait.as_millis() as u64));
            }
            if !st.tokens.contains_key(&tok) && st.tokens.len() >= TOKENS_MAX {
                st.tokens.retain(|_, b| at.saturating_duration_since(b.at) < Duration::from_secs(3600));
            }
            let b = st.tokens.entry(tok).or_insert(Bucket { left: budgets.per_token.1, at });
            if let Err(wait) = b.take(budgets.per_token, at) {
                return (push::SENT_BUDGET, Some(wait.as_millis() as u64));
            }
            if st.once.len() >= ONCE_MAX {
                st.once.retain(|_, t| at.saturating_duration_since(*t) < ONCE_FOR);
                if st.once.len() >= ONCE_MAX {
                    return (push::SENT_BUDGET, Some(60_000));
                }
            }
            st.once.insert(once, at);
        }
        match platform.send(s.env, s.token, s.body, expires(s.ttl)) {
            Outcome::Sent => {
                self.sent.fetch_add(1, Ordering::Relaxed);
                (push::SENT, None)
            }
            Outcome::Gone => (push::SENT_GONE, None),
            Outcome::Later(d) => {
                // Not sent: the next sender may try.
                self.lock().once.remove(&once);
                (push::SENT_FAILED, Some(d.as_millis() as u64))
            }
            Outcome::NoPath => {
                self.lock().once.remove(&once);
                (push::SENT_FAILED, None)
            }
        }
    }

    fn serve(self: &Arc<Self>, tcp: TcpStream) -> Result<()> {
        tcp.set_read_timeout(Some(HELLO_WAIT)).context("timeout")?;
        tcp.set_write_timeout(Some(HELLO_WAIT)).context("timeout")?;
        let conn = ServerConnection::new(self.tls.clone()).context("TLS")?;
        let mut s = StreamOwned::new(conn, tcp);
        while s.conn.is_handshaking() {
            s.conn.complete_io(&mut s.sock).context("TLS handshake")?;
        }
        let key = s
            .conn
            .peer_certificates()
            .and_then(|c| c.first())
            .and_then(|c| cbb_core::certs::Cert::parse(c.as_ref()).ok())
            .map(|c| c.public_key().to_vec())
            .ok_or_else(|| Error::msg("no client certificate"))?;
        let first = read_frame(&mut s)?;
        let m = frame::read(&first, MAX_FRAME).map_err(|r| Error::msg(r.name()))?;
        let creds: Vec<Vec<u8>> = match (m.t, m.map.get(2)) {
            (push::T_HELLO, Some(Value::Array(a))) if cbb_core::msg::check_map(&push::HELLO, &m.map).is_ok() => {
                a.iter().map(Value::encode).collect()
            }
            _ => return write_frame(&mut s, &push::error("the first message is push/hello")),
        };
        let refs: Vec<&[u8]> = creds.iter().map(Vec::as_slice).collect();
        let tag = match self.hello(&refs, &key, now_ms()) {
            Ok(t) => t,
            Err(why) => return write_frame(&mut s, &push::error(why)),
        };
        let left = self.lock().periods.get(&tag).map_or(0, |p| p.budget.left as u64);
        write_frame(&mut s, &push::ready(left))?;
        s.sock.set_read_timeout(Some(IDLE)).context("timeout")?;
        while !self.stop.load(Ordering::Relaxed) {
            let Ok(f) = read_frame(&mut s) else { return Ok(()) };
            let Ok(m) = frame::read(&f, MAX_FRAME) else {
                return write_frame(&mut s, &push::error("not a frame of the format"));
            };
            if m.t != push::T_SEND {
                continue;
            }
            let Ok(send) = push::Send::read(&m.map) else {
                return write_frame(&mut s, &push::error("push/send does not follow its table"));
            };
            let (status, retry) = self.send(&tag, &send);
            write_frame(&mut s, &push::sent(send.n, status, retry))?;
        }
        Ok(())
    }
}

fn read_frame(s: &mut impl Read) -> Result<Vec<u8>> {
    let mut h = [0u8; 4];
    s.read_exact(&mut h).context("read")?;
    let n = frame::length(h, MAX_FRAME).map_err(|r| Error::msg(r.name()))?;
    let mut f = vec![0u8; n + 4];
    f[..4].copy_from_slice(&h);
    s.read_exact(&mut f[4..]).context("read")?;
    Ok(f)
}

fn write_frame(s: &mut impl Write, f: &[u8]) -> Result<()> {
    s.write_all(f).and_then(|()| s.flush()).context("write")
}

impl Service {
    pub fn start(cfg: Config) -> Result<Service> {
        let clock: cbb_core::tls::Clock = Arc::new(crate::forward::SystemClock);
        let tls = cbb_core::tls::registration_server(&cfg.cert, &cfg.key, push::ALPN, &clock)?;
        let tcp = TcpListener::bind(cfg.listen).context(format!("cannot listen on {}", cfg.listen))?;
        let addr = tcp.local_addr().context("cannot listen")?;
        let inner = Arc::new(Inner {
            cfg,
            tls: Arc::new(tls),
            secret: cbb_core::certs::random_bytes(),
            state: Mutex::new(State::default()),
            stop: AtomicBool::new(false),
            sent: AtomicU64::new(0),
        });
        let accept = inner.clone();
        std::thread::Builder::new()
            .name("cbb-push accept".into())
            .spawn(move || accept.accept(tcp))
            .context("cannot start the service")?;
        Ok(Service { inner, addr })
    }

    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Counts for the log: tags held, tokens held, bodies sent.
    pub fn stats(&self) -> (usize, usize, u64) {
        let st = self.inner.lock();
        (st.periods.len(), st.tokens.len(), self.inner.sent.load(Ordering::Relaxed))
    }

    pub fn stop(&self) {
        self.inner.stop.store(true, Ordering::Relaxed);
        let _ = TcpStream::connect(self.addr);
    }
}

impl Inner {
    fn accept(self: Arc<Self>, tcp: TcpListener) {
        for c in tcp.incoming() {
            if self.stop.load(Ordering::Relaxed) {
                return;
            }
            let Ok(c) = c else { continue };
            let ip = c.peer_addr().map_or(IpAddr::from([0u8; 4]), |a| a.ip());
            {
                let mut st = self.lock();
                let b = self.cfg.budgets;
                let here = st.per_address.get(&ip).copied().unwrap_or(0);
                if st.connections >= b.connections || here >= b.per_address {
                    continue;
                }
                st.connections += 1;
                *st.per_address.entry(ip).or_default() += 1;
            }
            let me = self.clone();
            let spawned = std::thread::Builder::new().name("cbb-push conn".into()).spawn(move || {
                let _ = me.serve(c);
                let mut st = me.lock();
                st.connections -= 1;
                if let Some(n) = st.per_address.get_mut(&ip) {
                    *n -= 1;
                    if *n == 0 {
                        st.per_address.remove(&ip);
                    }
                }
            });
            if spawned.is_err() {
                let mut st = self.lock();
                st.connections -= 1;
                if let Some(n) = st.per_address.get_mut(&ip) {
                    *n -= 1;
                }
            }
        }
    }
}
