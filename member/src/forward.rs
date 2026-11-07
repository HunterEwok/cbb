// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! A hub's registration with the group's forwarder (docs/protocol.md,
//! section 13), as Go's forward.Register does it: TLS 1.3 to the forwarder
//! known by the pin of its key, the member certificate with the key kept
//! where the app keeps it, the proof of the hub's WireGuard key, the
//! group's records, then hellos from the hub's WireGuard port so that the
//! forwarder learns where that port is reached. The phones' hub in Rust
//! (ffi/) registers through it.
//!
//! When the forwarder's TCP port does not answer and the group's clients
//! come over VLESS, the registration goes inside VLESS with XHTTP, as the Go
//! hub's does (section 13, "VLESS"): through the settings the forwarder's
//! last answer gave, then the project's ways in, and the hub's hellos then
//! go over VLESS too, with the group's user ID.

use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use chacha20::ChaCha20;
use chacha20::cipher::{KeyIvInit, StreamCipher};
use gotatun::x25519::{PublicKey, StaticSecret};
use hmac::{Hmac, KeyInit, Mac};
use rustls::pki_types::{ServerName, UnixTime};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::Sha256;

use crate::certs::{self, b64};
use crate::error::{Context, Error, Result};

/// The registration's protocol and the labels of the keys it takes from TLS.
pub const PROTOCOL: &[u8] = b"cbb-forward/2";
const PROOF_LABEL: &[u8] = b"cbb forwarder key";
const HELLO_LABEL: &[u8] = b"cbb forwarder hello";

const SETUP_TIMEOUT: Duration = Duration::from_secs(15);
const HELLO_EVERY: Duration = Duration::from_secs(15);
const HELLO_FIRST: Duration = Duration::from_secs(1);
const MIN_BACKOFF: Duration = Duration::from_secs(1);
const MAX_BACKOFF: Duration = Duration::from_secs(60);
const MAX_FRAME: usize = 1 << 20;
const MAX_RECORDS: usize = 1024;
/// A hello: the type, the registration's ID, a counter and a MAC, behind the
/// mask's nonce and before up to HELLO_TAIL random bytes.
const NONCE: usize = 12;
const HELLO: usize = 4 + 8 + 8 + 16;
const HELLO_TAIL: usize = 32;
const MSG_HELLO: u8 = 0x80;

/// Sends a datagram from the hub's WireGuard port.
pub type SendFn = Arc<dyn Fn(SocketAddr, &[u8]) + Send + Sync>;

/// What a registration needs.
pub struct Config {
    /// The forwarder's address, the same for UDP and TCP, and the pins its
    /// key may have.
    pub endpoint: SocketAddr,
    pub pins: Vec<certs::KeyHash>,
    /// The hub's member certificate chain (the leaf, its admin CA if it has
    /// one, the group's roots) and its key.
    pub chain: Vec<Vec<u8>>,
    pub key: Arc<dyn crate::identity::ExternalKey>,
    /// The hub's WireGuard private key.
    pub wg_key: [u8; 32],
    /// The group's AmneziaWG settings, as the offers carry them.
    pub obfuscation: Option<Value>,
    /// The group's VLESS user ID, for a hub whose clients come over VLESS.
    pub vless_id: Option<String>,
    /// The group's authority records, which show the forwarder that the
    /// member key is the root's or an admin's; the next registration takes
    /// what is there then.
    pub records: Arc<Mutex<Vec<Value>>>,
    /// Sends a datagram from the hub's WireGuard port.
    pub send: SendFn,
    /// The project's ways in over VLESS, for a hub whose forwarder is the
    /// project's; the next registration takes what is there then.
    pub ways: Arc<Mutex<Ways>>,
    /// The VLESS settings of the forwarder's last answer, an offer's
    /// `vless`, which a registration over VLESS tries first; kept by the
    /// hub across its registrations.
    pub learned: Arc<Mutex<Option<Value>>>,
}

/// Whether the hub's forwarder is the project's, and the ways in over VLESS
/// that the newest signed entry points name for it (docs/protocol.md,
/// section 16, "Entry points"), as the phones' hub_set_project_ways takes them.
#[derive(Clone, Default, Debug)]
pub struct Ways {
    pub project: bool,
    pub entries: Vec<EntryWay>,
}

/// A way in of the entry points: `{transport, server_name, port, path}`.
#[derive(Clone, Debug, Deserialize)]
pub struct EntryWay {
    #[serde(default)]
    pub transport: String,
    pub server_name: String,
    pub port: u16,
    pub path: String,
}

/// The project's forwarder takes VLESS over XHTTP behind the web server of
/// cbb.tools, on its port 443 and this path (internal/forward's
/// ProjectVLESS): no secret the design relies on, it lets a hub that
/// reaches the forwarder only over VLESS register the first time.
const PROJECT_SITE: &str = "cbb.tools";
const PROJECT_XHTTP_PATH: &str = "/banMEJvnYJJap8S";
/// The most ways in a hub takes.
pub const MAX_WAYS: usize = 8;

/// The ways a hub tries over VLESS to its forwarder at addr when the
/// forwarder's TCP port does not answer, as Go's hub: the settings the
/// forwarder's last answer gave (learned, an offer's `vless`), then, for
/// the project's forwarder, the entry points' ways in, each site looked up
/// when it is not the forwarder's own, else the one built in. The user ID
/// is the group's; the registration puts its own in.
fn vless_ways(addr: std::net::IpAddr, id: &str, learned: Option<&Value>, ways: &Ways) -> Vec<cbb_core::vless::Link> {
    let mut out = Vec::new();
    if let Some(l) = learned.and_then(|v| cbb_core::vless::Link::from_offer(v).ok()) {
        out.push(l);
    }
    if !ways.project {
        return out;
    }
    let Ok(id) = cbb_core::vless::parse_id(id) else { return out };
    let mut project = Vec::new();
    for w in ways.entries.iter().take(MAX_WAYS) {
        if !w.transport.is_empty() && w.transport != "xhttp" {
            continue;
        }
        let at = if w.server_name == PROJECT_SITE {
            Some(addr)
        } else {
            use std::net::ToSocketAddrs;
            (w.server_name.as_str(), w.port).to_socket_addrs().ok().and_then(|mut a| a.next()).map(|a| a.ip())
        };
        let Some(at) = at else { continue };
        if w.port == 0
            || cbb_core::vless::check_server_name(&w.server_name).is_err()
            || cbb_core::vless::check_path(&w.path).is_err()
        {
            continue;
        }
        project.push(cbb_core::vless::Link {
            endpoint: SocketAddr::new(at, w.port).to_string(),
            server_name: w.server_name.clone(),
            path: w.path.clone(),
            id,
        });
    }
    if project.is_empty() {
        project.push(cbb_core::vless::Link {
            endpoint: SocketAddr::new(addr, 443).to_string(),
            server_name: PROJECT_SITE.into(),
            path: PROJECT_XHTTP_PATH.into(),
            id,
        });
    }
    out.extend(project);
    out
}

/// How the registration stands.
#[derive(Clone, Default, Serialize, Debug)]
pub struct Report {
    #[serde(skip_serializing_if = "core::ops::Not::not")]
    pub registered: bool,
    /// Where the forwarder reaches the hub's WireGuard port.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub seen: Option<String>,
    /// How the hub's clients reach the forwarder over VLESS, as an offer
    /// carries it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vless: Option<Value>,
    /// Why it is not registered.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// The running registration; dropping it stops it.
pub struct Registration {
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl Registration {
    /// Keeps the hub registered until dropped, registering again whenever
    /// the connection breaks; report hears how it stands.
    pub fn start(cfg: Config, report: Arc<Mutex<Report>>, log: Arc<dyn Fn(&str) + Send + Sync>) -> Registration {
        let stop = Arc::new(AtomicBool::new(false));
        let thread = {
            let stop = stop.clone();
            std::thread::spawn(move || run(&cfg, &report, &stop, &log))
        };
        Registration { stop, thread: Some(thread) }
    }
}

impl Drop for Registration {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

fn run(cfg: &Config, report: &Mutex<Report>, stop: &AtomicBool, log: &Arc<dyn Fn(&str) + Send + Sync>) {
    let mut backoff = MIN_BACKOFF;
    while !stop.load(Ordering::SeqCst) {
        let start = Instant::now();
        let err = match once(cfg, report, stop, log) {
            Ok(()) => return,
            Err(e) => e,
        };
        if stop.load(Ordering::SeqCst) {
            return;
        }
        let msg = err.for_log();
        log(&format!("cbb: the hub's registration with the forwarder: {msg}"));
        if let Ok(mut r) = report.lock() {
            // A failure leaves where the forwarder last saw the hub.
            *r = Report { error: Some(msg), seen: r.seen.take(), ..Report::default() };
        }
        if start.elapsed() > MAX_BACKOFF {
            backoff = MIN_BACKOFF;
        }
        let until = Instant::now() + backoff;
        while Instant::now() < until && !stop.load(Ordering::SeqCst) {
            std::thread::sleep(Duration::from_millis(100));
        }
        backoff = (backoff * 2).min(MAX_BACKOFF);
    }
}

#[derive(Debug)]
struct SystemClock;

impl rustls::time_provider::TimeProvider for SystemClock {
    fn current_time(&self) -> Option<UnixTime> {
        SystemTime::now().duration_since(UNIX_EPOCH).ok().map(UnixTime::since_unix_epoch)
    }
}

#[derive(Deserialize)]
struct Challenge {
    #[serde(with = "b64")]
    e: Vec<u8>,
}

#[derive(Serialize)]
struct Claim<'a> {
    #[serde(with = "b64")]
    key: Vec<u8>,
    #[serde(with = "b64")]
    proof: Vec<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    obfuscation: Option<&'a Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    vless: Option<&'a str>,
    /// A phone's root or admin key cannot sign without the user: the
    /// records show the forwarder that its member key is the root's or an
    /// admin's.
    admin_sig: Option<()>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    records: Vec<Value>,
}

#[derive(Deserialize, Default)]
struct Answer {
    #[serde(default)]
    id: u64,
    #[serde(with = "certs::b64::opt", default)]
    mask: Option<Vec<u8>>,
    #[serde(default)]
    vless: Option<VlessAnswer>,
    #[serde(default)]
    error: String,
    #[serde(default)]
    seen: String,
}

#[derive(Deserialize)]
struct VlessAnswer {
    #[serde(default)]
    transport: String,
    port: u16,
    #[serde(with = "certs::b64::opt", default)]
    public_key: Option<Vec<u8>>,
    #[serde(default)]
    short_id: String,
    server_name: String,
    #[serde(default)]
    path: String,
}

/// One registration, until it breaks or stop.
fn once(cfg: &Config, report: &Mutex<Report>, stop: &AtomicBool, log: &Arc<dyn Fn(&str) + Send + Sync>) -> Result<()> {
    let connect = |at: SocketAddr, tcp: TcpStream| {
        Registrar::handshake(tcp, at, &cfg.pins, &cfg.chain, &cfg.key, PROTOCOL, "forwarder")
    };
    // The stream over VLESS the registration took, and its way in.
    let mut over: Option<(crate::vless::Stream, cbb_core::vless::Link)> = None;
    let mut reg = match TcpStream::connect_timeout(&cfg.endpoint, SETUP_TIMEOUT) {
        Ok(tcp) => connect(cfg.endpoint, tcp)?,
        Err(direct) => {
            let direct = Error::msg(format!("reaching the forwarder: {direct}"));
            let Some(id) = &cfg.vless_id else { return Err(direct) };
            let ways = cfg.ways.lock().map(|w| w.clone()).unwrap_or_default();
            let learned = cfg.learned.lock().map(|l| l.clone()).unwrap_or_default();
            let ways = vless_ways(cfg.endpoint.ip(), id, learned.as_ref(), &ways);
            if ways.is_empty() {
                return Err(direct);
            }
            // Each way in until one gets through to the registration.
            let mut last = direct;
            let mut got = None;
            for w in ways {
                let tried = crate::vless::Stream::registration(&w, log.clone()).and_then(|s| {
                    let tcp = TcpStream::connect_timeout(&s.addr(), SETUP_TIMEOUT)
                        .context("cannot reach the stream over VLESS")?;
                    Ok((connect(s.addr(), tcp)?, s))
                });
                match tried {
                    Ok((r, s)) => {
                        over = Some((s, w));
                        got = Some(r);
                        break;
                    }
                    Err(e) => last = Error::msg(format!("{}; over VLESS: {}", last.for_log(), e.for_log())),
                }
            }
            got.ok_or(last)?
        }
    };
    let proof_key = reg.export(PROOF_LABEL)?;
    let hello_key = reg.export(HELLO_LABEL)?;
    let ch: Challenge = reg.read(stop)?;
    let (public, proof) = prove(&cfg.wg_key, &ch.e, &proof_key)
        .ok_or_else(|| Error::msg("registering with the forwarder: a bad challenge"))?;
    let mut records = cfg.records.lock().map(|r| r.clone()).unwrap_or_default();
    records.truncate(MAX_RECORDS);
    let claim = Claim {
        key: public.to_vec(),
        proof,
        obfuscation: cfg.obfuscation.as_ref(),
        vless: cfg.vless_id.as_deref(),
        admin_sig: None,
        records,
    };
    reg.write(&claim)?;
    let a: Answer = reg.read(stop)?;
    if !a.error.is_empty() {
        return Err(Error::msg(format!("the forwarder refused the registration: {}", a.error)));
    }
    let mask: [u8; 32] = a
        .mask
        .as_deref()
        .and_then(|m| m.try_into().ok())
        .ok_or_else(|| Error::msg("registering with the forwarder: no key for the hellos' mask"))?;
    let vless = match (&cfg.vless_id, a.vless) {
        (Some(id), Some(v)) => Some(vless_offer(cfg.endpoint, id, v)),
        (Some(_), None) => return Err(Error::msg("registering with the forwarder: it gave no VLESS settings")),
        (None, _) => None,
    };
    if vless.is_some()
        && let Ok(mut l) = cfg.learned.lock()
    {
        l.clone_from(&vless);
    }
    // Over VLESS the hub's own packets go there too, with the group's user
    // ID, which the forwarder lets in now: from the hub's WireGuard port to
    // a local port that leads to the forwarder's UDP port.
    let mut hello_to = cfg.endpoint;
    let mut _packets = None;
    if let (Some((_, way)), Some(id)) = (&over, &cfg.vless_id) {
        let way = serde_json::json!({
            "transport": "xhttp", "endpoint": way.endpoint, "server_name": way.server_name,
            "path": way.path, "id": id,
        });
        let c = vless
            .as_ref()
            .and_then(|v| crate::vless::Client::start(v, log.clone()).ok())
            .map_or_else(|| crate::vless::Client::start(&way, log.clone()), Ok)
            .map_err(|e| Error::msg(format!("the hub's packets over VLESS: {}", e.for_log())))?;
        hello_to = c.addr();
        _packets = Some(c);
    }
    if let Ok(mut r) = report.lock() {
        *r = Report { registered: true, vless: vless.clone(), ..Report::default() };
    }

    // Hellos until the connection breaks: every second until the forwarder
    // saw one, then every HELLO_EVERY; between them, its answers.
    reg.set_waiting()?;
    let mut counter = 0u64;
    let mut seen = String::new();
    let mut every = HELLO_FIRST;
    let mut next = Instant::now();
    while !stop.load(Ordering::SeqCst) {
        if Instant::now() >= next {
            let now = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_nanos() as u64).unwrap_or(0);
            counter = counter.saturating_add(1).max(now);
            (cfg.send)(hello_to, &hello(&mask, &hello_key, a.id, counter));
            next = Instant::now() + every;
        }
        let Some(f) = reg.next_frame(stop)? else { continue };
        let a: Answer = serde_json::from_slice(&f).unwrap_or_default();
        if !a.seen.is_empty() && a.seen != seen && a.seen.parse::<SocketAddr>().is_ok() {
            seen.clone_from(&a.seen);
            every = HELLO_EVERY;
            if let Ok(mut r) = report.lock() {
                *r = Report { registered: true, seen: Some(seen.clone()), vless: vless.clone(), ..Report::default() };
            }
        }
    }
    Ok(())
}

/// The VLESS settings an offer carries, from the forwarder's answer.
fn vless_offer(endpoint: SocketAddr, id: &str, v: VlessAnswer) -> Value {
    let mut m = serde_json::Map::new();
    if !v.transport.is_empty() {
        m.insert("transport".into(), Value::from(v.transport));
    }
    m.insert("endpoint".into(), Value::from(SocketAddr::new(endpoint.ip(), v.port).to_string()));
    if let Some(k) = v.public_key {
        m.insert("public_key".into(), Value::from(base64_std(&k)));
    }
    if !v.short_id.is_empty() {
        m.insert("short_id".into(), Value::from(v.short_id));
    }
    m.insert("server_name".into(), Value::from(v.server_name));
    if !v.path.is_empty() {
        m.insert("path".into(), Value::from(v.path));
    }
    m.insert("id".into(), Value::from(id));
    Value::Object(m)
}

fn base64_std(b: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(b)
}

/// The TLS connection of a registration with a server known by the pin
/// of its key, the forwarder or the relay (what, in the errors), as Go's
/// forward.TLSVerifiedByPin: its frames, JSON behind a 4-byte length, and
/// the keys exported from its TLS.
pub(crate) struct Registrar {
    s: rustls::StreamOwned<rustls::ClientConnection, TcpStream>,
    inbox: Vec<u8>,
    what: &'static str,
    /// Set up: a read that times out returns at once.
    waiting: bool,
}

impl Registrar {
    pub(crate) fn connect(
        endpoint: SocketAddr,
        pins: &[certs::KeyHash],
        chain: &[Vec<u8>],
        key: &Arc<dyn crate::identity::ExternalKey>,
        protocol: &[u8],
        what: &'static str,
    ) -> Result<Registrar> {
        let tcp = TcpStream::connect_timeout(&endpoint, SETUP_TIMEOUT)
            .map_err(|e| Error::msg(format!("reaching the {what}: {e}")))?;
        Registrar::handshake(tcp, endpoint, pins, chain, key, protocol, what)
    }

    /// The registration's TLS over a connection to endpoint.
    pub(crate) fn handshake(
        tcp: TcpStream,
        endpoint: SocketAddr,
        pins: &[certs::KeyHash],
        chain: &[Vec<u8>],
        key: &Arc<dyn crate::identity::ExternalKey>,
        protocol: &[u8],
        what: &'static str,
    ) -> Result<Registrar> {
        let clock: cbb_core::tls::Clock = Arc::new(SystemClock);
        let tls = cbb_core::tls::pinned_client(chain.to_vec(), key.clone(), pins.to_vec(), protocol, &clock)?;
        tcp.set_read_timeout(Some(SETUP_TIMEOUT)).context("a registration's socket")?;
        tcp.set_write_timeout(Some(SETUP_TIMEOUT)).context("a registration's socket")?;
        let _ = tcp.set_nodelay(true);
        // The server has no name; the pin names it, and the hello carries
        // no server name.
        let conn = rustls::ClientConnection::new(Arc::new(tls), ServerName::IpAddress(endpoint.ip().into()))
            .map_err(|e| Error::msg(format!("registering with the {what}: {e}")))?;
        let mut s = rustls::StreamOwned::new(conn, tcp);
        while s.conn.is_handshaking() {
            s.conn.complete_io(&mut s.sock).map_err(|e| Error::msg(format!("registering with the {what}: {e}")))?;
        }
        if s.conn.alpn_protocol() != Some(protocol) {
            return Err(Error::msg(format!("the {what} does not speak the registration protocol")));
        }
        Ok(Registrar { s, inbox: Vec::new(), what, waiting: false })
    }

    /// A key from the registration's TLS under label.
    pub(crate) fn export(&self, label: &[u8]) -> Result<[u8; 32]> {
        let out = self
            .s
            .conn
            .export_keying_material(bytes::BytesMut::zeroed(32), label, None)
            .map_err(|e| Error::msg(format!("registering with the {}: {e}", self.what)))?;
        out[..].try_into().map_err(|_| Error::msg(format!("registering with the {}: a short key", self.what)))
    }

    pub(crate) fn write<T: Serialize>(&mut self, v: &T) -> Result<()> {
        let what = self.what;
        let f = crate::wire::json_frame(v, MAX_FRAME)?;
        self.s
            .write_all(&f)
            .and_then(|()| self.s.flush())
            .map_err(|e| Error::msg(format!("registering with the {what}: {e}")))
    }

    /// The next message during the setup.
    pub(crate) fn read<T: serde::de::DeserializeOwned>(&mut self, stop: &AtomicBool) -> Result<T> {
        let f =
            self.next_frame(stop)?.ok_or_else(|| Error::msg(format!("registering with the {}: stopped", self.what)))?;
        serde_json::from_slice(&f).map_err(|_| Error::msg(format!("registering with the {}: a bad message", self.what)))
    }

    /// Ends the setup: from now on reads wait a moment only, so that the
    /// caller does its work between them.
    pub(crate) fn set_waiting(&mut self) -> Result<()> {
        self.waiting = true;
        self.s.sock.set_read_timeout(Some(Duration::from_millis(250))).context("a registration's socket")
    }

    /// The next whole frame, gathering what arrives; None when nothing came
    /// in a moment once the setup ended, or on stop.
    pub(crate) fn next_frame(&mut self, stop: &AtomicBool) -> Result<Option<Vec<u8>>> {
        let deadline = Instant::now() + SETUP_TIMEOUT;
        let mut buf = [0u8; 4096];
        loop {
            if let Some(head) = self.inbox.get(..4).and_then(|h| <[u8; 4]>::try_from(h).ok()) {
                let n = crate::wire::frame_len(head, MAX_FRAME)?;
                if self.inbox.len() >= 4 + n {
                    let f = self.inbox[4..4 + n].to_vec();
                    self.inbox.drain(..4 + n);
                    return Ok(Some(f));
                }
            }
            match self.s.read(&mut buf) {
                Ok(0) => return Err(Error::msg(format!("the {} closed the connection", self.what))),
                Ok(n) => self.inbox.extend_from_slice(&buf[..n]),
                Err(e) if matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut) => {
                    if self.waiting || stop.load(Ordering::SeqCst) {
                        return Ok(None);
                    }
                    if Instant::now() >= deadline {
                        return Err(Error::msg(format!("the {} did not answer", self.what)));
                    }
                }
                Err(e) => return Err(Error::msg(format!("the connection to the {} broke: {e}", self.what))),
            }
        }
    }
}

/// The proof that the device holds its WireGuard key wg_key, for the
/// server's ephemeral key e: its public key and HMAC-SHA256(X25519(wg_key,
/// e), proof_key); None for a bad e.
pub(crate) fn prove(wg_key: &[u8; 32], e: &[u8], proof_key: &[u8; 32]) -> Option<([u8; 32], Vec<u8>)> {
    let e: [u8; 32] = e.try_into().ok()?;
    let secret = StaticSecret::from(*wg_key);
    let shared = secret.diffie_hellman(&PublicKey::from(e));
    if !shared.was_contributory() {
        return None;
    }
    let mut m = <Hmac<Sha256> as KeyInit>::new_from_slice(shared.as_bytes()).ok()?;
    m.update(proof_key);
    Some((*PublicKey::from(&secret).as_bytes(), m.finalize().into_bytes().to_vec()))
}

/// A hub's hello for the registration id (Go's forward.hello): the counter
/// only grows, the MAC under the registration's key proves it is the hub's,
/// and ChaCha20 under the forwarder's mask key and a random nonce hides it,
/// with a random length.
pub fn hello(mask: &[u8; 32], key: &[u8; 32], id: u64, counter: u64) -> Vec<u8> {
    let mut tail = [0u8; 1];
    let _ = getrandom::fill(&mut tail);
    let mut p = bytes::BytesMut::zeroed(NONCE + HELLO + usize::from(tail[0]) % HELLO_TAIL);
    let _ = getrandom::fill(&mut p);
    let (nonce, rest) = p.split_at_mut(NONCE);
    let h = &mut rest[..HELLO];
    h[..4].copy_from_slice(&[MSG_HELLO, 0, 0, 0]);
    h[4..12].copy_from_slice(&id.to_be_bytes());
    h[12..20].copy_from_slice(&counter.to_be_bytes());
    if let Ok(mut m) = <Hmac<Sha256> as KeyInit>::new_from_slice(key) {
        m.update(&h[..20]);
        let mac = m.finalize().into_bytes();
        h[20..].copy_from_slice(&mac[..16]);
    }
    let mut c = ChaCha20::new(mask.into(), (&*nonce).into());
    c.apply_keystream(h);
    p.to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The ways in over VLESS, as Go's hub orders them: the forwarder's last
    /// answer, then the project's, the entry points' that are good, else
    /// the one built in; none for a forwarder that is not the project's
    /// and has not answered.
    #[test]
    fn ways_in_over_vless() {
        let at: std::net::IpAddr = "192.0.2.7".parse().unwrap();
        let id = "6f1c2b9e-3d4a-4f5b-8c7d-0e1f2a3b4c5d";
        let learned = serde_json::json!({"transport": "xhttp", "endpoint": "192.0.2.7:8443",
            "server_name": "cbb.example.org", "path": "/AbC-12_xyz0123456/a-group-of-its-own", "id": id});
        assert!(vless_ways(at, id, None, &Ways::default()).is_empty());
        let w = vless_ways(at, id, Some(&learned), &Ways::default());
        assert_eq!(w.len(), 1);
        assert_eq!(w[0].endpoint, "192.0.2.7:8443");

        let built_in = vless_ways(at, id, None, &Ways { project: true, entries: vec![] });
        assert_eq!(built_in.len(), 1);
        assert_eq!(
            (built_in[0].endpoint.as_str(), built_in[0].server_name.as_str(), built_in[0].path.as_str()),
            ("192.0.2.7:443", "cbb.tools", "/banMEJvnYJJap8S")
        );
        let entry = |transport: &str, path: &str| EntryWay {
            transport: transport.into(),
            server_name: "cbb.tools".into(),
            port: 8443,
            path: path.into(),
        };
        let ways = Ways {
            project: true,
            entries: vec![entry("xhttp", "/a-way-in-of-its-own"), entry("grpc", "/another-way-in"), entry("", "bad")],
        };
        let w = vless_ways(at, id, Some(&learned), &ways);
        assert_eq!(w.len(), 2, "{w:?}");
        assert_eq!(w[0].server_name, "cbb.example.org");
        assert_eq!((w[1].endpoint.as_str(), w[1].path.as_str()), ("192.0.2.7:8443", "/a-way-in-of-its-own"));
    }

    #[test]
    fn hellos_open_with_the_mask() {
        let mask: [u8; 32] = crate::tunnel::new_key().unwrap().try_into().unwrap();
        let key: [u8; 32] = crate::tunnel::new_key().unwrap().try_into().unwrap();
        let a = hello(&mask, &key, 7, 9);
        let b = hello(&mask, &key, 7, 9);
        assert!(a.len() >= NONCE + HELLO && a.len() < NONCE + HELLO + HELLO_TAIL);
        assert_ne!(a, b);
        let mut h = a[NONCE..NONCE + HELLO].to_vec();
        ChaCha20::new((&mask).into(), a[..NONCE].into()).apply_keystream(&mut h);
        assert_eq!(h[..4], [MSG_HELLO, 0, 0, 0]);
        assert_eq!(u64::from_be_bytes(h[4..12].try_into().unwrap()), 7);
        assert_eq!(u64::from_be_bytes(h[12..20].try_into().unwrap()), 9);
        let mut m = <Hmac<Sha256> as KeyInit>::new_from_slice(&key).unwrap();
        m.update(&h[..20]);
        assert_eq!(h[20..], m.finalize().into_bytes()[..16]);
    }
}
