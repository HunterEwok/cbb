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
//! Over VLESS, when the forwarder's TCP port does not answer, the Go hub
//! registers inside VLESS; this one does not yet, and reports the failure.

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
        let err = match once(cfg, report, stop) {
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
fn once(cfg: &Config, report: &Mutex<Report>, stop: &AtomicBool) -> Result<()> {
    let mut reg = Registrar::connect(cfg.endpoint, &cfg.pins, &cfg.chain, &cfg.key, PROTOCOL, "forwarder")?;
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
            (cfg.send)(cfg.endpoint, &hello(&mask, &hello_key, a.id, counter));
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
        let clock: cbb_core::tls::Clock = Arc::new(SystemClock);
        let tls = cbb_core::tls::pinned_client(chain.to_vec(), key.clone(), pins.to_vec(), protocol, &clock)?;
        let tcp = TcpStream::connect_timeout(&endpoint, SETUP_TIMEOUT)
            .map_err(|e| Error::msg(format!("reaching the {what}: {e}")))?;
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
