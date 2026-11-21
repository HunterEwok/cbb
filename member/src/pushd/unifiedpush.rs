// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! UnifiedPush (env 4): the body posted to the endpoint the phone's
//! distributor gave (RFC 8030), encrypted to the phone's keys (RFC 8291,
//! `aes128gcm`). The endpoint is a URL a phone named, so beside its shape
//! (`cbb_core::push::up_url`, the reader's) the service:
//!
//! - resolves the name once per send and connects to that address only,
//!   and only when it is global (`cbb_core::blind::card::public_ip`, the
//!   rule of a card's addresses), so no name leads it to a private,
//!   loopback, link-local or reserved address, however its DNS answers
//!   later;
//! - follows no redirect: an answer of 3xx is a failure;
//! - sends at most one message, reads at most 4 KiB of the answer, and
//!   gives the whole send (the lookup included) 8 s, under the member's
//!   own wait for the answer;
//! - budgets per group and host (a name lowercased); per group and
//!   address dialed; and per address for every group together, which
//!   refuses only the groups that already sent there most, so that neither
//!   a stranger's sends to a distributor's host nor many names at one
//!   address starve the others;
//! - a host that answered 429 waits as long as it asked (at most a day),
//!   for the group that asked only; that name at that address waits for
//!   everyone only when three groups were told so within ten minutes, and
//!   then at most five minutes; no other name at the address ever waits
//!   for it, so names of a stranger's own never close the address of the
//!   phone's distributor;
//! - keeps its tables as the service keeps its own (`shares.rs`), each
//!   group a share: when one is full, the group with the most entries
//!   loses its oldest, and no one is refused for it.
//!
//! The message the phone decrypts is parts, each a kind (1 byte), a length
//! (2 bytes, big-endian) and its bytes: kind 1 the body, kind 2 a
//! challenge of the service (24 bytes: the value, then the hint of the
//! send key it is for), kind 3 padding in place of a part that is not
//! there, so that every message has one size. The app reads the kinds it
//! knows and skips the others, so a size of the registry may change.

use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes128Gcm, Nonce};
use hkdf::Hkdf;
use p256::elliptic_curve::sec1::ToSec1Point;
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, StreamOwned};
use sha2::Sha256;

use super::shares::{Payer, Shared};
use super::{Delivery, Outcome, Platform};

/// The record size the header names: one record holds the whole body.
const RS: u32 = 4096;
/// The whole send, the lookup included.
const DEADLINE: Duration = Duration::from_secs(8);
/// The most of an answer read.
const MAX_ANSWER: usize = 4096;
/// Sends an hour and the burst: per group and host, per group and
/// address, and per address for every group.
const PER_TAG_HOST: (f64, f64) = (300.0, 30.0);
const PER_TAG_ADDRESS: (f64, f64) = (300.0, 30.0);
const PER_ADDRESS: (f64, f64) = (6000.0, 600.0);
/// Entries held at most in each table.
const TABLE_MAX: usize = 65_536;
/// How long a name at an address waits for everyone at most, and how many
/// groups' 429s from it within the window it takes.
const ADDRESS_WAIT_MAX: Duration = Duration::from_secs(300);
const ADDRESS_WAIT_GROUPS: usize = 3;
const ADDRESS_WAIT_WINDOW: Duration = Duration::from_secs(600);
/// The kinds of the message's parts.
pub const PART_BODY: u8 = 1;
pub const PART_CHALLENGE: u8 = 2;
pub const PART_PADDING: u8 = 3;

/// The message for the phone: its parts in kind order, a part that is not
/// there padded to its size, so a body, a body with a challenge and a
/// challenge alone are all one size (the body is always the registry's).
pub fn message(body: Option<&[u8]>, challenge: Option<&super::Challenge>) -> Vec<u8> {
    let mut out = Vec::new();
    let mut part = |kind: u8, b: &[u8]| {
        out.push(kind);
        out.extend_from_slice(&(b.len() as u16).to_be_bytes());
        out.extend_from_slice(b);
    };
    match body {
        Some(b) => part(PART_BODY, b),
        None => part(PART_PADDING, &[0; cbb_core::push::MAX_BODY]),
    }
    match challenge {
        Some(c) => part(PART_CHALLENGE, &c.bytes()),
        None => part(PART_PADDING, &[0; 24]),
    }
    out
}

/// RFC 8291's encryption of `plain` to the phone's `ua_public` (65 bytes)
/// and `auth`, with the sender's ephemeral key `as_secret` and `salt`: the
/// header (salt, record size, the sender's public key) and one record.
pub fn encrypt(
    plain: &[u8],
    ua_public: &[u8; 65],
    auth: &[u8; 16],
    as_secret: &p256::SecretKey,
    salt: &[u8; 16],
) -> Option<Vec<u8>> {
    let ua = p256::PublicKey::from_sec1_bytes(ua_public).ok()?;
    let as_public = as_secret.public_key().to_sec1_point(false);
    let as_public = as_public.as_bytes();
    let shared = p256::ecdh::diffie_hellman(as_secret.to_nonzero_scalar(), ua.as_affine());
    let mut key_info = b"WebPush: info\0".to_vec();
    key_info.extend_from_slice(ua_public);
    key_info.extend_from_slice(as_public);
    let mut ikm = [0u8; 32];
    Hkdf::<Sha256>::new(Some(auth), shared.raw_secret_bytes()).expand(&key_info, &mut ikm).ok()?;
    let prk = Hkdf::<Sha256>::new(Some(salt), &ikm);
    let mut cek = [0u8; 16];
    let mut nonce = [0u8; 12];
    prk.expand(b"Content-Encoding: aes128gcm\0", &mut cek).ok()?;
    prk.expand(b"Content-Encoding: nonce\0", &mut nonce).ok()?;
    let mut record = plain.to_vec();
    // The last record's delimiter, no padding.
    record.push(2);
    let sealed =
        Aes128Gcm::new_from_slice(&cek).ok()?.encrypt(&Nonce::from(nonce), Payload { msg: &record, aad: &[] }).ok()?;
    let mut out = Vec::with_capacity(21 + as_public.len() + sealed.len());
    out.extend_from_slice(salt);
    out.extend_from_slice(&RS.to_be_bytes());
    out.push(as_public.len() as u8);
    out.extend_from_slice(as_public);
    out.extend_from_slice(&sealed);
    Some(out)
}

/// The first global address of a name's answer, or None.
pub fn pick(addrs: impl IntoIterator<Item = SocketAddr>, allowed: &dyn Fn(IpAddr) -> bool) -> Option<SocketAddr> {
    addrs.into_iter().find(|a| allowed(a.ip()))
}

/// The request's head for `path` on `host`, a body of `len` bytes kept for
/// `ttl_s`.
pub fn request(host: &str, path: &str, len: usize, ttl_s: u64) -> String {
    format!(
        "POST {path} HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/octet-stream\r\nContent-Encoding: aes128gcm\r\nContent-Length: {len}\r\nTTL: {ttl_s}\r\nUrgency: high\r\nConnection: close\r\n\r\n"
    )
}

/// What an answer's status line and head mean. No redirect is followed.
pub fn outcome(answer: &[u8]) -> Outcome {
    let text = String::from_utf8_lossy(answer);
    let mut lines = text.split("\r\n");
    // Exactly three digits, then a space or the end of the line.
    let status = lines
        .next()
        .and_then(|l| l.strip_prefix("HTTP/1.1 ").or_else(|| l.strip_prefix("HTTP/1.0 ")))
        .filter(|l| l.len() == 3 || l.as_bytes().get(3) == Some(&b' '))
        .and_then(|l| l.get(..3))
        .filter(|s| s.bytes().all(|b| b.is_ascii_digit()))
        .and_then(|s| s.parse::<u16>().ok());
    let retry = lines
        .take_while(|l| !l.is_empty())
        .find_map(|l| {
            let (k, v) = l.split_once(':')?;
            k.trim().eq_ignore_ascii_case("retry-after").then(|| v.trim().parse::<u64>().ok()).flatten()
        })
        .map(|s| Duration::from_secs(s.clamp(1, 86_400)));
    match status {
        Some(200..=299) => Outcome::Sent,
        Some(404 | 410) => Outcome::Gone,
        Some(429) => Outcome::Later(retry.unwrap_or(Duration::from_secs(60))),
        Some(500..=599) => Outcome::Later(retry.unwrap_or(Duration::from_secs(30))),
        // A redirect, a refusal of the request, or no answer that reads.
        _ => Outcome::NoPath,
    }
}

#[derive(Clone, Copy)]
struct Bucket {
    left: f64,
    at: Instant,
}

impl Bucket {
    fn full((_, burst): (f64, f64), at: Instant) -> Bucket {
        Bucket { left: burst, at }
    }

    /// What is left now.
    fn fill(&mut self, (per_hour, burst): (f64, f64), now: Instant) -> f64 {
        self.left = (self.left + now.saturating_duration_since(self.at).as_secs_f64() * per_hour / 3600.0).min(burst);
        self.at = now;
        self.left
    }

    /// Takes one; the wait when it is spent.
    fn take(&mut self, rate: (f64, f64), now: Instant) -> Option<Duration> {
        if self.fill(rate, now) >= 1.0 {
            self.left -= 1.0;
            None
        } else {
            Some(Duration::from_secs_f64(((1.0 - self.left) * 3600.0 / rate.0).max(1.0)))
        }
    }
}

/// A name's recent 429s at one address: by which groups, and when.
#[derive(Clone, Default)]
struct Told {
    by: Vec<(Payer, Instant)>,
}

/// How the service reaches an endpoint: TLS with the system's roots, or for
/// the tests plain TCP to a loopback server.
enum Dial {
    Tls(Arc<ClientConfig>),
    #[cfg(test)]
    Plain,
}

/// How a host name becomes its addresses.
type Resolve = Arc<dyn Fn(&str) -> Vec<SocketAddr> + Send + Sync>;

/// The UnifiedPush path.
pub struct UnifiedPush {
    dial: Dial,
    allowed: Box<dyn Fn(IpAddr) -> bool + Send + Sync>,
    resolve: Resolve,
    budgets: Mutex<Budgets>,
}

/// The budgets and waits, each table shared by the groups (a group's tag
/// is its share).
struct Budgets {
    /// By (group, host).
    hosts: Shared<Bucket>,
    /// By (group, address).
    shares: Shared<Bucket>,
    /// By address, for every group.
    addresses: Shared<Bucket>,
    /// Until when a group leaves a host alone, by (group, host).
    waits: Shared<Instant>,
    /// Until when everyone leaves a name at an address alone, by (address,
    /// host).
    closed: Shared<Instant>,
    /// The recent 429s by (address, host).
    told: Shared<Told>,
}

impl Default for Budgets {
    fn default() -> Budgets {
        Budgets {
            hosts: Shared::new(TABLE_MAX),
            shares: Shared::new(TABLE_MAX),
            addresses: Shared::new(TABLE_MAX),
            waits: Shared::new(TABLE_MAX),
            closed: Shared::new(TABLE_MAX),
            told: Shared::new(TABLE_MAX),
        }
    }
}

/// A table's key for what parts name.
fn key(what: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    use sha2::Digest;
    let mut h = Sha256::new();
    h.update(what);
    for p in parts {
        h.update((p.len() as u32).to_be_bytes());
        h.update(p);
    }
    h.finalize().into()
}

fn share(tag: &[u8; 32]) -> Payer {
    let mut p = [0u8; 16];
    p.copy_from_slice(&tag[..16]);
    p
}

fn ip_bytes(ip: IpAddr) -> [u8; 16] {
    match ip.to_canonical() {
        IpAddr::V4(v4) => v4.to_ipv6_mapped().octets(),
        IpAddr::V6(v6) => v6.octets(),
    }
}

/// Takes one from the bucket under k, filed for payer if new; the wait.
fn take(t: &mut Shared<Bucket>, k: [u8; 32], payer: Payer, rate: (f64, f64), now: Instant) -> Option<Duration> {
    if t.get(&k).is_none() {
        let hour = Duration::from_secs(3600);
        t.insert(k, Bucket::full(rate, now), payer, |b| now.saturating_duration_since(b.at) >= hour);
    }
    t.get_mut(&k).and_then(|b| b.take(rate, now))
}

/// The wait left under k in t, if any.
fn waiting(t: &mut Shared<Instant>, k: &[u8; 32], now: Instant) -> Option<Duration> {
    match t.get(k).copied() {
        Some(until) if until > now => Some(until - now),
        Some(_) => {
            t.remove(k);
            None
        }
        None => None,
    }
}

fn system_resolve(host: &str) -> Vec<SocketAddr> {
    (host, 443).to_socket_addrs().map(|a| a.collect()).unwrap_or_default()
}

/// Looks host up within `limit`; nothing when the lookup takes longer
/// (the system's resolver has no limit of ours, so it runs aside).
fn resolve_within(resolve: &Resolve, host: &str, limit: Duration) -> Vec<SocketAddr> {
    let (tx, rx) = std::sync::mpsc::channel();
    let (r, h) = (resolve.clone(), host.to_string());
    if std::thread::Builder::new()
        .name("cbb-push lookup".into())
        .spawn(move || {
            let _ = tx.send(r(&h));
        })
        .is_err()
    {
        return Vec::new();
    }
    rx.recv_timeout(limit).unwrap_or_default()
}

impl UnifiedPush {
    pub fn new(roots: rustls::RootCertStore) -> crate::error::Result<UnifiedPush> {
        use crate::error::Context;
        let cfg = ClientConfig::builder_with_provider(Arc::new(cbb_core::tls::web::provider()))
            .with_safe_default_protocol_versions()
            .context("cannot set up the TLS toward UnifiedPush servers")?
            .with_root_certificates(roots)
            .with_no_client_auth();
        Ok(UnifiedPush {
            dial: Dial::Tls(Arc::new(cfg)),
            allowed: Box::new(cbb_core::blind::card::public_ip),
            resolve: Arc::new(system_resolve),
            budgets: Mutex::new(Budgets::default()),
        })
    }

    #[cfg(test)]
    fn plain(
        allowed: impl Fn(IpAddr) -> bool + Send + Sync + 'static,
        resolve: impl Fn(&str) -> Vec<SocketAddr> + Send + Sync + 'static,
    ) -> UnifiedPush {
        UnifiedPush {
            dial: Dial::Plain,
            allowed: Box::new(allowed),
            resolve: Arc::new(resolve),
            budgets: Mutex::new(Budgets::default()),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Budgets> {
        self.budgets.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Takes one send from the group's budget at host, unless a 429 told
    /// the group to leave it alone; the wait.
    fn budget(&self, tag: &[u8; 32], host: &str) -> Option<Duration> {
        let now = Instant::now();
        let host = host.to_ascii_lowercase();
        let k = key(b"host", &[tag, host.as_bytes()]);
        let mut b = self.lock();
        if let Some(w) = waiting(&mut b.waits, &k, now) {
            return Some(w);
        }
        take(&mut b.hosts, k, share(tag), PER_TAG_HOST, now)
    }

    /// Takes one send from the group's share of the address and from the
    /// address's budget, unless host at the address is closed for
    /// everyone; the wait. When the address's budget is spent, only the
    /// groups that sent there most (half their share spent or more) wait
    /// for it.
    fn address(&self, tag: &[u8; 32], host: &str, ip: IpAddr) -> Option<Duration> {
        let now = Instant::now();
        let ipb = ip_bytes(ip);
        let ka = key(b"address", &[&ipb]);
        let kc = key(b"closed", &[&ipb, host.to_ascii_lowercase().as_bytes()]);
        let ks = key(b"share", &[tag, &ipb]);
        let payer = share(tag);
        let mut b = self.lock();
        if let Some(w) = waiting(&mut b.closed, &kc, now) {
            return Some(w);
        }
        if let Some(w) = take(&mut b.shares, ks, payer, PER_TAG_ADDRESS, now) {
            return Some(w);
        }
        let light = b.shares.get_mut(&ks).is_some_and(|s| s.fill(PER_TAG_ADDRESS, now) >= PER_TAG_ADDRESS.1 / 2.0);
        match take(&mut b.addresses, ka, payer, PER_ADDRESS, now) {
            Some(w) if !light => Some(w),
            _ => None,
        }
    }

    /// The host at ip answered the group 429 with wait d: the group leaves
    /// the host alone that long; that name at that address closes for
    /// everyone (five minutes at most) once three groups were told so
    /// within ten minutes. Other names at the address go on.
    fn told_to_wait(&self, tag: &[u8; 32], host: &str, ip: IpAddr, d: Duration) {
        let now = Instant::now();
        let ipb = ip_bytes(ip);
        let payer = share(tag);
        let host = host.to_ascii_lowercase();
        let kw = key(b"host", &[tag, host.as_bytes()]);
        let ka = key(b"closed", &[&ipb, host.as_bytes()]);
        let mut b = self.lock();
        b.waits.insert(kw, now + d, payer, |u| *u <= now);
        if b.told.get(&ka).is_none() {
            b.told.insert(ka, Told::default(), payer, |t| {
                t.by.iter().all(|(_, at)| now.saturating_duration_since(*at) >= ADDRESS_WAIT_WINDOW)
            });
        }
        let Some(t) = b.told.get_mut(&ka) else { return };
        t.by.retain(|(p, at)| *p != payer && now.saturating_duration_since(*at) < ADDRESS_WAIT_WINDOW);
        t.by.push((payer, now));
        if t.by.len() >= ADDRESS_WAIT_GROUPS {
            t.by.clear();
            b.closed.insert(ka, now + d.min(ADDRESS_WAIT_MAX), payer, |u| *u <= now);
        }
    }

    fn post(&self, addr: SocketAddr, host: &str, head: &str, body: &[u8], until: Instant) -> Option<Vec<u8>> {
        let left = until.checked_duration_since(Instant::now()).filter(|d| !d.is_zero())?;
        let tcp = TcpStream::connect_timeout(&addr, left).ok()?;
        match &self.dial {
            Dial::Tls(cfg) => {
                let name = ServerName::try_from(host.to_string()).ok()?;
                let conn = ClientConnection::new(cfg.clone(), name).ok()?;
                exchange(Timed { s: StreamOwned::new(conn, tcp.try_clone().ok()?), tcp, until }, head, body)
            }
            #[cfg(test)]
            Dial::Plain => exchange(Timed { s: tcp.try_clone().ok()?, tcp, until }, head, body),
        }
    }
}

/// A stream whose every read and write waits only for what is left of
/// the send's deadline, so a peer that answers a byte at a time still ends
/// at the deadline.
struct Timed<S> {
    s: S,
    tcp: TcpStream,
    until: Instant,
}

impl<S> Timed<S> {
    fn arm(&self) -> std::io::Result<()> {
        let left = self
            .until
            .checked_duration_since(Instant::now())
            .filter(|d| !d.is_zero())
            .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::TimedOut))?;
        self.tcp.set_read_timeout(Some(left))?;
        self.tcp.set_write_timeout(Some(left))
    }
}

impl<S: Read> Read for Timed<S> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.arm()?;
        self.s.read(buf)
    }
}

impl<S: Write> Write for Timed<S> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.arm()?;
        self.s.write(buf)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.arm()?;
        self.s.flush()
    }
}

fn exchange(mut s: impl Read + Write, head: &str, body: &[u8]) -> Option<Vec<u8>> {
    s.write_all(head.as_bytes()).ok()?;
    s.write_all(body).ok()?;
    s.flush().ok()?;
    let mut answer = Vec::new();
    let mut buf = [0u8; 1024];
    while answer.len() < MAX_ANSWER {
        match s.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => answer.extend_from_slice(&buf[..n.min(MAX_ANSWER - answer.len())]),
        }
        // The status line and the head are all that is read of it.
        if answer.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
    }
    (!answer.is_empty()).then_some(answer)
}

/// The endpoint's host and path; the shape was checked by `up_url`.
fn split(url: &str) -> Option<(String, String)> {
    let rest = url.strip_prefix("https://")?;
    let (authority, path) = match rest.find(['/', '?']) {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let host = authority.strip_suffix(":443").unwrap_or(authority);
    let path = if path.starts_with('?') { format!("/{path}") } else { path.to_string() };
    Some((host.to_string(), path))
}

impl Platform for UnifiedPush {
    fn send(&self, d: &Delivery<'_>) -> Outcome {
        let until = Instant::now() + DEADLINE;
        if d.env != cbb_core::push::ENV_UNIFIEDPUSH || (d.body.is_none() && d.challenge.is_none()) {
            return Outcome::NoPath;
        }
        let Ok(up) = cbb_core::push::UnifiedPush::read(d.token) else { return Outcome::NoPath };
        let Some((host, path)) = split(up.url) else { return Outcome::NoPath };
        let host = host.to_ascii_lowercase();
        if let Some(wait) = self.budget(&d.tag, &host) {
            return Outcome::Later(wait);
        }
        // Resolved once: the address checked is the one connected to.
        let addrs = resolve_within(&self.resolve, &host, DEADLINE / 2);
        let Some(addr) = pick(addrs, &*self.allowed) else { return Outcome::NoPath };
        if let Some(wait) = self.address(&d.tag, &host, addr.ip()) {
            return Outcome::Later(wait);
        }
        let secret = p256::SecretKey::from_bytes(&cbb_core::certs::random_bytes::<32>().into());
        let Ok(secret) = secret else { return Outcome::Later(Duration::from_secs(1)) };
        let plain = message(d.body, d.challenge.as_ref());
        let Some(sealed) = encrypt(&plain, up.p256dh, up.auth, &secret, &cbb_core::certs::random_bytes()) else {
            return Outcome::NoPath;
        };
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs());
        let head = request(&host, &path, sealed.len(), d.expires_s.saturating_sub(now).max(1));
        match self.post(addr, &host, &head, &sealed, until) {
            Some(answer) => {
                let o = outcome(&answer);
                if let (Outcome::Later(wait), true) =
                    (&o, answer.starts_with(b"HTTP/1.1 429") || answer.starts_with(b"HTTP/1.0 429"))
                {
                    self.told_to_wait(&d.tag, &host, addr.ip(), *wait);
                }
                o
            }
            None => Outcome::Later(Duration::from_secs(30)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
    use p256::elliptic_curve::sec1::ToSec1Point;
    use std::net::TcpListener;

    fn b(s: &str) -> Vec<u8> {
        B64.decode(s).unwrap()
    }

    /// RFC 8291, appendix A.
    #[test]
    fn the_encryption_gives_rfc_8291s_example() {
        let plain = b"When I grow up, I want to be a watermelon";
        let as_secret = p256::SecretKey::from_slice(&b("yfWPiYE-n46HLnH0KqZOF1fJJU3MYrct3AELtAQ-oRw")).unwrap();
        let ua_public: [u8; 65] =
            b("BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcxaOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4")
                .try_into()
                .unwrap();
        let auth: [u8; 16] = b("BTBZMqHH6r4Tts7J_aSIgg").try_into().unwrap();
        let salt: [u8; 16] = b("DGv6ra1nlYgDCS1FRnbzlw").try_into().unwrap();
        let got = encrypt(plain, &ua_public, &auth, &as_secret, &salt).unwrap();
        let want = b(
            "DGv6ra1nlYgDCS1FRnbzlwAAEABBBP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A_yl95bQpu6cVPTpK4Mqgkf1CXztLVBSt2Ks3oZwbuwXPXLWyouBWLVWGNWQexSgSxsj_Qulcy4a-fN",
        );
        assert_eq!(B64.encode(&got), B64.encode(&want));
        // A body of the registry's size fits one record of RS.
        let big = encrypt(&[0; cbb_core::push::MAX_BODY], &ua_public, &auth, &as_secret, &salt).unwrap();
        assert_eq!(big.len(), 86 + cbb_core::push::MAX_BODY + 1 + 16);
        assert!(cbb_core::push::MAX_BODY + 1 + 16 <= RS as usize);
    }

    #[test]
    fn only_a_global_address_is_dialed_and_no_redirect_is_followed() {
        use cbb_core::blind::card::public_ip;
        let a = |s: &str| -> SocketAddr { s.parse().unwrap() };
        for bad in [
            "127.0.0.1:443",
            "10.1.2.3:443",
            "192.168.0.1:443",
            "100.64.0.1:443",
            "169.254.1.1:443",
            "[::1]:443",
            "[fd00::1]:443",
            "[fe80::1]:443",
            "[::ffff:10.0.0.1]:443",
            "[::127.0.0.1]:443",
            "[::808:808]:443",
            "[64:ff9b:1::a01:203]:443",
            "[2001:0:4136:e378:8000:63bf:f5fe:fdfc]:443",
            "192.0.0.8:443",
            "198.18.0.1:443",
        ] {
            assert_eq!(pick([a(bad)], &public_ip), None, "{bad}");
        }
        assert_eq!(pick([a("10.0.0.1:443"), a("93.184.216.34:443")], &public_ip), Some(a("93.184.216.34:443")));
        assert_eq!(outcome(b"HTTP/1.1 201 Created\r\n\r\n"), Outcome::Sent);
        assert_eq!(outcome(b"HTTP/1.1 410 Gone\r\n\r\n"), Outcome::Gone);
        assert_eq!(outcome(b"HTTP/1.1 301 Moved\r\nLocation: https://10.0.0.1/\r\n\r\n"), Outcome::NoPath);
        assert_eq!(outcome(b"HTTP/1.1 429 Slow\r\nRetry-After: 120\r\n\r\n"), Outcome::Later(Duration::from_secs(120)));
        assert_eq!(outcome(b"HTTP/1.1 503 Busy\r\n\r\n"), Outcome::Later(Duration::from_secs(30)));
        assert_eq!(outcome(b"garbage"), Outcome::NoPath);
        // The status is three digits and nothing more.
        assert_eq!(outcome(b"HTTP/1.1 2000 odd\r\n\r\n"), Outcome::NoPath);
        assert_eq!(outcome(b"HTTP/1.1 20x\r\n\r\n"), Outcome::NoPath);
        assert_eq!(outcome(b"HTTP/1.1 204\r\n\r\n"), Outcome::Sent);
        assert_eq!(outcome(b"HTTP/2 200\r\n\r\n"), Outcome::NoPath);
        assert_eq!(
            split("https://up.example.org:443/push/abc?x=1"),
            Some(("up.example.org".into(), "/push/abc?x=1".into()))
        );
        assert_eq!(split("https://up.example.org"), Some(("up.example.org".into(), "/".into())));
    }

    fn token(url: &str) -> Vec<u8> {
        let ua = p256::SecretKey::from_slice(&[7; 32]).unwrap().public_key().to_sec1_point(false);
        let p256dh: [u8; 65] = ua.as_bytes().try_into().unwrap();
        cbb_core::push::UnifiedPush { url, p256dh: &p256dh, auth: &[1; 16] }.write()
    }

    #[test]
    fn a_send_posts_once_to_the_resolved_address_within_the_hosts_budget() {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut s, _) = l.accept().unwrap();
            s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            let mut got = vec![0u8; 8192];
            let mut n = 0;
            while let Ok(k) = s.read(&mut got[n..]) {
                if k == 0 {
                    break;
                }
                n += k;
                if n >= 3105 {
                    break;
                }
            }
            s.write_all(b"HTTP/1.1 201 Created\r\nContent-Length: 0\r\n\r\n").unwrap();
            got.truncate(n);
            got
        });
        let resolved = Arc::new(Mutex::new(0));
        let r = resolved.clone();
        let up = UnifiedPush::plain(
            |ip| ip.is_loopback(),
            move |_| {
                *r.lock().unwrap() += 1;
                vec![addr]
            },
        );
        let t = token("https://up.example.org/push/abc");
        let body = vec![3u8; cbb_core::push::MAX_BODY];
        let far = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() + 600;
        let d = |env, token: &'static [u8], tag: u8| Delivery {
            env,
            token,
            body: None,
            challenge: Some(super::super::Challenge { value: [5; 16], key: [6; 8] }),
            expires_s: far,
            tag: [tag; 32],
        };
        let t: &'static [u8] = Box::leak(t.into_boxed_slice());
        let body: &'static [u8] = Box::leak(body.into_boxed_slice());
        let with = |env, token, tag| Delivery { body: Some(body), ..d(env, token, tag) };
        assert_eq!(up.send(&with(cbb_core::push::ENV_UNIFIEDPUSH, t, 1)), Outcome::Sent);
        let got = server.join().unwrap();
        let text = String::from_utf8_lossy(&got);
        assert!(text.starts_with("POST /push/abc HTTP/1.1\r\nHost: up.example.org\r\n"), "{text}");
        // The body and the challenge, as parts: 86 + 3 + 2972 + 3 + 24 + 1 + 16.
        assert!(text.contains("Content-Encoding: aes128gcm") && text.contains("Content-Length: 3105"), "{text}");
        assert_eq!(*resolved.lock().unwrap(), 1, "resolved once");
        // Not a global address: nothing is dialed.
        let up2 = UnifiedPush::plain(|_| false, move |_| vec![addr]);
        assert_eq!(up2.send(&with(cbb_core::push::ENV_UNIFIEDPUSH, t, 1)), Outcome::NoPath);
        // Another env, a broken token: no path.
        assert_eq!(up.send(&with(cbb_core::push::ENV_APNS, t, 1)), Outcome::NoPath);
        assert_eq!(up.send(&with(cbb_core::push::ENV_UNIFIEDPUSH, b"junk", 1)), Outcome::NoPath);
        // The group's burst of 30 at that host is spent (one went above),
        // in any case of its name; the rest of its sends wait. Another
        // group's are its own.
        for _ in 0..29 {
            assert!(up.budget(&[1; 32], "UP.example.org").is_none());
        }
        assert!(matches!(up.send(&with(cbb_core::push::ENV_UNIFIEDPUSH, t, 1)), Outcome::Later(_)));
        assert!(up.budget(&[2; 32], "up.example.org").is_none());
    }

    #[test]
    fn the_message_is_parts_of_a_kind_and_a_length() {
        let c = super::super::Challenge { value: [5; 16], key: [6; 8] };
        let m = message(Some(&[9; 3]), Some(&c));
        assert_eq!(&m[..6], &[PART_BODY, 0, 3, 9, 9, 9]);
        assert_eq!(&m[6..9], &[PART_CHALLENGE, 0, 24]);
        assert_eq!(&m[9..], &c.bytes());
        // A part that is not there is padding of its size: one size for all.
        let body = [9u8; cbb_core::push::MAX_BODY];
        let full = message(Some(&body), Some(&c));
        let alone = message(None, Some(&c));
        let bare = message(Some(&body), None);
        assert_eq!((alone.len(), bare.len()), (full.len(), full.len()));
        assert_eq!(alone[0], PART_PADDING);
        assert_eq!(&alone[alone.len() - 27..alone.len() - 24], &[PART_CHALLENGE, 0, 24]);
        assert_eq!(bare[bare.len() - 27], PART_PADDING);
    }

    #[test]
    fn a_send_ends_at_its_deadline_however_slowly_the_endpoint_answers() {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        std::thread::spawn(move || {
            let (mut s, _) = l.accept().unwrap();
            let mut got = vec![0u8; 8192];
            let _ = s.read(&mut got);
            // One byte every second, never the end of the head.
            for _ in 0..60 {
                if s.write_all(b"H").is_err() {
                    break;
                }
                std::thread::sleep(Duration::from_secs(1));
            }
        });
        let up = UnifiedPush::plain(|ip| ip.is_loopback(), move |_| vec![addr]);
        let t = token("https://up.example.org/push/abc");
        let body = vec![3u8; cbb_core::push::MAX_BODY];
        let d = Delivery {
            env: cbb_core::push::ENV_UNIFIEDPUSH,
            token: &t,
            body: Some(&body),
            challenge: None,
            expires_s: u64::MAX / 2,
            tag: [1; 32],
        };
        let started = Instant::now();
        let _ = up.send(&d);
        assert!(started.elapsed() < DEADLINE + Duration::from_secs(2), "{:?}", started.elapsed());
    }

    #[test]
    fn one_group_never_spends_an_address_for_the_others() {
        let up = UnifiedPush::plain(|_| true, |_| vec![]);
        let ip: IpAddr = "93.184.216.34".parse().unwrap();
        // One group's share of the address: its burst, then it waits.
        for _ in 0..PER_TAG_ADDRESS.1 as usize {
            assert!(up.address(&[1; 32], "up.example.org", ip).is_none());
        }
        assert!(up.address(&[1; 32], "up.example.org", ip).is_some());
        // Enough groups to spend the address's budget for every group...
        let groups = (PER_ADDRESS.1 / PER_TAG_ADDRESS.1) as u8;
        for g in 2..2 + groups {
            for _ in 0..PER_TAG_ADDRESS.1 as usize {
                let _ = up.address(&[g; 32], "up.example.org", ip);
            }
        }
        // ...and a group that has not sent there still goes, while one that
        // sent most waits.
        assert!(up.address(&[200; 32], "up.example.org", ip).is_none());
        let mut heavy = [7u8; 32];
        heavy[0] = 201;
        for _ in 0..(PER_TAG_ADDRESS.1 / 2.0) as usize + 1 {
            let _ = up.address(&heavy, "up.example.org", ip);
        }
        assert!(up.address(&heavy, "up.example.org", ip).is_some());
    }

    #[test]
    fn one_names_429_closes_neither_the_address_nor_another_groups_host() {
        let up = UnifiedPush::plain(|_| true, |_| vec![]);
        let ip: IpAddr = "93.184.216.34".parse().unwrap();
        // Another group's own name there answered 429 for a day.
        up.told_to_wait(&[9; 32], "mine.example", ip, Duration::from_secs(86_400));
        assert!(up.budget(&[9; 32], "MINE.example").is_some_and(|w| w > Duration::from_secs(86_000)));
        // The phone's group, at its distributor's name at that address: goes.
        assert!(up.budget(&[1; 32], "up.example.org").is_none());
        assert!(up.address(&[1; 32], "up.example.org", ip).is_none());
        // Even at that same name, another group goes.
        assert!(up.budget(&[2; 32], "mine.example").is_none());
        // Three groups of one maker, each told 429 by a name of its own at
        // that address: the phone's distributor's name there goes on.
        up.told_to_wait(&[10; 32], "a.example", ip, Duration::from_secs(86_400));
        up.told_to_wait(&[11; 32], "b.example", ip, Duration::from_secs(86_400));
        assert!(up.address(&[1; 32], "up.example.org", ip).is_none());
        assert!(up.address(&[1; 32], "a.example", ip).is_none(), "two groups at a name close nothing");
        // Three groups told by the same name within ten minutes close that
        // name at that address for everyone, for five minutes at most.
        up.told_to_wait(&[13; 32], "a.example", ip, Duration::from_secs(86_400));
        up.told_to_wait(&[14; 32], "a.example", ip, Duration::from_secs(86_400));
        let w = up.address(&[1; 32], "a.example", ip).expect("closed");
        assert!(w <= ADDRESS_WAIT_MAX && w > ADDRESS_WAIT_MAX - Duration::from_secs(5), "{w:?}");
        assert!(up.address(&[1; 32], "up.example.org", ip).is_none(), "another name is not closed");
        // One group told three times is one group.
        let other: IpAddr = "93.184.216.35".parse().unwrap();
        for _ in 0..3 {
            up.told_to_wait(&[12; 32], "c.example", other, Duration::from_secs(86_400));
        }
        assert!(up.address(&[1; 32], "c.example", other).is_none());
    }

    #[test]
    fn full_tables_make_room_from_the_group_with_most_entries() {
        let up = UnifiedPush::plain(|_| true, |_| vec![]);
        // One group sends to as many names as the table holds, and to as
        // many addresses.
        for i in 0..TABLE_MAX as u32 {
            assert!(up.budget(&[1; 32], &format!("n{i}.example")).is_none());
            let ip = IpAddr::from(std::net::Ipv4Addr::from(0x5d00_0000 + i));
            assert!(up.address(&[1; 32], "up.example.org", ip).is_none());
        }
        // A group that has not sent in this hour goes, to a name and an
        // address not among them.
        assert!(up.budget(&[2; 32], "up.example.org").is_none());
        assert!(up.address(&[2; 32], "up.example.org", "203.0.113.200".parse().unwrap()).is_none());
        let b = up.lock();
        assert_eq!((b.hosts.len(), b.shares.len(), b.addresses.len()), (TABLE_MAX, TABLE_MAX, TABLE_MAX));
    }
}
