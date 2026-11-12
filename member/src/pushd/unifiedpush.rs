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
//! - sends at most one body of the registry's size, reads at most 4 KiB of
//!   the answer, within 10 s;
//! - budgets per host, beside per token and per tag.

use std::collections::HashMap;
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

use super::{Outcome, Platform};

/// The record size the header names: one record holds the whole body.
const RS: u32 = 4096;
const TIMEOUT: Duration = Duration::from_secs(10);
/// The most of an answer read.
const MAX_ANSWER: usize = 4096;
/// Sends an hour to one host and the burst; hosts held at most.
const PER_HOST: (f64, f64) = (300.0, 30.0);
const HOSTS_MAX: usize = 65_536;

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
    let status = lines
        .next()
        .and_then(|l| l.strip_prefix("HTTP/1.1 ").or_else(|| l.strip_prefix("HTTP/1.0 ")))
        .and_then(|l| l.get(..3))
        .and_then(|s| s.parse::<u16>().ok());
    let retry = lines
        .take_while(|l| !l.is_empty())
        .find_map(|l| {
            let (k, v) = l.split_once(':')?;
            k.trim().eq_ignore_ascii_case("retry-after").then(|| v.trim().parse::<u64>().ok()).flatten()
        })
        .map(|s| Duration::from_secs(s.clamp(1, 86_400)));
    match status {
        Some(200..=202) => Outcome::Sent,
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

/// How the service reaches an endpoint: TLS with the system's roots, or for
/// the tests plain TCP to a loopback server.
enum Dial {
    Tls(Arc<ClientConfig>),
    #[cfg(test)]
    Plain,
}

/// How a host name becomes its addresses.
type Resolve = Box<dyn Fn(&str) -> Vec<SocketAddr> + Send + Sync>;

/// The UnifiedPush path.
pub struct UnifiedPush {
    dial: Dial,
    allowed: Box<dyn Fn(IpAddr) -> bool + Send + Sync>,
    resolve: Resolve,
    hosts: Mutex<HashMap<String, Bucket>>,
}

fn system_resolve(host: &str) -> Vec<SocketAddr> {
    (host, 443).to_socket_addrs().map(|a| a.collect()).unwrap_or_default()
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
            resolve: Box::new(system_resolve),
            hosts: Mutex::new(HashMap::new()),
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
            resolve: Box::new(resolve),
            hosts: Mutex::new(HashMap::new()),
        }
    }

    /// Takes one send from host's budget; the wait when it is spent.
    fn budget(&self, host: &str) -> Option<Duration> {
        let now = Instant::now();
        let mut hosts = self.hosts.lock().unwrap_or_else(|e| e.into_inner());
        if !hosts.contains_key(host) && hosts.len() >= HOSTS_MAX {
            hosts.retain(|_, b| now.saturating_duration_since(b.at) < Duration::from_secs(3600));
            if hosts.len() >= HOSTS_MAX {
                return Some(Duration::from_secs(60));
            }
        }
        let b = hosts.entry(host.to_ascii_lowercase()).or_insert(Bucket { left: PER_HOST.1, at: now });
        let rate = PER_HOST.0 / 3600.0;
        b.left = (b.left + now.saturating_duration_since(b.at).as_secs_f64() * rate).min(PER_HOST.1);
        b.at = now;
        if b.left >= 1.0 {
            b.left -= 1.0;
            None
        } else {
            Some(Duration::from_secs_f64(((1.0 - b.left) / rate).max(1.0)))
        }
    }

    fn post(&self, addr: SocketAddr, host: &str, head: &str, body: &[u8]) -> Option<Vec<u8>> {
        let tcp = TcpStream::connect_timeout(&addr, TIMEOUT).ok()?;
        tcp.set_read_timeout(Some(TIMEOUT)).ok()?;
        tcp.set_write_timeout(Some(TIMEOUT)).ok()?;
        match &self.dial {
            Dial::Tls(cfg) => {
                let name = ServerName::try_from(host.to_string()).ok()?;
                let conn = ClientConnection::new(cfg.clone(), name).ok()?;
                exchange(StreamOwned::new(conn, tcp), head, body)
            }
            #[cfg(test)]
            Dial::Plain => exchange(tcp, head, body),
        }
    }
}

fn exchange(mut s: impl Read + Write, head: &str, body: &[u8]) -> Option<Vec<u8>> {
    s.write_all(head.as_bytes()).ok()?;
    s.write_all(body).ok()?;
    s.flush().ok()?;
    let mut answer = Vec::new();
    let _ = s.take(MAX_ANSWER as u64).read_to_end(&mut answer);
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
    fn send(&self, env: u64, token: &[u8], body: &[u8], expires_s: u64) -> Outcome {
        if env != cbb_core::push::ENV_UNIFIEDPUSH {
            return Outcome::NoPath;
        }
        let Ok(up) = cbb_core::push::UnifiedPush::read(token) else { return Outcome::NoPath };
        let Some((host, path)) = split(up.url) else { return Outcome::NoPath };
        if let Some(wait) = self.budget(&host) {
            return Outcome::Later(wait);
        }
        // Resolved once: the address checked is the one connected to.
        let Some(addr) = pick((self.resolve)(&host), &*self.allowed) else { return Outcome::NoPath };
        let secret = p256::SecretKey::from_bytes(&cbb_core::certs::random_bytes::<32>().into());
        let Ok(secret) = secret else { return Outcome::Later(Duration::from_secs(1)) };
        let Some(sealed) = encrypt(body, up.p256dh, up.auth, &secret, &cbb_core::certs::random_bytes()) else {
            return Outcome::NoPath;
        };
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs());
        let head = request(&host, &path, sealed.len(), expires_s.saturating_sub(now).max(1));
        match self.post(addr, &host, &head, &sealed) {
            Some(answer) => outcome(&answer),
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
                if n >= 3075 {
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
        assert_eq!(up.send(cbb_core::push::ENV_UNIFIEDPUSH, &t, &body, far), Outcome::Sent);
        let got = server.join().unwrap();
        let text = String::from_utf8_lossy(&got);
        assert!(text.starts_with("POST /push/abc HTTP/1.1\r\nHost: up.example.org\r\n"), "{text}");
        assert!(text.contains("Content-Encoding: aes128gcm") && text.contains("Content-Length: 3075"));
        assert_eq!(*resolved.lock().unwrap(), 1, "resolved once");
        // Not a global address: nothing is dialed.
        let up2 = UnifiedPush::plain(|_| false, move |_| vec![addr]);
        assert_eq!(up2.send(cbb_core::push::ENV_UNIFIEDPUSH, &t, &body, far), Outcome::NoPath);
        // Another env, a broken token: no path.
        assert_eq!(up.send(cbb_core::push::ENV_APNS, &t, &body, far), Outcome::NoPath);
        assert_eq!(up.send(cbb_core::push::ENV_UNIFIEDPUSH, b"junk", &body, far), Outcome::NoPath);
        // The host's burst of 30 is spent (one went above); the rest wait.
        for _ in 0..29 {
            assert!(up.budget("up.example.org").is_none());
        }
        assert!(matches!(up.send(cbb_core::push::ENV_UNIFIEDPUSH, &t, &body, far), Outcome::Later(_)));
    }
}
