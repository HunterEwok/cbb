// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The way to Apple's push service (APNs) for the iPhone and the iPad:
//! HTTP/2 to `api.push.apple.com` (or the sandbox's for development builds),
//! a token signed with the team's key (ES256, renewed every 40 minutes, as
//! Apple asks between 20 and 60), and the request Apple takes: an alert
//! with `mutable-content` so that the app's notification extension opens
//! the body, the body itself in base64 under `c`, and the fixed
//! localization key of the text shown when the extension cannot run.
//! No `apns-collapse-id`, which would let Apple join two notifications.
//! A challenge of the service (24 bytes: the value and the hint of the
//! send key it is for) rides in base64 under `k`; with no body it goes
//! alone as a background push (`content-available`, priority 5), which
//! wakes the app without showing anything.

use std::net::{TcpStream, ToSocketAddrs};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use p256::ecdsa::{Signature, SigningKey, signature::Signer};
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, StreamOwned};

use super::h2::{Answer, Conn};
use super::{Challenge, Delivery, Outcome, Platform};
use crate::error::{Context, Error, Result};

/// Apple's hosts.
pub const PRODUCTION: &str = "api.push.apple.com";
pub const SANDBOX: &str = "api.sandbox.push.apple.com";
/// The app's bundle ID, the topic of its notifications.
pub const TOPIC: &str = "tools.cbb";
/// The localization key of the text shown when the extension cannot run:
/// the English text, which is the key of the app's String Catalog
/// (apps/l10n, place `ios`), so every language has it.
pub const LOC_KEY: &str = "New in your group. Open the app.";
/// How long a provider token is used.
const TOKEN_LIFE: Duration = Duration::from_secs(40 * 60);
/// Under the member's own wait for an answer (`member/src/push.rs`).
const TIMEOUT: Duration = Duration::from_secs(10);

/// The team's key and names.
pub struct Key {
    pub team: String,
    pub key_id: String,
    pub key: SigningKey,
}

impl Key {
    /// Reads Apple's `.p8` file (a PKCS #8 P-256 key in PEM).
    pub fn from_p8(pem: &str, team: &str, key_id: &str) -> Result<Key> {
        let b64: String = pem.lines().filter(|l| !l.starts_with("-----")).map(str::trim).collect::<Vec<_>>().concat();
        let der = STANDARD.decode(b64).map_err(|_| Error::msg("the APNs key is not a .p8 file"))?;
        let key = cbb_core::identity::signing_key(&der).map_err(|_| Error::msg("the APNs key is not a P-256 key"))?;
        let ok = |s: &str| s.len() == 10 && s.bytes().all(|b| b.is_ascii_alphanumeric());
        if !ok(team) || !ok(key_id) {
            return Err(Error::msg("the team ID and the key ID are 10 letters and digits each"));
        }
        Ok(Key { team: team.into(), key_id: key_id.into(), key })
    }

    /// A provider token issued at `iat` (seconds).
    pub fn token(&self, iat: u64) -> String {
        let head = URL_SAFE_NO_PAD.encode(format!(r#"{{"alg":"ES256","kid":"{}"}}"#, self.key_id));
        let claims = URL_SAFE_NO_PAD.encode(format!(r#"{{"iss":"{}","iat":{iat}}}"#, self.team));
        let signing = format!("{head}.{claims}");
        let sig: Signature = self.key.sign(signing.as_bytes());
        format!("{signing}.{}", URL_SAFE_NO_PAD.encode(sig.to_bytes()))
    }
}

/// The request's payload for a body, with the service's challenge when
/// there is one.
pub fn payload(body: &[u8], challenge: Option<&Challenge>) -> String {
    let k = challenge.map(|c| format!(r#","k":"{}""#, STANDARD.encode(c.bytes()))).unwrap_or_default();
    format!(r#"{{"aps":{{"alert":{{"loc-key":"{LOC_KEY}"}},"mutable-content":1}},"c":"{}"{k}}}"#, STANDARD.encode(body))
}

/// The payload of a challenge alone: a background push.
pub fn background(c: &Challenge) -> String {
    format!(r#"{{"aps":{{"content-available":1}},"k":"{}"}}"#, STANDARD.encode(c.bytes()))
}

/// What an answer from Apple means.
pub fn outcome(a: &Answer) -> Outcome {
    let reason = serde_json::from_slice::<serde_json::Value>(&a.body)
        .ok()
        .and_then(|v| v.get("reason").and_then(|r| r.as_str()).map(String::from))
        .unwrap_or_default();
    match (a.status, reason.as_str()) {
        (Some(200), _) => Outcome::Sent,
        (_, "Unregistered" | "BadDeviceToken" | "DeviceTokenNotForTopic" | "ExpiredToken") | (Some(410), _) => {
            Outcome::Gone
        }
        (_, "TooManyRequests") | (Some(429), _) => Outcome::Later(Duration::from_secs(60)),
        (_, "ExpiredProviderToken" | "InvalidProviderToken") => Outcome::Later(Duration::from_secs(5)),
        _ => Outcome::Later(Duration::from_secs(30)),
    }
}

type Tls = StreamOwned<ClientConnection, TcpStream>;

/// One host's connection and token.
struct Link {
    host: &'static str,
    conn: Option<Conn<Tls>>,
}

/// APNs in one environment (`env` 1 production, 2 sandbox), with that
/// environment's key: the team's keys are made for one environment each.
pub struct Apns {
    env: u64,
    key: Key,
    tls: Arc<ClientConfig>,
    token: Mutex<Option<(String, Instant)>>,
    link: Mutex<Link>,
}

impl Apns {
    pub fn new(env: u64, key: Key, roots: rustls::RootCertStore) -> Result<Apns> {
        let host = match env {
            cbb_core::push::ENV_APNS => PRODUCTION,
            cbb_core::push::ENV_APNS_SANDBOX => SANDBOX,
            _ => return Err(Error::msg("APNs has two environments only")),
        };
        let mut cfg = ClientConfig::builder_with_provider(Arc::new(cbb_core::tls::web::provider()))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .context("cannot set up the TLS toward APNs")?
            .with_root_certificates(roots)
            .with_no_client_auth();
        cfg.alpn_protocols = vec![b"h2".to_vec()];
        Ok(Apns { env, key, tls: Arc::new(cfg), token: Mutex::new(None), link: Mutex::new(Link { host, conn: None }) })
    }

    fn provider_token(&self) -> String {
        let mut t = self.token.lock().unwrap_or_else(|e| e.into_inner());
        if let Some((tok, at)) = t.as_ref()
            && at.elapsed() < TOKEN_LIFE
        {
            return tok.clone();
        }
        let iat = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs());
        let tok = self.key.token(iat);
        *t = Some((tok.clone(), Instant::now()));
        tok
    }

    fn connect(&self, host: &'static str) -> Result<Conn<Tls>> {
        let addr = (host, 443)
            .to_socket_addrs()
            .context(format!("cannot look up {host}"))?
            .next()
            .ok_or_else(|| Error::msg(format!("{host} has no address")))?;
        let tcp = TcpStream::connect_timeout(&addr, TIMEOUT).context(format!("cannot reach {host}"))?;
        let _ = tcp.set_nodelay(true);
        tcp.set_read_timeout(Some(TIMEOUT)).context("cannot set a timeout")?;
        tcp.set_write_timeout(Some(TIMEOUT)).context("cannot set a timeout")?;
        let name = ServerName::try_from(host).map_err(|_| Error::msg("not a host name"))?;
        let conn = ClientConnection::new(self.tls.clone(), name).context(format!("cannot start TLS to {host}"))?;
        let mut tls = StreamOwned::new(conn, tcp);
        while tls.conn.is_handshaking() {
            tls.conn.complete_io(&mut tls.sock).context(format!("TLS to {host} failed"))?;
        }
        if tls.conn.alpn_protocol() != Some(b"h2") {
            return Err(Error::msg(format!("{host} does not speak HTTP/2")));
        }
        Conn::start(tls)
    }
}

impl Platform for Apns {
    fn send(&self, d: &Delivery<'_>) -> Outcome {
        if d.env != self.env {
            return Outcome::NoPath;
        }
        // A device token is hex in the path.
        let hex: String = d.token.iter().map(|b| format!("{b:02x}")).collect();
        let path = format!("/3/device/{hex}");
        let auth = format!("bearer {}", self.provider_token());
        let exp = d.expires_s.to_string();
        let (kind, priority, body) = match (d.body, d.challenge.as_ref()) {
            (Some(b), c) => ("alert", "10", payload(b, c)),
            (None, Some(c)) => ("background", "5", background(c)),
            (None, None) => return Outcome::NoPath,
        };
        let headers = [
            ("authorization", auth.as_str()),
            ("apns-push-type", kind),
            ("apns-priority", priority),
            ("apns-topic", TOPIC),
            ("apns-expiration", exp.as_str()),
        ];
        let mut link = self.link.lock().unwrap_or_else(|e| e.into_inner());
        // One retry on a fresh connection when the kept one has closed.
        for _ in 0..2 {
            if link.conn.as_ref().is_none_or(|c| c.gone()) {
                match self.connect(link.host) {
                    Ok(c) => link.conn = Some(c),
                    Err(_) => return Outcome::Later(Duration::from_secs(30)),
                }
            }
            let host = link.host;
            let Some(conn) = link.conn.as_mut() else { continue };
            match conn.post(host, &path, &headers, body.as_bytes()) {
                Ok(a) => return outcome(&a),
                Err(_) => link.conn = None,
            }
        }
        Outcome::Later(Duration::from_secs(30))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::{VerifyingKey, signature::Verifier};

    fn key() -> Key {
        let der = cbb_core::identity::new_key().unwrap();
        let pem = format!("-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n", STANDARD.encode(&der));
        Key::from_p8(&pem, "ABCDE12345", "KEY0000001").unwrap()
    }

    #[test]
    fn the_provider_token_is_es256_over_the_teams_names() {
        let k = key();
        let t = k.token(1_790_000_000);
        let parts: Vec<&str> = t.split('.').collect();
        assert_eq!(parts.len(), 3);
        assert_eq!(URL_SAFE_NO_PAD.decode(parts[0]).unwrap(), br#"{"alg":"ES256","kid":"KEY0000001"}"#);
        assert_eq!(URL_SAFE_NO_PAD.decode(parts[1]).unwrap(), br#"{"iss":"ABCDE12345","iat":1790000000}"#);
        let sig = Signature::from_slice(&URL_SAFE_NO_PAD.decode(parts[2]).unwrap()).unwrap();
        VerifyingKey::from(&k.key).verify(format!("{}.{}", parts[0], parts[1]).as_bytes(), &sig).unwrap();
        assert!(Key::from_p8("x", "ABCDE12345", "KEY0000001").is_err());
    }

    #[test]
    fn the_payload_fits_apples_limit_and_shows_nothing_of_the_body() {
        let c = Challenge { value: [1; 16], key: [2; 8] };
        let p = payload(&[0u8; cbb_core::push::MAX_BODY], Some(&c));
        assert!(p.len() <= 4096, "{}", p.len());
        assert!(p.contains(r#""mutable-content":1"#) && p.contains(LOC_KEY));
        let v: serde_json::Value = serde_json::from_str(&p).unwrap();
        assert_eq!(STANDARD.decode(v["k"].as_str().unwrap()).unwrap(), c.bytes());
        assert!(serde_json::from_str::<serde_json::Value>(&payload(&[0; 4], None)).unwrap().get("k").is_none());
        // A challenge alone wakes the app and shows nothing.
        let v: serde_json::Value = serde_json::from_str(&background(&c)).unwrap();
        assert_eq!(v["aps"]["content-available"], 1);
        assert!(v["aps"].get("alert").is_none());
    }

    #[test]
    fn apples_answers_mean_what_the_sender_does() {
        let a = |status, body: &str| Answer { status, body: body.as_bytes().to_vec() };
        assert_eq!(outcome(&a(Some(200), "")), Outcome::Sent);
        assert_eq!(outcome(&a(Some(410), r#"{"reason":"Unregistered"}"#)), Outcome::Gone);
        assert_eq!(outcome(&a(None, r#"{"reason":"BadDeviceToken"}"#)), Outcome::Gone);
        assert_eq!(outcome(&a(None, r#"{"reason":"TooManyRequests"}"#)), Outcome::Later(Duration::from_secs(60)));
        assert_eq!(outcome(&a(Some(500), "")), Outcome::Later(Duration::from_secs(30)));
    }
}
