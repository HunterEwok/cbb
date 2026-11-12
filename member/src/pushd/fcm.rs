// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The way to Firebase Cloud Messaging (FCM, env 3) for the Android app's
//! full build: FCM's HTTP v1 API over HTTP/2 to `fcm.googleapis.com`, with
//! an OAuth access token the project's service account gets from Google
//! (an RS256 assertion signed with the account's key, renewed before its
//! hour is out). Each send is a data message, which the app's own code
//! opens (never a notification message, which Google would show): the body
//! in base64 under `c`, the service's challenge (24 bytes) under `k`. No
//! collapse key, which would let Google join two notifications.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use rsa::pkcs8::DecodePrivateKey;
use rsa::signature::{SignatureEncoding, Signer};
use rustls::ClientConfig;

use super::h2::{Answer, Conn, Tls, dial};
use super::{Delivery, Outcome, Platform};
use crate::error::{Context, Error, Result};

/// Google's hosts.
pub const FCM_HOST: &str = "fcm.googleapis.com";
pub const TOKEN_HOST: &str = "oauth2.googleapis.com";
const TOKEN_AUD: &str = "https://oauth2.googleapis.com/token";
const SCOPE: &str = "https://www.googleapis.com/auth/firebase.messaging";
/// An access token is used until this long before it expires.
const MARGIN: Duration = Duration::from_secs(5 * 60);
/// Under the member's own wait for an answer.
const TIMEOUT: Duration = Duration::from_secs(10);
/// FCM's limit on a data message's keys and values.
pub const MAX_DATA: usize = 4096;

/// The project's service account, from the JSON file Google gives.
pub struct Account {
    pub project: String,
    pub email: String,
    key: rsa::pkcs1v15::SigningKey<sha2::Sha256>,
}

impl Account {
    /// Reads the service account's JSON file (`project_id`, `client_email`,
    /// `private_key` in PKCS #8 PEM).
    pub fn from_json(json: &str) -> Result<Account> {
        let v: serde_json::Value = serde_json::from_str(json).map_err(|_| Error::msg("the FCM account is not JSON"))?;
        let field = |n: &str| {
            v.get(n)
                .and_then(|x| x.as_str())
                .map(str::to_string)
                .ok_or_else(|| Error::msg(format!("the FCM account has no {n}")))
        };
        let project = field("project_id")?;
        let email = field("client_email")?;
        let pem = field("private_key")?;
        let ok = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphanumeric() || b"-_.@".contains(&b));
        if !ok(&project) || !ok(&email) {
            return Err(Error::msg("the FCM account's project or email has characters it may not"));
        }
        let key =
            rsa::PrivateKey::from_pkcs8_pem(&pem).map_err(|_| Error::msg("the FCM account's key is not an RSA key"))?;
        Ok(Account { project, email, key: rsa::pkcs1v15::SigningKey::new(key) })
    }

    /// The OAuth assertion issued at `iat` (seconds), good for an hour.
    pub fn assertion(&self, iat: u64) -> String {
        let head = URL_SAFE_NO_PAD.encode(br#"{"alg":"RS256","typ":"JWT"}"#);
        let claims =
            serde_json::json!({ "iss": self.email, "scope": SCOPE, "aud": TOKEN_AUD, "iat": iat, "exp": iat + 3600 });
        let signing = format!("{head}.{}", URL_SAFE_NO_PAD.encode(claims.to_string()));
        let sig = self.key.sign(signing.as_bytes());
        format!("{signing}.{}", URL_SAFE_NO_PAD.encode(sig.to_vec()))
    }
}

/// The request's JSON for one delivery, or None when there is nothing to
/// send or the token is not one FCM gives.
pub fn message(token: &[u8], body: Option<&[u8]>, challenge: Option<&[u8; 24]>, ttl_s: u64) -> Option<String> {
    let token = std::str::from_utf8(token).ok()?;
    if token.is_empty() || !token.bytes().all(|b| b.is_ascii_alphanumeric() || b"-_:".contains(&b)) {
        return None;
    }
    let mut data = serde_json::Map::new();
    if let Some(b) = body {
        data.insert("c".into(), STANDARD.encode(b).into());
    }
    if let Some(c) = challenge {
        data.insert("k".into(), STANDARD.encode(c).into());
    }
    if data.is_empty() {
        return None;
    }
    // A body wakes the app at once; a challenge alone can wait for the
    // phone's next window.
    let priority = if body.is_some() { "HIGH" } else { "NORMAL" };
    let m = serde_json::json!({ "message": {
        "token": token,
        "data": data,
        "android": { "priority": priority, "ttl": format!("{}s", ttl_s.clamp(1, 2_419_200)) },
    }});
    Some(m.to_string())
}

/// What an answer from FCM means.
pub fn outcome(a: &Answer) -> Outcome {
    let v = serde_json::from_slice::<serde_json::Value>(&a.body).unwrap_or_default();
    let code = v["error"]["details"]
        .as_array()
        .and_then(|d| d.iter().find_map(|x| x["errorCode"].as_str()))
        .or_else(|| v["error"]["status"].as_str())
        .unwrap_or_default();
    match (a.status, code) {
        (Some(200), _) => Outcome::Sent,
        (_, "UNREGISTERED" | "SENDER_ID_MISMATCH") | (Some(404), _) => Outcome::Gone,
        (_, "QUOTA_EXCEEDED") | (Some(429), _) => Outcome::Later(Duration::from_secs(60)),
        (Some(401), _) => Outcome::Later(Duration::from_secs(5)),
        _ => Outcome::Later(Duration::from_secs(30)),
    }
}

/// FCM for one Firebase project.
pub struct Fcm {
    account: Account,
    tls: Arc<ClientConfig>,
    access: Mutex<Option<(String, Instant)>>,
    fcm: Mutex<Option<Conn<Tls>>>,
}

impl Fcm {
    pub fn new(account: Account, roots: rustls::RootCertStore) -> Result<Fcm> {
        let mut cfg = ClientConfig::builder_with_provider(Arc::new(cbb_core::tls::web::provider()))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .context("cannot set up the TLS toward FCM")?
            .with_root_certificates(roots)
            .with_no_client_auth();
        cfg.alpn_protocols = vec![b"h2".to_vec()];
        Ok(Fcm { account, tls: Arc::new(cfg), access: Mutex::new(None), fcm: Mutex::new(None) })
    }

    /// The access token, asked for again before it runs out.
    fn access(&self, again: bool) -> Result<String> {
        let mut a = self.access.lock().unwrap_or_else(|e| e.into_inner());
        if !again
            && let Some((tok, until)) = a.as_ref()
            && Instant::now() < *until
        {
            return Ok(tok.clone());
        }
        let iat = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs());
        let form = format!(
            "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion={}",
            self.account.assertion(iat)
        );
        let mut conn = dial(&self.tls, TOKEN_HOST, TIMEOUT)?;
        let ans =
            conn.post(TOKEN_HOST, "/token", &[("content-type", "application/x-www-form-urlencoded")], form.as_bytes())?;
        let v: serde_json::Value = serde_json::from_slice(&ans.body).unwrap_or_default();
        let (Some(200), Some(tok)) = (ans.status, v["access_token"].as_str()) else {
            return Err(Error::msg(format!(
                "Google refused the FCM account's token ({}): {}",
                ans.status.unwrap_or(0),
                v["error"].as_str().unwrap_or("no reason given")
            )));
        };
        let life = Duration::from_secs(v["expires_in"].as_u64().unwrap_or(3600));
        *a = Some((tok.to_string(), Instant::now() + life.saturating_sub(MARGIN)));
        Ok(tok.to_string())
    }
}

impl Platform for Fcm {
    fn send(&self, d: &Delivery<'_>) -> Outcome {
        if d.env != cbb_core::push::ENV_FCM {
            return Outcome::NoPath;
        }
        let now = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs());
        let challenge = d.challenge.map(|c| c.bytes());
        let Some(body) = message(d.token, d.body, challenge.as_ref(), d.expires_s.saturating_sub(now)) else {
            // A token that is not FCM's never will be.
            return if d.body.is_some() || d.challenge.is_some() { Outcome::Gone } else { Outcome::NoPath };
        };
        let path = format!("/v1/projects/{}/messages:send", self.account.project);
        for attempt in 0..2 {
            let Ok(tok) = self.access(attempt > 0) else { return Outcome::Later(Duration::from_secs(30)) };
            let auth = format!("Bearer {tok}");
            let headers = [("authorization", auth.as_str()), ("content-type", "application/json")];
            let mut conn = self.fcm.lock().unwrap_or_else(|e| e.into_inner());
            if conn.as_ref().is_none_or(|c| c.gone()) {
                match dial(&self.tls, FCM_HOST, TIMEOUT) {
                    Ok(c) => *conn = Some(c),
                    Err(_) => return Outcome::Later(Duration::from_secs(30)),
                }
            }
            let Some(c) = conn.as_mut() else { continue };
            match c.post(FCM_HOST, &path, &headers, body.as_bytes()) {
                // An access token Google no longer takes: a new one, once.
                Ok(a) if a.status == Some(401) && attempt == 0 => continue,
                Ok(a) => return outcome(&a),
                Err(_) => *conn = None,
            }
        }
        Outcome::Later(Duration::from_secs(30))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsa::pkcs8::EncodePrivateKey;
    use rsa::signature::{Keypair, Verifier};

    fn account() -> Account {
        let key = rsa::PrivateKey::new(&mut rand_like(), 2048).unwrap();
        let pem = key.to_pkcs8_pem(rsa::pkcs8::LineEnding::LF).unwrap();
        let json = serde_json::json!({ "type": "service_account", "project_id": "cbb-test", "client_email": "push@cbb-test.iam.gserviceaccount.com", "private_key": pem.as_str() });
        Account::from_json(&json.to_string()).unwrap()
    }

    fn rand_like() -> impl rsa::rand_core::CryptoRng {
        rsa::rand_core::UnwrapErr(getrandom::SysRng)
    }

    #[test]
    fn the_assertion_is_rs256_over_the_accounts_claims() {
        let a = account();
        let t = a.assertion(1_790_000_000);
        let parts: Vec<&str> = t.split('.').collect();
        assert_eq!(parts.len(), 3);
        assert_eq!(URL_SAFE_NO_PAD.decode(parts[0]).unwrap(), br#"{"alg":"RS256","typ":"JWT"}"#);
        let claims: serde_json::Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1]).unwrap()).unwrap();
        assert_eq!(claims["iss"], "push@cbb-test.iam.gserviceaccount.com");
        assert_eq!(claims["scope"], SCOPE);
        assert_eq!(claims["aud"], TOKEN_AUD);
        assert_eq!(claims["exp"].as_u64(), Some(1_790_003_600));
        let sig = rsa::pkcs1v15::Signature::try_from(URL_SAFE_NO_PAD.decode(parts[2]).unwrap().as_slice()).unwrap();
        let vk = a.key.verifying_key();
        vk.verify(format!("{}.{}", parts[0], parts[1]).as_bytes(), &sig).unwrap();
        assert!(Account::from_json("{}").is_err());
        assert!(Account::from_json(r#"{"project_id":"p","client_email":"e@x","private_key":"no"}"#).is_err());
    }

    #[test]
    fn a_message_is_data_only_and_fits_fcms_limit() {
        let token = b"dGVzdA:APA91b_token-of-the-phone";
        let c = [3u8; 24];
        let m = message(token, Some(&[0u8; cbb_core::push::MAX_BODY]), Some(&c), 3600).unwrap();
        let v: serde_json::Value = serde_json::from_str(&m).unwrap();
        let data = v["message"]["data"].as_object().unwrap();
        let size: usize = data.iter().map(|(k, v)| k.len() + v.as_str().unwrap().len()).sum();
        assert!(size <= MAX_DATA, "{size}");
        assert_eq!(STANDARD.decode(data["k"].as_str().unwrap()).unwrap(), c);
        assert!(v["message"].get("notification").is_none(), "never a notification Google shows");
        assert!(v["message"]["android"].get("collapse_key").is_none());
        assert_eq!(v["message"]["android"]["priority"], "HIGH");
        assert_eq!(v["message"]["android"]["ttl"], "3600s");
        // A challenge alone, at normal priority.
        let v: serde_json::Value = serde_json::from_str(&message(token, None, Some(&c), 60).unwrap()).unwrap();
        assert_eq!(v["message"]["android"]["priority"], "NORMAL");
        assert!(v["message"]["data"].get("c").is_none());
        // Nothing to send, or a token FCM never gives.
        assert!(message(token, None, None, 60).is_none());
        assert!(message(b"a\"b", Some(&[1]), None, 60).is_none());
        assert!(message(&[0xff, 0xfe], Some(&[1]), None, 60).is_none());
    }

    #[test]
    fn fcms_answers_mean_what_the_sender_does() {
        let a = |status, body: &str| Answer { status, body: body.as_bytes().to_vec() };
        assert_eq!(outcome(&a(Some(200), r#"{"name":"projects/p/messages/1"}"#)), Outcome::Sent);
        let gone = r#"{"error":{"code":404,"status":"NOT_FOUND","details":[{"errorCode":"UNREGISTERED"}]}}"#;
        assert_eq!(outcome(&a(Some(404), gone)), Outcome::Gone);
        let other = r#"{"error":{"code":403,"details":[{"errorCode":"SENDER_ID_MISMATCH"}]}}"#;
        assert_eq!(outcome(&a(Some(403), other)), Outcome::Gone);
        let quota = r#"{"error":{"code":429,"details":[{"errorCode":"QUOTA_EXCEEDED"}]}}"#;
        assert_eq!(outcome(&a(Some(429), quota)), Outcome::Later(Duration::from_secs(60)));
        assert_eq!(outcome(&a(Some(503), "")), Outcome::Later(Duration::from_secs(30)));
        // A bad request of ours is not the phone's fault: its token stays.
        let bad = r#"{"error":{"code":400,"status":"INVALID_ARGUMENT"}}"#;
        assert_eq!(outcome(&a(Some(400), bad)), Outcome::Later(Duration::from_secs(30)));
    }
}
