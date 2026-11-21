// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! A forwarder's registrations of 0.6 (`cbb-forward/3`) in the same
//! process, as the tests of a hub's registration need them: TLS pinned by
//! its key, the challenge, the hub's registration, checked as the
//! forwarder checks it (the certificate of a server key alone, the proof
//! of the WireGuard key, the face's hubs' credential alone that lists that
//! server key, signed by the period key first seen for its tag), an answer the test chooses, then where it saw the
//! hub.

use std::collections::HashMap;
use std::io::Read;
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use cbb_core::blind::credential::{Credential, TYPE_HUBS};
use cbb_core::certs::{self, Cert};
use cbb_core::tls::rustls;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

use crate::forward::v3::{self, Register, Registered, Way};

/// The forwarder's answer to a registration it took.
pub enum Answer {
    Registered(Registered),
    Refused(String),
    /// A frame of the test's own, for answers the format refuses.
    Raw(Vec<u8>),
}

/// The answer to a registration the forwarder's checks took.
pub type AnswerFn = Arc<dyn Fn(&Register) -> Answer + Send + Sync>;

/// A registration the forwarder took: what the hub sent, and the
/// certificates it showed.
#[derive(Clone)]
pub struct Claim {
    pub register: Register,
    pub certs: Vec<Vec<u8>>,
}

/// The period key the forwarder first saw for each tag.
type PeriodKeys = Mutex<HashMap<[u8; 16], Vec<u8>>>;

/// What the forwarder's connections keep together.
#[derive(Clone)]
struct Shared {
    claims: Arc<Mutex<Vec<Claim>>>,
    hello_keys: Arc<Mutex<Vec<[u8; 32]>>>,
    keys: Arc<PeriodKeys>,
}

pub struct Forwarder {
    pub addr: SocketAddr,
    pub pin: certs::KeyHash,
    pub claims: Arc<Mutex<Vec<Claim>>>,
    /// The hello key of each registration, from its TLS.
    pub hello_keys: Arc<Mutex<Vec<[u8; 32]>>>,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

/// The mask key the test forwarder gives.
pub const MASK: [u8; 32] = [9; 32];

/// A plain answer: the registration 7, the mask, and the way over VLESS
/// when the hub asked for one.
pub fn welcome() -> AnswerFn {
    Arc::new(|r: &Register| {
        Answer::Registered(Registered {
            id: 7,
            mask: MASK,
            vless: r.vless.map(|user| Way {
                user,
                port: Some(8443),
                host: "site.test".into(),
                path: "/AbC-12_xyz0123456/a-group-of-its-own".into(),
            }),
        })
    })
}

impl Forwarder {
    /// Starts it; after the answer it says where it saw the hub when seen
    /// is set.
    pub fn start(answer: AnswerFn, seen: Option<&'static str>) -> Forwarder {
        let der = cbb_core::identity::new_key().unwrap();
        let key = cbb_core::identity::signing_key(&der).unwrap();
        let point = p256::ecdsa::VerifyingKey::from(&key).to_sec1_point(false);
        let cert = certs::server_cert_by(point.as_bytes(), &mut |tbs| {
            use p256::ecdsa::signature::Signer;
            let sig: p256::ecdsa::Signature = key.sign(tbs);
            Ok(sig.to_der().as_bytes().to_vec())
        })
        .unwrap();
        let pin = Cert::parse(&cert).unwrap().key_hash();
        let clock: cbb_core::tls::Clock = Arc::new(crate::forward::SystemClock);
        let tls = Arc::new(cbb_core::tls::registration_server(&cert, &der, crate::forward::PROTOCOL, &clock).unwrap());
        let ln = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        ln.set_nonblocking(true).unwrap();
        let addr = ln.local_addr().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let sh = Shared {
            claims: Arc::new(Mutex::new(Vec::new())),
            hello_keys: Arc::new(Mutex::new(Vec::new())),
            keys: Arc::new(Mutex::new(HashMap::new())),
        };
        let thread = {
            let (stop, sh) = (stop.clone(), sh.clone());
            std::thread::spawn(move || {
                let mut conns = Vec::new();
                while !stop.load(Ordering::SeqCst) {
                    match ln.accept() {
                        Ok((c, _)) => {
                            let (tls, answer, stop, sh) = (tls.clone(), answer.clone(), stop.clone(), sh.clone());
                            conns.push(std::thread::spawn(move || {
                                let _ = serve(c, tls, &answer, seen, &stop, &sh);
                            }));
                        }
                        Err(_) => std::thread::sleep(Duration::from_millis(10)),
                    }
                }
                for c in conns {
                    let _ = c.join();
                }
            })
        };
        Forwarder { addr, pin, claims: sh.claims, hello_keys: sh.hello_keys, stop, thread: Some(thread) }
    }

    pub fn claims(&self) -> Vec<Claim> {
        self.claims.lock().unwrap().clone()
    }
}

impl Drop for Forwarder {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

/// The forwarder's checks of the credentials: the hubs' credential alone,
/// live, whose list has the server key the hub showed (by its hash); the
/// period key that signed it is the first the forwarder saw for its tag
/// (`PeriodKeys`).
fn check_credentials(envs: &[Vec<u8>], leaf: &[u8; 32], keys: &PeriodKeys) -> std::result::Result<(), &'static str> {
    let now = u64::try_from(crate::uptime::wall_ms()).unwrap_or(0);
    let [env] = envs else { return Err("the hub must show its hubs' credential alone") };
    let h = Credential::read(env).map_err(|_| "the group's credentials do not verify")?;
    if h.kind != TYPE_HUBS {
        return Err("the hub must show its hubs' credential alone");
    }
    if !h.live(now) {
        return Err("the group's credentials expired");
    }
    if keys.lock().unwrap().entry(h.group).or_insert_with(|| h.signer.clone()) != &h.signer {
        return Err("the group's credentials do not verify");
    }
    if !h.hubs.contains(leaf) {
        return Err("the group's hubs' credential does not list this hub");
    }
    Ok(())
}

fn serve(
    c: TcpStream,
    tls: Arc<rustls::ServerConfig>,
    answer: &AnswerFn,
    seen: Option<&str>,
    stop: &AtomicBool,
    sh: &Shared,
) -> std::io::Result<()> {
    use std::io::Write;
    c.set_nonblocking(false)?;
    c.set_read_timeout(Some(Duration::from_secs(10)))?;
    let mut s = rustls::StreamOwned::new(rustls::ServerConnection::new(tls).unwrap(), c);
    while s.conn.is_handshaking() {
        s.conn.complete_io(&mut s.sock)?;
    }
    let shown: Vec<Vec<u8>> = s.conn.peer_certificates().unwrap_or_default().iter().map(|c| c.to_vec()).collect();
    let hello = s.conn.export_keying_material([0u8; 32], b"cbb forwarder hello", None).unwrap();
    let proof_key = s.conn.export_keying_material([0u8; 32], b"cbb forwarder key", None).unwrap();
    sh.hello_keys.lock().unwrap().push(hello);
    let eph = gotatun::x25519::StaticSecret::from(certs::random_bytes::<32>());
    let e = gotatun::x25519::PublicKey::from(&eph);
    s.write_all(&v3::challenge(e.as_bytes()))?;
    s.flush()?;
    let (_, body) = crate::relayd::wire3::read(&mut s, 1 << 20).map_err(|e| std::io::Error::other(e.message()))?;
    let register = Register::read(&body).map_err(|e| std::io::Error::other(e.message()))?;
    sh.claims.lock().unwrap().push(Claim { register: register.clone(), certs: shown.clone() });
    let refusal = (|| {
        let [der] = shown.as_slice() else { return Some("show the certificate of your server key alone".into()) };
        let Ok(cert) = Cert::parse(der) else { return Some("show the certificate of your server key alone".into()) };
        let leaf = cbb_core::records::key::Key::es256(cert.public_key().to_vec()).hash().0;
        let shared = eph.diffie_hellman(&gotatun::x25519::PublicKey::from(register.key));
        let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(shared.as_bytes()).unwrap();
        mac.update(&proof_key);
        if !shared.was_contributory() || mac.verify_slice(&register.proof).is_err() {
            return Some("the hub does not hold that WireGuard key".to_string());
        }
        check_credentials(&register.credentials, &leaf, &sh.keys).err().map(str::to_string)
    })();
    let a = match refusal {
        Some(why) => Answer::Refused(why),
        None => answer(&register),
    };
    match a {
        Answer::Refused(why) => {
            s.write_all(&v3::error(&why))?;
            return s.flush();
        }
        Answer::Registered(r) => s.write_all(&r.write())?,
        Answer::Raw(b) => s.write_all(&b)?,
    }
    s.flush()?;
    if let Some(seen) = seen {
        std::thread::sleep(Duration::from_millis(200));
        s.write_all(&v3::seen(seen))?;
        s.flush()?;
    }
    s.sock.set_read_timeout(Some(Duration::from_millis(100)))?;
    let mut buf = [0u8; 64];
    while !stop.load(Ordering::SeqCst) {
        match s.read(&mut buf) {
            Ok(0) => break,
            Ok(_) => {}
            Err(e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => {}
            Err(_) => break,
        }
    }
    Ok(())
}
