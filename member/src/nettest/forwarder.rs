// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! A forwarder's registrations in the same process, as the tests of a hub's
//! registration need them: TLS pinned by its key, the challenge, the claim
//! and an answer the test chooses, then where it saw the hub.

use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use cbb_core::certs::{self, Cert};
use cbb_core::tls::rustls;
use serde_json::Value;

/// The answer to a claim, from the claim and the registration's hello key.
pub type AnswerFn = Arc<dyn Fn(&Value) -> Value + Send + Sync>;

pub struct Forwarder {
    pub addr: SocketAddr,
    pub pin: certs::KeyHash,
    pub claims: Arc<Mutex<Vec<Value>>>,
    /// The hello key of each registration, from its TLS.
    pub hello_keys: Arc<Mutex<Vec<[u8; 32]>>>,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

/// The mask key the test forwarder gives.
pub const MASK: [u8; 32] = [9; 32];

/// A plain answer: the registration 7, the mask, and VLESS settings when
/// the claim names a user ID.
pub fn welcome() -> AnswerFn {
    use base64::Engine;
    Arc::new(|claim: &Value| {
        let mut a = serde_json::json!({
            "id": 7,
            "mask": base64::engine::general_purpose::STANDARD.encode(MASK),
        });
        if claim.get("vless").is_some() {
            a["vless"] = serde_json::json!({
                "transport": "xhttp", "port": 8443, "server_name": "site.test",
                "path": "/AbC-12_xyz0123456/a-group-of-its-own",
            });
        }
        a
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
        let claims = Arc::new(Mutex::new(Vec::new()));
        let hello_keys = Arc::new(Mutex::new(Vec::new()));
        let thread = {
            let (stop, claims, hello_keys) = (stop.clone(), claims.clone(), hello_keys.clone());
            std::thread::spawn(move || {
                let mut conns = Vec::new();
                while !stop.load(Ordering::SeqCst) {
                    match ln.accept() {
                        Ok((c, _)) => {
                            let (tls, answer, stop, claims, hello_keys) =
                                (tls.clone(), answer.clone(), stop.clone(), claims.clone(), hello_keys.clone());
                            conns.push(std::thread::spawn(move || {
                                let _ = serve(c, tls, &answer, seen, &stop, &claims, &hello_keys);
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
        Forwarder { addr, pin, claims, hello_keys, stop, thread: Some(thread) }
    }

    pub fn claims(&self) -> Vec<Value> {
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

fn write_frame(s: &mut impl Write, v: &Value) -> std::io::Result<()> {
    let b = serde_json::to_vec(v).unwrap();
    s.write_all(&(b.len() as u32).to_be_bytes())?;
    s.write_all(&b)?;
    s.flush()
}

fn read_frame(s: &mut impl Read) -> std::io::Result<Value> {
    let mut h = [0u8; 4];
    s.read_exact(&mut h)?;
    let mut b = vec![0u8; u32::from_be_bytes(h) as usize];
    s.read_exact(&mut b)?;
    serde_json::from_slice(&b).map_err(std::io::Error::other)
}

fn serve(
    c: TcpStream,
    tls: Arc<rustls::ServerConfig>,
    answer: &AnswerFn,
    seen: Option<&str>,
    stop: &AtomicBool,
    claims: &Mutex<Vec<Value>>,
    hello_keys: &Mutex<Vec<[u8; 32]>>,
) -> std::io::Result<()> {
    use base64::Engine;
    c.set_nonblocking(false)?;
    c.set_read_timeout(Some(Duration::from_secs(10)))?;
    let mut s = rustls::StreamOwned::new(rustls::ServerConnection::new(tls).unwrap(), c);
    while s.conn.is_handshaking() {
        s.conn.complete_io(&mut s.sock)?;
    }
    let hello = s.conn.export_keying_material([0u8; 32], b"cbb forwarder hello", None).unwrap();
    hello_keys.lock().unwrap().push(hello);
    let e = crate::tunnel::new_key().unwrap();
    let e_pub =
        gotatun::x25519::PublicKey::from(&gotatun::x25519::StaticSecret::from(<[u8; 32]>::try_from(&e[..]).unwrap()));
    write_frame(&mut s, &serde_json::json!({"e": base64::engine::general_purpose::STANDARD.encode(e_pub.as_bytes())}))?;
    let claim = read_frame(&mut s)?;
    claims.lock().unwrap().push(claim.clone());
    let a = answer(&claim);
    let refused = a.get("error").is_some();
    write_frame(&mut s, &a)?;
    if refused {
        return Ok(());
    }
    if let Some(seen) = seen {
        std::thread::sleep(Duration::from_millis(200));
        write_frame(&mut s, &serde_json::json!({"seen": seen}))?;
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
