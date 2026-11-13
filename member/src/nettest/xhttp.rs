// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! A web server in front of a forwarder, as the tests of the way over VLESS
//! need one: TLS with a certificate of its own, XHTTP's `packet-up` mode,
//! and an echo of what each session uploads to its download, VLESS's
//! response header first. Knobs make it answer what a real one may.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError, Sender, channel};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use cbb_core::tls::rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use cbb_core::tls::rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use cbb_core::tls::rustls::{self, ClientConfig, DigitallySignedStruct, ServerConfig, SignatureScheme};

/// How the site answers.
#[derive(Clone)]
pub struct Knobs {
    /// The status of the download's and the uploads' answers.
    pub get_status: u16,
    pub post_status: u16,
    /// The uploads' answers: chunked, or ended by closing, in place of a
    /// length; and with `Connection: close`.
    pub post_chunked: bool,
    pub post_close_delimited: bool,
    pub post_connection_close: bool,
    /// The download's body has this length, in place of chunks: it ends
    /// once that much went.
    pub get_length: Option<u64>,
    /// The download sends no VLESS response header but this version byte.
    pub bad_version: Option<u8>,
    /// Never answer an upload.
    pub silent_posts: bool,
}

impl Default for Knobs {
    fn default() -> Knobs {
        Knobs {
            get_status: 200,
            post_status: 200,
            post_chunked: false,
            post_close_delimited: false,
            post_connection_close: false,
            get_length: None,
            bad_version: None,
            silent_posts: false,
        }
    }
}

/// An upload the site took: its session, sequence and body.
#[derive(Clone, Debug)]
pub struct Post {
    pub session: String,
    pub seq: u64,
    pub body: Vec<u8>,
}

#[derive(Default)]
struct Sessions {
    downs: HashMap<String, Sender<Vec<u8>>>,
    held: HashMap<String, Vec<Vec<u8>>>,
}

pub struct Site {
    pub addr: SocketAddr,
    pub posts: Arc<Mutex<Vec<Post>>>,
    pub gets: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

/// The VLESS request header's length, which the first upload of a session
/// carries before its packets.
pub const HEADER: usize = 26;

impl Site {
    pub fn start(knobs: Knobs) -> Site {
        let key = cbb_core::identity::new_key().unwrap();
        let signing = cbb_core::identity::signing_key(&key).unwrap();
        let point = p256::ecdsa::VerifyingKey::from(&signing).to_sec1_point(false);
        let cert = cbb_core::certs::server_cert_by(point.as_bytes(), &mut |tbs| {
            use p256::ecdsa::signature::Signer;
            let sig: p256::ecdsa::Signature = signing.sign(tbs);
            Ok(sig.to_der().as_bytes().to_vec())
        })
        .unwrap();
        let mut cfg = ServerConfig::builder_with_provider(Arc::new(cbb_core::tls::web::provider()))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![CertificateDer::from(cert)], PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key)))
            .unwrap();
        cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
        let cfg = Arc::new(cfg);
        let ln = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        ln.set_nonblocking(true).unwrap();
        let addr = ln.local_addr().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let posts = Arc::new(Mutex::new(Vec::new()));
        let gets = Arc::new(AtomicUsize::new(0));
        let sessions = Arc::new(Mutex::new(Sessions::default()));
        let thread = {
            let (stop, posts, gets) = (stop.clone(), posts.clone(), gets.clone());
            std::thread::spawn(move || {
                while !stop.load(Ordering::SeqCst) {
                    match ln.accept() {
                        Ok((c, _)) => {
                            let (cfg, knobs, stop, posts, gets, sessions) = (
                                cfg.clone(),
                                knobs.clone(),
                                stop.clone(),
                                posts.clone(),
                                gets.clone(),
                                sessions.clone(),
                            );
                            std::thread::spawn(move || {
                                let _ = serve(c, &cfg, &knobs, &stop, &posts, &gets, &sessions);
                            });
                        }
                        Err(_) => std::thread::sleep(Duration::from_millis(10)),
                    }
                }
            })
        };
        Site { addr, posts, gets, stop, thread: Some(thread) }
    }

    pub fn posts(&self) -> Vec<Post> {
        self.posts.lock().unwrap().clone()
    }

    /// The `vless` settings of a hub's offer for this site.
    pub fn offer(&self, id: &str) -> serde_json::Value {
        serde_json::json!({
            "transport": "xhttp",
            "endpoint": self.addr.to_string(),
            "server_name": "site.test",
            "path": "/AbC-12_xyz0123456/a-group-of-its-own",
            "id": id,
        })
    }
}

impl Drop for Site {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

type Tls = rustls::StreamOwned<rustls::ServerConnection, TcpStream>;

fn serve(
    c: TcpStream,
    cfg: &Arc<ServerConfig>,
    knobs: &Knobs,
    stop: &AtomicBool,
    posts: &Mutex<Vec<Post>>,
    gets: &AtomicUsize,
    sessions: &Mutex<Sessions>,
) -> std::io::Result<()> {
    c.set_nonblocking(false)?;
    c.set_read_timeout(Some(Duration::from_millis(100)))?;
    let mut s: Tls = rustls::StreamOwned::new(rustls::ServerConnection::new(cfg.clone()).unwrap(), c);
    let mut buf = Vec::new();
    loop {
        let Some((method, target, len)) = read_request(&mut s, &mut buf, stop)? else { return Ok(()) };
        let parts: Vec<&str> = target.trim_start_matches('/').split('/').collect();
        if method == "GET" {
            gets.fetch_add(1, Ordering::SeqCst);
            let session = parts.last().copied().unwrap_or_default().to_string();
            if knobs.get_status != 200 {
                s.write_all(format!("HTTP/1.1 {} No\r\nContent-Length: 0\r\n\r\n", knobs.get_status).as_bytes())?;
                continue;
            }
            let (tx, rx) = channel();
            {
                let mut st = sessions.lock().unwrap();
                for p in st.held.remove(&session).unwrap_or_default() {
                    let _ = tx.send(p);
                }
                st.downs.insert(session.clone(), tx);
            }
            return download(&mut s, knobs, stop, &rx);
        }
        // POST {path}/{session}/{seq}
        let mut body = vec![0u8; len];
        let have = buf.len().min(len);
        body[..have].copy_from_slice(&buf[..have]);
        buf.drain(..have);
        read_full(&mut s, &mut body[have..], stop)?;
        let seq: u64 = parts.last().and_then(|p| p.parse().ok()).unwrap_or(0);
        let session = parts.get(parts.len().saturating_sub(2)).copied().unwrap_or_default().to_string();
        posts.lock().unwrap().push(Post { session: session.clone(), seq, body: body.clone() });
        let payload = if seq == 0 { body.get(HEADER..).unwrap_or_default().to_vec() } else { body };
        if knobs.post_status == 200 {
            let mut st = sessions.lock().unwrap();
            match st.downs.get(&session) {
                Some(tx) => {
                    let _ = tx.send(payload);
                }
                None => st.held.entry(session).or_default().push(payload),
            }
        }
        if knobs.silent_posts {
            continue;
        }
        let status = knobs.post_status;
        let close = if knobs.post_connection_close { "Connection: close\r\n" } else { "" };
        if knobs.post_close_delimited {
            s.write_all(format!("HTTP/1.1 {status} OK\r\n\r\nok").as_bytes())?;
            s.conn.send_close_notify();
            let _ = s.flush();
            return Ok(());
        }
        if knobs.post_chunked {
            s.write_all(
                format!("HTTP/1.1 {status} OK\r\n{close}Transfer-Encoding: chunked\r\n\r\n2\r\nok\r\n0\r\n\r\n")
                    .as_bytes(),
            )?;
        } else {
            s.write_all(format!("HTTP/1.1 {status} OK\r\n{close}Content-Length: 2\r\n\r\nok").as_bytes())?;
        }
        s.flush()?;
        if knobs.post_connection_close {
            return Ok(());
        }
    }
}

fn download(s: &mut Tls, knobs: &Knobs, stop: &AtomicBool, rx: &Receiver<Vec<u8>>) -> std::io::Result<()> {
    let first = match knobs.bad_version {
        Some(v) => vec![v, 0],
        None => vec![0, 0],
    };
    match knobs.get_length {
        Some(n) => {
            s.write_all(format!("HTTP/1.1 200 OK\r\nContent-Length: {n}\r\n\r\n").as_bytes())?;
            s.write_all(&first)?;
        }
        None => {
            s.write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n")?;
            s.write_all(&chunk(&first))?;
        }
    }
    s.flush()?;
    while !stop.load(Ordering::SeqCst) {
        match rx.recv_timeout(Duration::from_millis(100)) {
            Ok(p) if p.is_empty() => {}
            Ok(p) => {
                if knobs.get_length.is_some() {
                    s.write_all(&p)?;
                } else {
                    s.write_all(&chunk(&p))?;
                }
                s.flush()?;
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => break,
        }
    }
    Ok(())
}

fn chunk(b: &[u8]) -> Vec<u8> {
    let mut v = format!("{:x}\r\n", b.len()).into_bytes();
    v.extend_from_slice(b);
    v.extend_from_slice(b"\r\n");
    v
}

fn timed_out(e: &std::io::Error) -> bool {
    matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut)
}

/// The next request's method, target and body length.
fn read_request(s: &mut Tls, buf: &mut Vec<u8>, stop: &AtomicBool) -> std::io::Result<Option<(String, String, usize)>> {
    let mut chunk = [0u8; 4096];
    loop {
        if let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&buf[..end]).to_string();
            buf.drain(..end + 4);
            let mut lines = head.split("\r\n");
            let mut first = lines.next().unwrap_or_default().split(' ');
            let method = first.next().unwrap_or_default().to_string();
            let target = first.next().unwrap_or_default().to_string();
            let len = lines
                .filter_map(|l| l.split_once(':'))
                .find(|(n, _)| n.eq_ignore_ascii_case("content-length"))
                .and_then(|(_, v)| v.trim().parse().ok())
                .unwrap_or(0);
            return Ok(Some((method, target, len)));
        }
        if stop.load(Ordering::SeqCst) {
            return Ok(None);
        }
        match s.read(&mut chunk) {
            Ok(0) => return Ok(None),
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(e) if timed_out(&e) => {}
            Err(e) => return Err(e),
        }
    }
}

fn read_full(s: &mut Tls, mut b: &mut [u8], stop: &AtomicBool) -> std::io::Result<()> {
    while !b.is_empty() {
        if stop.load(Ordering::SeqCst) {
            return Err(std::io::Error::other("stopped"));
        }
        match s.read(b) {
            Ok(0) => return Err(std::io::Error::other("closed")),
            Ok(n) => b = &mut b[n..],
            Err(e) if timed_out(&e) => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// A client configuration that takes the site's certificate, as the
/// system's roots take a public site's.
pub fn client_config() -> Arc<ClientConfig> {
    let provider = Arc::new(cbb_core::tls::web::provider());
    let mut c = ClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AnySite(provider)))
        .with_no_client_auth();
    c.alpn_protocols = vec![b"http/1.1".to_vec()];
    Arc::new(c)
}

#[derive(Debug)]
struct AnySite(Arc<rustls::crypto::CryptoProvider>);

impl ServerCertVerifier for AnySite {
    fn verify_server_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::General("no TLS 1.2".into()))
    }

    fn verify_tls13_signature(
        &self,
        m: &[u8],
        c: &CertificateDer<'_>,
        d: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(m, c, d, &self.0.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}
