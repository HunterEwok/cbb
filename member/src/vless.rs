// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The lite member's way to the group's hub over VLESS with XHTTP
//! (docs/protocol.md, section 11, "VLESS"), for networks that block
//! WireGuard and AmneziaWG: HTTPS to the forwarder's own site, whose web
//! server passes the offer's path to the forwarder. As internal/vless's
//! client, it is a local UDP port: the tunnel (src/tunnel.rs) sends its
//! WireGuard packets there, and they go to the forwarder inside VLESS, in
//! XHTTP's `packet-up` mode, which is plain HTTP requests: one GET carries
//! the forwarder's answers, POSTs carry the packets, at most 32 KiB each,
//! one after another, gathered for 10 to 50 ms. A session that fails is
//! dropped and the next packet opens a new one.
//!
//! The TLS is rustls with the core's provider (cbb_core::tls::web), the
//! site's certificate checked against the roots of the system (or
//! SSL_CERT_FILE). Unlike Xray's client, which speaks HTTP/2 in a browser's
//! ClientHello, it speaks HTTP/1.1 in rustls's own: a difference a network
//! can see, not a weakness, as the packets are WireGuard with the member
//! TLS inside. The bytes of VLESS and XHTTP are the core's
//! (cbb_core::vless).

use std::collections::VecDeque;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use cbb_core::tls::rustls::pki_types::pem::PemObject;
use cbb_core::tls::rustls::pki_types::{CertificateDer, ServerName};
use cbb_core::tls::rustls::{self, ClientConfig, ClientConnection, RootCertStore, StreamOwned};
use cbb_core::vless::{self as cv, Body, Chunked, Down, Link};
use serde_json::Value;

use crate::error::{Context, Error, Result};

/// The CA bundles of the common Linux systems, the first that exists
/// taken, unless SSL_CERT_FILE names one.
const ROOTS: &[&str] = &[
    "/etc/ssl/certs/ca-certificates.crt",
    "/etc/pki/tls/certs/ca-bundle.crt",
    "/etc/ssl/ca-bundle.pem",
    "/etc/ssl/cert.pem",
];

/// How long a connection or a request may take.
const TIMEOUT: Duration = Duration::from_secs(10);
/// How often the threads look whether they should stop.
const POLL: Duration = Duration::from_millis(250);
/// The packets held while no session carries them; older ones are dropped,
/// as a network would.
const MAX_QUEUE: usize = 64;
/// The longest wait before a failed session is tried again.
const MAX_BACKOFF: Duration = Duration::from_secs(30);

type Tls = StreamOwned<ClientConnection, TcpStream>;

/// What the threads share: the link, the TLS and where answers go.
struct Ctx {
    link: Link,
    endpoint: SocketAddr,
    tls: Arc<ClientConfig>,
    udp: UdpSocket,
    /// The tunnel's socket, which the packets come from and answers go to.
    peer: Mutex<Option<SocketAddr>>,
    stop: AtomicBool,
    log: Arc<dyn Fn(&str) + Send + Sync>,
}

/// The running way. Dropping it stops it.
pub struct Client {
    addr: SocketAddr,
    ctx: Arc<Ctx>,
    thread: Option<JoinHandle<()>>,
}

impl Client {
    /// Starts the way for the `vless` settings of a hub's offer. Nothing is
    /// sent until the tunnel sends its first packet.
    pub fn start(offer: &Value, log: Arc<dyn Fn(&str) + Send + Sync>) -> Result<Client> {
        let link = Link::from_offer(offer)?;
        let endpoint: SocketAddr =
            link.endpoint.parse().map_err(|_| Error::msg(format!("{:?} is not an address", link.endpoint)))?;
        let tls = Arc::new(tls_config()?);
        let udp = UdpSocket::bind("127.0.0.1:0").context("cannot open the local port of the way over VLESS")?;
        udp.set_read_timeout(Some(POLL)).context("cannot open the local port of the way over VLESS")?;
        let addr = udp.local_addr().context("cannot open the local port of the way over VLESS")?;
        let ctx = Arc::new(Ctx { link, endpoint, tls, udp, peer: Mutex::new(None), stop: AtomicBool::new(false), log });
        let thread = {
            let ctx = ctx.clone();
            std::thread::spawn(move || upload(&ctx))
        };
        Ok(Client { addr, ctx, thread: Some(thread) })
    }

    /// The local address the tunnel sends to.
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        self.ctx.stop.store(true, Ordering::SeqCst);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

/// The TLS of the web server: TLS 1.3, HTTP/1.1, the roots of the system.
fn tls_config() -> Result<ClientConfig> {
    let (path, certs) = match std::env::var_os("SSL_CERT_FILE") {
        Some(p) => {
            let p = std::path::PathBuf::from(p);
            let certs = read_roots(&p)?;
            (p, certs)
        }
        None => {
            let p = ROOTS.iter().map(std::path::Path::new).find(|p| p.exists()).ok_or_else(|| {
                Error::msg(
                    "the system has no CA certificates for the way over VLESS; install them or set SSL_CERT_FILE",
                )
            })?;
            (p.to_path_buf(), read_roots(p)?)
        }
    };
    let mut roots = RootCertStore::empty();
    roots.add_parsable_certificates(certs);
    if roots.is_empty() {
        return Err(Error::msg(format!("{} has no CA certificates", path.display())));
    }
    let mut config = ClientConfig::builder_with_provider(Arc::new(cbb_core::tls::web::provider()))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .context("cannot set up the TLS of the way over VLESS")?
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(config)
}

fn read_roots(path: &std::path::Path) -> Result<Vec<CertificateDer<'static>>> {
    let certs = CertificateDer::pem_file_iter(path).context(format!("cannot read {}", path.display()))?;
    // A bundle may hold an entry rustls cannot read; the rest still count.
    Ok(certs.filter_map(|c| c.ok()).collect())
}

/// Random bytes; the system always has them where the tunnel runs.
fn random<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    let _ = getrandom::fill(&mut b);
    b
}

/// A number from lo to hi, both included.
fn between(lo: u32, hi: u32) -> u32 {
    lo + u32::from_le_bytes(random()) % (hi - lo + 1)
}

/// A session's ID as Xray's client makes it: a random UUID, which is also
/// the form of a group's VLESS user ID (Go's tunnel.NewVLESSID).
pub(crate) fn session_id() -> String {
    let mut b: [u8; 16] = random();
    b[6] = b[6] & 0x0f | 0x40;
    b[8] = b[8] & 0x3f | 0x80;
    let h: String = b.iter().map(|x| format!("{x:02x}")).collect();
    format!("{}-{}-{}-{}-{}", &h[..8], &h[8..12], &h[12..16], &h[16..20], &h[20..])
}

/// Xray's padding of a request: 100 to 1000 X's.
fn padding() -> usize {
    between(100, 1000) as usize
}

fn timed_out(e: &io::Error) -> bool {
    matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut)
}

/// A TLS connection to the web server, its handshake done.
fn connect(ctx: &Ctx) -> Result<Tls> {
    let what = || format!("cannot reach the forwarder's site at {}", ctx.endpoint);
    let tcp = TcpStream::connect_timeout(&ctx.endpoint, TIMEOUT).context(what())?;
    let _ = tcp.set_nodelay(true);
    tcp.set_read_timeout(Some(TIMEOUT)).context(what())?;
    tcp.set_write_timeout(Some(TIMEOUT)).context(what())?;
    let name = ServerName::try_from(ctx.link.server_name.clone())
        .map_err(|_| Error::msg(format!("{:?} is not a server name", ctx.link.server_name)))?;
    let conn = ClientConnection::new(ctx.tls.clone(), name).context(what())?;
    let mut tls = StreamOwned::new(conn, tcp);
    while tls.conn.is_handshaking() {
        tls.conn.complete_io(&mut tls.sock).context(format!("the TLS with {} fails", ctx.link.server_name))?;
    }
    tls.sock.set_read_timeout(Some(POLL)).context(what())?;
    Ok(tls)
}

/// Reads an answer's head, leaving in buf what came after it.
fn read_head(ctx: &Ctx, tls: &mut Tls, buf: &mut Vec<u8>, deadline: Option<Instant>) -> Result<cv::Head> {
    let mut chunk = [0u8; 4096];
    loop {
        if let Some(h) = cv::parse_head(buf)? {
            buf.drain(..h.len);
            return Ok(h);
        }
        match tls.read(&mut chunk) {
            Ok(0) => return Err(Error::msg("the forwarder's site closed the connection")),
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(e) if timed_out(&e) => {
                if ctx.stop.load(Ordering::SeqCst) || deadline.is_some_and(|d| Instant::now() > d) {
                    return Err(Error::msg("the forwarder's site does not answer"));
                }
            }
            Err(e) => return Err(Error::with("the connection to the forwarder's site fails", e)),
        }
    }
}

/// Reads an upload's answer to its end.
fn read_answer(ctx: &Ctx, tls: &mut Tls) -> Result<cv::Head> {
    let deadline = Instant::now() + TIMEOUT;
    let mut data = Vec::new();
    let head = read_head(ctx, tls, &mut data, Some(deadline))?;
    let mut chunked = Chunked::default();
    let mut body = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        match head.body {
            Body::Length(n) => {
                body.append(&mut data);
                if body.len() as u64 >= n {
                    return Ok(head);
                }
            }
            Body::Chunked => {
                chunked.push(&std::mem::take(&mut data), &mut body)?;
                if chunked.done() {
                    return Ok(head);
                }
            }
            Body::Close => body.append(&mut data),
        }
        if body.len() > 64 << 10 {
            return Err(Error::msg("the forwarder's site answers an upload at length"));
        }
        match tls.read(&mut chunk) {
            Ok(0) if head.body == Body::Close => return Ok(head),
            Ok(0) => return Err(Error::msg("the forwarder's site closed the connection")),
            Ok(n) => data.extend_from_slice(&chunk[..n]),
            Err(e) if timed_out(&e) => {
                if ctx.stop.load(Ordering::SeqCst) || Instant::now() > deadline {
                    return Err(Error::msg("the forwarder's site does not answer"));
                }
            }
            Err(e) => return Err(Error::with("the connection to the forwarder's site fails", e)),
        }
    }
}

/// One XHTTP session: its download in a thread of its own, its uploads in
/// order on one connection.
struct Session {
    id: String,
    seq: u64,
    post: Option<Tls>,
    /// The requests the upload connection still takes before a new one, as
    /// Xray's client drops its connections after a few hundred.
    left: u32,
    ended: Arc<AtomicBool>,
    down: Option<JoinHandle<()>>,
}

impl Session {
    fn open(ctx: &Arc<Ctx>) -> Session {
        let id = session_id();
        let ended = Arc::new(AtomicBool::new(false));
        let down = {
            let (ctx, id, ended) = (ctx.clone(), id.clone(), ended.clone());
            std::thread::spawn(move || {
                if let Err(e) = download(&ctx, &id, &ended)
                    && !ctx.stop.load(Ordering::SeqCst)
                    && !ended.load(Ordering::SeqCst)
                {
                    (ctx.log)(&format!("cbb: the way over VLESS: {}", e.for_log()));
                }
                ended.store(true, Ordering::SeqCst);
            })
        };
        Session { id, seq: 0, post: None, left: 0, ended, down: Some(down) }
    }

    /// Sends what fits of the queue in one upload; the first carries VLESS's
    /// request header before its packets.
    fn send(&mut self, ctx: &Ctx, queue: &mut VecDeque<Vec<u8>>) -> Result<()> {
        if self.ended.load(Ordering::SeqCst) {
            return Err(Error::msg("the forwarder ended the session"));
        }
        let mut body = if self.seq == 0 { cv::request_header(&ctx.link.id) } else { Vec::new() };
        while let Some(p) = queue.front() {
            let f = cv::frame(p)?;
            if body.len() + f.len() > cv::MAX_POST {
                if f.len() + 26 > cv::MAX_POST {
                    queue.pop_front(); // never fits; a WireGuard packet is far smaller
                    continue;
                }
                break;
            }
            body.extend_from_slice(&f);
            queue.pop_front();
        }
        if self.post.is_none() || self.left == 0 {
            self.post = Some(connect(ctx)?);
            self.left = between(600, 900);
        }
        let tls = self.post.as_mut().expect("connected");
        let req = cv::request(&ctx.link, &self.id, Some(self.seq), body.len(), padding());
        let sent = tls.write_all(req.as_bytes()).and_then(|_| tls.write_all(&body)).and_then(|_| tls.flush());
        if let Err(e) = sent {
            self.post = None;
            return Err(Error::with("cannot upload to the forwarder's site", e));
        }
        let head = match read_answer(ctx, tls) {
            Ok(h) => h,
            Err(e) => {
                self.post = None;
                return Err(e);
            }
        };
        if head.status != 200 {
            self.post = None;
            return Err(Error::msg(format!("the forwarder's site answers an upload with {}", head.status)));
        }
        if head.close {
            self.post = None;
        }
        self.left -= 1;
        self.seq += 1;
        Ok(())
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        self.ended.store(true, Ordering::SeqCst);
        if let Some(t) = self.down.take() {
            let _ = t.join();
        }
    }
}

/// The session's download: the forwarder's answers, passed to the tunnel.
fn download(ctx: &Ctx, id: &str, ended: &AtomicBool) -> Result<()> {
    let mut tls = connect(ctx)?;
    let req = cv::request(&ctx.link, id, None, 0, padding());
    tls.write_all(req.as_bytes())
        .and_then(|_| tls.flush())
        .context("cannot ask the forwarder's site for the download")?;
    let mut buf = Vec::new();
    let head = read_head(ctx, &mut tls, &mut buf, Some(Instant::now() + TIMEOUT))?;
    if head.status != 200 {
        return Err(Error::msg(format!("the forwarder's site answers the download with {}", head.status)));
    }
    let mut chunked = Chunked::default();
    let mut down = Down::default();
    let mut left = match head.body {
        Body::Length(n) => n,
        _ => u64::MAX,
    };
    let mut chunk = [0u8; 16 << 10];
    let mut data = buf;
    loop {
        if !data.is_empty() {
            let body = match head.body {
                Body::Chunked => {
                    let mut out = Vec::new();
                    chunked.push(&data, &mut out)?;
                    out
                }
                Body::Length(_) => {
                    let n = (data.len() as u64).min(left) as usize;
                    left -= n as u64;
                    data[..n].to_vec()
                }
                Body::Close => std::mem::take(&mut data),
            };
            data.clear();
            let packets = down.push(&body)?;
            let peer = *ctx.peer.lock().unwrap();
            if let Some(p) = peer {
                for pkt in packets {
                    let _ = ctx.udp.send_to(&pkt, p);
                }
            }
            if chunked.done() || left == 0 {
                return Err(Error::msg("the forwarder ended the download"));
            }
        }
        if ctx.stop.load(Ordering::SeqCst) || ended.load(Ordering::SeqCst) {
            return Ok(());
        }
        match tls.read(&mut chunk) {
            Ok(0) => return Err(Error::msg("the forwarder ended the download")),
            Ok(n) => data.extend_from_slice(&chunk[..n]),
            Err(e) if timed_out(&e) => {}
            Err(e) => return Err(Error::with("the download from the forwarder's site fails", e)),
        }
    }
}

/// The uploads: the tunnel's packets, gathered, in the current session.
fn upload(ctx: &Arc<Ctx>) {
    let mut queue: VecDeque<Vec<u8>> = VecDeque::new();
    let mut session: Option<Session> = None;
    let mut buf = vec![0u8; 64 << 10];
    let mut retry_at = Instant::now();
    let mut backoff = Duration::from_secs(1);
    let mut said = false;
    while !ctx.stop.load(Ordering::SeqCst) {
        if !receive(ctx, &mut buf, &mut queue, None) {
            continue;
        }
        // Gather what else comes for a moment, as Xray's client does
        // between its uploads.
        let until = Instant::now() + Duration::from_millis(u64::from(between(10, 50)));
        while Instant::now() < until && queue.len() < MAX_QUEUE {
            receive(ctx, &mut buf, &mut queue, Some(until));
        }
        while !queue.is_empty() && !ctx.stop.load(Ordering::SeqCst) {
            if session.as_ref().is_some_and(|s| s.ended.load(Ordering::SeqCst)) {
                session = None;
            }
            if session.is_none() {
                if Instant::now() < retry_at {
                    break;
                }
                session = Some(Session::open(ctx));
            }
            match session.as_mut().expect("opened").send(ctx, &mut queue) {
                Ok(()) => {
                    backoff = Duration::from_secs(1);
                    said = false;
                }
                Err(e) => {
                    if !said {
                        (ctx.log)(&format!("cbb: the way over VLESS: {}", e.for_log()));
                        said = true;
                    }
                    session = None;
                    retry_at = Instant::now() + backoff;
                    backoff = (backoff * 2).min(MAX_BACKOFF);
                    break;
                }
            }
        }
    }
}

/// Takes a packet of the tunnel into the queue, waiting at most until the
/// deadline (or POLL); reports whether one came.
fn receive(ctx: &Ctx, buf: &mut [u8], queue: &mut VecDeque<Vec<u8>>, until: Option<Instant>) -> bool {
    if let Some(u) = until {
        let wait = u.saturating_duration_since(Instant::now()).max(Duration::from_millis(1));
        let _ = ctx.udp.set_read_timeout(Some(wait.min(POLL)));
    } else {
        let _ = ctx.udp.set_read_timeout(Some(POLL));
    }
    match ctx.udp.recv_from(buf) {
        // Only the tunnel on this computer sends here.
        Ok((n, from)) if from.ip().is_loopback() => {
            *ctx.peer.lock().unwrap() = Some(from);
            queue.push_back(buf[..n].to_vec());
            if queue.len() > MAX_QUEUE {
                queue.pop_front();
            }
            true
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_ids_are_uuids() {
        let id = session_id();
        assert_eq!(id.len(), 36);
        assert_eq!(&id[14..15], "4");
        assert!(matches!(&id[19..20], "8" | "9" | "a" | "b"));
        assert_ne!(id, session_id());
        for _ in 0..1000 {
            let p = padding();
            assert!((100..=1000).contains(&p));
        }
    }
}
