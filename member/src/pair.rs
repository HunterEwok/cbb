// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! Joining a group over the network: the TLS connection around the
//! exchange of cbb_core::pair, either listening for the phone that scanned
//! this device's QR code or dialing a Linux member's open pairing window.

use std::io::Write;
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::time::{Duration, Instant};

pub use cbb_core::pair::*;

use crate::error::{Context, Error, Result, Wrap};
use crate::identity::Identity;
use crate::tls;
use crate::wire;

/// What stores a join's result: the records that lead to the group's
/// roots, then the identity, so the identity never trusts roots its records
/// do not name.
pub type Save = SaveRef<'static>;
/// Save, borrowing what it uses.
pub type SaveRef<'a> = dyn Fn(&Identity, &[crate::records::Record], &[crate::records::ClaimTime]) -> Result<()> + 'a;

const ATTEMPT_TIMEOUT: Duration = Duration::from_secs(30);
/// How long a join waits for the member to close the connection after the
/// last frame.
const CLOSE_WAIT: Duration = Duration::from_secs(3);
/// How long a listening join waits.
pub const LIFETIME: Duration = Duration::from_secs(5 * 60);
/// How long a member that dialed a listening joiner has to start the TLS
/// handshake.
const HELLO_TIMEOUT: Duration = Duration::from_secs(5);
/// How many attempts from one source may end without a wrong code before
/// a listening joiner takes none from it.
const MAX_IDLE: u32 = 5;
/// How many sources a listening joiner counts one by one; the others share
/// one count.
const MAX_SOURCES: usize = 1024;
/// How long a member that dialed a listening joiner has, from its
/// connection, until it proved that it knows the code: a member sends its
/// CPace message and its tag right after the TLS handshake.
const PROVE_TIMEOUT: Duration = Duration::from_secs(10);
/// How long the running attempt keeps a listening joiner against a new
/// connection before its member proved that it knows the code.
const GIVE_WAY: Duration = Duration::from_secs(2);

/// The source a connection from ip counts against, for the limits of a
/// pairing window, a listening joiner and the member port: the address
/// itself, or the /64 of a global IPv6 address, within which a device may
/// change its address at will. Every device of a home network shares its
/// unique-local and link-local /64s, so those count address by address.
pub fn source(ip: IpAddr) -> IpAddr {
    match ip.to_canonical() {
        IpAddr::V4(a) => IpAddr::V4(a),
        IpAddr::V6(a) => {
            let s = a.segments();
            let shared = (s[0] & 0xfe00) == 0xfc00 || (s[0] & 0xffc0) == 0xfe80;
            if shared { IpAddr::V6(a) } else { IpAddr::V6(std::net::Ipv6Addr::new(s[0], s[1], s[2], s[3], 0, 0, 0, 0)) }
        }
    }
}

/// The attempts of each source that ended without a wrong code, which a
/// listening joiner counts so that no device on the network can hold it
/// for its whole wait.
#[derive(Default)]
struct Idle(std::collections::HashMap<IpAddr, u32>);

impl Idle {
    fn key(&self, ip: IpAddr) -> IpAddr {
        let k = source(ip);
        if self.0.contains_key(&k) || self.0.len() < MAX_SOURCES {
            k
        } else {
            IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED)
        }
    }

    fn spent(&self, ip: IpAddr) -> bool {
        self.0.get(&self.key(ip)).is_some_and(|n| *n >= MAX_IDLE)
    }

    fn count(&mut self, ip: IpAddr) {
        let k = self.key(ip);
        *self.0.entry(k).or_default() += 1;
    }
}

/// Runs the joining side over a connection a member dialed to this joiner,
/// which showed its QR code. The member confirms first, so a device that
/// does not know the code learns nothing.
/// proven is called once the member proved that it knows the code.
fn accept(j: &Joiner, sock: TcpStream, code: &str, save: &SaveRef<'_>, proven: &dyn Fn()) -> Result<Identity> {
    let (cfg, exporter) = match j.external_key() {
        Some(k) => tls::pair_server_external(&j.cert, k.clone(), &tls::clock())?,
        None => tls::pair_server(&j.cert, &j.key, &tls::clock())?,
    };
    let session = tls::Session::server(Arc::new(cfg))?;
    run(j, tls::Stream::new(session, sock), &exporter, Password::Code(code), true, save, proven)
}

/// Runs the joining side over a connection to a member's open pairing
/// window, with the code the user typed.
pub fn join(j: &Joiner, sock: TcpStream, code: &str, save: &SaveRef<'_>) -> Result<Identity> {
    dial(j, sock, Password::Code(code), save)
}

/// Runs the joining side over a connection to the pairing window of a
/// remote invitation, with its secret, as Go's JoinSecret: the window's
/// admin confirms the device, which may take up to CONFIRM_WAIT. group is
/// the invitation's group tag; a member of another group is refused.
pub fn join_secret(j: &Joiner, sock: TcpStream, secret: &[u8], group: &str, save: &SaveRef<'_>) -> Result<Identity> {
    dial(j, sock, Password::Secret(secret, group), save)
}

/// How long a remote invitation's admin may take to confirm the device, as
/// Go's confirmWait.
pub const CONFIRM_WAIT: Duration = Duration::from_secs(300);

/// What proves the joiner may join: the code the user typed, or a remote
/// invitation's secret.
#[derive(Clone, Copy)]
enum Password<'a> {
    Code(&'a str),
    Secret(&'a [u8], &'a str),
}

fn dial(j: &Joiner, sock: TcpStream, password: Password, save: &SaveRef<'_>) -> Result<Identity> {
    let (cfg, exporter) = match j.external_key() {
        Some(k) => tls::pair_client_external(&j.cert, k.clone(), &tls::clock())?,
        None => tls::pair_client(&j.cert, &j.key, &tls::clock())?,
    };
    let session = tls::Session::client(Arc::new(cfg), tls::server_name(None))?;
    run(j, tls::Stream::new(session, sock), &exporter, password, false, save, &|| {})
}

fn run(
    j: &Joiner,
    mut tc: tls::Stream,
    exporter: &tls::Exporter,
    password: Password,
    member_first: bool,
    save: &SaveRef<'_>,
    proven: &dyn Fn(),
) -> Result<Identity> {
    if let Password::Code(code) = password {
        normalize_code(code)?;
    }
    tc.sock.set_read_timeout(Some(ATTEMPT_TIMEOUT)).context("the connection broke")?;
    tc.sock.set_write_timeout(Some(ATTEMPT_TIMEOUT)).context("the connection broke")?;
    tls::handshake(&mut tc.session, &tc.sock, "the TLS handshake failed")?;
    if tc.session.alpn_protocol() != Some(tls::PAIR_PROTOCOL) {
        return Err(Error::msg("the device does not offer pairing"));
    }
    let member_der = tc
        .session
        .peer_certificates()
        .and_then(|c| c.first())
        .map(|c| c.to_vec())
        .ok_or_else(|| Error::msg("the device does not offer pairing"))?;
    let mut sid = [0u8; 32];
    exporter.export(EXPORTER_LABEL, &[], &mut sid).wrap("cannot bind the pairing to TLS")?;
    let id = exchange(j, &mut tc, password, &member_der, &sid, member_first, save, proven)?;
    tc.close();
    // The last frame reaches the member before this returns: through a
    // tunnel whose link stops right after, it would be lost on the way. The
    // member closes the connection once it has it.
    let _ = tc.sock.shutdown(std::net::Shutdown::Write);
    let _ = tc.sock.set_read_timeout(Some(CLOSE_WAIT));
    let mut buf = [0u8; 512];
    let until = Instant::now() + CLOSE_WAIT;
    while Instant::now() < until && matches!(std::io::Read::read(&mut tc.sock, &mut buf), Ok(n) if n > 0) {}
    Ok(id)
}

/// Runs the frames of the exchange over a TLS stream; proven is called
/// once the member's reply verified.
#[allow(clippy::too_many_arguments)]
fn exchange(
    j: &Joiner,
    tc: &mut tls::Stream,
    password: Password,
    member_der: &[u8],
    sid: &[u8],
    member_first: bool,
    save: &SaveRef<'_>,
    proven: &dyn Fn(),
) -> Result<Identity> {
    let send = |rw: &mut dyn Write, f: &[u8]| -> Result<()> {
        rw.write_all(f).context("the connection broke")?;
        rw.flush().context("the connection broke")
    };
    let (mut ex, first) = match password {
        Password::Code(code) => j.start(code, member_der, sid, member_first)?,
        Password::Secret(secret, group) => j.start_secret(secret, group, member_der, sid)?,
    };
    send(tc, &first)?;
    let confirm = match ex.reply(&wire::read_frame(tc, MAX_FRAME)?) {
        Ok(f) => f,
        Err(Failure { error, send: reply }) => {
            if let Some(f) = reply {
                let _ = send(tc, &f);
            }
            return Err(error);
        }
    };
    proven();
    send(tc, &confirm)?;
    if let Password::Secret(..) = password {
        // The admin is asked now.
        tc.sock.set_read_timeout(Some(ATTEMPT_TIMEOUT + CONFIRM_WAIT)).context("the connection broke")?;
    }
    let rw = tc;
    let res = ex
        .welcome(&wire::read_frame(rw, MAX_FRAME)?, crate::uptime::wall_ms())
        .and_then(|id| save(&id, &ex.records(), &ex.claim_times()).map(|_| id));
    let _ = send(rw, &done(res.is_ok()));
    res
}

/// Reports whether an address may reach the member port: what mDNS would
/// publish (private IPv4, unique-local and link-local IPv6) or loopback.
pub fn home_address(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(a) => a.is_private() || a.is_loopback() || a.is_link_local(),
        IpAddr::V6(a) => {
            if let Some(v4) = a.to_ipv4_mapped() {
                return home_address(IpAddr::V4(v4));
            }
            a.is_loopback() || (a.segments()[0] & 0xfe00) == 0xfc00 || (a.segments()[0] & 0xffc0) == 0xfe80
        }
    }
}

/// The addresses for the QR code: those mDNS would publish, IPv4 first,
/// without link-local ones, at most four.
pub fn qr_addresses(port: u16) -> Vec<String> {
    let mut v4 = Vec::new();
    let mut v6 = Vec::new();
    for iface in if_addrs::get_if_addrs().unwrap_or_default() {
        if iface.is_loopback() || !crate::interfaces::allowed(&iface.name) {
            continue;
        }
        match iface.ip() {
            IpAddr::V4(a) if a.is_private() => v4.push(SocketAddr::new(IpAddr::V4(a), port).to_string()),
            IpAddr::V6(a) if (a.segments()[0] & 0xfe00) == 0xfc00 => {
                v6.push(SocketAddr::new(IpAddr::V6(a), port).to_string())
            }
            _ => {}
        }
    }
    v4.extend(v6);
    v4.dedup();
    v4.truncate(4);
    v4
}

/// Listens for a member that dials this joiner, for up to LIFETIME. It
/// calls shown with the QR code's text once it listens, takes one attempt
/// at a time, gives up after the third wrong code, and returns the new
/// identity, which save stored. A source whose attempts ended MAX_IDLE
/// times without a wrong code gets no more, a member must start the
/// handshake within HELLO_TIMEOUT and prove that it knows the code within
/// PROVE_TIMEOUT, and an attempt that has not proved it after GIVE_WAY
/// ends for a new connection.
#[allow(clippy::too_many_arguments)]
pub fn listen(
    joiner: &Joiner,
    ln: TcpListener,
    addrs: Option<Vec<String>>,
    code: &str,
    wait: Duration,
    shown: &dyn Fn(&str),
    save: &SaveRef<'_>,
    log: &dyn Fn(&str),
) -> Result<Identity> {
    let port = ln.local_addr().context("cannot listen")?.port();
    let addrs = addrs.unwrap_or_else(|| qr_addresses(port));
    if addrs.is_empty() {
        return Err(Error::msg(
            "this device has no address on the home network; connect it to the network, or use pair -code",
        ));
    }
    shown(&join_qr(code, &addrs, &joiner.fingerprint()));
    // Announced, so that a computer finds it by the code alone.
    let _announced = crate::discovery::announce_joiner(&joiner.id, port, &joiner.fingerprint());
    ln.set_nonblocking(true).context("cannot listen")?;
    let end = Instant::now() + wait;
    let turn = std::sync::Mutex::new(Turn::default());
    let (tx, rx) = std::sync::mpsc::sync_channel::<(TcpStream, SocketAddr)>(1);
    std::thread::scope(|scope| {
        let watcher = scope.spawn(|| watch(&ln, &turn, tx, end));
        let res = attempts(joiner, code, save, log, &turn, &rx, end);
        turn.lock().unwrap().over = true;
        let watched = watcher.join().unwrap_or(Ok(()));
        // Why the listener stopped, if it did, explains a joiner that
        // waited in vain.
        res.or_else(|e| watched.and(Err(e)))
    })
}

/// What the listener and the running attempt of a listening joiner share.
#[derive(Default)]
struct Turn {
    /// The running attempt's socket, when it started, and whether its
    /// member proved that it knows the code.
    running: Option<(TcpStream, Instant)>,
    proven: bool,
    idle: Idle,
    /// The failed attempts of each address.
    tries: Attempts<IpAddr>,
    /// The joiner stopped listening.
    over: bool,
}

impl Turn {
    /// Whether a new connection may take the place of the running attempt
    /// at now: none runs, or it has not proved the code after GIVE_WAY.
    fn gives_way(&self, now: Instant) -> bool {
        match &self.running {
            None => true,
            Some((_, since)) => !self.proven && now.duration_since(*since) >= GIVE_WAY,
        }
    }

    /// Shuts the running attempt when its member has not proved the code
    /// within PROVE_TIMEOUT.
    fn expire(&mut self, now: Instant) {
        if let Some((sock, since)) = &self.running
            && !self.proven
            && now.duration_since(*since) >= PROVE_TIMEOUT
        {
            let _ = sock.shutdown(std::net::Shutdown::Both);
        }
    }
}

/// Accepts the connections of a listening joiner and hands them to the
/// attempts one at a time, until it stops listening or end.
fn watch(
    ln: &TcpListener,
    turn: &std::sync::Mutex<Turn>,
    tx: std::sync::mpsc::SyncSender<(TcpStream, SocketAddr)>,
    end: Instant,
) -> Result<()> {
    loop {
        let now = Instant::now();
        {
            let mut t = turn.lock().unwrap();
            if t.over || now >= end {
                return Ok(());
            }
            t.expire(now);
        }
        let (sock, from) = match ln.accept() {
            Ok(c) => c,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(100));
                continue;
            }
            Err(e) => {
                turn.lock().unwrap().over = true;
                return Err(Error::with("cannot accept a connection", e));
            }
        };
        if !home_address(from.ip()) || !crate::interfaces::arrived(&sock) {
            continue;
        }
        let mut t = turn.lock().unwrap();
        if t.idle.spent(from.ip()) || !t.tries.allowed(from.ip()) || !t.gives_way(Instant::now()) {
            continue;
        }
        if let Some((old, _)) = t.running.take() {
            let _ = old.shutdown(std::net::Shutdown::Both);
        }
        drop(t);
        // Busy with one handed over and not started yet: this one waits
        // for none.
        let _ = tx.try_send((sock, from));
    }
}

/// Runs the attempts of a listening joiner on the connections watch hands
/// over, until one admits it, the third wrong code or end.
fn attempts(
    joiner: &Joiner,
    code: &str,
    save: &SaveRef<'_>,
    log: &dyn Fn(&str),
    turn: &std::sync::Mutex<Turn>,
    rx: &std::sync::mpsc::Receiver<(TcpStream, SocketAddr)>,
    end: Instant,
) -> Result<Identity> {
    let mut failures = 0;
    while Instant::now() < end && !turn.lock().unwrap().over {
        let (sock, from) = match rx.recv_timeout(Duration::from_millis(100)) {
            Ok(c) => c,
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => continue,
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
        };
        {
            let mut t = turn.lock().unwrap();
            t.running = sock.try_clone().ok().map(|s| (s, Instant::now()));
            t.proven = false;
        }
        let _ = sock.set_nonblocking(false);
        if !hello_comes(&sock) {
            let mut t = turn.lock().unwrap();
            t.running = None;
            t.idle.count(from.ip());
            continue;
        }
        let res = accept(joiner, sock, code, save, &|| turn.lock().unwrap().proven = true);
        let mut t = turn.lock().unwrap();
        t.running = None;
        match res {
            Ok(id) => return Ok(id),
            Err(e) => {
                log(&format!("cbb: a pairing attempt from {from} failed: {}", e.for_log()));
                t.tries.failed(from.ip());
                if is_wrong_code(&e) {
                    failures += 1;
                    if failures >= MAX_FAILURES {
                        return Err(Error::with(format!("pair: {}", Refusal::TooMany), Refusal::TooMany));
                    }
                } else {
                    t.idle.count(from.ip());
                }
            }
        }
    }
    Err(Error::msg("no device joined this one in time; run join again"))
}

/// Whether the peer sends something within HELLO_TIMEOUT, as a member
/// that dialed starts its TLS handshake at once.
fn hello_comes(sock: &TcpStream) -> bool {
    if sock.set_read_timeout(Some(HELLO_TIMEOUT)).is_err() {
        return false;
    }
    matches!(sock.peek(&mut [0u8; 1]), Ok(n) if n > 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sources() {
        let a: IpAddr = "192.168.1.5".parse().unwrap();
        assert_eq!(source(a), a);
        assert_eq!(source("::ffff:192.168.1.5".parse().unwrap()), a);
        // A global address counts by its /64.
        let b: IpAddr = "2001:db8:2:3:aaaa:bbbb:cccc:dddd".parse().unwrap();
        assert_eq!(source(b), "2001:db8:2:3::".parse::<IpAddr>().unwrap());
        assert_eq!(source("2001:db8:2:3::9".parse().unwrap()), source(b));
        assert_ne!(source("2001:db8:2:4::9".parse().unwrap()), source(b));
        // Every device of the network shares the unique-local and
        // link-local /64s: each address counts on its own.
        for (one, other) in [("fd00:1:2:3::1", "fd00:1:2:3::2"), ("fe80::1", "fe80::2")] {
            let (one, other): (IpAddr, IpAddr) = (one.parse().unwrap(), other.parse().unwrap());
            assert_eq!(source(one), one);
            assert_ne!(source(one), source(other));
        }
    }

    #[test]
    fn a_listening_joiner_counts_attempts_that_tried_no_code() {
        let mut idle = Idle::default();
        let a: IpAddr = "fd00::1".parse().unwrap();
        for _ in 0..MAX_IDLE {
            assert!(!idle.spent(a));
            idle.count(a);
        }
        assert!(idle.spent(a));
        // Another device of the same network is not.
        assert!(!idle.spent("fd00::2".parse().unwrap()));
        assert!(!idle.spent("192.168.1.9".parse().unwrap()));
        // Past MAX_SOURCES, new sources share one count.
        let mut idle = Idle::default();
        for i in 0..MAX_SOURCES as u32 {
            idle.count(IpAddr::V4(std::net::Ipv4Addr::from(0x0a00_0000 + i)));
        }
        for i in 0..MAX_IDLE {
            idle.count(IpAddr::V4(std::net::Ipv4Addr::from(0x0b00_0000 + i)));
        }
        assert!(idle.spent("172.16.0.1".parse().unwrap()));
        assert!(!idle.spent("10.0.0.1".parse().unwrap()));
    }

    /// A host that connects to a listening joiner and stays silent does
    /// not hold it: the joiner closes it after HELLO_TIMEOUT.
    #[test]
    fn a_silent_connection_is_closed_soon() {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let _silent = TcpStream::connect(l.local_addr().unwrap()).unwrap();
        let (sock, _) = l.accept().unwrap();
        let t = Instant::now();
        assert!(!hello_comes(&sock));
        assert!(t.elapsed() < HELLO_TIMEOUT + Duration::from_secs(2));
        let mut talking = TcpStream::connect(l.local_addr().unwrap()).unwrap();
        talking.write_all(b"x").unwrap();
        let (sock, _) = l.accept().unwrap();
        assert!(hello_comes(&sock));
    }
    /// An attempt whose member has not proved the code gives way to a new
    /// connection after GIVE_WAY, and ends after PROVE_TIMEOUT; one whose
    /// member proved it keeps the joiner.
    #[test]
    fn a_member_that_proves_nothing_gives_way() {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut peer = TcpStream::connect(l.local_addr().unwrap()).unwrap();
        let (sock, _) = l.accept().unwrap();
        let now = Instant::now();
        let mut t = Turn::default();
        assert!(t.gives_way(now));
        t.running = Some((sock, now));
        assert!(!t.gives_way(now));
        assert!(t.gives_way(now + GIVE_WAY));
        t.proven = true;
        assert!(!t.gives_way(now + GIVE_WAY));
        t.expire(now + PROVE_TIMEOUT);
        t.proven = false;
        t.expire(now + PROVE_TIMEOUT - Duration::from_millis(1));
        peer.set_read_timeout(Some(Duration::from_millis(200))).unwrap();
        assert!(peer.read(&mut [0u8; 1]).is_err(), "closed too soon");
        t.expire(now + PROVE_TIMEOUT);
        peer.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        assert_eq!(peer.read(&mut [0u8; 1]).unwrap(), 0);
    }

    /// A host that finishes the TLS handshake with a listening joiner and
    /// then says nothing loses its attempt to the next connection.
    #[test]
    fn a_quiet_member_loses_its_attempt_to_the_next() {
        let joiner = Joiner::new("router").unwrap();
        let ln = TcpListener::bind("127.0.0.1:0").unwrap();
        let at = ln.local_addr().unwrap();
        ln.set_nonblocking(true).unwrap();
        let end = Instant::now() + Duration::from_secs(30);
        let turn = std::sync::Mutex::new(Turn::default());
        let (tx, rx) = std::sync::mpsc::sync_channel(1);
        let save: &SaveRef<'_> = &|_, _, _| Err(Error::msg("not in this test"));
        std::thread::scope(|scope| {
            scope.spawn(|| watch(&ln, &turn, tx, end));
            let member = scope.spawn(|| {
                let member = Joiner::new("quiet").unwrap();
                let (cfg, _) = tls::pair_client(&member.cert, &member.key, &tls::clock()).unwrap();
                let session = tls::Session::client(Arc::new(cfg), tls::server_name(None)).unwrap();
                let mut quiet = tls::Stream::new(session, TcpStream::connect(at).unwrap());
                tls::handshake(&mut quiet.session, &quiet.sock, "handshake").unwrap();
                std::thread::sleep(GIVE_WAY + Duration::from_millis(300));
                let t = Instant::now();
                let mut next = TcpStream::connect(at).unwrap();
                next.write_all(b"x").unwrap();
                quiet.sock.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
                let mut buf = [0u8; 64];
                while matches!(quiet.sock.read(&mut buf), Ok(n) if n > 0) {}
                let took = t.elapsed();
                std::thread::sleep(Duration::from_millis(200));
                let counted = turn.lock().unwrap().idle.0.get(&source(at.ip())).copied();
                turn.lock().unwrap().over = true;
                (took, counted)
            });
            let _ = attempts(&joiner, "123456", save, &|_| {}, &turn, &rx, end);
            let (took, counted) = member.join().unwrap();
            assert!(took < Duration::from_secs(3), "{took:?}");
            assert!(counted >= Some(1), "{counted:?}");
        });
    }

    use crate::certs::Cert;
    use std::io::Read;

    #[test]
    fn the_joiner_certificate() {
        let j = Joiner::new("router").unwrap();
        let c = Cert::parse(&j.cert).unwrap();
        assert_eq!(c.common_name.as_deref(), Some(j.id.as_str()));
        assert!(c.p256);
        assert!(c.signed_by(&c));
        assert_eq!(j.fingerprint().len(), 44);
        // rustls and the core's provider take the key and the certificate.
        tls::pair_server(&j.cert, &j.key, &tls::clock()).unwrap();
    }
}
