// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! `cbb next link`: the lite member's network through the Next's ESP8266.
//! It runs at NextPi's shell on the Pi's UART, where the Next's driver
//! exchanges frames with it (frame.rs), and drives the ESP's AT commands
//! (esp.rs) through those frames. A local TCP port stands for the peer: each
//! connection to it becomes a connection of the ESP to the peer, and the
//! member protocol with its TLS runs over it as over any socket, so the ESP
//! and the Z80 see only ciphertext. The Next's clock, which the driver sends
//! at the start, sets the Pi's, which has none of its own. It is the
//! service's paste target `next` too: a remote paste goes to the driver in
//! key frames, which it types into the program in front.

use std::collections::VecDeque;
use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::path::Path;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use super::esp::{self, Esp, Event};
use super::frame::{self, Decoder};
use crate::error::{Context, Error, Result};

pub const USAGE: &str =
    "usage: cbb next link -to host:port [-port port] [-serve esp-port:local-port] [-zone +hh:mm] [-log file] [-trace]";

/// The local port the member dials for the peer.
pub const PORT: u16 = 8769;
/// How long the ESP may take to answer a command.
const ESP_TIMEOUT: Duration = Duration::from_secs(10);
/// How far the Pi's clock may be off before the Next's sets it.
const CLOCK_SLACK: i64 = 2;
/// The characters sent to type each second: the driver types one a frame,
/// 50 a second, and its ring holds 255, so it never fills.
const KEYS_PER_SECOND: usize = 50;

/// One connection of the member, carried by one of the ESP's.
struct Conn {
    stream: TcpStream,
    /// Which use of the slot this is, so a late word of an earlier
    /// connection in the same slot is ignored.
    use_: u64,
    up: bool,
    /// Bytes from the member before the ESP's connection was up.
    pending: Vec<u8>,
}

/// What the threads around Link tell it.
pub enum Msg {
    Uart(Vec<u8>),
    UartClosed,
    Accepted(TcpStream),
    Local(u8, u64, Vec<u8>),
    LocalClosed(u8, u64),
    /// Characters to type, in the Spectrum character set.
    Keys(Vec<u8>),
    Log(String),
}

/// The link without its threads: bytes and connections in, frames out.
pub struct Link<W: Write> {
    out: W,
    dec: Decoder,
    esp: Esp,
    target: (String, u16),
    /// The local port the ESP's own connections lead to.
    serve_to: Option<u16>,
    /// New connections the threads must read from: slot, use and stream.
    pub readers: Vec<(u8, u64, TcpStream)>,
    /// The local time's offset from UTC, in seconds.
    zone: i64,
    /// The driver said hello: frames may go out.
    hello: bool,
    /// Bytes on the wire sent and taken by the driver, as 16-bit counts.
    sent: u16,
    acked: u16,
    wire: VecDeque<u8>,
    conns: Vec<Option<Conn>>,
    gens: u64,
    busy_since: Option<Instant>,
    keys: VecDeque<u8>,
    keys_sent: Option<Instant>,
    /// The time the Next's clock gave, in seconds since 1970, to set.
    pub clock: Option<i64>,
    pub quit: bool,
    /// Logs the bytes to and from the ESP (`-trace`).
    pub trace: bool,
    log: Box<dyn FnMut(&str) + Send>,
}

impl<W: Write> Link<W> {
    pub fn new(out: W, target: (String, u16), zone: i64, log: Box<dyn FnMut(&str) + Send>) -> Link<W> {
        Link {
            out,
            dec: Decoder::new(),
            esp: Esp::new(),
            target,
            serve_to: None,
            readers: Vec::new(),
            zone,
            hello: false,
            sent: 0,
            acked: 0,
            wire: VecDeque::new(),
            conns: (0..esp::LINKS).map(|_| None).collect(),
            gens: 0,
            busy_since: None,
            keys: VecDeque::new(),
            keys_sent: None,
            clock: None,
            trace: false,
            quit: false,
            log,
        }
    }

    /// Has the ESP take connections on esp_port, each led to local_port,
    /// where the member listens: phones that sync with it, and the one
    /// that admits it to the group.
    pub fn serve(&mut self, esp_port: u16, local_port: u16) {
        self.serve_to = Some(local_port);
        self.esp.serve(esp_port);
    }

    /// Hands one word of the threads to the link.
    pub fn handle(&mut self, m: Msg, now: Instant) {
        match m {
            Msg::Uart(b) => self.uart(&b),
            Msg::UartClosed => self.quit = true,
            Msg::Accepted(s) => self.accepted(s),
            Msg::Local(id, use_, data) => {
                if let Some(c) = self.conn(id, use_) {
                    if c.up {
                        self.esp.send(id, &data);
                    } else {
                        c.pending.extend_from_slice(&data);
                    }
                }
            }
            Msg::LocalClosed(id, use_) => {
                if self.conn(id, use_).is_some() {
                    self.conns[id as usize] = None;
                    self.esp.close(id);
                }
            }
            Msg::Keys(k) => self.keys.extend(k),
            Msg::Log(s) => (self.log)(&s),
        }
        self.after(now);
    }

    /// Checks the ESP's time to answer; called now and then.
    pub fn tick(&mut self, now: Instant) {
        self.after(now);
    }

    fn conn(&mut self, id: u8, use_: u64) -> Option<&mut Conn> {
        self.conns.get_mut(id as usize)?.as_mut().filter(|c| c.use_ == use_)
    }

    fn uart(&mut self, bytes: &[u8]) {
        for f in self.dec.push(bytes) {
            match f.kind {
                frame::HELLO => {
                    if !self.hello {
                        (self.log)(&format!("the Next's driver: {}", String::from_utf8_lossy(&f.data)));
                    }
                    self.hello = true;
                }
                frame::ACK if f.data.len() == 2 => self.acked = u16::from_le_bytes([f.data[0], f.data[1]]),
                frame::FROM_ESP => {
                    if self.trace {
                        (self.log)(&format!("esp< {}", f.data.escape_ascii()));
                    }
                    self.esp.input(&f.data)
                }
                frame::TIME => match msdos_time(&f.data) {
                    Some(local) => self.clock = Some(local - self.zone),
                    None => (self.log)("the Next's clock gave no valid time"),
                },
                frame::QUIT => self.quit = true,
                _ => {}
            }
        }
    }

    /// The member dialled the local port. Dialled connections take the
    /// ESP's slots from the top, since the ESP gives its own from 0.
    fn accepted(&mut self, stream: TcpStream) {
        let free = self.conns.iter().rposition(Option::is_none);
        let (Some(id), true) = (free, self.esp.ready()) else {
            (self.log)("no connection of the ESP is free, or the ESP is not ready");
            stream.shutdown(Shutdown::Both).ok();
            return;
        };
        if self.add(id as u8, stream, false) {
            let (host, port) = self.target.clone();
            self.esp.dial_tcp(id as u8, &host, port);
        }
    }

    fn add(&mut self, id: u8, stream: TcpStream, up: bool) -> bool {
        let Ok(reader) = stream.try_clone() else { return false };
        self.gens += 1;
        self.conns[id as usize] = Some(Conn { stream, use_: self.gens, up, pending: Vec::new() });
        self.readers.push((id, self.gens, reader));
        true
    }

    /// A connection the ESP took: it leads to the member's local port.
    fn inbound(&mut self, id: u8) {
        let to = self.serve_to.and_then(|p| TcpStream::connect(("127.0.0.1", p)).ok());
        if !to.is_some_and(|s| self.add(id, s, true)) {
            (self.log)("the member does not listen for the ESP's connection");
            self.esp.close(id);
        }
    }

    /// Hands the ESP's events to the connections and sends what is due.
    fn after(&mut self, now: Instant) {
        if self.esp.busy() {
            let since = *self.busy_since.get_or_insert(now);
            if now.duration_since(since) > ESP_TIMEOUT {
                (self.log)("the ESP did not answer; starting it again");
                self.esp.timeout();
                self.busy_since = None;
            }
        } else {
            self.busy_since = None;
        }
        for ev in self.esp.take_events() {
            match ev {
                Event::Ready => (self.log)("the ESP is ready"),
                Event::Connected(id) if self.conns[id as usize].is_none() => self.inbound(id),
                Event::Connected(id) => {
                    if let Some(c) = self.conns[id as usize].as_mut() {
                        c.up = true;
                        let pending = std::mem::take(&mut c.pending);
                        if !pending.is_empty() {
                            self.esp.send(id, &pending);
                        }
                    }
                }
                Event::Data(id, data) => {
                    let broken = match self.conns[id as usize].as_mut() {
                        Some(c) => c.stream.write_all(&data).is_err(),
                        None => false,
                    };
                    if broken {
                        self.drop_conn(id);
                        self.esp.close(id);
                    }
                }
                Event::Failed(id, why) => {
                    (self.log)(&format!("cannot reach {}:{}: {why}", self.target.0, self.target.1));
                    self.drop_conn(id);
                }
                Event::Closed(id) => self.drop_conn(id),
                Event::Reset => {
                    (self.log)("the ESP restarted");
                    for id in 0..esp::LINKS {
                        self.drop_conn(id);
                    }
                }
                Event::Sent(_) => {}
            }
        }
        let bytes = self.esp.take_output();
        if !bytes.is_empty() {
            if self.trace {
                (self.log)(&format!("esp> {}", bytes.escape_ascii()));
            }
            self.wire.extend(frame::encode(frame::TO_ESP, &bytes));
        }
        let due = self.keys_sent.is_none_or(|t| now.duration_since(t) >= Duration::from_secs(1));
        if self.hello && due && !self.keys.is_empty() {
            let n = self.keys.len().min(KEYS_PER_SECOND);
            let k: Vec<u8> = self.keys.drain(..n).collect();
            self.wire.extend(frame::encode(frame::KEYS, &k));
            self.keys_sent = Some(now);
        }
        self.flush();
    }

    fn drop_conn(&mut self, id: u8) {
        if let Some(c) = self.conns[id as usize].take() {
            c.stream.shutdown(Shutdown::Both).ok();
        }
    }

    /// Sends the waiting bytes that fit in the driver's window.
    fn flush(&mut self) {
        if !self.hello {
            return;
        }
        let ahead = self.sent.wrapping_sub(self.acked) as usize;
        let room = frame::WINDOW.saturating_sub(ahead).min(self.wire.len());
        if room == 0 {
            return;
        }
        let chunk: Vec<u8> = self.wire.drain(..room).collect();
        if self.out.write_all(&chunk).and_then(|()| self.out.flush()).is_err() {
            self.quit = true;
        }
        self.sent = self.sent.wrapping_add(room as u16);
    }

    #[cfg(test)]
    pub fn output(&self) -> &W {
        &self.out
    }
}

/// The Next's clock as NextZXOS gives it to a driver (drv_drvrtc, as
/// M_DATE): the date and the time in MS-DOS's form, each 16 bits
/// little-endian, date first; seconds since 1970 in the clock's own time.
pub fn msdos_time(r: &[u8]) -> Option<i64> {
    if r.len() < 4 {
        return None;
    }
    let date = u16::from_le_bytes([r[0], r[1]]) as i64;
    let time = u16::from_le_bytes([r[2], r[3]]) as i64;
    let (year, month, day) = (1980 + (date >> 9), (date >> 5) & 15, date & 31);
    let (hour, min, sec) = (time >> 11, (time >> 5) & 63, (time & 31) * 2);
    if sec > 59 || min > 59 || hour > 23 || !(1..=31).contains(&day) || !(1..=12).contains(&month) {
        return None;
    }
    Some(days_from_civil(year, month, day) * 86400 + hour * 3600 + min * 60 + sec)
}

/// Days since 1970-01-01 of a date in the proleptic Gregorian calendar.
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

/// `+hh:mm` or `-hh:mm` as seconds.
fn zone(s: &str) -> Result<i64> {
    let bad = || Error::msg("the zone is +hh:mm or -hh:mm");
    let (sign, rest) = match s.as_bytes().first() {
        Some(b'+') => (1, &s[1..]),
        Some(b'-') => (-1, &s[1..]),
        _ => return Err(bad()),
    };
    let (h, m) = rest.split_once(':').ok_or_else(bad)?;
    let (h, m): (i64, i64) = (h.parse().map_err(|_| bad())?, m.parse().map_err(|_| bad())?);
    if h > 14 || m > 59 {
        return Err(bad());
    }
    Ok(sign * (h * 3600 + m * 60))
}

fn host_port(s: &str) -> Result<(String, u16)> {
    let (h, p) = s.rsplit_once(':').ok_or_else(|| Error::msg("the peer is host:port"))?;
    let h = h.trim_start_matches('[').trim_end_matches(']');
    Ok((h.to_string(), p.parse().context("the peer's port is a number")?))
}

/// Sets the system clock when it is off by more than CLOCK_SLACK.
fn set_clock(secs: i64, log: &mut dyn FnMut(&str)) {
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64);
    if now.is_ok_and(|n| (n - secs).abs() <= CLOCK_SLACK) {
        return;
    }
    let ts = libc::timespec { tv_sec: secs as libc::time_t, tv_nsec: 0 };
    // SAFETY: clock_settime only reads the timespec passed to it.
    if unsafe { libc::clock_settime(libc::CLOCK_REALTIME, &ts) } == 0 {
        log(&format!("set the clock from the Next's: {}", crate::node::date(secs)));
    } else {
        log(&format!("cannot set the clock: {}", std::io::Error::last_os_error()));
    }
}

/// The paste target `next`: a remote paste becomes characters to type.
struct NextKeys(mpsc::Sender<Msg>);

impl crate::pastehelper::Target for NextKeys {
    fn name(&self) -> &'static str {
        crate::service::NEXT
    }

    fn inject(
        &self,
        text: &str,
        _method: &str,
        enter: bool,
        _no_lock_check: bool,
    ) -> std::result::Result<(), crate::pastehelper::Fail> {
        // The Next only types: a paste and a typed text are the same here.
        let mut k = crate::next::to_spectrum(text);
        if enter {
            k.push(b'\r');
        }
        if k.is_empty() {
            return crate::pastehelper::refuse("the text is empty");
        }
        self.0.send(Msg::Keys(k)).map_err(|_| crate::pastehelper::Fail::Failed(Error::msg("the link stopped")))
    }
}

/// Runs the link on standard input and output until the driver quits or
/// the UART closes; it takes remote pastes through the service at socket.
pub fn run(socket: &Path, args: &[String]) -> Result<()> {
    let (mut target, mut port, mut zone_s, mut log_path, mut serve) = (None, PORT, 0i64, None::<String>, None);
    let mut trace = false;
    let mut i = 0;
    while i < args.len() {
        if crate::flag(&args[i]) == Some("trace") {
            trace = true;
            i += 1;
            continue;
        }
        let value = || args.get(i + 1).cloned().ok_or_else(|| Error::msg(USAGE));
        match crate::flag(&args[i]) {
            Some("to") => target = Some(host_port(&value()?)?),
            Some("port") => port = value()?.parse().context("the port is a number")?,
            Some("zone") => zone_s = zone(&value()?)?,
            Some("log") => log_path = Some(value()?),
            Some("serve") => {
                let v = value()?;
                let (a, b) = v.split_once(':').ok_or_else(|| Error::msg(USAGE))?;
                serve = Some((
                    a.parse::<u16>().context("the ESP's port is a number")?,
                    b.parse::<u16>().context("the local port is a number")?,
                ));
            }
            _ => return Err(Error::msg(USAGE)),
        }
        i += 2;
    }
    let target = target.ok_or_else(|| Error::msg(USAGE))?;
    // Standard error is the UART too: the log goes to a file or nowhere.
    let mut file = match &log_path {
        Some(p) => Some(std::fs::OpenOptions::new().create(true).append(true).open(p).context("cannot open the log")?),
        None => None,
    };
    let log: Box<dyn FnMut(&str) + Send> = Box::new(move |s: &str| {
        if let Some(f) = file.as_mut() {
            writeln!(f, "{s}").ok();
        }
    });
    let listener = TcpListener::bind(("127.0.0.1", port)).context(format!("cannot listen on 127.0.0.1:{port}"))?;
    let _raw = crate::next::RawTerminal::new(1, true);
    let (tx, rx) = mpsc::channel::<Msg>();
    {
        let tx = tx.clone();
        std::thread::spawn(move || {
            let mut stdin = std::io::stdin();
            let tty = std::io::IsTerminal::is_terminal(&stdin);
            let mut buf = [0u8; 512];
            loop {
                match stdin.read(&mut buf) {
                    Ok(0) if tty => continue, // the read's timeout
                    Ok(0) | Err(_) => {
                        tx.send(Msg::UartClosed).ok();
                        return;
                    }
                    Ok(n) => {
                        if tx.send(Msg::Uart(buf[..n].to_vec())).is_err() {
                            return;
                        }
                    }
                }
            }
        });
    }
    {
        let tx = tx.clone();
        std::thread::spawn(move || {
            for s in listener.incoming().flatten() {
                if tx.send(Msg::Accepted(s)).is_err() {
                    return;
                }
            }
        });
    }
    {
        let (tx, socket) = (tx.clone(), socket.to_path_buf());
        std::thread::spawn(move || {
            let keys = NextKeys(tx.clone());
            crate::pastehelper::serve(&socket, &keys, &|s: &str| {
                tx.send(Msg::Log(s.to_string())).ok();
            })
        });
    }
    let mut link = Link::new(std::io::stdout(), target, zone_s, log);
    link.trace = trace;
    if let Some((a, b)) = serve {
        link.serve(a, b);
    }
    while !link.quit {
        let now = Instant::now();
        match rx.recv_timeout(Duration::from_millis(200)) {
            Ok(m) => link.handle(m, now),
            Err(mpsc::RecvTimeoutError::Timeout) => link.tick(now),
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
        if let Some(secs) = link.clock.take() {
            set_clock(secs, &mut *link.log);
        }
        for (id, use_, mut s) in std::mem::take(&mut link.readers) {
            let tx = tx.clone();
            std::thread::spawn(move || {
                let mut buf = [0u8; 2048];
                loop {
                    match s.read(&mut buf) {
                        Ok(0) | Err(_) => {
                            tx.send(Msg::LocalClosed(id, use_)).ok();
                            return;
                        }
                        Ok(n) => {
                            if tx.send(Msg::Local(id, use_, buf[..n].to_vec())).is_err() {
                                return;
                            }
                        }
                    }
                }
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nextlink::frame::{Frame, encode};

    /// The driver's side of the wire, with the ESP behind it.
    struct Next {
        dec: Decoder,
        taken: u16,
    }

    impl Next {
        /// The bytes the link sent, as the ESP gets them, and the ACK back.
        fn esp_bytes(&mut self, wire: &[u8]) -> (Vec<u8>, Vec<u8>) {
            self.taken = self.taken.wrapping_add(wire.len() as u16);
            let mut esp = Vec::new();
            for Frame { kind, data } in self.dec.push(wire) {
                assert_eq!(kind, frame::TO_ESP);
                esp.extend(data);
            }
            (esp, encode(frame::ACK, &self.taken.to_le_bytes()))
        }
    }

    fn new_link() -> (Link<Vec<u8>>, Next, Instant) {
        let link = Link::new(Vec::new(), ("192.168.0.10".into(), 8763), 3600, Box::new(|_| {}));
        (link, Next { dec: Decoder::new(), taken: 0 }, Instant::now())
    }

    /// Takes what the link wrote since `at`, as the ESP's bytes.
    fn sent(link: &Link<Vec<u8>>, next: &mut Next, at: &mut usize) -> (String, Vec<u8>) {
        let wire = link.output()[*at..].to_vec();
        *at = link.output().len();
        let (esp, ack) = next.esp_bytes(&wire);
        (String::from_utf8_lossy(&esp).into_owned(), ack)
    }

    fn from_esp(b: &[u8]) -> Msg {
        Msg::Uart(encode(frame::FROM_ESP, b))
    }

    #[test]
    fn a_connection_through_the_esp() {
        let (mut link, mut next, now) = new_link();
        let mut at = 0;
        // Nothing goes out before the driver's hello.
        link.handle(Msg::Uart(Vec::new()), now);
        assert!(link.output().is_empty());
        link.handle(Msg::Uart(encode(frame::HELLO, b"cbb.drv 0.1")), now);
        for (cmd, answer) in
            [("AT\r\n", &b"\r\nOK\r\n"[..]), ("ATE0\r\n", b"\r\nOK\r\n"), ("AT+CIPMUX=1\r\n", b"\r\nOK\r\n")]
        {
            let (esp, ack) = sent(&link, &mut next, &mut at);
            assert_eq!(esp, cmd);
            link.handle(Msg::Uart(ack), now);
            link.handle(from_esp(answer), now);
        }
        // The member dials the local port.
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let member = TcpStream::connect(l.local_addr().unwrap()).unwrap();
        let (ours, _) = l.accept().unwrap();
        link.handle(Msg::Accepted(ours), now);
        let (id, use_, _reader) = link.readers.pop().expect("taken");
        assert_eq!(id, 4);
        let (esp, ack) = sent(&link, &mut next, &mut at);
        assert_eq!(esp, "AT+CIPSTART=4,\"TCP\",\"192.168.0.10\",8763\r\n");
        link.handle(Msg::Uart(ack), now);
        // Bytes before the ESP's connection is up wait for it.
        link.handle(Msg::Local(id, use_, b"hello".to_vec()), now);
        link.handle(from_esp(b"4,CONNECT\r\n\r\nOK\r\n"), now);
        let (esp, ack) = sent(&link, &mut next, &mut at);
        assert_eq!(esp, "AT+CIPSEND=4,5\r\n");
        link.handle(Msg::Uart(ack), now);
        link.handle(from_esp(b"\r\nOK\r\n> "), now);
        let (esp, ack) = sent(&link, &mut next, &mut at);
        assert_eq!(esp, "hello");
        link.handle(Msg::Uart(ack), now);
        link.handle(from_esp(b"\r\nSEND OK\r\n+IPD,4,6:world!"), now);
        let mut got = [0u8; 6];
        let mut m = member.try_clone().unwrap();
        m.read_exact(&mut got).unwrap();
        assert_eq!(&got, b"world!");
        // The peer closes: so does the member's connection.
        link.handle(from_esp(b"4,CLOSED\r\n"), now);
        assert_eq!(m.read(&mut got).unwrap(), 0);
        // A late word of that connection changes nothing.
        link.handle(Msg::LocalClosed(id, use_), now);
        assert!(sent(&link, &mut next, &mut at).0.is_empty());
    }

    /// A connection the ESP took leads to the member's local port.
    #[test]
    fn inbound() {
        let (mut link, mut next, now) = new_link();
        let mut at = 0;
        let member = TcpListener::bind("127.0.0.1:0").unwrap();
        link.serve(8763, member.local_addr().unwrap().port());
        link.handle(Msg::Uart(encode(frame::HELLO, b"")), now);
        for cmd in ["AT\r\n", "ATE0\r\n", "AT+CIPMUX=1\r\n", "AT+CIPSERVER=1,8763\r\n", "AT+CIPSTO=0\r\n"] {
            let (esp, ack) = sent(&link, &mut next, &mut at);
            assert_eq!(esp, cmd);
            link.handle(Msg::Uart(ack), now);
            link.handle(from_esp(b"\r\nOK\r\n"), now);
        }
        link.handle(from_esp(b"0,CONNECT\r\n\r\n+IPD,0,5:phone"), now);
        let (mut s, _) = member.accept().unwrap();
        let mut got = [0u8; 5];
        s.read_exact(&mut got).unwrap();
        assert_eq!(&got, b"phone");
        let (id, use_, _) = link.readers.pop().unwrap();
        assert_eq!(id, 0);
        link.handle(Msg::Local(id, use_, b"lite".to_vec()), now);
        assert_eq!(sent(&link, &mut next, &mut at).0, "AT+CIPSEND=0,4\r\n");
    }

    /// The link sends no more than the window before the driver's ACK.
    #[test]
    fn window() {
        let (mut link, _, now) = new_link();
        link.handle(Msg::Uart(encode(frame::HELLO, b"")), now);
        link.wire.extend(vec![0u8; 1000]);
        link.tick(now);
        assert_eq!(link.output().len(), frame::WINDOW);
        link.tick(now);
        assert_eq!(link.output().len(), frame::WINDOW);
        link.handle(Msg::Uart(encode(frame::ACK, &100u16.to_le_bytes())), now);
        assert_eq!(link.output().len(), frame::WINDOW + 100);
    }

    /// Keys go 50 a second, whatever the driver's window allows.
    #[test]
    fn keys_paced() {
        let (mut link, mut next, now) = new_link();
        link.handle(Msg::Uart(encode(frame::HELLO, b"")), now);
        let mut at = 0;
        sent(&link, &mut next, &mut at); // AT
        link.handle(Msg::Keys(vec![b'x'; 120]), now);
        let keys = |link: &Link<Vec<u8>>, at: &mut usize| {
            let wire = link.output()[*at..].to_vec();
            *at = link.output().len();
            Decoder::new()
                .push(&wire)
                .into_iter()
                .filter(|f| f.kind == frame::KEYS)
                .map(|f| f.data.len())
                .sum::<usize>()
        };
        assert_eq!(keys(&link, &mut at), 50);
        link.tick(now + Duration::from_millis(500));
        assert_eq!(keys(&link, &mut at), 0);
        link.tick(now + Duration::from_secs(1));
        assert_eq!(keys(&link, &mut at), 50);
        link.tick(now + Duration::from_secs(2));
        assert_eq!(keys(&link, &mut at), 20);
    }

    #[test]
    fn esp_silent() {
        let (mut link, mut next, now) = new_link();
        link.handle(Msg::Uart(encode(frame::HELLO, b"")), now);
        let mut at = 0;
        assert_eq!(sent(&link, &mut next, &mut at).0, "AT\r\n");
        link.tick(now + ESP_TIMEOUT + Duration::from_secs(1));
        link.tick(now + ESP_TIMEOUT + Duration::from_secs(1));
        assert_eq!(sent(&link, &mut next, &mut at).0, "AT\r\n");
    }

    #[test]
    fn clock() {
        // 2026-11-02 01:30:14 local, an hour ahead of UTC.
        let date: u16 = (46 << 9) | (11 << 5) | 2;
        let time: u16 = (1 << 11) | (30 << 5) | 7;
        let (mut link, _, now) = new_link();
        link.handle(Msg::Uart(encode(frame::TIME, &[date.to_le_bytes(), time.to_le_bytes()].concat())), now);
        assert_eq!(link.clock, Some(1_793_583_014 - 3600));
        assert_eq!(msdos_time(&[0x21, 0, 0, 0]), Some(315_532_800)); // 1980-01-01
        assert_eq!(msdos_time(&[0x20, 0, 0, 0]), None); // day 0
        assert_eq!(msdos_time(&[0x21, 0, 0, 0xC0]), None); // hour 24
    }

    #[test]
    fn flags() {
        assert_eq!(zone("+01:00").unwrap(), 3600);
        assert_eq!(zone("-05:30").unwrap(), -19800);
        assert!(zone("01:00").is_err());
        assert_eq!(host_port("[fe80::1]:8763").unwrap(), ("fe80::1".into(), 8763));
        assert!(host_port("host").is_err());
    }
}
