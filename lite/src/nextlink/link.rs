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
//! key frames, which it types into the program in front. NextPi starts
//! nothing of ours at boot, so the link starts the service when none runs,
//! pointed at its own ports. While it runs, `.cbb paste`, `copy` and
//! `text` come through the driver's frames too (frame::CBB_OUT): the link
//! runs their `cbb next` as NextPi's shell would, and sends back what it
//! writes (frame::CBB_IN).

use std::collections::VecDeque;
use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::path::Path;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use super::esp::{self, Esp, Event};
use super::frame::{self, Decoder};
use crate::error::{Context, Error, Result};

pub const USAGE: &str = "usage: cbb next link -to host:port [-port port] [-serve esp-port:local-port] [-udp local-port:host:port] [-zone +hh:mm] [-join code] [-paste on|on-enter|off] [-log file] [-trace]";

/// The line the link writes once the UART is raw, which `.cbb net on`
/// waits for before it turns the driver on.
pub const READY: &[u8] = b"CBBLINK\r\n";

/// The local port the member dials for the peer.
pub const PORT: u16 = 8769;
/// How long the ESP may take to answer a command.
const ESP_TIMEOUT: Duration = Duration::from_secs(10);
/// How long it may take to answer a dial: it tries a host that does not
/// answer for several seconds before it gives up.
const DIAL_TIMEOUT: Duration = Duration::from_secs(30);
/// The waits after a failed dial of -to before the next, doubling: while
/// the ESP dials it does nothing else, so a peer it cannot reach (away from
/// home) would hold back the tunnel's datagrams.
const DIAL_BACKOFF: (Duration, Duration) = (Duration::from_secs(5), Duration::from_secs(60));
/// The longest of those waits while the tunnel's hub answers: the member is
/// away from home, where -to is not reached, and each dial would silence
/// the tunnel's member connection for as long as the ESP tries, which on
/// a link this slow its peers count as a broken connection.
const DIAL_BACKOFF_AWAY: Duration = Duration::from_secs(600);
/// How recent an answer from the tunnel's hub counts as away from home.
const AWAY_ANSWER: Duration = Duration::from_secs(120);
/// How long the link waits for the Next's clock before it starts the
/// service without it.
const SERVICE_WAIT: Duration = Duration::from_secs(10);
/// How often the link checks that the service runs, after it started it.
const SERVICE_CHECK: Duration = Duration::from_secs(20);
/// How far the Pi's clock may be off before the Next's sets it.
const CLOCK_SLACK: i64 = 2;
/// The ESP's connection that carries the datagrams of `-udp`: the last, as
/// the ESP gives its own connections from 0 and the dialled TCP ones take
/// the slots below it.
const UDP_ID: u8 = esp::LINKS - 1;
/// The datagrams kept while the ESP's UDP connection opens; older ones are
/// dropped, as UDP may.
const UDP_QUEUE: usize = 8;

/// The prompt that ends each command for `.cbb`, as NextPi's shell writes it.
const PROMPT: &[u8] = b"\r\nSUP>";
/// The longest command line `.cbb` types.
const LINE_MAX: usize = 256;

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

/// A local UDP port that leads, through one UDP connection of the ESP, to
/// a fixed peer: the hub, or the forwarder, for the tunnel of sync away
/// from home (`cbb service -tunnel-via`).
pub struct Udp {
    sock: UdpSocket,
    target: (String, u16),
    /// The ESP's own port for the connection.
    esp_port: u16,
    /// Where the last datagram came from, which the answers go to.
    peer: Option<SocketAddr>,
    /// When the hub last answered through the ESP.
    answered: Option<Instant>,
    state: UdpState,
    queue: VecDeque<Vec<u8>>,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum UdpState {
    Down,
    Dialing,
    Up,
}

impl Udp {
    pub fn new(sock: UdpSocket, target: (String, u16), esp_port: u16) -> Udp {
        Udp { sock, target, esp_port, peer: None, answered: None, state: UdpState::Down, queue: VecDeque::new() }
    }
}

/// What the threads around Link tell it.
pub enum Msg {
    Uart(Vec<u8>),
    UartClosed,
    Accepted(TcpStream),
    /// A datagram to the local UDP port, and where it came from.
    Datagram(SocketAddr, Vec<u8>),
    Local(u8, u64, Vec<u8>),
    LocalClosed(u8, u64),
    /// Characters to type, in the Spectrum character set.
    Keys(Vec<u8>),
    Log(String),
    /// What the command `.cbb` runs wrote, and its end.
    CommandOut(Vec<u8>),
    CommandEnded,
}

/// The link without its threads: bytes and connections in, frames out.
pub struct Link<W: Write> {
    out: W,
    dec: Decoder,
    esp: Esp,
    target: (String, u16),
    /// The local port the ESP's own connections lead to.
    serve_to: Option<u16>,
    udp: Option<Udp>,
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
    /// No dial of -to before this, after a failed one, and the last wait.
    dial_after: Option<Instant>,
    dial_wait: Duration,
    /// The ESP's answers when busy_since was set.
    answers: u64,
    keys: VecDeque<u8>,
    keys_sent: Option<Instant>,
    /// The time the Next's clock gave, in seconds since 1970, to set.
    pub clock: Option<i64>,
    pub quit: bool,
    /// The command line `.cbb` types, until its end.
    line: Vec<u8>,
    /// A command of `.cbb`'s runs, and whether it was stopped, so that
    /// nothing more of it goes to the Next.
    command: bool,
    stopped: bool,
    /// For run(): the arguments of a command to start, its input, and
    /// whether to stop it.
    pub start: Option<Vec<String>>,
    pub input: Vec<u8>,
    pub stop: bool,
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
            udp: None,
            readers: Vec::new(),
            zone,
            hello: false,
            sent: 0,
            acked: 0,
            wire: VecDeque::new(),
            conns: (0..esp::LINKS).map(|_| None).collect(),
            gens: 0,
            busy_since: None,
            dial_after: None,
            dial_wait: Duration::ZERO,
            answers: 0,
            keys: VecDeque::new(),
            keys_sent: None,
            clock: None,
            trace: false,
            quit: false,
            line: Vec::new(),
            command: false,
            stopped: false,
            start: None,
            input: Vec::new(),
            stop: false,
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

    /// Carries the datagrams of a local UDP port through the ESP.
    pub fn udp(&mut self, u: Udp) {
        self.udp = Some(u);
    }

    /// Hands one word of the threads to the link.
    pub fn handle(&mut self, m: Msg, now: Instant) {
        match m {
            Msg::Uart(b) => self.uart(&b),
            Msg::UartClosed => self.quit = true,
            Msg::Accepted(s) => self.accepted(s, now),
            Msg::Datagram(from, data) => self.datagram(from, data),
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
            Msg::CommandOut(b) => {
                if !self.stopped {
                    self.answer_cbb(&b);
                }
            }
            Msg::CommandEnded => {
                self.command = false;
                self.input.clear();
                if !std::mem::take(&mut self.stopped) {
                    self.answer_cbb(PROMPT);
                }
            }
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
                frame::CBB_OUT => self.cbb_bytes(&f.data),
                _ => {}
            }
        }
    }

    /// `.cbb`'s bytes: a command line while none runs, else its input; an
    /// empty frame stops it.
    fn cbb_bytes(&mut self, data: &[u8]) {
        if data.is_empty() {
            self.line.clear();
            if self.command {
                self.stop = true;
                self.stopped = true;
            }
            return;
        }
        for (i, &b) in data.iter().enumerate() {
            if self.command {
                self.input.extend_from_slice(&data[i..]);
                return;
            }
            if b != b'\n' && b != b'\r' {
                if self.line.len() < LINE_MAX {
                    self.line.push(b);
                }
                continue;
            }
            let line = String::from_utf8_lossy(&std::mem::take(&mut self.line)).into_owned();
            if line.trim().is_empty() {
                continue;
            }
            match command_args(&line) {
                Some(args) => {
                    (self.log)(&format!("runs cbb {}", args.join(" ")));
                    self.start = Some(args);
                    self.command = true;
                }
                None => {
                    self.answer_cbb(b"CBBERR the network runs only cbb next paste and copy\r");
                    self.answer_cbb(PROMPT);
                }
            }
        }
    }

    fn answer_cbb(&mut self, b: &[u8]) {
        self.wire.extend(frame::encode(frame::CBB_IN, b));
    }

    /// The member dialled the local port. Dialled connections take the
    /// ESP's slots from the top, since the ESP gives its own from 0.
    fn accepted(&mut self, stream: TcpStream, now: Instant) {
        if self.dial_after.is_some_and(|t| now < t) {
            // The member tries again later; the ESP stays free meanwhile.
            stream.shutdown(Shutdown::Both).ok();
            return;
        }
        let top = if self.udp.is_some() { UDP_ID as usize } else { self.conns.len() };
        let free = self.conns[..top].iter().rposition(Option::is_none);
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

    /// A datagram to the local UDP port goes out on the ESP's UDP
    /// connection, which opens first when it is not up.
    fn datagram(&mut self, from: SocketAddr, data: Vec<u8>) {
        let ready = self.esp.ready();
        let Some(u) = self.udp.as_mut() else { return };
        u.peer = Some(from);
        if u.state == UdpState::Up {
            self.esp.send_datagram(UDP_ID, &data);
            return;
        }
        if u.queue.len() == UDP_QUEUE {
            u.queue.pop_front();
        }
        u.queue.push_back(data);
        if u.state == UdpState::Down && ready && self.conns[UDP_ID as usize].is_none() {
            u.state = UdpState::Dialing;
            let ((host, port), local) = (u.target.clone(), u.esp_port);
            self.esp.dial_udp(UDP_ID, &host, port, local);
        }
    }

    /// Handles an event of the ESP's UDP connection; false when the event
    /// is not one.
    fn udp_event(&mut self, ev: &Event, now: Instant) -> bool {
        let Some(u) = self.udp.as_mut() else { return false };
        match ev {
            Event::Connected(UDP_ID) if u.state == UdpState::Dialing => {
                u.state = UdpState::Up;
                for d in std::mem::take(&mut u.queue) {
                    self.esp.send_datagram(UDP_ID, &d);
                }
            }
            Event::Data(UDP_ID, d) if u.state == UdpState::Up => {
                u.answered = Some(now);
                if let Some(p) = u.peer {
                    u.sock.send_to(d, p).ok();
                }
            }
            Event::Failed(UDP_ID, why) if u.state != UdpState::Down => {
                u.state = UdpState::Down;
                u.queue.clear();
                let (host, port) = u.target.clone();
                (self.log)(&format!("cannot reach {host}:{port} over UDP: {why}"));
            }
            Event::Closed(UDP_ID) if u.state != UdpState::Down => u.state = UdpState::Down,
            Event::Reset => {
                u.state = UdpState::Down;
                return false;
            }
            _ => return false,
        }
        true
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
        if self.esp.answers() != self.answers {
            // An answer came: the wait for the next one starts now.
            self.answers = self.esp.answers();
            self.busy_since = None;
        }
        if self.esp.busy() {
            let since = *self.busy_since.get_or_insert(now);
            let limit = if self.esp.dialing() { DIAL_TIMEOUT } else { ESP_TIMEOUT };
            if now.duration_since(since) > limit {
                (self.log)("the ESP did not answer; starting it again");
                self.esp.timeout();
                self.busy_since = None;
            }
        } else {
            self.busy_since = None;
        }
        for ev in self.esp.take_events() {
            if self.udp_event(&ev, now) {
                continue;
            }
            match ev {
                Event::Ready => (self.log)("the ESP is ready"),
                Event::Connected(id) if self.conns[id as usize].is_none() => self.inbound(id),
                Event::Connected(id) => {
                    if let Some(c) = self.conns[id as usize].as_mut() {
                        self.dial_wait = Duration::ZERO;
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
                    if self.conns[id as usize].as_ref().is_some_and(|c| !c.up) {
                        // A dial of -to.
                        let away = self
                            .udp
                            .as_ref()
                            .and_then(|u| u.answered)
                            .is_some_and(|t| now.duration_since(t) < AWAY_ANSWER);
                        self.dial_wait = next_dial_wait(self.dial_wait, away);
                        self.dial_after = Some(now + self.dial_wait);
                        (self.log)(&format!(
                            "cannot reach {}:{}: {why}; trying again in {}s",
                            self.target.0,
                            self.target.1,
                            self.dial_wait.as_secs()
                        ));
                    } else {
                        (self.log)(&format!("the ESP's connection {id} broke off: {why}"));
                    }
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
        // An ack past what was sent counts a byte that was not a frame's
        // (a stray LF the driver took): nothing is waiting then.
        let ahead = (self.sent.wrapping_sub(self.acked) as i16).max(0) as usize;
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

    /// Whether a command of `.cbb`'s runs.
    pub fn running(&self) -> bool {
        self.command
    }

    #[cfg(test)]
    pub fn output(&self) -> &W {
        &self.out
    }
}

/// The arguments for this program of a command line `.cbb` types: `cbb
/// [-debug] next paste|copy ...`, and nothing else.
fn command_args(line: &str) -> Option<Vec<String>> {
    let words: Vec<&str> = line.split_whitespace().collect();
    let (&first, mut rest) = words.split_first()?;
    if first != "cbb" {
        return None;
    }
    let mut args = Vec::new();
    if rest.first() == Some(&"-debug") {
        args.push("-debug".to_string());
        rest = &rest[1..];
    }
    match rest {
        ["next", "paste" | "copy", ..] => {
            args.extend(rest.iter().map(|w| w.to_string()));
            Some(args)
        }
        _ => None,
    }
}

/// Starts a command of `.cbb`'s: this program with the link's state, its
/// output to the link as it comes, its end after.
fn start_command(
    g: &crate::Global,
    args: &[String],
    tx: &mpsc::Sender<Msg>,
) -> Result<(std::process::ChildStdin, u32)> {
    let mut cmd = std::process::Command::new(std::env::current_exe().context("cannot find this program")?);
    cmd.arg("-state").arg(&g.state).arg("-socket").arg(&g.socket).args(args);
    cmd.stdin(std::process::Stdio::piped()).stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::null());
    let mut child = cmd.spawn().context("cannot run cbb next")?;
    let (Some(stdin), Some(mut stdout)) = (child.stdin.take(), child.stdout.take()) else {
        return Err(Error::msg("cannot reach cbb next"));
    };
    let pid = child.id();
    let tx = tx.clone();
    std::thread::spawn(move || {
        let mut buf = [0u8; 512];
        loop {
            match stdout.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if tx.send(Msg::CommandOut(buf[..n].to_vec())).is_err() {
                        break;
                    }
                }
            }
        }
        child.wait().ok();
        tx.send(Msg::CommandEnded).ok();
    });
    Ok((stdin, pid))
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
    // A phone (the lite library inside its app) never sets the clock.
    #[cfg(target_os = "ios")]
    let set = {
        let _ = secs;
        false
    };
    #[cfg(not(target_os = "ios"))]
    let set = {
        let ts = libc::timespec { tv_sec: secs as libc::time_t, tv_nsec: 0 };
        // SAFETY: clock_settime only reads the timespec passed to it.
        unsafe { libc::clock_settime(libc::CLOCK_REALTIME, &ts) == 0 }
    };
    if set {
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
pub fn run(g: &crate::Global, args: &[String]) -> Result<()> {
    let socket: &Path = &g.socket;
    let (mut target, mut port, mut zone_s, mut log_path, mut serve) = (None, PORT, 0i64, None::<String>, None);
    let mut trace = false;
    let mut udp = None;
    let mut join = None;
    let mut paste = None;
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
            Some("join") => join = Some(value()?),
            Some("paste") => {
                paste = Some(match value()?.as_str() {
                    "on" => (true, false),
                    "on-enter" => (true, true),
                    "off" => (false, false),
                    _ => return Err(Error::msg(USAGE)),
                })
            }
            Some("udp") => {
                let v = value()?;
                let (a, rest) = v.split_once(':').ok_or_else(|| Error::msg(USAGE))?;
                udp = Some((a.parse::<u16>().context("the local UDP port is a number")?, host_port(rest)?));
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
    let udp = match udp {
        Some((p, target)) => {
            let s = UdpSocket::bind(("127.0.0.1", p)).context(format!("cannot open UDP port 127.0.0.1:{p}"))?;
            Some((s, target, p))
        }
        None => None,
    };
    let udp_port = udp.as_ref().map(|u| u.2);
    let _raw = crate::next::RawTerminal::new(1, true);
    // Tells .cbb net on that the link runs and the UART is raw, so it may
    // turn the driver on: before that the shell's echo and its flow control
    // would take the driver's frames.
    {
        let mut out = std::io::stdout();
        out.write_all(READY).ok();
        out.flush().ok();
    }
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
    if let Some((s, target, p)) = udp {
        let (tx, reader) = (tx.clone(), s.try_clone().context("cannot open the UDP port")?);
        std::thread::spawn(move || {
            let mut buf = [0u8; 2048];
            while let Ok((n, from)) = reader.recv_from(&mut buf) {
                if tx.send(Msg::Datagram(from, buf[..n].to_vec())).is_err() {
                    return;
                }
            }
        });
        link.udp(Udp::new(s, target, p));
    }
    if let Some((a, b)) = serve {
        link.serve(a, b);
    }
    // The service starts once the Pi's clock is right, for its
    // certificates' dates, or after SERVICE_WAIT without the Next's; with
    // -join, once this member is in the group: it joins with the code from
    // cbb pair on the full member at -to, through a connection to the
    // link's own port, which the ESP carries there.
    let mut service_at = join.is_none().then(|| Instant::now() + SERVICE_WAIT);
    let mut join_at = join.as_ref().map(|_| Instant::now() + SERVICE_WAIT);
    let (joined_tx, joined) = mpsc::channel::<bool>();
    let mut command: Option<(std::process::ChildStdin, u32)> = None;
    while !link.quit {
        let now = Instant::now();
        if joined.try_recv() == Ok(true) {
            service_at = Some(now);
        }
        match rx.recv_timeout(Duration::from_millis(200)) {
            Ok(m) => link.handle(m, now),
            Err(mpsc::RecvTimeoutError::Timeout) => link.tick(now),
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
        if let Some(args) = link.start.take() {
            match start_command(g, &args, &tx) {
                Ok(c) => command = Some(c),
                Err(e) => {
                    let line = format!("CBBERR {}\r", e.for_user());
                    link.handle(Msg::CommandOut(line.into_bytes()), now);
                    link.handle(Msg::CommandEnded, now);
                }
            }
        }
        if !link.input.is_empty() {
            let input = std::mem::take(&mut link.input);
            if let Some((stdin, _)) = command.as_mut() {
                stdin.write_all(&input).ok();
            }
        }
        if std::mem::take(&mut link.stop)
            && let Some((_, pid)) = command.take()
        {
            // SAFETY: kill only sends a signal to the command's process.
            unsafe { libc::kill(pid as libc::pid_t, libc::SIGTERM) };
        }
        if !link.running() {
            command = None;
        }
        let clock = link.clock.take();
        if let Some(secs) = clock {
            set_clock(secs, &mut *link.log);
        }
        // The join checks certificates' dates too, so it waits as the
        // service does.
        if join_at.is_some_and(|at| clock.is_some() || now >= at) {
            join_at = None;
            let (g, log, done, code) = (g.clone(), tx.clone(), joined_tx.clone(), join.clone().unwrap_or_default());
            std::thread::spawn(move || {
                let res = TcpStream::connect(("127.0.0.1", port))
                    .context("cannot reach the link's port")
                    .and_then(|s| crate::join_with_code(&g, s, &code));
                let line = match &res {
                    Ok(id) => format!("joined the group {} as {}", id.tag(), id.id),
                    Err(e) => format!("cannot join: {}", e.for_user()),
                };
                log.send(Msg::Log(line)).ok();
                done.send(res.is_ok()).ok();
            });
        }
        if service_at.is_some_and(|at| clock.is_some() || now >= at) {
            // And again a while later: a service that stopped (.cbb pair
            // stops it while cbb next pair waits on its port) starts again.
            service_at = Some(now + SERVICE_CHECK);
            match start_service(g, port, udp_port, log_path.as_deref()) {
                Ok(true) => (link.log)("started the service"),
                Ok(false) => {}
                Err(e) => (link.log)(&format!("cannot start the service: {}", e.for_user())),
            }
            if let Some((on, enter)) = paste.take() {
                let (g, log) = (g.clone(), tx.clone());
                std::thread::spawn(move || set_paste(&g, on, enter, &log));
            }
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

/// Tells the service whether the group's admins may paste on the Next, as
/// .cbb paste-receive set it (-paste): the Next's user is the Pi's, so
/// the switch is theirs. The service may still be starting: it is asked
/// again for a minute.
fn set_paste(g: &crate::Global, on: bool, enter: bool, log: &mpsc::Sender<Msg>) {
    let h = crate::control::Header {
        op: "paste-receive".into(),
        name: if on { "on" } else { "off" }.into(),
        enter,
        ..Default::default()
    };
    let mut last = String::new();
    for _ in 0..30 {
        std::thread::sleep(Duration::from_secs(2));
        match crate::request(g, &crate::control::Message::new(h.clone(), Vec::new())) {
            Ok(_) => {
                log.send(Msg::Log(format!("remote paste is {} here (enter {enter})", h.name))).ok();
                return;
            }
            Err(e) => last = e.for_user(),
        }
    }
    log.send(Msg::Log(format!("cannot set remote paste: {last}"))).ok();
}

/// The wait after a failed dial of -to that follows wait; away is whether
/// the tunnel's hub answered lately.
fn next_dial_wait(wait: Duration, away: bool) -> Duration {
    (wait * 2).clamp(DIAL_BACKOFF.0, if away { DIAL_BACKOFF_AWAY } else { DIAL_BACKOFF.1 })
}

/// Starts `cbb service` when none answers at the control socket, dialling
/// the link's port for the peer and, with `-udp`, its tunnel through the
/// link's UDP port; it outlives the link, and logs where the link does.
/// Tells whether it started one.
fn start_service(g: &crate::Global, port: u16, udp: Option<u16>, log: Option<&str>) -> Result<bool> {
    if std::os::unix::net::UnixStream::connect(&g.socket).is_ok() {
        return Ok(false);
    }
    let mut cmd = std::process::Command::new(std::env::current_exe().context("cannot find this program")?);
    cmd.arg("-state").arg(&g.state).arg("-socket").arg(&g.socket);
    cmd.args(service_args(port, udp));
    let out = match log {
        Some(p) => std::process::Stdio::from(
            std::fs::OpenOptions::new().create(true).append(true).open(p).context("cannot open the log")?,
        ),
        None => std::process::Stdio::null(),
    };
    cmd.stdin(std::process::Stdio::null()).stdout(std::process::Stdio::null()).stderr(out);
    // Its own process group, so the end of the link and its shell's
    // signals leave it running.
    std::os::unix::process::CommandExt::process_group(&mut cmd, 0);
    cmd.spawn().context("cannot run cbb service")?;
    Ok(true)
}

/// The arguments of the service the link starts.
fn service_args(port: u16, udp: Option<u16>) -> Vec<String> {
    let mut a = vec!["service".to_string(), "-peer".into(), format!("127.0.0.1:{port}")];
    if let Some(u) = udp {
        a.extend(["-tunnel-via".into(), format!("127.0.0.1:{u}")]);
    }
    a
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nextlink::frame::{Frame, encode};

    #[test]
    fn away_the_home_peer_is_dialled_rarely() {
        let mut w = Duration::ZERO;
        let mut home = Vec::new();
        for _ in 0..6 {
            w = next_dial_wait(w, false);
            home.push(w.as_secs());
        }
        assert_eq!(home, [5, 10, 20, 40, 60, 60]);
        for _ in 0..6 {
            w = next_dial_wait(w, true);
        }
        assert_eq!(w, DIAL_BACKOFF_AWAY);
        // Back home the wait comes down to the home one.
        assert_eq!(next_dial_wait(w, false), DIAL_BACKOFF.1);
    }

    #[test]
    fn the_service_dials_the_links_ports() {
        assert_eq!(service_args(8769, None), ["service", "-peer", "127.0.0.1:8769"]);
        assert_eq!(
            service_args(8769, Some(8770)),
            ["service", "-peer", "127.0.0.1:8769", "-tunnel-via", "127.0.0.1:8770"]
        );
    }

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

    /// The frames for `.cbb` the link wrote since `at`.
    fn to_cbb(link: &Link<Vec<u8>>, at: &mut usize) -> Vec<u8> {
        let wire = link.output()[*at..].to_vec();
        *at = link.output().len();
        Decoder::new().push(&wire).into_iter().filter(|f| f.kind == frame::CBB_IN).flat_map(|f| f.data).collect()
    }

    /// `.cbb paste` while the network runs: the link starts `cbb next
    /// paste` as the shell would, and its output and the prompt go back.
    #[test]
    fn runs_cbbs_commands() {
        let (mut link, _, now) = new_link();
        let mut at = 0;
        link.handle(Msg::Uart(encode(frame::HELLO, b"cbb.drv 0.2")), now);
        to_cbb(&link, &mut at);
        link.handle(Msg::Uart(encode(frame::CBB_OUT, b"cbb -debug next paste -max 8192\n")), now);
        assert_eq!(
            link.start.take(),
            Some(vec!["-debug".into(), "next".into(), "paste".into(), "-max".into(), "8192".into()])
        );
        assert!(link.running());
        link.handle(Msg::CommandOut(b"CBB1 2 0\rhi\rCBBOK\r".to_vec()), now);
        link.handle(Msg::CommandEnded, now);
        assert_eq!(to_cbb(&link, &mut at), b"CBB1 2 0\rhi\rCBBOK\r\r\nSUP>");
        assert!(!link.running());
        // A copy: the line, then its text, which is the command's input.
        link.handle(Msg::Uart(encode(frame::CBB_OUT, b"cbb next copy 5 0000abcd\n")), now);
        assert!(link.start.take().is_some());
        link.handle(Msg::Uart(encode(frame::CBB_OUT, b"hel")), now);
        link.handle(Msg::Uart(encode(frame::CBB_OUT, b"lo")), now);
        assert_eq!(std::mem::take(&mut link.input), b"hello");
        // .cbb stops it: nothing more of it, not even the prompt.
        link.handle(Msg::Uart(encode(frame::CBB_OUT, b"")), now);
        assert!(std::mem::take(&mut link.stop));
        link.handle(Msg::CommandOut(b"CBBERR stopped\r".to_vec()), now);
        link.handle(Msg::CommandEnded, now);
        assert!(to_cbb(&link, &mut at).is_empty());
    }

    /// Only `cbb next paste` and `copy`: the rest of the shell stays shut.
    #[test]
    fn refuses_other_commands() {
        let (mut link, _, now) = new_link();
        let mut at = 0;
        link.handle(Msg::Uart(encode(frame::HELLO, b"cbb.drv 0.2")), now);
        to_cbb(&link, &mut at);
        for line in ["rm -rf /\n", "cbb next link -to x:1\n", "cbb service\n"] {
            link.handle(Msg::Uart(encode(frame::CBB_OUT, line.as_bytes())), now);
            assert!(link.start.is_none(), "{line}");
            let out = to_cbb(&link, &mut at);
            assert!(out.starts_with(b"CBBERR ") && out.ends_with(b"\r\nSUP>"), "{}", out.escape_ascii());
        }
        assert_eq!(
            command_args("cbb next copy -secret 3 00000000"),
            Some(vec!["next".into(), "copy".into(), "-secret".into(), "3".into(), "00000000".into()])
        );
        assert_eq!(command_args("sudo cbb next paste"), None);
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

    /// The datagrams of the local UDP port go out on the ESP's UDP
    /// connection, opened at the first, and the answers come back to
    /// where they came from; the dialled TCP connections keep off its slot.
    #[test]
    fn udp_through_the_esp() {
        let (mut link, mut next, now) = new_link();
        let mut at = 0;
        let ours = UdpSocket::bind("127.0.0.1:0").unwrap();
        let tunnel = UdpSocket::bind("127.0.0.1:0").unwrap();
        tunnel.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        link.udp(Udp::new(ours, ("hub.example".into(), 51820), 8770));
        link.handle(Msg::Uart(encode(frame::HELLO, b"")), now);
        for cmd in ["AT\r\n", "ATE0\r\n", "AT+CIPMUX=1\r\n"] {
            let (esp, ack) = sent(&link, &mut next, &mut at);
            assert_eq!(esp, cmd);
            link.handle(Msg::Uart(ack), now);
            link.handle(from_esp(b"\r\nOK\r\n"), now);
        }
        let me = tunnel.local_addr().unwrap();
        link.handle(Msg::Datagram(me, b"one".to_vec()), now);
        link.handle(Msg::Datagram(me, b"two".to_vec()), now);
        let (esp, ack) = sent(&link, &mut next, &mut at);
        assert_eq!(esp, "AT+CIPSTART=4,\"UDP\",\"hub.example\",51820,8770,0\r\n");
        link.handle(Msg::Uart(ack), now);
        link.handle(from_esp(b"4,CONNECT\r\n\r\nOK\r\n"), now);
        for d in ["one", "two"] {
            let (esp, ack) = sent(&link, &mut next, &mut at);
            assert_eq!(esp, "AT+CIPSEND=4,3\r\n");
            link.handle(Msg::Uart(ack), now);
            link.handle(from_esp(b"\r\nOK\r\n> "), now);
            let (esp, ack) = sent(&link, &mut next, &mut at);
            assert_eq!(esp, d, "each datagram in a send of its own");
            link.handle(Msg::Uart(ack), now);
            link.handle(from_esp(b"\r\nSEND OK\r\n"), now);
        }
        link.handle(from_esp(b"+IPD,4,5:hello"), now);
        let mut buf = [0u8; 16];
        let (n, _) = tunnel.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"hello");
        // The member's TCP connection takes the slot below.
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let _member = TcpStream::connect(l.local_addr().unwrap()).unwrap();
        link.handle(Msg::Accepted(l.accept().unwrap().0), now);
        assert_eq!(link.readers.pop().expect("taken").0, 3);
        let (esp, ack) = sent(&link, &mut next, &mut at);
        assert_eq!(esp, "AT+CIPSTART=3,\"TCP\",\"192.168.0.10\",8763\r\n");
        link.handle(Msg::Uart(ack), now);
        link.handle(from_esp(b"3,CONNECT\r\n\r\nOK\r\n"), now);
        // The connection drops: the next datagram opens it again.
        link.handle(from_esp(b"4,CLOSED\r\n"), now);
        link.handle(Msg::Datagram(me, b"three".to_vec()), now);
        let (esp, _) = sent(&link, &mut next, &mut at);
        assert_eq!(esp, "AT+CIPSTART=4,\"UDP\",\"hub.example\",51820,8770,0\r\n");
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

    /// An ack that counts a stray byte besides the frames, before the
    /// hello, leaves the window open.
    #[test]
    fn ack_past_what_was_sent() {
        let (mut link, _, now) = new_link();
        let mut wire = encode(frame::ACK, &1u16.to_le_bytes());
        wire.extend(encode(frame::HELLO, b"cbb.drv 0.1"));
        link.handle(Msg::Uart(wire), now);
        assert!(!link.output().is_empty(), "the link waits for nothing");
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
    fn a_busy_esp_that_answers_is_not_restarted() {
        let (mut link, mut next, now) = new_link();
        link.handle(Msg::Uart(encode(frame::HELLO, b"")), now);
        let mut at = 0;
        // Each answer comes within the timeout, the whole stretch after it.
        let step = ESP_TIMEOUT / 2 + Duration::from_secs(1);
        let mut t = now;
        for cmd in ["AT\r\n", "ATE0\r\n", "AT+CIPMUX=1\r\n"] {
            let (esp, ack) = sent(&link, &mut next, &mut at);
            assert_eq!(esp, cmd);
            link.handle(Msg::Uart(ack), t);
            link.tick(t);
            t += step;
            link.tick(t);
            link.handle(from_esp(b"\r\nOK\r\n"), t);
        }
        assert!(t.duration_since(now) > ESP_TIMEOUT);
        assert!(link.esp.ready());
    }

    #[test]
    fn a_peer_out_of_reach_is_dialled_less_often() {
        let (mut link, mut next, now) = new_link();
        let mut at = 0;
        link.handle(Msg::Uart(encode(frame::HELLO, b"")), now);
        for cmd in ["AT\r\n", "ATE0\r\n", "AT+CIPMUX=1\r\n"] {
            let (esp, ack) = sent(&link, &mut next, &mut at);
            assert_eq!(esp, cmd);
            link.handle(Msg::Uart(ack), now);
            link.handle(from_esp(b"\r\nOK\r\n"), now);
        }
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let dial = |link: &mut Link<Vec<u8>>, t| {
            let _member = TcpStream::connect(l.local_addr().unwrap()).unwrap();
            link.handle(Msg::Accepted(l.accept().unwrap().0), t);
        };
        dial(&mut link, now);
        let (esp, ack) = sent(&link, &mut next, &mut at);
        assert!(esp.starts_with("AT+CIPSTART=4,\"TCP\""), "{esp}");
        link.handle(Msg::Uart(ack), now);
        link.handle(from_esp(b"4,CONNECT FAIL\r\n\r\nERROR\r\n"), now);
        // Right after, the member's next try is turned away at once.
        dial(&mut link, now + Duration::from_secs(1));
        assert_eq!(sent(&link, &mut next, &mut at).0, "");
        // After the wait it dials again.
        dial(&mut link, now + DIAL_BACKOFF.0 + Duration::from_secs(1));
        assert!(sent(&link, &mut next, &mut at).0.starts_with("AT+CIPSTART=4,"));
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
