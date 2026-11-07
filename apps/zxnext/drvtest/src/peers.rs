// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! What sits on the Next's UARTs, played here: the ESP8266 with its AT
//! firmware (1.2, as on the owner's Next: echo on, transparent mode with
//! +++) and a web server behind it as nginx answers, and NextPi's shell
//! on the Pi.

use std::collections::{HashMap, VecDeque};
use std::path::PathBuf;

use crate::next::Peer;

/// Bytes queued to the Next, each not before its time (microseconds).
#[derive(Default)]
struct Out {
    q: VecDeque<(u64, u8)>,
}

impl Out {
    fn push(&mut self, at: u64, bytes: &[u8]) {
        let at = self.q.back().map(|b| b.0.max(at)).unwrap_or(at);
        for &b in bytes {
            self.q.push_back((at, b));
        }
    }
    fn pop(&mut self, now: u64) -> Option<u8> {
        match self.q.front() {
            Some(&(t, _)) if t <= now => self.q.pop_front().map(|b| b.1),
            _ => None,
        }
    }
}

/// How the web server misbehaves, for the tests of the failures.
#[derive(Clone, Default)]
pub struct Faults {
    /// Close the connection after this many requests.
    pub close_after: Option<u32>,
    /// Answer every request with this status, without a body.
    pub status: Option<u16>,
    /// Never answer.
    pub silent: bool,
}

pub struct Esp {
    pub baud: u32,
    /// The ESP's own speed when the Next sends at another.
    line: Vec<u8>,
    out: Out,
    pub passthrough: bool,
    pub connected: bool,
    cipmode: u8,
    /// Passthrough: the bytes since the last gap, and when the last came.
    burst: Vec<u8>,
    last_rx: u64,
    request: Vec<u8>,
    /// The HTTP requests on this connection.
    pub requests: u32,
    pub site: PathBuf,
    pub faults: Faults,
    pub wifi: bool,
    /// After AT+RST, the time it joins the Wi-Fi network again.
    wifi_at: u64,
    pub log: Vec<String>,
    /// A baud change after the OK goes out.
    pending_baud: Option<(u64, u32)>,
    /// The members on the Wi-Fi network that answer mDNS: address, port,
    /// and their TXT's own strings, split by commas ("r=lite", "p=1").
    pub members: Vec<(String, u16, String)>,
    cipdinfo: bool,
    /// Connection 4, UDP, in CIPMUX=1.
    udp: bool,
    /// CIPMUX=1, and a server, which the network's link leaves; the old
    /// firmware keeps CIPMUX=1 with a server until AT+RST.
    pub mux: bool,
    pub server: bool,
    /// Non-transparent AT+CIPSEND: bytes still to take.
    sending: usize,
    datagram: Vec<u8>,
}

/// A member's answer to the legacy unicast question, as Go's mdns packs
/// it: the question again, the PTR, then SRV, TXT and A.
fn mdns_answer(q: &[u8], ip: &str, port: u16, txt_own: &str) -> Vec<u8> {
    let mut m = vec![q[0], q[1], 0x84, 0, 0, 1, 0, 1, 0, 0, 0, 3];
    m.extend_from_slice(&q[12..]);
    let rec = |m: &mut Vec<u8>, name: &[u8], t: u16, data: &[u8]| {
        m.extend_from_slice(name);
        m.extend_from_slice(&t.to_be_bytes());
        m.extend_from_slice(&[0, 1, 0, 0, 0, 10]);
        m.extend_from_slice(&(data.len() as u16).to_be_bytes());
        m.extend_from_slice(data);
    };
    let instance = b"\x0bdev-0000001\xc0\x0c".to_vec();
    rec(&mut m, b"\xc0\x0c", 12, &instance);
    let mut srv = vec![0, 0, 0, 0];
    srv.extend_from_slice(&port.to_be_bytes());
    srv.extend_from_slice(b"\x04host\x05local\x00");
    rec(&mut m, &instance, 33, &srv);
    let mut txt = Vec::new();
    for t in ["v=1", "g=abcdef"].into_iter().chain(txt_own.split(',')) {
        if t.is_empty() {
            continue;
        }
        txt.push(t.len() as u8);
        txt.extend_from_slice(t.as_bytes());
    }
    rec(&mut m, &instance, 16, &txt);
    let a: Vec<u8> = ip.split('.').map(|o| o.parse::<u8>().unwrap()).collect();
    rec(&mut m, b"\x04host\x05local\x00", 1, &a);
    m
}

impl Esp {
    pub fn new(site: PathBuf) -> Esp {
        Esp {
            baud: 115_200,
            line: Vec::new(),
            out: Out::default(),
            passthrough: false,
            connected: false,
            cipmode: 0,
            burst: Vec::new(),
            last_rx: 0,
            request: Vec::new(),
            requests: 0,
            site,
            faults: Faults::default(),
            wifi: true,
            wifi_at: 0,
            log: Vec::new(),
            pending_baud: None,
            members: Vec::new(),
            cipdinfo: false,
            mux: false,
            server: false,
            udp: false,
            sending: 0,
            datagram: Vec::new(),
        }
    }

    /// The datagram the Next sent: to 224.0.0.251:5353, the members answer.
    fn datagram(&mut self, now: u64) {
        let d = std::mem::take(&mut self.datagram);
        self.out.push(
            now + 2_000,
            format!("\r\nRecv {} bytes\r\n\r\nSEND OK\r\n", d.len()).as_bytes(),
        );
        self.log
            .push(format!("{:.3}s UDP: {} bytes", now as f64 / 1e6, d.len()));
        if d.len() < 12 || !find(&d, b"\x04_cbb\x04_tcp\x05local\x00").is_some() {
            return;
        }
        for (k, (ip, port, r)) in self.members.clone().iter().enumerate() {
            let m = mdns_answer(&d, ip, *port, r);
            let head = if self.cipdinfo {
                format!("\r\n+IPD,4,{},{ip},5353:", m.len())
            } else {
                format!("\r\n+IPD,4,{}:", m.len())
            };
            let at = now + 20_000 + 10_000 * k as u64;
            self.out.push(at, head.as_bytes());
            self.out.push(at, &m);
        }
    }

    fn reply(&mut self, now: u64, s: &str) {
        self.out.push(now + 2_000, s.as_bytes());
    }

    fn command(&mut self, now: u64, cmd: &str) {
        self.log.push(format!("{:.3}s AT: {cmd}", now as f64 / 1e6));
        if std::env::var("PEER_LOG").is_ok() {
            eprintln!("{}", self.log.last().unwrap());
        }
        let c = cmd.trim();
        if c == "AT" || c == "ATE0" || c == "ATE1" {
            return self.reply(now, "\r\nOK\r\n");
        }
        if c == "AT+CIPMUX=0" || c == "AT+CIPMUX=1" {
            if self.connected || self.udp || self.server && c.ends_with('0') {
                return self.reply(now, "\r\nERROR\r\n");
            }
            self.mux = c.ends_with('1');
            return self.reply(now, "\r\nOK\r\n");
        }
        if c == "AT+RST" {
            self.mux = false;
            self.server = false;
            self.connected = false;
            self.udp = false;
            self.cipdinfo = false;
            self.cipmode = 0;
            self.reply(now, "\r\nOK\r\n");
            self.out
                .push(now + 100_000, b"\x8a\xf3 ets Jan  8 2013\r\n\r\nready\r\n");
            self.wifi_at = now + 3_000_000;
            self.out
                .push(self.wifi_at, b"WIFI CONNECTED\r\nWIFI GOT IP\r\n");
            self.pending_baud = Some((now + 5_000, 115_200));
            return;
        }
        if let Some(m) = c.strip_prefix("AT+CIPMODE=") {
            self.cipmode = m.parse().unwrap_or(0);
            return self.reply(now, "\r\nOK\r\n");
        }
        if c == "AT+CIPCLOSE=4" {
            if self.mux && self.udp {
                self.udp = false;
                return self.reply(now, "4,CLOSED\r\n\r\nOK\r\n");
            }
            return self.reply(now, "\r\nERROR\r\n");
        }
        if c == "AT+CIPCLOSE" {
            if self.connected && !self.mux {
                self.connected = false;
                self.udp = false;
                return self.reply(now, "CLOSED\r\n\r\nOK\r\n");
            }
            return self.reply(now, "\r\nERROR\r\n");
        }
        if let Some(v) = c.strip_prefix("AT+CIPDINFO=") {
            self.cipdinfo = v == "1";
            return self.reply(now, "\r\nOK\r\n");
        }
        if c.starts_with("AT+CIPSTART") && now < self.wifi_at {
            return self.reply(now, "\r\nERROR\r\n");
        }
        if c.starts_with("AT+CIPSTART=4,\"UDP\"") {
            if !self.mux {
                return self.reply(now, "\r\nERROR\r\n");
            }
            if self.udp {
                return self.reply(now, "ALREADY CONNECTED\r\n\r\nERROR\r\n");
            }
            self.udp = true;
            return self.reply(now, "4,CONNECT\r\n\r\nOK\r\n");
        }
        if let Some(n) = c.strip_prefix("AT+CIPSEND=4,") {
            if !self.udp || self.cipmode != 0 {
                return self.reply(now, "\r\nERROR\r\n");
            }
            self.sending = n.parse().unwrap();
            self.datagram.clear();
            return self.reply(now, "\r\nOK\r\n> ");
        }
        if let Some(port) = c.strip_prefix("AT+CIPSERVER=1,") {
            if !self.mux || port.is_empty() {
                return self.reply(now, "\r\nERROR\r\n");
            }
            self.server = true;
            return self.reply(now, "\r\nOK\r\n");
        }
        if c.starts_with("AT+CIPSTART=") {
            if self.connected || self.mux {
                return self.reply(now, "ALREADY CONNECTED\r\n\r\nERROR\r\n");
            }
            if !self.wifi {
                return self.reply(now, "DNS Fail\r\n\r\nERROR\r\n");
            }
            self.connected = true;
            self.requests = 0;
            self.out.push(now + 80_000, b"CONNECT\r\n\r\nOK\r\n");
            return;
        }
        if c == "AT+CIPSEND" && self.cipmode == 1 && self.connected {
            self.out.push(now + 2_000, b"\r\nOK\r\n\r\n>");
            self.passthrough = true;
            self.burst.clear();
            return;
        }
        if let Some(rest) = c.strip_prefix("AT+UART_CUR=") {
            let baud: u32 = rest.split(',').next().unwrap().parse().unwrap();
            self.reply(now, "\r\nOK\r\n");
            self.pending_baud = Some((now + 5_000, baud));
            return;
        }
        if c == "AT+CIFSR" {
            return self
                .reply(now, "+CIFSR:STAIP,\"192.168.0.166\"\r\n+CIFSR:STAMAC,\"08:3a:f2:00:00:01\"\r\n\r\nOK\r\n");
        }
        if c.is_empty() {
            return;
        }
        self.reply(now, "\r\nERROR\r\n");
    }

    /// A request on the connection, answered as nginx does.
    fn http(&mut self, now: u64) {
        while let Some(end) = find(&self.request, b"\r\n\r\n") {
            let req: Vec<u8> = self.request.drain(..end + 4).collect();
            let text = String::from_utf8_lossy(&req).to_string();
            self.requests += 1;
            self.log.push(format!(
                "{:.3}s HTTP: {}",
                now as f64 / 1e6,
                text.lines().next().unwrap_or("")
            ));
            if std::env::var("PEER_LOG").is_ok() {
                eprintln!("{}", self.log.last().unwrap());
            }
            if self.faults.silent {
                continue;
            }
            if let Some(n) = self.faults.close_after {
                if self.requests > n {
                    self.connected = false;
                    self.passthrough = false;
                    self.out.push(now + 30_000, b"\r\nCLOSED\r\n");
                    return;
                }
            }
            let mut lines = text.split("\r\n");
            let first = lines.next().unwrap_or("");
            let mut range = None;
            let mut headers = HashMap::new();
            for l in lines {
                if let Some((k, v)) = l.split_once(':') {
                    headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
                }
            }
            if let Some(r) = headers.get("range").and_then(|r| r.strip_prefix("bytes=")) {
                let (a, b) = r.split_once('-').unwrap();
                range = Some((a.parse::<usize>().unwrap(), b.parse::<usize>().unwrap()));
            }
            let path = first.split(' ').nth(1).unwrap_or("/");
            let file = path.strip_prefix("/zxnext/").map(|n| self.site.join(n));
            let body = file.and_then(|f| std::fs::read(f).ok());
            let at = now + 40_000;
            if let Some(code) = self.faults.status {
                let resp = format!(
                    "HTTP/1.1 {code} Error\r\nServer: nginx\r\nContent-Length: 0\r\nConnection: keep-alive\r\n\r\n"
                );
                self.out.push(at, resp.as_bytes());
                continue;
            }
            let head = "Server: nginx\r\nDate: Wed, 04 Nov 2026 13:00:00 GMT\r\nContent-Type: application/octet-stream";
            match (body, range) {
                (None, _) => {
                    let page = b"<html>\r\n<head><title>404 Not Found</title></head>\r\n<body>\r\n<center><h1>404 Not Found</h1></center>\r\n<hr><center>nginx</center>\r\n</body>\r\n</html>\r\n";
                    let resp = format!(
                        "HTTP/1.1 404 Not Found\r\nServer: nginx\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n",
                        page.len()
                    );
                    self.out.push(at, resp.as_bytes());
                    self.out.push(at, page);
                }
                (Some(b), Some((x, y))) => {
                    let y = y.min(b.len() - 1);
                    let part = &b[x..=y];
                    let resp = format!(
                        "HTTP/1.1 206 Partial Content\r\n{head}\r\nContent-Length: {}\r\nLast-Modified: Wed, 04 Nov 2026 12:00:00 GMT\r\nConnection: keep-alive\r\nETag: \"6909f0e0-{:x}\"\r\nContent-Range: bytes {x}-{y}/{}\r\n\r\n",
                        part.len(),
                        b.len(),
                        b.len()
                    );
                    self.out.push(at, resp.as_bytes());
                    self.out.push(at, part);
                }
                (Some(b), None) => {
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\n{head}\r\nContent-Length: {}\r\nLast-Modified: Wed, 04 Nov 2026 12:00:00 GMT\r\nConnection: keep-alive\r\nETag: \"6909f0e0-{:x}\"\r\nAccept-Ranges: bytes\r\n\r\n",
                        b.len(),
                        b.len()
                    );
                    self.out.push(at, resp.as_bytes());
                    self.out.push(at, &b);
                }
            }
        }
    }
}

fn find(h: &[u8], n: &[u8]) -> Option<usize> {
    h.windows(n.len()).position(|w| w == n)
}

impl Peer for Esp {
    fn rx(&mut self, now: u64, b: u8, baud: u32) {
        if std::env::var("PEER_LOG").as_deref() == Ok("2") {
            eprintln!(
                "{:.4}s esp< {:02x} {:?} at {baud}",
                now as f64 / 1e6,
                b,
                b as char
            );
        }
        if self.passthrough {
            // +++ alone, with quiet before it, leaves transparent mode.
            if now.saturating_sub(self.last_rx) > 20_000 {
                self.burst.clear();
            }
            self.last_rx = now;
            self.burst.push(b);
            if self.burst == b"+++" {
                self.passthrough = false;
                self.log.push(format!("{:.3}s +++", now as f64 / 1e6));
                // The request bytes "++" may have gone on; nginx sees junk.
                self.request.clear();
                return;
            }
            if self.connected {
                self.request.push(b);
                self.http(now);
            }
            return;
        }
        if self.sending > 0 {
            self.datagram.push(b);
            self.sending -= 1;
            if self.sending == 0 {
                self.datagram(now);
            }
            return;
        }
        // Command mode: the echo, then the line at CR LF.
        self.out.push(now, &[b]);
        if b == b'\n' {
            let line = String::from_utf8_lossy(&self.line).to_string();
            self.line.clear();
            self.command(now, line.trim_end_matches('\r'));
        } else {
            self.line.push(b);
        }
    }
    fn tx(&mut self, now: u64) -> Option<u8> {
        if let Some((t, baud)) = self.pending_baud {
            if now >= t {
                self.baud = baud;
                self.pending_baud = None;
            }
        }
        self.out.pop(now)
    }
    fn baud(&self) -> u32 {
        self.baud
    }
    fn as_any(&mut self) -> &mut dyn std::any::Any {
        self
    }
}

/// The first line of a site's SIGNED that the played Pi's cbb takes as
/// signed by the release keys; the lines after it are the Next's files.
pub const SIGNED_OK: &str = "{\"played\":\"signed\"}";

/// NextPi's supervisor shell: SUP> and the commands .cbb types.
pub struct Pi {
    out: Out,
    line: Vec<u8>,
    /// Raw input: bytes still to take, and where they go.
    raw: usize,
    /// Whether the raw bytes are cbb next copy's text, not a file's.
    raw_copy: bool,
    pub received: Vec<u8>,
    /// The group's latest text, which cbb next paste gives.
    pub clip: Vec<u8>,
    /// What cbb next copy took.
    pub copied: Vec<u8>,
    /// The cbb on the Pi: its SHA-256 in hex, or none.
    pub cbb_sha: Option<String>,
    pub log: Vec<String>,
    pub answers: bool,
    /// Whether the tty takes a speed above 115200 for the copy.
    pub fast: bool,
    /// Whether the Pi's cbb-state holds an identity: it is in a group.
    pub in_group: bool,
    /// Whether the Pi's cbb has check-list: an older one has not.
    pub checks_lists: bool,
    baud: u32,
    /// A speed stty sets, and when.
    pending_baud: Option<(u64, u32)>,
}

impl Pi {
    pub fn new() -> Pi {
        Pi {
            out: Out::default(),
            line: Vec::new(),
            raw: 0,
            raw_copy: false,
            received: Vec::new(),
            clip: b"Hello from the group".to_vec(),
            copied: Vec::new(),
            cbb_sha: None,
            log: Vec::new(),
            answers: true,
            fast: true,
            in_group: false,
            checks_lists: true,
            baud: 115_200,
            pending_baud: None,
        }
    }

    fn apply_baud(&mut self, now: u64) {
        if let Some((t, baud)) = self.pending_baud {
            if now >= t {
                self.baud = baud;
                self.pending_baud = None;
            }
        }
    }

    fn say(&mut self, now: u64, s: &str) {
        self.out.push(now + 1_000, s.as_bytes());
    }

    fn prompt(&mut self, now: u64) {
        self.say(now + 5_000, "\r\nSUP>");
    }

    fn command(&mut self, now: u64, cmd: &str) {
        self.log.push(format!("{:.3}s $ {cmd}", now as f64 / 1e6));
        if std::env::var("PEER_LOG").is_ok() {
            eprintln!("pi {}", self.log.last().unwrap());
        }
        if cmd.contains("sha256sum /NextPi/nextpi/cbb.bin") {
            let s = self.cbb_sha.clone().unwrap_or_else(|| "none".into());
            self.say(now + 50_000, &format!("CBBS {s}\r\n"));
            return self.prompt(now + 50_000);
        }
        if let Some(rest) = cmd.strip_prefix("s=$(stty -g); stty ") {
            // Without a speed, the line keeps its own.
            let speed: u32 = rest.split(' ').next().unwrap().parse().unwrap_or(self.baud);
            let n: usize = cmd
                .split("head -c ")
                .nth(1)
                .unwrap()
                .split(' ')
                .next()
                .unwrap()
                .parse()
                .unwrap();
            if !self.fast && speed != 115_200 {
                self.say(
                    now + 10_000,
                    &format!("stty: invalid argument '{speed}'\r\n"),
                );
                return self.prompt(now + 10_000);
            }
            self.pending_baud = Some((now + 5_000, speed));
            // After stty raw the tty adds no CR to an LF, as a real one:
            // printf gives what it is given.
            let sleep = if cmd.contains(" && sleep 1 && ") {
                1_000_000
            } else {
                0
            };
            let next = cmd
                .split(" && ")
                .find(|p| p.starts_with("printf"))
                .unwrap_or("");
            let out = next
                .strip_prefix("printf '")
                .and_then(|t| t.strip_suffix('\''))
                .map(|t| t.replace("\\r", "\r").replace("\\n", "\n"))
                .unwrap_or_default();
            self.say(now + 10_000 + sleep, &out);
            self.raw = n;
            self.received.clear();
            return;
        }
        // The lite member's frames (member/README.md): a text, and a copy
        // that answers CBBGO, takes its bytes raw, then says CBBOK.
        let words: Vec<&str> = cmd.split_whitespace().filter(|w| *w != "-debug").collect();
        if words.len() >= 3 && words[0] == "cbb" && words[1] == "next" {
            match &words[2..] {
                ["paste", "-max", _] => {
                    let crc = crate::crc32(&self.clip);
                    let mut f = format!("CBB1 {} {crc:08x}\r", self.clip.len()).into_bytes();
                    f.extend_from_slice(&self.clip);
                    f.extend_from_slice(b"\rCBBOK\r");
                    self.out.push(now + 50_000, &f);
                    return self.prompt(now + 50_000);
                }
                ["copy", rest @ ..] => {
                    let n = rest
                        .iter()
                        .rev()
                        .nth(1)
                        .and_then(|n| n.parse().ok())
                        .unwrap_or(0);
                    self.say(now + 50_000, "CBBGO\r");
                    self.raw = n;
                    self.raw_copy = true;
                    self.copied.clear();
                    return;
                }
                _ => {}
            }
        }
        // cbb next check-list (member/src/next.rs) on the list that came
        // raw: here its signature is a first line that says so (SIGNED_OK),
        // which the tests leave out to stand for a list the release keys
        // did not sign.
        if cmd.starts_with(
            "/NextPi/nextpi/cbb next check-list /NextPi/nextpi/cbb.list || echo CBBERR; ",
        ) {
            let text = String::from_utf8_lossy(&self.received).to_string();
            let mut lines = text.lines();
            let out = if !self.checks_lists {
                "cbb: unknown command\r\nCBBERR\r\n".to_string()
            } else if lines.next() == Some(SIGNED_OK) {
                let mut out: String = lines.map(|l| format!("CBBL {l}\r")).collect();
                out += "CBBOK\r";
                out
            } else {
                "CBBERR the signature does not match\r".to_string()
            };
            self.say(now + 100_000, &out);
            return self.prompt(now + 100_000);
        }
        if cmd.starts_with("test -e /NextPi/nextpi/cbb-state/identity.json && echo CBB$((1))IN") {
            let s = if self.in_group {
                "CBB1IN\r\nCBB1END\r\n"
            } else {
                "CBB1END\r\n"
            };
            self.say(now + 20_000, s);
            return self.prompt(now + 20_000);
        }
        if cmd.starts_with("pkill -f '/NextPi/nextpi/cbb'; cbb leave -yes; ")
            && cmd.ends_with("echo CBB$((1))GONE")
        {
            self.in_group = false;
            self.say(now + 50_000, "CBB1GONE\r\n");
            return self.prompt(now + 50_000);
        }
        if cmd.starts_with("pkill -f '/NextPi/nextpi/cbb'; cd /NextPi/nextpi && rm -rf ")
            && cmd.ends_with("echo CBB$((1))GONE")
        {
            self.cbb_sha = None;
            self.say(now + 100_000, "CBB1GONE\r\n");
            return self.prompt(now + 100_000);
        }
        if cmd.starts_with("cd /NextPi/nextpi && if ! command -v sha256sum") {
            let want = cmd.split('\'').nth(1).unwrap_or("");
            let got = crate::sha256::hex(&self.received);
            if got == want {
                self.cbb_sha = Some(got);
                self.say(now + 200_000, "CBBOK\r\n");
            } else {
                self.say(now + 200_000, "CBBERR\r\n");
            }
            return self.prompt(now + 200_000);
        }
        self.prompt(now);
    }
}

impl Default for Pi {
    fn default() -> Self {
        Pi::new()
    }
}

impl Peer for Pi {
    fn rx(&mut self, now: u64, b: u8, _baud: u32) {
        self.apply_baud(now);
        if !self.answers {
            return;
        }
        if self.raw > 0 && self.raw_copy {
            self.copied.push(b);
            self.raw -= 1;
            if self.raw == 0 {
                self.raw_copy = false;
                self.say(now + 50_000, "CBBOK\r");
                self.prompt(now + 50_000);
            }
            return;
        }
        if self.raw > 0 {
            self.received.push(b);
            self.raw -= 1;
            if self.raw == 0 {
                // stty $s: the line's speed again.
                self.pending_baud = Some((now + 1_000, 115_200));
                self.prompt(now);
            }
            return;
        }
        match b {
            3 | 4 => {
                self.line.clear();
                self.prompt(now);
            }
            b'\n' | b'\r' => {
                self.out.push(now, b"\r\n");
                let cmd = String::from_utf8_lossy(&self.line).to_string();
                self.line.clear();
                self.command(now, &cmd);
            }
            _ => {
                self.out.push(now, &[b]);
                self.line.push(b);
            }
        }
    }
    fn tx(&mut self, now: u64) -> Option<u8> {
        self.apply_baud(now);
        self.out.pop(now)
    }
    fn baud(&self) -> u32 {
        self.baud
    }
    fn as_any(&mut self) -> &mut dyn std::any::Any {
        self
    }
}
