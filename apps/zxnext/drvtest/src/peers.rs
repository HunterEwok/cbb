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
    pub log: Vec<String>,
    /// A baud change after the OK goes out.
    pending_baud: Option<(u64, u32)>,
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
            log: Vec::new(),
            pending_baud: None,
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
        if c == "AT" || c == "ATE0" || c == "ATE1" || c == "AT+CIPMUX=0" && !self.connected {
            return self.reply(now, "\r\nOK\r\n");
        }
        if let Some(m) = c.strip_prefix("AT+CIPMODE=") {
            self.cipmode = m.parse().unwrap_or(0);
            return self.reply(now, "\r\nOK\r\n");
        }
        if c == "AT+CIPCLOSE" {
            if self.connected {
                self.connected = false;
                return self.reply(now, "CLOSED\r\n\r\nOK\r\n");
            }
            return self.reply(now, "\r\nERROR\r\n");
        }
        if c.starts_with("AT+CIPSTART=") {
            if self.connected {
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
            self.log.push(format!("{:.3}s HTTP: {}", now as f64 / 1e6, text.lines().next().unwrap_or("")));
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
            eprintln!("{:.4}s esp< {:02x} {:?} at {baud}", now as f64 / 1e6, b, b as char);
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

/// NextPi's supervisor shell: SUP> and the commands .cbb types.
pub struct Pi {
    out: Out,
    line: Vec<u8>,
    /// Raw input: bytes still to take, and where they go.
    raw: usize,
    pub received: Vec<u8>,
    /// The cbb on the Pi: its SHA-256 in hex, or none.
    pub cbb_sha: Option<String>,
    pub log: Vec<String>,
    pub answers: bool,
}

impl Pi {
    pub fn new() -> Pi {
        Pi {
            out: Out::default(),
            line: Vec::new(),
            raw: 0,
            received: Vec::new(),
            cbb_sha: None,
            log: Vec::new(),
            answers: true,
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
        if cmd.starts_with("stty raw -echo -iexten; echo CBBGO") {
            let n: usize = cmd.split("head -c ").nth(1).unwrap().split(' ').next().unwrap().parse().unwrap();
            self.say(now + 10_000, "CBBGO\r\n");
            self.raw = n;
            self.received.clear();
            return;
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
        if !self.answers {
            return;
        }
        if self.raw > 0 {
            self.received.push(b);
            self.raw -= 1;
            if self.raw == 0 {
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
        self.out.pop(now)
    }
    fn baud(&self) -> u32 {
        115_200
    }
    fn as_any(&mut self) -> &mut dyn std::any::Any {
        self
    }
}
