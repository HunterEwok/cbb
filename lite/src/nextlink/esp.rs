// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The Next's ESP8266 driven with its stock AT firmware (AT 1.2), without
//! I/O: bytes from the ESP go in, and out come the bytes for the ESP and
//! the events of its connections. Several connections at once (CIPMUX=1),
//! TCP and UDP, the data in `+IPD` blocks, so the end of a connection never
//! hides in its data. The ESP carries only what the member protocol has
//! already encrypted.

use std::collections::VecDeque;

/// The ESP's connections are numbered 0 to 4.
pub const LINKS: u8 = 5;
/// The most bytes one AT+CIPSEND takes.
const SEND_MAX: usize = 2048;

/// What happened on the ESP.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// The ESP answers, and takes several connections.
    Ready,
    /// A connection opened.
    Connected(u8),
    /// A dial failed, with the ESP's words.
    Failed(u8, String),
    /// Bytes arrived on a connection.
    Data(u8, Vec<u8>),
    /// The ESP took the bytes given to send.
    Sent(u8),
    /// A connection closed.
    Closed(u8),
    /// The ESP restarted (its banner and `ready`): every connection is gone.
    Reset,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Cmd {
    Hello,
    EchoOff,
    Mux,
    Dial {
        id: u8,
        line: String,
    },
    /// AT+CIPSEND, then the bytes at the prompt.
    Send {
        id: u8,
        data: Vec<u8>,
    },
    Close(u8),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Wait {
    /// Nothing is in flight.
    None,
    /// The command's OK or ERROR.
    Answer,
    /// The prompt `>` of AT+CIPSEND.
    Prompt,
    /// SEND OK after the bytes.
    SendOk,
}

/// The ESP, as far as its answers tell.
#[derive(Debug)]
pub struct Esp {
    buf: Vec<u8>,
    queue: VecDeque<Cmd>,
    current: Option<Cmd>,
    wait: Wait,
    out: Vec<u8>,
    events: Vec<Event>,
    ready: bool,
}

impl Default for Esp {
    fn default() -> Self {
        Esp::new()
    }
}

impl Esp {
    /// Starts by asking the ESP for an answer, turning its echo off and
    /// several connections on.
    pub fn new() -> Esp {
        let mut e = Esp {
            buf: Vec::new(),
            queue: VecDeque::new(),
            current: None,
            wait: Wait::None,
            out: Vec::new(),
            events: Vec::new(),
            ready: false,
        };
        e.start();
        e
    }

    fn start(&mut self) {
        self.queue.clear();
        self.current = None;
        self.wait = Wait::None;
        self.ready = false;
        self.queue.extend([Cmd::Hello, Cmd::EchoOff, Cmd::Mux]);
        self.next();
    }

    /// Whether the ESP took the setup and connections can be dialled.
    pub fn ready(&self) -> bool {
        self.ready
    }

    /// Dials a TCP connection; Connected or Failed follows.
    pub fn dial_tcp(&mut self, id: u8, host: &str, port: u16) {
        self.dial(id, format!("AT+CIPSTART={id},\"TCP\",\"{}\",{port}", quote(host)));
    }

    /// Opens a UDP connection to one peer, from local_port.
    #[allow(dead_code)] // for sync away from home, the tunnel's next step
    pub fn dial_udp(&mut self, id: u8, host: &str, port: u16, local_port: u16) {
        self.dial(id, format!("AT+CIPSTART={id},\"UDP\",\"{}\",{port},{local_port},0", quote(host)));
    }

    fn dial(&mut self, id: u8, line: String) {
        assert!(id < LINKS);
        self.queue.push_back(Cmd::Dial { id, line });
        self.next();
    }

    /// Sends bytes on a connection, in blocks the ESP takes; one Sent
    /// follows each block.
    pub fn send(&mut self, id: u8, data: &[u8]) {
        assert!(id < LINKS);
        for chunk in data.chunks(SEND_MAX) {
            self.queue.push_back(Cmd::Send { id, data: chunk.to_vec() });
        }
        self.next();
    }

    /// Closes a connection; Closed follows.
    pub fn close(&mut self, id: u8) {
        assert!(id < LINKS);
        self.queue.push_back(Cmd::Close(id));
        self.next();
    }

    /// The bytes to write to the ESP now.
    pub fn take_output(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.out)
    }

    /// The events since the last call.
    pub fn take_events(&mut self) -> Vec<Event> {
        std::mem::take(&mut self.events)
    }

    /// No answer came in time: the command in flight is given up, its
    /// connection closed, and the setup starts again.
    pub fn timeout(&mut self) {
        if let Some(id) = self.current.as_ref().and_then(cmd_id) {
            self.events.push(Event::Failed(id, "the ESP did not answer".into()));
        }
        self.buf.clear();
        self.start();
    }

    /// Whether a command waits for the ESP's answer.
    pub fn busy(&self) -> bool {
        self.wait != Wait::None
    }

    /// Takes bytes from the ESP.
    pub fn input(&mut self, bytes: &[u8]) {
        self.buf.extend_from_slice(bytes);
        while self.step() {}
    }

    /// Handles one thing at the front of the buffer; false when it needs
    /// more bytes.
    fn step(&mut self) -> bool {
        // Blank lines between answers.
        while self.buf.first().is_some_and(|&b| b == b'\r' || b == b'\n') {
            self.buf.remove(0);
        }
        if self.buf.is_empty() {
            return false;
        }
        if self.buf.starts_with(b"+IPD,") {
            return self.ipd();
        }
        if b"+IPD,".starts_with(&self.buf) {
            return false; // could still become +IPD
        }
        if self.wait == Wait::Prompt && self.buf[0] == b'>' {
            self.buf.remove(0);
            if let Some(Cmd::Send { data, .. }) = &self.current {
                self.out.extend_from_slice(data);
            }
            self.wait = Wait::SendOk;
            return true;
        }
        let Some(end) = self.buf.windows(2).position(|w| w == b"\r\n") else {
            return false;
        };
        let line: Vec<u8> = self.buf.drain(..end + 2).take(end).collect();
        self.line(&String::from_utf8_lossy(&line));
        true
    }

    /// `+IPD,<id>,<len>:<bytes>`.
    fn ipd(&mut self) -> bool {
        let Some(colon) = self.buf.iter().position(|&b| b == b':') else {
            if self.buf.len() > 16 {
                self.buf.drain(..5); // not a header after all
                return true;
            }
            return false;
        };
        let head = String::from_utf8_lossy(&self.buf[5..colon]).to_string();
        let mut parts = head.split(',');
        let (Some(Ok(id)), Some(Ok(len))) = (parts.next().map(str::parse::<u8>), parts.next().map(str::parse::<usize>))
        else {
            self.buf.drain(..=colon);
            return true;
        };
        if self.buf.len() < colon + 1 + len {
            return false;
        }
        let data: Vec<u8> = self.buf.drain(..colon + 1 + len).skip(colon + 1).collect();
        self.events.push(Event::Data(id, data));
        true
    }

    fn line(&mut self, line: &str) {
        let line = line.trim();
        if let Some((id, what)) = link_line(line) {
            match what {
                "CONNECT" => self.events.push(Event::Connected(id)),
                "CLOSED" => self.events.push(Event::Closed(id)),
                // CONNECT FAIL: the ERROR after it ends the dial.
                _ => {}
            }
            return;
        }
        match line {
            "ready" => {
                if self.ready || self.wait != Wait::None {
                    self.events.push(Event::Reset);
                }
                self.start();
            }
            "OK" | "ALREADY CONNECTED" | "no change" if self.wait == Wait::Answer => self.done(),
            "OK" if self.wait == Wait::Prompt => {} // AT+CIPSEND's OK before its prompt
            "SEND OK" if self.wait == Wait::SendOk => {
                if let Some(Cmd::Send { id, .. }) = self.current {
                    self.events.push(Event::Sent(id));
                }
                self.done();
            }
            "ERROR" | "SEND FAIL" | "link is not valid" if self.wait != Wait::None => self.failed(line),
            _ => {} // busy p..., echo, WIFI GOT IP and the like
        }
    }

    fn done(&mut self) {
        if matches!(self.current, Some(Cmd::Mux)) {
            self.ready = true;
            self.events.push(Event::Ready);
        }
        self.current = None;
        self.wait = Wait::None;
        self.next();
    }

    fn failed(&mut self, why: &str) {
        match self.current.take() {
            Some(Cmd::Dial { id, .. }) => self.events.push(Event::Failed(id, why.into())),
            Some(Cmd::Send { id, .. }) => {
                // The bytes were lost: the connection cannot go on.
                self.queue.retain(|c| cmd_id(c) != Some(id));
                self.queue.push_front(Cmd::Close(id));
            }
            // Already closed (ERROR to a close): no Closed came, so say it.
            Some(Cmd::Close(id)) => self.events.push(Event::Closed(id)),
            Some(Cmd::Hello) => self.queue.push_front(Cmd::Hello),
            _ => {}
        }
        self.wait = Wait::None;
        self.next();
    }

    fn next(&mut self) {
        if self.wait != Wait::None {
            return;
        }
        let Some(cmd) = self.queue.pop_front() else {
            return;
        };
        let (line, wait) = match &cmd {
            Cmd::Hello => ("AT".to_string(), Wait::Answer),
            Cmd::EchoOff => ("ATE0".to_string(), Wait::Answer),
            Cmd::Mux => ("AT+CIPMUX=1".to_string(), Wait::Answer),
            Cmd::Dial { line, .. } => (line.clone(), Wait::Answer),
            Cmd::Send { id, data } => (format!("AT+CIPSEND={id},{}", data.len()), Wait::Prompt),
            Cmd::Close(id) => (format!("AT+CIPCLOSE={id}"), Wait::Answer),
        };
        self.out.extend_from_slice(line.as_bytes());
        self.out.extend_from_slice(b"\r\n");
        self.current = Some(cmd);
        self.wait = wait;
    }
}

fn cmd_id(c: &Cmd) -> Option<u8> {
    match c {
        Cmd::Dial { id, .. } | Cmd::Send { id, .. } | Cmd::Close(id) => Some(*id),
        _ => None,
    }
}

/// `<id>,CONNECT`, `<id>,CLOSED` and `<id>,CONNECT FAIL`.
fn link_line(line: &str) -> Option<(u8, &str)> {
    let (id, what) = line.split_once(',')?;
    let id: u8 = id.parse().ok()?;
    (id < LINKS).then_some((id, what))
}

/// A host name inside the AT command's quotes: no quotes or commas of its own.
fn quote(host: &str) -> String {
    host.chars().filter(|c| !matches!(c, '"' | ',' | '\\' | '\r' | '\n')).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Feeds the ESP's answers and checks what goes out.
    fn talk(e: &mut Esp, expect: &str, answer: &[u8]) {
        assert_eq!(String::from_utf8_lossy(&e.take_output()), expect);
        e.input(answer);
    }

    fn ready() -> Esp {
        let mut e = Esp::new();
        talk(&mut e, "AT\r\n", b"AT\r\n\r\nOK\r\n");
        talk(&mut e, "ATE0\r\n", b"ATE0\r\n\r\nOK\r\n");
        talk(&mut e, "AT+CIPMUX=1\r\n", b"\r\nOK\r\n");
        assert!(e.ready());
        assert_eq!(e.take_events(), vec![Event::Ready]);
        e
    }

    #[test]
    fn dial_send_receive_close() {
        let mut e = ready();
        e.dial_tcp(0, "192.168.0.10", 8763);
        talk(&mut e, "AT+CIPSTART=0,\"TCP\",\"192.168.0.10\",8763\r\n", b"0,CONNECT\r\n\r\nOK\r\n");
        assert_eq!(e.take_events(), vec![Event::Connected(0)]);
        e.send(0, b"hello");
        talk(&mut e, "AT+CIPSEND=0,5\r\n", b"\r\nOK\r\n> ");
        talk(&mut e, "hello", b"\r\nRecv 5 bytes\r\n\r\nSEND OK\r\n");
        assert_eq!(e.take_events(), vec![Event::Sent(0)]);
        // Data with CR LF and "CLOSED" inside stays data.
        e.input(b"\r\n+IPD,0,10:ab\r\nCLOSED");
        e.input(b"\r\n+IPD,0,3:xyz");
        assert_eq!(e.take_events(), vec![Event::Data(0, b"ab\r\nCLOSED".to_vec()), Event::Data(0, b"xyz".to_vec())]);
        e.close(0);
        talk(&mut e, "AT+CIPCLOSE=0\r\n", b"0,CLOSED\r\n\r\nOK\r\n");
        assert_eq!(e.take_events(), vec![Event::Closed(0)]);
        assert!(!e.busy());
    }

    /// The +IPD header split across reads.
    #[test]
    fn split_ipd() {
        let mut e = ready();
        for b in b"+IPD,1,4:da\x7eta".iter().take(14) {
            e.input(&[*b]);
        }
        assert_eq!(e.take_events(), vec![Event::Data(1, b"da\x7et".to_vec())]);
    }

    #[test]
    fn failed_dial_and_queue() {
        let mut e = ready();
        e.dial_tcp(0, "10.0.0.1", 1);
        e.dial_udp(1, "hub.example", 51820, 4000);
        talk(&mut e, "AT+CIPSTART=0,\"TCP\",\"10.0.0.1\",1\r\n", b"0,CONNECT FAIL\r\n\r\nERROR\r\n");
        talk(&mut e, "AT+CIPSTART=1,\"UDP\",\"hub.example\",51820,4000,0\r\n", b"1,CONNECT\r\n\r\nOK\r\n");
        assert_eq!(e.take_events(), vec![Event::Failed(0, "ERROR".into()), Event::Connected(1)]);
    }

    /// A lost send closes its connection.
    #[test]
    fn send_fail_closes() {
        let mut e = ready();
        e.send(2, b"abc");
        talk(&mut e, "AT+CIPSEND=2,3\r\n", b"\r\nOK\r\n> ");
        talk(&mut e, "abc", b"\r\nSEND FAIL\r\n");
        talk(&mut e, "AT+CIPCLOSE=2\r\n", b"2,CLOSED\r\n\r\nOK\r\n");
        assert_eq!(e.take_events(), vec![Event::Closed(2)]);
    }

    /// The ESP restarts: its banner, then `ready`; the setup runs again.
    #[test]
    fn reset() {
        let mut e = ready();
        e.input(b"\r\n\x00\xff garbage ets Jan  8 2013\r\n\r\nready\r\n");
        assert_eq!(e.take_events(), vec![Event::Reset]);
        assert!(!e.ready());
        assert_eq!(e.take_output(), b"AT\r\n");
    }

    #[test]
    fn timeout_restarts() {
        let mut e = ready();
        e.dial_tcp(3, "10.0.0.2", 80);
        e.take_output();
        e.timeout();
        assert_eq!(e.take_events(), vec![Event::Failed(3, "the ESP did not answer".into())]);
        assert_eq!(e.take_output(), b"AT\r\n");
    }

    #[test]
    fn host_cannot_break_the_command() {
        let mut e = ready();
        e.dial_tcp(0, "a\",\"UDP\r\nAT+RST", 1);
        assert_eq!(e.take_output(), b"AT+CIPSTART=0,\"TCP\",\"aUDPAT+RST\",1\r\n");
    }

    #[test]
    fn big_send_in_blocks() {
        let mut e = ready();
        e.send(0, &vec![7u8; SEND_MAX + 1]);
        assert_eq!(e.take_output(), format!("AT+CIPSEND=0,{SEND_MAX}\r\n").as_bytes());
        e.input(b"OK\r\n>");
        assert_eq!(e.take_output().len(), SEND_MAX);
        e.input(b"\r\nSEND OK\r\n");
        assert_eq!(e.take_output(), b"AT+CIPSEND=0,1\r\n");
    }
}
