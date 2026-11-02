// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! `cbb next link` as a program: this test plays the Next's driver and its
//! ESP8266 on the link's standard input and output, with the frames written
//! out again here from the description in docs/roadmap.md, and the ESP's
//! connection a real one to an echo server, so a member's bytes go through
//! the link to the peer and back.

use std::io::{BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

const START: u8 = 0x7E;

fn frame(kind: u8, data: &[u8]) -> Vec<u8> {
    let mut out = vec![START];
    let mut sum = kind.wrapping_add(data.len() as u8);
    let mut put = |b: u8| {
        out.push(b);
        if b == START {
            out.push(START);
        }
    };
    put(kind);
    put(data.len() as u8);
    for &b in data {
        sum = sum.wrapping_add(b);
        put(b);
    }
    put(sum);
    out
}

/// Reads one frame (no lost bytes on a pipe) and counts the wire bytes.
fn read_frame(r: &mut impl Read, taken: &mut u16) -> (u8, Vec<u8>) {
    let mut byte = || {
        let mut b = [0u8];
        r.read_exact(&mut b).expect("the link closed its output");
        *taken = taken.wrapping_add(1);
        b[0]
    };
    while byte() != START {}
    let mut unstuff = || {
        let b = byte();
        if b == START {
            assert_eq!(byte(), START, "a single start byte inside a frame");
        }
        b
    };
    let kind = unstuff();
    let len = unstuff() as usize;
    let data: Vec<u8> = (0..len).map(|_| unstuff()).collect();
    let sum = data.iter().fold(kind.wrapping_add(len as u8), |s, &b| s.wrapping_add(b));
    assert_eq!(unstuff(), sum, "the frame's sum");
    (kind, data)
}

#[test]
fn bytes_through_the_esp_and_back() {
    let echo = TcpListener::bind("127.0.0.1:0").unwrap();
    let echo_port = echo.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for s in echo.incoming().flatten() {
            let mut w = s.try_clone().unwrap();
            std::io::copy(&mut &s, &mut w).ok();
        }
    });
    // A free port for the link's own.
    let port = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let mut child = Command::new(env!("CARGO_BIN_EXE_cbb"))
        .args(["next", "link", "-to", &format!("127.0.0.1:{echo_port}"), "-port", &port.to_string()])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut to_link = child.stdin.take().unwrap();
    let mut from_link = BufReader::new(child.stdout.take().unwrap());
    // The link's line once the UART is raw; .cbb turns the driver on only
    // then, so the driver never counts it.
    let mut ready = [0u8; 9];
    from_link.read_exact(&mut ready).unwrap();
    assert_eq!(&ready, b"CBBLINK\r\n");
    to_link.write_all(&frame(b'H', b"test driver")).unwrap();

    // The fake ESP: AT lines in, answers out; its connection 0 is a real
    // socket to the echo server, whose bytes come back as +IPD.
    let (tx, rx) = mpsc::channel::<Vec<u8>>();
    let mut taken = 0u16;
    let mut esp_in = Vec::new();
    let mut peer: Option<TcpStream> = None;
    let mut sending: Option<usize> = None;
    let mut member: Option<TcpStream> = None;
    let mut mux = false;
    let mut got = Vec::new();
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    while got.len() < 4 {
        assert!(std::time::Instant::now() < deadline, "no echo through the link; got {got:?}");
        let (kind, data) = read_frame(&mut from_link, &mut taken);
        assert_eq!(kind, b'e');
        to_link.write_all(&frame(b'A', &taken.to_le_bytes())).unwrap();
        esp_in.extend(data);
        let mut answers = Vec::new();
        loop {
            if let Some(n) = sending {
                if esp_in.len() < n {
                    break;
                }
                let bytes: Vec<u8> = esp_in.drain(..n).collect();
                peer.as_mut().unwrap().write_all(&bytes).unwrap();
                sending = None;
                answers.extend_from_slice(b"\r\nSEND OK\r\n");
                continue;
            }
            let Some(end) = esp_in.windows(2).position(|w| w == b"\r\n") else { break };
            let line = String::from_utf8(esp_in.drain(..end + 2).take(end).collect()).unwrap();
            if let Some(rest) = line.strip_prefix("AT+CIPSTART=4,\"TCP\",\"127.0.0.1\",") {
                let p: u16 = rest.parse().unwrap();
                let s = TcpStream::connect(("127.0.0.1", p)).unwrap();
                let (mut r, tx) = (s.try_clone().unwrap(), tx.clone());
                std::thread::spawn(move || {
                    let mut buf = [0u8; 256];
                    while let Ok(n @ 1..) = r.read(&mut buf) {
                        tx.send(buf[..n].to_vec()).ok();
                    }
                });
                peer = Some(s);
                answers.extend_from_slice(b"4,CONNECT\r\n\r\nOK\r\n");
            } else if let Some(n) = line.strip_prefix("AT+CIPSEND=4,") {
                sending = Some(n.parse().unwrap());
                answers.extend_from_slice(b"\r\nOK\r\n> ");
            } else {
                mux |= line == "AT+CIPMUX=1";
                answers.extend_from_slice(b"\r\nOK\r\n");
            }
        }
        if !answers.is_empty() {
            to_link.write_all(&frame(b'E', &answers)).unwrap();
        }
        // Once the ESP is set up, the member dials the link's port.
        if member.is_none() && mux {
            let mut m = TcpStream::connect(("127.0.0.1", port)).unwrap();
            m.write_all(b"ping").unwrap();
            m.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            member = Some(m);
        }
        let sent = answers.windows(7).any(|w| w == b"SEND OK");
        if sent {
            let b = rx.recv_timeout(Duration::from_secs(5)).expect("the echo");
            let mut ipd = format!("\r\n+IPD,4,{}:", b.len()).into_bytes();
            ipd.extend(b);
            to_link.write_all(&frame(b'E', &ipd)).unwrap();
            let m = member.as_mut().unwrap();
            let mut buf = [0u8; 16];
            let n = m.read(&mut buf).expect("the echo through the link");
            got.extend_from_slice(&buf[..n]);
        }
    }
    assert_eq!(got, b"ping");
    to_link.write_all(&frame(b'Q', b"")).unwrap();
    let status = child.wait().unwrap();
    assert!(status.success());
}
