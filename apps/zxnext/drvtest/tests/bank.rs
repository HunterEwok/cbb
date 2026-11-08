// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! cbb.drv's bank (drv/bank.asm, `make build/drv/bank.bin` first) in a Z80
//! emulator, with the Next's two UARTs, its system variables and NextZXOS's
//! clock call played here; the frames written out again from
//! member/README.md, "The network through the Next's ESP8266".

use std::collections::VecDeque;

use iz80::{Cpu, Machine, Reg8, Reg16};

const START: u8 = 0x7E;
const LAST_K: u16 = 23560;
const FLAGS: u16 = 23611;
/// Where a call returns: a HALT the test stops at.
const DONE: u16 = 0x0100;

#[derive(Default)]
struct Uart {
    rx: VecDeque<u8>,
    tx: Vec<u8>,
    over: bool,
    /// Bytes the send buffer takes until the next interrupt; None for no
    /// limit.
    room: Option<usize>,
}

struct Next {
    mem: Vec<u8>,
    select: u8,
    esp: Uart,
    pi: Uart,
    /// The Next registers, the one selected, and the 8K banks MMU6 shows.
    nr: [u8; 256],
    nr_sel: u8,
    banks: std::collections::HashMap<u8, Vec<u8>>,
    /// Layer 2's palette (9-bit entries), its index, a first byte waiting.
    pal: [u16; 256],
    pal_first: Option<u8>,
    clip: [u8; 4],
    clip_index: usize,
    port_l2: u8,
    border: Vec<u8>,
    /// The keyboard's reads: a key is down from the read keys_at for 10.
    key_reads: usize,
    keys_at: usize,
    /// The palette, resolution and Layer 2 when the key went down.
    shown: Option<([u16; 256], u8, u8)>,
}

const MMU6: u16 = 0xC000;

impl Next {
    fn mapped(&self, a: u16) -> bool {
        (MMU6..0xE000).contains(&a) && self.nr[0x56] != 0
    }
    fn nr_read(&mut self, r: u8) -> u8 {
        match r {
            // A read leaves the index; a write moves it on.
            0x18 => self.clip[self.clip_index],
            0x41 => (self.pal[self.nr[0x40] as usize] >> 1) as u8,
            0x44 => (self.pal[self.nr[0x40] as usize] & 1) as u8,
            r => self.nr[r as usize],
        }
    }
    fn nr_write(&mut self, r: u8, v: u8) {
        match r {
            0x18 => {
                self.clip[self.clip_index] = v;
                self.clip_index = (self.clip_index + 1) % 4;
            }
            0x1C => {
                if v & 1 != 0 {
                    self.clip_index = 0;
                }
            }
            0x40 => {
                self.nr[0x40] = v;
                self.pal_first = None;
            }
            0x44 => match self.pal_first.take() {
                None => self.pal_first = Some(v),
                Some(f) => {
                    let i = self.nr[0x40];
                    self.pal[i as usize] = (f as u16) << 1 | (v & 1) as u16;
                    self.nr[0x40] = i.wrapping_add(1);
                }
            },
            0x56 => {
                self.banks.entry(v).or_insert_with(|| vec![0xAA; 8192]);
                self.nr[0x56] = v;
            }
            r => self.nr[r as usize] = v,
        }
    }
}

impl Next {
    fn uart(&mut self) -> &mut Uart {
        if self.select & 0x40 != 0 {
            &mut self.pi
        } else {
            &mut self.esp
        }
    }
}

impl Machine for Next {
    fn peek(&mut self, a: u16) -> u8 {
        if self.mapped(a) {
            return self.banks[&self.nr[0x56]][(a - MMU6) as usize];
        }
        self.mem[a as usize]
    }
    fn poke(&mut self, a: u16, v: u8) {
        if self.mapped(a) {
            let b = self.nr[0x56];
            self.banks.get_mut(&b).unwrap()[(a - MMU6) as usize] = v;
            return;
        }
        self.mem[a as usize] = v;
    }
    fn port_in(&mut self, a: u16) -> u8 {
        match a {
            0x133B => {
                let u = self.uart();
                let full = u.room == Some(0);
                let s = (!u.rx.is_empty()) as u8 | (full as u8) << 1 | (u.over as u8) << 2;
                u.over = false;
                s
            }
            0x143B => self.uart().rx.pop_front().unwrap_or(0),
            0x153B => self.select,
            0x253B => {
                let r = self.nr_sel;
                self.nr_read(r)
            }
            0x123B => self.port_l2,
            a if a & 0xFF == 0xFE => {
                self.key_reads += 1;
                let down = (self.keys_at..self.keys_at + 10).contains(&self.key_reads);
                if down && self.shown.is_none() {
                    self.shown = Some((self.pal, self.nr[0x70], self.port_l2));
                }
                if down { 0xFE } else { 0xFF }
            }
            _ => panic!("the driver read port {a:#06x}"),
        }
    }
    fn port_out(&mut self, a: u16, v: u8) {
        match a {
            0x133B => {
                let u = self.uart();
                assert_ne!(u.room, Some(0), "the driver sent into a full buffer");
                u.room = u.room.map(|r| r - 1);
                u.tx.push(v);
            }
            0x153B => self.select = v,
            0x243B => self.nr_sel = v,
            0x253B => {
                let r = self.nr_sel;
                self.nr_write(r, v)
            }
            0x123B => self.port_l2 = v,
            a if a & 0xFF == 0xFE => self.border.push(v & 7),
            _ => panic!("the driver wrote port {a:#06x}"),
        }
    }
}

struct Driver {
    cpu: Cpu,
    next: Next,
}

impl Driver {
    fn new() -> Driver {
        let mut mem = vec![0u8; 0x10000];
        let bank = std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../build/drv/bank.bin"
        ))
        .expect("make build/drv/bank.bin first");
        mem[0xE000..0xE000 + bank.len()].copy_from_slice(&bank);
        mem[DONE as usize] = 0x76; // HALT
        // drv_drvrtc: BC = 2026-11-02, DE = 01:30:14, carry clear.
        let rtc = [0x01, 0x62, 0x5D, 0x11, 0xC7, 0x0B, 0xA7, 0xC9]; // ld bc / ld de / and a / ret
        mem[0x2003..0x2003 + rtc.len()].copy_from_slice(&rtc);
        let esp = Uart {
            room: Some(64),
            ..Uart::default()
        };
        Driver {
            cpu: Cpu::new_z80(),
            next: Next {
                mem,
                select: 0x40,
                esp,
                pi: Uart::default(),
                nr: [0; 256],
                nr_sel: 0,
                banks: Default::default(),
                pal: [0; 256],
                pal_first: None,
                clip: [0, 159, 0, 255],
                clip_index: 0,
                port_l2: 0,
                border: Vec::new(),
                key_reads: 0,
                keys_at: usize::MAX - 20,
                shown: None,
            },
        }
    }

    /// Calls addr with registers BC and DE and runs to its RET.
    fn call(&mut self, addr: u16, bc: u16, de: u16) {
        let r = self.cpu.registers();
        r.set16(Reg16::SP, 0x3F00);
        r.set16(Reg16::BC, bc);
        r.set16(Reg16::DE, de);
        r.set_pc(addr);
        self.next.mem[0x3EFE] = DONE as u8;
        self.next.mem[0x3EFF] = (DONE >> 8) as u8;
        self.cpu.registers().set16(Reg16::SP, 0x3EFE);
        for _ in 0..20_000_000 {
            if self.cpu.registers().pc() == DONE {
                return;
            }
            self.cpu.execute_instruction(&mut self.next);
        }
        panic!("the call to {addr:#06x} did not return");
    }

    fn interrupt(&mut self) {
        // The ESP's 64-byte buffer sends about 38 bytes a frame at 19200
        // baud; here it empties between interrupts.
        if self.next.esp.room.is_some() {
            self.next.esp.room = Some(64);
        }
        self.call(0xE003, 0, 0);
    }

    fn on(&mut self) {
        self.call(0xE000, 0x0200, 0x0001); // DRIVER 124,2,1: DE = 1
    }

    /// The frames the Pi got since the last call.
    fn pi_frames(&mut self) -> Vec<(u8, Vec<u8>)> {
        frames(&std::mem::take(&mut self.next.pi.tx))
    }
}

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

fn frames(wire: &[u8]) -> Vec<(u8, Vec<u8>)> {
    let mut out = Vec::new();
    let mut i = 0;
    let next = |i: &mut usize| {
        let b = wire[*i];
        *i += 1;
        if b == START {
            assert_eq!(
                wire[*i], START,
                "a single start byte inside a frame: {wire:02x?}"
            );
            *i += 1;
        }
        b
    };
    while i < wire.len() {
        assert_eq!(
            wire[i], START,
            "a frame starts with the start byte: {wire:02x?}"
        );
        i += 1;
        let kind = next(&mut i);
        let len = next(&mut i) as usize;
        let data: Vec<u8> = (0..len).map(|_| next(&mut i)).collect();
        let sum = data
            .iter()
            .fold(kind.wrapping_add(len as u8), |s, &b| s.wrapping_add(b));
        assert_eq!(next(&mut i), sum, "the sum of a {} frame", kind as char);
        out.push((kind, data));
    }
    out
}

fn kinds(f: &[(u8, Vec<u8>)]) -> String {
    f.iter().map(|(k, _)| *k as char).collect()
}

#[test]
fn off_until_turned_on() {
    let mut d = Driver::new();
    d.next.pi.rx.extend(b"SUP> ");
    d.interrupt();
    assert!(d.next.pi.tx.is_empty() && d.next.esp.tx.is_empty());
    assert_eq!(d.next.pi.rx.len(), 5, "it reads nothing while off");
}

#[test]
fn hello_clock_and_the_esp_both_ways() {
    let mut d = Driver::new();
    d.on();
    d.next.pi.rx.extend(b"SUP> "); // the shell's prompt before the link starts
    d.next.pi.rx.extend(frame(b'e', b"AT\r\n"));
    d.next.esp.rx.extend(b"ready\r\n");
    d.interrupt();
    assert_eq!(d.next.esp.tx, b"AT\r\n");
    let f = d.pi_frames();
    assert_eq!(kinds(&f), "EAHT", "{f:?}");
    assert_eq!(f[0].1, b"ready\r\n");
    assert_eq!(
        f[1].1,
        (5 + 8u16).to_le_bytes(),
        "the bytes taken from the Pi"
    );
    assert_eq!(f[2].1, b"cbb.drv 0.3");
    assert_eq!(
        f[3].1,
        [0x62, 0x5D, 0xC7, 0x0B],
        "date then time, little-endian"
    );
    assert_eq!(d.next.select, 0x40, "the UART it found is selected again");
    d.call(0xE000, 0x0400, 0);
    let r = d.cpu.registers();
    assert_eq!(
        (r.get16(Reg16::BC), r.get16(Reg16::DE)),
        (4, 7),
        "bytes to and from the ESP"
    );
    // Nothing new: no frames.
    d.interrupt();
    assert!(d.pi_frames().is_empty());
}

/// Start bytes inside a frame in both directions, and a long burst from
/// the ESP in frames of at most 48 bytes.
#[test]
fn start_bytes_and_bursts() {
    let mut d = Driver::new();
    d.on();
    d.interrupt();
    d.pi_frames();
    d.next.pi.rx.extend(frame(b'e', &[START, 1, START, START]));
    let burst: Vec<u8> = (0..100u8)
        .map(|i| if i % 7 == 0 { START } else { i })
        .collect();
    d.next.esp.rx.extend(&burst);
    d.interrupt();
    d.interrupt();
    d.interrupt();
    assert_eq!(d.next.esp.tx, [START, 1, START, START]);
    let got: Vec<u8> = d
        .pi_frames()
        .into_iter()
        .filter(|(k, _)| *k == b'E')
        .flat_map(|(_, b)| b)
        .collect();
    assert_eq!(got, burst);
}

/// A frame with a wrong sum is dropped and counted; the next one goes.
#[test]
fn wrong_sum() {
    let mut d = Driver::new();
    d.on();
    let mut bad = frame(b'e', b"lost");
    *bad.last_mut().unwrap() ^= 1;
    d.next.pi.rx.extend(bad);
    d.next.pi.rx.extend(frame(b'e', b"kept"));
    d.interrupt();
    assert_eq!(d.next.esp.tx, b"kept");
    d.call(0xE000, 0x0100, 0);
    assert_eq!(d.cpu.registers().get16(Reg16::DE), 1, "dropped frames");
    // The dropped frame: type e, length 4, the sum so far and the bad sum.
    d.call(0xE000, 0x0500, 0);
    let r = d.cpu.registers();
    let good = frame(b'e', b"lost");
    let sum = *good.last().unwrap();
    assert_eq!(r.get16(Reg16::BC), 0x0400 | b'e' as u16);
    assert_eq!(r.get16(Reg16::DE), ((sum ^ 1) as u16) << 8 | sum as u16);
    assert_eq!(r.get16(Reg16::HL), 16, "the bytes taken");
    // The first six bytes from the Pi, kept from index 1.
    d.call(0xE000, 0x0600, 1);
    let r = d.cpu.registers();
    assert_eq!(r.get16(Reg16::BC), u16::from_le_bytes([0x7E, b'e']));
}

/// Keys: one a frame, each once the program took the last (FLAGS bit 5).
#[test]
fn keys() {
    let mut d = Driver::new();
    d.on();
    d.next.pi.rx.extend(frame(b'K', b"10 PRINT\r"));
    let mut typed = Vec::new();
    for _ in 0..30 {
        d.interrupt();
        if d.next.mem[FLAGS as usize] & 0x20 != 0 {
            typed.push(d.next.mem[LAST_K as usize]);
            d.next.mem[FLAGS as usize] &= !0x20; // the ROM took it
        }
    }
    assert_eq!(typed, b"10 PRINT\r");
}

/// The ESP's ring fills up: the driver leaves the Pi's bytes in its UART
/// until there is room, so nothing is lost.
#[test]
fn ring_full_holds_the_pi() {
    let mut d = Driver::new();
    d.on();
    let mut sent = Vec::new();
    for i in 0..8u8 {
        let data = vec![i; 200];
        d.next.pi.rx.extend(frame(b'e', &data));
        sent.extend(data);
    }
    d.interrupt();
    assert_eq!(d.next.esp.tx.len(), 64, "one buffer's worth a frame");
    assert!(
        !d.next.pi.rx.is_empty(),
        "some frames wait in the Pi's UART"
    );
    for _ in 0..30 {
        d.interrupt();
    }
    assert_eq!(d.next.esp.tx, sent);
    d.call(0xE000, 0x0100, 0);
    assert_eq!(d.cpu.registers().get16(Reg16::DE), 0, "no frame dropped");
}

#[test]
fn quit_turns_it_off() {
    let mut d = Driver::new();
    d.on();
    d.next.pi.rx.extend(frame(b'Q', b""));
    d.interrupt();
    d.call(0xE000, 0x0300, 0);
    assert_eq!(d.cpu.registers().get8(Reg8::A), 0);
    assert_eq!(d.cpu.registers().get16(Reg16::DE), 0);
    d.on();
    d.call(0xE000, 0x0300, 0);
    assert_eq!(
        d.cpu.registers().get16(Reg16::DE),
        1,
        "the state in DE for M_DRVAPI"
    );
}

/// The Pi's bytes come a few at a time, between interrupts, after the
/// shell's echo of the driver's own hello.
#[test]
fn bytes_one_at_a_time() {
    let mut d = Driver::new();
    d.on();
    let mut wire = b"cbb next link\r\n~H^K".to_vec();
    for _ in 0..3 {
        wire.extend(frame(b'e', b"AT\r\n"));
    }
    for b in wire {
        d.next.pi.rx.push_back(b);
        d.interrupt();
    }
    d.interrupt();
    assert_eq!(d.next.esp.tx, b"AT\r\nAT\r\nAT\r\n");
}

/// A second run counts the Pi's bytes from 0 again, as the link does: an
/// ack with the count of the run before would close the link's window.
#[test]
fn turned_on_again_counts_from_zero() {
    let mut d = Driver::new();
    d.on();
    d.next.pi.rx.extend(b"cbb next link\r\n");
    d.next.pi.rx.extend(frame(b'Q', b""));
    d.interrupt();
    d.pi_frames();
    d.on();
    d.call(0xE000, 0x0100, 0);
    assert_eq!(d.cpu.registers().get16(Reg16::HL), 0, "bytes taken");
    d.next.pi.rx.push_back(b'\n'); // the end of CBBLINK's line
    d.interrupt();
    let f = d.pi_frames();
    assert_eq!(kinds(&f), "AHT", "{f:?}");
    assert_eq!(
        f[0].1,
        1u16.to_le_bytes(),
        "the first ack counts this run only"
    );
}

impl Driver {
    /// Call 7 with D and E.
    fn cbb_out(&mut self, d: u8, e: u8) {
        self.call(0xE000, 0x0700, (d as u16) << 8 | e as u16);
        assert!(
            !self.cpu.registers().get_flag(iz80::Flag::C),
            "call 7 failed"
        );
    }
    /// Call 8 until it has nothing: what .cbb reads.
    fn cbb_in(&mut self) -> Vec<u8> {
        let mut got = Vec::new();
        loop {
            self.call(0xE000, 0x0800, 0);
            let de = self.cpu.registers().get16(Reg16::DE);
            if de >> 8 == 0 {
                return got;
            }
            got.push(de as u8);
        }
    }
}

/// .cbb's command goes to the Pi in frames while the network runs, and the
/// Pi's answers come back through their own ring.
#[test]
fn carries_cbbs_commands() {
    let mut d = Driver::new();
    d.on();
    d.interrupt();
    d.pi_frames();
    d.next.select = 0x00; // .cbb may have the ESP's selected
    d.cbb_out(0, 0);
    for &b in b"cbb next paste -max 8192\n" {
        d.cbb_out(1, b);
    }
    assert_eq!(d.next.select, 0x00, "the UART it found is selected again");
    // The bytes wait for the interrupt, which sends them in one frame.
    assert!(d.pi_frames().is_empty());
    d.interrupt();
    let f = d.pi_frames();
    assert_eq!(
        f.iter().find(|f| f.0 == b'C').map(|f| f.1.clone()),
        Some(b"cbb next paste -max 8192\n".to_vec()),
        "{f:?}"
    );
    d.next.pi.rx.extend(frame(b'c', b"CBB1 2 0\rhi\r"));
    d.next.pi.rx.extend(frame(b'e', b"AT\r\n"));
    d.next.pi.rx.extend(frame(b'c', b"CBBOK\r\r\nSUP>"));
    d.interrupt();
    assert_eq!(d.cbb_in(), b"CBB1 2 0\rhi\rCBBOK\r\r\nSUP>");
    assert_eq!(d.next.esp.tx, b"AT\r\n", "the network goes on meanwhile");
    // 64 bytes go at once; a stop sends what waits, then an empty frame.
    for i in 0..70u8 {
        d.cbb_out(1, i);
    }
    d.cbb_out(3, 0);
    let f: Vec<_> = d.pi_frames().into_iter().filter(|f| f.0 == b'C').collect();
    assert_eq!(f.iter().map(|f| f.1.len()).collect::<Vec<_>>(), [64, 6, 0]);
    d.cbb_out(4, 0);
}

/// Answers nobody reads are dropped, and never hold the network up; an
/// open ring holds the Pi in its UART when it is full.
#[test]
fn answers_wait_only_while_open() {
    let mut d = Driver::new();
    d.on();
    for _ in 0..8 {
        d.next.pi.rx.extend(frame(b'c', &[b'x'; 200]));
    }
    d.next.pi.rx.extend(frame(b'e', b"AT\r\n"));
    d.interrupt();
    assert_eq!(d.next.esp.tx, b"AT\r\n");
    assert!(d.cbb_in().is_empty(), "closed: nothing kept");
    d.cbb_out(0, 0);
    for _ in 0..8 {
        d.next.pi.rx.extend(frame(b'c', &[b'y'; 200]));
    }
    d.next.pi.rx.extend(frame(b'e', b"AT\r\n"));
    d.interrupt();
    assert!(!d.next.pi.rx.is_empty(), "the rest waits in the Pi's UART");
    let mut got = d.cbb_in();
    for _ in 0..10 {
        d.interrupt();
        got.extend(d.cbb_in());
    }
    assert_eq!(got, vec![b'y'; 1600]);
    assert_eq!(d.next.esp.tx, b"AT\r\nAT\r\n");
    d.call(0xE000, 0x0100, 0);
    assert_eq!(d.cpu.registers().get16(Reg16::DE), 0, "no frame dropped");
}

impl Driver {
    /// Call 9: the start in the background; its E.
    fn boot(&mut self, d: u8, e: u8) -> u8 {
        self.call(0xE000, 0x0900, (d as u16) << 8 | e as u16);
        assert!(
            !self.cpu.registers().get_flag(iz80::Flag::C),
            "call 9 refused"
        );
        self.cpu.registers().get8(Reg8::E)
    }

    fn arm(&mut self, line: &[u8]) {
        self.boot(0, 0);
        for &b in line {
            self.boot(1, b);
        }
        self.boot(2, 0);
    }

    fn enabled(&mut self) -> bool {
        self.call(0xE000, 0x0300, 0);
        self.cpu.registers().get16(Reg16::DE) != 0
    }
}

/// Just after power-on the driver waits for NextPi's shell, pressing Enter
/// now and then, types the line once the shell is quiet, and turns itself
/// on when the link says CBBLINK, the rest of the Pi's bytes then frames.
#[test]
fn starts_the_network_once_the_pi_is_up() {
    let mut d = Driver::new();
    let line = b"cbb next link -to 192.168.0.175:8764 -serve 8764:8764\n";
    d.arm(line);
    assert_eq!(d.boot(3, 0), 1, "waits for the prompt");
    // Boot messages, but no prompt: an Enter every two seconds.
    for i in 0..300 {
        if i % 10 == 0 {
            d.next.pi.rx.extend(b"[    3.1] systemd: starting\r\n");
        }
        d.interrupt();
        assert!(!d.enabled());
    }
    let enters = d.next.pi.tx.iter().filter(|&&b| b == b'\n').count();
    assert!((2..=4).contains(&enters), "{enters} Enters in six seconds");
    assert!(
        d.next.pi.tx.iter().all(|&b| b == b'\n'),
        "only Enters before the prompt"
    );
    d.next.pi.tx.clear();
    d.next.pi.rx.extend(b"NextPi ready\r\nSU");
    d.interrupt();
    d.next.pi.rx.extend(b"P>");
    d.interrupt();
    assert_eq!(d.boot(3, 0), 2, "the prompt: waits for quiet");
    for _ in 0..30 {
        d.interrupt();
    }
    // An Enter may still have gone just before the prompt came.
    let typed: Vec<u8> = d
        .next
        .pi
        .tx
        .iter()
        .copied()
        .skip_while(|&b| b == b'\n')
        .collect();
    assert_eq!(typed, line, "the line, once");
    assert_eq!(d.boot(3, 0), 4, "waits for the link");
    // The shell's echo, then CBBLINK and a frame in the same burst.
    d.next.pi.rx.extend(&line[..line.len() - 1]);
    d.next.pi.rx.extend(b"\r\nCBBLINK\r\n");
    d.next.pi.rx.extend(frame(b'e', b"AT\r\n"));
    d.interrupt();
    assert!(d.enabled(), "on");
    assert_eq!(d.boot(3, 0), 7);
    d.next.pi.tx.clear();
    d.interrupt();
    assert_eq!(
        d.next.esp.tx, b"AT\r\n",
        "the frame after CBBLINK went to the ESP"
    );
    let kinds: Vec<u8> = d.pi_frames().iter().map(|f| f.0).collect();
    assert!(kinds.contains(&b'H'), "a hello: {kinds:?}");
    assert_eq!(d.next.select, 0x40, "the UART selection is kept");
}

/// A Pi that never shows its prompt: after three minutes the start gives
/// up, says so in its state, and the driver stays off; turning the driver
/// off ends a start that waits.
#[test]
fn gives_up_when_the_pi_does_not_start() {
    let mut d = Driver::new();
    d.arm(b"cbb next link\n");
    for _ in 0..9000 {
        d.interrupt();
    }
    assert_eq!(d.boot(3, 0), 5, "no prompt");
    assert!(!d.enabled());
    assert_eq!(d.next.pi.tx.last(), Some(&3), "Ctrl-C at the end");
    d.next.pi.tx.clear();
    d.next.pi.rx.extend(b"SUP>");
    for _ in 0..40 {
        d.interrupt();
    }
    assert!(d.next.pi.tx.is_empty(), "nothing typed after giving up");
    d.arm(b"cbb next link\n");
    d.call(0xE000, 0x0200, 0); // off
    assert_eq!(d.boot(3, 0), 0);
    d.next.pi.rx.extend(b"SUP>");
    for _ in 0..40 {
        d.interrupt();
    }
    assert!(d.next.pi.tx.is_empty());
}

/// The line holds 255 bytes; one more is refused.
#[test]
fn the_line_has_room_for_255_bytes() {
    let mut d = Driver::new();
    d.boot(0, 0);
    for _ in 0..255 {
        d.boot(1, b'x');
    }
    d.call(0xE000, 0x0900, 0x0100 | b'x' as u16);
    assert!(d.cpu.registers().get_flag(iz80::Flag::C));
}

/// The bytes of a test image: 81920 of pixels, then the palette.
fn test_image(hi: bool) -> Vec<u8> {
    let mut b: Vec<u8> = (0..81920u32).map(|i| (i * 7 + i / 256) as u8).collect();
    let n = if hi { 16 } else { 256 };
    for i in 0..n {
        b.push(i as u8 ^ 0x5A);
        b.push((i & 1) as u8);
    }
    b
}

fn head(mode: u8, bytes: &[u8]) -> Vec<u8> {
    let sum = bytes.iter().fold(0u16, |s, &b| s.wrapping_add(b as u16));
    frame(b'J', &[mode, sum as u8, (sum >> 8) as u8])
}

/// What the driver must put back after an image.
fn screen_before(d: &mut Driver) {
    for (i, r) in [0x12u8, 0x14, 0x15, 0x16, 0x17, 0x43, 0x6B, 0x70, 0x71].into_iter().enumerate() {
        d.next.nr[r as usize] = 0x11 + i as u8;
    }
    d.next.nr[0x56] = 0; // MMU6 as the program left it (0: not banked here)
    d.next.clip = [8, 150, 4, 250];
    d.next.port_l2 = 0x01;
    for (i, e) in d.next.pal.iter_mut().enumerate() {
        *e = (i as u16 * 3) & 0x1FF;
    }
    d.next.mem[23624] = 5 << 3; // BORDCR: a cyan border
}

#[test]
fn shows_an_image_over_the_program_and_puts_the_screen_back() {
    let mut d = Driver::new();
    d.on();
    d.interrupt();
    d.pi_frames();
    screen_before(&mut d);
    let (pal, clip) = (d.next.pal, d.next.clip);
    let regs = d.next.nr;
    d.call(0xE000, 0x0A00, 0x1F28); // call 10: banks 40-49, state 31
    assert_eq!(d.cpu.registers().get16(Reg16::DE), 0, "no banks before");
    let img = test_image(false);
    d.next.pi.rx.extend(frame(b'I', &[]));
    d.next.pi.rx.extend(head(b'L', &img));
    d.next.pi.rx.extend(img.iter());
    d.next.keys_at = 5000;
    d.interrupt();
    assert!(kinds(&d.pi_frames()).contains('i'), "it asks for the image");
    assert!(d.next.pi.rx.is_empty(), "every byte read");
    for k in 0..10u8 {
        let bank = &d.next.banks[&(40 + k)];
        assert_eq!(&bank[..], &img[k as usize * 8192..(k as usize + 1) * 8192], "bank {}", 40 + k);
    }
    let (shown, res, l2) = d.next.shown.expect("a key was waited for");
    assert_eq!(res, 0x10, "320x256");
    assert_eq!(l2, 0x02, "Layer 2 on");
    for i in 0..256 {
        assert_eq!(shown[i], (img[81920 + 2 * i] as u16) << 1 | img[81921 + 2 * i] as u16, "colour {i}");
    }
    // A column a flip: 320 flips of blue and yellow, then the blinking.
    assert!(d.next.border.windows(2).filter(|w| w == &[1, 6]).count() >= 150);
    // The screen as it was.
    assert_eq!(d.next.pal, pal);
    assert_eq!(d.next.clip, clip);
    assert_eq!(d.next.port_l2, 0x01);
    for r in [0x12usize, 0x14, 0x15, 0x16, 0x17, 0x43, 0x6B, 0x70, 0x71, 0x56] {
        assert_eq!(d.next.nr[r], regs[r], "register {r:#04x}");
    }
    assert_eq!(*d.next.border.last().unwrap(), 5, "the border BASIC set");
    // Off: the banks come back, and an image waits for none.
    d.call(0xE000, 0x0A00, 0);
    assert_eq!(d.cpu.registers().get16(Reg16::DE), 0x1F28);
    d.next.pi.rx.extend(frame(b'I', &[]));
    d.interrupt();
    assert!(!kinds(&d.pi_frames()).contains('i'));
}

#[test]
fn a_damaged_image_is_not_shown() {
    let mut d = Driver::new();
    d.on();
    d.interrupt();
    d.pi_frames();
    screen_before(&mut d);
    let pal = d.next.pal;
    d.call(0xE000, 0x0A00, 0x1F28);
    let img = test_image(true);
    let mut bad = img.clone();
    bad[1000] ^= 1;
    d.next.pi.rx.extend(frame(b'I', &[]));
    d.next.pi.rx.extend(head(b'H', &img));
    d.next.pi.rx.extend(bad.iter().take(81920 + 32));
    d.next.keys_at = 10;
    d.interrupt();
    assert!(d.next.shown.is_none(), "no key waited for");
    assert_eq!(d.next.pal, pal);
    assert_eq!(d.next.port_l2, 0x01);
}
