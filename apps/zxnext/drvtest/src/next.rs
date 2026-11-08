// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! A ZX Spectrum Next as far as a dot command sees it, for running `.cbb`
//! (build/CBB) here: the Z80N, the MMU, NextZXOS's restarts as the API
//! documents them (RST $8 hooks, RST $10, RST $18, the IM1 interrupt), the
//! card as a directory, the two UARTs with their 512-byte buffers and the
//! time a byte takes on the line, and the keyboard.
//!
//! The ROM's printing is played here too, in a character grid with the
//! ROM's rules: the upper screen is rows 0-21, AT 22 is "Out of screen",
//! printing past row 21 scrolls the whole screen.
//!
//! Besides running the command, it checks the rules a dot command must
//! keep (NextZXOS_and_esxDOS_APIs.pdf, "Dot commands" and the hooks; z88dk's
//! zxn_crt_798): writes only to its own pages, the screen and the system
//! variables; IY at ERR_NR when an interrupt comes; the stack outside the
//! divMMC area for RST $10, RST $18 and interrupts; code at 0xE000 runs
//! only from the overlay pages; M_P3DOS with MMU2 at the default. Each
//! breach is a `Breach`, with the PC.

use std::collections::VecDeque;
use std::path::{Path, PathBuf};

use iz80::{Cpu, Flag, Machine, Reg8, Reg16};

pub const PAGE: usize = 8192;
pub const PAGES: usize = 224;
/// Where the dot command returns to: a HALT in the divMMC ROM.
const DONE: u16 = 0x1F10;
/// EI; RET, where the interrupt returns through.
const EI_RET: u16 = 0x1F00;
/// Where NextZXOS starts the command from: IM 1, EI, JP 0x2000.
const START: u16 = 0x1F30;
/// An EXX for `Run::exx`.
const EXX: u16 = 0x1F20;
/// The interrupt's entry, one after 0x0038 (see `step`).
const ISR: u16 = 0x0039;
/// The system variables (bank 5 at 0x4000).
pub const ERR_NR: u16 = 0x5C3A;
pub const FRAMES: u16 = 23672;
pub const SCR_CT: u16 = 23692;
pub const ATTR_P: u16 = 23693;
pub const BORDCR: u16 = 23624;
pub const LAST_K: u16 = 23560;
/// The end of the system variables and the channel area: beyond is BASIC's.
const SYSVARS_END: u16 = 0x5D00;

#[derive(Debug, Clone)]
pub struct Breach {
    pub pc: u16,
    pub what: String,
}

/// A device on a UART: it is told each byte the Next sends, and gives the
/// bytes it sends back, each at a time.
pub trait Peer {
    /// A byte from the Next at time `now` (in microseconds), at the
    /// Next's speed `baud`.
    fn rx(&mut self, now: u64, byte: u8, baud: u32);
    /// The next byte towards the Next, if one is ready at `now`.
    fn tx(&mut self, now: u64) -> Option<u8>;
    /// The speed the device sends and listens at.
    fn baud(&self) -> u32;
    /// The device itself, for a test to look at afterwards.
    fn as_any(&mut self) -> &mut dyn std::any::Any;
    /// Its sound's level at `now`, for EAR (the Pi's I2S), if it plays.
    fn ear(&mut self, _now: u64) -> Option<bool> {
        None
    }
}

pub struct Uart {
    pub fifo: VecDeque<u8>,
    pub overflowed: bool,
    pub overflows: u32,
    prescaler: u32,
    /// When the next byte from the peer can arrive, in microseconds.
    next_rx: f64,
    /// Bytes the Next queued to send, and when the line is free again.
    tx_queue: usize,
    tx_free: f64,
    pub peer: Box<dyn Peer>,
}

impl Uart {
    pub fn new(peer: Box<dyn Peer>) -> Uart {
        Uart {
            fifo: VecDeque::new(),
            overflowed: false,
            overflows: 0,
            prescaler: 243, // 115200 at 28 MHz
            next_rx: 0.0,
            tx_queue: 0,
            tx_free: 0.0,
            peer,
        }
    }

    pub fn baud(&self) -> u32 {
        (28_000_000 / self.prescaler.max(1)) as u32
    }

    /// Microseconds a byte takes on the line, ten bits.
    fn byte_us(&self) -> f64 {
        10.0 * 1e6 / self.baud() as f64
    }

    /// Whether the two ends agree on the speed (within 4%).
    fn agree(&self) -> bool {
        let a = self.baud() as f64;
        let b = self.peer.baud() as f64;
        (a - b).abs() / b < 0.04
    }

    fn advance(&mut self, now: f64) {
        let byte = self.byte_us();
        // What the Next sends leaves at the line's speed.
        while self.tx_queue > 0 && self.tx_free <= now {
            self.tx_queue -= 1;
            self.tx_free += byte;
        }
        if self.tx_queue == 0 && self.tx_free < now {
            self.tx_free = now;
        }
        while self.next_rx <= now {
            match self.peer.tx(self.next_rx as u64) {
                Some(b) => {
                    let b = if self.agree() { b } else { b ^ 0x5A | 0x80 };
                    if self.fifo.len() >= 512 {
                        self.overflowed = true;
                        self.overflows += 1;
                    } else {
                        self.fifo.push_back(b);
                    }
                    self.next_rx += byte;
                }
                None => {
                    self.next_rx = now + 1.0;
                    break;
                }
            }
        }
    }

    fn send(&mut self, now: f64, b: u8) {
        let baud = self.baud();
        let b = if self.agree() { b } else { b ^ 0x5A | 0x80 };
        self.peer.rx(now as u64, b, baud);
        self.tx_queue += 1;
    }
}

/// A key held from one time to another, in microseconds: its half-row
/// (the port's high byte with one bit clear) and its bit.
#[derive(Clone, Copy, Debug)]
pub struct Key {
    pub from: u64,
    pub until: u64,
    pub row: u8,
    pub bit: u8,
}

pub const KEY_SPACE: (u8, u8) = (0x7F, 0);
pub const KEY_ENTER: (u8, u8) = (0xBF, 0);

/// The ROM's printing: a 32 x 24 grid of characters and attributes.
pub struct Screen {
    pub chars: [[u8; 32]; 24],
    pub attrs: [[u8; 32]; 24],
    pub row: u8,
    pub col: u8,
    pending: Vec<u8>,
    /// Scrolls of the upper screen the ROM made.
    pub scrolls: u32,
}

impl Screen {
    fn new() -> Screen {
        Screen {
            chars: [[b' '; 32]; 24],
            attrs: [[0x38; 32]; 24],
            row: 0,
            col: 0,
            pending: Vec::new(),
            scrolls: 0,
        }
    }

    /// The rows as text.
    pub fn text(&self) -> String {
        let mut s = String::new();
        for r in 0..24 {
            let line: String = self.chars[r]
                .iter()
                .map(|&c| {
                    if (32..127).contains(&c) {
                        c as char
                    } else {
                        '?'
                    }
                })
                .collect();
            s.push_str(&format!("{r:2} |{line}|\n"));
        }
        s
    }

    pub fn row_text(&self, r: usize) -> String {
        self.chars[r].iter().map(|&c| c as char).collect::<String>()
    }
}

/// The screen's byte for a pixel line of a character cell.
pub fn pixel_offset(row: usize, line: usize, col: usize) -> usize {
    (row / 8) * 0x800 + line * 0x100 + (row % 8) * 32 + col
}

/// The ROM's glyphs, played: line 1 holds the character, line 2 its
/// complement, the rest blank; a space is all blank.
fn glyph(c: u8) -> [u8; 8] {
    if c == b' ' {
        [0; 8]
    } else {
        [0, c, !c, 0, 0, 0, 0, 0]
    }
}

impl Next {
    /// The screen as the pixels show it: a printed character where the
    /// cell holds a glyph, '.' for a blank cell, '#' for anything else.
    pub fn screen_text(&self) -> String {
        let mut out = String::new();
        for r in 0..24 {
            let mut line = String::new();
            for k in 0..32 {
                let cell: Vec<u8> = (0..8)
                    .map(|l| self.ram[10 * PAGE + pixel_offset(r, l, k)])
                    .collect();
                let c = cell[1];
                line.push(if cell.iter().all(|&b| b == 0) {
                    ' '
                } else if cell[0] == 0
                    && cell[2] == !c
                    && cell[3..].iter().all(|&b| b == 0)
                    && (32..127).contains(&c)
                {
                    c as char
                } else if c == 143 || c == 138 {
                    '='
                } else {
                    '#'
                });
            }
            out.push_str(&format!("{r:2} |{line}|\n"));
        }
        out
    }
}

pub enum Fault {
    /// A BASIC error in RST $10 (its code minus one, as M_ERRH gets it).
    Basic(u8),
}

struct File {
    path: PathBuf,
    pos: u64,
    write: bool,
}

pub struct Next {
    pub ram: Vec<u8>,
    div_rom: Vec<u8>,
    pub div_ram: Vec<u8>,
    pub mmu: [u8; 8],
    nr_sel: u8,
    pub nr: [u8; 256],
    /// The pages the command owns: those it was given and those it took.
    pub ours: Vec<bool>,
    /// The overlay pages, which alone may run at 0xE000.
    pub overlays: Vec<u8>,
    /// Time in microseconds.
    pub now: f64,
    pub esp: Uart,
    pub pi: Uart,
    select: u8,
    pub keys: Vec<Key>,
    pub border: u8,
    pub border_changes: u32,
    pub pc: u16,
    pub breaches: Vec<Breach>,
    /// Writes to the screen's pixels and attributes: (pc, address).
    pub screen_writes: Vec<(u16, u16)>,
    pub screen: Screen,
    pub card: PathBuf,
    files: Vec<Option<File>>,
    pub errh: u16,
    pub drivers: Vec<(u8, Vec<u8>)>,
    /// cbb.drv's start in the background (call 9): its line and state.
    pub boot_line: Vec<u8>,
    pub boot_state: u8,
    /// The driver's banks for images (call 10): the first, and the state's.
    pub img_banks: u16,
    /// Whether cbb.drv runs the network (its call 2 switches it).
    pub net: bool,
    /// Whether cbb.drv carries .cbb's commands to the Pi while the network
    /// runs (its calls 7 and 8, cbb.drv 0.2): they go to the Pi played
    /// here as if typed at its shell, and its answers come back; without
    /// them the calls set carry, as an older driver's do.
    pub via: bool,
    /// The bytes .cbb sent through call 7.
    pub via_sent: Vec<u8>,
    /// The dot command's own file on the card, which NextZXOS keeps open
    /// while it runs (handle 0, from M_GETHANDLE): it cannot be erased
    /// until the command closes it. /cbb/CBB, as ../CBB runs it, or
    /// C:/DOT/CBB when the card has one.
    pub running: String,
    /// The palette's 9-bit colours as written (NR 0x40/0x41/0x44), per index.
    pub palette: Vec<u16>,
    pal_index: u8,
    pal_second: bool,
    pub log: Vec<String>,
    /// The time a card write of 4K holds the CPU, interrupts off.
    pub card_write_us: f64,
    /// The stack BASIC called the command with.
    pub basic_sp: u16,
    /// What RST $10 printed, with the ATs.
    pub printed: String,
    /// An address whose writes go to the log.
    pub watch: Option<u16>,
    /// Layer 2's port (0x123B): bit 1 shows it.
    pub layer2: u8,
    /// Layer 2's clip window (NR 0x18, its index reset by NR 0x1C).
    pub clip: [u8; 4],
    clip_index: usize,
    /// What Layer 2 showed when its clip window opened to the whole
    /// screen: the 80K of its banks from NR 0x12 and the palette.
    pub shown: Option<(Vec<u8>, Vec<u16>)>,
}

impl Next {
    fn slot_addr(&self, a: u16) -> (Option<u8>, usize) {
        let slot = (a >> 13) as usize;
        let off = (a as usize) & (PAGE - 1);
        if slot < 2 {
            (None, off)
        } else {
            (Some(self.mmu[slot]), off)
        }
    }

    pub fn read(&self, a: u16) -> u8 {
        let slot = (a >> 13) as usize;
        let off = (a as usize) & (PAGE - 1);
        match slot {
            0 => self.div_rom[off],
            1 => self.div_ram[off],
            _ => self.ram[self.mmu[slot] as usize * PAGE + off],
        }
    }

    /// A write as the command's code makes it, checked.
    fn write(&mut self, a: u16, v: u8) {
        if Some(a) == self.watch {
            let line = format!(
                "{:.3}s watch {a:#06x} = {v} from {:#06x} (mmu7 {})",
                self.now / 1e6,
                self.pc,
                self.mmu[7]
            );
            self.log.push(line);
        }
        let slot = (a >> 13) as usize;
        let off = (a as usize) & (PAGE - 1);
        match slot {
            0 => self.breach(format!("wrote {v:#04x} to the divMMC ROM at {a:#06x}")),
            1 => self.div_ram[off] = v,
            _ => {
                let page = self.mmu[slot];
                if page == 10 && off < 0x1B00 {
                    self.screen_writes.push((self.pc, a));
                } else if page == 10 && (off as u16) < SYSVARS_END - 0x4000 {
                    // the system variables
                } else if a < self.basic_sp
                    && a >= self.basic_sp.wrapping_sub(512)
                    && slot == 7
                    && page == 1
                {
                    // BASIC's machine stack, which the command runs on at first
                } else if !self.ours.get(page as usize).copied().unwrap_or(false) {
                    self.breach(format!(
                        "wrote {v:#04x} to page {page} at {a:#06x}, not the command's"
                    ));
                }
                self.ram[page as usize * PAGE + off] = v;
            }
        }
    }

    /// A write by NextZXOS itself (the hooks, the ROM), unchecked.
    pub fn os_write(&mut self, a: u16, v: u8) {
        let (page, off) = self.slot_addr(a);
        match page {
            None if a >= 0x2000 => self.div_ram[off] = v,
            None => {}
            Some(p) => self.ram[p as usize * PAGE + off] = v,
        }
    }

    pub fn read16(&self, a: u16) -> u16 {
        self.read(a) as u16 | (self.read(a.wrapping_add(1)) as u16) << 8
    }

    pub fn os_write16(&mut self, a: u16, v: u16) {
        self.os_write(a, v as u8);
        self.os_write(a.wrapping_add(1), (v >> 8) as u8);
    }

    pub fn breach(&mut self, what: String) {
        let pc = self.pc;
        if self.breaches.len() < 200 {
            self.breaches.push(Breach { pc, what });
        }
    }

    fn uart(&mut self) -> &mut Uart {
        if self.select & 0x40 != 0 {
            &mut self.pi
        } else {
            &mut self.esp
        }
    }

    /// The CPU's clock from NR 0x07.
    pub fn mhz(&self) -> f64 {
        [3.5, 7.0, 14.0, 28.0][(self.nr[0x07] & 3) as usize]
    }

    fn keyboard(&self, high: u8) -> u8 {
        let mut v = 0xFF;
        let t = self.now as u64;
        for k in &self.keys {
            if t >= k.from && t < k.until && (!high & !k.row) != 0 {
                v &= !(1 << k.bit);
            }
        }
        v
    }

    fn nextreg_write(&mut self, r: u8, v: u8) {
        match r {
            0x50..=0x57 => {
                let slot = (r - 0x50) as usize;
                if slot < 2 && v != 0xFF {
                    self.breach(format!("mapped page {v} over the divMMC (NR {r:#04x})"));
                }
                self.mmu[slot] = v;
            }
            0x40 => {
                self.pal_index = v;
                self.pal_second = false;
            }
            0x41 => {
                let i = self.pal_index as usize;
                self.palette[i] = (v as u16) << 1 | (v as u16 & 1);
            }
            0x44 => {
                let i = self.pal_index as usize;
                if !self.pal_second {
                    self.palette[i] = (v as u16) << 1 | (self.palette[i] & 1);
                    self.pal_second = true;
                } else {
                    self.palette[i] = (self.palette[i] & !1) | (v as u16 & 1);
                    self.pal_second = false;
                    if self.nr[0x43] & 0x80 == 0 {
                        self.pal_index = self.pal_index.wrapping_add(1);
                    }
                }
            }
            0x1C => {
                if v & 1 != 0 {
                    self.clip_index = 0;
                }
            }
            0x18 => {
                self.clip[self.clip_index] = v;
                self.clip_index = (self.clip_index + 1) % 4;
                if self.clip == [0, 159, 0, 255] && self.layer2 & 2 != 0 {
                    let base = self.nr[0x12] as usize * 2 * PAGE;
                    let pixels = self.ram[base..base + 10 * PAGE].to_vec();
                    self.shown = Some((pixels, self.palette.clone()));
                }
            }
            0x07 | 0x08 | 0x43 | 0xA0 | 0x7F | 0x12 | 0x14 | 0x15 | 0x16 | 0x17 | 0x6B | 0x70 | 0x71 => {}
            _ => self
                .log
                .push(format!("{:#06x}: NR {r:#04x} = {v:#04x}", self.pc)),
        }
        self.nr[r as usize] = v;
    }

    fn nextreg_read(&mut self, r: u8) -> u8 {
        match r {
            0x50..=0x57 => self.mmu[(r - 0x50) as usize],
            0x18 => self.clip[self.clip_index],
            0x41 => (self.palette[self.pal_index as usize] >> 1) as u8,
            0x44 => (self.palette[self.pal_index as usize] & 1) as u8,
            _ => self.nr[r as usize],
        }
    }
}

impl Machine for Next {
    fn peek(&mut self, a: u16) -> u8 {
        self.read(a)
    }
    fn poke(&mut self, a: u16, v: u8) {
        self.write(a, v);
    }
    fn port_in(&mut self, a: u16) -> u8 {
        let now = self.now;
        match a {
            0x253B => {
                let r = self.nr_sel;
                self.nextreg_read(r)
            }
            0x133B => {
                let u = self.uart();
                u.advance(now);
                let full = u.tx_queue >= 64;
                let s = (!u.fifo.is_empty()) as u8
                    | (full as u8) << 1
                    | (u.overflowed as u8) << 2
                    | ((u.fifo.len() >= 384) as u8) << 3;
                u.overflowed = false;
                s
            }
            0x143B => {
                let u = self.uart();
                u.advance(now);
                u.fifo.pop_front().unwrap_or(0)
            }
            0x153B => self.select,
            0x163B => 0,
            0x123B => self.layer2,
            0x243B => self.nr_sel,
            _ if a & 0xFF == 0xFE => {
                let k = self.keyboard((a >> 8) as u8);
                // EAR, bit 6: the Pi's sound once NR 0xA2 bit 0 hands it there.
                let now = self.now as u64;
                match self.pi.peer.ear(now) {
                    Some(level) if self.nr[0xA2] & 1 != 0 => k & !0x40 | (level as u8) << 6,
                    _ => k,
                }
            }
            _ if a & 0xFF == 0x1F => 0, // Kempston
            _ => {
                self.breach(format!("read port {a:#06x}"));
                0xFF
            }
        }
    }
    fn port_out(&mut self, a: u16, v: u8) {
        let now = self.now;
        match a {
            0x243B => self.nr_sel = v,
            0x253B => {
                let r = self.nr_sel;
                self.nextreg_write(r, v);
            }
            0x133B => {
                let pc = self.pc;
                let u = self.uart();
                u.advance(now);
                if u.tx_queue >= 64 {
                    let _ = pc;
                    self.breach("sent into a full UART buffer".into());
                    return;
                }
                u.send(now, v);
            }
            0x143B => {
                let u = self.uart();
                if v & 0x80 != 0 {
                    u.prescaler = (u.prescaler & 0x7F) | ((v as u32 & 0x7F) << 7);
                } else {
                    u.prescaler = (u.prescaler & !0x7F) | v as u32;
                }
            }
            0x153B => self.select = v,
            0x163B => {}
            0x123B => self.layer2 = v,
            0x7FFD | 0x1FFD | 0xDFFD => {
                if a == 0x7FFD {
                    let bank = v & 7;
                    self.mmu[6] = bank * 2;
                    self.mmu[7] = bank * 2 + 1;
                }
            }
            _ if a & 0xFF == 0xFE => {
                if self.border != v & 7 {
                    self.border_changes += 1;
                }
                self.border = v & 7;
            }
            _ => self.breach(format!("wrote {v:#04x} to port {a:#06x}")),
        }
    }
}

pub struct Run {
    pub cpu: Cpu,
    pub hw: Next,
    next_int: f64,
    int_until: f64,
    pub frames: u64,
    /// The interrupt's pushes below SP, as the ROM's handler makes them.
    pub done: bool,
    /// Carry and A, HL on the command's return.
    pub result: Option<(bool, u8, u16)>,
    /// z88dk's __z_page_table, and the logical pages of the overlays,
    /// which alone may run at 0xE000.
    pub page_table: u16,
    pub overlay_logical: Vec<u8>,
    /// The last instructions: PC, SP and MMU7's page.
    pub trace: VecDeque<(u16, u16, u8)>,
}

/// Lowercase, for matching names on the card as FAT does.
fn fold(s: &str) -> String {
    s.to_ascii_lowercase()
}

impl Run {
    /// Starts `.cbb ARGS` from the card's /cbb, as ../CBB ARGS: the dot
    /// command's file `dot` (build/CBB).
    pub fn new(dot: &Path, card: &Path, args: &str, esp: Box<dyn Peer>, pi: Box<dyn Peer>) -> Run {
        let file = std::fs::read(dot).expect("make build/CBB first");
        let mut ram = vec![0u8; PAGES * PAGE];
        // Whatever BASIC had: a pattern, so that reading it shows.
        for (i, b) in ram.iter_mut().enumerate() {
            *b = (i * 7 + 3) as u8;
        }
        let mut div_rom = vec![0xC9u8; PAGE];
        div_rom[0x0038] = 0x00;
        div_rom[EI_RET as usize] = 0xFB;
        div_rom[EI_RET as usize + 1] = 0xC9;
        div_rom[DONE as usize] = 0x76;
        div_rom[EXX as usize] = 0xD9;
        // NextZXOS enters the command in IM 1 with interrupts on.
        div_rom[START as usize..START as usize + 6]
            .copy_from_slice(&[0xED, 0x56, 0xFB, 0xC3, 0x00, 0x20]);
        let mut div_ram = vec![0u8; PAGE];
        div_ram[..PAGE].copy_from_slice(&file[..PAGE]);
        let mut hw = Next {
            ram,
            div_rom,
            div_ram,
            mmu: [0xFF, 0xFF, 10, 11, 4, 5, 0, 1],
            nr_sel: 0,
            nr: [0; 256],
            ours: vec![false; PAGES],
            overlays: Vec::new(),
            now: 0.0,
            esp: Uart::new(esp),
            pi: Uart::new(pi),
            select: 0,
            keys: Vec::new(),
            border: 7,
            border_changes: 0,
            layer2: 0,
            clip: [0, 255, 0, 191],
            clip_index: 0,
            shown: None,
            pc: 0,
            breaches: Vec::new(),
            screen_writes: Vec::new(),
            screen: Screen::new(),
            card: card.to_path_buf(),
            files: Vec::new(),
            errh: 0,
            drivers: Vec::new(),
            boot_line: Vec::new(),
            boot_state: 0,
            img_banks: 0,
            net: false,
            via: false,
            via_sent: Vec::new(),
            running: "/cbb/CBB".into(),
            palette: (0..256).map(|i| i as u16 * 2).collect(),
            pal_index: 0,
            pal_second: false,
            log: Vec::new(),
            card_write_us: 20_000.0,
            basic_sp: 0xFF3E,
            printed: String::new(),
            watch: std::env::var("WATCH")
                .ok()
                .map(|w| u16::from_str_radix(&w, 16).unwrap()),
        };
        hw.nr[0x00] = 10; // the Next
        hw.nr[0x01] = 0x32; // core 3.02
        hw.nr[0x07] = 0; // 3.5 MHz, as BASIC starts
        hw.nr[0x7F] = 8;
        hw.nr[0xA0] = 0;
        // The screen: BASIC's, white paper, black ink, cleared.
        for i in 0..0x1800 {
            hw.ram[10 * PAGE + i] = 0;
        }
        for i in 0x1800..0x1B00 {
            hw.ram[10 * PAGE + i] = 0x38;
        }
        // The system variables as NextZXOS's BASIC leaves them: BANKM and
        // BANK678 with ROM 3 and RAM 0 paged, the rest zero but for these.
        for a in 0x5B00u16..0x5D00 {
            hw.os_write(a, 0);
        }
        let sysvars: [(u16, u8); 8] = [
            (BORDCR, 0x38),
            (ATTR_P, 0x38),
            (SCR_CT, 1),
            (23659, 2),
            (23611, 0x0C),
            (LAST_K, 0),
            (23388, 0x10),
            (23399, 0x04),
        ];
        for (a, v) in sysvars {
            hw.os_write(a, v);
        }
        // Ten minutes after power-on: .cbb net on leaves the start to the
        // driver only in the first two (a test sets FRAMES lower for that).
        hw.os_write16(FRAMES, 30_000);
        hw.os_write(FRAMES + 2, 0);
        // The command line, in BASIC's line, ended by ENTER.
        let line = format!("../CBB {args}\r");
        let at = 0x5D40u16;
        for (i, b) in line.bytes().enumerate() {
            hw.os_write(at + i as u16, b);
        }
        let mut cpu = Cpu::new_z80();
        let r = cpu.registers();
        // BASIC's stack, under RAMTOP, and the return to NextZXOS.
        let sp = 0xFF40u16;
        hw.os_write16(sp - 2, DONE);
        r.set16(Reg16::SP, sp - 2);
        r.set16(Reg16::HL, at + 7);
        r.set16(Reg16::BC, at);
        r.set16(Reg16::IY, ERR_NR);
        r.set_pc(START);
        // The rest of the file, as M_GETHANDLE gives it.
        hw.files.push(Some(File {
            path: dot.to_path_buf(),
            pos: PAGE as u64,
            write: false,
        }));
        Run {
            cpu,
            hw,
            next_int: 20_000.0,
            int_until: 0.0,
            frames: 0,
            done: false,
            result: None,
            page_table: 0,
            overlay_logical: Vec::new(),
            trace: VecDeque::new(),
        }
    }

    fn pop(&mut self) -> u16 {
        let sp = self.cpu.registers().get16(Reg16::SP);
        let v = self.hw.read16(sp);
        self.cpu.registers().set16(Reg16::SP, sp.wrapping_add(2));
        v
    }

    fn reg(&mut self, r: Reg16) -> u16 {
        self.cpu.registers().get16(r)
    }

    fn set(&mut self, r: Reg16, v: u16) {
        self.cpu.registers().set16(r, v);
    }

    fn carry(&mut self, c: bool) {
        let r = self.cpu.registers();
        if c {
            r.set_flag(Flag::C)
        } else {
            r.clear_flag(Flag::C)
        }
    }

    fn ok(&mut self) {
        self.carry(false);
    }

    fn err(&mut self, code: u8) {
        self.cpu.registers().set_a(code);
        self.carry(true);
    }

    fn string(&self, mut a: u16) -> String {
        let mut s = String::new();
        loop {
            let c = self.hw.read(a);
            if c == 0 || c == 0x0D || s.len() > 255 {
                return s;
            }
            s.push(c as char);
            a = a.wrapping_add(1);
        }
    }

    /// A card path to a host path: /cbb/X, c:/dot/X, X in /cbb.
    fn host(&self, name: &str) -> PathBuf {
        let mut n = name.trim().to_string();
        if let Some(rest) = n.strip_prefix("c:").or_else(|| n.strip_prefix("C:")) {
            n = rest.to_string();
        }
        if !n.starts_with('/') {
            n = format!("/cbb/{n}");
        }
        let mut p = self.hw.card.clone();
        for part in n.split('/').filter(|s| !s.is_empty()) {
            // FAT ignores case: an existing name in any case is the one.
            let found = std::fs::read_dir(&p).ok().and_then(|d| {
                d.filter_map(|e| e.ok())
                    .find(|e| fold(&e.file_name().to_string_lossy()) == fold(part))
                    .map(|e| e.path())
            });
            p = found.unwrap_or_else(|| p.join(part));
        }
        p
    }

    fn hook(&mut self, code: u8) {
        let a = self.cpu.registers().a();
        let hl = self.reg(Reg16::HL);
        let bc = self.reg(Reg16::BC);
        let de = self.reg(Reg16::DE);
        match code {
            0x88 => {
                // M_DOSVERSION: NextZXOS 2.07 in its own mode.
                self.cpu.registers().set_a(0);
                self.set(Reg16::DE, 0x0207);
                self.set(Reg16::BC, 0x4E58);
                self.ok();
            }
            0x8D => {
                self.cpu.registers().set_a(0);
                self.ok();
            }
            0x95 => {
                self.hw.errh = hl;
                self.ok();
            }
            0x9A => {
                let name = self.string(hl);
                let path = self.host(&name);
                let mode = (bc >> 8) as u8;
                let exists = path.is_file();
                let write = mode & 2 != 0;
                let create = mode & 0x0C;
                if !exists && create == 0 {
                    return self.err(5);
                }
                if exists && create == 0x04 {
                    return self.err(18);
                }
                if !exists || create == 0x0C {
                    if !path.parent().map(|d| d.is_dir()).unwrap_or(false) {
                        return self.err(5);
                    }
                    std::fs::write(&path, []).unwrap();
                }
                self.hw.log.push(format!("open {name} mode {mode:#04x}"));
                let h = self.hw.files.len();
                self.hw.files.push(Some(File {
                    path,
                    pos: 0,
                    write,
                }));
                self.cpu.registers().set_a(h as u8);
                self.ok();
            }
            0x9B => {
                match self.hw.files.get_mut(a as usize) {
                    Some(f @ Some(_)) => *f = None,
                    _ => return self.err(7),
                }
                self.ok();
            }
            0x9D | 0x9E => {
                let Some(Some(f)) = self.hw.files.get(a as usize) else {
                    return self.err(7);
                };
                let (path, pos, write) = (f.path.clone(), f.pos, f.write);
                if hl < 0x4000 && hl >= 0x2000 {
                    // allowed: the command's own 8K
                }
                if code == 0x9D {
                    let data = std::fs::read(&path).unwrap_or_default();
                    let start = (pos as usize).min(data.len());
                    let end = (start + bc as usize).min(data.len());
                    for (i, b) in data[start..end].iter().enumerate() {
                        self.hw.os_write(hl.wrapping_add(i as u16), *b);
                    }
                    self.hw.files[a as usize].as_mut().unwrap().pos = end as u64;
                    self.set(Reg16::BC, (end - start) as u16);
                } else {
                    if !write {
                        return self.err(8);
                    }
                    let mut data = std::fs::read(&path).unwrap_or_default();
                    let pos = pos as usize;
                    if data.len() < pos {
                        data.resize(pos, 0);
                    }
                    let bytes: Vec<u8> =
                        (0..bc).map(|i| self.hw.read(hl.wrapping_add(i))).collect();
                    let end = pos + bytes.len();
                    if data.len() < end {
                        data.resize(end, 0);
                    }
                    data[pos..end].copy_from_slice(&bytes);
                    std::fs::write(&path, &data).unwrap();
                    self.hw.files[a as usize].as_mut().unwrap().pos = end as u64;
                    // The card holds the CPU meanwhile, interrupts off.
                    let us = self.hw.card_write_us * bc as f64 / 4096.0;
                    self.hw.now += us;
                    self.next_int = self.next_int.max(self.hw.now);
                    let now = self.hw.now;
                    self.hw.esp.advance(now);
                    self.hw.pi.advance(now);
                }
                self.ok();
            }
            0x9F => {
                let Some(Some(f)) = self.hw.files.get_mut(a as usize) else {
                    return self.err(7);
                };
                let off = (bc as u64) << 16 | de as u64;
                match hl & 0xFF {
                    0 => f.pos = off,
                    1 => f.pos += off,
                    _ => f.pos = f.pos.saturating_sub(off),
                }
                let pos = f.pos;
                self.set(Reg16::BC, (pos >> 16) as u16);
                self.set(Reg16::DE, pos as u16);
                self.ok();
            }
            0xAA => {
                let name = self.string(hl);
                let path = self.host(&name);
                if path.exists() {
                    return self.err(18);
                }
                std::fs::create_dir(&path).unwrap();
                self.ok();
            }
            0xAB => {
                // F_RMDIR: an empty folder only.
                let name = self.string(hl);
                let path = self.host(&name);
                if !path.is_dir()
                    || std::fs::read_dir(&path)
                        .map(|mut d| d.next().is_some())
                        .unwrap_or(true)
                {
                    return self.err(5);
                }
                std::fs::remove_dir(&path).unwrap();
                self.hw.log.push(format!("rmdir {name}"));
                self.ok();
            }
            0xAD => {
                let name = self.string(hl);
                let path = self.host(&name);
                if !path.is_file() {
                    return self.err(5);
                }
                // NextZXOS keeps a large dot command's file open (handle 0
                // here, as M_GETHANDLE gives it) until it closes it.
                let running = self.hw.running.clone();
                if path == self.host(&running) && matches!(self.hw.files.first(), Some(Some(_))) {
                    return self.err(6); // in use
                }
                if let Ok(dir) = std::env::var("CBB_UNLINKED") {
                    let _ = std::fs::copy(&path, Path::new(&dir).join(path.file_name().unwrap()));
                }
                std::fs::remove_file(&path).unwrap();
                self.hw.log.push(format!("unlink {name}"));
                self.ok();
            }
            0xB0 => {
                let from = self.host(&self.string(hl));
                let to = self.host(&self.string(de));
                if !from.is_file() || to.exists() {
                    return self.err(if to.exists() { 18 } else { 5 });
                }
                std::fs::rename(&from, &to).unwrap();
                self.ok();
            }
            0x92 => self.drvapi(),
            0x94 => self.p3dos(),
            _ => {
                self.hw
                    .breach(format!("RST $8 hook {code:#04x}, not played here"));
                self.err(2);
            }
        }
    }

    fn drvapi(&mut self) {
        let bc = self.reg(Reg16::BC);
        let de = self.reg(Reg16::DE);
        let hl = self.reg(Reg16::HL);
        let (id, call) = (bc as u8, (bc >> 8) as u8);
        if hl != 0 && hl < 0x4000 {
            self.hw
                .breach(format!("M_DRVAPI with a buffer at {hl:#06x}, under 0x4000"));
        }
        if id == 0 {
            match call {
                1 => {
                    let drv = de as u8 & 0x7F;
                    if self.hw.drivers.iter().any(|d| d.0 == drv) {
                        return self.err(18);
                    }
                    let code: Vec<u8> = (0..512).map(|i| self.hw.read(hl + i)).collect();
                    self.hw.drivers.push((drv, code));
                    self.ok();
                }
                2 => {
                    let drv = de as u8 & 0x7F;
                    self.hw.drivers.retain(|d| d.0 != drv);
                    self.ok();
                }
                4 => {
                    let drv = de as u8 & 0x7F;
                    let Some(code) = self
                        .hw
                        .drivers
                        .iter()
                        .find(|d| d.0 == drv)
                        .map(|d| d.1.clone())
                    else {
                        return self.err(5);
                    };
                    for (i, b) in code.iter().enumerate() {
                        self.hw.os_write(hl + i as u16, *b);
                    }
                    self.ok();
                }
                _ => {
                    self.hw
                        .breach(format!("M_DRVAPI driver 0 call {call}, not played here"));
                    self.err(2);
                }
            }
            return;
        }
        if !self.hw.drivers.iter().any(|d| d.0 == id) {
            self.cpu.registers().set_a(0);
            return self.carry(true);
        }
        // cbb.drv: the network's state; its counters are zero.
        match call {
            2 => {
                self.hw.net = de != 0;
                self.hw.boot_state = 0;
                self.ok();
            }
            // The start in the background: the line kept, and the state
            // left waiting for the prompt, as the Pi here never shows it
            // to a driver.
            9 => match de >> 8 {
                0 => {
                    self.hw.boot_line.clear();
                    self.hw.boot_state = 0;
                    self.ok();
                }
                1 => {
                    self.hw.boot_line.push(de as u8);
                    self.ok();
                }
                2 => {
                    self.hw.boot_state = 1;
                    self.ok();
                }
                3 => {
                    self.set(Reg16::DE, self.hw.boot_state as u16);
                    self.ok();
                }
                _ => self.carry(true),
            },
            3 => {
                self.set(Reg16::DE, self.hw.net as u16);
                self.ok();
            }
            10 => {
                let old = std::mem::replace(&mut self.hw.img_banks, de);
                self.set(Reg16::DE, old);
                self.ok();
            }
            7 | 8 if !self.hw.via => self.carry(true),
            7 => {
                let now = self.hw.now as u64;
                match de >> 8 {
                    1 => {
                        self.hw.via_sent.push(de as u8);
                        self.hw.pi.peer.rx(now, de as u8, 115_200);
                    }
                    3 => {
                        self.hw.via_sent.push(3);
                        self.hw.pi.peer.rx(now, 3, 115_200);
                    }
                    _ => {}
                }
                self.ok();
            }
            8 => {
                let now = self.hw.now as u64;
                let b = self.hw.pi.peer.tx(now);
                self.set(Reg16::DE, b.map_or(0, |b| 0x100 | b as u16));
                self.ok();
            }
            _ => {
                self.set(Reg16::BC, 0);
                self.set(Reg16::DE, 0);
                self.set(Reg16::HL, 0);
                self.ok();
            }
        }
    }

    /// EXX, run by the CPU itself from the ROM, as iz80 shows no
    /// alternate registers.
    fn exx(&mut self) {
        let pc = self.cpu.registers().pc();
        let pending = self.int_until > 0.0;
        self.cpu.signal_interrupt(false);
        self.cpu.registers().set_pc(EXX);
        self.cpu.execute_instruction(&mut self.hw);
        self.cpu.registers().set_pc(pc);
        if pending {
            self.cpu.signal_interrupt(true);
        }
    }

    fn p3dos(&mut self) {
        let de = self.reg(Reg16::DE);
        if self.hw.mmu[2] != 10 {
            self.hw
                .breach(format!("M_P3DOS with MMU2 at page {}", self.hw.mmu[2]));
        }
        let iy = self.reg(Reg16::IY);
        if iy != ERR_NR {
            self.hw.breach(format!("M_P3DOS with IY at {iy:#06x}"));
        }
        // The call's own registers are the alternate set.
        self.exx();
        let hl = self.reg(Reg16::HL);
        let e = self.reg(Reg16::DE) as u8;
        self.exx();
        if de != 0x01BD {
            self.hw
                .breach(format!("M_P3DOS call {de:#06x}, not played here"));
            return self.carry(false);
        }
        let (kind, reason) = ((hl >> 8) as u8, hl as u8);
        if kind != 0 {
            self.hw.breach(format!("IDE_BANK of type {kind}"));
        }
        match reason {
            1 => {
                // The free pages from the top.
                let page = (18..PAGES)
                    .rev()
                    .find(|&p| !self.hw.ours[p] && !self.hw.overlays.contains(&(p as u8)));
                match page {
                    Some(p) => {
                        self.hw.ours[p] = true;
                        let mut de2 = self.reg(Reg16::DE);
                        de2 = (de2 & 0xFF00) | p as u16;
                        self.set(Reg16::DE, de2);
                        self.carry(true);
                    }
                    None => self.carry(false),
                }
            }
            3 => {
                if !self.hw.ours[e as usize] {
                    self.hw.breach(format!("freed page {e}, not the command's"));
                }
                self.hw.ours[e as usize] = false;
                self.carry(true);
            }
            _ => {
                self.hw.breach(format!("IDE_BANK reason {reason}"));
                self.carry(false);
            }
        }
    }

    /// RST $10: the ROM prints A.
    fn print(&mut self, c: u8) -> Option<Fault> {
        let sp = self.reg(Reg16::SP);
        if (0x2000..0x4000).contains(&sp) {
            self.hw.breach(format!(
                "RST $10 with the stack at {sp:#06x}, in the divMMC"
            ));
        }
        if c == 0x80 {
            self.hw.breach("RST $10 with A = $80".into());
        }
        let s = &mut self.hw.screen;
        if !s.pending.is_empty() {
            s.pending.push(c);
            let want = if s.pending[0] == 22 || s.pending[0] == 23 {
                3
            } else {
                2
            };
            if s.pending.len() < want {
                return None;
            }
            let p = std::mem::take(&mut s.pending);
            match p[0] {
                22 => {
                    self.hw
                        .printed
                        .push_str(&format!("\n[AT {},{}]", p[1], p[2]));
                    if p[1] > 21 || p[2] > 31 {
                        return Some(Fault::Basic(4)); // 5 Out of screen
                    }
                    s.row = p[1];
                    s.col = p[2];
                }
                23 => s.col = p[1] % 32,
                16 => {
                    let ink = p[1];
                    if ink < 8 {
                        let a = self.hw.read(23695);
                        self.hw.os_write(23695, (a & !7) | ink);
                    }
                }
                17 => {
                    let paper = p[1];
                    if paper < 8 {
                        let a = self.hw.read(23695);
                        self.hw.os_write(23695, (a & !0x38) | paper << 3);
                    }
                }
                19 => {
                    let a = self.hw.read(23695);
                    self.hw
                        .os_write(23695, if p[1] == 1 { a | 0x40 } else { a & !0x40 });
                }
                18 => {
                    let a = self.hw.read(23695);
                    self.hw
                        .os_write(23695, if p[1] == 1 { a | 0x80 } else { a & !0x80 });
                }
                _ => {}
            }
            return None;
        }
        match c {
            16..=23 => {
                s.pending.push(c);
                None
            }
            13 => {
                s.col = 0;
                s.row += 1;
                self.scroll_if_needed()
            }
            6 => {
                s.col = if s.col < 16 { 16 } else { 0 };
                if s.col == 0 {
                    s.row += 1;
                }
                self.scroll_if_needed()
            }
            8 => {
                s.col = s.col.saturating_sub(1);
                None
            }
            32..=255 => {
                if s.col > 31 {
                    s.col = 0;
                    s.row += 1;
                    if let Some(f) = self.scroll_if_needed() {
                        return Some(f);
                    }
                }
                self.hw.printed.push(if (32..127).contains(&c) {
                    c as char
                } else {
                    '~'
                });
                let s = &mut self.hw.screen;
                let (r, k) = (s.row as usize, s.col as usize);
                s.chars[r][k] = c;
                let attr = self.hw.read(23695);
                self.hw.screen.attrs[r][k] = attr;
                self.hw.ram[10 * PAGE + 0x1800 + r * 32 + k] = attr;
                // The glyph: a pattern that names the character, which
                // Screen::read takes back from the pixels.
                for (line, v) in glyph(c).iter().enumerate() {
                    self.hw.ram[10 * PAGE + pixel_offset(r, line, k)] = *v;
                }
                self.hw.screen.col += 1;
                None
            }
            _ => None,
        }
    }

    /// The ROM scrolls the upper screen when the position passes row 21.
    fn scroll_if_needed(&mut self) -> Option<Fault> {
        while self.hw.screen.row > 21 {
            let ct = self.hw.read(SCR_CT);
            if ct <= 1 {
                // "scroll?" waits for a key; N, SPACE or BREAK stop.
                self.hw.breach("the ROM asked scroll?".into());
            } else {
                self.hw.os_write(SCR_CT, ct - 1);
            }
            let s = &mut self.hw.screen;
            s.scrolls += 1;
            s.chars.copy_within(1..22, 0);
            s.attrs.copy_within(1..22, 0);
            s.chars[21] = [b' '; 32];
            s.row -= 1;
            for r in 0..22 {
                for line in 0..8 {
                    for k in 0..32 {
                        let v = if r < 21 {
                            self.hw.ram[10 * PAGE + pixel_offset(r + 1, line, k)]
                        } else {
                            0
                        };
                        self.hw.ram[10 * PAGE + pixel_offset(r, line, k)] = v;
                    }
                }
                for k in 0..32 {
                    let v = if r < 21 {
                        self.hw.ram[10 * PAGE + 0x1800 + (r + 1) * 32 + k]
                    } else {
                        0x38
                    };
                    self.hw.ram[10 * PAGE + 0x1800 + r * 32 + k] = v;
                }
            }
            self.hw.breach("the ROM scrolled the whole screen".into());
        }
        None
    }

    /// RST $18: the 48K ROM's routines that the command uses.
    fn rom_call(&mut self, addr: u16) {
        let sp = self.reg(Reg16::SP);
        if (0x2000..0x4000).contains(&sp) {
            self.hw.breach(format!(
                "RST $18 with the stack at {sp:#06x}, in the divMMC"
            ));
        }
        self.hw
            .breach(format!("RST $18 to {addr:#06x}, not played here"));
    }

    /// The IM1 interrupt: FRAMES and the keyboard, with the system
    /// variables at IY as the ROM's handler takes them.
    fn interrupt(&mut self) {
        let sp = self.reg(Reg16::SP);
        let iy = self.reg(Reg16::IY);
        if iy != ERR_NR {
            self.hw.breach(format!(
                "an interrupt with IY at {iy:#06x}: the ROM writes there"
            ));
        }
        // z88dk's exit moves the stack to the top of the dot command's
        // divMMC memory (DOTN_REGISTER_SP, 0x4000) while it puts the pages
        // back, interrupts on: the handler's few bytes land in the space
        // CODE leaves free (budget.sh keeps 1K).
        if sp < 0x3F00 {
            self.hw.breach(format!(
                "an interrupt with the stack at {sp:#06x}, in the divMMC"
            ));
        }
        // The handler pushes AF and HL, and the ROM's KEYBOARD a few more.
        for i in 3..=10u16 {
            let a = sp.wrapping_sub(i);
            let (page, _) = self.hw.slot_addr(a);
            match page {
                Some(p) if self.hw.ours[p as usize] || p == 10 || p == 11 => {}
                // BASIC's own stack, as the startup and the exit run on it.
                Some(1) if a < self.hw.basic_sp && a >= self.hw.basic_sp.wrapping_sub(512) => {}
                Some(p) => self.hw.breach(format!(
                    "an interrupt's pushes at {a:#06x} land in page {p}, not the command's"
                )),
                None => {}
            }
            self.hw.os_write(a, 0xEE);
        }
        let f = self.hw.read16(FRAMES).wrapping_add(1);
        self.hw.os_write16(FRAMES, f);
        let k = self.hw.keyboard(0x00);
        if k != 0xFF {
            self.hw.os_write(LAST_K, b' ');
        }
        self.frames += 1;
        // The handler outlasts /INT, and takes its time.
        self.cpu.signal_interrupt(false);
        self.int_until = 0.0;
        self.tick(4000);
        self.cpu.registers().set_pc(EI_RET);
    }

    /// One instruction, or one restart of NextZXOS.
    pub fn step(&mut self) {
        let pc = self.cpu.registers().pc();
        self.hw.pc = pc;
        let sp = self.cpu.registers().get16(Reg16::SP);
        if self.trace.len() >= 3_000_000 {
            self.trace.pop_front();
        }
        self.trace.push_back((pc, sp, self.hw.mmu[7]));
        if pc == DONE {
            let r = self.cpu.registers();
            let c = r.get_flag(Flag::C);
            let a = r.a();
            let hl = r.get16(Reg16::HL);
            self.result = Some((c, a, hl));
            self.done = true;
            return;
        }
        if pc < 0x2000 {
            match pc {
                0x0008 => {
                    let ret = self.pop();
                    let code = self.hw.read(ret);
                    self.cpu.registers().set_pc(ret.wrapping_add(1));
                    self.hook(code);
                }
                0x0010 => {
                    let a = self.cpu.registers().a();
                    let ret = self.pop();
                    match self.print(a) {
                        None => self.cpu.registers().set_pc(ret),
                        Some(Fault::Basic(code)) => {
                            self.hw
                                .log
                                .push(format!("BASIC error {} in RST $10", code + 1));
                            self.hw
                                .breach(format!("BASIC error {} in RST $10", code + 1));
                            if self.hw.errh == 0 {
                                self.done = true;
                                return;
                            }
                            self.set(Reg16::DE, ret);
                            self.cpu.registers().set_a(code);
                            let h = self.hw.errh;
                            self.cpu.registers().set_pc(h);
                        }
                    }
                }
                0x0018 => {
                    let ret = self.pop();
                    let addr = self.hw.read16(ret);
                    self.cpu.registers().set_pc(ret.wrapping_add(2));
                    self.rom_call(addr);
                }
                ISR => self.interrupt(),
                EI_RET | 0x1F01 | 0x0038 | START..=0x1F35 => self.exec(),
                _ => {
                    self.hw.breach(format!("ran the divMMC ROM at {pc:#06x}"));
                    self.done = true;
                }
            }
            self.tick(20);
            return;
        }
        if pc >= 0xE000 {
            let page = self.hw.mmu[7];
            let overlays: Vec<u8> = self
                .overlay_logical
                .iter()
                .map(|&l| self.hw.read(self.page_table + l as u16))
                .collect();
            if !overlays.contains(&page) {
                self.hw.breach(format!(
                    "ran code at {pc:#06x} from page {page}, not an overlay"
                ));
                self.done = true;
                return;
            }
        }
        if self.hw.read(pc) == 0xED && self.z80n() {
            return;
        }
        self.exec();
    }

    fn exec(&mut self) {
        let before = self.cpu.cycle_count();
        self.cpu.execute_instruction(&mut self.hw);
        let t = self.cpu.cycle_count() - before;
        self.tick(t);
    }

    fn tick(&mut self, t: u64) {
        self.hw.now += t as f64 / self.hw.mhz();
        if self.int_until > 0.0 && self.hw.now >= self.int_until {
            self.cpu.signal_interrupt(false);
            self.int_until = 0.0;
        }
        if self.hw.now >= self.next_int {
            self.next_int += 20_000.0;
            // /INT for about 32 T-states at 3.5 MHz.
            self.cpu.signal_interrupt(true);
            self.int_until = self.hw.now + 9.0;
        }
    }

    /// The Z80N's own instructions (ED xx), which iz80 lacks; false when
    /// it is a Z80 one.
    fn z80n(&mut self) -> bool {
        let pc = self.cpu.registers().pc();
        let op = self.hw.read(pc.wrapping_add(1));
        let n1 = self.hw.read(pc.wrapping_add(2));
        let n2 = self.hw.read(pc.wrapping_add(3));
        let (len, t): (u16, u64) = match op {
            0x91 => {
                self.hw.nextreg_write(n1, n2);
                (4, 20)
            }
            0x92 => {
                let a = self.cpu.registers().a();
                self.hw.nextreg_write(n1, a);
                (3, 17)
            }
            0x31 | 0x32 | 0x33 => {
                let a = self.cpu.registers().a() as u16;
                let r = [Reg16::HL, Reg16::DE, Reg16::BC][(op - 0x31) as usize];
                let v = self.reg(r).wrapping_add(a);
                self.set(r, v);
                (2, 8)
            }
            0x34 | 0x35 | 0x36 => {
                let nn = n1 as u16 | (n2 as u16) << 8;
                let r = [Reg16::HL, Reg16::DE, Reg16::BC][(op - 0x34) as usize];
                let v = self.reg(r).wrapping_add(nn);
                self.set(r, v);
                (4, 16)
            }
            0x23 => {
                let a = self.cpu.registers().a();
                self.cpu.registers().set_a(a.rotate_left(4));
                (2, 8)
            }
            0x24 => {
                let a = self.cpu.registers().a();
                self.cpu.registers().set_a(a.reverse_bits());
                (2, 8)
            }
            0x30 => {
                let de = self.reg(Reg16::DE);
                self.set(Reg16::DE, (de >> 8) * (de & 0xFF));
                (2, 8)
            }
            0x8A => {
                let sp = self.reg(Reg16::SP).wrapping_sub(2);
                self.set(Reg16::SP, sp);
                // big-endian operand
                self.hw.write(sp, n2);
                self.hw.write(sp.wrapping_add(1), n1);
                (4, 23)
            }
            0x27 => {
                let a = self.cpu.registers().a() & n1;
                let r = self.cpu.registers();
                r.put_flag(Flag::Z, a == 0);
                r.put_flag(Flag::S, a & 0x80 != 0);
                (3, 11)
            }
            0xA4 | 0xAC | 0xB4 | 0xBC => {
                // ldix, lddx, ldirx, lddrx: as ldi/ldd, but a byte equal to A is not written
                loop {
                    let hl = self.reg(Reg16::HL);
                    let de = self.reg(Reg16::DE);
                    let bc = self.reg(Reg16::BC);
                    let v = self.hw.read(hl);
                    if v != self.cpu.registers().a() {
                        self.hw.write(de, v);
                    }
                    let down = op == 0xAC || op == 0xBC;
                    self.set(
                        Reg16::HL,
                        if down {
                            hl.wrapping_sub(1)
                        } else {
                            hl.wrapping_add(1)
                        },
                    );
                    self.set(Reg16::DE, de.wrapping_add(1));
                    self.set(Reg16::BC, bc.wrapping_sub(1));
                    self.tick(16);
                    if op < 0xB0 || bc == 1 {
                        break;
                    }
                }
                (2, 0)
            }
            0x28..=0x2C => {
                let de = self.reg(Reg16::DE);
                let b = self.reg(Reg16::BC) >> 8;
                let v = match op {
                    0x28 => de << (b & 31).min(16) as u32 & 0xFFFF,
                    0x29 => ((de as i16) >> (b & 31).min(15)) as u16,
                    0x2A => {
                        if b & 31 >= 16 {
                            0
                        } else {
                            de >> (b & 31)
                        }
                    }
                    0x2B => {
                        if b & 31 >= 16 {
                            0xFFFF
                        } else {
                            !((!de) >> (b & 31))
                        }
                    }
                    _ => de.rotate_left((b & 15) as u32),
                };
                let v = if op == 0x28 && b & 31 >= 16 { 0 } else { v };
                self.set(Reg16::DE, v);
                (2, 8)
            }
            0xA2 => {
                // INI: iz80 takes the port after B's decrement; the Z80 before.
                let bc = self.reg(Reg16::BC);
                let v = self.hw.port_in(bc);
                let hl = self.reg(Reg16::HL);
                self.hw.write(hl, v);
                self.set(Reg16::HL, hl.wrapping_add(1));
                let b = ((bc >> 8) as u8).wrapping_sub(1);
                self.set(Reg16::BC, (b as u16) << 8 | (bc & 0xFF));
                let r = self.cpu.registers();
                r.put_flag(Flag::Z, b == 0);
                r.set_flag(Flag::N);
                (2, 16)
            }
            0x40..=0x7F | 0xA0..=0xA3 | 0xA8..=0xAB | 0xB0..=0xB3 | 0xB8..=0xBB => return false,
            _ => {
                self.hw.breach(format!("ED {op:02x}: not emulated here"));
                self.done = true;
                return true;
            }
        };
        let r = self.cpu.registers();
        r.set_pc(pc.wrapping_add(len));
        self.tick(t);
        let _ = Reg8::A;
        true
    }

    /// Runs until the command returns or `seconds` of the Next's time pass.
    pub fn run(&mut self, seconds: f64) {
        let until = self.hw.now + seconds * 1e6;
        while !self.done && self.hw.now < until {
            self.step();
            if self.hw.breaches.iter().any(|b| b.what.starts_with("ran ")) {
                self.done = true;
            }
        }
    }
}
