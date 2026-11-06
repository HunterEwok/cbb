// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The frames between the Next's driver and the lite member on the Pi's UART
//! (docs/roadmap.md, "The Next's network in the background"). A frame is the
//! start byte 0x7E, a type, a length (0 to 255), that many bytes and a sum of
//! the type, the length and the bytes, modulo 256. Inside a frame every 0x7E
//! is sent twice, so a single 0x7E always starts a frame and a reader that
//! lost a byte finds the next one. The Z80 reads it with a few compares and
//! an add a byte.

/// The start of a frame.
pub const START: u8 = 0x7E;
/// The most bytes in one frame.
pub const MAX: usize = 255;

/// Bytes the ESP sent (driver to Pi).
pub const FROM_ESP: u8 = b'E';
/// Bytes for the ESP (Pi to driver).
pub const TO_ESP: u8 = b'e';
/// The driver's hello: its version and what it counted (driver to Pi).
pub const HELLO: u8 = b'H';
/// The Next's clock: the date and the time in MS-DOS's form, as
/// NextZXOS gives them to a driver, each 16 bits little-endian (driver to Pi).
pub const TIME: u8 = b'T';
/// How many of the Pi's bytes on the wire the driver has taken, as a 16-bit
/// little-endian count (driver to Pi); the Pi sends no more than WINDOW
/// bytes ahead.
pub const ACK: u8 = b'A';
/// The driver stops the link, and NextPi's shell has the UART again
/// (driver to Pi).
pub const QUIT: u8 = b'Q';
/// Characters to type, in the Spectrum character set (Pi to driver).
pub const KEYS: u8 = b'K';
/// What `.cbb` types for the Pi's shell while the network runs (driver to
/// Pi): a command line, then the command's input; an empty frame stops the
/// command (cbb.drv 0.2).
pub const CBB_OUT: u8 = b'C';
/// The command's output for `.cbb`, then `\r\nSUP>` as NextPi's shell
/// writes its prompt (Pi to driver).
pub const CBB_IN: u8 = b'c';

/// How many bytes on the wire the Pi sends before the driver's ACK: less
/// than the Next's 512-byte receive buffer, with room for a frame in flight.
pub const WINDOW: usize = 384;

/// One frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub kind: u8,
    pub data: Vec<u8>,
}

/// The bytes of a frame on the wire; data longer than MAX goes in several
/// frames of the same type.
pub fn encode(kind: u8, data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() + 8);
    for chunk in data.chunks(MAX) {
        put(&mut out, kind, chunk);
    }
    if data.is_empty() {
        put(&mut out, kind, &[]);
    }
    out
}

fn put(out: &mut Vec<u8>, kind: u8, data: &[u8]) {
    let mut sum = kind.wrapping_add(data.len() as u8);
    out.push(START);
    let mut byte = |b: u8| {
        out.push(b);
        if b == START {
            out.push(START);
        }
    };
    byte(kind);
    byte(data.len() as u8);
    for &b in data {
        sum = sum.wrapping_add(b);
        byte(b);
    }
    byte(sum);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    /// Waiting for a start byte.
    Idle,
    Kind,
    Len,
    Data,
    Sum,
}

/// Reads frames from the bytes as they come; a frame with a wrong sum, or
/// cut short by a new start, is dropped and counted.
#[derive(Debug)]
pub struct Decoder {
    state: State,
    /// The last byte was a 0x7E inside a frame: the next one says whether
    /// it was doubled.
    escape: bool,
    kind: u8,
    len: usize,
    sum: u8,
    data: Vec<u8>,
    /// Frames dropped for a wrong sum or a break.
    pub dropped: u32,
}

impl Default for Decoder {
    fn default() -> Self {
        Decoder { state: State::Idle, escape: false, kind: 0, len: 0, sum: 0, data: Vec::new(), dropped: 0 }
    }
}

impl Decoder {
    pub fn new() -> Decoder {
        Decoder::default()
    }

    /// Takes the bytes and returns the frames they finish.
    pub fn push(&mut self, bytes: &[u8]) -> Vec<Frame> {
        let mut out = Vec::new();
        for &b in bytes {
            if self.state == State::Idle {
                if b == START {
                    self.begin();
                }
                continue;
            }
            if self.escape {
                self.escape = false;
                if b != START {
                    // A single 0x7E: a new frame starts, and b is its type.
                    self.dropped += 1;
                    self.begin();
                    self.take(b, &mut out);
                    continue;
                }
            } else if b == START {
                self.escape = true;
                continue;
            }
            self.take(b, &mut out);
        }
        out
    }

    fn begin(&mut self) {
        self.state = State::Kind;
        self.escape = false;
        self.data.clear();
    }

    fn take(&mut self, b: u8, out: &mut Vec<Frame>) {
        match self.state {
            State::Idle => {}
            State::Kind => {
                self.kind = b;
                self.sum = b;
                self.state = State::Len;
            }
            State::Len => {
                self.len = b as usize;
                self.sum = self.sum.wrapping_add(b);
                self.state = if self.len == 0 { State::Sum } else { State::Data };
            }
            State::Data => {
                self.data.push(b);
                self.sum = self.sum.wrapping_add(b);
                if self.data.len() == self.len {
                    self.state = State::Sum;
                }
            }
            State::Sum => {
                if b == self.sum {
                    out.push(Frame { kind: self.kind, data: std::mem::take(&mut self.data) });
                } else {
                    self.dropped += 1;
                }
                self.state = State::Idle;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let data: Vec<u8> = (0..=255u8).chain([START, START, 0, START]).collect();
        let wire = encode(TO_ESP, &data);
        let mut d = Decoder::new();
        let frames = d.push(&wire);
        assert_eq!(frames.len(), 2);
        assert_eq!(frames[0].data.len(), MAX);
        let joined: Vec<u8> = frames.iter().flat_map(|f| f.data.clone()).collect();
        assert_eq!(joined, data);
        assert!(frames.iter().all(|f| f.kind == TO_ESP));
        assert_eq!(d.dropped, 0);
    }

    #[test]
    fn byte_by_byte_and_empty() {
        let wire = [encode(ACK, &[0x80, 0x01]), encode(HELLO, &[])].concat();
        let mut d = Decoder::new();
        let mut frames = Vec::new();
        for b in wire {
            frames.extend(d.push(&[b]));
        }
        assert_eq!(frames, vec![Frame { kind: ACK, data: vec![0x80, 0x01] }, Frame { kind: HELLO, data: vec![] }]);
    }

    /// The sum covers a start byte in the length (126 bytes of data).
    #[test]
    fn start_byte_as_length() {
        let data = vec![1u8; START as usize];
        let wire = encode(KEYS, &data);
        assert_eq!(&wire[..4], &[START, KEYS, START, START]);
        assert_eq!(Decoder::new().push(&wire), vec![Frame { kind: KEYS, data }]);
    }

    /// A lost byte costs that frame only: the reader finds the next start.
    #[test]
    fn lost_byte() {
        let mut first = encode(FROM_ESP, b"hello");
        first.remove(4);
        let wire = [first, encode(FROM_ESP, b"world")].concat();
        let mut d = Decoder::new();
        let frames = d.push(&wire);
        assert_eq!(frames, vec![Frame { kind: FROM_ESP, data: b"world".to_vec() }]);
        assert_eq!(d.dropped, 1);
    }

    #[test]
    fn wrong_sum() {
        let mut wire = encode(TIME, &[1, 2, 3, 4, 5, 6, 7]);
        *wire.last_mut().unwrap() ^= 1;
        let mut d = Decoder::new();
        assert!(d.push(&wire).is_empty());
        assert_eq!(d.dropped, 1);
    }

    /// Noise before the first start (the shell's prompt) is skipped.
    #[test]
    fn noise_before() {
        let wire = [b"SUP> ".to_vec(), encode(HELLO, b"1")].concat();
        assert_eq!(Decoder::new().push(&wire), vec![Frame { kind: HELLO, data: b"1".to_vec() }]);
    }
}
