// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! A YubiKey on a phone's USB-C port, reached through the USB CCID class
//! (USB Device Class Specification for Integrated Circuit(s) Cards Interface
//! Devices, revision 1.1): the app only finds the card's CCID interface,
//! claims it and moves bytes on its bulk endpoints ([`Bulk`]); this module
//! frames each APDU as a `PC_to_RDR_XfrBlock` and reads the reader's
//! `RDR_to_PC_DataBlock`, as pcscd's ccid driver does on a computer. The
//! answer is a [`Card`]'s, so GET RESPONSE stays in piv.rs.
//!
//! A YubiKey that waits for its touch keeps asking for more time (a "time
//! extension": bStatus's command status 2), which resets the wait; the step
//! fails only when the card stays silent for the whole of [`Ccid::patience`]
//! reads.

use super::Card;
use crate::error::{Error, Result};

/// The app's bulk endpoints of the card's CCID interface.
pub trait Bulk: Send {
    /// Sends bytes on the bulk-out endpoint.
    fn write(&mut self, data: &[u8]) -> Result<()>;
    /// Reads one transfer from the bulk-in endpoint, at most `max` bytes;
    /// empty when nothing came within the app's read timeout (about a
    /// second).
    fn read(&mut self, max: usize) -> Result<Vec<u8>>;
}

const PC_TO_RDR_ICC_POWER_ON: u8 = 0x62;
const PC_TO_RDR_XFR_BLOCK: u8 = 0x6f;
const RDR_TO_PC_DATA_BLOCK: u8 = 0x80;
/// The header of every CCID message.
const HEADER: usize = 10;
/// The largest message this side takes: an extended APDU's answer and
/// more, far above what PIV answers in one block.
const MAX_MESSAGE: usize = HEADER + 65_538;
/// The most bytes one bulk-in read asks for.
const READ_MAX: usize = 16 * 1024;

/// How many messages behind an answer may be and still be dropped as late
/// rather than refused.
const STALE: u8 = 8;

pub const SILENT: &str = "the YubiKey on USB did not answer: plug it in again and try once more";

/// A card behind its CCID interface: powered on at the first APDU.
pub struct Ccid<B: Bulk> {
    bulk: B,
    seq: u8,
    powered: bool,
    /// How many empty reads in a row end a step; a time extension resets
    /// the count.
    pub patience: u32,
}

impl<B: Bulk> Ccid<B> {
    pub fn new(bulk: B) -> Ccid<B> {
        Ccid { bulk, seq: 0, powered: false, patience: 30 }
    }

    /// Sends one message of the given type and returns the data of its
    /// answer.
    fn exchange(&mut self, kind: u8, data: &[u8]) -> Result<Vec<u8>> {
        let seq = self.seq;
        self.seq = self.seq.wrapping_add(1);
        let len = u32::try_from(data.len()).map_err(|_| Error::msg("the APDU is too long for CCID"))?;
        let mut m = Vec::with_capacity(HEADER + data.len());
        m.push(kind);
        m.extend_from_slice(&len.to_le_bytes());
        // Slot 0; the sequence number; then for IccPowerOn the automatic
        // voltage, for XfrBlock a BWI of 0 and level parameter 0 (the short
        // APDU exchange, which a YubiKey takes).
        m.extend_from_slice(&[0, seq, 0, 0, 0]);
        m.extend_from_slice(data);
        self.bulk.write(&m)?;
        let mut silent = 0u32;
        loop {
            let a = self.message(&mut silent)?;
            // A late answer to an earlier message, as when the touch came
            // after an earlier step had given up, is dropped; the wait for
            // this one goes on as it was.
            let behind = seq.wrapping_sub(a[6]);
            if (1..=STALE).contains(&behind) {
                continue;
            }
            if a[0] != RDR_TO_PC_DATA_BLOCK {
                return Err(Error::msg(format!("the YubiKey's reader answered with message {:02x}", a[0])));
            }
            if a[6] != seq {
                return Err(Error::msg(format!(
                    "the YubiKey's reader answered message {} while cbb waited for {seq}",
                    a[6]
                )));
            }
            let (status, error) = (a[7], a[8]);
            match status >> 6 {
                0 => return Ok(a[HEADER..].to_vec()),
                // More time, as while the card waits for its touch.
                2 => {
                    silent = 0;
                    continue;
                }
                1 => {
                    return Err(Error::msg(format!(
                        "the YubiKey's reader refused: status {status:02x}, error {error:02x}"
                    )));
                }
                _ => return Err(Error::msg(format!("the YubiKey's reader answered status {status:02x}"))),
            }
        }
    }

    /// Reads one whole message from the reader, which may come in several
    /// transfers; silent counts the empty reads.
    fn message(&mut self, silent: &mut u32) -> Result<Vec<u8>> {
        let mut m = Vec::new();
        loop {
            let want = if m.len() < HEADER { HEADER } else { HEADER + data_len(&m)? };
            if m.len() >= want {
                if m.len() > want {
                    return Err(Error::msg("the YubiKey's reader sent more than its message"));
                }
                return Ok(m);
            }
            let r = self.bulk.read(READ_MAX)?;
            if r.is_empty() {
                *silent += 1;
                if *silent >= self.patience {
                    return Err(Error::msg(SILENT));
                }
                continue;
            }
            m.extend_from_slice(&r);
            if m.len() > MAX_MESSAGE {
                return Err(Error::msg("the YubiKey's reader sent a message too long"));
            }
        }
    }
}

/// The data length a message's header gives.
fn data_len(m: &[u8]) -> Result<usize> {
    let n = u32::from_le_bytes([m[1], m[2], m[3], m[4]]) as usize;
    if HEADER + n > MAX_MESSAGE {
        return Err(Error::msg("the YubiKey's reader announced a message too long"));
    }
    Ok(n)
}

impl<B: Bulk> Card for Ccid<B> {
    fn transmit(&mut self, apdu: &[u8]) -> Result<Vec<u8>> {
        if !self.powered {
            // The answer is the card's ATR, which PIV does not need.
            self.exchange(PC_TO_RDR_ICC_POWER_ON, &[])?;
            self.powered = true;
        }
        let a = self.exchange(PC_TO_RDR_XFR_BLOCK, apdu)?;
        if a.len() < 2 {
            return Err(Error::msg("the YubiKey answered without a status word"));
        }
        Ok(a)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};

    /// A reader that answers by a script: each write is checked against
    /// what the test expects, and each read takes the next transfer.
    #[derive(Default)]
    struct Script {
        written: Vec<Vec<u8>>,
        reads: VecDeque<Vec<u8>>,
    }

    #[derive(Clone, Default)]
    struct Fake(Arc<Mutex<Script>>);

    impl Bulk for Fake {
        fn write(&mut self, data: &[u8]) -> Result<()> {
            self.0.lock().unwrap().written.push(data.to_vec());
            Ok(())
        }
        fn read(&mut self, max: usize) -> Result<Vec<u8>> {
            let mut s = self.0.lock().unwrap();
            let mut r = s.reads.pop_front().unwrap_or_default();
            if r.len() > max {
                let rest = r.split_off(max);
                s.reads.push_front(rest);
            }
            Ok(r)
        }
    }

    fn block(seq: u8, status: u8, data: &[u8]) -> Vec<u8> {
        let mut m = vec![RDR_TO_PC_DATA_BLOCK];
        m.extend_from_slice(&(data.len() as u32).to_le_bytes());
        m.extend_from_slice(&[0, seq, status, 0, 0]);
        m.extend_from_slice(data);
        m
    }

    fn reads(f: &Fake, r: Vec<Vec<u8>>) {
        f.0.lock().unwrap().reads.extend(r);
    }

    #[test]
    fn powers_on_once_and_frames_each_apdu() {
        let f = Fake::default();
        reads(&f, vec![block(0, 0, &[0x3b, 0x8d]), block(1, 0, &[0x90, 0x00]), block(2, 0, &[0x01, 0x90, 0x00])]);
        let mut c = Ccid::new(f.clone());
        assert_eq!(c.transmit(&[0x00, 0xa4, 0x04, 0x00]).unwrap(), vec![0x90, 0x00]);
        assert_eq!(c.transmit(&[0x00, 0xfd, 0x00, 0x00]).unwrap(), vec![0x01, 0x90, 0x00]);
        let w = f.0.lock().unwrap().written.clone();
        assert_eq!(w.len(), 3);
        assert_eq!(w[0], vec![PC_TO_RDR_ICC_POWER_ON, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(w[1], vec![PC_TO_RDR_XFR_BLOCK, 4, 0, 0, 0, 0, 1, 0, 0, 0, 0x00, 0xa4, 0x04, 0x00]);
        assert_eq!(w[2][6], 2, "the sequence number counts up");
    }

    #[test]
    fn waits_through_time_extensions_for_the_touch() {
        let f = Fake::default();
        let mut r = vec![block(0, 0, &[0x3b])];
        // The card asks for more time again and again while it waits for
        // the touch, with silent reads between: more than patience in all,
        // fewer in a row.
        for _ in 0..5 {
            r.push(block(1, 0x80, &[]));
            r.push(Vec::new());
            r.push(Vec::new());
        }
        r.push(block(1, 0, &[0xaa, 0x90, 0x00]));
        reads(&f, r);
        let mut c = Ccid::new(f);
        c.patience = 3;
        assert_eq!(c.transmit(&[0x00, 0x87, 0x11, 0x9a]).unwrap(), vec![0xaa, 0x90, 0x00]);
    }

    #[test]
    fn a_silent_card_ends_the_step() {
        let f = Fake::default();
        reads(&f, vec![block(0, 0, &[0x3b])]);
        let mut c = Ccid::new(f);
        c.patience = 4;
        let e = c.transmit(&[0x00, 0xa4, 0x04, 0x00]).unwrap_err();
        assert!(e.to_string().contains("did not answer"), "{e}");
    }

    #[test]
    fn a_message_in_several_transfers_is_joined() {
        let f = Fake::default();
        let data: Vec<u8> = (0..300u16).map(|i| i as u8).chain([0x90, 0x00]).collect();
        let whole = block(1, 0, &data);
        reads(
            &f,
            vec![
                block(0, 0, &[0x3b]),
                whole[..64].to_vec(),
                Vec::new(),
                whole[64..200].to_vec(),
                whole[200..].to_vec(),
            ],
        );
        let mut c = Ccid::new(f);
        assert_eq!(c.transmit(&[0x00, 0xcb, 0x3f, 0xff]).unwrap(), data);
    }

    #[test]
    fn refuses_a_wrong_sequence_number() {
        let f = Fake::default();
        reads(&f, vec![block(0, 0, &[0x3b]), block(7, 0, &[0x90, 0x00])]);
        let mut c = Ccid::new(f);
        let e = c.transmit(&[0x00, 0xa4, 0x04, 0x00]).unwrap_err();
        assert!(e.to_string().contains("waited for 1"), "{e}");
    }

    #[test]
    fn drops_a_late_answer_to_an_earlier_message() {
        let f = Fake::default();
        // The earlier step's answer (seq 1) arrives while the next one
        // (seq 2) waits; the right one follows.
        reads(
            &f,
            vec![
                block(0, 0, &[0x3b]),
                block(1, 0, &[0x90, 0x00]),
                block(2, 0, &[0x6a, 0x82]),
                block(1, 0, &[0x90, 0x00]),
                block(3, 0, &[0x90, 0x00]),
            ],
        );
        let mut c = Ccid::new(f);
        assert_eq!(c.transmit(&[0x00, 0xa4, 0x04, 0x00]).unwrap(), [0x90, 0x00]);
        assert_eq!(c.transmit(&[0x00, 0xa4, 0x04, 0x00]).unwrap(), [0x6a, 0x82]);
        assert_eq!(c.transmit(&[0x00, 0xa4, 0x04, 0x00]).unwrap(), [0x90, 0x00]);
    }

    #[test]
    fn refuses_an_answer_from_the_future_or_far_off() {
        for wrong in [2u8, 200] {
            let f = Fake::default();
            reads(&f, vec![block(0, 0, &[0x3b]), block(wrong, 0, &[0x90, 0x00])]);
            let mut c = Ccid::new(f);
            let e = c.transmit(&[0x00, 0xa4, 0x04, 0x00]).unwrap_err();
            assert!(e.to_string().contains("waited for 1"), "{wrong}: {e}");
        }
    }

    #[test]
    fn refuses_short_long_and_failed_answers() {
        // An answer without a status word.
        let f = Fake::default();
        reads(&f, vec![block(0, 0, &[0x3b]), block(1, 0, &[0x90])]);
        assert!(Ccid::new(f).transmit(&[0, 0xa4, 4, 0]).unwrap_err().to_string().contains("status word"));
        // More bytes than the header announced.
        let f = Fake::default();
        let mut long = block(1, 0, &[0x90, 0x00]);
        long.push(0xff);
        reads(&f, vec![block(0, 0, &[0x3b]), long]);
        assert!(Ccid::new(f).transmit(&[0, 0xa4, 4, 0]).unwrap_err().to_string().contains("more than its message"));
        // A failed command: no card in the slot.
        let f = Fake::default();
        reads(&f, vec![block(0, 0x42, &[])]);
        assert!(Ccid::new(f).transmit(&[0, 0xa4, 4, 0]).unwrap_err().to_string().contains("refused"));
        // A header that announces more than any answer.
        let f = Fake::default();
        let mut huge = block(0, 0, &[]);
        huge[1..5].copy_from_slice(&(u32::MAX).to_le_bytes());
        reads(&f, vec![huge]);
        assert!(Ccid::new(f).transmit(&[0, 0xa4, 4, 0]).unwrap_err().to_string().contains("too long"));
        // Another message type.
        let f = Fake::default();
        let mut other = block(0, 0, &[]);
        other[0] = 0x81;
        reads(&f, vec![other]);
        assert!(Ccid::new(f).transmit(&[0, 0xa4, 4, 0]).unwrap_err().to_string().contains("message 81"));
    }

    #[test]
    fn piv_runs_over_ccid() {
        // The member's own fake YubiKey behind a fake CCID reader: selecting
        // PIV and reading the version go through the framing both ways.
        struct Reader {
            card: crate::piv::recovery::tests::Yubi,
            out: VecDeque<Vec<u8>>,
        }
        #[derive(Clone)]
        struct R(Arc<Mutex<Reader>>);
        impl Bulk for R {
            fn write(&mut self, m: &[u8]) -> Result<()> {
                let mut r = self.0.lock().unwrap();
                let seq = m[6];
                let a = match m[0] {
                    PC_TO_RDR_ICC_POWER_ON => block(seq, 0, &[0x3b]),
                    PC_TO_RDR_XFR_BLOCK => {
                        let ans = r.card.handle(&m[HEADER..]);
                        // A time extension before every answer.
                        r.out.push_back(block(seq, 0x80, &[]));
                        block(seq, 0, &ans)
                    }
                    _ => panic!("message {:02x}", m[0]),
                };
                r.out.push_back(a);
                Ok(())
            }
            fn read(&mut self, _: usize) -> Result<Vec<u8>> {
                Ok(self.0.lock().unwrap().out.pop_front().unwrap_or_default())
            }
        }
        let r = R(Arc::new(Mutex::new(Reader {
            card: crate::piv::recovery::tests::Yubi::new([5, 4, 3]),
            out: VecDeque::new(),
        })));
        let mut c = Ccid::new(r);
        let i = crate::piv::recovery::inspect(&mut c, "123456").unwrap();
        assert!(i.default_key);
    }
}
