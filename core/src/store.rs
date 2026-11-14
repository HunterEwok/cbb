// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The saved state of a member without a file system, such as the ESP32
//! with only its flash. The state is a set of fields, each a tag and its
//! bytes, saved whole into one of two slots. A save goes to the slot that
//! does not hold the newest copy, so a power cut while it is written leaves
//! the last good copy readable; a load takes the newest slot whose frame is
//! intact.
//!
//! A frame is the magic "cbb1", a sequence number (u32, little-endian), the
//! payload's length (u32, little-endian), the payload and the SHA-256 of all
//! that came before it. Erased flash (all 0xff) is no frame.
//!
//! Versions: the magic's digit is the frame's layout, and the field
//! [`FIELD_VERSION`] the oldest version of this store that reads the fields
//! (absent: 1). A later program reads every earlier store. An earlier one
//! that finds a later frame or a later version stops ([`load`] gives
//! [`Newer`]) and changes nothing: it never takes the store for empty and
//! starts as new.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use crate::certs::sha256;

const MAGIC: &[u8; 4] = b"cbb1";

/// The version of the store this program writes and reads.
pub const VERSION: u32 = 1;

/// The reserved field 0: the oldest version of the store that reads these
/// fields, a u32 little-endian; absent, 1. A program writes it only when it
/// changes the fields so that an earlier one would misread them.
pub const FIELD_VERSION: u8 = 0;

/// A store of a later program: a frame of a later layout in either slot,
/// or fields whose [`FIELD_VERSION`] is above [`VERSION`]. The program
/// stops with a clear message and writes nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Newer;
/// The length of a frame's header: the magic, the sequence number and the
/// payload's length.
pub const HEADER: usize = 12;
const DIGEST: usize = 32;

/// How many bytes a frame of a payload of len bytes takes in its slot.
pub const fn frame_len(len: usize) -> usize {
    HEADER.saturating_add(len).saturating_add(DIGEST)
}

/// A frame for seq and payload, to write at the start of a slot.
pub fn frame(seq: u32, payload: &[u8]) -> Vec<u8> {
    let mut f = Vec::with_capacity(frame_len(payload.len()));
    f.extend_from_slice(MAGIC);
    f.extend_from_slice(&seq.to_le_bytes());
    f.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    f.extend_from_slice(payload);
    let digest = sha256(&f);
    f.extend_from_slice(&digest);
    f
}

/// The length of the frame whose header starts head, or None if head starts
/// no frame. It lets a reader fetch the header first and then only as much
/// as the frame takes.
pub fn frame_len_in(head: &[u8]) -> Option<usize> {
    if head.get(..4)? != MAGIC {
        return None;
    }
    let len = u32::from_le_bytes(head.get(8..HEADER)?.try_into().ok()?) as usize;
    HEADER.checked_add(len)?.checked_add(DIGEST)
}

/// The sequence number and payload of the frame at the start of slot, or
/// None if it holds no intact frame.
pub fn read(slot: &[u8]) -> Option<(u32, &[u8])> {
    let len = frame_len_in(slot)?;
    let end = len.checked_sub(DIGEST)?;
    if sha256(slot.get(..end)?)[..] != *slot.get(end..len)? {
        return None;
    }
    let seq = u32::from_le_bytes(slot.get(4..8)?.try_into().ok()?);
    Some((seq, slot.get(HEADER..end)?))
}

/// The newest intact copy among the two slots.
#[derive(Debug, PartialEq, Eq)]
pub struct Newest<'a> {
    pub slot: usize,
    pub seq: u32,
    pub payload: &'a [u8],
}

/// Picks the newest intact copy. Sequence numbers wrap: b is newer than a
/// when it is less than half the range ahead of it.
pub fn newest<'a>(a: &'a [u8], b: &'a [u8]) -> Option<Newest<'a>> {
    match (read(a), read(b)) {
        (None, None) => None,
        (Some((seq, payload)), None) => Some(Newest { slot: 0, seq, payload }),
        (None, Some((seq, payload))) => Some(Newest { slot: 1, seq, payload }),
        (Some((sa, pa)), Some((sb, pb))) => {
            if (sb.wrapping_sub(sa) as i32) > 0 {
                Some(Newest { slot: 1, seq: sb, payload: pb })
            } else {
                Some(Newest { slot: 0, seq: sa, payload: pa })
            }
        }
    }
}

/// Whether slot starts with the magic of a later layout ("cbb" and a digit
/// above 1), intact or not: torn or whole, it is a later program's.
fn later_frame(slot: &[u8]) -> bool {
    match slot.get(..4) {
        Some([b'c', b'b', b'b', d]) => d.is_ascii_digit() && *d > MAGIC[3],
        _ => false,
    }
}

/// The store at a start: the newest intact copy among the two slots, or
/// none, unless a later program wrote either slot or its fields ask for a
/// later version ([`Newer`]). Fields that do not decode are the caller's to
/// report as damaged.
pub fn load<'a>(a: &'a [u8], b: &'a [u8]) -> Result<Option<Newest<'a>>, Newer> {
    if later_frame(a) || later_frame(b) {
        return Err(Newer);
    }
    let n = newest(a, b);
    if let Some(f) = n.as_ref().and_then(|n| Fields::decode(n.payload))
        && f.version() > VERSION
    {
        return Err(Newer);
    }
    Ok(n)
}

/// Where the next save goes, and its sequence number: the other slot than
/// the newest copy's, one number on.
pub fn next(newest: Option<(usize, u32)>) -> (usize, u32) {
    match newest {
        None => (0, 0),
        Some((slot, seq)) => (if slot == 0 { 1 } else { 0 }, seq.wrapping_add(1)),
    }
}

/// The saved fields, each a tag and its bytes. Tags the program does not
/// know are kept as they are, so an older firmware does not drop what a
/// newer one saved.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Fields(BTreeMap<u8, Vec<u8>>);

impl Fields {
    pub fn get(&self, tag: u8) -> Option<&[u8]> {
        self.0.get(&tag).map(Vec::as_slice)
    }

    pub fn set(&mut self, tag: u8, value: impl Into<Vec<u8>>) {
        self.0.insert(tag, value.into());
    }

    pub fn remove(&mut self, tag: u8) {
        self.0.remove(&tag);
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// The oldest version of the store that reads these fields
    /// ([`FIELD_VERSION`]): 1 when absent, and above any version when it is
    /// not four bytes.
    pub fn version(&self) -> u32 {
        match self.get(FIELD_VERSION) {
            None => 1,
            Some(v) => <[u8; 4]>::try_from(v).map_or(u32::MAX, u32::from_le_bytes),
        }
    }

    /// Each field as its tag, its length (u32, little-endian) and its bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for (tag, value) in &self.0 {
            out.push(*tag);
            out.extend_from_slice(&(value.len() as u32).to_le_bytes());
            out.extend_from_slice(value);
        }
        out
    }

    /// The fields of an encoding, or None if it is cut short.
    pub fn decode(mut b: &[u8]) -> Option<Fields> {
        let mut fields = BTreeMap::new();
        while let Some((&tag, rest)) = b.split_first() {
            let len = u32::from_le_bytes(rest.get(..4)?.try_into().ok()?) as usize;
            let end = 4usize.checked_add(len)?;
            let value = rest.get(4..end)?;
            fields.insert(tag, value.to_vec());
            b = rest.get(end..)?;
        }
        Some(Fields(fields))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An earlier program that finds a later program's store stops and
    /// never takes it for empty; a later program reads this one's.
    #[test]
    fn a_later_store_stops_an_earlier_program() {
        let empty = slot(&[]);
        let ours = slot(&frame(3, &Fields::default().encode()));
        assert_eq!(load(&empty, &empty), Ok(None));
        assert_eq!(load(&ours, &empty).unwrap().unwrap().seq, 3);
        // A frame of a later layout, whole or torn, in either slot.
        let mut later = frame(9, b"later");
        later[3] = b'2';
        let torn = slot(&later[..10]);
        for s in [slot(&later), torn] {
            assert_eq!(read(&s), None);
            assert_eq!(load(&s, &empty), Err(Newer));
            assert_eq!(load(&ours, &s), Err(Newer));
        }
        // Fields that ask for a later version, or say it in another form.
        for v in [2u32.to_le_bytes().to_vec(), vec![1]] {
            let mut f = Fields::default();
            f.set(1, b"wifi".to_vec());
            f.set(FIELD_VERSION, v);
            assert_eq!(load(&slot(&frame(4, &f.encode())), &empty), Err(Newer));
        }
        // Version 1 written is this program's.
        let mut f = Fields::default();
        f.set(FIELD_VERSION, VERSION.to_le_bytes().to_vec());
        assert_eq!(load(&slot(&frame(5, &f.encode())), &ours).unwrap().unwrap().seq, 5);
    }

    fn slot(frame: &[u8]) -> Vec<u8> {
        let mut s = frame.to_vec();
        s.resize(256, 0xff);
        s
    }

    #[test]
    fn frame_round_trip() {
        let s = slot(&frame(7, b"hello"));
        assert_eq!(read(&s), Some((7, &b"hello"[..])));
        assert_eq!(frame(7, b"hello").len(), frame_len(5));
        assert_eq!(frame_len_in(&s[..HEADER]), Some(frame_len(5)));
        assert_eq!(frame_len_in(&[0xff; HEADER]), None);
        assert_eq!(frame_len_in(&s[..HEADER - 1]), None);
    }

    #[test]
    fn erased_and_damaged_slots_hold_nothing() {
        assert_eq!(read(&[0xff; 256]), None);
        assert_eq!(read(&[]), None);
        let mut s = slot(&frame(1, b"hello"));
        s[HEADER] ^= 1;
        assert_eq!(read(&s), None);
        // A length that runs past the slot.
        let mut s = frame(1, b"hello");
        s[8..12].copy_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(read(&s), None);
        // A frame cut short, as by a power cut.
        let f = frame(1, b"hello");
        assert_eq!(read(&f[..f.len() - 1]), None);
    }

    #[test]
    fn newest_takes_the_later_intact_slot() {
        let erased = [0xff; 256];
        assert_eq!(newest(&erased, &erased), None);
        assert_eq!(next(None), (0, 0));

        let a = slot(&frame(0, b"one"));
        let n = newest(&a, &erased).unwrap();
        assert_eq!((n.slot, n.seq, n.payload), (0, 0, &b"one"[..]));
        assert_eq!(next(Some((n.slot, n.seq))), (1, 1));

        let b = slot(&frame(1, b"two"));
        let n = newest(&a, &b).unwrap();
        assert_eq!((n.slot, n.payload), (1, &b"two"[..]));
        assert_eq!(next(Some((n.slot, n.seq))), (0, 2));

        // A save into slot 0 that a power cut broke: slot 1 still holds the last good copy.
        let mut torn = slot(&frame(2, b"three"));
        torn[20] ^= 0x55;
        assert_eq!(newest(&torn, &b).unwrap().payload, b"two");
    }

    #[test]
    fn sequence_numbers_wrap() {
        let a = slot(&frame(u32::MAX, b"old"));
        let b = slot(&frame(0, b"new"));
        assert_eq!(newest(&a, &b).unwrap().payload, b"new");
        assert_eq!(newest(&b, &a).unwrap().payload, b"new");
        let n = newest(&b, &a).unwrap();
        assert_eq!(next(Some((n.slot, n.seq))), (1, 1));
    }

    #[test]
    fn fields_round_trip_and_keep_unknown_tags() {
        let mut f = Fields::default();
        assert!(f.is_empty());
        f.set(1, "home");
        f.set(2, b"secret".to_vec());
        f.set(200, vec![]);
        let g = Fields::decode(&f.encode()).unwrap();
        assert_eq!(g, f);
        assert_eq!(g.get(1), Some(&b"home"[..]));
        assert_eq!(g.get(200), Some(&[][..]));
        f.remove(2);
        assert_eq!(f.get(2), None);
        assert_eq!(Fields::decode(&[]), Some(Fields::default()));
    }

    #[test]
    fn fields_cut_short_do_not_decode() {
        let mut f = Fields::default();
        f.set(1, "home");
        let e = f.encode();
        for n in 1..e.len() {
            assert_eq!(Fields::decode(&e[..n]), None, "cut at {n}");
        }
    }
}
