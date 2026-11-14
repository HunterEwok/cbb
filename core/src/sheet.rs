// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The 0.6 recovery sheet: the group's 32-byte recovery secret on paper,
//! as text a person types and as a QR code, each with its version. The
//! keys come from the secret in `records::pq::recovery_keys`; the sheet adds
//! no derivation of its own.
//!
//! The text is Crockford's base32 in 4 lines of 4 groups of 4 characters.
//! Its 56 data characters are the version (`1`), the secret (52 characters,
//! the last 4 bits zero) and a whole-sheet check (3 characters, 15 bits);
//! each line is 14 of them and a line check (2 characters, 10 bits), so a
//! reader says which line holds a mistake, and when every line check holds
//! but the whole check does not, that the typing has a mistake rather than
//! that the sheet is another group's.
//!
//! The QR code is text in QR's alphanumeric mode: `CBBR`, the version and
//! the base32 of the secret and the Group ID (77 characters, the last bit
//! zero). Every check is over the canonical form: upper case, `I` and `L`
//! read as `1`, `O` as `0`, spaces and hyphens dropped. A later version is
//! "needs a newer cbb", and nothing else of it is read.

use alloc::string::String;
use alloc::vec::Vec;

use zeroize::{Zeroize, Zeroizing};

use crate::format::sha256;
use crate::records::key::{GroupId, Recovery};

/// Crockford's base32 alphabet.
const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
/// The version this program writes and reads, as its character.
pub const VERSION: u8 = b'1';
/// The label of each line's check.
pub const LABEL_LINE: &str = "cbb recovery sheet v1";
/// The label of the whole-sheet check.
pub const LABEL_WHOLE: &str = "cbb recovery sheet v1 whole";
/// The start of the QR code's text.
pub const QR_PREFIX: &str = "CBBR";
/// The lines of the text.
pub const LINES: usize = 4;
/// The data characters of one line.
pub const LINE_DATA: usize = 14;
/// The check characters of one line.
pub const LINE_CHECK: usize = 2;
/// The characters of one line: 4 groups of 4.
pub const LINE: usize = LINE_DATA + LINE_CHECK;
/// The characters of the text.
pub const TEXT: usize = LINES * LINE;
/// The secret's characters.
const SECRET_CHARS: usize = 52;
/// The whole-sheet check's characters.
const WHOLE_CHARS: usize = 3;
/// The characters of a 0.5 sheet's text, which 0.6 does not read.
const EARLIER_TEXT: usize = 56;
/// The start of a 0.5 sheet's QR code (`cbb://recover?`) in the canonical
/// form, where `O` reads as `0`.
const EARLIER_QR: &str = "CBB://REC0VER?";
/// The characters after the QR's prefix and version: 48 bytes in base32.
const QR_DATA: usize = 77;
/// The QR code's characters: the prefix, the version and the data.
pub const QR_TEXT: usize = QR_PREFIX.len() + 1 + QR_DATA;
/// The longest input read, with room for spaces and line ends.
pub const MAX_INPUT: usize = 512;

const _: () = assert!(1 + SECRET_CHARS + WHOLE_CHARS == LINES * LINE_DATA);

/// Why a sheet was refused, in the words an app shows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reason {
    /// Neither a sheet's text nor its QR code.
    NotSheet,
    /// A sheet of an earlier cbb (0.5), whose groups 0.6 made anew.
    Earlier,
    /// A sheet of a later version: "this sheet needs a newer cbb".
    Newer,
    /// Not as many characters as a sheet has.
    Length,
    /// A character outside the alphabet after the first.
    Damaged,
    /// The lines whose check fails, as bits: line 1 is bit 0.
    Lines(u8),
    /// Padding bits that are not zero.
    Padding,
    /// Every line check holds and the whole check does not: a mistake in
    /// the typing that the line checks missed.
    Whole,
    /// The sheet is for another group.
    OtherGroup,
}

impl Reason {
    /// What the app tells the person.
    pub fn message(&self) -> &'static str {
        match self {
            Reason::NotSheet => "this is not a cbb recovery sheet",
            Reason::Earlier => "this is a sheet of an earlier cbb, whose groups were made anew",
            Reason::Newer => "this sheet needs a newer cbb",
            Reason::Length => "a recovery sheet has 4 lines of 16 characters",
            Reason::Damaged => "a character is not one a recovery sheet uses",
            Reason::Lines(_) => "a line has a mistake",
            Reason::Padding => "the sheet has a mistake",
            Reason::Whole => "there is a mistake in the typing",
            Reason::OtherGroup => "this sheet is for another group",
        }
    }
}

/// What a sheet gave: the secret, and from a QR code the Group ID.
pub struct Read {
    pub secret: Zeroizing<[u8; 32]>,
    pub group: Option<GroupId>,
}

fn value(c: u8) -> Option<u8> {
    ALPHABET.iter().position(|a| *a == c).and_then(|p| u8::try_from(p).ok())
}

/// The canonical form: upper case, `I` and `L` as `1`, `O` as `0`, spaces,
/// line ends and hyphens dropped. Other characters stay, to be refused.
fn canonical(s: &str) -> Zeroizing<Vec<u8>> {
    let mut out = Zeroizing::new(Vec::with_capacity(s.len()));
    for c in s.chars() {
        if c == '-' || c.is_whitespace() {
            continue;
        }
        let c = match c.to_ascii_uppercase() {
            'I' | 'L' => '1',
            'O' => '0',
            c => c,
        };
        out.push(if c.is_ascii() { c as u8 } else { 0 });
    }
    out
}

/// The character of the low 5 bits of v.
fn symbol(v: u32) -> u8 {
    ALPHABET.get((v & 31) as usize).copied().unwrap_or(b'0')
}

/// Bytes as base32 characters, the last character's spare bits zero.
fn encode32(b: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut out = Zeroizing::new(Vec::with_capacity(b.len().saturating_mul(8).div_ceil(5)));
    let (mut acc, mut bits) = (0u32, 0u32);
    for &x in b {
        acc = (acc << 8) | u32::from(x);
        bits = bits.saturating_add(8);
        while bits >= 5 {
            bits = bits.saturating_sub(5);
            out.push(symbol(acc >> bits));
        }
    }
    if bits > 0 {
        out.push(symbol(acc << 5u32.saturating_sub(bits)));
    }
    acc.zeroize();
    out
}

/// Base32 characters as n bytes; Padding when the spare bits are not zero.
fn decode32(chars: &[u8], n: usize) -> Result<Zeroizing<Vec<u8>>, Reason> {
    if chars.len() != n.saturating_mul(8).div_ceil(5) {
        return Err(Reason::Length);
    }
    let mut out = Zeroizing::new(Vec::with_capacity(n));
    let (mut acc, mut bits) = (0u32, 0u32);
    for &c in chars {
        acc = (acc << 5) | u32::from(value(c).ok_or(Reason::Damaged)?);
        bits = bits.saturating_add(5);
        if bits >= 8 {
            bits = bits.saturating_sub(8);
            out.push((acc >> bits) as u8);
        }
    }
    let spare = acc & 1u32.checked_shl(bits).map_or(u32::MAX, |m| m.saturating_sub(1));
    acc.zeroize();
    if spare != 0 {
        return Err(Reason::Padding);
    }
    Ok(out)
}

/// The first `n` bits (10 or 15) of a digest as base32 characters.
fn check_chars(digest: &[u8; 32], n: u32) -> Vec<u8> {
    let bits = u32::from(u16::from_be_bytes([digest[0], digest[1]])) >> 16u32.saturating_sub(n);
    (0..n / 5).rev().map(|i: u32| symbol(bits >> i.saturating_mul(5))).collect()
}

fn line_check(line: usize, data: &[u8]) -> Vec<u8> {
    let number = [u8::try_from(line.saturating_add(1)).unwrap_or(0)];
    check_chars(&sha256(&[LABEL_LINE.as_bytes(), &[0], &number, data]), 10)
}

fn whole_check(version: u8, secret: &[u8; 32]) -> Vec<u8> {
    check_chars(&sha256(&[LABEL_WHOLE.as_bytes(), &[0], &[version], secret]), 15)
}

/// The sheet's text: 4 lines of 4 groups of 4 characters, the groups apart
/// by a space and the lines by a line end.
pub fn text(secret: &[u8; 32]) -> String {
    let mut data = Zeroizing::new(Vec::with_capacity(LINES * LINE_DATA));
    data.push(VERSION);
    data.extend_from_slice(&encode32(secret));
    data.extend(whole_check(VERSION, secret));
    let mut out = String::with_capacity(TEXT + TEXT / 4);
    for (i, line) in data.chunks(LINE_DATA).enumerate() {
        let mut chars = Zeroizing::new(line.to_vec());
        chars.extend(line_check(i, line));
        if i > 0 {
            out.push('\n');
        }
        for (j, group) in chars.chunks(4).enumerate() {
            if j > 0 {
                out.push(' ');
            }
            out.extend(group.iter().map(|&c| char::from(c)));
        }
    }
    out
}

/// The QR code's text for the secret and the group.
pub fn qr(secret: &[u8; 32], group: &GroupId) -> String {
    let mut b = Zeroizing::new(Vec::with_capacity(48));
    b.extend_from_slice(secret);
    b.extend_from_slice(&group.0);
    let mut out = String::with_capacity(QR_TEXT);
    out.push_str(QR_PREFIX);
    out.push(char::from(VERSION));
    out.extend(encode32(&b).iter().map(|&c| char::from(c)));
    out
}

/// Reads a sheet's text or its QR code.
pub fn read(input: &str) -> Result<Read, Reason> {
    if input.len() > MAX_INPUT {
        return Err(Reason::NotSheet);
    }
    let c = canonical(input);
    if c.starts_with(EARLIER_QR.as_bytes()) {
        return Err(Reason::Earlier);
    }
    match c.strip_prefix(QR_PREFIX.as_bytes()) {
        Some(rest) => read_qr(rest),
        None => read_text(&c),
    }
}

fn read_qr(rest: &[u8]) -> Result<Read, Reason> {
    let (&version, data) = rest.split_first().ok_or(Reason::NotSheet)?;
    if version != VERSION {
        return Err(Reason::Newer);
    }
    if data.len() != QR_DATA {
        return Err(Reason::Length);
    }
    let b = decode32(data, 48)?;
    let mut secret = Zeroizing::new([0u8; 32]);
    secret.copy_from_slice(b.get(..32).ok_or(Reason::Length)?);
    let group = b.get(32..48).and_then(GroupId::from_slice).ok_or(Reason::Length)?;
    Ok(Read { secret, group: Some(group) })
}

fn read_text(c: &[u8]) -> Result<Read, Reason> {
    let (&version, _) = c.split_first().ok_or(Reason::NotSheet)?;
    if value(version).is_none() {
        return Err(Reason::NotSheet);
    }
    // A character outside the alphabet is a mistake in a sheet's text of
    // its length, and otherwise no sheet: words are not a later version.
    if c.iter().any(|&x| value(x).is_none()) {
        return Err(if c.len() == TEXT && version == VERSION { Reason::Damaged } else { Reason::NotSheet });
    }
    if c.len() == EARLIER_TEXT {
        return Err(Reason::Earlier);
    }
    if version != VERSION {
        return Err(Reason::Newer);
    }
    if c.len() != TEXT {
        return Err(Reason::Length);
    }
    let mut wrong = 0u8;
    let mut data = Zeroizing::new(Vec::with_capacity(LINES * LINE_DATA));
    for (i, line) in c.chunks(LINE).enumerate() {
        let (d, check) = line.split_at(LINE_DATA);
        if line_check(i, d) != check {
            wrong |= 1 << i;
        }
        data.extend_from_slice(d);
    }
    if wrong != 0 {
        return Err(Reason::Lines(wrong));
    }
    let s = decode32(data.get(1..1 + SECRET_CHARS).ok_or(Reason::Length)?, 32)?;
    let mut secret = Zeroizing::new([0u8; 32]);
    secret.copy_from_slice(&s);
    if data.get(1 + SECRET_CHARS..) != Some(whole_check(version, &secret).as_slice()) {
        return Err(Reason::Whole);
    }
    Ok(Read { secret, group: None })
}

/// Checks what a sheet gave against the group: K1 and K2 from the secret
/// must be the group's recovery keys. A QR code naming another group is
/// another group's; one naming this group with other keys is damaged; a
/// text with other keys is another group's (its checks held).
pub fn check(read: &Read, group: &GroupId, recovery: &Recovery) -> Result<(), Reason> {
    if read.group.as_ref().is_some_and(|g| g != group) {
        return Err(Reason::OtherGroup);
    }
    match (check_keys(read, recovery), read.group.is_some()) {
        (true, _) => Ok(()),
        (false, true) => Err(Reason::Damaged),
        (false, false) => Err(Reason::OtherGroup),
    }
}

/// Whether K1 and K2 from the secret are the group's recovery keys.
fn check_keys(read: &Read, recovery: &Recovery) -> bool {
    crate::records::pq::recovery_keys(&read.secret).is_ok_and(|(k1, k2)| {
        use p256::elliptic_curve::sec1::ToSec1Point as _;
        let p1 = k1.public_key().to_sec1_point(false).as_bytes().to_vec();
        p1 == recovery.k1.public() && k2.public() == recovery.k2.public()
    })
}

pub mod yubikey;

#[cfg(test)]
mod tests;
