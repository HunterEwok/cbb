// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! Signing with the group's recovery key on a YubiKey, or another card with
//! the PIV application (NIST SP 800-73-4), as Go's internal/piv does: the
//! root phone made the key in a free retired slot (82 to 95), where it never
//! leaves the card, and stored the key's admin CA as the slot's certificate
//! (docs/protocol.md, section 10, "The recovery key"). The YubiKey may be in
//! daily use for other things, so nothing else on it is touched: select the
//! application, find the slot whose certificate is the recovery key's, check
//! the PIN and sign a SHA-256 digest with P-256. cbb does this itself,
//! without cbb-helper; the card is reached through PC/SC (pcscd's socket on
//! Linux, PCSC.framework on a Mac, winscard on Windows).

use cbb_core::certs::Cert;

use crate::error::{Error, Result};

/// A connection to one card: transmit sends an APDU and returns the answer
/// with its status word last. Dropping it disconnects.
pub trait Card: Send {
    fn transmit(&mut self, apdu: &[u8]) -> Result<Vec<u8>>;
}

/// The PIV application's identifier.
const AID: &[u8] = &[0xa0, 0x00, 0x00, 0x03, 0x08];

/// The retired key slots, where the recovery key goes.
pub const FIRST_SLOT: u8 = 0x82;
pub const LAST_SLOT: u8 = 0x95;
/// The PIV algorithm of an ECC P-256 key.
const ALG_ECC_P256: u8 = 0x11;
/// The PIV application PIN's reference.
const PIN_REF: u8 = 0x80;

/// The most one command takes from the card: a certificate object is at
/// most a few kilobytes.
const MAX_ANSWER: usize = 16 << 10;

pub const NO_CARD: &str = "no YubiKey found: plug it in, or hold it to the reader";
pub const TWO_CARDS: &str = "two YubiKeys hold the recovery key: leave only one plugged in";
pub const NO_KEY: &str = "this YubiKey holds no recovery key of the group: the root phone puts it in a retired PIV slot with its certificate, and a newer recovery key replaces the older one";
pub const BLOCKED: &str = "the YubiKey's PIN is blocked: unblock it with its PUK (ykman piv access unblock-pin)";

fn refused(sw: u16) -> Error {
    Error::msg(format!("the YubiKey refused: status {sw:04x}"))
}

/// The data object of a retired slot's certificate: 5FC10D for slot 82, up
/// to 5FC120 for slot 95.
fn cert_object(slot: u8) -> [u8; 3] {
    [0x5f, 0xc1, 0x0d + slot - FIRST_SLOT]
}

/// Sends one command and returns its data, following the card's "more
/// data" answers (61xx) with GET RESPONSE, and its status word.
fn transmit(c: &mut dyn Card, apdu: &[u8]) -> Result<(Vec<u8>, u16)> {
    let mut out = Vec::new();
    let mut apdu = apdu.to_vec();
    loop {
        let r = c.transmit(&apdu)?;
        if r.len() < 2 {
            return Err(Error::msg("the YubiKey answered without a status word"));
        }
        out.extend_from_slice(&r[..r.len() - 2]);
        if out.len() > MAX_ANSWER {
            return Err(Error::msg("the YubiKey's answer is too long"));
        }
        let (sw1, sw2) = (r[r.len() - 2], r[r.len() - 1]);
        if sw1 != 0x61 {
            return Ok((out, u16::from(sw1) << 8 | u16::from(sw2)));
        }
        apdu = vec![0x00, 0xc0, 0x00, 0x00, sw2];
    }
}

/// Builds a short APDU: CLA INS P1 P2, then Lc and data when there is data,
/// then Le 00; data longer than 255 bytes goes in a chain of commands (CLA
/// 10 on all but the last), and the last one's answer is returned.
fn command(c: &mut dyn Card, ins: u8, p1: u8, p2: u8, mut data: &[u8]) -> Result<(Vec<u8>, u16)> {
    while data.len() > 255 {
        let mut apdu = vec![0x10, ins, p1, p2, 255];
        apdu.extend_from_slice(&data[..255]);
        let (_, sw) = transmit(c, &apdu)?;
        if sw != 0x9000 {
            return Ok((Vec::new(), sw));
        }
        data = &data[255..];
    }
    let mut apdu = vec![0x00, ins, p1, p2];
    if !data.is_empty() {
        apdu.push(data.len() as u8);
        apdu.extend_from_slice(data);
    }
    apdu.push(0);
    transmit(c, &apdu)
}

/// Selects the PIV application.
pub fn select(c: &mut dyn Card) -> Result<()> {
    match command(c, 0xa4, 0x04, 0x00, AID)? {
        (_, 0x9000) => Ok(()),
        (_, sw) => Err(refused(sw)),
    }
}

/// Reads a retired slot's certificate; None if it holds none.
pub fn certificate(c: &mut dyn Card, slot: u8) -> Result<Option<Cert>> {
    if !(FIRST_SLOT..=LAST_SLOT).contains(&slot) {
        return Err(Error::msg("not a retired PIV slot"));
    }
    let data = match command(c, 0xcb, 0x3f, 0xff, &tlv(0x5c, &cert_object(slot)))? {
        (_, 0x6a82) => return Ok(None),
        (d, 0x9000) => d,
        (_, sw) => return Err(refused(sw)),
    };
    let bad = |what: &str| Error::msg(format!("the YubiKey's certificate object {what}"));
    let (obj, rest) = read_tlv(&data, 0x53).ok_or_else(|| bad("does not parse"))?;
    if !rest.is_empty() {
        return Err(bad("does not parse"));
    }
    let (der, rest) = read_tlv(obj, 0x70).ok_or_else(|| bad("holds no certificate"))?;
    // 71 says whether it is compressed; the root phone never compresses it.
    if let Some((info, _)) = read_tlv(rest, 0x71)
        && info.len() == 1
        && info[0] != 0
    {
        return Err(bad("is compressed"));
    }
    Ok(Some(Cert::parse(der)?))
}

/// Checks the PIN, which the card then takes as given until the connection
/// ends.
pub fn verify(c: &mut dyn Card, pin: &str) -> Result<()> {
    if !(6..=8).contains(&pin.len()) {
        return Err(Error::msg("a YubiKey's PIN has 6 to 8 characters"));
    }
    let mut p = [0xffu8; 8];
    p[..pin.len()].copy_from_slice(pin.as_bytes());
    match command(c, 0x20, 0x00, PIN_REF, &p)?.1 {
        0x9000 => Ok(()),
        0x6983 => Err(Error::msg(BLOCKED)),
        sw if sw & 0xfff0 == 0x63c0 => match sw & 0xf {
            0 => Err(Error::msg(BLOCKED)),
            left => Err(Error::msg(format!("wrong PIN for the YubiKey; {left} attempts left before it is blocked"))),
        },
        sw => Err(refused(sw)),
    }
}

/// Signs a SHA-256 digest with the P-256 key in slot, which may wait for a
/// touch, and checks the signature against public, the slot's certificate's
/// key, so that a card with another key in the slot never signs a record
/// that would not verify. verify must have taken the PIN.
pub fn sign(c: &mut dyn Card, slot: u8, public: &[u8], digest: &[u8; 32]) -> Result<Vec<u8>> {
    use p256::ecdsa::signature::hazmat::PrehashVerifier as _;
    let input = tlv(0x7c, &[tlv(0x82, &[]), tlv(0x81, digest)].concat());
    let data = match command(c, 0x87, ALG_ECC_P256, slot, &input)? {
        (_, 0x6982) => return Err(Error::msg("the YubiKey wants its PIN first")),
        (d, 0x9000) => d,
        (_, sw) => return Err(refused(sw)),
    };
    let bad = || Error::msg("the YubiKey's signature does not parse");
    let (outer, _) = read_tlv(&data, 0x7c).ok_or_else(bad)?;
    let (sig, _) = read_tlv(outer, 0x82).ok_or_else(bad)?;
    let vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(public)
        .map_err(|_| Error::msg("the recovery key is not a P-256 key"))?;
    let s = p256::ecdsa::Signature::from_der(sig).map_err(|_| bad())?;
    vk.verify_prehash(digest, &s)
        .map_err(|_| Error::msg("the YubiKey's signature does not match its certificate's key"))?;
    Ok(sig.to_vec())
}

/// Encodes tag, length (BER) and value.
fn tlv(tag: u8, v: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    match v.len() {
        n if n < 0x80 => out.push(n as u8),
        n if n < 0x100 => out.extend_from_slice(&[0x81, n as u8]),
        n => out.extend_from_slice(&[0x82, (n >> 8) as u8, n as u8]),
    }
    out.extend_from_slice(v);
    out
}

/// Reads one TLV with tag at the start of b: its value and what follows.
fn read_tlv(b: &[u8], tag: u8) -> Option<(&[u8], &[u8])> {
    if b.len() < 2 || b[0] != tag {
        return None;
    }
    let (n, i) = match b[1] {
        0x81 => (usize::from(*b.get(2)?), 3),
        0x82 => (usize::from(*b.get(2)?) << 8 | usize::from(*b.get(3)?), 4),
        l if l >= 0x80 => return None,
        l => (usize::from(l), 2),
    };
    if b.len() - i.min(b.len()) < n || b.len() < i {
        return None;
    }
    Some((&b[i..i + n], &b[i + n..]))
}

/// The recovery key on a card: the card, selected, its slot and the slot's
/// certificate.
pub struct Key {
    pub card: Box<dyn Card>,
    pub slot: u8,
    pub cert: Cert,
}

/// Keeps the card of cards that holds the key whose certificate's key hash
/// is key_hash, the only one, and drops the others.
pub fn find(cards: Vec<Box<dyn Card>>, key_hash: &[u8; 32]) -> Result<Key> {
    let mut keys = Vec::new();
    let mut last = NO_CARD;
    for mut c in cards {
        if select(c.as_mut()).is_err() {
            continue;
        }
        last = NO_KEY;
        let mut found = None;
        for slot in FIRST_SLOT..=LAST_SLOT {
            if let Ok(Some(cert)) = certificate(c.as_mut(), slot)
                && cert.key_hash() == *key_hash
            {
                found = Some((slot, cert));
                break;
            }
        }
        if let Some((slot, cert)) = found {
            keys.push(Key { card: c, slot, cert });
        }
    }
    match keys.len() {
        0 => Err(Error::msg(last)),
        1 => Ok(keys.pop().expect("one key")),
        _ => Err(Error::msg(TWO_CARDS)),
    }
}

/// Signs digest with the recovery key whose certificate's key hash is
/// key_hash, on the card PC/SC finds, after its PIN; the certificate's key
/// must be public.
pub fn sign_with_card(key_hash: &[u8; 32], pin: &str, public: &[u8], digest: &[u8; 32]) -> Result<Vec<u8>> {
    let mut k = find(cards()?, key_hash)?;
    if k.cert.public_key() != public {
        return Err(Error::msg("the YubiKey's recovery key is not the one the records name"));
    }
    verify(k.card.as_mut(), pin)?;
    sign(k.card.as_mut(), k.slot, public, digest)
}

/// Every card in the readers PC/SC lists, connected.
fn cards() -> Result<Vec<Box<dyn Card>>> {
    #[cfg(all(unix, not(target_os = "macos")))]
    return crate::third_party::pcsclite::cards();
    #[cfg(target_os = "macos")]
    return mac::cards();
    #[cfg(windows)]
    return win::cards();
    #[allow(unreachable_code)]
    Err(Error::msg("a YubiKey is not read on this system"))
}

/// Joins the reader names of a multi-string, each ended by NUL, the list by
/// another.
#[cfg(any(target_os = "macos", windows, test))]
fn reader_names<T: Copy + PartialEq + Default>(b: &[T]) -> Vec<Vec<T>> {
    b.split(|c| *c == T::default()).take_while(|s| !s.is_empty()).map(<[T]>::to_vec).collect()
}

/// SCARD_IO_REQUEST for T=1, as the platforms lay it out.
#[cfg(any(target_os = "macos", windows))]
#[repr(C)]
struct IoRequest {
    protocol: u32,
    length: u32,
}

#[cfg(any(target_os = "macos", windows))]
const PROTOCOL_T1: u32 = 2;
#[cfg(any(target_os = "macos", windows))]
const SHARE_EXCLUSIVE: u32 = 1;
#[cfg(any(target_os = "macos", windows))]
const SCOPE_SYSTEM: u32 = 2;
#[cfg(any(target_os = "macos", windows))]
const LEAVE_CARD: u32 = 0;
#[cfg(any(target_os = "macos", windows))]
const NO_READERS: u32 = 0x8010_002e;

#[cfg(any(target_os = "macos", windows))]
fn scard_err(what: &str, r: i32) -> Error {
    Error::msg(format!("{what}: PC/SC error {:#x}", r as u32))
}

/// A context, released once its last card is dropped.
#[cfg(any(target_os = "macos", windows))]
struct Context<C: Copy>(C, unsafe extern "system" fn(C) -> i32);

#[cfg(any(target_os = "macos", windows))]
impl<C: Copy> Drop for Context<C> {
    fn drop(&mut self) {
        // SAFETY: the context was established and is released once.
        unsafe { (self.1)(self.0) };
    }
}

#[cfg(target_os = "macos")]
mod mac {
    use std::ffi::{CString, c_char};
    use std::sync::Arc;

    use super::*;

    // On a Mac SCARDCONTEXT and SCARDHANDLE are int32_t, DWORD uint32_t.
    #[link(name = "PCSC", kind = "framework")]
    unsafe extern "system" {
        fn SCardEstablishContext(scope: u32, r1: *const u8, r2: *const u8, ctx: *mut i32) -> i32;
        fn SCardReleaseContext(ctx: i32) -> i32;
        fn SCardListReaders(ctx: i32, groups: *const c_char, readers: *mut c_char, n: *mut u32) -> i32;
        fn SCardConnect(
            ctx: i32,
            reader: *const c_char,
            share: u32,
            proto: u32,
            card: *mut i32,
            active: *mut u32,
        ) -> i32;
        fn SCardDisconnect(card: i32, disposition: u32) -> i32;
        fn SCardTransmit(
            card: i32,
            send_pci: *const IoRequest,
            send: *const u8,
            send_len: u32,
            recv_pci: *mut IoRequest,
            recv: *mut u8,
            recv_len: *mut u32,
        ) -> i32;
    }

    struct MacCard {
        card: i32,
        _ctx: Arc<Context<i32>>,
    }

    impl Card for MacCard {
        fn transmit(&mut self, apdu: &[u8]) -> Result<Vec<u8>> {
            let send = IoRequest { protocol: PROTOCOL_T1, length: 8 };
            let mut out = vec![0u8; 258];
            let mut n = out.len() as u32;
            // SAFETY: the buffers are valid for the lengths given.
            let r = unsafe {
                SCardTransmit(
                    self.card,
                    &send,
                    apdu.as_ptr(),
                    apdu.len() as u32,
                    std::ptr::null_mut(),
                    out.as_mut_ptr(),
                    &mut n,
                )
            };
            if r != 0 {
                return Err(scard_err("SCardTransmit", r));
            }
            out.truncate(n as usize);
            Ok(out)
        }
    }

    impl Drop for MacCard {
        fn drop(&mut self) {
            // SAFETY: the card was connected and is disconnected once.
            unsafe { SCardDisconnect(self.card, LEAVE_CARD) };
        }
    }

    pub(super) fn cards() -> Result<Vec<Box<dyn Card>>> {
        let mut ctx = 0i32;
        // SAFETY: ctx receives the context.
        let r = unsafe { SCardEstablishContext(SCOPE_SYSTEM, std::ptr::null(), std::ptr::null(), &mut ctx) };
        if r != 0 {
            return Err(scard_err("SCardEstablishContext", r));
        }
        let ctx = Arc::new(Context(ctx, SCardReleaseContext));
        let mut n = 0u32;
        // SAFETY: a null buffer asks for the length.
        let r = unsafe { SCardListReaders(ctx.0, std::ptr::null(), std::ptr::null_mut(), &mut n) };
        if r as u32 == NO_READERS || (r == 0 && n == 0) {
            return Err(Error::msg(NO_CARD));
        }
        if r != 0 {
            return Err(scard_err("SCardListReaders", r));
        }
        let mut buf = vec![0 as c_char; n as usize];
        // SAFETY: buf has n bytes.
        let r = unsafe { SCardListReaders(ctx.0, std::ptr::null(), buf.as_mut_ptr(), &mut n) };
        if r != 0 {
            return Err(scard_err("SCardListReaders", r));
        }
        buf.truncate(n as usize);
        let mut out: Vec<Box<dyn Card>> = Vec::new();
        for name in reader_names(&buf) {
            let name: Vec<u8> = name.iter().map(|c| *c as u8).collect();
            let Ok(name) = CString::new(name) else { continue };
            let (mut card, mut proto) = (0i32, 0u32);
            // SAFETY: name is NUL-terminated; card and proto receive values.
            let r = unsafe { SCardConnect(ctx.0, name.as_ptr(), SHARE_EXCLUSIVE, PROTOCOL_T1, &mut card, &mut proto) };
            if r == 0 {
                out.push(Box::new(MacCard { card, _ctx: Arc::clone(&ctx) }));
            }
        }
        if out.is_empty() {
            return Err(Error::msg(NO_CARD));
        }
        Ok(out)
    }
}

#[cfg(windows)]
mod win {
    use std::sync::Arc;

    use super::*;

    // SCARDCONTEXT and SCARDHANDLE are ULONG_PTR, DWORD u32, LONG i32.
    #[link(name = "winscard")]
    unsafe extern "system" {
        fn SCardEstablishContext(scope: u32, r1: *const u8, r2: *const u8, ctx: *mut usize) -> i32;
        fn SCardReleaseContext(ctx: usize) -> i32;
        fn SCardListReadersW(ctx: usize, groups: *const u16, readers: *mut u16, n: *mut u32) -> i32;
        fn SCardConnectW(
            ctx: usize,
            reader: *const u16,
            share: u32,
            proto: u32,
            card: *mut usize,
            active: *mut u32,
        ) -> i32;
        fn SCardDisconnect(card: usize, disposition: u32) -> i32;
        fn SCardTransmit(
            card: usize,
            send_pci: *const IoRequest,
            send: *const u8,
            send_len: u32,
            recv_pci: *mut IoRequest,
            recv: *mut u8,
            recv_len: *mut u32,
        ) -> i32;
    }

    struct WinCard {
        card: usize,
        _ctx: Arc<Context<usize>>,
    }

    impl Card for WinCard {
        fn transmit(&mut self, apdu: &[u8]) -> Result<Vec<u8>> {
            let send = IoRequest { protocol: PROTOCOL_T1, length: 8 };
            let mut out = vec![0u8; 258];
            let mut n = out.len() as u32;
            // SAFETY: the buffers are valid for the lengths given.
            let r = unsafe {
                SCardTransmit(
                    self.card,
                    &send,
                    apdu.as_ptr(),
                    apdu.len() as u32,
                    std::ptr::null_mut(),
                    out.as_mut_ptr(),
                    &mut n,
                )
            };
            if r != 0 {
                return Err(scard_err("SCardTransmit", r));
            }
            out.truncate(n as usize);
            Ok(out)
        }
    }

    impl Drop for WinCard {
        fn drop(&mut self) {
            // SAFETY: the card was connected and is disconnected once.
            unsafe { SCardDisconnect(self.card, LEAVE_CARD) };
        }
    }

    pub(super) fn cards() -> Result<Vec<Box<dyn Card>>> {
        let mut ctx = 0usize;
        // SAFETY: ctx receives the context.
        let r = unsafe { SCardEstablishContext(SCOPE_SYSTEM, std::ptr::null(), std::ptr::null(), &mut ctx) };
        if r != 0 {
            return Err(scard_err("SCardEstablishContext", r));
        }
        let ctx = Arc::new(Context(ctx, SCardReleaseContext));
        let mut n = 0u32;
        // SAFETY: a null buffer asks for the length.
        let r = unsafe { SCardListReadersW(ctx.0, std::ptr::null(), std::ptr::null_mut(), &mut n) };
        if r as u32 == NO_READERS || (r == 0 && n == 0) {
            return Err(Error::msg(NO_CARD));
        }
        if r != 0 {
            return Err(scard_err("SCardListReaders", r));
        }
        let mut buf = vec![0u16; n as usize];
        // SAFETY: buf has n characters.
        let r = unsafe { SCardListReadersW(ctx.0, std::ptr::null(), buf.as_mut_ptr(), &mut n) };
        if r != 0 {
            return Err(scard_err("SCardListReaders", r));
        }
        buf.truncate(n as usize);
        let mut out: Vec<Box<dyn Card>> = Vec::new();
        for mut name in reader_names(&buf) {
            name.push(0);
            let (mut card, mut proto) = (0usize, 0u32);
            // SAFETY: name is NUL-terminated; card and proto receive values.
            let r = unsafe { SCardConnectW(ctx.0, name.as_ptr(), SHARE_EXCLUSIVE, PROTOCOL_T1, &mut card, &mut proto) };
            if r == 0 {
                out.push(Box::new(WinCard { card, _ctx: Arc::clone(&ctx) }));
            }
        }
        if out.is_empty() {
            return Err(Error::msg(NO_CARD));
        }
        Ok(out)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    use p256::ecdsa::SigningKey;
    use p256::ecdsa::signature::hazmat::PrehashSigner as _;

    use super::*;

    /// A card with the PIV application, as Go's pivtest: retired slots with
    /// P-256 keys and their certificates, PIN 123456 with three tries,
    /// command chaining, and long answers in parts (61xx).
    #[derive(Default)]
    pub struct Fake {
        pub slots: HashMap<u8, (SigningKey, Option<Vec<u8>>)>,
        pub tries: u8,
        pub no_piv: bool,
        pub closed: bool,
        selected: bool,
        verified: bool,
        chain: Vec<u8>,
        pending: Vec<u8>,
    }

    /// A shared fake, so that a test sees it after find took the card.
    #[derive(Clone)]
    pub struct Shared(pub Arc<Mutex<Fake>>);

    impl Card for Shared {
        fn transmit(&mut self, apdu: &[u8]) -> Result<Vec<u8>> {
            self.0.lock().unwrap().transmit(apdu)
        }
    }

    impl Drop for Shared {
        fn drop(&mut self) {
            if Arc::strong_count(&self.0) <= 2 {
                let mut f = self.0.lock().unwrap();
                f.closed = true;
                f.selected = false;
                f.verified = false;
            }
        }
    }

    fn sw(mut data: Vec<u8>, w: u16) -> Vec<u8> {
        data.extend_from_slice(&w.to_be_bytes());
        data
    }

    impl Fake {
        fn send(&mut self, data: Vec<u8>) -> Vec<u8> {
            self.pending.extend(data);
            // Parts shorter than a card's, so that every answer comes in
            // several and GET RESPONSE is exercised.
            let n = self.pending.len().min(100);
            let part: Vec<u8> = self.pending.drain(..n).collect();
            match self.pending.len() {
                0 => sw(part, 0x9000),
                left => sw(part, 0x6100 | left.min(255) as u16),
            }
        }

        fn transmit(&mut self, apdu: &[u8]) -> Result<Vec<u8>> {
            if self.closed {
                return Err(Error::msg("the fake card is closed"));
            }
            if apdu.len() < 4 {
                return Ok(sw(vec![], 0x6700));
            }
            let (cla, ins, p1, p2) = (apdu[0], apdu[1], apdu[2], apdu[3]);
            let mut data = Vec::new();
            if apdu.len() > 5 {
                let n = usize::from(apdu[4]);
                if apdu.len() < 5 + n {
                    return Ok(sw(vec![], 0x6700));
                }
                data = apdu[5..5 + n].to_vec();
            }
            if ins == 0xc0 {
                return Ok(self.send(vec![]));
            }
            if cla & 0x10 != 0 {
                self.chain.extend(data);
                return Ok(sw(vec![], 0x9000));
            }
            let data = [std::mem::take(&mut self.chain), data].concat();
            if ins == 0xa4 {
                if self.no_piv || data != AID {
                    return Ok(sw(vec![], 0x6a82));
                }
                self.selected = true;
                self.verified = false;
                return Ok(sw(vec![], 0x9000));
            }
            if !self.selected {
                return Ok(sw(vec![], 0x6d00));
            }
            match ins {
                0xcb => {
                    if p1 != 0x3f || p2 != 0xff || data.len() != 5 || data[..4] != [0x5c, 0x03, 0x5f, 0xc1] {
                        return Ok(sw(vec![], 0x6a80));
                    }
                    let Some((_, Some(cert))) = self.slots.get(&(0x82 + data[4] - 0x0d)) else {
                        return Ok(sw(vec![], 0x6a82));
                    };
                    let obj = tlv(0x53, &[tlv(0x70, cert), tlv(0x71, &[0])].concat());
                    Ok(self.send(obj))
                }
                0x20 => {
                    if self.tries == 0 {
                        return Ok(sw(vec![], 0x6983));
                    }
                    let mut want = [0xffu8; 8];
                    want[..6].copy_from_slice(b"123456");
                    if data == want {
                        self.tries = 3;
                        self.verified = true;
                        return Ok(sw(vec![], 0x9000));
                    }
                    self.tries -= 1;
                    Ok(sw(vec![], 0x63c0 | u16::from(self.tries)))
                }
                0x87 => {
                    if !self.verified {
                        return Ok(sw(vec![], 0x6982));
                    }
                    let Some((key, _)) = self.slots.get(&p2) else { return Ok(sw(vec![], 0x6a82)) };
                    if p1 != ALG_ECC_P256 {
                        return Ok(sw(vec![], 0x6a80));
                    }
                    let (outer, _) = read_tlv(&data, 0x7c).unwrap();
                    let (_, rest) = read_tlv(outer, 0x82).unwrap();
                    let (digest, _) = read_tlv(rest, 0x81).unwrap();
                    let sig: p256::ecdsa::Signature = key.sign_prehash(digest).unwrap();
                    Ok(self.send(tlv(0x7c, &tlv(0x82, sig.to_der().as_bytes()))))
                }
                _ => Ok(sw(vec![], 0x6d00)),
            }
        }
    }

    pub fn key(n: u8) -> SigningKey {
        let mut b = [0u8; 32];
        b[31] = n;
        b[0] = 1;
        SigningKey::from_bytes(&b.into()).unwrap()
    }

    /// A certificate of key, as the root phone stores in the slot.
    pub fn cert(k: &SigningKey) -> Vec<u8> {
        cbb_core::certs::self_signed(&cbb_core::certs::DeviceId::random(), k).unwrap()
    }

    fn public(k: &SigningKey) -> Vec<u8> {
        k.verifying_key().to_sec1_point(false).as_bytes().to_vec()
    }

    /// A card whose slot 84 holds a key and its certificate; 82 holds a key
    /// of something else.
    pub fn new_card(n: u8) -> Shared {
        let mut f = Fake { tries: 3, ..Fake::default() };
        let k = key(n);
        let c = cert(&k);
        f.slots.insert(0x84, (k, Some(c)));
        let other = key(n.wrapping_add(100));
        let oc = cert(&other);
        f.slots.insert(0x82, (other, Some(oc)));
        Shared(Arc::new(Mutex::new(f)))
    }

    fn hash_of(card: &Shared, slot: u8) -> [u8; 32] {
        let f = card.0.lock().unwrap();
        Cert::parse(f.slots[&slot].1.as_ref().unwrap()).unwrap().key_hash()
    }

    #[test]
    fn signs() {
        let card = new_card(1);
        let want = hash_of(&card, 0x84);
        let pk = public(&card.0.lock().unwrap().slots[&0x84].0);
        let mut k = find(vec![Box::new(card.clone())], &want).unwrap();
        assert_eq!(k.slot, 0x84);
        let digest = cbb_core::certs::sha256(b"a record");
        assert!(sign(k.card.as_mut(), k.slot, &pk, &digest).is_err(), "signed without the PIN");
        verify(k.card.as_mut(), "123456").unwrap();
        sign(k.card.as_mut(), k.slot, &pk, &digest).unwrap();
        // Another key than the certificate's.
        let other = public(&key(50));
        assert!(sign(k.card.as_mut(), k.slot, &other, &digest).is_err());
    }

    #[test]
    fn wrong_pin() {
        let mut card = new_card(2);
        select(&mut card).unwrap();
        let e = verify(&mut card, "654321").unwrap_err();
        assert!(e.message().contains("2 attempts left"), "{}", e.message());
        let _ = verify(&mut card, "654321");
        let _ = verify(&mut card, "654321");
        assert_eq!(verify(&mut card, "123456").unwrap_err().message(), BLOCKED);
        assert!(verify(&mut card, "12345").is_err(), "a PIN of 5 characters");
    }

    #[test]
    fn finds_the_one_card() {
        let bank = new_card(3);
        bank.0.lock().unwrap().no_piv = true;
        let empty = new_card(4);
        empty.0.lock().unwrap().slots.remove(&0x84);
        let want = hash_of(&new_card(5), 0x84);
        assert_eq!(find(vec![], &want).err().unwrap().message(), NO_CARD);
        assert_eq!(find(vec![Box::new(bank.clone())], &hash_of(&bank, 0x84)).err().unwrap().message(), NO_CARD);
        assert_eq!(find(vec![Box::new(empty.clone())], &want).err().unwrap().message(), NO_KEY);
        assert!(bank.0.lock().unwrap().closed && empty.0.lock().unwrap().closed, "left a card it does not use open");

        let one = new_card(6);
        let k = find(vec![Box::new(new_card(7)), Box::new(one.clone()), Box::new(new_card(8))], &hash_of(&one, 0x84))
            .unwrap();
        assert_eq!(k.slot, 0x84);

        let last = new_card(9);
        {
            let mut f = last.0.lock().unwrap();
            let s = f.slots.remove(&0x84).unwrap();
            f.slots.insert(LAST_SLOT, s);
            f.slots.insert(0x84, (key(10), None));
        }
        let k = find(vec![Box::new(last.clone())], &hash_of(&last, LAST_SLOT)).unwrap();
        assert_eq!(k.slot, LAST_SLOT);

        let (a, b) = (new_card(11), new_card(12));
        {
            let src = one.0.lock().unwrap();
            let (k, c) = &src.slots[&0x84];
            for card in [&a, &b] {
                card.0.lock().unwrap().slots.insert(0x84, (k.clone(), c.clone()));
            }
        }
        assert_eq!(
            find(vec![Box::new(a.clone()), Box::new(b.clone())], &hash_of(&one, 0x84)).err().unwrap().message(),
            TWO_CARDS
        );
        assert!(a.0.lock().unwrap().closed && b.0.lock().unwrap().closed, "left a card open after two");
        let mut c = one.clone();
        select(&mut c).unwrap();
        assert!(certificate(&mut c, 0x9c).is_err(), "a slot that is not retired");
    }

    #[test]
    fn chains_long_commands() {
        let mut card = new_card(13);
        select(&mut card).unwrap();
        // The AID with 300 bytes after it is not the PIV application's.
        let (_, sw) = command(&mut card, 0xa4, 0x04, 0x00, &[0u8; 300]).unwrap();
        assert_eq!(sw, 0x6a82);
    }

    #[test]
    fn reads_tlvs() {
        for n in [0usize, 0x7f, 0x80, 0xff, 0x100, 0x1234] {
            let mut b = tlv(0x53, &vec![0; n]);
            b.push(1);
            let (v, rest) = read_tlv(&b, 0x53).unwrap();
            assert_eq!((v.len(), rest.len()), (n, 1));
        }
        for b in [&[][..], &[0x53], &[0x54, 0], &[0x53, 0x83, 0, 0, 1], &[0x53, 0x81], &[0x53, 0x82, 1], &[0x53, 2, 0]]
        {
            assert!(read_tlv(b, 0x53).is_none(), "{b:02x?}");
        }
    }

    #[test]
    fn splits_reader_names() {
        let names = reader_names(b"Yubico YubiKey\0Other\0\0".as_slice());
        assert_eq!(names, [b"Yubico YubiKey".to_vec(), b"Other".to_vec()]);
        assert!(reader_names(b"\0".as_slice()).is_empty());
    }
}
