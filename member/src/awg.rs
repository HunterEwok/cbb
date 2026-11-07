// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! AmneziaWG around GotaTun's WireGuard, for a hub that hides its tunnel
//! (docs/design.md, "Blocked networks"; docs/protocol.md, section 11). The
//! settings are the group's, in the hub's offer, as internal/tunnel's
//! Obfuscation names them; the packets are amneziawg-go's
//! (internal/third_party/amneziawg-go), which the Go hub speaks:
//!
//! - every message gets random bytes in front of it (S1 the initiation, S2
//!   the response, S3 the cookie reply, S4 data);
//! - its type field is drawn from the message's range (H1 to H4) instead of
//!   WireGuard's 1 to 4, and mac1 and mac2 are over that field;
//! - with the header protection key, ChaCha20 under the key, with the first
//!   12 bytes in front as the nonce, hides the message from its type field:
//!   the whole of a handshake message, the 16 bytes of a data message's
//!   header;
//! - an initiation follows JC packets of random bytes.
//!
//! GotaTun makes and takes plain WireGuard messages. A message going out
//! gets its type, its macs (mac1 under the hub's key, mac2 under the cookie
//! the hub gave), its padding and its protection here; a message coming in
//! is unhidden, its mac1 checked against this device's key, and it is given
//! to GotaTun as plain WireGuard, with its mac1 made again for GotaTun's
//! check. A cookie reply is taken here and never reaches GotaTun, since its
//! cookie is sealed to the mac1 this side sent.
//!
//! None of this adds security: WireGuard's and the member TLS's stay the
//! same, with or without it.

use std::time::{Duration, Instant};

use blake2::digest::{FixedOutput, KeyInit, Update};
use blake2::{Blake2s256, Blake2sMac, Digest};
use chacha20::ChaCha20;
use chacha20::cipher::{KeyIvInit, StreamCipher};
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use serde::Deserialize;
use serde_json::Value;

use crate::error::{Error, Result};

const INITIATION: usize = 148;
const RESPONSE: usize = 92;
const COOKIE_REPLY: usize = 64;
const DATA_HEADER: usize = 16;
const DATA_MIN: usize = 32; // the header and an empty message's tag
const NONCE: usize = 12;
const COOKIE_LIFE: Duration = Duration::from_secs(120 - 5);

// The bounds of internal/tunnel's Check, so that both sides take the same
// settings.
const MAX_JUNK_COUNT: u32 = 16;
const MAX_JUNK_SIZE: u32 = 1000;
const MIN_PADDING: u32 = 16;
const MAX_PADDING: u32 = 64;

/// An inclusive range of a message's type field.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Range {
    pub min: u32,
    pub max: u32,
}

impl Range {
    /// Reads "min-max" as internal/tunnel's Range does: two decimal numbers
    /// of 32 bits in their shortest form, the first not above the second.
    fn parse(s: &str) -> Result<Range> {
        let bad = || Error::msg(format!("{s:?} is not a range such as 100-200"));
        let (lo, hi) = s.split_once('-').ok_or_else(bad)?;
        let (min, max) = (number(lo).ok_or_else(bad)?, number(hi).ok_or_else(bad)?);
        if min > max {
            return Err(bad());
        }
        Ok(Range { min, max })
    }

    fn contains(&self, v: u32) -> bool {
        self.min <= v && v <= self.max
    }

    fn overlaps(&self, o: &Range) -> bool {
        self.min <= o.max && o.min <= self.max
    }

    fn pick(&self) -> u32 {
        self.min + below(self.max - self.min + 1)
    }
}

/// A decimal number of 32 bits in its shortest form.
fn number(s: &str) -> Option<u32> {
    if s.is_empty() || s.len() > 10 || (s.len() > 1 && s.starts_with('0')) || !s.bytes().all(|c| c.is_ascii_digit()) {
        return None;
    }
    s.parse::<u64>().ok().and_then(|n| u32::try_from(n).ok())
}

/// A uniform random number below n, 0 for n 0 (the whole range of 32 bits).
fn below(n: u32) -> u32 {
    let mut b = [0u8; 8];
    random(&mut b);
    let r = u64::from_le_bytes(b);
    if n == 0 { r as u32 } else { (r % u64::from(n)) as u32 }
}

fn random(b: &mut [u8]) {
    // getrandom fails only on a system without randomness, where nothing
    // of the tunnel works; the bytes here hide, they do not protect.
    let _ = getrandom::fill(b);
}

/// The group's AmneziaWG settings, as the hub's offer carries them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Obfuscation {
    pub jc: u32,
    pub jmin: u32,
    pub jmax: u32,
    pub s: [u32; 4],
    pub h: [Range; 4],
    pub header_key: [u8; 32],
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Raw {
    jc: u32,
    jmin: u32,
    jmax: u32,
    s1: u32,
    s2: u32,
    s3: u32,
    s4: u32,
    h1: String,
    h2: String,
    h3: String,
    h4: String,
    header_protection_key: String,
}

impl Obfuscation {
    /// Reads the settings of an offer and refuses what internal/tunnel's
    /// Check refuses.
    pub fn from_offer(v: &Value) -> Result<Obfuscation> {
        let r: Raw = serde_json::from_value(v.clone())
            .map_err(|e| Error::msg(format!("the hub's AmneziaWG settings do not read: {e}")))?;
        use base64::Engine as _;
        let key = base64::engine::general_purpose::STANDARD
            .decode(&r.header_protection_key)
            .ok()
            .and_then(|k| <[u8; 32]>::try_from(k).ok())
            .ok_or_else(|| Error::msg("the hub's header protection key is not 32 bytes in base64"))?;
        let o = Obfuscation {
            jc: r.jc,
            jmin: r.jmin,
            jmax: r.jmax,
            s: [r.s1, r.s2, r.s3, r.s4],
            h: [Range::parse(&r.h1)?, Range::parse(&r.h2)?, Range::parse(&r.h3)?, Range::parse(&r.h4)?],
            header_key: key,
        };
        o.check()?;
        Ok(o)
    }

    /// New random settings for a group's hub, as internal/tunnel's
    /// NewObfuscation makes them: each header range in its own quarter of
    /// the space above WireGuard's types, in a random order.
    pub fn random() -> Result<Obfuscation> {
        let num = |lo: u32, hi: u32| lo + below(hi - lo + 1);
        let jc = num(3, 8);
        let jmin = num(40, 100);
        let jmax = jmin + num(100, 500);
        let mut s;
        loop {
            s = [
                num(MIN_PADDING, MAX_PADDING),
                num(MIN_PADDING, MAX_PADDING),
                num(MIN_PADDING, 32),
                num(MIN_PADDING, 32),
            ];
            let (a, b, c) = (INITIATION + s[0] as usize, RESPONSE + s[1] as usize, COOKIE_REPLY + s[2] as usize);
            if a != b && a != c && b != c {
                break;
            }
        }
        let mut quarters = [0u32, 1, 2, 3];
        for i in (1..4).rev() {
            quarters.swap(i, num(0, i as u32) as usize);
        }
        let h = quarters.map(|q| {
            let start = (q << 30) + 16 + num(0, 1 << 29);
            Range { min: start, max: start + (1u32 << num(16, 24)) - 1 }
        });
        let mut header_key = [0u8; 32];
        getrandom::fill(&mut header_key).map_err(|_| Error::msg("cannot make a key: the system has no randomness"))?;
        let o = Obfuscation { jc, jmin, jmax, s, h, header_key };
        o.check()?;
        Ok(o)
    }

    /// The settings as the offers and the state file carry them.
    pub fn to_value(&self) -> Value {
        use base64::Engine as _;
        let r = |r: &Range| format!("{}-{}", r.min, r.max);
        serde_json::json!({
            "jc": self.jc, "jmin": self.jmin, "jmax": self.jmax,
            "s1": self.s[0], "s2": self.s[1], "s3": self.s[2], "s4": self.s[3],
            "h1": r(&self.h[0]), "h2": r(&self.h[1]), "h3": r(&self.h[2]), "h4": r(&self.h[3]),
            "header_protection_key": base64::engine::general_purpose::STANDARD.encode(self.header_key),
        })
    }

    fn check(&self) -> Result<()> {
        if self.jc > MAX_JUNK_COUNT {
            return Err(Error::msg(format!("the hub's settings have {} junk packets", self.jc)));
        }
        if self.jmin > self.jmax || self.jmax > MAX_JUNK_SIZE {
            return Err(Error::msg(format!("the hub's settings have junk of {} to {} bytes", self.jmin, self.jmax)));
        }
        if self.header_key.iter().all(|&b| b == 0) {
            return Err(Error::msg("the hub's settings have no header protection key"));
        }
        let [s1, s2, s3, _] = self.s.map(|s| s as usize);
        let (a, b, c) = (INITIATION + s1, RESPONSE + s2, COOKIE_REPLY + s3);
        if a == b || a == c || b == c {
            return Err(Error::msg("the hub's settings give two handshake messages the same size"));
        }
        if self.s.iter().any(|&s| !(MIN_PADDING..=MAX_PADDING).contains(&s)) {
            return Err(Error::msg("the hub's settings pad a message by less than 16 or more than 64 bytes"));
        }
        for (i, h) in self.h.iter().enumerate() {
            if h.min <= 4 {
                return Err(Error::msg(format!("the hub's settings have h{} at {}", i + 1, h.min)));
            }
            if self.h[i + 1..].iter().any(|o| h.overlaps(o)) {
                return Err(Error::msg("the hub's settings have two overlapping type ranges"));
            }
        }
        Ok(())
    }
}

/// BLAKE2s-256 of the parts, one after another: WireGuard's HASH.
fn hash(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Blake2s256::new();
    for p in parts {
        Digest::update(&mut h, p);
    }
    h.finalize().into()
}

/// The keyed BLAKE2s-128 of WireGuard's MAC.
fn mac(key: &[u8], msg: &[u8]) -> [u8; 16] {
    let mut m =
        <Blake2sMac<blake2::digest::consts::U16> as KeyInit>::new_from_slice(key).expect("a key of 16 or 32 bytes");
    Update::update(&mut m, msg);
    m.finalize_fixed().into()
}

/// The offsets of mac1 in the handshake messages: mac2 follows it.
fn mac1_at(len: usize) -> usize {
    len - 32
}

/// The transform between GotaTun's WireGuard and AmneziaWG's packets, for
/// one hub.
pub struct Awg {
    o: Obfuscation,
    /// HASH("mac1----" ‖ key): mac1's key for what goes to the hub, and for
    /// what this device takes.
    mac1_out: [u8; 32],
    mac1_in: [u8; 32],
    /// HASH("cookie--" ‖ hub's key): the key of the hub's cookie replies.
    cookie_key: [u8; 32],
    /// The mac1 of the last handshake message sent, which a cookie reply
    /// is sealed to.
    last_mac1: Option<[u8; 16]>,
    cookie: Option<([u8; 16], Instant)>,
}

impl Awg {
    /// The transform for the hub of public key `hub`, this device's being
    /// `own`.
    pub fn new(o: Obfuscation, hub: &[u8; 32], own: &[u8; 32]) -> Awg {
        Awg {
            mac1_out: hash(&[b"mac1----", hub]),
            mac1_in: hash(&[b"mac1----", own]),
            cookie_key: hash(&[b"cookie--", hub]),
            o,
            last_mac1: None,
            cookie: None,
        }
    }

    fn protect(&self, nonce: &[u8], data: &mut [u8]) {
        let mut c = ChaCha20::new(&self.o.header_key.into(), nonce[..NONCE].into());
        c.apply_keystream(data);
    }

    /// The datagrams to send for one message GotaTun made: the junk before
    /// an initiation, then the message as AmneziaWG has it. A message
    /// GotaTun should not have made goes as nothing.
    pub fn outgoing(&mut self, wg: &[u8]) -> Vec<Vec<u8>> {
        let Some(&t) = wg.first() else { return Vec::new() };
        if wg.len() < 4 || wg[1..4] != [0, 0, 0] || !(1..=4).contains(&t) {
            return Vec::new();
        }
        let i = usize::from(t - 1);
        let mut out = Vec::new();
        if t == 1 {
            for _ in 0..self.o.jc {
                let n = self.o.jmin + below(self.o.jmax - self.o.jmin);
                let mut junk = vec![0u8; n as usize];
                random(&mut junk);
                out.push(junk);
            }
        }
        let pad = self.o.s[i] as usize;
        let mut p = vec![0u8; pad + wg.len()];
        random(&mut p[..pad]);
        p[pad..].copy_from_slice(wg);
        let msg = &mut p[pad..];
        msg[..4].copy_from_slice(&self.o.h[i].pick().to_le_bytes());
        match t {
            1 | 2 => {
                let m1 = mac1_at(msg.len());
                let mac1 = mac(&self.mac1_out, &msg[..m1]);
                msg[m1..m1 + 16].copy_from_slice(&mac1);
                let mac2 = match self.cookie {
                    Some((c, at)) if at.elapsed() < COOKIE_LIFE => mac(&c, &msg[..m1 + 16]),
                    _ => [0u8; 16],
                };
                msg[m1 + 16..m1 + 32].copy_from_slice(&mac2);
                self.last_mac1 = Some(mac1);
            }
            3 => return Vec::new(), // this side never refuses a handshake with a cookie
            _ => {}
        }
        let (nonce, msg) = p.split_at_mut(pad);
        let end = if t == 4 { DATA_HEADER } else { msg.len() };
        self.protect(nonce, &mut msg[..end]);
        out.push(p);
        out
    }

    /// The WireGuard message for GotaTun of a datagram from the hub, or
    /// None for one that is not the hub's (a wrong size, type or mac1) or
    /// that this side took itself (a cookie reply).
    pub fn incoming(&mut self, data: &[u8]) -> Option<Vec<u8>> {
        if data.len() < NONCE {
            return None;
        }
        let mut ks = [0u8; 4];
        self.protect(&data[..NONCE], &mut ks);
        let typ = |pad: usize| -> u32 {
            let mut t = [0u8; 4];
            for (j, b) in t.iter_mut().enumerate() {
                *b = data[pad + j] ^ ks[j];
            }
            u32::from_le_bytes(t)
        };
        let s = self.o.s.map(|s| s as usize);
        let sizes = [INITIATION, RESPONSE, COOKIE_REPLY];
        // As amneziawg-go tells them apart: a handshake message by its size
        // and type, a data message by its type.
        let kind = (0..3)
            .find(|&i| data.len() == s[i] + sizes[i] && self.o.h[i].contains(typ(s[i])))
            .or_else(|| (data.len() >= s[3] + DATA_MIN && self.o.h[3].contains(typ(s[3]))).then_some(3))?;
        let pad = s[kind];
        let mut msg = data[pad..].to_vec();
        let end = if kind == 3 { DATA_HEADER } else { msg.len() };
        self.protect(&data[..NONCE], &mut msg[..end]);
        match kind {
            2 => {
                self.take_cookie(&msg);
                None
            }
            3 => {
                msg[..4].copy_from_slice(&4u32.to_le_bytes());
                Some(msg)
            }
            _ => {
                let m1 = mac1_at(msg.len());
                if mac(&self.mac1_in, &msg[..m1]) != msg[m1..m1 + 16] {
                    return None;
                }
                msg[..4].copy_from_slice(&(kind as u32 + 1).to_le_bytes());
                let mac1 = mac(&self.mac1_in, &msg[..m1]);
                msg[m1..m1 + 16].copy_from_slice(&mac1);
                msg[m1 + 16..m1 + 32].fill(0);
                Some(msg)
            }
        }
    }

    /// Opens a cookie reply: type, receiver, a 24-byte nonce, the sealed
    /// cookie, sealed to the mac1 of the last handshake message sent.
    fn take_cookie(&mut self, msg: &[u8]) {
        let Some(mac1) = self.last_mac1 else { return };
        let aead = XChaCha20Poly1305::new((&self.cookie_key).into());
        let nonce = XNonce::from_slice(&msg[8..32]);
        if let Ok(c) = aead.decrypt(nonce, Payload { msg: &msg[32..64], aad: &mac1 })
            && let Ok(c) = <[u8; 16]>::try_from(c.as_slice())
        {
            self.cookie = Some((c, Instant::now()));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A key of the test's own, new each time.
    fn key() -> [u8; 32] {
        let k: Vec<u8> = (0..4).flat_map(|_| getrandom::u64().unwrap().to_le_bytes()).collect();
        k.try_into().unwrap()
    }

    static HEADER_KEY: std::sync::OnceLock<[u8; 32]> = std::sync::OnceLock::new();

    fn settings() -> Obfuscation {
        Obfuscation {
            jc: 3,
            jmin: 40,
            jmax: 140,
            s: [20, 33, 17, 25],
            h: [
                Range { min: 1_000_016, max: 1_065_551 },
                Range { min: 1_073_741_840, max: 1_073_807_375 },
                Range { min: 2_147_483_664, max: 2_147_549_199 },
                Range { min: 3_221_225_488, max: 3_221_291_023 },
            ],
            // The same for every end in a run, as a group's settings are.
            header_key: *HEADER_KEY.get_or_init(key),
        }
    }

    /// The two ends of a link: each one's AmneziaWG of the other's
    /// handshake reads back as the WireGuard message, with a mac1 its own
    /// key makes.
    #[test]
    fn random_settings_check_and_read_back() {
        for _ in 0..50 {
            let o = Obfuscation::random().unwrap();
            assert_eq!(Obfuscation::from_offer(&o.to_value()).unwrap(), o);
        }
    }

    #[test]
    fn handshakes_and_data_go_both_ways() {
        let (a, b) = (key(), key());
        let mut to_b = Awg::new(settings(), &b, &a);
        let mut to_a = Awg::new(settings(), &a, &b);
        let mut init = vec![0u8; INITIATION];
        init[0] = 1;
        init[4..20].fill(9);
        let sent = to_b.outgoing(&init);
        assert_eq!(sent.len(), 4, "three junk packets and the initiation");
        assert!(sent[..3].iter().all(|j| (40..140).contains(&j.len())));
        assert_eq!(sent[3].len(), 20 + INITIATION);
        assert!(sent[3][20..24] != [1, 0, 0, 0]);
        for j in &sent[..3] {
            assert!(to_a.incoming(j).is_none(), "junk is dropped");
        }
        let got = to_a.incoming(&sent[3]).unwrap();
        assert_eq!(got[..116], init[..116]);
        assert_eq!(got[116..132], mac(&hash(&[b"mac1----", &b]), &got[..116]));
        let mut data = vec![0u8; 80];
        data[0] = 4;
        data[4..16].copy_from_slice(&[5; 12]);
        let sent = to_b.outgoing(&data);
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].len(), 25 + 80);
        assert_eq!(to_a.incoming(&sent[0]).unwrap(), data);
    }

    /// A message whose mac1 is not made under this device's key is not
    /// passed on, nor one changed on the way.
    #[test]
    fn foreign_messages_are_dropped() {
        let (a, b, c) = (key(), key(), key());
        let mut to_c = Awg::new(settings(), &c, &a);
        let mut b_side = Awg::new(settings(), &a, &b);
        let mut resp = vec![0u8; RESPONSE];
        resp[0] = 2;
        let sent = to_c.outgoing(&resp).pop().unwrap();
        assert!(b_side.incoming(&sent).is_none(), "made for c, not for b");
        let mut a_side = Awg::new(settings(), &a, &c);
        let mut changed = sent.clone();
        changed[40] ^= 1;
        assert!(a_side.incoming(&changed).is_none());
        assert!(a_side.incoming(&sent[..sent.len() - 1]).is_none());
    }

    /// The settings are read as Go writes them, and Check's refusals are
    /// the same.
    #[test]
    fn reads_go_settings() {
        let go = r#"{"jc":5,"jmin":50,"jmax":300,"s1":20,"s2":33,"s3":17,"s4":25,"h1":"1000016-1065551","h2":"1073741840-1073807375","h3":"2147483664-2147549199","h4":"3221225488-3221291023","header_protection_key":"BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc="}"#;
        let v: Value = serde_json::from_str(go).unwrap();
        let o = Obfuscation::from_offer(&v).unwrap();
        assert_eq!(o.jc, 5);
        assert_eq!(o.h[3].max, 3_221_291_023);
        let bad = |from: &str, to: &str| {
            let v: Value = serde_json::from_str(&go.replace(from, to)).unwrap();
            Obfuscation::from_offer(&v).is_err()
        };
        assert!(bad("\"jc\":5", "\"jc\":17"));
        assert!(bad("\"s1\":20", "\"s1\":12"));
        assert!(bad("1000016-1065551", "01000016-1065551"));
        assert!(bad("1000016-1065551", "1073741840-1073807375"), "overlapping");
        assert!(bad("\"s2\":33", "\"s2\":76"), "the response as long as the initiation");
        assert!(bad("BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc=", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="));
        assert!(bad("\"jc\":5", "\"jc\":5,\"i1\":\"\""), "unknown settings");
    }
}
