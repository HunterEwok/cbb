// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Translated to Rust from internal/third_party/cpace/cpace.go; see
// README.md.

//! The CPace balanced password-authenticated key exchange, which lets two
//! parties that share a low-entropy secret (a password) derive a strong
//! shared key without exposing the password to offline dictionary attacks.
//!
//! This module implements the cipher suite CPACE-X25519-SHA512 of “CPace, a
//! balanced composable PAKE”, draft-irtf-cfrg-cpace-21,
//! <https://datatracker.ietf.org/doc/draft-irtf-cfrg-cpace/21/>.
//!
//! A CPace exchange is a single round trip. Each party calls [`start`] with
//! the shared password and the other inputs the two parties are expected to
//! agree on, sends the resulting message and its associated data to the
//! other party, and then calls [`State::finish`] with the message and
//! associated data it receives. Both parties derive the same intermediate
//! session key if and only if they started with the same password, channel
//! identifier, and session identifier, and each saw what the other sent.
//!
//! By itself CPace provides implicit authentication only. Applications that
//! need explicit authentication add a key confirmation round using
//! [`State::tag`] and [`State::verify`], which also strengthens the forward
//! secrecy of the exchange.

mod field;

use alloc::vec;
use alloc::vec::Vec;

use hmac::{KeyInit, Mac};
use sha2::{Digest, Sha512};
use x25519_dalek::{PublicKey, StaticSecret};

/// Suite constants for CPACE-X25519-SHA512.
const DSI: &[u8] = b"CPace255"; // domain separation identifier
const DSI_ISK: &[u8] = b"CPace255_ISK"; // domain separation identifier for the session key
const DSI_SID: &[u8] = b"CPaceSidOutput"; // domain separation identifier for the session identifier
const DSI_MAC: &[u8] = b"CPaceMac"; // domain separation identifier for the confirmation key
const BLOCK_SIZE: usize = 128; // input block size of H
const ELEMENT_SIZE: usize = 32; // size of a group element and of a scalar

/// The part a party plays in a CPace exchange.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Role {
    /// Initiator and Responder are the roles of the two parties in an
    /// exchange with a defined message ordering, in which the initiator's
    /// message precedes the responder's.
    Initiator,
    Responder,
    /// Symmetric is the role of both parties in an exchange without a
    /// defined message ordering, in which either party may speak first. It
    /// requires the associated data of the two parties to differ in every
    /// exchange.
    #[allow(dead_code)]
    Symmetric,
}

/// The inputs to a CPace exchange.
pub struct Config<'a> {
    /// This party's role in the exchange.
    pub role: Role,
    /// The shared secret, called PRS in the draft.
    pub password: &'a [u8],
    /// Identifies the channel connecting the two parties, called CI in the
    /// draft. It is not sent on the wire.
    pub channel_id: &'a [u8],
    /// Identifies this exchange, called sid in the draft.
    pub session_id: &'a [u8],
    /// This party's associated data, called ADa and ADb in the draft. It is
    /// sent on the wire in the clear and authenticated by the exchange.
    pub ad: &'a [u8],
}

/// An error of the exchange.
#[derive(Debug, PartialEq, Eq)]
pub struct Error(&'static str);

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.0)
    }
}

impl core::error::Error for Error {}

/// One party's state during a CPace exchange.
pub struct State {
    role: Role,
    sid: Vec<u8>,
    ad: Vec<u8>,
    msg: [u8; ELEMENT_SIZE],
    priv_key: Option<StaticSecret>,

    sid_output: Option<Vec<u8>>,
    tag: Option<Vec<u8>>,      // this party's key confirmation tag
    peer_tag: Option<Vec<u8>>, // the other party's expected key confirmation tag
}

/// Starts a CPace exchange, returning the state needed to finish it and the
/// message to send to the other party. The message must be sent along with
/// cfg.ad, which the other party passes to [`State::finish`].
pub fn start(cfg: &Config) -> Result<(State, Vec<u8>), Error> {
    // G.sample_scalar is 32 uniformly random bytes; X25519 clamps them as
    // RFC 7748 requires.
    let mut scalar = [0u8; ELEMENT_SIZE];
    getrandom::fill(&mut scalar).map_err(|_| Error("cpace: no randomness"))?;
    start_with(cfg, scalar)
}

/// start with the secret scalar supplied by the caller, for tests.
fn start_with(cfg: &Config, scalar: [u8; ELEMENT_SIZE]) -> Result<(State, Vec<u8>), Error> {
    let priv_key = StaticSecret::from(scalar);
    let g = PublicKey::from(generator(cfg.password, cfg.channel_id, cfg.session_id));
    // Y = G.scalar_mult(y, g).
    let msg = priv_key.diffie_hellman(&g).to_bytes();
    if msg == [0u8; ELEMENT_SIZE] {
        // Only if the generator is a low-order point, which the hash to the
        // curve produces with negligible probability.
        return Err(Error("cpace: invalid generator"));
    }
    let s = State {
        role: cfg.role,
        sid: cfg.session_id.to_vec(),
        ad: cfg.ad.to_vec(),
        msg,
        priv_key: Some(priv_key),
        sid_output: None,
        tag: None,
        peer_tag: None,
    };
    Ok((s, msg.to_vec()))
}

impl State {
    /// Completes a CPace exchange using the message and associated data
    /// received from the other party, returning the intermediate session
    /// key.
    ///
    /// It reports an error if the message is not a valid group element,
    /// encodes a low-order point, or is this party's own message relayed
    /// back to it. It can be called only once: the secret scalar of an
    /// exchange must never be reused.
    pub fn finish(&mut self, msg: &[u8], ad: &[u8]) -> Result<Vec<u8>, Error> {
        let priv_key = self.priv_key.take().ok_or(Error("cpace: exchange already finished"))?;

        // An honest party's message equals ours only with negligible
        // probability, so a message that does is our own relayed back to us.
        if msg == self.msg {
            return Err(Error("cpace: invalid peer message: our own message"));
        }
        let peer: [u8; ELEMENT_SIZE] = msg.try_into().map_err(|_| Error("cpace: invalid peer message"))?;
        // K = G.scalar_mult_vfy(y, Y'), aborting if K is the neutral element.
        let k = priv_key.diffie_hellman(&PublicKey::from(peer)).to_bytes();
        if k == [0u8; ELEMENT_SIZE] {
            return Err(Error("cpace: invalid peer message: low order point"));
        }

        let (mut ya, mut ada, mut yb, mut adb) = (&self.msg[..], &self.ad[..], msg, ad);
        if self.role == Role::Responder {
            (ya, ada, yb, adb) = (yb, adb, ya, ada);
        }

        // ISK = H.hash(lv_cat(G.DSI || "_ISK", sid, K) || transcript(Ya, ADa, Yb, ADb))
        let mut b = lv_cat(Vec::new(), &[DSI_ISK, &self.sid, &k]);
        b = self.transcript(b, ya, ada, yb, adb);
        let isk = Sha512::digest(&b).to_vec();
        b.fill(0);

        // sid_output = H.hash("CPaceSidOutput" || transcript(Ya, ADa, Yb, ADb))
        let b = self.transcript(DSI_SID.to_vec(), ya, ada, yb, adb);
        self.sid_output = Some(Sha512::digest(&b).to_vec());

        // Key confirmation tags, each computed over the message its sender
        // sent: mac_key = H.hash("CPaceMac" || sid || ISK),
        // Ta = MAC(mac_key, lv_cat(Ya, ADa)), Tb = MAC(mac_key, lv_cat(Yb, ADb)).
        let mut b = Vec::with_capacity(DSI_MAC.len() + self.sid.len() + isk.len());
        b.extend_from_slice(DSI_MAC);
        b.extend_from_slice(&self.sid);
        b.extend_from_slice(&isk);
        let mac_key = Sha512::digest(&b);
        b.fill(0);
        self.tag = Some(mac(mac_key.as_ref(), &self.msg, &self.ad));
        self.peer_tag = Some(mac(mac_key.as_ref(), msg, ad));

        Ok(isk)
    }

    /// Returns this party's key confirmation tag, to be sent to the other
    /// party after a successful finish; None before.
    pub fn tag(&self) -> Option<Vec<u8>> {
        self.tag.clone()
    }

    /// Checks the other party's key confirmation tag, reporting an error if
    /// it is not the expected one, which means the two parties did not
    /// derive the same key. It reports an error if called before a
    /// successful finish.
    pub fn verify(&self, tag: &[u8]) -> Result<(), Error> {
        let want = self.peer_tag.as_ref().ok_or(Error("cpace: exchange not finished"))?;
        // Compare in constant time, as hmac.Equal does.
        let diff = tag.iter().zip(want).fold(0u8, |d, (a, b)| d | (a ^ b));
        if tag.len() != want.len() || diff != 0 {
            return Err(Error("cpace: key confirmation failed"));
        }
        Ok(())
    }

    /// Returns a public identifier for the exchange, derived from the
    /// exchange transcript; None before a successful finish.
    #[allow(dead_code)]
    pub fn session_id(&self) -> Option<Vec<u8>> {
        self.sid_output.clone()
    }

    /// Appends transcript(Ya, ADa, Yb, ADb) to b, using ordered
    /// concatenation if the exchange has no defined message ordering.
    fn transcript(&self, b: Vec<u8>, ya: &[u8], ada: &[u8], yb: &[u8], adb: &[u8]) -> Vec<u8> {
        if self.role == Role::Symmetric {
            return o_cat(b, &lv_cat(Vec::new(), &[ya, ada]), &lv_cat(Vec::new(), &[yb, adb]));
        }
        lv_cat(lv_cat(b, &[ya, ada]), &[yb, adb])
    }
}

/// Returns MAC(key, lv_cat(msg, ad)).
fn mac(key: &[u8], msg: &[u8], ad: &[u8]) -> Vec<u8> {
    let mut m = hmac::Hmac::<Sha512>::new_from_slice(key).expect("HMAC takes a key of any length");
    m.update(&lv_cat(Vec::new(), &[msg, ad]));
    m.finalize().into_bytes().to_vec()
}

/// Returns generator_string(G.DSI, PRS, CI, sid, H.s_in_bytes), which is
/// lv_cat(DSI, PRS, zero_bytes(len_zpad), CI, sid). The zero padding fills
/// the hash function's first input block, so that the number of bytes
/// hashed does not depend on the password length.
fn generator_string(prs: &[u8], ci: &[u8], sid: &[u8]) -> Vec<u8> {
    let b = lv_cat(Vec::new(), &[DSI, prs]);
    let zpad = (BLOCK_SIZE as isize - 1 - b.len() as isize).max(0) as usize;
    lv_cat(b, &[&vec![0u8; zpad], ci, sid])
}

/// Returns the u-coordinate of the group generator derived from the
/// password (PRS), channel identifier (CI), and session identifier (sid),
/// implementing G.calculate_generator.
fn generator(prs: &[u8], ci: &[u8], sid: &[u8]) -> [u8; 32] {
    let mut b = generator_string(prs, ci, sid);
    let h = Sha512::digest(&b);
    b.fill(0);

    // Interpret the first 32 bytes of the hash as a field element, as in
    // decodeUCoordinate, and map it to the curve with Elligator 2.
    let mut u = [0u8; 32];
    u.copy_from_slice(&h[..ELEMENT_SIZE]);
    let r = field::from_bytes(&u);
    u.fill(0);
    field::elligator2(&r)
}

/// Appends prepend_len(v) to b: v prefixed by its length, encoded using
/// LEB128.
fn prepend_len(mut b: Vec<u8>, v: &[u8]) -> Vec<u8> {
    let mut n = v.len();
    loop {
        if n < 128 {
            b.push(n as u8);
        } else {
            b.push((n as u8 & 0x7f) | 0x80);
        }
        n >>= 7;
        if n == 0 {
            break;
        }
    }
    b.extend_from_slice(v);
    b
}

/// Appends lv_cat(vs...) to b: the concatenation of the vs, each prefixed
/// by its length.
fn lv_cat(mut b: Vec<u8>, vs: &[&[u8]]) -> Vec<u8> {
    for v in vs {
        b = prepend_len(b, v);
    }
    b
}

/// Appends o_cat(v1, v2) to b: the two values in lexicographic order, larger
/// first, prefixed by "oc".
fn o_cat(mut b: Vec<u8>, v1: &[u8], v2: &[u8]) -> Vec<u8> {
    b.extend_from_slice(b"oc");
    let (first, second) = if v1 < v2 { (v2, v1) } else { (v1, v2) };
    b.extend_from_slice(first);
    b.extend_from_slice(second);
    b
}

#[cfg(test)]
mod tests;
