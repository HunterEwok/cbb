// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! Push to a phone whose app is closed (format section 20.4, roadmap item
//! 57): the phone's registration (member message `push`, t 28), the body a
//! member seals to that phone, and the messages between a member and the
//! project's push service (t 100–104, ALPN `cbb-push/1`).
//!
//! - A phone tells each member it is connected to, for each group apart, the
//!   token of its platform's push service, the platform (`env`) and a push
//!   key of 32 random bytes it drew for that group. The message is not
//!   signed and never passed on: a member takes it only from the device
//!   itself over their member connection.
//! - The body is one fixed size per platform (the env registry, 2972 bytes
//!   for every platform today), sealed with ChaCha20-Poly1305 under a key
//!   derived from the push key. Inside: a reduced copy (format section 10)
//!   whose origin's signature the phone checks before it shows anything; or
//!   a hint that a copy waits; or a hint of a group event. Hints are shown
//!   as "open the app", never as facts.
//! - Every honest sender of one body makes the same bytes: the nonce is
//!   derived from the plaintext, a copy is reduced with age 0 and an event
//!   carries its record's own time. The service drops a repeat by the bytes,
//!   and the phone's extension shows nothing it already showed.
//! - With each token the phone draws a send key; each registration carries
//!   its signature over the platform, the token and the registration's
//!   number. The service keeps the newest number per token and refuses an
//!   older one: a member removed since the phone registered again holds
//!   only older ones (until the first send under the new number, an old one
//!   passes, and its bodies do not open under the new push key). A member
//!   present at a token's very first registration could bind it first; the
//!   way out is a new token, or 30 days without a send under that binding.
//!
//! The service sees its own face's period tag and the server keys' hashes
//! (the blind credentials of section 8), tokens, times and one size per
//! platform; never a group ID, a device ID, a name or content.

#[cfg(test)]
mod tests;

use alloc::vec::Vec;

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::format::Rule;
use crate::format::cbor::head_len;
use crate::format::cbor::{self, Value};
use crate::format::frame;
use crate::msg::{Field, Table, Ty, check_map};
use crate::records::key::Key;

// ------------------------------------------------------------- numbers

/// Member message `push`: a phone's registration, to a member.
pub const T_PUSH: u64 = 28;
/// Member message `push-renew` (t 29), member → phone: the push service
/// answered `stale` to a send under the phone's registration with this
/// slot; the phone registers again.
pub const T_RENEW: u64 = 29;
/// The push service's messages.
pub const T_HELLO: u64 = 100;
pub const T_READY: u64 = 101;
pub const T_SEND: u64 = 102;
pub const T_SENT: u64 = 103;
pub const T_ERROR: u64 = 104;
/// The ALPN of a member's connection to the push service.
pub const ALPN: &[u8] = b"cbb-push/1";

/// The platforms and their environments (`push/env`). A reader keeps a
/// value it does not know and hands it on as it is (E-1).
pub const ENV_APNS: u64 = 1;
pub const ENV_APNS_SANDBOX: u64 = 2;
pub const ENV_FCM: u64 = 3;
pub const ENV_UNIFIEDPUSH: u64 = 4;
pub const ENV_PUSHKIT: u64 = 5;
pub const ENV_AURORA: u64 = 6;

/// `push/kinds` bits.
pub const KIND_COPIES: u64 = 1;
pub const KIND_EVENTS: u64 = 2;

/// The body's kinds.
pub const BODY_COPY: u64 = 1;
pub const BODY_WAITS: u64 = 2;
pub const BODY_EVENT: u64 = 3;

/// Events (`pushbody/event`), rule 33's.
pub const EVENT_JOINED: u64 = 1;
pub const EVENT_REMOVED: u64 = 2;
pub const EVENT_WAITING: u64 = 3;
pub const EVENT_ROOT: u64 = 4;
pub const EVENT_OWN_RECORD: u64 = 5;
pub const EVENT_STOPPED: u64 = 6;

/// `push/sent/status`.
pub const SENT: u64 = 1;
pub const SENT_GONE: u64 = 2;
pub const SENT_BUDGET: u64 = 3;
pub const SENT_FAILED: u64 = 4;
pub const SENT_REPEAT: u64 = 5;
/// The send key's algorithm is one the service does not take.
pub const SENT_KEY: u64 = 6;
/// The send key, its signature or the registration's number does not hold
/// for this token: the registration is an old one.
pub const SENT_STALE: u64 = 7;

/// The longest wait a service asks of a sender: a day.
pub const MAX_RETRY_MS: u64 = 86_400_000;
/// The longest send key's public part and signature a service may take
/// later (the format's bound of a second signature).
pub const MAX_SEND_KEY: usize = crate::format::envelope::MAX_SIG2;
pub const MAX_SEND_SIG: usize = crate::format::envelope::MAX_SIG2;

/// The nonce and the tag around a body's plaintext.
pub const NONCE_LEN: usize = 12;
pub const TAG_LEN: usize = 16;
/// The smallest body: a nonce and a tag around nothing.
pub const MIN_BODY: usize = NONCE_LEN + TAG_LEN;
/// The largest body any platform takes.
pub const MAX_BODY: usize = 2972;
/// The longest token: FCM states no maximum, and a UnifiedPush endpoint or
/// a WNS channel is a URL. The longest send is on the 16384 step; an APNs
/// or FCM token keeps it on the 4096 step.
pub const MAX_TOKEN: usize = 4096;

/// The longest UnifiedPush endpoint: its token, with the keys, within
/// [`MAX_TOKEN`].
pub const MAX_UP_URL: usize = 4000;

/// The body's size for a platform: the env registry. 2972 bytes for every
/// platform today: base64 of it in each service's wrapper stays under its
/// 4096 bytes (APNs, FCM, Push Kit), and RFC 8291's encryption of it under
/// UnifiedPush's. A platform found smaller later changes only its row.
/// None for an env this version does not know: it is kept, never sent.
pub fn body_len(env: u64) -> Option<usize> {
    match env {
        ENV_APNS | ENV_APNS_SANDBOX | ENV_FCM | ENV_UNIFIEDPUSH | ENV_PUSHKIT | ENV_AURORA => Some(MAX_BODY),
        _ => None,
    }
}

// --------------------------------------------------------------- tables

const fn f(n: u16, rule: &'static str, ty: Ty, needed: bool) -> Field {
    Field { n, rule, ty, needed }
}

const ENV: Ty = Ty::Uint { min: 1, max: 255 };
const TOKEN: Ty = Ty::BytesUpTo(MAX_TOKEN);
const SEQ: Ty = Ty::Uint { min: 1, max: 1 << 53 };
const N: Ty = Ty::Uint { min: 1, max: u32::MAX as u64 };
const STATUS: Ty = Ty::Uint { min: 1, max: 255 };

/// Member message `push` (t 28).
pub static PUSH: Table = Table {
    shape: "push/shape",
    fields: &[
        f(2, "push/token", TOKEN, false),
        f(3, "push/env", ENV, false),
        f(4, "push/key", Ty::Bytes(32), false),
        f(5, "push/seq", SEQ, true),
        f(6, "push/kinds", Ty::Uint { min: 0, max: u32::MAX as u64 }, true),
        f(7, "push/send-key", Ty::Signer(MAX_SEND_KEY), false),
        f(8, "push/send-sig", Ty::BytesUpTo(MAX_SEND_SIG), false),
        f(9, "push/slot", Ty::Bytes(16), false),
        f(10, "push/challenge", Ty::Bytes(16), false),
    ],
};

/// Member message `push-renew` (t 29).
pub static RENEW: Table = Table { shape: "push-renew/shape", fields: &[f(2, "push-renew/slot", Ty::Bytes(16), true)] };

/// The token of env 4 (UnifiedPush, RFC 8030 and 8291): the endpoint and
/// the phone's keys for the message's encryption.
pub static PUSH_UP: Table = Table {
    shape: "push-up/shape",
    fields: &[
        f(1, "push-up/url", Ty::Text(MAX_UP_URL), true),
        f(2, "push-up/p256dh", Ty::Bytes(65), true),
        f(3, "push-up/auth", Ty::Bytes(16), true),
    ],
};

/// `push/hello` (t 100): the face's hubs' and members' credentials.
pub static HELLO: Table = Table {
    shape: "push/hello/shape",
    fields: &[f(2, "push/hello/credentials", Ty::Array { of: &Ty::Envelope, max: 2 }, true)],
};
/// `push/ready` (t 101): sends left this hour for the tag.
pub static READY: Table = Table {
    shape: "push/ready/shape",
    fields: &[f(2, "push/ready/left", Ty::Uint { min: 0, max: u32::MAX as u64 }, true)],
};
/// `push/send` (t 102).
pub static SEND: Table = Table {
    shape: "push/send/shape",
    fields: &[
        f(2, "push/send/n", N, true),
        f(3, "push/send/token", TOKEN, true),
        f(4, "push/send/env", ENV, true),
        // 5 was `once`: reserved, never used again.
        f(6, "push/send/body", Ty::BytesUpTo(MAX_BODY), true),
        f(7, "push/send/ttl", Ty::Uint { min: 1, max: 4 }, false),
        f(8, "push/send/key", Ty::Signer(MAX_SEND_KEY), true),
        f(9, "push/send/sig", Ty::BytesUpTo(MAX_SEND_SIG), true),
        f(10, "push/send/seq", SEQ, true),
        f(11, "push/send/slot", Ty::Bytes(16), true),
        f(12, "push/send/challenge", Ty::Bytes(16), false),
    ],
};
/// `push/sent` (t 103).
pub static SENT_TABLE: Table = Table {
    shape: "push/sent/shape",
    fields: &[
        f(2, "push/sent/n", N, true),
        f(3, "push/sent/status", STATUS, true),
        f(4, "push/sent/retry_ms", Ty::Uint { min: 1, max: MAX_RETRY_MS }, false),
    ],
};
/// `push/error` (t 104).
pub static ERROR: Table =
    Table { shape: "push/error/shape", fields: &[f(2, "push/error/reason", Ty::Text(256), true)] };

/// The body's plaintext (its needs depend on the kind; see [`Body::read`]).
pub static BODY: Table = Table {
    shape: "pushbody/shape",
    fields: &[
        f(0, "pushbody/kind", Ty::Uint { min: 1, max: (1 << 63) - 1 }, true),
        f(2, "pushbody/copy", Ty::BytesUpTo(PLAIN_LEN), false),
        f(3, "pushbody/id", Ty::Bytes(16), false),
        f(4, "pushbody/origin", Ty::Bytes(16), false),
        f(5, "pushbody/event", Ty::Uint { min: 1, max: (1 << 63) - 1 }, false),
        f(6, "pushbody/device", Ty::Bytes(16), false),
        f(7, "pushbody/time_ms", Ty::Uint { min: 0, max: (1 << 63) - 1 }, false),
    ],
};

/// Every table of this file, for the vectors.
pub static ALL: [&Table; 9] = [&PUSH, &RENEW, &PUSH_UP, &HELLO, &READY, &SEND, &SENT_TABLE, &ERROR, &BODY];

/// The table of message type t, if this file numbers it.
pub fn of(t: u64) -> Option<&'static Table> {
    Some(match t {
        T_PUSH => &PUSH,
        T_RENEW => &RENEW,
        T_HELLO => &HELLO,
        T_READY => &READY,
        T_SEND => &SEND,
        T_SENT => &SENT_TABLE,
        T_ERROR => &ERROR,
        _ => return None,
    })
}

pub const RULE_PUSH_SHAPE: Rule = Rule::field("push/shape");
pub const RULE_PUSH_KEY: Rule = Rule::field("push/key");
/// The send key's signature does not hold.
pub const RULE_SEND_SIG: Rule = Rule::field("push/send-sig");
pub const RULE_BODY_SHAPE: Rule = Rule::field("pushbody/shape");
pub const RULE_BODY_PAD: Rule = Rule::field("pushbody/pad");
pub const RULE_BODY_OPEN: Rule = Rule::field("pushbody/open");
pub const RULE_BODY_SIZE: Rule = Rule::field("pushbody/size");
/// The body's nonce is not the one its plaintext gives.
pub const RULE_BODY_NONCE: Rule = Rule::field("pushbody/nonce");
/// A copy in a body has an age: every sender writes it with age 0.
pub const RULE_BODY_AGE: Rule = Rule::field("pushbody/age");
pub const RULE_UP_URL: Rule = Rule::field("push-up/url");
/// `push-up/p256dh` is not an uncompressed point of P-256.
pub const RULE_UP_KEY: Rule = Rule::field("push-up/p256dh");

// --------------------------------------------------------- registration

/// A phone's registration with a member of one group.
#[derive(Clone, PartialEq, Eq)]
pub struct Registration {
    pub seq: u64,
    /// The bits the phone asks for; 0 is push off. Unknown bits are kept
    /// and never read.
    pub kinds: u64,
    /// With `kinds` ≠ 0: the token, the platform, the push key and the send
    /// key's signature.
    pub on: Option<On>,
}

/// What a registration that is on carries.
#[derive(Clone, PartialEq, Eq)]
pub struct On {
    pub token: Vec<u8>,
    pub env: u64,
    pub key: Zeroizing<[u8; 32]>,
    /// The phone's send key for this token, as the format writes a key. A
    /// member keeps one of an algorithm it does not know and passes it on.
    pub send_key: Key,
    /// Its signature over [`send_message`].
    pub send_sig: Vec<u8>,
    /// 16 random bytes the phone draws per group registration (never the
    /// group's ID): the service keeps the highest seq per (token, slot),
    /// so one group's registrations never silence another's.
    pub slot: [u8; 16],
    /// The last challenge the push service sent to the token, which the
    /// send key's signature then covers: possession of the token, proved
    /// to the service, confirms its binding to this send key.
    pub challenge: Option<[u8; 16]>,
}

impl On {
    /// What its signature covers, under registration number `seq`.
    pub fn signed(&self, seq: u64) -> Signed<'_> {
        Signed { env: self.env, token: &self.token, slot: &self.slot, seq, challenge: self.challenge.as_ref() }
    }
}

impl core::fmt::Debug for Registration {
    // The push key never goes to a log; the token neither.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Registration")
            .field("seq", &self.seq)
            .field("kinds", &self.kinds)
            .field("env", &self.on.as_ref().map(|o| o.env))
            .finish()
    }
}

/// What the send key signs, under the label `cbb push send v1`: the
/// platform, the token, the registration's slot and its number, and the
/// last challenge the service sent to the token when the phone has one.
pub fn send_message(env: u64, token: &[u8], slot: &[u8; 16], seq: u64, challenge: Option<&[u8; 16]>) -> Vec<u8> {
    let mut a = alloc::vec![Value::Uint(env), Value::Bytes(token), Value::Bytes(slot), Value::Uint(seq)];
    if let Some(c) = challenge {
        a.push(Value::Bytes(c));
    }
    Value::Array(a).encode()
}

const LABEL_SEND: &str = "cbb push send v1";

/// The latest clock a phone numbers a registration with: 2100-01-01. A
/// clock past it (a unit mistake) is read as this, so seq keeps room.
pub const MAX_CLOCK_MS: u64 = 4_102_444_800_000;
/// How far ahead of its own clock the service takes a seq.
pub const MAX_SEQ_AHEAD_MS: u64 = 86_400_000;

/// What checking a send key's signature found.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SendCheck {
    /// ES256, and the signature holds.
    Good,
    /// An algorithm this version does not know: a member keeps it, the
    /// service answers [`SENT_KEY`].
    Unknown,
}

/// What a send or a registration says the send key signed.
#[derive(Clone, Copy, Debug)]
pub struct Signed<'a> {
    pub env: u64,
    pub token: &'a [u8],
    pub slot: &'a [u8; 16],
    pub seq: u64,
    pub challenge: Option<&'a [u8; 16]>,
}

impl Signed<'_> {
    fn message(&self) -> Vec<u8> {
        send_message(self.env, self.token, self.slot, self.seq, self.challenge)
    }
}

/// Checks the send key's signature over what `s` names.
pub fn check_send(key: &Key, sig: &[u8], s: &Signed<'_>) -> Result<SendCheck, Rule> {
    match key.check_signer().map_err(|_| RULE_SEND_SIG)? {
        crate::records::key::KeyCheck::Unknown => Ok(SendCheck::Unknown),
        crate::records::key::KeyCheck::Good => {
            crate::records::key::verify_es256(key, LABEL_SEND, &s.message(), sig).map_err(|_| RULE_SEND_SIG)?;
            Ok(SendCheck::Good)
        }
    }
}

/// Signs what `s` names with the phone's send key.
pub fn sign_send(key: &dyn crate::identity::ExternalKey, s: &Signed<'_>) -> crate::error::Result<[u8; 64]> {
    crate::records::key::sign_es256(key, LABEL_SEND, &s.message())
}

/// The number a phone gives its next registration: one more than the one
/// it saved, and never less than its clock in milliseconds (a clock past
/// [`MAX_CLOCK_MS`] read as that), so a phone restored from a backup with
/// an older number still moves forward at the service. A saved number
/// more than [`MAX_SEQ_AHEAD_MS`] ahead of the clock (saved while the
/// clock was ahead) is one the service refuses, and so would be every one
/// after it until the clock caught up: the next is the clock then
/// ([`seq_was_ahead`]), which members take by [`Registration::replaced_by`].
pub fn next_seq(saved: Option<u64>, now_ms: u64) -> u64 {
    let now = now_ms.min(MAX_CLOCK_MS);
    match saved {
        Some(s) if seq_was_ahead(s, now) => now,
        _ => saved.map_or(1, |s| s.saturating_add(1)).max(now),
    }
    .clamp(1, 1 << 53)
}

/// Whether a saved number is more than [`MAX_SEQ_AHEAD_MS`] ahead of the
/// clock `now_ms`.
pub fn seq_was_ahead(saved: u64, now_ms: u64) -> bool {
    !seq_in_time(saved, now_ms.min(MAX_CLOCK_MS))
}

/// Whether the service takes `seq` at its clock `now_ms`: seq is a clock
/// by rule, so one more than a day ahead is never honest.
pub fn seq_in_time(seq: u64, now_ms: u64) -> bool {
    seq <= now_ms.saturating_add(MAX_SEQ_AHEAD_MS)
}

impl Registration {
    /// Reads message `push` (its map, `t` 28). A member does not check the
    /// send key's signature: the service does.
    pub fn read(m: &Value<'_>) -> Result<Registration, Rule> {
        check_map(&PUSH, m)?;
        let uint = |n| m.get(n).and_then(Value::as_uint);
        let bytes = |n| m.get(n).and_then(Value::as_bytes);
        let seq = uint(5).ok_or(RULE_PUSH_SHAPE)?;
        let kinds = uint(6).ok_or(RULE_PUSH_SHAPE)?;
        let challenge = match bytes(10) {
            None => None,
            Some(c) => Some(<[u8; 16]>::try_from(c).map_err(|_| RULE_PUSH_SHAPE)?),
        };
        let on = match (kinds, bytes(2), uint(3), bytes(4), m.get(7), bytes(8), bytes(9)) {
            (0, None, None, None, None, None, None) if challenge.is_none() => None,
            (k, Some(token), Some(env), Some(key), Some(send_key), Some(send_sig), Some(slot)) if k != 0 => {
                let key: [u8; 32] = key.try_into().map_err(|_| RULE_PUSH_SHAPE)?;
                // A key of zeros is no key a phone drew.
                if key == [0; 32] {
                    return Err(RULE_PUSH_KEY);
                }
                let send_key = Key::read(send_key).map_err(|_| RULE_PUSH_SHAPE)?;
                let slot = <[u8; 16]>::try_from(slot).map_err(|_| RULE_PUSH_SHAPE)?;
                Some(On {
                    token: token.to_vec(),
                    env,
                    key: Zeroizing::new(key),
                    send_key,
                    send_sig: send_sig.to_vec(),
                    slot,
                    challenge,
                })
            }
            _ => return Err(RULE_PUSH_SHAPE),
        };
        Ok(Registration { seq, kinds, on })
    }

    /// The frame of message `push`; None for one its reader refuses.
    pub fn write(&self) -> Option<Vec<u8>> {
        let mut m = alloc::vec![(frame::FIELD_T, Value::Uint(T_PUSH))];
        if let Some(on) = &self.on {
            m.push((2, Value::Bytes(&on.token)));
            m.push((3, Value::Uint(on.env)));
            m.push((4, Value::Bytes(&on.key[..])));
        }
        m.push((5, Value::Uint(self.seq)));
        m.push((6, Value::Uint(self.kinds)));
        if let Some(on) = &self.on {
            m.push((7, on.send_key.to_value()));
            m.push((8, Value::Bytes(&on.send_sig)));
            m.push((9, Value::Bytes(&on.slot)));
            if let Some(c) = &on.challenge {
                m.push((10, Value::Bytes(c)));
            }
        }
        let f = frame::write(&Value::Map(m));
        let back = frame::read(&f, frame::LIMIT_MEMBER).ok().and_then(|msg| Registration::read(&msg.map).ok());
        (back.as_ref() == Some(self)).then_some(f)
    }

    /// Whether the phone asks for pushes of kind bit `kind`.
    pub fn wants(&self, kind: u64) -> bool {
        self.on.is_some() && self.kinds & kind != 0
    }

    /// Whether a member that holds `self` takes `newer` in its place, by
    /// the member's clock `now_ms`: a higher number; or a lower one only
    /// when both hold: the held number is more than a day ahead of the
    /// clock (the service refuses it), and the newer one is within a day of
    /// the clock either way (the phone's clock was set right again).
    pub fn replaced_by(&self, newer: &Registration, now_ms: u64) -> bool {
        newer.seq > self.seq
            || (self.seq > now_ms.saturating_add(MAX_SEQ_AHEAD_MS) && newer.seq.abs_diff(now_ms) <= MAX_SEQ_AHEAD_MS)
    }
}

/// Message `push-renew` (t 29) for the registration with `slot`.
pub fn renew(slot: &[u8; 16]) -> Vec<u8> {
    frame::write(&Value::Map(alloc::vec![(frame::FIELD_T, Value::Uint(T_RENEW)), (2, Value::Bytes(slot))]))
}

/// Reads message `push-renew`: the slot of the registration to make again.
pub fn read_renew(m: &Value<'_>) -> Result<[u8; 16], Rule> {
    check_map(&RENEW, m)?;
    m.get(2).and_then(Value::as_bytes).and_then(|b| <[u8; 16]>::try_from(b).ok()).ok_or(Rule::field("push-renew/shape"))
}

/// Who may register: the device itself over its own member connection, and
/// only a phone or a computer, never a leaf or a watch (they never get a
/// push, and a leaf has no app to wake).
pub fn may_register(role: u64) -> bool {
    role == crate::records::body::ROLE_PHONE || role == crate::records::body::ROLE_MEMBER
}

/// A UnifiedPush token: the endpoint and RFC 8291's keys.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct UnifiedPush<'a> {
    pub url: &'a str,
    pub p256dh: &'a [u8; 65],
    pub auth: &'a [u8; 16],
}

impl<'a> UnifiedPush<'a> {
    /// Reads a token of env 4. The service reads it; a member keeps any
    /// token as bytes.
    pub fn read(token: &'a [u8]) -> Result<UnifiedPush<'a>, Rule> {
        let v = cbor::decode(token)?;
        check_map(&PUSH_UP, &v)?;
        let url = v.get(1).and_then(Value::as_text).ok_or(RULE_UP_URL)?;
        if !up_url(url) {
            return Err(RULE_UP_URL);
        }
        let p256dh: &[u8; 65] =
            v.get(2).and_then(Value::as_bytes).and_then(|b| b.try_into().ok()).ok_or(RULE_UP_KEY)?;
        // RFC 8291's key: an uncompressed point of P-256.
        if p256dh.first() != Some(&4) || p256::PublicKey::from_sec1_bytes(p256dh).is_err() {
            return Err(RULE_UP_KEY);
        }
        let auth = v.get(3).and_then(Value::as_bytes).and_then(|b| b.try_into().ok()).ok_or(RULE_UP_URL)?;
        Ok(UnifiedPush { url, p256dh, auth })
    }

    /// The token's encoding.
    pub fn write(&self) -> Vec<u8> {
        Value::Map(alloc::vec![
            (1, Value::Text(self.url)),
            (2, Value::Bytes(&self.p256dh[..])),
            (3, Value::Bytes(&self.auth[..])),
        ])
        .encode()
    }
}

/// Whether a UnifiedPush endpoint holds to the rows: printable ASCII,
/// `https://`, no user, no fragment, a host name (never an address) of two
/// labels at least, and port 443 when one is named. That the name
/// leads only to public addresses the service checks on the address it
/// connects to.
pub fn up_url(url: &str) -> bool {
    let Some(rest) = url.strip_prefix("https://") else { return false };
    if !url.bytes().all(|b| (0x21..=0x7e).contains(&b)) || url.contains('#') {
        return false;
    }
    let authority = rest.split(['/', '?']).next().unwrap_or("");
    if authority.contains('@') {
        return false;
    }
    let host = match authority.rsplit_once(':') {
        Some((h, "443")) => h,
        Some(_) => return false,
        None => authority,
    };
    let labels: Vec<&str> = host.split('.').collect();
    let label = |l: &&str| {
        (1..=63).contains(&l.len())
            && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
            && !l.starts_with('-')
            && !l.ends_with('-')
    };
    host.len() <= 253
        && labels.len() >= 2
        && labels.iter().all(label)
        // No top-level name starts with a digit; a resolver may read such a
        // last label as part of an address (hex, octal or decimal).
        && labels.last().is_some_and(|l| !l.starts_with(|c: char| c.is_ascii_digit()))
}

// ----------------------------------------------------------------- keys

const LABEL_BODY: &str = "cbb push body v1";
const LABEL_NONCE: &str = "cbb push nonce v1";
const LABEL_AD: &str = "cbb push v1";

fn derive(pk: &[u8; 32], info: &str) -> Zeroizing<[u8; 32]> {
    let mut out = Zeroizing::new([0u8; 32]);
    // 32 bytes are well within HKDF-SHA256's limit.
    let _ = Hkdf::<Sha256>::new(None, pk).expand(info.as_bytes(), &mut out[..]);
    out
}

/// The nonce of a body: the first 12 bytes of HMAC-SHA256(nonce key,
/// associated data ‖ plaintext). One plaintext under one key and number
/// always gives the same nonce, two plaintexts two nonces: every honest
/// sender of a body makes the same bytes, and no nonce serves twice.
fn nonce_for(pk: &[u8; 32], ad: &[u8], plain: &[u8]) -> [u8; NONCE_LEN] {
    let k = derive(pk, LABEL_NONCE);
    let mut out = [0u8; NONCE_LEN];
    // HMAC takes a key of any length, so this never fails.
    if let Ok(mut mac) = <Hmac<Sha256> as hmac::KeyInit>::new_from_slice(&k[..]) {
        mac.update(ad);
        mac.update(plain);
        let full = mac.finalize().into_bytes();
        for (o, b) in out.iter_mut().zip(full.iter()) {
            *o = *b;
        }
    }
    out
}

fn associated(seq: u64) -> Vec<u8> {
    let mut ad = Vec::with_capacity(LABEL_AD.len().saturating_add(9));
    ad.extend_from_slice(LABEL_AD.as_bytes());
    ad.push(0);
    ad.extend_from_slice(&seq.to_be_bytes());
    ad
}

// ----------------------------------------------------------------- body

/// The plaintext's size in a body of `MAX_BODY` bytes.
pub const PLAIN_LEN: usize = MAX_BODY - MIN_BODY;

/// What a body says.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Body {
    /// A reduced copy (format section 10.1) holding this phone's wrap and
    /// the payload whole: shown only after the origin's signature and the
    /// commitment hold.
    Copy(Vec<u8>),
    /// A hint: a copy waits (it did not fit, or it is a file).
    Waits { id: [u8; 16], origin: [u8; 16] },
    /// A hint: something happened in the group. An event this version does
    /// not number is the neutral hint.
    Event { id: [u8; 16], event: u64, device: Option<[u8; 16]>, time_ms: Option<u64> },
    /// A kind this version does not know: the neutral hint.
    Unknown(u64),
}

/// The zeros a map of `base` bytes and `entries` entries needs in a `pad`
/// field (key 1) so that its encoding is exactly `target` bytes; None when
/// no padding reaches it exactly.
fn pad_for(base: usize, entries: usize, target: usize) -> Option<usize> {
    let grow = head_len((entries as u64).saturating_add(1)).saturating_sub(head_len(entries as u64));
    let fixed = base.checked_add(grow)?.checked_add(1)?;
    [1usize, 2, 3, 5, 9].into_iter().find_map(|hl| {
        let plen = target.checked_sub(fixed)?.checked_sub(hl)?;
        (head_len(plen as u64) == hl).then_some(plen)
    })
}

impl Body {
    /// The map, without `pad`.
    fn entries(&self) -> Vec<(u16, Value<'_>)> {
        match self {
            Body::Copy(c) => alloc::vec![(0, Value::Uint(BODY_COPY)), (2, Value::Bytes(c))],
            Body::Waits { id, origin } => {
                alloc::vec![(0, Value::Uint(BODY_WAITS)), (3, Value::Bytes(id)), (4, Value::Bytes(origin)),]
            }
            Body::Event { id, event, device, time_ms } => {
                let mut m = alloc::vec![(0, Value::Uint(BODY_EVENT)), (3, Value::Bytes(id)), (5, Value::Uint(*event)),];
                if let Some(d) = device {
                    m.push((6, Value::Bytes(d)));
                }
                if let Some(t) = time_ms {
                    m.push((7, Value::Uint(*t)));
                }
                m
            }
            Body::Unknown(k) => alloc::vec![(0, Value::Uint(*k))],
        }
    }

    /// The plaintext padded to exactly `PLAIN_LEN` bytes; None when it
    /// does not fit (a copy too large: send [`Body::Waits`]).
    pub fn plaintext(&self) -> Option<Vec<u8>> {
        self.padded(PLAIN_LEN)
    }

    /// The plaintext padded to exactly `len` bytes.
    /// None as well for a body its reader would refuse or read otherwise
    /// (an empty copy, a known kind written as [`Body::Unknown`]).
    fn padded(&self, len: usize) -> Option<Vec<u8>> {
        let entries = self.entries();
        let base = Value::Map(entries.clone()).encode();
        let out = if base.len() == len {
            base
        } else {
            let plen = pad_for(base.len(), entries.len(), len)?;
            let zeros = alloc::vec![0u8; plen];
            let mut all = entries;
            // `pad` is key 1: after key 0, before the rest.
            all.insert(1, (1, Value::Bytes(&zeros)));
            Value::Map(all).encode()
        };
        (Body::read(&out).as_ref() == Ok(self)).then_some(out)
    }

    /// Reads a plaintext opened from a body of any size: a map in the
    /// profile with the one padding that brings it to its size.
    pub fn read(b: &[u8]) -> Result<Body, Rule> {
        let v = cbor::decode(b)?;
        // A kind this version does not number is the neutral hint before
        // any other field is read against the table.
        match v.get(0).and_then(Value::as_uint) {
            Some(k) if k > BODY_EVENT => return Ok(Body::Unknown(k)),
            Some(BODY_COPY | BODY_WAITS | BODY_EVENT) => {}
            _ => return Err(Rule::field("pushbody/kind")),
        }
        check_map(&BODY, &v)?;
        if let Some(p) = v.get(1)
            && p.as_bytes().is_none_or(|z| z.iter().any(|x| *x != 0))
        {
            return Err(RULE_BODY_PAD);
        }
        let id16 = |n| v.get(n).and_then(Value::as_bytes).and_then(|b| <[u8; 16]>::try_from(b).ok());
        let kind = v.get(0).and_then(Value::as_uint).ok_or(RULE_BODY_SHAPE)?;
        let need = |r: &'static str| Rule::field(r);
        let body = match kind {
            BODY_COPY => {
                let c = v.get(2).and_then(Value::as_bytes).ok_or(need("pushbody/copy"))?;
                // Age is outside the origin's signature: every sender
                // writes 0 (left out), so one copy has one plaintext.
                if cbor::decode(c).is_ok_and(|cv| cv.get(crate::format::copy::FIELD_AGE).is_some()) {
                    return Err(RULE_BODY_AGE);
                }
                Body::Copy(c.to_vec())
            }
            BODY_WAITS => {
                Body::Waits { id: id16(3).ok_or(need("pushbody/id"))?, origin: id16(4).ok_or(need("pushbody/origin"))? }
            }
            BODY_EVENT => Body::Event {
                id: id16(3).ok_or(need("pushbody/id"))?,
                event: v.get(5).and_then(Value::as_uint).ok_or(need("pushbody/event"))?,
                device: id16(6),
                time_ms: v.get(7).and_then(Value::as_uint),
            },
            k => Body::Unknown(k),
        };
        // One padding only: the one that brings the other fields, known or
        // not (fields from 8 and kinds from 4 are a later version's), to
        // this size.
        let rest: Vec<(u16, Value<'_>)> = v.as_map().unwrap_or(&[]).iter().filter(|(k, _)| *k != 1).cloned().collect();
        let base = Value::Map(rest.clone()).encode().len();
        let exact = match v.get(1).and_then(Value::as_bytes) {
            None => base == b.len(),
            Some(z) => pad_for(base, rest.len(), b.len()) == Some(z.len()),
        };
        if !exact {
            return Err(RULE_BODY_PAD);
        }
        Ok(body)
    }

    /// Whether this is a hint (shown as "open the app"), not content.
    pub fn is_hint(&self) -> bool {
        !matches!(self, Body::Copy(_))
    }
}

/// Seals a body for env's platform under the push key of registration
/// `seq`: nonce ‖ ChaCha20-Poly1305, the nonce derived from the plaintext.
/// None when the env has no size this version knows or the body does not
/// fit.
pub fn seal(pk: &[u8; 32], seq: u64, env: u64, body: &Body) -> Option<Vec<u8>> {
    let len = body_len(env)?;
    // Every size of the registry is MAX_BODY today; a smaller row would
    // pad to its own plaintext size.
    if len != MAX_BODY {
        return None;
    }
    let plain = Zeroizing::new(body.plaintext()?);
    let k = derive(pk, LABEL_BODY);
    let aead = ChaCha20Poly1305::new_from_slice(&k[..]).ok()?;
    let ad = associated(seq);
    let nonce = nonce_for(pk, &ad, &plain);
    let ct = aead.encrypt(&Nonce::from(nonce), Payload { msg: &plain, aad: &ad }).ok()?;
    let mut out = Vec::with_capacity(len);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    (out.len() == len).then_some(out)
}

/// Opens a body of a size of the registry under the push key of
/// registration `seq`; the AEAD decides.
pub fn open(pk: &[u8; 32], seq: u64, sealed: &[u8]) -> Result<Body, Rule> {
    if sealed.len() != MAX_BODY {
        return Err(RULE_BODY_SIZE);
    }
    let (nonce, ct) = sealed.split_at(NONCE_LEN);
    let nonce: [u8; NONCE_LEN] = nonce.try_into().map_err(|_| RULE_BODY_SIZE)?;
    let k = derive(pk, LABEL_BODY);
    let aead = ChaCha20Poly1305::new_from_slice(&k[..]).map_err(|_| RULE_BODY_OPEN)?;
    let ad = associated(seq);
    let plain =
        Zeroizing::new(aead.decrypt(&Nonce::from(nonce), Payload { msg: ct, aad: &ad }).map_err(|_| RULE_BODY_OPEN)?);
    // One plaintext has one body: a nonce of the sender's choosing would
    // make the same copy anew for the service's check of repeats.
    if nonce_for(pk, &ad, &plain) != nonce {
        return Err(RULE_BODY_NONCE);
    }
    Body::read(&plain)
}

/// The body for copy `copy` (its wire form) to `phone`: None when the copy
/// is not sealed to the phone (it learns nothing of it); else the reduced
/// copy with age 0 when it fits with the payload whole, else the hint that
/// it waits. Three sizes of a reduced copy cannot be padded exactly and
/// wait too: the phone sees a hint, the service only the body's one size.
pub fn copy_body(
    copy: &crate::format::copy::Copy<'_>,
    readers: &[(crate::records::key::DeviceId, u64)],
    phone: &crate::records::key::DeviceId,
    id: [u8; 16],
    origin: [u8; 16],
) -> Option<Body> {
    if !readers.iter().any(|(d, _)| d == phone) {
        return None;
    }
    let mut same = copy.clone();
    same.age_ms = 0;
    if same.payload.is_some()
        && let Ok(reduced) = crate::copies::reduce(&same, readers, phone)
        && cbor::decode(&reduced).is_ok_and(|v| v.get(crate::format::copy::FIELD_PAYLOAD).is_some())
    {
        let body = Body::Copy(reduced);
        if body.plaintext().is_some() {
            return Some(body);
        }
    }
    Some(Body::Waits { id, origin })
}

// ---------------------------------------------------- service messages

/// `push/send`.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Send<'a> {
    pub n: u64,
    pub token: &'a [u8],
    pub env: u64,
    pub body: &'a [u8],
    pub ttl: Option<u64>,
    /// The registration's send key, its signature and its number, as the
    /// phone gave them.
    pub key: Key,
    pub sig: &'a [u8],
    pub seq: u64,
    pub slot: [u8; 16],
    /// The challenge the registration's signature covers, if it has one.
    pub challenge: Option<[u8; 16]>,
}

impl<'a> Send<'a> {
    /// Reads `push/send` from its map.
    pub fn read(m: &'a Value<'a>) -> Result<Send<'a>, Rule> {
        check_map(&SEND, m)?;
        let bad = Rule::field("push/send/shape");
        Ok(Send {
            n: m.get(2).and_then(Value::as_uint).ok_or(bad)?,
            token: m.get(3).and_then(Value::as_bytes).ok_or(bad)?,
            env: m.get(4).and_then(Value::as_uint).ok_or(bad)?,
            body: m.get(6).and_then(Value::as_bytes).ok_or(bad)?,
            ttl: m.get(7).and_then(Value::as_uint),
            key: m.get(8).map(Key::read).ok_or(bad)?.map_err(|_| bad)?,
            sig: m.get(9).and_then(Value::as_bytes).ok_or(bad)?,
            seq: m.get(10).and_then(Value::as_uint).ok_or(bad)?,
            slot: m.get(11).and_then(Value::as_bytes).and_then(|b| <[u8; 16]>::try_from(b).ok()).ok_or(bad)?,
            challenge: match m.get(12) {
                None => None,
                Some(c) => Some(c.as_bytes().and_then(|b| <[u8; 16]>::try_from(b).ok()).ok_or(bad)?),
            },
        })
    }

    /// Its frame; None for one its reader refuses.
    pub fn write(&self) -> Option<Vec<u8>> {
        let mut m = alloc::vec![
            (frame::FIELD_T, Value::Uint(T_SEND)),
            (2, Value::Uint(self.n)),
            (3, Value::Bytes(self.token)),
            (4, Value::Uint(self.env)),
            (6, Value::Bytes(self.body)),
        ];
        if let Some(t) = self.ttl {
            m.push((7, Value::Uint(t)));
        }
        m.push((8, self.key.to_value()));
        m.push((9, Value::Bytes(self.sig)));
        m.push((10, Value::Uint(self.seq)));
        m.push((11, Value::Bytes(&self.slot)));
        if let Some(c) = &self.challenge {
            m.push((12, Value::Bytes(c)));
        }
        let f = frame::write(&Value::Map(m));
        let msg = frame::read(&f, MAX_SERVICE_FRAME).ok()?;
        (Send::read(&msg.map).ok().as_ref() == Some(self)).then_some(f)
    }

    /// What its signature covers.
    pub fn signed(&self) -> Signed<'_> {
        Signed { env: self.env, token: self.token, slot: &self.slot, seq: self.seq, challenge: self.challenge.as_ref() }
    }

    /// Whether the body has its env's size. The service answers a body of
    /// another size, or an env it has no path for, with status 4.
    pub fn sized(&self) -> bool {
        body_len(self.env) == Some(self.body.len())
    }
}

/// The largest frame between a member and the push service: a send with
/// the longest token, send key and signature fits.
pub const MAX_SERVICE_FRAME: usize = 16_384;

/// `push/hello`'s frame: one or two credentials, as its table says.
pub fn hello(credentials: &[&[u8]]) -> Result<Vec<u8>, Rule> {
    if credentials.is_empty() || credentials.len() > 2 {
        return Err(Rule::field("push/hello/credentials"));
    }
    let items: Result<Vec<Value<'_>>, Rule> = credentials.iter().map(|c| cbor::decode(c)).collect();
    let f = frame::write(&Value::Map(alloc::vec![(frame::FIELD_T, Value::Uint(T_HELLO)), (2, Value::Array(items?))]));
    let msg = frame::read(&f, MAX_SERVICE_FRAME)?;
    check_map(&HELLO, &msg.map)?;
    Ok(f)
}

/// `push/ready`'s frame.
pub fn ready(left: u64) -> Vec<u8> {
    frame::write(&Value::Map(alloc::vec![(frame::FIELD_T, Value::Uint(T_READY)), (2, Value::Uint(left))]))
}

/// `push/sent`'s frame. `retry_ms` goes only with the statuses that carry
/// it ([`SENT_BUDGET`], [`SENT_FAILED`]), at most [`MAX_RETRY_MS`].
pub fn sent(n: u64, status: u64, retry_ms: Option<u64>) -> Vec<u8> {
    let mut m = alloc::vec![(frame::FIELD_T, Value::Uint(T_SENT)), (2, Value::Uint(n)), (3, Value::Uint(status))];
    if let Some(r) = retry_ms.filter(|_| matches!(status, SENT_BUDGET | SENT_FAILED)) {
        m.push((4, Value::Uint(r.clamp(1, MAX_RETRY_MS))));
    }
    frame::write(&Value::Map(m))
}

/// `push/sent` as a sender reads it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Sent {
    pub n: u64,
    /// The status as the sender acts on it ([`status`]).
    pub status: u64,
    /// How long to wait, only with the statuses that carry it.
    pub retry_ms: Option<u64>,
}

impl Sent {
    pub fn read(m: &Value<'_>) -> Result<Sent, Rule> {
        check_map(&SENT_TABLE, m)?;
        let bad = Rule::field("push/sent/shape");
        let st = status(m.get(3).and_then(Value::as_uint).ok_or(bad)?);
        Ok(Sent {
            n: m.get(2).and_then(Value::as_uint).ok_or(bad)?,
            status: st,
            retry_ms: m.get(4).and_then(Value::as_uint).filter(|_| matches!(st, SENT_BUDGET | SENT_FAILED)),
        })
    }
}

/// What a sender does with a status: a status this version does not know
/// is "failed, try later" (E-1).
pub fn status(s: u64) -> u64 {
    match s {
        SENT | SENT_GONE | SENT_BUDGET | SENT_REPEAT | SENT_KEY | SENT_STALE => s,
        _ => SENT_FAILED,
    }
}

/// `push/error`'s frame.
pub fn error(reason: &str) -> Vec<u8> {
    frame::write(&Value::Map(alloc::vec![(frame::FIELD_T, Value::Uint(T_ERROR)), (2, Value::Text(reason))]))
}
