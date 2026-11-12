// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The tables of the messages wave 3 numbers. Each row: the field's number,
//! the rule a bad value breaks, its type, and whether it is needed.

use super::{Field, Table, Ty};
use crate::format::Alg;

const fn f(n: u16, rule: &'static str, ty: Ty, needed: bool) -> Field {
    Field { n, rule, ty, needed }
}

const ID16: Ty = Ty::Bytes(16);
const B32: Ty = Ty::Bytes(32);
const TEXT64: Ty = Ty::Text(64);
const REASON: Ty = Ty::Text(256);
const WG_KEY: Ty = Ty::Key(Alg::X25519);
const MEMBER_KEY: Ty = Ty::Key(Alg::Es256);
const ADDR: Ty = Ty::Addr;
const U32: Ty = Ty::Uint { min: 0, max: u32::MAX as u64 };
const U16: Ty = Ty::Uint { min: 1, max: 65535 };
const MS: Ty = Ty::Uint { min: 1, max: (1 << 63) - 1 };
const ENV: Ty = Ty::Envelope;

// ---------------------------------------------------------------- pairing

/// `ADb` of message 65: what the joiner learns of the group before CPace
/// ends, and shows ("you are joining …").
pub static ADB: Table = Table {
    shape: "pair/adb/shape",
    fields: &[
        f(1, "pair/adb/group", ID16, true),
        f(2, "pair/adb/device", ID16, true),
        f(3, "pair/adb/name", TEXT64, true),
    ],
};

pub static PAIR_START: Table = Table {
    shape: "pair/start/shape",
    fields: &[
        f(2, "pair/start/ya", Ty::BytesUpTo(256), true),
        f(3, "pair/start/ada", Ty::BytesUpTo(16384), true),
        f(4, "pair/start/commitment", B32, true),
    ],
};
pub static PAIR_REPLY: Table = Table {
    shape: "pair/reply/shape",
    fields: &[
        f(2, "pair/reply/yb", Ty::BytesUpTo(256), true),
        f(3, "pair/reply/adb", Ty::BytesUpTo(1024), true),
        f(4, "pair/reply/nonce", B32, true),
    ],
};
pub static PAIR_CONFIRM: Table = Table {
    shape: "pair/confirm/shape",
    fields: &[f(2, "pair/confirm/ta", Ty::BytesUpTo(64), true), f(3, "pair/confirm/nonce", B32, true)],
};
pub static PAIR_WELCOME: Table = Table {
    shape: "pair/welcome/shape",
    fields: &[f(2, "pair/welcome/tb", Ty::BytesUpTo(64), true), f(3, "pair/welcome/welcome", Ty::Map(&WELCOME), true)],
};
pub static PAIR_DONE: Table = Table { shape: "pair/done/shape", fields: &[] };
pub static PAIR_ERROR: Table =
    Table { shape: "pair/error/shape", fields: &[f(2, "pair/error/code", Ty::Uint { min: 1, max: 255 }, true)] };

/// The Welcome (format 11.2). Its records are read by the records' reader,
/// the keys statements and the credentials by theirs.
pub static WELCOME: Table = Table {
    shape: "welcome/shape",
    fields: &[
        f(1, "welcome/root", MEMBER_KEY, true),
        f(2, "welcome/records", Ty::Array { of: &ENV, max: 4096 }, true),
        f(3, "welcome/claim-ages", Ty::Set { of: &Ty::Age, max: 4096 }, false),
        f(4, "welcome/keys", Ty::Array { of: &ENV, max: 256 }, false),
        f(5, "welcome/time", MS, true),
        f(6, "welcome/grant", Ty::Map(&GRANT), false),
        f(7, "welcome/credentials", Ty::Array { of: &ENV, max: 259 }, false),
        f(8, "welcome/counted", Ty::Set { of: &B32, max: 16 }, false),
    ],
};

/// A leaf's first grant in a Welcome: the fields 2–5 of message `grant`
/// (format section 7), read by the grant's own reader.
pub static GRANT: Table = Table {
    shape: "welcome/grant/shape",
    fields: &[
        f(2, "welcome/grant", ENV, true),
        f(3, "welcome/grant", Ty::BytesUpTo(8192), true),
        f(4, "welcome/grant", Ty::Array { of: &B32, max: 8 }, false),
        f(5, "welcome/grant", Ty::Uint { min: 1, max: u32::MAX as u64 }, false),
    ],
};

// ---------------------------------------------------------------- invitation

/// The invitation (A-41 … A-46), the bytes of its text after `cbb://join#`.
/// Its reader (`crate::join::invitation`) adds the rules between fields:
/// which fields each kind of path has, home-only without a way from away,
/// guarded only for a leaf, settings only on a guest or bypass path.
pub static INVITE: Table = Table {
    shape: "invite/shape",
    fields: &[
        f(1, "invite/shape", ID16, true),
        f(2, "invite/shape", B32, true),
        f(3, "invite/path", Ty::Array { of: &Ty::Map(&PATH), max: 4 }, true),
        f(4, "invite/profile", Ty::Map(&PROFILE), true),
    ],
};

pub static PATH: Table = Table {
    shape: "invite/path/shape",
    fields: &[
        f(1, "invite/path", Ty::Uint { min: 1, max: 3 }, true),
        f(2, "invite/path", Ty::Once { of: &ADDR, max: 8 }, false),
        f(3, "invite/path", WG_KEY, false),
        f(4, "invite/path", B32, false),
        f(5, "invite/path", B32, false),
        f(6, "invite/obfuscation", Ty::Map(&OBFUSCATION), false),
    ],
};

pub static PROFILE: Table = Table {
    shape: "invite/profile/shape",
    fields: &[
        f(1, "invite/profile", Ty::Uint { min: 1, max: 4 }, true),
        f(2, "invite/profile", Ty::Uint { min: 1, max: 15 }, false),
        f(3, "invite/profile", Ty::Flag, false),
        f(4, "invite/profile", Ty::Flag, false),
    ],
};

// ---------------------------------------------------------------- hubs

/// The group's AmneziaWG settings, as a hub's offer gives them.
pub static OBFUSCATION: Table = Table {
    shape: "obfuscation/shape",
    fields: &[
        f(1, "obfuscation/jc", Ty::Uint { min: 1, max: 128 }, true),
        f(2, "obfuscation/jmin", Ty::Uint { min: 0, max: 1280 }, true),
        f(3, "obfuscation/jmax", Ty::Uint { min: 1, max: 1280 }, true),
        f(4, "obfuscation/s", Ty::Array { of: &Ty::Uint { min: 0, max: 64 }, max: 4 }, true),
        f(5, "obfuscation/h", Ty::Array { of: &Ty::Array { of: &U32, max: 2 }, max: 4 }, true),
        f(6, "obfuscation/key", B32, false),
    ],
};

/// The way to a hub's forwarder over VLESS with XHTTP.
pub static VLESS: Table = Table {
    shape: "vless/shape",
    fields: &[
        f(1, "vless/user", ID16, true),
        f(2, "vless/port", U16, false),
        f(3, "vless/host", Ty::Text(253), false),
        f(4, "vless/path", Ty::Text(128), false),
    ],
};

/// A hub's offer: in `result` field 6 to the device that sent `tunnel`, and
/// in `guest` to an invitation's guest. No pre-shared key: each device
/// exports its own from its connection with the hub (`crate::hubkey`), and
/// the offer confirms it with its tag. Field 5 (the hub, for an offer passed
/// on) is not used: offers are not passed between hubs (A-22).
pub static OFFER: Table = Table {
    shape: "offer/shape",
    fields: &[
        f(1, "offer/hub-key", WG_KEY, true),
        f(2, "offer/endpoints", Ty::Once { of: &ADDR, max: 8 }, false),
        f(3, "offer/obfuscation", Ty::Map(&OBFUSCATION), false),
        f(4, "offer/vless", Ty::Map(&VLESS), false),
        f(6, "offer/moved", Ty::Flag, false),
        f(7, "offer/next-key", WG_KEY, false),
        f(8, "offer/confirm", B32, false),
        f(9, "offer/endpoint-keys", Ty::Array { of: &Ty::Map(&ENDPOINT_KEY), max: 8 }, false),
    ],
};

/// The hub's own key on one endpoint of an offer: the key it serves
/// WireGuard under on that forwarder's endpoint (its key for that face).
/// An endpoint without one uses the offer's key (field 1).
pub static ENDPOINT_KEY: Table = Table {
    shape: "offer/endpoint-key/shape",
    fields: &[f(1, "offer/endpoint-key/endpoint", ADDR, true), f(2, "offer/endpoint-key/key", WG_KEY, true)],
};

/// `tunnel` (t 15): to a hub only, the device's WireGuard key toward it and
/// the confirmation tag of this connection's pre-shared key.
pub static TUNNEL: Table =
    Table { shape: "tunnel/shape", fields: &[f(2, "tunnel/key", WG_KEY, true), f(3, "tunnel/confirm", B32, true)] };

/// `hubs` (t 16): what a hub tells the group's other hubs: that it serves
/// or stopped. No clients and no offers (A-22: a device uses only hubs it
/// met); fields 4 and 5 stay unused.
pub static HUBS: Table = Table {
    shape: "hubs/shape",
    fields: &[f(2, "hubs/stopped", Ty::Flag, false), f(3, "hubs/serving", Ty::Flag, false)],
};

/// `guest` ops (field 2 of message `guest`).
pub const GUEST_OPEN: u64 = 1;
pub const GUEST_OPENED: u64 = 2;
pub const GUEST_REFUSED: u64 = 3;
pub const GUEST_DATA: u64 = 4;
pub const GUEST_END: u64 = 5;
pub const GUEST_ADMITTED: u64 = 6;
pub const GUEST_CLOSE: u64 = 7;

/// `guest` (t 17): an admin and a hub about an invitation's guest, named by
/// the guest's WireGuard key.
pub static GUEST: Table = Table {
    shape: "guest/shape",
    fields: &[
        f(2, "guest/op", Ty::Uint { min: 1, max: 7 }, true),
        f(3, "guest/key", WG_KEY, true),
        f(4, "guest/psk", B32, false),
        f(5, "guest/expires", MS, false),
        f(6, "guest/offer", Ty::Map(&OFFER), false),
        f(7, "guest/reason", REASON, false),
        f(8, "guest/conn", Ty::Uint { min: 1, max: u32::MAX as u64 }, false),
        f(9, "guest/data", Ty::BytesUpTo(16384), false),
        f(10, "guest/device", ID16, false),
        f(11, "guest/invite", ID16, false),
    ],
};

/// `credentials` (t 11), between members: the current period's credentials,
/// and in field 3 room for the group's AmneziaWG settings to change with
/// the period in a later version. Only members get this message, so a
/// server never sees the settings. No 0.6 writer sets field 3; a 0.6
/// reader checks its shape and does not apply it.
pub static CREDENTIALS: Table = Table {
    shape: "member-credentials/shape",
    fields: &[
        f(2, "member-credentials/list", Ty::Array { of: &ENV, max: 259 }, true),
        f(3, "member-credentials/obfuscation", Ty::Map(&OBFUSCATION), false),
    ],
};

// ---------------------------------------------------------------- waiting

/// One request that waits for an admin (A-49).
pub static REQUEST: Table = Table {
    shape: "waiting/request/shape",
    fields: &[
        f(1, "waiting/request/invite", ID16, true),
        f(2, "waiting/request/key", MEMBER_KEY, true),
        f(3, "waiting/request/info", Ty::Map(&INFO), true),
        f(4, "waiting/request/network", Ty::Uint { min: 1, max: 3 }, true),
        f(5, "waiting/request/held", Ty::Uint { min: 1, max: 86_400_000 }, false),
        f(6, "waiting/request/attempts", Ty::Uint { min: 1, max: 255 }, true),
    ],
};

/// The joiner's Info (format 11.2), as a request carries it.
pub static INFO: Table = Table {
    shape: "pair/info/shape",
    fields: &[
        f(1, "pair/info/name", TEXT64, true),
        f(2, "pair/info/os", Ty::Uint { min: 1, max: u32::MAX as u64 }, false),
        f(3, "pair/info/caps", Ty::Uint { min: 1, max: 7 }, false),
        f(4, "pair/info/role", Ty::Uint { min: 1, max: 4 }, true),
        f(5, "pair/info/admin", MEMBER_KEY, false),
        f(6, "pair/info/admin-pop", Ty::Bytes(64), false),
        f(7, "pair/info/keys", ENV, false),
        f(8, "pair/info/device", Ty::Map(&INFO_DEVICE), false),
        f(9, "pair/info/invite", ID16, false),
    ],
};

/// The hello's `device` map in an Info: a map; its fields are the hello's,
/// read by the hello's reader.
pub static INFO_DEVICE: Table = Table { shape: "pair/info/device/shape", fields: &[] };

/// `waiting` (t 26): from the device that holds requests (a hub of the
/// group, the one a joiner reached) to an admin that may admit: who knocked
/// while no admin was there.
pub static WAITING: Table = Table {
    shape: "waiting/shape",
    fields: &[f(2, "waiting/requests", Ty::Once { of: &Ty::Map(&REQUEST), max: 16 }, true)],
};

/// `dismiss` (t 27): from that admin to the holder: drop the requests of
/// this invitation, or of this key.
pub static DISMISS: Table =
    Table { shape: "dismiss/shape", fields: &[f(2, "dismiss/invite", ID16, true), f(3, "dismiss/key", B32, false)] };

// ---------------------------------------------------------------- servers

/// Forwarder: 80 challenge, 81 register, 82 registered, 83 error, 84 seen.
pub static FWD_CHALLENGE: Table =
    Table { shape: "forward/challenge/shape", fields: &[f(2, "forward/challenge/e", B32, true)] };
pub static FWD_REGISTER: Table = Table {
    shape: "forward/register/shape",
    fields: &[
        f(2, "forward/register/key", WG_KEY, true),
        f(3, "forward/register/proof", B32, true),
        f(4, "forward/register/obfuscation", Ty::Map(&OBFUSCATION), false),
        f(5, "forward/register/vless", ID16, false),
        f(6, "forward/register/credentials", Ty::Array { of: &ENV, max: 3 }, true),
    ],
};
pub static FWD_REGISTERED: Table = Table {
    shape: "forward/registered/shape",
    fields: &[
        f(2, "forward/registered/id", Ty::Uint { min: 1, max: (1 << 63) - 1 }, true),
        f(3, "forward/registered/mask", B32, true),
        f(4, "forward/registered/vless", Ty::Map(&VLESS), false),
    ],
};
pub static SERVER_ERROR: Table =
    Table { shape: "server/error/shape", fields: &[f(2, "server/error/reason", REASON, true)] };
pub static FWD_SEEN: Table = Table { shape: "forward/seen/shape", fields: &[f(2, "forward/seen/addr", ADDR, true)] };

/// Relay: 90 challenge, 91 register, 92 registered, 93 error; inside the
/// tunnel 94 watch, 95 dial, 96 answer, 97 online, 98 call, 99 ok.
pub static RELAY_CHALLENGE: Table = Table {
    shape: "relay/challenge/shape",
    fields: &[f(2, "relay/challenge/e", B32, true), f(3, "relay/challenge/root", Ty::Flag, false)],
};
pub static RELAY_REGISTER: Table = Table {
    shape: "relay/register/shape",
    fields: &[
        f(2, "relay/register/key", WG_KEY, true),
        f(3, "relay/register/proof", B32, true),
        f(4, "relay/register/credentials", Ty::Array { of: &ENV, max: 3 }, true),
        f(5, "relay/register/root", MEMBER_KEY, false),
    ],
};
pub static RELAY_REGISTERED: Table = Table {
    shape: "relay/registered/shape",
    fields: &[
        f(2, "relay/registered/key", WG_KEY, true),
        f(3, "relay/registered/psk", B32, true),
        f(4, "relay/registered/addr", Ty::Text(64), true),
    ],
};
pub static RELAY_WATCH: Table = Table { shape: "relay/watch/shape", fields: &[] };
/// A device's name on a relay is its pseudonym: the hash of its server key
/// for the period.
pub static RELAY_DIAL: Table = Table { shape: "relay/dial/shape", fields: &[f(2, "relay/dial/name", B32, true)] };
pub static RELAY_ANSWER: Table =
    Table { shape: "relay/answer/shape", fields: &[f(2, "relay/answer/ticket", ID16, true)] };
pub static RELAY_ONLINE: Table =
    Table { shape: "relay/online/shape", fields: &[f(2, "relay/online/names", Ty::Set { of: &B32, max: 64 }, false)] };
pub static RELAY_CALL: Table = Table {
    shape: "relay/call/shape",
    fields: &[f(2, "relay/call/name", B32, true), f(3, "relay/call/ticket", ID16, true)],
};
pub static RELAY_OK: Table = Table { shape: "relay/ok/shape", fields: &[] };

/// `result` (t 10), with the hub's offer in field 6.
pub static RESULT: Table = Table {
    shape: "result/shape",
    fields: &[
        f(2, "result/id", ID16, true),
        f(3, "result/by", ID16, true),
        f(4, "result/status", Ty::Uint { min: 1, max: 3 }, true),
        f(5, "result/reason", REASON, false),
        f(6, "result/tunnel", Ty::Map(&OFFER), false),
    ],
};

pub const T_RESULT: u64 = 10;
pub const T_CREDENTIALS: u64 = 11;
pub const T_TUNNEL: u64 = 15;
pub const T_HUBS: u64 = 16;
pub const T_GUEST: u64 = 17;
pub const T_WAITING: u64 = 26;
pub const T_DISMISS: u64 = 27;
pub const T_FWD_CHALLENGE: u64 = 80;
pub const T_FWD_REGISTER: u64 = 81;
pub const T_FWD_REGISTERED: u64 = 82;
pub const T_FWD_ERROR: u64 = 83;
pub const T_FWD_SEEN: u64 = 84;
pub const T_RELAY_CHALLENGE: u64 = 90;
pub const T_RELAY_REGISTER: u64 = 91;
pub const T_RELAY_REGISTERED: u64 = 92;
pub const T_RELAY_ERROR: u64 = 93;
pub const T_RELAY_WATCH: u64 = 94;
pub const T_RELAY_DIAL: u64 = 95;
pub const T_RELAY_ANSWER: u64 = 96;
pub const T_RELAY_ONLINE: u64 = 97;
pub const T_RELAY_CALL: u64 = 98;
pub const T_RELAY_OK: u64 = 99;

/// Every table, for the vectors and the format document.
pub static ALL: &[&Table] = &[
    &ADB,
    &PAIR_START,
    &PAIR_REPLY,
    &PAIR_CONFIRM,
    &PAIR_WELCOME,
    &PAIR_DONE,
    &PAIR_ERROR,
    &WELCOME,
    &GRANT,
    &INFO,
    &INFO_DEVICE,
    &INVITE,
    &PATH,
    &PROFILE,
    &OBFUSCATION,
    &VLESS,
    &OFFER,
    &ENDPOINT_KEY,
    &TUNNEL,
    &HUBS,
    &GUEST,
    &REQUEST,
    &WAITING,
    &DISMISS,
    &FWD_CHALLENGE,
    &FWD_REGISTER,
    &FWD_REGISTERED,
    &SERVER_ERROR,
    &FWD_SEEN,
    &RELAY_CHALLENGE,
    &RELAY_REGISTER,
    &RELAY_REGISTERED,
    &RELAY_WATCH,
    &RELAY_DIAL,
    &RELAY_ANSWER,
    &RELAY_ONLINE,
    &RELAY_CALL,
    &RELAY_OK,
    &RESULT,
    &CREDENTIALS,
];

/// The table of a message type wave 3 numbers.
pub fn of(t: u64) -> Option<&'static Table> {
    Some(match t {
        T_RESULT => &RESULT,
        T_CREDENTIALS => &CREDENTIALS,
        T_TUNNEL => &TUNNEL,
        T_HUBS => &HUBS,
        T_GUEST => &GUEST,
        T_WAITING => &WAITING,
        T_DISMISS => &DISMISS,
        64 => &PAIR_START,
        65 => &PAIR_REPLY,
        66 => &PAIR_CONFIRM,
        67 => &PAIR_WELCOME,
        68 => &PAIR_DONE,
        69 => &PAIR_ERROR,
        T_FWD_CHALLENGE => &FWD_CHALLENGE,
        T_FWD_REGISTER => &FWD_REGISTER,
        T_FWD_REGISTERED => &FWD_REGISTERED,
        T_FWD_ERROR | T_RELAY_ERROR => &SERVER_ERROR,
        T_FWD_SEEN => &FWD_SEEN,
        T_RELAY_CHALLENGE => &RELAY_CHALLENGE,
        T_RELAY_REGISTER => &RELAY_REGISTER,
        T_RELAY_REGISTERED => &RELAY_REGISTERED,
        T_RELAY_WATCH => &RELAY_WATCH,
        T_RELAY_DIAL => &RELAY_DIAL,
        T_RELAY_ANSWER => &RELAY_ANSWER,
        T_RELAY_ONLINE => &RELAY_ONLINE,
        T_RELAY_CALL => &RELAY_CALL,
        T_RELAY_OK => &RELAY_OK,
        _ => return None,
    })
}
