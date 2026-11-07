// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The frames of the member protocol (docs/protocol.md, section 4): a
//! 4-byte big-endian length and a JSON message.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::authority::Record;
use crate::certs::b64;
use crate::clip::{Event, Hello};
use crate::copy::Sealed;
use crate::error::{Context, Error, Result};

/// The largest frame.
pub const MAX_FRAME: usize = 7 << 20;

/// One message of the member protocol. The hello and the event are decoded
/// on their own, so an event this member cannot read, for example from a
/// newer version, is dropped without ending the connection.
#[derive(Clone, Serialize, Deserialize, Default, Debug)]
pub struct Message {
    #[serde(rename = "t", default)]
    pub kind: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub role: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hello: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event: Option<Value>,
    #[serde(with = "b64::opt", default, skip_serializing_if = "Option::is_none")]
    pub cert: Option<Vec<u8>>,
    #[serde(with = "b64::opt", default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<Vec<u8>>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub records: Vec<Record>,
    #[serde(with = "b64::opt", default, skip_serializing_if = "Option::is_none")]
    pub admin_ca: Option<Vec<u8>>,
    /// In a tunnel message, the group's hub's offer (section 11), decoded
    /// on its own with [`TunnelOffer`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tunnel: Option<Value>,
    /// In a command message, the signed command (section 15).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command: Option<Record>,
    /// In a result message, the answer to a command.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<CommandResult>,
    /// In an entries message, the signed entry points `{keys, entries}`
    /// (section 16, "Entry points"), decoded on their own.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entries: Option<Value>,
    /// In a reach message, the members a computer is connected to (section
    /// 4, "Reach"), kept as it came: the lite member shows no devices.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reach: Option<Value>,
    /// In a hubs message, what a hub shares with the group's other hubs
    /// (section 11, "Several hubs"), kept as it came.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hubs: Option<Value>,
    /// In a credentials message, the group's server credentials the sender
    /// keeps (section 18), kept as they came.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credentials: Option<Value>,
    /// In an evidence message, an attestation of one of the sender's keys
    /// (section 17, "Evidence"), kept as it came.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence: Option<Value>,
    /// In a get or missing message, a range of a copy's sealed blob
    /// ("Content" in section 4).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub get: Option<Get>,
}

/// A range of a copy's sealed blob, by its SHA-256 ("Content" in section
/// 4): length 1 to [`MAX_GET`] asks for it, 0 cancels every get of the blob.
#[derive(Serialize, Deserialize, Default, Debug, Clone, PartialEq)]
pub struct Get {
    #[serde(with = "b64")]
    pub sha256: Vec<u8>,
    #[serde(default)]
    pub offset: i64,
    #[serde(default)]
    pub length: i64,
}

/// The most bytes a get asks for.
pub const MAX_GET: i64 = 1 << 20;
/// The most data a chunk carries.
pub const MAX_CHUNK_DATA: usize = 256 << 10;
/// A chunk frame's size with its padding at most, its length word apart.
pub const MAX_CHUNK_FRAME: usize = 278_528;

impl Get {
    /// Whether it is a get a member may take: a hash of 32 bytes, an
    /// offset that is not negative, and a length of 0 (a cancel) to MAX_GET.
    pub fn valid(&self) -> bool {
        self.sha256.len() == 32 && self.offset >= 0 && (0..=MAX_GET).contains(&self.length)
    }
}

/// A get message, or with length 0 the cancel of every get of the blob.
pub fn get(g: Get) -> Message {
    Message { kind: "get".into(), get: Some(g), ..Default::default() }
}

/// A missing message: the answer to a get for a blob this member does not
/// hold whole.
pub fn missing(g: Get) -> Message {
    Message { kind: "missing".into(), get: Some(g), ..Default::default() }
}

/// The hello m with the features the sender supports beyond its protocol
/// version (`media`: it serves the content of media events).
pub fn with_features(mut m: Message, features: &[&str]) -> Message {
    if !features.is_empty()
        && let Some(Value::Object(h)) = m.hello.as_mut()
    {
        h.insert("features".into(), to_value(features));
    }
    m
}

/// The answer to a command (section 15): `done`, `refused` or `failed`, and
/// why for the last two.
#[derive(Serialize, Deserialize, Default, Debug, Clone, PartialEq)]
pub struct CommandResult {
    #[serde(default)]
    pub id: String,
    /// The receiver of the command, which names itself, so that a sender
    /// takes a result a member in between passed back only from it.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub by: String,
    #[serde(default)]
    pub status: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub reason: String,
    /// In the result of a hub command, the new hub's offer (section 11,
    /// "Moving the hub"), kept as it came, so a phone passes it back and
    /// its app reads it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tunnel: Option<Value>,
}

/// The content of a hello.
#[derive(Serialize, Deserialize, Default, Debug)]
pub struct HelloBody {
    #[serde(rename = "wall_ms", default)]
    pub wall: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current: Option<Value>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub records: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub name: String,
    /// The sender's operating system, as device records name it.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub os: String,
    /// What the sender says about its device, for showing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device: Option<Value>,
    /// The sender's WireGuard public key, for the group's hub (section 11);
    /// absent while sync away from home is off on it.
    #[serde(with = "b64::opt", default, skip_serializing_if = "Option::is_none")]
    pub tunnel_key: Option<Vec<u8>>,
    /// The sender's own preshared key, which every hub uses for it
    /// (section 11, "Several hubs").
    #[serde(with = "b64::opt", default, skip_serializing_if = "Option::is_none")]
    pub tunnel_psk: Option<Vec<u8>>,
    /// From a full member that is not an admin yet: the SubjectPublicKeyInfo
    /// of its admin key, which the root may certify (section 10, "Admins").
    #[serde(with = "b64::opt", default, skip_serializing_if = "Option::is_none")]
    pub admin_key: Option<Vec<u8>>,
    /// The sender's sync mode: own, shared, receive or send; shown, never
    /// trusted.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub mode: String,
    /// Whether the sender is muted, and for how many milliseconds more, 0
    /// for until the mute is lifted (design.md, "Muting a device"); shown,
    /// never trusted.
    #[serde(default, skip_serializing_if = "core::ops::Not::not")]
    pub muted: bool,
    #[serde(default, skip_serializing_if = "is_zero_i64")]
    pub muted_for_ms: i64,
    /// Where the sender says its keys live: `file` or `hardware`
    /// (section 17); shown, never trusted.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub key_store: String,
    /// The quick actions that are on at the sender, for the phones'
    /// buttons (section 15); shown, never trusted.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub actions: Vec<String>,
    /// The sender's public key for sealed messages (section 15, "Sealed
    /// commands"), which a root records in its device record.
    #[serde(with = "b64::opt", default, skip_serializing_if = "Option::is_none")]
    pub seal: Option<Vec<u8>>,
    /// The seq of the signed entry points the sender holds and of the
    /// keys.json they came with (section 16, "Entry points"); 0 for none.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub entries_seq: u64,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub entries_keys_seq: u64,
    /// What the sender supports beyond its protocol version: `media` from
    /// one that serves the content of media events.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub features: Vec<String>,
}

fn is_zero(n: &u64) -> bool {
    *n == 0
}

fn is_zero_i64(n: &i64) -> bool {
    *n == 0
}

/// What a hello says about the sender's device (section 4, "Device"): its
/// form, its system's version, its own version and its network card's MAC
/// address. Shown, never trusted; any field may be empty.
#[derive(Serialize, Deserialize, Default, Debug, Clone, PartialEq)]
pub struct DeviceInfo {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub form: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub os_version: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub version: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub mac: String,
}

/// The forms a device may name, for its icon.
pub const FORMS: [&str; 12] =
    ["laptop", "desktop", "phone", "tablet", "tv", "board", "server", "router", "console", "watch", "retro", "other"];

impl DeviceInfo {
    /// The same without its invalid fields: an unknown form, a version
    /// longer than 32 bytes or with control characters, a MAC address other
    /// than six lowercase hex bytes with colons.
    pub fn cleaned(&self) -> DeviceInfo {
        let short =
            |s: &str| if s.len() <= 32 && !s.chars().any(char::is_control) { s.to_string() } else { String::new() };
        let mac_ok = self.mac.len() == 17
            && self.mac.split(':').count() == 6
            && self
                .mac
                .split(':')
                .all(|p| p.len() == 2 && p.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)));
        DeviceInfo {
            form: if FORMS.contains(&self.form.as_str()) { self.form.clone() } else { String::new() },
            os_version: short(&self.os_version),
            version: short(&self.version),
            mac: if mac_ok { self.mac.clone() } else { String::new() },
        }
    }

    /// Whether it says nothing.
    pub fn is_empty(&self) -> bool {
        *self == DeviceInfo::default()
    }

    /// The device of a hello's body, cleaned; empty when it has none or it
    /// does not decode.
    pub fn of(body: &HelloBody) -> DeviceInfo {
        body.device
            .as_ref()
            .and_then(|v| serde_json::from_value::<DeviceInfo>(v.clone()).ok())
            .map(|d| d.cleaned())
            .unwrap_or_default()
    }
}

/// The group's hub's offer for a member's tunnel key (section 11).
#[derive(Serialize, Deserialize, Default, Debug, Clone, PartialEq)]
pub struct TunnelOffer {
    #[serde(with = "b64")]
    pub hub_key: Vec<u8>,
    #[serde(with = "b64")]
    pub psk: Vec<u8>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub endpoints: Vec<String>,
    /// AmneziaWG's settings, when the hub's tunnel is obfuscated.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub obfuscation: Option<Value>,
    /// The way to the hub's forwarder over VLESS, then the only way.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vless: Option<Value>,
    /// In an offer a hub passes on, the hub it is for: another of the
    /// group's hubs, or the new hub when the sender hands the hub over
    /// (section 11, "Several hubs" and "Moving the hub").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hub: Option<String>,
    /// In an offer passed on, that the sender is no hub any more.
    #[serde(default, skip_serializing_if = "core::ops::Not::not")]
    pub moved: bool,
    /// The key the hub serves with in the next period, which the member
    /// tries after `hub_key` (section 11, "The hub's key"); empty for none.
    #[serde(with = "b64", default, skip_serializing_if = "Vec::is_empty")]
    pub next_key: Vec<u8>,
}

/// The roles a peer may claim.
pub fn known_role(r: &str) -> bool {
    matches!(r, "full" | "phone" | "lite")
}

/// A hello message from a lite member running on `os` (`"linux"`, or
/// `"none"` for firmware) with what it says about its device, with its
/// tunnel key and its own preshared key while sync away from home is on,
/// the quick actions that are on there, and where its keys live:
/// `"file"`, or `"rootless"` for a rootless install (docs/protocol.md,
/// section 17), and the keys.json and entries.json seqs of the entry points
/// it holds, (0, 0) for none.
#[allow(clippy::too_many_arguments)]
pub fn hello(
    h: &Hello,
    records: String,
    role: &str,
    name: &str,
    os: &str,
    device: &DeviceInfo,
    tunnel_key: Option<(&[u8], &[u8])>,
    mode: &str,
    mute: Option<i64>,
    actions: &[String],
    key_store: &str,
    seal: Option<&[u8]>,
    entries: (u64, u64),
    admin_key: Option<&[u8]>,
) -> Message {
    let device = device.cleaned();
    let body = HelloBody {
        wall: h.wall,
        // The current copy travels sealed, with its age as of now; a member
        // sends no copy in the open.
        current: h.current.as_ref().and_then(|e| {
            e.sealed.as_ref().map(|s| {
                let mut s = s.clone();
                s.age = e.age;
                to_value(&s)
            })
        }),
        records,
        name: name.to_string(),
        os: os.to_string(),
        device: if device.is_empty() { None } else { Some(to_value(&device)) },
        tunnel_key: tunnel_key.map(|(k, _)| k.to_vec()),
        tunnel_psk: tunnel_key.map(|(_, p)| p.to_vec()),
        admin_key: admin_key.map(<[u8]>::to_vec),
        mode: mode.to_string(),
        muted: mute.is_some(),
        muted_for_ms: mute.unwrap_or(0),
        // The lite member keeps its keys in a file, or in the ESP32's
        // flash: "file", or "rootless" for a rootless install (D-79); a
        // phone's app that runs it, in its secure hardware: "hardware".
        key_store: key_store.into(),
        actions: actions.to_vec(),
        seal: seal.map(<[u8]>::to_vec),
        entries_seq: entries.1,
        entries_keys_seq: if entries.1 == 0 { 0 } else { entries.0 },
        features: Vec::new(),
    };
    Message { kind: "hello".into(), role: role.into(), hello: Some(to_value(&body)), ..Default::default() }
}

/// A message part as JSON. The parts are plain structs of strings, numbers
/// and lists, which serde_json always encodes.
#[allow(clippy::expect_used, reason = "plain structs always encode")]
fn to_value<T: Serialize + ?Sized>(v: &T) -> serde_json::Value {
    serde_json::to_value(v).expect("a plain struct encodes")
}

/// The result message that answers a command.
pub fn result(r: CommandResult) -> Message {
    Message { kind: "result".into(), result: Some(r), ..Default::default() }
}

/// An event message: the copy as it travels, sealed (docs/protocol.md,
/// section 4).
pub fn event(s: &Sealed) -> Message {
    Message { kind: "event".into(), event: Some(to_value(s)), ..Default::default() }
}

/// An entries message, which passes the signed entry points on.
pub fn entries(set: &Value) -> Message {
    Message { kind: "entries".into(), entries: Some(set.clone()), ..Default::default() }
}

/// A command message: a command an admin signed for its receiver
/// (section 15), which a member in between passes on unchanged.
pub fn command(r: &Record) -> Message {
    Message { kind: "command".into(), command: Some(r.clone()), ..Default::default() }
}

/// A cert message: a renewed member certificate for the receiver and the
/// admin CA that issued it, None when a root did.
pub fn cert(cert: &[u8], issuer: Option<&[u8]>) -> Message {
    Message { kind: "cert".into(), cert: Some(cert.to_vec()), issuer: issuer.map(<[u8]>::to_vec), ..Default::default() }
}

/// An admin message: the receiver's admin CA, for the admin key its hello
/// offered (section 10, "Admins").
pub fn admin(ca: &[u8]) -> Message {
    Message { kind: "admin".into(), admin_ca: Some(ca.to_vec()), ..Default::default() }
}

/// A tunnel message: the group's hub's offer for the receiver's tunnel key
/// (section 11).
pub fn tunnel(offer: &Value) -> Message {
    Message { kind: "tunnel".into(), tunnel: Some(offer.clone()), ..Default::default() }
}

/// A hubs message: what a hub shares with the group's other hubs (section
/// 11, "Several hubs").
pub fn hubs(share: &Value) -> Message {
    Message { kind: "hubs".into(), hubs: Some(share.clone()), ..Default::default() }
}

/// A credentials message: the group's server credentials the sender keeps
/// (section 18).
pub fn credentials(list: &Value) -> Message {
    Message { kind: "credentials".into(), credentials: Some(list.clone()), ..Default::default() }
}

/// An evidence message: an attestation of one of the sender's keys
/// (section 17, "Evidence").
pub fn evidence(e: &Value) -> Message {
    Message { kind: "evidence".into(), evidence: Some(e.clone()), ..Default::default() }
}

/// A message with only its type, such as a ping or a goodbye.
pub fn bare(kind: &str) -> Message {
    Message { kind: kind.into(), ..Default::default() }
}

/// Decodes the body of a frame. A number that is not an integer as in a
/// signed body makes it no message (strict::integers_only).
pub fn decode(body: &[u8]) -> Result<Message> {
    crate::strict::integers_only(body).map_err(|_| Error::msg("a frame is not a message"))?;
    serde_json::from_slice(body).context("a frame is not a message")
}

/// Decodes a hello and returns the rest of it as it came, its current copy
/// as the engine's unread event of the sealed copy, which the member checks
/// and opens. A current copy that does not decode, for example from a newer
/// version, counts as none.
pub fn decode_hello(v: Option<&Value>) -> Result<(Hello, HelloBody)> {
    let v = v.filter(|v| v.is_object()).ok_or_else(|| Error::msg("the hello does not decode"))?;
    let b: HelloBody = serde_json::from_value(v.clone()).context("the hello does not decode")?;
    let current = b
        .current
        .as_ref()
        .filter(|c| !c.is_null())
        .and_then(|c| serde_json::from_value::<Sealed>(c.clone()).ok())
        .map(Event::of);
    Ok((Hello { wall: b.wall, current }, b))
}

/// Encodes a message as a frame.
pub fn frame(m: &Message) -> Result<Vec<u8>> {
    let data = serde_json::to_vec(m).context("cannot encode a message")?;
    if data.len() > MAX_FRAME {
        return Err(Error::msg("the message is too large"));
    }
    let mut out = Vec::with_capacity(data.len().saturating_add(4));
    out.extend_from_slice(&(data.len() as u32).to_be_bytes());
    out.extend_from_slice(&data);
    Ok(out)
}

/// Encodes v as a frame of at most max bytes of JSON.
pub fn json_frame<T: Serialize>(v: &T, max: usize) -> Result<Vec<u8>> {
    let data = serde_json::to_vec(v).context("cannot encode a frame")?;
    if data.len() > max {
        return Err(Error::msg("the frame is too large"));
    }
    let mut out = (data.len() as u32).to_be_bytes().to_vec();
    out.extend_from_slice(&data);
    Ok(out)
}

/// Reads the length of a frame from its first four bytes, and checks that
/// it is at most max.
pub fn frame_len(head: [u8; 4], max: usize) -> Result<usize> {
    let size = u32::from_be_bytes(head) as usize;
    if size > max {
        return Err(Error::msg(format!("a frame of {size} bytes is too large")));
    }
    Ok(size)
}

#[cfg(test)]
mod tests {
    use super::{CommandResult, decode};

    /// A hub command's result keeps the new hub's offer, so a phone that
    /// passes it back, and its app, read it (section 11, "Moving the hub").
    #[test]
    fn a_result_keeps_its_tunnel() {
        let m = decode(br#"{"t":"result","result":{"id":"c","status":"done","tunnel":{"hub_key":"x"}}}"#).unwrap();
        let r: CommandResult = m.result.unwrap();
        assert_eq!(r.tunnel.as_ref().and_then(|t| t["hub_key"].as_str()), Some("x"));
        let again = serde_json::to_value(&r).unwrap();
        assert_eq!(again["tunnel"]["hub_key"], "x");
        assert!(serde_json::to_value(CommandResult::default()).unwrap().get("tunnel").is_none());
    }
}
