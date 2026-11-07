// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! Commands (docs/protocol.md, section 15), as their receiver reads them,
//! and the names, systems and key stores that device records and commands
//! share. Whether a command counts for a member is the record set's to say
//! (`crate::group::Records::verify_command`).

use alloc::collections::BTreeSet;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use serde::{Deserialize, Serialize};

use crate::certs::{self, b64};
use crate::error::{Context, Error, Result};

/// The version of a command's body.
const VERSION: i64 = 1;
/// The version of a command whose orders are sealed to the receiver
/// (docs/protocol.md, section 15, "Sealed commands").
const SEALED_VERSION: i64 = 2;
/// The most bytes of a command's body: a hub command carries up to 256
/// clients' keys.
const MAX_COMMAND_BODY: usize = 64 << 10;
/// A paste command's body may be larger: it carries up to 1 MiB of text.
const MAX_PASTE_BODY: usize = 2 << 20;
/// The longest text of a paste command, and of one typed key by key.
pub const MAX_PASTE_TEXT: usize = 1 << 20;
pub const MAX_TYPE_TEXT: usize = 4 << 10;
/// The most addresses and clients a hub command gives, as Go's.
const MAX_HUB_ENDPOINTS: usize = 8;
const MAX_HUB_CLIENTS: usize = 256;
/// How long a command lives at most after it was signed.
pub const COMMAND_LIFETIME_MS: i64 = 30_000;
/// How far ahead of the receiver's clock a command's time may be.
pub const COMMAND_AHEAD_MS: i64 = 60_000;
/// The longest mute a command gives, 30 days, as Go's MaxMute.
pub const MAX_MUTE_MS: i64 = 30 * 24 * 3600 * 1000;

/// A command (docs/protocol.md, section 15), as its receiver checked it.
#[derive(Serialize, Deserialize, Default, Clone, Debug)]
pub struct Command {
    #[serde(default)]
    v: i64,
    /// `mode`, `hub`, `paste`, `paste-off`, `action`, `actions-off`,
    /// `away-off`, `mute` or `unmute`.
    #[serde(rename = "type", default)]
    pub kind: String,
    #[serde(default)]
    pub group: String,
    /// The signer's device ID, for showing.
    #[serde(default)]
    pub by: String,
    #[serde(default)]
    pub to: String,
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub time_ms: i64,
    #[serde(default)]
    pub expires_ms: i64,
    /// In a mode command, the mode; not checked against the known modes
    /// here. In a paste command, `paste` or `type`.
    #[serde(default)]
    pub mode: String,
    /// In a hub command, the order.
    #[serde(default)]
    pub hub: Option<serde_json::Value>,
    /// In a paste command: press Enter after the text.
    #[serde(default)]
    pub enter: bool,
    /// In a paste command: `text` or `secret`.
    #[serde(rename = "kind", default)]
    pub paste_kind: String,
    /// In a paste command: the text.
    #[serde(default)]
    pub text: String,
    /// In an action command: the name of the action, which the receiver
    /// defines.
    #[serde(default)]
    pub action: String,
    /// In a mute command: how long, up to [`MAX_MUTE_MS`]; 0 for until an
    /// unmute command or the device's user lifts it.
    #[serde(default)]
    pub for_ms: i64,
    /// In a command of version 2, the orders above sealed to the
    /// receiver's key; [`Command::open`] opens them.
    #[serde(with = "b64", default)]
    sealed: Vec<u8>,
    /// Whether [`Command::open`] took the orders out of the sealed part.
    #[serde(skip)]
    pub opened: bool,
}

/// The orders a sealed command seals: all of a command but its header.
#[derive(Deserialize)]
struct Orders {
    #[serde(default)]
    mode: String,
    #[serde(default)]
    hub: Option<serde_json::Value>,
    #[serde(default)]
    enter: bool,
    #[serde(default)]
    kind: String,
    #[serde(default)]
    text: String,
    #[serde(default)]
    action: String,
    #[serde(default)]
    for_ms: i64,
}

/// The longest name of a quick action.
pub const MAX_ACTION_NAME: usize = 32;

/// Whether name may name a quick action, as Go's ValidActionName: 1 to
/// MAX_ACTION_NAME of a-z, 0-9 and -, starting with a letter.
/// Whether a watch's admin key may sign a command of type `kind`, as Go's
/// WatchCommand (docs/protocol.md, section 10, "Watches"): one that turns
/// remote paste, the quick actions or sync away from home off, or that runs
/// a quick action.
pub fn watch_command(kind: &str) -> bool {
    matches!(kind, "paste-off" | "actions-off" | "away-off" | "action")
}

pub fn valid_action_name(name: &str) -> bool {
    let b = name.as_bytes();
    b.len() <= MAX_ACTION_NAME
        && b.first().is_some_and(u8::is_ascii_lowercase)
        && b.iter().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-')
}

impl Command {
    /// Reads and checks a command's body, in the strict form of signed
    /// bodies.
    pub(crate) fn parse(data: &[u8]) -> Result<Command> {
        if data.len() > MAX_PASTE_BODY {
            return Err(Error::msg("the command is too large"));
        }
        crate::strict::check(data, COMMAND_FIELDS)?;
        let body: Command = serde_json::from_slice(data).context("a command does not decode")?;
        if data.len() > body.max_body() {
            return Err(Error::msg("the command is too large"));
        }
        body.check()?;
        Ok(body)
    }

    fn max_body(&self) -> usize {
        if self.kind == "paste" { MAX_PASTE_BODY } else { MAX_COMMAND_BODY }
    }

    /// A sealed command's associated data, as Go's: its open header, each
    /// string with its length before it (4 bytes, big-endian) and each
    /// time in 8 bytes, big-endian, after the context.
    fn aad(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for f in ["cbb command v2", &self.kind, &self.group, &self.by, &self.to, &self.id] {
            out.extend_from_slice(&u32::try_from(f.len()).unwrap_or(u32::MAX).to_be_bytes());
            out.extend_from_slice(f.as_bytes());
        }
        out.extend_from_slice(&self.time_ms.to_be_bytes());
        out.extend_from_slice(&self.expires_ms.to_be_bytes());
        out
    }

    /// Takes the orders of a sealed command out of its sealed part with
    /// `secret`, this member's secret for sealed messages, and checks them
    /// as those of a command in the open, as Go's CommandBody.Open. A
    /// command in the open stays as it is.
    pub fn open(&mut self, secret: &[u8]) -> Result<()> {
        if self.v != SEALED_VERSION {
            return Ok(());
        }
        let plain = crate::seal::open(secret, &self.aad(), &self.sealed)
            .map_err(|_| Error::msg("the sealed command does not open with this device's key"))?;
        if plain.len() > self.max_body() {
            return Err(Error::msg("the command is too large"));
        }
        crate::strict::check(&plain, &[])?;
        let o: Orders = serde_json::from_slice(&plain).context("a sealed command's orders do not decode")?;
        let mut c = self.clone();
        c.v = VERSION;
        c.sealed = Vec::new();
        c.mode = o.mode;
        c.hub = o.hub;
        c.enter = o.enter;
        c.paste_kind = o.kind;
        c.text = o.text;
        c.action = o.action;
        c.for_ms = o.for_ms;
        c.check()?;
        c.v = SEALED_VERSION;
        c.opened = true;
        *self = c;
        Ok(())
    }

    /// Seals the orders of `body`, a command in the open, to `public`, the
    /// receiver's key for sealed messages, as Go's SealCommand: the body
    /// that comes back has the same header with `v` 2 and `sealed`, in the
    /// canonical form, for the sender to sign.
    pub fn seal_body(body: &[u8], public: &[u8]) -> Result<Vec<u8>> {
        Self::seal_body_with(body, public, |aad, plain| crate::seal::seal(public, aad, plain))
    }

    /// seal_body with the randomness drawn from seed: for tests only.
    #[doc(hidden)]
    pub fn seal_body_with_seed(body: &[u8], public: &[u8], seed: [u8; 32]) -> Result<Vec<u8>> {
        Self::seal_body_with(body, public, |aad, plain| crate::seal::seal_with_seed(public, aad, plain, seed))
    }

    fn seal_body_with(
        body: &[u8],
        public: &[u8],
        seal: impl FnOnce(&[u8], &[u8]) -> core::result::Result<Vec<u8>, Error>,
    ) -> Result<Vec<u8>> {
        let c = Self::parse(body)?;
        if c.v != VERSION {
            return Err(Error::msg("only a command in the open is sealed"));
        }
        crate::seal::check_public_key(public)?;
        let Ok(serde_json::Value::Object(mut header)) = serde_json::from_slice::<serde_json::Value>(body) else {
            return Err(Error::msg("a command does not decode"));
        };
        let mut orders = serde_json::Map::new();
        for k in ["mode", "hub", "enter", "kind", "text", "action", "for_ms"] {
            if let Some(v) = header.remove(k) {
                orders.insert(String::from(k), v);
            }
        }
        let mut plain = Vec::new();
        crate::strict::write_canonical(&mut plain, &serde_json::Value::Object(orders));
        if plain.len() > c.max_body() {
            return Err(Error::msg("the command is too large"));
        }
        let sealed = seal(&c.aad(), &plain)?;
        header.insert(String::from("v"), serde_json::Value::from(SEALED_VERSION));
        header.insert(
            String::from("sealed"),
            serde_json::Value::String(base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &sealed)),
        );
        let mut out = Vec::new();
        crate::strict::write_canonical(&mut out, &serde_json::Value::Object(header));
        if out.len() > c.max_body() {
            return Err(Error::msg("the command is too large"));
        }
        Ok(out)
    }

    /// Whether the command's orders are sealed and not yet opened.
    pub fn sealed(&self) -> bool {
        self.v == SEALED_VERSION && !self.opened
    }

    fn has_orders(&self) -> bool {
        !self.mode.is_empty()
            || self.hub.is_some()
            || self.enter
            || !self.paste_kind.is_empty()
            || !self.text.is_empty()
            || !self.action.is_empty()
            || self.for_ms != 0
    }

    fn check(&self) -> Result<()> {
        if self.v != VERSION && self.v != SEALED_VERSION {
            return Err(Error::msg(format!("unknown command version {}", self.v)));
        }
        if !certs::is_id(&self.id) {
            return Err(Error::msg("the command has no valid ID"));
        }
        if self.v == VERSION && !self.sealed.is_empty() {
            return Err(Error::msg("a command of version 1 carries a sealed part"));
        }
        if self.v == SEALED_VERSION {
            // Its orders are sealed: none of them in the open, and a type
            // they are checked for once opened.
            if self.sealed.is_empty() {
                return Err(Error::msg("a sealed command has no sealed part"));
            }
            if self.has_orders() {
                return Err(Error::msg("a sealed command carries orders in the open"));
            }
            if !matches!(
                self.kind.as_str(),
                "mode" | "hub" | "paste" | "paste-off" | "action" | "actions-off" | "away-off" | "mute" | "unmute"
            ) {
                return Err(Error::msg(format!("unknown command type {:?}", self.kind)));
            }
            return self.check_header();
        }
        let hub = self.hub.as_ref().is_some_and(|h| !h.is_null());
        let paste = self.enter || !self.paste_kind.is_empty() || !self.text.is_empty();
        if paste && self.kind != "paste" {
            return Err(Error::msg(format!("a {} command carries a paste", self.kind)));
        }
        if self.kind != "action" && !self.action.is_empty() {
            return Err(Error::msg(format!("a {} command names an action", self.kind)));
        }
        if self.kind != "mute" && self.for_ms != 0 {
            return Err(Error::msg(format!("a {} command gives a time", self.kind)));
        }
        match self.kind.as_str() {
            "mode" if self.mode.is_empty() || hub => return Err(Error::msg("a mode command names no mode")),
            "hub" if !hub || !self.mode.is_empty() => return Err(Error::msg("a hub command has no order")),
            "hub" if !self.hub_valid() => return Err(Error::msg("a hub command's order is not valid")),
            "paste-off" | "actions-off" | "away-off" | "unmute" if hub || !self.mode.is_empty() => {
                return Err(Error::msg(format!("a {} command carries an order", self.kind)));
            }
            "mute" if hub || !self.mode.is_empty() => return Err(Error::msg("a mute command carries an order")),
            "mute" if !(0..=MAX_MUTE_MS).contains(&self.for_ms) => {
                return Err(Error::msg(format!("a mute command's time is not from 0 to {MAX_MUTE_MS} ms")));
            }
            "action" if hub || !self.mode.is_empty() => {
                return Err(Error::msg("an action command carries an order"));
            }
            "action" if !valid_action_name(&self.action) => {
                return Err(Error::msg(format!(
                    "an action command's name {:?} is not 1 to {MAX_ACTION_NAME} of a-z, 0-9 and -, starting with a letter",
                    self.action
                )));
            }
            "paste" => self.check_paste(hub)?,
            "mode" | "hub" | "paste-off" | "action" | "actions-off" | "away-off" | "mute" | "unmute" => {}
            k => return Err(Error::msg(format!("unknown command type {k:?}"))),
        }
        self.check_header()
    }

    /// Checks a command's open header past its version and ID, as Go's
    /// checkHeader: the receiver and the signer's device, and the lifetime.
    fn check_header(&self) -> Result<()> {
        if !certs::is_id(&self.to) {
            return Err(Error::msg("the command names no valid device"));
        }
        if !certs::is_id(&self.by) {
            return Err(Error::msg("a command's by is not a device ID"));
        }
        // A time before 1970 is no signing time; from it the difference cannot overflow.
        if self.time_ms < 0
            || self.expires_ms <= self.time_ms
            || self.expires_ms.checked_sub(self.time_ms).is_none_or(|d| d > COMMAND_LIFETIME_MS)
        {
            return Err(Error::msg("the command's lifetime is not valid"));
        }
        Ok(())
    }

    /// Whether the hub order is valid, as Go's HubOrder.check: its members
    /// of the right types, the clients' keys base64 in its standard form, a
    /// forwarder with an address and a key or an address at least, at most
    /// 8 addresses and 256 clients, each client a device ID once with keys
    /// of 32 bytes; or an order to stop being a hub, `stop` and nothing else.
    fn hub_valid(&self) -> bool {
        let Some(h) = self.hub.as_ref() else { return true };
        let Ok(o) = serde_json::from_value::<HubOrder>(h.clone()) else { return false };
        if o.stop {
            return o.forwarder.is_none() && o.endpoints.is_empty() && o.clients.is_empty();
        }
        if o.forwarder.as_ref().is_some_and(|f| f.endpoint.is_empty() || f.key.is_empty())
            || (o.forwarder.is_none() && o.endpoints.is_empty())
            || o.endpoints.len() > MAX_HUB_ENDPOINTS
            || o.clients.len() > MAX_HUB_CLIENTS
        {
            return false;
        }
        let mut seen = BTreeSet::new();
        o.clients.iter().all(|c| {
            certs::is_id(&c.device) && seen.insert(c.device.as_str()) && c.key.len() == 32 && c.psk.len() == 32
        })
    }

    fn check_paste(&self, hub: bool) -> Result<()> {
        let limit = match self.mode.as_str() {
            "paste" => MAX_PASTE_TEXT,
            "type" => MAX_TYPE_TEXT,
            m => return Err(Error::msg(format!("a paste command's way {m:?} is not paste or type"))),
        };
        if hub {
            return Err(Error::msg("a paste command carries a hub order"));
        }
        if self.paste_kind != "text" && self.paste_kind != "secret" {
            return Err(Error::msg("a paste command's kind is not text or secret"));
        }
        if self.text.is_empty() {
            return Err(Error::msg("a paste command has no text"));
        }
        if self.text.len() > limit {
            return Err(Error::msg(format!("a paste command's text is longer than {limit} bytes")));
        }
        Ok(())
    }
}

/// A hub command's order, as Go's HubOrder reads it; only checked here.
#[derive(Deserialize)]
#[allow(dead_code)]
struct HubOrder {
    #[serde(default)]
    stop: bool,
    #[serde(default)]
    forwarder: Option<HubForwarder>,
    #[serde(default)]
    endpoints: Vec<String>,
    #[serde(default)]
    clients: Vec<HubClient>,
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct HubForwarder {
    #[serde(default)]
    endpoint: String,
    #[serde(default)]
    key: String,
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct HubClient {
    #[serde(default)]
    device: String,
    #[serde(with = "b64", default)]
    key: Vec<u8>,
    #[serde(with = "b64", default)]
    psk: Vec<u8>,
}

/// The members every command's body has.
const COMMAND_FIELDS: &[&str] = &["v", "type", "group", "by", "to", "id", "time_ms", "expires_ms"];

/// Whether `os` names an operating system that device records know.
pub fn valid_os(os: &str) -> bool {
    matches!(
        os,
        "linux" | "windows" | "macos" | "ios" | "android" | "aurora" | "sailfish" | "watchos" | "wearos" | "none"
    )
}

/// Where a device of role keeps its keys, as its record's store says, as
/// Go's StoreOf: a record without one is from before the field, when a
/// phone's keys were in hardware and every other device's in a file.
pub fn store_of<'a>(store: &'a str, role: &str) -> &'a str {
    match store {
        "file" | "hardware" | "proven" | "rootless" => store,
        _ if role == "phone" || role == "watch" => "hardware",
        _ => "file",
    }
}

/// Reports whether s is a device name: 1 to 64 bytes of UTF-8 without
/// control characters.
pub fn valid_name(s: &str) -> bool {
    !s.is_empty() && s.len() <= 64 && !s.chars().any(char::is_control)
}

#[cfg(test)]
#[path = "verdicts.rs"]
mod verdicts;
