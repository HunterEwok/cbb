// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! A command of 0.6 as the service carries it out or an admin sends it:
//! its type and its orders (format section 6), read from and written to
//! the map the core seals (`cbb_core::commands::orders`). The core checks
//! the orders' rows before they reach this; reading only takes them apart.

use cbb_core::clip::Mode;
use cbb_core::commands::{
    COMMAND_ACTION, COMMAND_ACTIONS_OFF, COMMAND_AWAY_OFF, COMMAND_DEVICE, COMMAND_HUB, COMMAND_MODE, COMMAND_MUTE,
    COMMAND_PASTE, COMMAND_PASTE_OFF, COMMAND_UNMUTE, orders,
};
use cbb_core::format::cbor::{self, Value};

use crate::error::{Error, Result};

/// How a paste goes into the target.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Way {
    /// Through the clipboard and the paste keys.
    Paste,
    /// Typed out key by key.
    Type,
}

/// What a paste pastes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum What {
    Text(String),
    Secret(String),
    /// The group's copy of images or files with this ID.
    Media([u8; 16]),
}

/// A hub's orders (field 10, 11 or 13): the hub to use, the forwarders it
/// registers with, or stop.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct Hub {
    /// The hub to use: its endpoint and key.
    pub hub: Option<(String, [u8; 32])>,
    /// Up to eight forwarders, each its address and its pin, which the
    /// root signs here so that nobody takes a forwarder's key on first use.
    pub forwarders: Vec<(String, [u8; 32])>,
    /// Stop being a hub (alone).
    pub stop: bool,
}

/// A command's type with its orders.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Order {
    Mode(Mode),
    Hub(Hub),
    Paste {
        way: Way,
        enter: bool,
        what: What,
    },
    PasteOff,
    Action(String),
    ActionsOff,
    AwayOff,
    /// For so long, or None for until an unmute.
    Mute(Option<u64>),
    Unmute,
    /// A small device's own command: its name and its CBOR arguments.
    Device {
        name: String,
        args: Option<Vec<u8>>,
    },
}

fn uint(m: &Value<'_>, n: u16) -> Option<u64> {
    m.get(n).and_then(Value::as_uint)
}

fn text(m: &Value<'_>, n: u16) -> Option<String> {
    m.get(n).and_then(Value::as_text).map(str::to_string)
}

fn fixed<const N: usize>(v: &Value<'_>) -> Option<[u8; N]> {
    v.as_bytes().and_then(|b| b.try_into().ok())
}

impl Order {
    /// The command type.
    pub fn kind(&self) -> u64 {
        match self {
            Order::Mode(_) => COMMAND_MODE,
            Order::Hub(_) => COMMAND_HUB,
            Order::Paste { .. } => COMMAND_PASTE,
            Order::PasteOff => COMMAND_PASTE_OFF,
            Order::Action(_) => COMMAND_ACTION,
            Order::ActionsOff => COMMAND_ACTIONS_OFF,
            Order::AwayOff => COMMAND_AWAY_OFF,
            Order::Mute(_) => COMMAND_MUTE,
            Order::Unmute => COMMAND_UNMUTE,
            Order::Device { .. } => COMMAND_DEVICE,
        }
    }

    /// The command's name, as the log and the views show it.
    pub fn name(&self) -> &'static str {
        match self {
            Order::Mode(_) => "mode",
            Order::Hub(_) => "hub",
            Order::Paste { .. } => "paste",
            Order::PasteOff => "paste-off",
            Order::Action(_) => "action",
            Order::ActionsOff => "actions-off",
            Order::AwayOff => "away-off",
            Order::Mute(_) => "mute",
            Order::Unmute => "unmute",
            Order::Device { .. } => "device",
        }
    }

    /// The orders to seal, a map in the profile; None for a type that has
    /// none. Checked against the type's rows, as the receiver will.
    pub fn orders(&self) -> Result<Option<Vec<u8>>> {
        let mut f: Vec<(u16, Value<'_>)> = Vec::new();
        match self {
            Order::Mode(m) => f.push((10, Value::Uint(if *m == Mode::Own { 2 } else { 1 }))),
            Order::Hub(h) => {
                if h.stop {
                    f.push((13, Value::Uint(1)));
                } else {
                    if let Some((e, k)) = &h.hub {
                        f.push((10, Value::Array(vec![Value::Text(e), Value::Bytes(k)])));
                    }
                    if !h.forwarders.is_empty() {
                        let each =
                            h.forwarders.iter().map(|(a, pin)| Value::Array(vec![Value::Text(a), Value::Bytes(pin)]));
                        f.push((11, Value::Array(each.collect())));
                    }
                }
            }
            Order::Paste { way, enter, what } => {
                f.push((10, Value::Uint(if *way == Way::Type { 2 } else { 1 })));
                if *enter {
                    f.push((11, Value::Uint(1)));
                }
                match what {
                    What::Text(t) => f.extend([(12, Value::Uint(1)), (13, Value::Text(t))]),
                    What::Secret(t) => f.extend([(12, Value::Uint(2)), (13, Value::Text(t))]),
                    What::Media(id) => f.extend([(12, Value::Uint(3)), (14, Value::Bytes(id))]),
                }
            }
            Order::Action(a) => f.push((10, Value::Text(a))),
            Order::Mute(ms) => {
                if let Some(ms) = ms {
                    f.push((10, Value::Uint(*ms)));
                }
            }
            Order::Device { name, args } => {
                f.push((10, Value::Text(name)));
                if let Some(a) = args {
                    f.push((11, Value::Bytes(a)));
                }
            }
            Order::PasteOff | Order::ActionsOff | Order::AwayOff | Order::Unmute => return Ok(None),
        }
        let b = Value::Map(f).encode();
        orders::check(self.kind(), &b)
            .map_err(|r| Error::msg(format!("the {} command's orders break {r}", self.name())))?;
        Ok(Some(b))
    }

    /// Reads a command taken here: its type and its opened orders, which
    /// the core checked.
    pub fn read(kind: u64, orders: Option<&[u8]>) -> Result<Order> {
        let bad = || Error::msg(format!("the orders of command type {kind} do not read"));
        let m = match orders {
            Some(b) => Some(cbor::decode(b).map_err(|_| bad())?),
            None => None,
        };
        let need = || m.as_ref().ok_or_else(bad);
        Ok(match kind {
            COMMAND_MODE => Order::Mode(if uint(need()?, 10) == Some(2) { Mode::Own } else { Mode::Shared }),
            COMMAND_HUB => {
                let m = need()?;
                let pair = |v: &Value<'_>| match v.as_array() {
                    Some([Value::Text(e), k]) => fixed(k).map(|k| (e.to_string(), k)).ok_or_else(bad),
                    _ => Err(bad()),
                };
                let hub = m.get(10).map(pair).transpose()?;
                let forwarders = match m.get(11).map(Value::as_array) {
                    None => Vec::new(),
                    Some(Some(a)) => a.iter().map(pair).collect::<Result<_>>()?,
                    Some(None) => return Err(bad()),
                };
                Order::Hub(Hub { hub, forwarders, stop: uint(m, 13) == Some(1) })
            }
            COMMAND_PASTE => {
                let m = need()?;
                let what = match uint(m, 12) {
                    Some(1) => What::Text(text(m, 13).ok_or_else(bad)?),
                    Some(2) => What::Secret(text(m, 13).ok_or_else(bad)?),
                    Some(3) => What::Media(m.get(14).and_then(fixed).ok_or_else(bad)?),
                    _ => return Err(bad()),
                };
                Order::Paste {
                    way: if uint(m, 10) == Some(2) { Way::Type } else { Way::Paste },
                    enter: uint(m, 11) == Some(1),
                    what,
                }
            }
            COMMAND_PASTE_OFF => Order::PasteOff,
            COMMAND_ACTION => Order::Action(text(need()?, 10).ok_or_else(bad)?),
            COMMAND_ACTIONS_OFF => Order::ActionsOff,
            COMMAND_AWAY_OFF => Order::AwayOff,
            COMMAND_MUTE => Order::Mute(m.as_ref().and_then(|m| uint(m, 10))),
            COMMAND_UNMUTE => Order::Unmute,
            COMMAND_DEVICE => {
                let m = need()?;
                Order::Device {
                    name: text(m, 10).ok_or_else(bad)?,
                    args: m.get(11).and_then(Value::as_bytes).map(<[u8]>::to_vec),
                }
            }
            _ => return Err(Error::msg(format!("this device does not know command type {kind}"))),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_order_reads_back_as_written() {
        let all = [
            Order::Mode(Mode::Own),
            Order::Mode(Mode::Shared),
            Order::Hub(Hub { stop: true, ..Hub::default() }),
            Order::Hub(Hub {
                hub: Some(("10.0.0.2:7600".into(), [3; 32])),
                forwarders: vec![("fwd.example:443".into(), [4; 32]), ("[2001:db8::7]:8764".into(), [5; 32])],
                stop: false,
            }),
            Order::Paste { way: Way::Type, enter: true, what: What::Text("ls".into()) },
            Order::Paste { way: Way::Paste, enter: false, what: What::Secret("hunter2".into()) },
            Order::Paste { way: Way::Paste, enter: false, what: What::Media([9; 16]) },
            Order::PasteOff,
            Order::Action("lock-screen".into()),
            Order::ActionsOff,
            Order::AwayOff,
            Order::Mute(Some(60_000)),
            Order::Mute(None),
            Order::Unmute,
            Order::Device { name: "open".into(), args: Some(vec![0xa1, 0x01, 0x02]) },
        ];
        for o in all {
            let b = o.orders().unwrap();
            let back = Order::read(o.kind(), b.as_deref()).unwrap();
            assert_eq!(back, o);
        }
    }

    #[test]
    fn orders_the_receiver_would_refuse_are_not_written() {
        assert!(Order::Action("Lock Screen".into()).orders().is_err());
        assert!(Order::Mute(Some(0)).orders().is_err());
        assert!(Order::Paste { way: Way::Type, enter: false, what: What::Media([1; 16]) }.orders().is_err());
        assert!(Order::read(99, None).is_err());
    }
}
