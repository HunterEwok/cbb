// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! What the apps show of the group (docs/apps.md, "What the member
//! shows"): the member keeps the user's order of the tiles and their
//! collections (`cbb_core::arrange`, docs/apps.md "Collections and the
//! order of the tiles") in `arrangement.json` in its state folder, and
//! answers `view` with the tiles ready to draw: this device and the
//! others, in that order and those collections, each with what the group
//! knows of it, and how many others are online. `arrange` changes the
//! order and answers the same. The view carries `warnings`: why this
//! device does not sync (`crate::why`). The arrangement stays on this device and is
//! never sent to the group.

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use cbb_core::arrange::{Arrangement, Item, Op};
use serde::Serialize;

use crate::control::Device;
use crate::error::{Error, Result};

/// The file the arrangement is kept in.
pub const FILE: &str = "arrangement.json";

/// A tile: a device, or a collection of devices.
#[derive(Serialize, Debug, Clone)]
#[serde(rename_all = "lowercase")]
pub enum Tile {
    Device(Box<Device>),
    Collection { id: String, name: String, devices: Vec<Device> },
}

/// What the apps draw.
#[derive(Serialize, Debug, Clone, Default)]
pub struct View {
    /// The tiles in the user's order, this device among them.
    pub tiles: Vec<Tile>,
    /// How many other devices of the group are online, and listed.
    pub online: usize,
    pub others: usize,
    /// The user changed the order, which `reset` undoes.
    pub custom: bool,
    /// Why this device does not sync (`cbb_core::why`, docs/apps.md "Why it
    /// does not sync"), the reason that stops the most first; the same as
    /// status's `why`, empty when everything syncs.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<cbb_core::why::Reason>,
}

/// The arrangement of one member, kept in its state folder.
pub struct Tiles {
    path: PathBuf,
    lock: Mutex<()>,
}

impl Tiles {
    pub fn new(state_dir: &Path) -> Tiles {
        Tiles { path: state_dir.join(FILE), lock: Mutex::new(()) }
    }

    fn load(&self, group: &str) -> Arrangement {
        let stored = std::fs::read(&self.path).ok().and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok());
        Arrangement::decode(stored.as_ref(), group)
    }

    fn keep(&self, a: &Arrangement) -> Result<()> {
        let data = serde_json::to_vec(a).map_err(|e| Error::msg(format!("cannot encode the arrangement: {e}")))?;
        crate::files::write_atomic(&self.path, &data, 0o600)
    }

    /// The view of the group's devices, as the member lists them, with op
    /// applied first when there is one; a change that does not fit is
    /// refused whole. Devices that left the group leave the arrangement.
    pub fn view(&self, group: &str, devices: Vec<Device>, op: Option<&Op>) -> Result<View> {
        let _held = self.lock.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let ids: Vec<String> = devices.iter().map(|d| d.id.clone()).collect();
        let me = devices.iter().find(|d| d.this).map(|d| d.id.clone());
        let mut a = self.load(group);
        let before = a.clone();
        a.prune(&ids);
        if let Some(op) = op {
            a.apply(op, &ids, me.as_deref()).map_err(|e| Error::msg(e.to_string()))?;
        }
        if a != before && (op.is_some() || self.path.exists()) {
            self.keep(&a)?;
        }
        Ok(build(&a, devices, me.as_deref()))
    }
}

/// The tiles of the arrangement for the devices.
pub fn build(a: &Arrangement, devices: Vec<Device>, me: Option<&str>) -> View {
    let ids: Vec<String> = devices.iter().map(|d| d.id.clone()).collect();
    let others: Vec<&Device> = devices.iter().filter(|d| !d.this).collect();
    let online = others.iter().filter(|d| d.online).count();
    let others = others.len();
    let find = |id: &str| devices.iter().find(|d| d.id == id).cloned();
    let tiles = a
        .view(&ids, me)
        .into_iter()
        .filter_map(|it| match it {
            Item::Device(id) => find(&id).map(|d| Tile::Device(Box::new(d))),
            Item::Collection(c) => Some(Tile::Collection {
                devices: c.devices.iter().filter_map(|d| find(d)).collect(),
                id: c.id,
                name: c.name,
            }),
        })
        .collect();
    View { tiles, online, others, custom: !a.items.is_empty(), warnings: Vec::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn device(id: &str, this: bool, online: bool) -> Device {
        Device { id: id.into(), name: id.to_uppercase(), this, online, listed: true, ..Default::default() }
    }

    fn ids(v: &View) -> Vec<String> {
        v.tiles
            .iter()
            .map(|t| match t {
                Tile::Device(d) => d.id.clone(),
                Tile::Collection { name, devices, .. } => {
                    format!("{name}[{}]", devices.iter().map(|d| d.id.as_str()).collect::<Vec<_>>().join(","))
                }
            })
            .collect()
    }

    #[test]
    fn keeps_the_users_order_and_drops_who_left() {
        let tmp = std::env::temp_dir().join(format!("cbb-view-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        struct Gone(PathBuf);
        impl Drop for Gone {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let _gone = Gone(tmp.clone());
        let t = Tiles::new(&tmp);
        let all = || {
            vec![
                device("s", true, true),
                device("a", false, true),
                device("b", false, false),
                device("c", false, false),
            ]
        };

        let v = t.view("G", all(), None).unwrap();
        assert_eq!(ids(&v), ["s", "a", "b", "c"]);
        assert_eq!((v.online, v.others, v.custom), (1, 3, false));
        assert!(!tmp.join(FILE).exists(), "nothing is written until the user arranges");

        let op: Op = serde_json::from_str(r#"{"op":"new","name":"Desk","devices":["b","c"]}"#).unwrap();
        let v = t.view("G", all(), Some(&op)).unwrap();
        assert_eq!(ids(&v), ["s", "a", "Desk[b,c]"]);
        assert!(v.custom);
        let op: Op = serde_json::from_str(r#"{"op":"move","item":{"device":"a"}}"#).unwrap();
        assert_eq!(ids(&t.view("G", all(), Some(&op)).unwrap()), ["s", "Desk[b,c]", "a"]);

        // A change that does not fit changes nothing.
        let op: Op = serde_json::from_str(r#"{"op":"rename","collection":"c9","name":"x"}"#).unwrap();
        assert!(t.view("G", all(), Some(&op)).is_err());
        assert_eq!(ids(&t.view("G", all(), None).unwrap()), ["s", "Desk[b,c]", "a"]);

        // c left the group: it leaves the arrangement too.
        let fewer = vec![device("s", true, true), device("a", false, true), device("b", false, false)];
        assert_eq!(ids(&t.view("G", fewer, None).unwrap()), ["s", "Desk[b]", "a"]);
        let kept: serde_json::Value = serde_json::from_slice(&std::fs::read(tmp.join(FILE)).unwrap()).unwrap();
        assert!(!kept.to_string().contains("\"c\""), "{kept}");

        // Another group starts fresh.
        assert_eq!(ids(&t.view("H", all(), None).unwrap()), ["s", "a", "b", "c"]);
    }

    #[test]
    fn bad_json_starts_fresh() {
        let tmp = std::env::temp_dir().join(format!("cbb-view-bad-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        std::fs::write(tmp.join(FILE), b"not json").unwrap();
        let t = Tiles::new(&tmp);
        let v = t.view("G", vec![device("s", true, true), device("a", false, false)], None).unwrap();
        let _ = std::fs::remove_dir_all(&tmp);
        assert_eq!(ids(&v), ["s", "a"]);
        assert!(!v.custom);
    }

    #[test]
    fn a_tile_carries_the_device() {
        let v = build(&Arrangement::empty("G"), vec![device("a", false, true), device("s", true, true)], Some("s"));
        let json = serde_json::to_value(&v).unwrap();
        assert_eq!(json["tiles"][0]["device"]["self"], true);
        assert_eq!(json["tiles"][1]["device"]["name"], "A");
        assert_eq!(json["online"], 1);
        assert!(json.get("warnings").is_none(), "no warnings when everything syncs");
        let reason = cbb_core::why::Reason {
            code: "sync_off".into(),
            level: cbb_core::why::Level::Stop,
            until_ms: 0,
            device: String::new(),
            devices: Vec::new(),
            value: String::new(),
            detail: String::new(),
        };
        let json = serde_json::to_value(View { warnings: vec![reason], ..v }).unwrap();
        assert_eq!(
            (json["warnings"][0]["code"].as_str(), json["warnings"][0]["level"].as_str()),
            (Some("sync_off"), Some("stop"))
        );
    }
}
