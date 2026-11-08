// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The arrangement of the device tiles (docs/apps.md, "Collections and the
//! order of the tiles"): the user's own order and collections, kept in the
//! app's settings and never sent to the group. The twin of the tray app's
//! arrange.go and the kits' Arrangement.kt and Arrangement.swift, all
//! checked against testdata/arrangement/vectors.json; the Aurora app uses
//! it through the core's `arrange` call.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

/// The stored format's version.
pub const VERSION: i64 = 1;
/// At most so many collections.
pub const MAX_COLLECTIONS: usize = 32;
/// A collection's name has at most so many bytes.
pub const MAX_NAME: usize = 64;

/// A collection of devices.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Collection {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub devices: Vec<String>,
}

/// A device, or a collection of devices.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Item {
    Device(String),
    Collection(Collection),
}

/// A device or a collection, as an operation names it.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Ref {
    Device(String),
    Collection(String),
}

/// A change the user makes; see Arrangement::apply.
#[derive(Clone, Debug, Deserialize)]
#[serde(tag = "op", rename_all = "lowercase")]
pub enum Op {
    /// item before before, or at the end of its level.
    Move {
        item: Ref,
        #[serde(default)]
        before: Option<Ref>,
    },
    Into {
        device: String,
        collection: String,
    },
    Out {
        device: String,
    },
    New {
        name: String,
        #[serde(default)]
        devices: Vec<String>,
    },
    Rename {
        collection: String,
        name: String,
    },
    Ungroup {
        collection: String,
    },
    Reset,
}

/// The stored arrangement, as the settings keep it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Arrangement {
    pub v: i64,
    pub group: String,
    #[serde(default)]
    pub items: Vec<Item>,
}

fn refuse() -> Error {
    Error::msg("the arrangement cannot take that")
}

/// A collection's name trimmed, 1 to 64 bytes.
pub fn collection_name(s: &str) -> Result<String> {
    let t = s.trim();
    if t.is_empty() || t.len() > MAX_NAME {
        return Err(Error::msg(format!("a collection's name has 1 to {MAX_NAME} bytes")));
    }
    Ok(t.to_string())
}

impl Arrangement {
    /// A fresh arrangement for the group.
    pub fn empty(group: &str) -> Arrangement {
        Arrangement { v: VERSION, group: group.to_string(), items: Vec::new() }
    }

    /// The stored arrangement for the group: a fresh one when there is
    /// none, it does not read, or it was made for another group or by
    /// another version.
    pub fn decode(stored: Option<&serde_json::Value>, group: &str) -> Arrangement {
        match stored.and_then(|v| serde_json::from_value::<Arrangement>(v.clone()).ok()) {
            Some(a) if a.v == VERSION && a.group == group => a,
            _ => Arrangement::empty(group),
        }
    }

    /// What the app shows: the stored items in order without the devices
    /// that are not listed, collections without listed devices left out
    /// unless they were just made, then the listed devices that appear
    /// nowhere, in the order given. me, this device, is an item as the
    /// others are, first while the stored items do not place it.
    pub fn view(&self, devices: &[String], me: Option<&str>) -> Vec<Item> {
        let devices = self_first(devices, me);
        let listed: BTreeSet<&str> = devices.iter().map(String::as_str).collect();
        let mut seen: BTreeSet<String> = BTreeSet::new();
        let mut out = Vec::new();
        for it in &self.items {
            match it {
                Item::Device(d) => {
                    if listed.contains(d.as_str()) && seen.insert(d.clone()) {
                        out.push(it.clone());
                    }
                }
                Item::Collection(c) => {
                    let ds: Vec<String> = c
                        .devices
                        .iter()
                        .filter(|d| listed.contains(d.as_str()) && seen.insert((*d).clone()))
                        .cloned()
                        .collect();
                    if !ds.is_empty() || c.devices.is_empty() {
                        out.push(Item::Collection(Collection { devices: ds, ..c.clone() }));
                    }
                }
            }
        }
        for d in &devices {
            if listed.contains(d.as_str()) && seen.insert(d.clone()) {
                if Some(d.as_str()) == me {
                    out.insert(0, Item::Device(d.clone()));
                } else {
                    out.push(Item::Device(d.clone()));
                }
            }
        }
        out
    }

    /// Drops the devices that are not listed, and the collections that
    /// lose their last device that way; the app calls it only when the list
    /// is whole (the group loaded, this device in it).
    pub fn prune(&mut self, devices: &[String]) {
        let listed: BTreeSet<&str> = devices.iter().map(String::as_str).collect();
        self.items.retain_mut(|it| match it {
            Item::Device(d) => listed.contains(d.as_str()),
            Item::Collection(c) => {
                let empty = c.devices.is_empty();
                c.devices.retain(|d| listed.contains(d.as_str()));
                empty || !c.devices.is_empty()
            }
        });
    }

    /// Makes the change, on the arrangement as view shows it for devices;
    /// the stored items then hold the whole order. A change
    /// that does not fit fails and leaves the arrangement as it was.
    pub fn apply(&mut self, op: &Op, devices: &[String], me: Option<&str>) -> Result<()> {
        let mut shown: BTreeSet<String> = BTreeSet::new();
        for it in self.view(devices, me) {
            match it {
                Item::Device(d) => {
                    shown.insert(d);
                }
                Item::Collection(c) => shown.extend(c.devices),
            }
        }
        let mut w = Work { items: self.items.clone() };
        let devices = self_first(devices, me);
        for d in &devices {
            if shown.contains(d) && w.find(d).is_none() {
                if Some(d.as_str()) == me {
                    w.items.insert(0, Item::Device(d.clone()));
                } else {
                    w.items.push(Item::Device(d.clone()));
                }
            }
        }
        w.apply(op, &devices, &shown)?;
        self.items = w.items;
        Ok(())
    }
}

/// devices with me, this device, first: the group's order as the app shows
/// it.
fn self_first(devices: &[String], me: Option<&str>) -> Vec<String> {
    match me {
        Some(m) if devices.iter().any(|d| d == m) => {
            core::iter::once(m.to_string()).chain(devices.iter().filter(|d| d.as_str() != m).cloned()).collect()
        }
        _ => devices.to_vec(),
    }
}

struct Work {
    items: Vec<Item>,
}

impl Work {
    fn find(&self, d: &str) -> Option<usize> {
        self.items.iter().position(|it| match it {
            Item::Device(x) => x == d,
            Item::Collection(c) => c.devices.iter().any(|x| x == d),
        })
    }

    fn collection(&self, id: &str) -> Option<usize> {
        self.items.iter().position(|it| matches!(it, Item::Collection(c) if c.id == id))
    }

    fn coll(&mut self, i: usize) -> Result<&mut Collection> {
        match self.items.get_mut(i) {
            Some(Item::Collection(c)) => Ok(c),
            _ => Err(refuse()),
        }
    }

    /// Removes d from where it is; a collection it leaves empty goes away,
    /// unless it is keep.
    fn take(&mut self, d: &str, keep: Option<&str>) {
        self.items.retain_mut(|it| match it {
            Item::Device(x) => x != d,
            Item::Collection(c) => {
                if Some(c.id.as_str()) == keep || !c.devices.iter().any(|x| x == d) {
                    return true;
                }
                c.devices.retain(|x| x != d);
                !c.devices.is_empty()
            }
        });
    }

    fn new_id(&self) -> String {
        let mut n = 1usize;
        loop {
            let id = format!("c{n}");
            if self.collection(&id).is_none() {
                return id;
            }
            n = n.saturating_add(1);
        }
    }

    fn insert(&mut self, at: usize, it: Item) {
        let at = at.min(self.items.len());
        self.items.insert(at, it);
    }

    fn apply(&mut self, op: &Op, devices: &[String], shown: &BTreeSet<String>) -> Result<()> {
        match op {
            Op::Move { item, before } => self.mv(item, before.as_ref(), shown),
            Op::Into { device, collection } => {
                if !shown.contains(device) {
                    return Err(refuse());
                }
                let ci = self.collection(collection).ok_or_else(refuse)?;
                if self.coll(ci)?.devices.contains(device) {
                    return Ok(());
                }
                self.take(device, None);
                let i = self.collection(collection).ok_or_else(refuse)?;
                self.coll(i)?.devices.push(device.clone());
                Ok(())
            }
            Op::Out { device } => {
                let ci = self.find(device).ok_or_else(refuse)?;
                if !shown.contains(device) {
                    return Err(refuse());
                }
                let id = self.coll(ci)?.id.clone();
                self.take(device, None);
                let at = self.collection(&id).map_or(ci, |i| i.saturating_add(1));
                self.insert(at, Item::Device(device.clone()));
                Ok(())
            }
            Op::New { name, devices: ds } => {
                let name = collection_name(name)?;
                if self.items.iter().filter(|it| matches!(it, Item::Collection(_))).count() >= MAX_COLLECTIONS {
                    return Err(Error::msg(format!("at most {MAX_COLLECTIONS} collections")));
                }
                let mut list: Vec<String> = Vec::new();
                for d in ds {
                    if !shown.contains(d) || list.contains(d) {
                        return Err(refuse());
                    }
                    list.push(d.clone());
                }
                let at = match list.first() {
                    None => self.items.len(),
                    Some(d) => self.find(d).ok_or_else(refuse)?,
                };
                let id = self.new_id();
                self.insert(at, Item::Collection(Collection { id: id.clone(), name, devices: list.clone() }));
                for d in &list {
                    self.take(d, Some(&id));
                }
                Ok(())
            }
            Op::Rename { collection, name } => {
                let ci = self.collection(collection).ok_or_else(refuse)?;
                let name = collection_name(name)?;
                self.coll(ci)?.name = name;
                Ok(())
            }
            Op::Ungroup { collection } => {
                let ci = self.collection(collection).ok_or_else(refuse)?;
                let ds = core::mem::take(&mut self.coll(ci)?.devices);
                self.items.remove(ci);
                for (k, d) in ds.into_iter().enumerate() {
                    self.insert(ci.saturating_add(k), Item::Device(d));
                }
                Ok(())
            }
            Op::Reset => {
                self.reset(devices);
                Ok(())
            }
        }
    }

    fn mv(&mut self, item: &Ref, before: Option<&Ref>, shown: &BTreeSet<String>) -> Result<()> {
        match item {
            Ref::Device(d) => {
                let src = self.find(d).filter(|_| shown.contains(d)).ok_or_else(refuse)?;
                if before == Some(&Ref::Device(d.clone())) {
                    return Ok(());
                }
                let src_coll = match self.items.get(src) {
                    Some(Item::Collection(c)) => Some(c.id.clone()),
                    _ => None,
                };
                match before {
                    None => {
                        self.take(d, None);
                        match src_coll.and_then(|id| self.collection(&id)) {
                            Some(ci) => self.coll(ci)?.devices.push(d.clone()),
                            None => self.items.push(Item::Device(d.clone())),
                        }
                    }
                    Some(Ref::Collection(id)) => {
                        let mut at = self.collection(id).ok_or_else(refuse)?;
                        self.take(d, None);
                        // The collection may have gone with its last device:
                        // then the device stands where it was.
                        if let Some(i) = self.collection(id) {
                            at = i;
                        }
                        self.insert(at, Item::Device(d.clone()));
                    }
                    Some(Ref::Device(b)) => {
                        if !shown.contains(b) || self.find(b).is_none() {
                            return Err(refuse());
                        }
                        self.take(d, None);
                        let bi = self.find(b).ok_or_else(refuse)?;
                        match self.items.get_mut(bi) {
                            Some(Item::Collection(c)) => {
                                let k = c.devices.iter().position(|x| x == b).unwrap_or(0);
                                c.devices.insert(k, d.clone());
                            }
                            _ => self.insert(bi, Item::Device(d.clone())),
                        }
                    }
                }
                Ok(())
            }
            Ref::Collection(id) => {
                let ci = self.collection(id).ok_or_else(refuse)?;
                if before == Some(&Ref::Collection(id.clone())) {
                    return Ok(());
                }
                if let Some(b) = before {
                    let at = match b {
                        Ref::Collection(x) => self.collection(x),
                        Ref::Device(x) => self.find(x).filter(|_| shown.contains(x)),
                    };
                    at.ok_or_else(refuse)?;
                }
                let it = self.items.remove(ci);
                match before {
                    None => self.items.push(it),
                    Some(Ref::Collection(x)) => {
                        let at = self.collection(x).ok_or_else(refuse)?;
                        self.insert(at, it);
                    }
                    Some(Ref::Device(x)) => {
                        let at = self.find(x).ok_or_else(refuse)?;
                        self.insert(at, it);
                    }
                }
                Ok(())
            }
        }
    }

    fn reset(&mut self, devices: &[String]) {
        let rank: BTreeMap<&str, usize> = devices.iter().enumerate().map(|(i, d)| (d.as_str(), i)).collect();
        let by_rank = |x: &str, y: &str| match (rank.get(x), rank.get(y)) {
            (Some(a), Some(b)) => a.cmp(b),
            (Some(_), None) => core::cmp::Ordering::Less,
            (None, Some(_)) => core::cmp::Ordering::Greater,
            (None, None) => x.cmp(y),
        };
        for it in &mut self.items {
            if let Item::Collection(c) = it {
                c.devices.sort_by(|a, b| by_rank(a, b));
            }
        }
        fn first(it: &Item) -> Option<&str> {
            match it {
                Item::Device(d) => Some(d),
                Item::Collection(c) => c.devices.first().map(String::as_str),
            }
        }
        self.items.sort_by(|x, y| match (first(x), first(y)) {
            (None, None) => core::cmp::Ordering::Equal,
            (None, Some(_)) => core::cmp::Ordering::Greater,
            (Some(_), None) => core::cmp::Ordering::Less,
            (Some(a), Some(b)) => by_rank(a, b),
        });
    }
}

#[cfg(test)]
#[path = "arrange/tests.rs"]
mod tests;
