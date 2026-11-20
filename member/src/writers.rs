// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The records a computer writes for the group as its root or one of its
//! admins, on the records of 0.6 (`cbb_core::records`): removing, freezing
//! and thawing a device, renaming it, the window for incoming copies, the
//! group's hubs and its settings. Each writer takes the set and the key
//! that signs and gives back the records it added, which the member keeps
//! and passes on (`Mesh::changed`). It stands where the admin of 0.5
//! (`admin`) stands until the service switches.

use cbb_core::identity::ExternalKey;
use cbb_core::records::body::{Device, Kind, RIGHT_HUB, Removal, Settings};
use cbb_core::records::eval::DeviceState;
use cbb_core::records::{DeviceId, Key, Record, RecordId, RecordSet, State};

use crate::error::{Error, Result};
use crate::own::Own;

/// The shortest prefix of a device ID in hex that names a device.
const MIN_PREFIX: usize = 4;

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// The key this device signs the group's records with: its root key while
/// it is the group's current root, else its admin key while a device of
/// the group that is not frozen holds it. None when it signs nothing.
pub fn signer<'a>(own: &'a Own, state: &State) -> Option<&'a dyn ExternalKey> {
    if let Some(root) = &own.root
        && state.roots.last() == Some(&Key::es256(root.public()).hash())
    {
        return Some(&**root);
    }
    let admin = own.admin.as_ref()?;
    let h = Key::es256(admin.public()).hash();
    state.devices.iter().any(|d| d.admin == Some(h) && !d.frozen).then_some(&**admin)
}

/// The device a person names: by its name (as written first, then in any
/// case), or by a prefix of its ID in hex of at least four digits; an error
/// when none or several fit.
pub fn find<'a>(state: &'a State, target: &str) -> Result<&'a DeviceState> {
    let t = target.trim();
    let mut by_name: Vec<&DeviceState> = state.devices.iter().filter(|d| d.name == t).collect();
    if by_name.is_empty() {
        by_name = state.devices.iter().filter(|d| d.name.eq_ignore_ascii_case(t)).collect();
    }
    let fits: Vec<&DeviceState> = if by_name.is_empty() && t.len() >= MIN_PREFIX {
        let lower = t.to_ascii_lowercase();
        state.devices.iter().filter(|d| hex(&d.id.0).starts_with(&lower)).collect()
    } else {
        by_name
    };
    match fits.as_slice() {
        [d] => Ok(d),
        [] => Err(Error::msg(format!("no device {t:?} in the group; cbb status lists them"))),
        _ => Err(Error::msg(format!(
            "several devices fit {t:?}; name one by its ID: {}",
            fits.iter().map(|d| hex(&d.id.0)).collect::<Vec<_>>().join(", ")
        ))),
    }
}

/// The device record that counts now for device id: the newest that the
/// state counts, as written.
fn device_record(set: &RecordSet, state: &State, id: &DeviceId) -> Option<Device> {
    set.ids()
        .filter(|rid| state.counting.contains(rid))
        .filter_map(|rid| set.get(rid))
        .filter_map(|r| match &r.body().kind {
            Kind::Device(d) if d.key.device_id() == *id => Some((r.body().time_ms, r.body().seq, (**d).clone())),
            _ => None,
        })
        .max_by_key(|(t, seq, _)| (*t, *seq))
        .map(|(_, _, d)| d)
}

/// The keys of a device that a removal or a freeze names: its member key,
/// and its admin key when it holds one.
fn keys_of(d: &DeviceState) -> Vec<cbb_core::records::KeyHash> {
    let mut keys = vec![d.key.hash()];
    keys.extend(d.admin);
    keys.sort();
    keys
}

/// Removes a device from the group: its keys count no more.
pub fn remove(
    set: &mut RecordSet,
    signer: &dyn ExternalKey,
    target: &str,
    now_ms: u64,
) -> Result<(DeviceState, Vec<Record>)> {
    let st = set.state();
    let d = find(&st, target)?.clone();
    if Some(d.id) == st.root_device {
        return Err(Error::msg("the root's device is not removed: the group changes its root instead"));
    }
    let keys = keys_of(&d);
    let out =
        if st.roots.last() == Some(&Key::es256(signer.public()).hash()) && keys.iter().any(|k| st.two_histories(k)) {
            set.write_removal(&st, signer, &keys, now_ms)
        } else {
            set.write_record(&st, signer, Kind::Revoke(Removal { keys, seen: Vec::new() }), now_ms)
        };
    Ok((d, out.map_err(|e| Error::msg(format!("cannot remove the device: {e}")))?))
}

/// The names of the devices whose keys signed two histories: none when
/// the group has no fork to resolve.
pub fn two_histories(state: &State) -> Vec<String> {
    state.devices.iter().filter(|d| keys_of(d).iter().any(|k| state.two_histories(k))).map(|d| d.name.clone()).collect()
}

/// Freezes a device (its keys sign nothing and it gets no copies until it
/// is thawed), or thaws it.
pub fn freeze(
    set: &mut RecordSet,
    signer: &dyn ExternalKey,
    target: &str,
    on: bool,
    now_ms: u64,
) -> Result<(DeviceState, Vec<Record>)> {
    let st = set.state();
    let d = find(&st, target)?.clone();
    if on == d.frozen {
        return Ok((d, Vec::new()));
    }
    let keys = keys_of(&d);
    let kind = if on {
        Kind::Freeze(Removal { keys, seen: Vec::new() })
    } else {
        // The freezes that hold it, as the state counts them.
        let ids: Vec<RecordId> = set
            .ids()
            .filter(|rid| st.counting.contains(rid))
            .filter(|rid| {
                set.get(rid).is_some_and(
                    |r| matches!(&r.body().kind, Kind::Freeze(rm) if rm.keys.iter().any(|k| keys.contains(k))),
                )
            })
            .copied()
            .collect();
        if ids.is_empty() {
            return Err(Error::msg("no freeze of this device counts: it is held by its group's stop"));
        }
        let mut ids = ids;
        ids.sort();
        Kind::Thaw { ids, seen: Vec::new() }
    };
    let out = set.write_record(&st, signer, kind, now_ms);
    Ok((d, out.map_err(|e| Error::msg(format!("cannot change the freeze: {e}")))?))
}

/// Whether a person may give a device this name: 1 to 64 bytes and no
/// control characters.
pub fn valid_name(s: &str) -> bool {
    cbb_core::join::info::valid_name(s)
}

/// Gives a device another name.
pub fn rename(
    set: &mut RecordSet,
    signer: &dyn ExternalKey,
    target: &str,
    name: &str,
    now_ms: u64,
) -> Result<(DeviceState, Vec<Record>)> {
    let name = name.trim();
    if !valid_name(name) {
        return Err(Error::msg("a device name has 1 to 64 characters and no control characters"));
    }
    let st = set.state();
    let d = find(&st, target)?.clone();
    // The same name signs nothing and still answers.
    if d.name == name {
        return Ok((d, Vec::new()));
    }
    if st.devices.iter().any(|o| o.id != d.id && o.name == name) {
        return Err(Error::msg(format!("another device is called {name}")));
    }
    let mut rec = device_record(set, &st, &d.id).ok_or_else(|| Error::msg("the device's record is not here"))?;
    rec.name = name.to_string();
    rec.seen = Vec::new();
    let out = set.write_record(&st, signer, Kind::device(rec), now_ms);
    Ok((d, out.map_err(|e| Error::msg(format!("cannot rename the device: {e}")))?))
}

/// Sets how long a copy from another device stays live on each member.
pub fn set_incoming(
    set: &mut RecordSet,
    signer: &dyn ExternalKey,
    incoming_ms: u64,
    now_ms: u64,
) -> Result<Vec<Record>> {
    let st = set.state();
    set.write_record(&st, signer, Kind::Copies { incoming_ms, seen: Vec::new() }, now_ms)
        .map_err(|e| Error::msg(format!("cannot set the window for incoming copies: {e}")))
}

/// Names the group's hubs, by the devices a person names, each with the
/// right to be a hub; none clears it.
pub fn set_hubs(set: &mut RecordSet, signer: &dyn ExternalKey, targets: &[String], now_ms: u64) -> Result<Vec<Record>> {
    let st = set.state();
    let mut hubs = Vec::with_capacity(targets.len());
    for t in targets {
        let d = find(&st, t)?;
        // Only a device whose record gives it the right counts as a hub.
        if d.rights & RIGHT_HUB == 0 {
            return Err(Error::msg(format!("{} may not be a hub: its record does not give it the right", d.name)));
        }
        hubs.push(d.id);
    }
    hubs.sort();
    hubs.dedup();
    set.write_record(&st, signer, Kind::Hubs { hubs, seen: Vec::new() }, now_ms)
        .map_err(|e| Error::msg(format!("cannot name the hubs: {e}")))
}

/// Changes the group's settings from what they are now.
pub fn set_settings(
    set: &mut RecordSet,
    signer: &dyn ExternalKey,
    change: impl FnOnce(&mut Settings),
    now_ms: u64,
) -> Result<Vec<Record>> {
    let st = set.state();
    let mut s = st.settings.clone();
    change(&mut s);
    if s == st.settings {
        return Ok(Vec::new());
    }
    set.write_record(&st, signer, Kind::settings(s), now_ms)
        .map_err(|e| Error::msg(format!("cannot change the group's settings: {e}")))
}

#[cfg(test)]
mod tests;
