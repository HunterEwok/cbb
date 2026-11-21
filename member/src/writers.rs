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
use cbb_core::records::body::{CAP_HUB, Device, Kind, RIGHT_HUB, ROLE_MEMBER, Removal, Settings};
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
pub(crate) fn keys_of(d: &DeviceState) -> Vec<cbb_core::records::KeyHash> {
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
        return Err(Error::msg(format!(
            "{} holds the group's root, which is not removed: the root changes only with its recovery key (cbb recovery)",
            d.name
        )));
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

/// Voids both histories of every key that signed two (docs/protocol.md,
/// section 10, "Going on after two histories"): the root's `resolve`
/// naming the records of each key at the seq where it forked, so that the
/// key goes on from the record before them. Gives whose keys they were, by
/// device name (the first bytes of the key in hex when no device has it),
/// and what was written. Only the group's root resolves.
pub fn resolve(set: &mut RecordSet, signer: &dyn ExternalKey, now_ms: u64) -> Result<(Vec<String>, Vec<Record>)> {
    use cbb_core::records::eval::ConflictKind;
    let st = set.state();
    if st.roots.last() != Some(&Key::es256(signer.public()).hash()) {
        return Err(Error::msg(
            "only the group's root resolves two histories: run cbb resolve on the root computer, or resolve them on the root phone",
        ));
    }
    let (mut ids, mut who) = (Vec::new(), Vec::new());
    for c in st.conflicts.iter().filter(|c| c.kind == ConflictKind::TwoHistories) {
        ids.extend(c.records.iter().copied());
        for k in &c.signers {
            let d =
                st.devices.iter().find(|d| d.key.hash() == *k || d.admin == Some(*k)).or_else(|| {
                    (st.roots.last() == Some(k)).then(|| st.root_device.and_then(|r| st.device(&r))).flatten()
                });
            who.push(d.map_or_else(|| hex(&k.0[..4]), |d| d.name.clone()));
        }
    }
    if ids.is_empty() {
        return Err(Error::msg("no key of the group signed two histories"));
    }
    ids.sort();
    ids.dedup();
    let out = set
        .write_record(&st, signer, Kind::Resolve(ids), now_ms)
        .map_err(|e| Error::msg(format!("cannot void the two histories: {e}")))?;
    Ok((who, out))
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
    if Some(d.id) == st.root_device {
        return Err(Error::msg(format!("{} holds the group's root, which nobody freezes", d.name)));
    }
    if on && d.frozen {
        return Err(Error::msg(format!("{} is frozen already", d.name)));
    }
    if !on && !d.frozen {
        return Err(Error::msg(format!("{} is not frozen", d.name)));
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
    // A device record that names an admin key, or of a watch, counts only
    // from the root's key, and so does the root's own device's.
    let by_root = st.roots.last() == Some(&Key::es256(signer.public()).hash());
    if !by_root && (d.admin.is_some() || d.role == cbb_core::records::body::ROLE_WATCH || Some(d.id) == st.root_device)
    {
        return Err(Error::msg(format!(
            "only the group's root renames {}: it is an admin or a watch, or the root's own device",
            d.name
        )));
    }
    let mut rec = device_record(set, &st, &d.id).ok_or_else(|| Error::msg("the device's record is not here"))?;
    rec.name = name.to_string();
    rec.seen = Vec::new();
    let out = set.write_record(&st, signer, Kind::device(rec), now_ms);
    Ok((d, out.map_err(|e| Error::msg(format!("cannot rename the device: {e}")))?))
}

/// Makes a device an admin with the admin key it offered when it paired
/// (`admin`, a P-256 point): its record again, naming the key with the
/// powers and commands of its kind (a phone's or a computer's).
pub fn make_admin(
    set: &mut RecordSet,
    signer: &dyn ExternalKey,
    target: &str,
    admin: &[u8],
    now_ms: u64,
) -> Result<(DeviceState, Vec<Record>)> {
    use cbb_core::records::body::{AdminKind, ROLE_PHONE};
    let st = set.state();
    let d = find(&st, target)?.clone();
    let key = Key::es256(admin.to_vec());
    let hash = key.hash();
    let taken = st.devices.iter().any(|o| o.key.hash() == hash || o.admin == Some(hash)) || st.roots.contains(&hash);
    if taken {
        return Err(Error::msg(format!("the admin key that {} offered belongs to another key of the group", d.name)));
    }
    let mut rec = device_record(set, &st, &d.id).ok_or_else(|| Error::msg("the device's record is not here"))?;
    let kind = if d.role == ROLE_PHONE { AdminKind::Phone } else { AdminKind::Computer };
    let (powers, commands) = kind.grants();
    rec.admin = Some(key);
    rec.powers = powers;
    rec.commands = commands;
    rec.seen = Vec::new();
    let out = set.write_record(&st, signer, Kind::device(rec), now_ms);
    Ok((d, out.map_err(|e| Error::msg(format!("cannot make the device an admin: {e}")))?))
}

/// On the group's root, records where a member's keys live as its hello
/// says (docs/protocol.md, section 17): a record that says `file` while the
/// hello says hardware gets `hardware`, and a hello that says rootless
/// gets `rootless`, without an admin key, powers or commands (D-79).
/// Anything else, a phone's record, a record that already says it, or a
/// signer that is not the root, signs nothing and gives None.
pub fn store_from_hello(
    set: &mut RecordSet,
    signer: &dyn ExternalKey,
    device: &DeviceId,
    hello_store: u64,
    now_ms: u64,
) -> Result<Option<DeviceState>> {
    use cbb_core::records::body::{STORE_FILE, STORE_HARDWARE, STORE_ROOTLESS};
    let st = set.state();
    if st.roots.last() != Some(&Key::es256(signer.public()).hash()) {
        return Ok(None);
    }
    let Some(d) = st.devices.iter().find(|d| d.id == *device).cloned() else { return Ok(None) };
    if d.role != ROLE_MEMBER || st.root_device == Some(d.id) {
        return Ok(None);
    }
    let rootless = hello_store == STORE_ROOTLESS && d.store != STORE_ROOTLESS;
    let hardware = hello_store == STORE_HARDWARE && d.store == STORE_FILE;
    if !rootless && !hardware {
        return Ok(None);
    }
    let mut rec = device_record(set, &st, &d.id).ok_or_else(|| Error::msg("the device's record is not here"))?;
    rec.store = hello_store;
    if rootless {
        (rec.admin, rec.powers, rec.commands, rec.proof) = (None, 0, 0, 0);
    }
    rec.seen = Vec::new();
    set.write_record(&st, signer, Kind::device(rec), now_ms)
        .map_err(|e| Error::msg(format!("cannot record where {}'s keys live: {e}", d.name)))?;
    Ok(Some(d))
}

/// What an attestation showed of a device's keys, for its record
/// (docs/protocol.md, section 17): the store, and the kind of hardware
/// when proven (`proof` 1 android-tee, 2 android-strongbox, 3 tpm).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Shown {
    /// The store and proof the attestation proves.
    Store { store: u64, proof: u64 },
    /// Proven no more (a revoked certificate): only a record that says
    /// proven changes, to hardware.
    NotProven,
}

/// Records, on the group's root (signer holds the current root key), what
/// device's attestation of its member key `key` shows, when its record
/// says otherwise; None when nothing changes: the key is not the record's
/// (it sends the evidence again when it next connects), the record says
/// it already, or the device's keys are rootless, which nothing proves.
pub fn record_proven(
    set: &mut RecordSet,
    signer: &dyn ExternalKey,
    device: &DeviceId,
    key: &cbb_core::records::KeyHash,
    shown: Shown,
    now_ms: u64,
) -> Result<Option<(DeviceState, u64, u64)>> {
    use cbb_core::records::body::{STORE_HARDWARE, STORE_PROVEN, STORE_ROOTLESS};
    let st = set.state();
    if st.roots.last() != Some(&Key::es256(signer.public()).hash()) {
        return Ok(None);
    }
    let Some(d) = st.devices.iter().find(|d| d.id == *device).cloned() else { return Ok(None) };
    if d.key.hash() != *key || d.store == STORE_ROOTLESS || st.root_device == Some(d.id) {
        return Ok(None);
    }
    let (store, proof) = match shown {
        Shown::NotProven if d.store == STORE_PROVEN => (STORE_HARDWARE, 0),
        Shown::NotProven => return Ok(None),
        Shown::Store { store, proof } => (store, if store == STORE_PROVEN { proof } else { 0 }),
    };
    if (d.store, d.proof) == (store, proof) {
        return Ok(None);
    }
    let mut rec = device_record(set, &st, &d.id).ok_or_else(|| Error::msg("the device's record is not here"))?;
    (rec.store, rec.proof) = (store, proof);
    rec.seen = Vec::new();
    set.write_record(&st, signer, Kind::device(rec), now_ms)
        .map_err(|e| Error::msg(format!("cannot record what {}'s attestation proves: {e}", d.name)))?;
    Ok(Some((d, store, proof)))
}

/// Makes this device (me) the group's root with the group's recovery key
/// (rule 33): the change of root, signed by both halves of the recovery
/// key, naming new_root, with this device's record again as the root's
/// own (its admin key, if it had one, goes: a change of root takes every
/// admin key back). Every other device stays; leave_out names the keys
/// that do not. Gives what was written, for the set's owner to save.
pub fn recover(
    set: &mut RecordSet,
    recovery: &dyn ExternalKey,
    recovery2: &cbb_core::records::pq::PqKey,
    new_root: &dyn ExternalKey,
    me: &DeviceId,
    leave_out: &[cbb_core::records::KeyHash],
    now_ms: u64,
) -> Result<cbb_core::records::set::Written> {
    use cbb_core::records::body::{RIGHT_READ, RIGHT_SECRETS, RIGHT_SEND};
    let st = set.state();
    let mut rec = device_record(set, &st, me).ok_or_else(|| Error::msg("this device's record is not here"))?;
    rec.holds_root = true;
    rec.admin = None;
    rec.powers = 0;
    rec.commands = 0;
    rec.rights |= RIGHT_READ | RIGHT_SEND | RIGHT_SECRETS;
    rec.seen = Vec::new();
    set.write_change(&st, recovery, recovery2, new_root, rec, leave_out, false, now_ms)
        .map_err(|e| Error::msg(format!("cannot make this device the group's root: {e}")))
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
    use cbb_core::records::body::MAX_HUBS;
    if targets.is_empty() || targets.len() > MAX_HUBS {
        return Err(Error::msg(format!("name 1 to {MAX_HUBS} hubs")));
    }
    let st = set.state();
    let by_root = st.roots.last() == Some(&Key::es256(signer.public()).hash());
    let mut hubs = Vec::with_capacity(targets.len());
    let mut grant = Vec::new();
    for t in targets {
        let d = find(&st, t)?;
        if hubs.contains(&d.id) {
            return Err(Error::msg(format!("{} is named twice", d.name)));
        }
        // Only a device whose record gives it the right counts as a hub.
        // The root gives it to a member with the cap hub that an admin
        // admitted, which could not (it grants base rights only).
        if d.rights & RIGHT_HUB == 0 {
            if !(by_root && d.role == ROLE_MEMBER && d.caps & CAP_HUB != 0) {
                return Err(Error::msg(format!("{} may not be a hub: its record does not give it the right", d.name)));
            }
            grant.push(d.id);
        }
        hubs.push(d.id);
    }
    let mut out = Vec::new();
    for id in grant {
        let st = set.state();
        let mut rec = device_record(set, &st, &id).ok_or_else(|| Error::msg("the device's record is not here"))?;
        rec.rights |= RIGHT_HUB;
        rec.seen = Vec::new();
        out.extend(
            set.write_record(&st, signer, Kind::device(rec), now_ms)
                .map_err(|e| Error::msg(format!("cannot let the device be a hub: {e}")))?,
        );
    }
    // In the user's order, which is the order the hubs serve in (format
    // 4.8): not sorted.
    let st = set.state();
    out.extend(
        set.write_record(&st, signer, Kind::Hubs { hubs, seen: Vec::new() }, now_ms)
            .map_err(|e| Error::msg(format!("cannot name the hubs: {e}")))?,
    );
    Ok(out)
}

/// Whether a device's rights make it a hub that only passes copies on: the
/// right to be a hub, and neither to read nor to send.
pub fn is_forward_only(rights: u64) -> bool {
    use cbb_core::records::body::{RIGHT_READ, RIGHT_SEND};
    rights & RIGHT_HUB != 0 && rights & (RIGHT_READ | RIGHT_SEND) == 0
}

/// Makes the device target one of the group's hubs that only passes the
/// copies on, as the root alone may: its record keeps the right to be a hub
/// and loses those to read, send and paste secrets, and the hubs record
/// names it after the hubs it names already. A device that is no member
/// computer with the cap hub, or that is an admin or the root, is refused.
pub fn set_forward_only(
    set: &mut RecordSet,
    signer: &dyn ExternalKey,
    target: &str,
    now_ms: u64,
) -> Result<Vec<Record>> {
    use cbb_core::records::body::{MAX_HUBS, RIGHT_READ, RIGHT_SECRETS, RIGHT_SEND};
    let st = set.state();
    let d = find(&st, target)?.clone();
    if d.role != ROLE_MEMBER || d.caps & CAP_HUB == 0 || d.admin.is_some() || st.root_device == Some(d.id) {
        return Err(Error::msg(format!(
            "{} may not be a hub that only passes copies on: that takes a computer that is neither an admin nor the root",
            d.name
        )));
    }
    let mut out = Vec::new();
    if !is_forward_only(d.rights) {
        let mut rec = device_record(set, &st, &d.id).ok_or_else(|| Error::msg("the device's record is not here"))?;
        rec.rights = (rec.rights | RIGHT_HUB) & !(RIGHT_READ | RIGHT_SEND | RIGHT_SECRETS);
        rec.seen = Vec::new();
        out.extend(
            set.write_record(&st, signer, Kind::device(rec), now_ms)
                .map_err(|e| Error::msg(format!("cannot make {} a hub that only passes copies on: {e}", d.name)))?,
        );
    }
    let st = set.state();
    if !st.hubs.contains(&d.id) {
        let mut hubs = st.hubs.clone();
        if hubs.len() >= MAX_HUBS {
            return Err(Error::msg(format!("the group names {MAX_HUBS} hubs already")));
        }
        hubs.push(d.id);
        out.extend(
            set.write_record(&st, signer, Kind::Hubs { hubs, seen: Vec::new() }, now_ms)
                .map_err(|e| Error::msg(format!("cannot name the hubs: {e}")))?,
        );
    }
    Ok(out)
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
